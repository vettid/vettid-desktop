//! The session engine of a paired desktop (VAULT-MESSAGING §8), as the
//! vault's Go device client runs it (`client.poll`, `pollPersist`,
//! `handle`, `sendFull`, `queueLocked`, `flushOutboxLocked`, `maintain`):
//!
//! - **Sending** ([`Session::send`], [`Session::resend`],
//!   [`Session::request`], [`Session::reply`]): the message is sealed in
//!   the session's epoch (which assigns its `seq`), put in the outbox,
//!   **stored**, then deposited; `Ok` means stored. What the relay hasn't
//!   accepted stays in the outbox and is deposited again on the next send
//!   or poll, also after a restart; the vault dedupes a resend by its
//!   inner `id` (§8.2). An application retry reuses the inner id
//!   ([`Session::resend`], §8.6). Ephemeral types and `vault.lock` never
//!   enter the stored outbox (§8.5, §8.6): [`Session::send_once`] deposits
//!   them once, from memory.
//! - **Receiving** ([`Session::poll`]): collect a batch; for each message,
//!   the relay `msg_id` dedupe, the vault's relay key as sender (§6.3), the
//!   epoch's keys, the freshness rules by type class (§8.4, §8.5), the
//!   inner `id` dedupe, and for a response, a request still waiting for it
//!   (§8.1; the waiting requests are stored, so a restart doesn't lose
//!   their answers). The engine answers the token messages itself (§7.2);
//!   every other message goes to the caller. The batch's effects are
//!   **stored before any message is acked** (§8.3); if storing fails,
//!   nothing is acked, everything rolls back, and the relay delivers the
//!   batch again.
//! - **Tokens** (§7.2): a fresh standing token for the vault when the one
//!   this device issued has less than 10 days left, and a refresh request
//!   when the vault's token to this device has less than 3.
//! - **Refused** (`token_revoked`, §8.6): nothing more is sent, but the
//!   device keeps collecting, where a `device.unlinked` may still wait.
//! - **A message without `re` of a type the caller doesn't know** must be
//!   answered with `unsupported_type` (§5.3): the caller does that with
//!   [`Session::reply_unsupported`].
//!
//! The responder side (the vault's rekeys, new-epoch messages before
//! `hs.fin`, key retention) comes in the next part; until then a rekey
//! `hs.init` is dropped like any message this engine can't open.

use chrono::{DateTime, TimeDelta, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use vettid_relay::auth::decode_key;
use vettid_relay::client::{Message, RelayError};
use vettid_relay::token::Token;
use vettid_vms::envelope::{new_ulid, Envelope, Inner, Mode, Response, Status, MAX_CLOCK_SKEW_FUTURE};
use vettid_vms::handshake::{Epoch, EpochState, HandshakeError, TYPE_INIT};
use vettid_vms::strict_json::{self, Builder};
use zeroize::Zeroizing;

use crate::pairing::Clock;
use crate::store::{DeviceState, OutboxEntry, Persist, StoreError};
use crate::token::{check_from_vault, mint_for_vault};
use crate::transport::Transport;

/// How long relay `msg_id`s and durable inner `id`s are kept (§8.2).
pub const SEEN_KEEP: TimeDelta = TimeDelta::days(16);
/// How long an ephemeral message's inner `id` is kept, at least (§8.5).
pub const EPHEMERAL_KEEP: TimeDelta = TimeDelta::minutes(10);
/// How long a request waits for its response to be accepted (the vault
/// caches responses 24 h, §8.2).
pub const ASKED_KEEP: TimeDelta = TimeDelta::hours(24);
/// How long an outbox entry is tried: the vault refuses durable messages
/// older than 16 days (§8.4).
pub const OUTBOX_MAX_AGE: TimeDelta = TimeDelta::days(16);
/// The most outbox entries kept; past it, the oldest is dropped (and
/// reported).
pub const OUTBOX_CAP: usize = 64;
/// Re-issue the vault's standing token when this much of it is left.
pub const REISSUE_BELOW: TimeDelta = TimeDelta::days(10);
/// Ask the vault for a fresh token when this much of ours is left.
pub const REFRESH_BELOW: TimeDelta = TimeDelta::days(3);
/// How often a refresh request may be repeated.
const REFRESH_EVERY: TimeDelta = TimeDelta::hours(1);
/// An interactive request's default timeout (§8.1).
pub const REQUEST_TIMEOUT: TimeDelta = TimeDelta::seconds(30);
/// The longest long-poll wait per collect.
const POLL_WAIT_SECS: i64 = 25;
const POLL_MAX: u32 = 32;
/// Backoff before the outbox is tried again after a temporary failure.
const OUTBOX_BACKOFF: TimeDelta = TimeDelta::seconds(5);
const OUTBOX_MAX_BACKOFF: TimeDelta = TimeDelta::minutes(5);

/// The ephemeral types of §8.5: they need `exp`, have no age limit, and
/// are deduped in memory only; every other type is durable.
pub const EPHEMERAL_TYPES: &[&str] =
    &["call.ice", "call.ringing", "call.keepalive", "location.update", "presence.ping", "presence.pong", "presence.result", "vault.locking"];

/// Whether `kind` is durable (§8.5).
pub fn durable(kind: &str) -> bool {
    !EPHEMERAL_TYPES.contains(&kind)
}

/// Whether `kind` may wait in the stored outbox: not an ephemeral type,
/// and not `vault.lock`, which "MUST NOT" be put in an outbox that
/// outlives the attempt (§8.6).
pub fn outbox_allowed(kind: &str) -> bool {
    durable(kind) && kind != "vault.lock"
}

const RELAY_TOKEN_ISSUED: &str = "relay.token.issued";
const RELAY_TOKEN_REFRESH: &str = "relay.token.refresh";
/// The outbox label of a refresh request (its reply is labelled
/// `relay.token.refresh`): only the newest of each is worth sending.
const REFRESH_REQUEST: &str = "relay.token.refresh?";

/// Why a session operation failed. Carries no secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// The vault's mailbox refused this device (`token_revoked`): it has
    /// been unlinked. Nothing more is sent; polling still collects.
    Refused,
    /// A relay call failed.
    Relay(RelayError),
    /// The state couldn't be stored; nothing of the operation was acked
    /// or sent, and it rolled back.
    Store(StoreError),
    /// Sealing failed.
    Seal(HandshakeError),
    /// A request had no response within its timeout.
    TimedOut,
    /// This type may not wait in the stored outbox (an ephemeral type, or
    /// `vault.lock`): use [`Session::send_once`].
    NotQueueable,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused => f.write_str("session: this device was removed from the vault"),
            Self::Relay(e) => write!(f, "session: {e}"),
            Self::Store(e) => write!(f, "session: {e}"),
            Self::Seal(e) => write!(f, "session: {e}"),
            Self::TimedOut => f.write_str("session: no response in time"),
            Self::NotQueueable => f.write_str("session: this message type is sent once, not queued"),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<StoreError> for SessionError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<RelayError> for SessionError {
    fn from(e: RelayError) -> Self {
        Self::Relay(e)
    }
}

/// A paired desktop's session with its vault. `Debug` prints nothing
/// secret.
pub struct Session<T: Transport, C: Clock> {
    transport: T,
    clock: C,
    state: DeviceState,
    epoch: Epoch,
    relay_key: SigningKey,
    /// Messages for the caller not yet returned (from inside `request`).
    /// Already stored and acked: never dropped.
    held: Vec<Inner>,
    /// Outbox entries dropped without delivery (evicted, refused by the
    /// relay for good, or expired), by `type`, until taken.
    dropped: Vec<String>,
    /// Something changed that must be stored with the batch.
    dirty: bool,
    outbox_next: DateTime<Utc>,
    outbox_backoff: TimeDelta,
    refresh_sent: Option<DateTime<Utc>>,
}

impl<T: Transport, C: Clock> std::fmt::Debug for Session<T, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session").field("epoch", &self.epoch).field("outbox", &self.state.outbox.len()).finish_non_exhaustive()
    }
}

/// What the engine keeps across an operation, to roll back if storing
/// fails.
struct Checkpoint {
    state: DeviceState,
    epoch: EpochState,
    refresh_sent: Option<DateTime<Utc>>,
    dropped: usize,
}

impl<T: Transport, C: Clock> Session<T, C> {
    /// The paired device's session, if the desktop is paired
    /// ([`DeviceState::load_paired`]: a pending state is removed).
    /// `make_transport` gets this device's relay key.
    pub fn open(store: &mut impl Persist, make_transport: impl FnOnce(SigningKey) -> T, clock: C) -> Result<Option<Self>, SessionError> {
        let Some(state) = DeviceState::load_paired(store)? else { return Ok(None) };
        let relay_key = SigningKey::from_bytes(&state.relay_seed);
        let epoch = Epoch::restore(state.epoch.clone());
        let now = clock.now();
        Ok(Some(Session {
            transport: make_transport(relay_key.clone()),
            clock,
            state,
            epoch,
            relay_key,
            held: Vec::new(),
            dropped: Vec::new(),
            dirty: false,
            outbox_next: now,
            outbox_backoff: OUTBOX_BACKOFF,
            refresh_sent: None,
        }))
    }

    /// The device id the vault assigned.
    pub fn device_id(&self) -> Option<&str> {
        self.state.device_id.as_deref()
    }

    /// Whether the vault has refused this device.
    pub fn is_refused(&self) -> bool {
        self.state.refused
    }

    /// How many deposits wait in the outbox.
    pub fn outbox_len(&self) -> usize {
        self.state.outbox.len()
    }

    /// The `type`s of outbox entries dropped without delivery since the
    /// last call (evicted at the cap, refused by the relay for good, or
    /// expired): the caller tells the person they weren't sent.
    pub fn take_dropped(&mut self) -> Vec<String> {
        std::mem::take(&mut self.dropped)
    }

    fn own_pk(&self) -> VerifyingKey {
        self.relay_key.verifying_key()
    }

    fn checkpoint(&self) -> Checkpoint {
        Checkpoint { state: self.state.clone(), epoch: self.epoch.snapshot(), refresh_sent: self.refresh_sent, dropped: self.dropped.len() }
    }

    fn rollback(&mut self, c: Checkpoint) {
        self.state = c.state;
        self.epoch = Epoch::restore(c.epoch);
        self.refresh_sent = c.refresh_sent;
        self.dropped.truncate(c.dropped);
        self.dirty = false;
    }

    /// Prune what has outlived its keep, then store.
    fn save(&mut self, store: &mut impl Persist) -> Result<(), StoreError> {
        let now = self.clock.now();
        self.state.seen.retain(|_, t| now - *t <= SEEN_KEEP);
        self.state.seen_inner.retain(|_, until| *until >= now);
        self.state.asked.retain(|_, until| *until >= now);
        self.state.epoch = self.epoch.snapshot();
        self.state.save(store)?;
        self.dirty = false;
        Ok(())
    }

    /// Seal `inner` and put it in the outbox under `label` (not stored or
    /// sent yet). A token entry replaces a waiting one of its label: only
    /// the newest is worth sending. Past the cap the oldest is evicted
    /// and reported.
    fn queue(&mut self, label: &str, mut inner: Inner) -> Result<(), SessionError> {
        let env = self.epoch.seal(&mut inner).map_err(SessionError::Seal)?;
        if [RELAY_TOKEN_ISSUED, REFRESH_REQUEST].contains(&label) {
            self.state.outbox.retain(|o| o.kind != label);
        }
        self.state.outbox.push(OutboxEntry { kind: label.to_string(), payload: env, created: self.clock.now(), exp: inner.exp });
        while self.state.outbox.len() > OUTBOX_CAP {
            let evicted = self.state.outbox.remove(0);
            self.dropped.push(evicted.kind);
        }
        self.dirty = true;
        Ok(())
    }

    fn inner(&self, id: Option<&str>, kind: &str, body: String, response: Option<Response>, exp: Option<DateTime<Utc>>) -> Result<Inner, SessionError> {
        let now = self.clock.now();
        let id = match id {
            Some(id) => id.to_string(),
            None => new_ulid(now).map_err(|e| SessionError::Seal(HandshakeError::Suite(e)))?,
        };
        Ok(Inner { id, kind: kind.into(), ts: now, seq: None, response, exp, body: Zeroizing::new(body) })
    }

    /// Arm a request's id for its response, until the earlier of
    /// [`ASKED_KEEP`] and its `exp` plus the clock skew. Stored with the
    /// state, so a restart doesn't drop the answer.
    fn arm(&mut self, id: &str, exp: Option<DateTime<Utc>>) {
        let mut until = self.clock.now() + ASKED_KEEP;
        if let Some(e) = exp {
            until = until.min(e + MAX_CLOCK_SKEW_FUTURE);
        }
        self.state.asked.insert(id.to_string(), until);
        self.dirty = true;
    }

    /// Queue, store, then try to deposit. `Ok` once stored: a deposit that
    /// fails for now stays in the outbox, and one dropped is reported by
    /// [`Session::take_dropped`]. `Refused` if the vault's mailbox turns
    /// out to refuse this device.
    async fn send_inner(&mut self, store: &mut impl Persist, inner: Inner, request: bool) -> Result<String, SessionError> {
        if self.state.refused {
            return Err(SessionError::Refused);
        }
        if !outbox_allowed(&inner.kind) {
            return Err(SessionError::NotQueueable);
        }
        let (id, exp, kind) = (inner.id.clone(), inner.exp, inner.kind.clone());
        let cp = self.checkpoint();
        self.queue(&kind, inner)?;
        if request {
            self.arm(&id, exp);
        }
        if let Err(e) = self.save(store) {
            self.rollback(cp);
            return Err(e.into());
        }
        self.outbox_next = self.clock.now();
        // Stored: a temporary failure or a store error after the deposit
        // doesn't change the answer. Only a refusal does: the device was
        // removed, and this message won't go (it is reported as dropped).
        match self.flush(store).await {
            Err(SessionError::Refused) => Err(SessionError::Refused),
            _ => Ok(id),
        }
    }

    /// Send an event or a request of `kind` with `body` (a JSON object),
    /// with a new inner id; returns it. See [`Session::resend`] for a
    /// retry. A request's response arrives through [`Session::poll`] (or
    /// use [`Session::request`]).
    pub async fn send(&mut self, store: &mut impl Persist, kind: &str, body: &str, request: bool) -> Result<String, SessionError> {
        let inner = self.inner(None, kind, body.to_string(), None, None)?;
        self.send_inner(store, inner, request).await
    }

    /// Send again with the same inner `id` (an application retry, §8.6):
    /// the vault answers it from its cache instead of acting twice, and a
    /// request's id is armed again for that answer.
    pub async fn resend(&mut self, store: &mut impl Persist, id: &str, kind: &str, body: &str, request: bool) -> Result<String, SessionError> {
        let inner = self.inner(Some(id), kind, body.to_string(), None, None)?;
        self.send_inner(store, inner, request).await
    }

    /// Deposit an ephemeral message or `vault.lock` once, from memory, not
    /// through the stored outbox (§8.5, §8.6): if it isn't accepted now,
    /// it isn't sent, and the error says so. The epoch's `seq` is stored
    /// first.
    pub async fn send_once(&mut self, store: &mut impl Persist, kind: &str, body: &str, exp: Option<DateTime<Utc>>) -> Result<String, SessionError> {
        if self.state.refused {
            return Err(SessionError::Refused);
        }
        let mut inner = self.inner(None, kind, body.to_string(), None, exp)?;
        let cp = self.checkpoint();
        let env = self.epoch.seal(&mut inner).map_err(SessionError::Seal)?;
        if let Err(e) = self.save(store) {
            self.rollback(cp);
            return Err(e.into());
        }
        let to = &self.state.vault.relay;
        let token = Token::from_received(self.state.vault_token.to_string());
        match self.transport.deposit(&to.url, &to.mailbox, &token, &env).await {
            Ok(_) => Ok(inner.id),
            Err(d) if d.possibly_delivered && !d.error.retryable() => Ok(inner.id),
            Err(d) => Err(SessionError::Relay(d.error)),
        }
    }

    /// Answer `to` (a request from the vault) with `status` and `body`.
    pub async fn reply(&mut self, store: &mut impl Persist, to: &Inner, status: Status, body: &str) -> Result<(), SessionError> {
        let inner = self.inner(None, &to.kind, body.to_string(), Some(Response { re: to.id.clone(), status }), None)?;
        self.send_inner(store, inner, false).await.map(drop)
    }

    /// Answer a request whose `type` the caller doesn't know with
    /// `unsupported_type` (§5.3).
    pub async fn reply_unsupported(&mut self, store: &mut impl Persist, to: &Inner) -> Result<(), SessionError> {
        let status = Status::Error { code: "unsupported_type".into(), message: None };
        self.reply(store, to, status, "{}").await
    }

    /// Send a request and wait for its response, up to `timeout`, polling
    /// meanwhile (temporary relay failures are retried until then); other
    /// messages that arrive are kept for the next [`Session::poll`]. On
    /// `TimedOut` the request stays armed: [`Session::resend`] it with the
    /// same id rather than sending a new one.
    pub async fn request(&mut self, store: &mut impl Persist, kind: &str, body: &str, timeout: TimeDelta) -> Result<Inner, SessionError> {
        let id = self.send(store, kind, body, true).await?;
        let deadline = self.clock.now() + timeout;
        loop {
            let left = (deadline - self.clock.now()).num_seconds().clamp(1, POLL_WAIT_SECS) as u64;
            match self.poll_batch(store, left).await {
                Ok(mut got) => {
                    if let Some(i) = got.iter().position(|m| m.response.as_ref().is_some_and(|r| r.re == id)) {
                        let answer = got.remove(i);
                        self.held.extend(got);
                        return Ok(answer);
                    }
                    self.held.extend(got);
                }
                Err(SessionError::Relay(e)) if e.retryable() => {}
                Err(e) => return Err(e),
            }
            if self.clock.now() >= deadline {
                return Err(SessionError::TimedOut);
            }
        }
    }

    /// Deposit the outbox in order on the vault token held now (Go's
    /// `flushOutboxLocked`):
    /// - accepted, or a failure after which it may have been stored (and
    ///   not worth retrying): removed;
    /// - `token_revoked`: this device is refused; the outbox is emptied;
    /// - any 429 (rate limited, or a quota that the vault frees later,
    ///   §8.6), a 5xx, a transport error: it and the rest stay, and the
    ///   outbox waits a backoff;
    /// - another client error: dropped, and reported;
    /// - older than [`OUTBOX_MAX_AGE`], or past its `exp`: dropped unsent,
    ///   and reported.
    async fn flush(&mut self, store: &mut impl Persist) -> Result<(), SessionError> {
        let now = self.clock.now();
        if self.state.refused {
            return Err(SessionError::Refused);
        }
        if self.state.outbox.is_empty() || now < self.outbox_next {
            return Ok(());
        }
        let to = self.state.vault.relay.clone();
        let token = Token::from_received(self.state.vault_token.to_string());
        let mut changed = false;
        let mut temporary = None;
        while let Some(e) = self.state.outbox.first().cloned() {
            if now - e.created > OUTBOX_MAX_AGE || e.exp.is_some_and(|x| now > x) {
                self.state.outbox.remove(0);
                self.dropped.push(e.kind);
                changed = true;
                continue;
            }
            if let Err(d) = self.transport.deposit(&to.url, &to.mailbox, &token, &e.payload).await {
                match &d.error {
                    RelayError::Relay { code, .. } if code == "token_revoked" => {
                        self.state.refused = true;
                        let lost: Vec<String> = self.state.outbox.drain(..).map(|o| o.kind).collect();
                        self.dropped.extend(lost);
                        self.save(store)?;
                        return Err(SessionError::Refused);
                    }
                    RelayError::Relay { status: 429, retry_after, .. } => {
                        let wait = retry_after.map(|s| TimeDelta::seconds(s.min(3600) as i64));
                        temporary = Some((d.error.clone(), wait));
                        break;
                    }
                    err if err.retryable() => {
                        temporary = Some((err.clone(), None));
                        break;
                    }
                    _ if d.possibly_delivered => {} // stored: done
                    _ => self.dropped.push(e.kind.clone()),
                }
            }
            self.state.outbox.remove(0);
            changed = true;
        }
        if changed {
            self.save(store)?;
        }
        match temporary {
            Some((err, wait)) => {
                self.outbox_next = now + wait.unwrap_or(self.outbox_backoff).max(self.outbox_backoff);
                self.outbox_backoff = (self.outbox_backoff * 2).min(OUTBOX_MAX_BACKOFF);
                Err(SessionError::Relay(err))
            }
            None => {
                self.outbox_backoff = OUTBOX_BACKOFF;
                Ok(())
            }
        }
    }

    /// The messages for the caller: those held from inside
    /// [`Session::request`] if there are any (returned at once, never
    /// lost), otherwise one collected batch: events and requests from the
    /// vault, and responses to this device's requests, all already
    /// stored. Also deposits the outbox and keeps the tokens fresh. A
    /// refused device still collects (`device.unlinked`, §8.6); check
    /// [`Session::is_refused`].
    pub async fn poll(&mut self, store: &mut impl Persist) -> Result<Vec<Inner>, SessionError> {
        if !self.held.is_empty() {
            return Ok(std::mem::take(&mut self.held));
        }
        self.poll_batch(store, POLL_WAIT_SECS as u64).await
    }

    async fn poll_batch(&mut self, store: &mut impl Persist, wait_secs: u64) -> Result<Vec<Inner>, SessionError> {
        match self.flush(store).await {
            Ok(()) | Err(SessionError::Relay(_)) | Err(SessionError::Refused) => {}
            Err(e) => return Err(e),
        }
        let msgs = self.transport.collect(&self.state.relay_url, wait_secs, POLL_MAX).await?;
        let cp = self.checkpoint();
        let mut events = Vec::new();
        for m in &msgs {
            self.handle(m, &mut events);
        }
        self.maintain();
        if self.dirty {
            if let Err(e) = self.save(store) {
                // Nothing acked: the relay delivers the batch again.
                self.rollback(cp);
                return Err(e.into());
            }
        }
        for m in &msgs {
            // Best effort: what isn't acked comes again, and is a duplicate.
            let _ = self.transport.ack(&self.state.relay_url, &m.msg_id).await;
        }
        self.outbox_next = self.outbox_next.min(self.clock.now());
        match self.flush(store).await {
            Ok(()) | Err(SessionError::Relay(_)) | Err(SessionError::Refused) => {}
            Err(e) => return Err(e),
        }
        Ok(events)
    }

    /// Handle one collected message; what is for the caller goes to
    /// `events`. Anything new marks the state dirty.
    fn handle(&mut self, m: &Message, events: &mut Vec<Inner>) {
        if self.state.seen.contains_key(&m.msg_id) {
            return;
        }
        let now = self.clock.now();
        self.state.seen.insert(m.msg_id.clone(), now);
        self.dirty = true;
        // §6.3: only the vault's relay key may send to this device.
        let vault_pk = self.state.vault.relay.pk;
        if !decode_key(&m.sender).is_some_and(|s| s.as_bytes() == vault_pk.as_bytes()) {
            return;
        }
        let Ok(env) = Envelope::parse(&m.payload) else { return };
        if env.mode() != Mode::Session {
            return;
        }
        let Ok(inner) = self.epoch.open(&env) else { return };
        if inner.kind == TYPE_INIT {
            return; // a rekey: the responder comes in the next part
        }
        // §8.4, §8.5: by the type's class (an ephemeral type without exp
        // is refused).
        if inner.check_time(now, durable(&inner.kind)).is_err() {
            return;
        }
        // §8.2, the inner id: a duplicate is dropped, unless it answers a
        // request still waiting (a resent request gets the cached answer).
        let waiting = inner.response.as_ref().is_some_and(|r| self.state.asked.contains_key(&r.re));
        if self.state.seen_inner.contains_key(&inner.id) && !waiting {
            return;
        }
        let keep = match inner.exp {
            Some(exp) => (now + EPHEMERAL_KEEP).max(exp + MAX_CLOCK_SKEW_FUTURE),
            None => now + SEEN_KEEP,
        };
        self.state.seen_inner.insert(inner.id.clone(), keep);
        if let Some(r) = &inner.response {
            // §8.1: a response to no pending request is dropped.
            if self.state.asked.remove(&r.re).is_none() {
                return;
            }
            if inner.kind == RELAY_TOKEN_REFRESH {
                self.store_vault_token(&inner.body, now);
                return;
            }
            events.push(inner);
            return;
        }
        match inner.kind.as_str() {
            RELAY_TOKEN_ISSUED => self.store_vault_token(&inner.body, now),
            RELAY_TOKEN_REFRESH => {
                // The vault asks for a fresh standing token: answer with one.
                if let Some(body) = self.mint_body(now) {
                    let response = Some(Response { re: inner.id.clone(), status: Status::Ok });
                    if let Ok(reply) = self.inner(None, RELAY_TOKEN_REFRESH, body, response, None) {
                        let _ = self.queue(RELAY_TOKEN_REFRESH, reply);
                    }
                }
            }
            "device.paired" | "device.pair.rejected" => {} // late: the pairing is done
            _ => events.push(inner),
        }
    }

    /// A fresh standing token for the vault, as a `{kind, token}` body;
    /// records its expiry.
    fn mint_body(&mut self, now: DateTime<Utc>) -> Option<String> {
        let (token, exp) = mint_for_vault(&self.relay_key, &self.state.relay_url, &self.state.vault.relay.pk, now, 0).ok()?;
        self.state.issued_exp = exp;
        self.dirty = true;
        let body = Zeroizing::new(Builder::with_capacity(token.as_str().len() + 64).string("kind", "standing").string("token", token.as_str()).finish());
        Some(body.to_string())
    }

    /// Keep a standing token the vault sent, if it's valid for this device
    /// and lasts longer than the one held (§7.2).
    fn store_vault_token(&mut self, body: &str, now: DateTime<Utc>) {
        let Ok(o) = strict_json::parse_object(body.as_bytes()) else { return };
        let Ok(token) = o.string("token") else { return };
        match o.opt_string("kind") {
            Ok(None) => {}
            Ok(Some(k)) if k == "standing" => {}
            _ => return,
        }
        let vault_pk = self.state.vault.relay.pk;
        if let Ok(exp) = check_from_vault(&token, &vault_pk, &self.own_pk(), now) {
            if exp > self.state.vault_token_exp {
                self.state.vault_token = Zeroizing::new(token);
                self.state.vault_token_exp = exp;
                self.dirty = true;
            }
        }
    }

    /// The token upkeep of §7.2, queued (stored and sent with the batch).
    fn maintain(&mut self) {
        if self.state.refused {
            return;
        }
        let now = self.clock.now();
        if self.state.issued_exp - now < REISSUE_BELOW {
            if let Some(body) = self.mint_body(now) {
                if let Ok(i) = self.inner(None, RELAY_TOKEN_ISSUED, body, None, None) {
                    let _ = self.queue(RELAY_TOKEN_ISSUED, i);
                }
            }
        }
        let held_left = self.state.vault_token_exp - now;
        let due = self.refresh_sent.is_none_or(|t| now - t >= REFRESH_EVERY);
        if held_left < REFRESH_BELOW && held_left > TimeDelta::zero() && due {
            if let Ok(i) = self.inner(None, RELAY_TOKEN_REFRESH, "{}".into(), None, None) {
                let id = i.id.clone();
                if self.queue(REFRESH_REQUEST, i).is_ok() {
                    self.arm(&id, None);
                    self.refresh_sent = Some(now);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
