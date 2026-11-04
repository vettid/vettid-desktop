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
//! - **Rekeys** (§6.5), which the vault starts on every unlock and every 7
//!   days; this device only answers them, as the vault's device client
//!   does (`handle`, `handleRekey`, `pruneAwaiting`):
//!   - an `hs.init` under the current epoch is answered once: its
//!     `hs.resp` goes into the stored outbox, tagged with the `hs.init`'s
//!     inner id, and that id counts as handled only once the relay has
//!     taken the `hs.resp` (§6.3: one `hs.resp` per `hs.init`). A
//!     retransmitted `hs.init` is skipped while its answer is queued, and
//!     after;
//!   - the waiting responders are stored (at most [`MAX_AWAITING`]; the
//!     oldest is aborted), and aborted after 16 days. Aborting one takes its
//!     `hs.resp` out of the outbox if it is still there, and an `hs.resp`
//!     that leaves the outbox unsent (refused, evicted, expired) aborts its
//!     responder. A responder aborted at the cap **after** its `hs.resp`
//!     went out can strand that rekey (the vault would finish an epoch this
//!     device no longer holds the keys of); that is safe while the vault
//!     starts a new rekey only after the last one has ended, as it does;
//!   - **a message of the new epoch before its `hs.fin` is left unacked,
//!     and not marked seen** (§6.3, 0.23.0): the relay delivers it again
//!     once `hs.fin` has established the epoch. So is an `hs.fin` refused
//!     only because its `ts` is ahead of this device's clock
//!     (`ClockFuture`): only the vault can make it, and it doesn't send it
//!     again. **This is stricter than the vault's Go device client**, which
//!     acks and drops it; other clients should do the same as here;
//!   - `hs.fin` (once `sig_I` verifies) makes the new epoch current: the
//!     old one's send key and `rk` are deleted, and its receive key is
//!     kept 16 days for late messages. An `hs.fin` or `hs.resp` that
//!     arrives again later is ignored.
//!
//! - **The stored inbox**: events that change this device's state
//!   ([`INBOX_TYPES`]: `device.unlinked`, `identity.rotate`) are stored in
//!   the same batch, before their ack, and [`Session::poll`] returns each
//!   of them (again after every restart) until the caller calls
//!   [`Session::handled`]. At most [`INBOX_CAP`]: past it, such an event is
//!   left unacked (the relay keeps it) rather than dropped. Other events
//!   are acked, then returned, so a crash before the caller acts on them
//!   loses them. Inbox events come first in what a poll returns, and they
//!   are returned even when the relay can't be reached. An event left
//!   unacked over the cap is kept only as long as the relay keeps it and
//!   its epoch's receive key lasts (16 days); `device.unlinked` is never
//!   held back by the cap.
//! - **`device.unlinked`** (§7.4, §8.6): the device is refused at once
//!   (nothing more is sent, the outbox is dropped and reported, waiting
//!   rekeys end, and a [`Session::request`] in progress returns `Refused`)
//!   and [`Session::unlinked`] says so from then on, with the reason. A
//!   later one, and any other inbox event (`identity.rotate`, also those
//!   already waiting), is acked and dropped: the app never acts on a
//!   removed device. **The reason comes from the vault: the app maps it to
//!   the known values (none for a plain unlink, `transferred`,
//!   `replaced`, `vault_deleted`) and never shows it raw.** The engine **doesn't erase**
//!   anything: the app decides, by the reason, what to erase and what to
//!   tell the person (§6.7.1; §12.5 adds a confirmation for
//!   `vault_deleted` on a phone). The app checks [`Session::unlinked`]
//!   after [`Session::open`]. (`token_revoked` alone only refuses: it
//!   offers an erase, never makes one, §8.6.)
//!
//! Not yet done: `seq` gap tracking (a receiver may use `seq` to see gaps
//! and order one sender's messages for display, §8.4; nothing reads it
//! here yet), and following `identity.rotate` (it is only kept in the
//! inbox for the caller).

use chrono::{DateTime, TimeDelta, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use vettid_relay::auth::decode_key;
use vettid_relay::client::{Message, RelayError};
use vettid_relay::token::Token;
use vettid_vms::envelope::{new_ulid, Envelope, EnvelopeError, Inner, Mode, Response, Status, MAX_CLOCK_SKEW_FUTURE};
use vettid_vms::handshake::{
    answer_rekey, HandshakeError, Keyring, KeyringState, RekeyConfig, Responder, ResponderState, POLICY_VAULT_TO_DEVICE, TYPE_FIN,
    RECEIVE_KEY_RETENTION, TYPE_INIT, TYPE_RESP,
};
use vettid_vms::strict_json::{self, Builder};
use zeroize::Zeroizing;

use crate::pairing::Clock;
use crate::store::{DeviceState, OutboxEntry, PendingEnd, Persist, StoreError};
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

/// The longest `exp` ahead of now a `vault.lock` may carry (§8.6).
pub const VAULT_LOCK_MAX_EXP: TimeDelta = TimeDelta::seconds(60);

/// The event types that change this device's state: stored in the inbox
/// until the app has handled them.
pub const INBOX_TYPES: &[&str] = &["device.unlinked", "identity.rotate"];
/// The most events the inbox holds; past it, one more is left unacked.
pub const INBOX_CAP: usize = 64;
/// The largest body an inbox event may have; a larger one is left unacked,
/// like one over the cap (a `device.unlinked` still unlinks, kept with its
/// reason only).
pub const INBOX_MAX_BODY: usize = 16 * 1024;
/// The longest `reason` kept; a longer one (or one not printable ASCII) is
/// kept as empty.
const MAX_REASON: usize = 64;
const DEVICE_UNLINKED: &str = "device.unlinked";

/// The most rekeys waiting for `hs.fin` at once; past it, the oldest is
/// aborted. The vault starts a new one only when the last is done or
/// abandoned.
pub const MAX_AWAITING: usize = 8;

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
    /// `send_once` takes an ephemeral type with an `exp` in the future, or
    /// `vault.lock` with an `exp` at most 60 s ahead (§8.5, §8.6).
    BadExp,
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
            Self::BadExp => f.write_str("session: this message type needs a valid exp"),
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
    /// The current epoch and the previous ones' receive keys.
    keys: Keyring,
    /// Rekeys answered, waiting for `hs.fin`, oldest first.
    awaiting: Vec<Waiting>,
    /// Inbox events already returned by this session (after a restart,
    /// all of them are returned again).
    returned: std::collections::HashSet<String>,
    relay_key: SigningKey,
    /// Messages for the caller not yet returned (from inside `request`).
    /// Their batch is already stored and acked: they aren't dropped by an
    /// error here, but a crash before the caller acts loses them.
    held: Vec<Inner>,
    /// Outbox entries dropped without delivery (evicted, refused by the
    /// relay for good, or expired), by `type`, until taken.
    dropped: Vec<String>,
    /// Outbox entries removed after a failure after which they may have
    /// been stored (`possibly_delivered`), by `type`, until taken.
    maybe_sent: Vec<String>,
    /// Something changed that must be stored with the batch.
    dirty: bool,
    /// The outbox isn't tried before this (a backoff, or the relay's
    /// `retry_after`, §8.6): no send or poll moves it earlier.
    hold_until: DateTime<Utc>,
    outbox_backoff: TimeDelta,
    refresh_sent: Option<DateTime<Utc>>,
}

impl<T: Transport, C: Clock> std::fmt::Debug for Session<T, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session").field("epoch", self.keys.current()).field("outbox", &self.state.outbox.len()).finish_non_exhaustive()
    }
}

/// A rekey answered and waiting for `hs.fin`.
struct Waiting {
    responder: Responder,
    /// The inner id of the `hs.init` it answers (its `hs.resp` in the
    /// outbox carries it as `re`).
    init: String,
}

/// Stored times fitted to `now`, so that a clock that went back (it was
/// fast when they were stored) leaves the state readable instead of
/// refused: a retired receive key is kept at most the retention from now,
/// and a waiting rekey counts as answered no later than now.
fn fit_ring(mut ring: KeyringState, now: DateTime<Utc>) -> KeyringState {
    for (_, until) in &mut ring.retired {
        *until = (*until).min(now + RECEIVE_KEY_RETENTION);
    }
    ring
}

fn fit_waiting((mut r, init): (ResponderState, String), now: DateTime<Utc>) -> Result<Waiting, HandshakeError> {
    r.since = r.since.min(now);
    Ok(Waiting { responder: Responder::restore(r, now)?, init })
}

/// What the engine keeps across an operation, to roll back if storing
/// fails.
struct Checkpoint {
    state: DeviceState,
    keys: KeyringState,
    awaiting: Vec<(ResponderState, String)>,
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
        let now = clock.now();
        let ring = fit_ring(KeyringState { current: state.epoch.clone(), retired: state.retired.clone() }, now);
        let keys = Keyring::restore(ring, now).map_err(|_| StoreError::Corrupt)?;
        let awaiting = state.awaiting.iter().cloned().map(|w| fit_waiting(w, now)).collect::<Result<Vec<_>, _>>().map_err(|_| StoreError::Corrupt)?;
        // At most the newest MAX_AWAITING.
        let mut s = Session {
            transport: make_transport(relay_key.clone()),
            clock,
            state,
            keys,
            awaiting,
            returned: Default::default(),
            relay_key,
            held: Vec::new(),
            dropped: Vec::new(),
            maybe_sent: Vec::new(),
            dirty: false,
            hold_until: now,
            outbox_backoff: OUTBOX_BACKOFF,
            refresh_sent: None,
        };
        // At most the newest MAX_AWAITING, the others aborted (their queued
        // hs.resp taken out of the outbox).
        s.trim_awaiting();
        Ok(Some(s))
    }

    /// Abort the oldest waiting rekeys past [`MAX_AWAITING`].
    fn trim_awaiting(&mut self) {
        while self.awaiting.len() > MAX_AWAITING {
            let oldest = self.awaiting[0].init.clone();
            self.abort_waiting(|w| w.init == oldest);
        }
    }

    /// An outbox entry that leaves unsent (evicted, refused for good,
    /// expired): reported, and if it is an `hs.resp`, its rekey can't be
    /// finished and stops waiting (the `hs.init` is left to be answered
    /// again).
    fn lost(&mut self, e: OutboxEntry) {
        if let Some(init) = &e.re {
            self.abort_waiting(|w| w.init == *init);
        }
        self.dropped.push(e.kind);
    }

    /// The device id the vault assigned.
    pub fn device_id(&self) -> Option<&str> {
        self.state.device_id.as_deref()
    }

    /// Whether the vault has refused this device.
    pub fn is_refused(&self) -> bool {
        self.state.refused
    }

    /// `Some(reason)` once the vault's `device.unlinked` has arrived (the
    /// reason is empty if it gave none): this device was removed, and the
    /// app erases its state and says so.
    pub fn unlinked(&self) -> Option<&str> {
        self.state.unlinked.as_deref()
    }

    /// The inbox events waiting to be handled, in order (also those already
    /// returned by a poll): for an app that lost track after a failed
    /// handle.
    pub fn pending_inbox(&self) -> &[Inner] {
        &self.state.inbox
    }

    /// The caller has acted on the inbox event `id`: it is removed, and
    /// that is stored. Unknown ids are ignored.
    pub fn handled(&mut self, store: &mut impl Persist, id: &str) -> Result<(), SessionError> {
        let Some(i) = self.state.inbox.iter().position(|e| e.id == id) else { return Ok(()) };
        let cp = self.checkpoint();
        self.state.inbox.remove(i);
        if let Err(e) = self.save(store) {
            self.rollback(cp);
            return Err(e.into());
        }
        self.returned.remove(id);
        Ok(())
    }

    /// This device's `device.session.end` waiting for its answer, if any
    /// (stored; see [`crate::access`]).
    pub fn access_end(&self) -> Option<&PendingEnd> {
        self.state.access_end.as_ref()
    }

    /// Whether the stored unanswered end didn't read when this session
    /// opened, and was taken as an end of everything with its attempts
    /// spent (see [`DeviceState::access_end_unreadable`]). For the app to
    /// log; it carries no stored value.
    pub fn access_end_unreadable(&self) -> bool {
        self.state.access_end_unreadable
    }

    /// Record (or clear) the unanswered `device.session.end`, and store it.
    pub(crate) fn set_access_end(&mut self, store: &mut impl Persist, end: Option<PendingEnd>) -> Result<(), SessionError> {
        let cp = self.checkpoint();
        self.state.access_end = end;
        if let Err(e) = self.save(store) {
            self.rollback(cp);
            return Err(e.into());
        }
        Ok(())
    }

    /// A new inner `id` (a ULID by this session's clock).
    pub(crate) fn new_id(&self) -> Result<String, SessionError> {
        new_ulid(self.clock.now()).map_err(|e| SessionError::Seal(HandshakeError::Suite(e)))
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

    /// The `type`s of outbox entries whose deposit failed in a way after
    /// which they may have been stored, since the last call: the caller can
    /// show them as "may have been sent" (the vault dedupes a resend).
    pub fn take_maybe_sent(&mut self) -> Vec<String> {
        std::mem::take(&mut self.maybe_sent)
    }

    /// Take the messages for the caller that a [`Session::request`] collected
    /// while it waited for its answer (the next [`Session::poll`] would
    /// return them first), without collecting more: for a caller that only
    /// sends requests and must not wait on a long-poll to see them.
    pub fn take_held(&mut self) -> Vec<Inner> {
        std::mem::take(&mut self.held)
    }

    fn own_pk(&self) -> VerifyingKey {
        self.relay_key.verifying_key()
    }

    fn awaiting_states(&self) -> Vec<(ResponderState, String)> {
        self.awaiting.iter().filter_map(|w| Some((w.responder.snapshot().ok()?, w.init.clone()))).collect()
    }

    /// Stop waiting for the rekeys `drop` picks: each is aborted, and its
    /// `hs.resp`, if still queued, is taken out of the outbox (an answer
    /// whose keys are gone must not go out).
    fn abort_waiting(&mut self, drop: impl Fn(&Waiting) -> bool) {
        let mut gone = Vec::new();
        self.awaiting.retain_mut(|w| {
            if drop(w) {
                w.responder.abort();
                gone.push(std::mem::take(&mut w.init));
                false
            } else {
                true
            }
        });
        if !gone.is_empty() {
            self.state.outbox.retain(|o| o.re.as_ref().is_none_or(|re| !gone.contains(re)));
            self.dirty = true;
        }
    }

    fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            state: self.state.clone(),
            keys: self.keys.snapshot(),
            awaiting: self.awaiting_states(),
            refresh_sent: self.refresh_sent,
            dropped: self.dropped.len(),
        }
    }

    fn rollback(&mut self, c: Checkpoint) {
        let now = self.clock.now();
        self.state = c.state;
        // The snapshots, fitted to the clock (which may have gone back),
        // restore: they were taken from a valid keyring and responders.
        // Should one not, the session keeps what it has rather than lose
        // keys.
        let restored = Keyring::restore(fit_ring(c.keys, now), now);
        debug_assert!(restored.is_ok(), "a keyring snapshot restores");
        if let Ok(k) = restored {
            self.keys = k;
        }
        let waiting: Result<Vec<_>, _> = c.awaiting.into_iter().map(|w| fit_waiting(w, now)).collect();
        debug_assert!(waiting.is_ok(), "a responder snapshot restores");
        if let Ok(w) = waiting {
            self.awaiting = w;
        }
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
        let asked = &self.state.asked;
        self.state.asked_kinds.retain(|id, _| asked.contains_key(id));
        let ring = self.keys.snapshot();
        self.state.epoch = ring.current;
        self.state.retired = ring.retired;
        self.state.awaiting = self.awaiting_states();
        self.state.save(store)?;
        self.dirty = false;
        Ok(())
    }

    /// Seal `inner` and put it in the outbox under `label` (not stored or
    /// sent yet). A token entry replaces a waiting one of its label: only
    /// the newest is worth sending. Past the cap the oldest is evicted
    /// and reported.
    fn queue(&mut self, label: &str, mut inner: Inner) -> Result<(), SessionError> {
        let env = self.keys.current_mut().seal(&mut inner).map_err(SessionError::Seal)?;
        if [RELAY_TOKEN_ISSUED, REFRESH_REQUEST].contains(&label) {
            self.state.outbox.retain(|o| o.kind != label);
        }
        self.push_outbox(OutboxEntry { kind: label.to_string(), payload: env, created: self.clock.now(), exp: inner.exp, re: None });
        Ok(())
    }

    /// Put an entry at the end of the outbox; past the cap the oldest is
    /// evicted and reported.
    fn push_outbox(&mut self, entry: OutboxEntry) {
        self.state.outbox.push(entry);
        while self.state.outbox.len() > OUTBOX_CAP {
            let evicted = self.state.outbox.remove(0);
            self.lost(evicted);
        }
        self.dirty = true;
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
    fn arm(&mut self, id: &str, kind: &str, exp: Option<DateTime<Utc>>) {
        let mut until = self.clock.now() + ASKED_KEEP;
        if let Some(e) = exp {
            until = until.min(e + MAX_CLOCK_SKEW_FUTURE);
        }
        self.state.asked.insert(id.to_string(), until);
        self.state.asked_kinds.insert(id.to_string(), kind.to_string());
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
            self.arm(&id, &kind, exp);
        }
        if let Err(e) = self.save(store) {
            self.rollback(cp);
            return Err(e.into());
        }
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
    /// first. Only those types: an ephemeral type needs an `exp` in the
    /// future (§8.5), and `vault.lock` one at most 60 seconds ahead (§8.6);
    /// both are checked before anything is sealed.
    pub async fn send_once(&mut self, store: &mut impl Persist, kind: &str, body: &str, exp: Option<DateTime<Utc>>) -> Result<String, SessionError> {
        if self.state.refused {
            return Err(SessionError::Refused);
        }
        let now = self.clock.now();
        let exp_ok = match (kind, exp) {
            ("vault.lock", Some(e)) => e > now && e - now <= VAULT_LOCK_MAX_EXP,
            (k, Some(e)) if !durable(k) => e > now,
            _ => false,
        };
        if !exp_ok {
            return Err(SessionError::BadExp);
        }
        let mut inner = self.inner(None, kind, body.to_string(), None, exp)?;
        let cp = self.checkpoint();
        let env = self.keys.current_mut().seal(&mut inner).map_err(SessionError::Seal)?;
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
        self.wait_for(store, id, timeout).await
    }

    /// [`Session::request`] again under the same inner `id` (an
    /// application retry, §8.6): the vault answers it from its cache
    /// instead of acting twice.
    pub async fn request_again(&mut self, store: &mut impl Persist, id: &str, kind: &str, body: &str, timeout: TimeDelta) -> Result<Inner, SessionError> {
        let id = self.resend(store, id, kind, body, true).await?;
        self.wait_for(store, id, timeout).await
    }

    /// Poll until the response to `id` arrives, up to `timeout`.
    async fn wait_for(&mut self, store: &mut impl Persist, id: String, timeout: TimeDelta) -> Result<Inner, SessionError> {
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
            if self.state.refused {
                // Removed (or refused) meanwhile: no answer will come.
                return Err(SessionError::Refused);
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
        if self.state.outbox.is_empty() || now < self.hold_until {
            return Ok(());
        }
        let to = self.state.vault.relay.clone();
        let token = Token::from_received(self.state.vault_token.to_string());
        let mut changed = false;
        let mut temporary = None;
        while let Some(e) = self.state.outbox.first().cloned() {
            if now - e.created > OUTBOX_MAX_AGE || e.exp.is_some_and(|x| now > x) {
                self.state.outbox.remove(0);
                self.lost(e);
                changed = true;
                continue;
            }
            let taken = match self.transport.deposit(&to.url, &to.mailbox, &token, &e.payload).await {
                Ok(_) => true,
                Err(d) => match &d.error {
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
                    _ if d.possibly_delivered => {
                        self.maybe_sent.push(e.kind.clone());
                        true
                    }
                    _ => false,
                },
            };
            self.state.outbox.remove(0);
            // An hs.resp the relay took (or may have): its hs.init is
            // handled now, and a retransmission of it is skipped. One that
            // was refused for good is lost (see `lost`).
            if !taken {
                self.lost(e);
            } else if let Some(init) = &e.re {
                self.state.seen_inner.insert(init.clone(), now + SEEN_KEEP);
            }
            changed = true;
        }
        if changed {
            self.save(store)?;
        }
        match temporary {
            Some((err, wait)) => {
                self.hold_until = now + wait.unwrap_or(self.outbox_backoff).max(self.outbox_backoff);
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
    /// [`Session::request`] if there are any (returned at once, not lost to
    /// an error here), otherwise one collected batch: events and requests
    /// from the vault, and responses to this device's requests. Their
    /// batch is stored and acked before they are returned, so the engine's
    /// own effects survive a crash, but the caller's handling of them does
    /// not (see the module doc). Also deposits the outbox and keeps the tokens fresh. A
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
        let msgs = match self.transport.collect(&self.state.relay_url, wait_secs, POLL_MAX).await {
            Ok(m) => m,
            Err(e) => {
                // The inbox is local and stored: what wasn't returned yet
                // is returned now, even with the relay out of reach.
                let pending = self.unreturned();
                return if pending.is_empty() { Err(e.into()) } else { Ok(pending) };
            }
        };
        let cp = self.checkpoint();
        let mut events = Vec::new();
        let mut acks = Vec::with_capacity(msgs.len());
        for m in &msgs {
            if self.handle(m, &mut events) {
                acks.push(&m.msg_id);
            }
        }
        self.maintain();
        if self.dirty {
            if let Err(e) = self.save(store) {
                // Nothing acked: the relay delivers the batch again.
                self.rollback(cp);
                return Err(e.into());
            }
        }
        for id in acks {
            // Best effort: what isn't acked comes again, and is a duplicate.
            let _ = self.transport.ack(&self.state.relay_url, id).await;
        }
        let flushed = self.flush(store).await;
        // The inbox events not yet returned (stored, so not lost) come
        // first, then the batch's other events.
        let mut out = self.unreturned();
        out.append(&mut events);
        match flushed {
            Ok(()) | Err(SessionError::Relay(_)) | Err(SessionError::Refused) => Ok(out),
            Err(e) => {
                // The batch is stored and acked: its events wait for the
                // next poll rather than be lost to this error.
                self.held.append(&mut out);
                Err(e)
            }
        }
    }

    /// The inbox events this session hasn't returned yet, marked returned.
    fn unreturned(&mut self) -> Vec<Inner> {
        let mut out = Vec::new();
        for e in &self.state.inbox {
            if self.returned.insert(e.id.clone()) {
                out.push(e.clone());
            }
        }
        out
    }

    /// Handle one collected message; what is for the caller goes to
    /// `events`. Anything new marks the state dirty. Returns whether to
    /// ack it: every message but one of a new epoch before its `hs.fin`.
    fn handle(&mut self, m: &Message, events: &mut Vec<Inner>) -> bool {
        if self.state.seen.contains_key(&m.msg_id) {
            return true;
        }
        let now = self.clock.now();
        let was_dirty = self.dirty;
        self.state.seen.insert(m.msg_id.clone(), now);
        self.dirty = true;
        // §6.3: only the vault's relay key may send to this device.
        let vault_pk = self.state.vault.relay.pk;
        let Some(sender) = decode_key(&m.sender).filter(|s| s.as_bytes() == vault_pk.as_bytes()) else { return true };
        let Ok(env) = Envelope::parse(&m.payload) else { return true };
        if env.mode() != Mode::Session {
            return true;
        }
        let pruned = self.prune_awaiting(now);
        let Ok((inner, current)) = self.keys.open(&env, now) else {
            let ack = self.handle_new_epoch(m, &env, &sender, now);
            if !ack {
                // Left as it was: nothing of it is stored (as Go's
                // handleBatch), so its redeliveries don't rewrite the state.
                self.dirty = was_dirty || pruned;
            }
            return ack;
        };
        match inner.kind.as_str() {
            TYPE_INIT => {
                self.handle_rekey(&m.payload, &inner, current, &sender, now);
                return true;
            }
            // A handshake message again (an hs.fin redeposited after its
            // epoch is up): nothing to do.
            TYPE_RESP | TYPE_FIN => return true,
            _ => {}
        }
        let ack = self.handle_inner(inner, now, events);
        if !ack {
            // The inbox is full: left for the relay to deliver again.
            self.state.seen.remove(&m.msg_id);
            self.dirty = was_dirty || pruned;
        }
        ack
    }

    /// A message no epoch of the keyring opens: an `hs.fin` for a waiting
    /// rekey, a message of its new epoch that came first, or junk.
    fn handle_new_epoch(&mut self, m: &Message, env: &Envelope, sender: &VerifyingKey, now: DateTime<Utc>) -> bool {
        let Some(i) = self.awaiting.iter().position(|w| w.responder.addressed(env)) else { return true };
        match self.awaiting[i].responder.handle_fin(&m.payload, sender, now) {
            Ok(done) => {
                // handle_fin gives an active epoch, which activate takes.
                let activated = self.keys.activate(done.epoch, now);
                debug_assert!(activated.is_ok(), "an established rekey activates");
                // Every other waiting rekey came from the epoch just
                // retired, which may no longer be rekeyed (§6.5): they stop
                // waiting, and their queued answers don't go out. (A
                // repeated hs.fin then opens under the new epoch and is
                // ignored.)
                self.abort_waiting(|_| true);
                true
            }
            // §6.3 (0.23.0): the new epoch isn't established yet. Leave it
            // unacked and unseen, without handling it: the relay delivers
            // it again after hs.fin. So too an hs.fin refused only because
            // its `ts` is ahead of this device's clock (which may be slow):
            // only the vault can make a message that decrypts under these
            // keys, and the vault doesn't send hs.fin again.
            Err(HandshakeError::Type) | Err(HandshakeError::Envelope(EnvelopeError::ClockFuture)) => {
                self.state.seen.remove(&m.msg_id);
                false
            }
            // Not a valid hs.fin (forged, stale): the rekey still waits.
            Err(_) => true,
        }
    }

    /// Answer a rekey `hs.init` (§6.5), once: only under the current
    /// epoch, and not while it is already answered (its `hs.resp` queued)
    /// or handled.
    fn handle_rekey(&mut self, raw: &[u8], inner: &Inner, current: bool, sender: &VerifyingKey, now: DateTime<Utc>) {
        if !current || self.state.refused {
            return;
        }
        let answered = self.state.seen_inner.contains_key(&inner.id) || self.state.outbox.iter().any(|o| o.re.as_deref() == Some(inner.id.as_str()));
        if answered {
            return;
        }
        let cfg = RekeyConfig {
            identity: SigningKey::from_bytes(&self.state.ik_seed),
            peer_ik: self.state.vault.ik,
            peer_relay_key: self.state.vault.relay.pk,
            collect_sender: *sender,
            pinned_suite: self.keys.current().suite(),
            policy: POLICY_VAULT_TO_DEVICE,
            id: None,
            now,
        };
        let Ok((responder, resp)) = answer_rekey(raw, inner, self.keys.current(), &cfg) else { return };
        self.push_outbox(OutboxEntry { kind: TYPE_RESP.into(), payload: resp, created: now, exp: None, re: Some(inner.id.clone()) });
        self.awaiting.push(Waiting { responder, init: inner.id.clone() });
        self.trim_awaiting();
    }

    /// Abort the rekeys whose `hs.fin` can't come any more (16 days): their
    /// epoch's messages must not stay unacked for it (§6.5). Says whether
    /// any went.
    fn prune_awaiting(&mut self, now: DateTime<Utc>) -> bool {
        let before = self.awaiting.len();
        self.abort_waiting(|w| w.responder.expired(now));
        self.awaiting.len() != before
    }

    /// An opened message of an established epoch, other than a handshake
    /// message. Returns whether to ack it: all but an inbox event that
    /// finds the inbox full.
    fn handle_inner(&mut self, mut inner: Inner, now: DateTime<Utc>, events: &mut Vec<Inner>) -> bool {
        // §8.4, §8.5: by the type's class (an ephemeral type without exp
        // is refused).
        if inner.check_time(now, durable(&inner.kind)).is_err() {
            return true;
        }
        // §8.2, the inner id: a duplicate is dropped, unless it answers a
        // request still waiting (a resent request gets the cached answer).
        let waiting = inner.response.as_ref().is_some_and(|r| self.state.asked.contains_key(&r.re));
        if self.state.seen_inner.contains_key(&inner.id) && !waiting {
            return true;
        }
        let for_inbox = inner.response.is_none() && INBOX_TYPES.contains(&inner.kind.as_str());
        let unlinking = for_inbox && inner.kind == DEVICE_UNLINKED;
        if for_inbox && !unlinking {
            // A removed device acts on nothing more.
            if self.state.unlinked.is_some() {
                return true;
            }
            // Too many or too large: left for the relay. (The removal is
            // never held back: it is terminal, and at most one is kept.)
            if self.state.inbox.len() >= INBOX_CAP || inner.body.len() > INBOX_MAX_BODY {
                return false;
            }
        }
        let keep = match inner.exp {
            Some(exp) => (now + EPHEMERAL_KEEP).max(exp + MAX_CLOCK_SKEW_FUTURE),
            // As long as the time check could pass it (a `ts` ahead of now
            // by up to the skew stays fresh that much longer).
            None => now.max(inner.ts) + SEEN_KEEP,
        };
        self.state.seen_inner.insert(inner.id.clone(), keep);
        if let Some(r) = &inner.response {
            // §8.1: a response to no pending request is dropped, and so is
            // one whose type isn't its request's (a response has its
            // request's type).
            let kind_ok = self.state.asked_kinds.get(&r.re).is_none_or(|k| *k == inner.kind);
            if !kind_ok || self.state.asked.remove(&r.re).is_none() {
                return true;
            }
            self.state.asked_kinds.remove(&r.re);
            if inner.kind == RELAY_TOKEN_REFRESH {
                self.store_vault_token(&inner.body, now);
                return true;
            }
            events.push(inner);
            return true;
        }
        if for_inbox {
            if unlinking {
                if self.state.unlinked.is_some() {
                    return true; // already removed: a later notice adds nothing
                }
                let reason = self.unlink(&inner.body);
                if inner.body.len() > INBOX_MAX_BODY {
                    inner.body = Zeroizing::new(Builder::new().string("reason", &reason).finish());
                }
            }
            // Only what the store can write back (it can't fail for a parsed
            // event; dropped otherwise rather than lose the state).
            if inner.marshal(Mode::Session).is_ok() {
                // Returned with the batch, once it is stored and acked.
                self.state.inbox.push(inner);
            }
            return true;
        }
        match inner.kind.as_str() {
            RELAY_TOKEN_ISSUED => self.store_vault_token(&inner.body, now),
            RELAY_TOKEN_REFRESH if self.state.refused => {} // refused: nothing more is sent
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
        true
    }

    /// The vault says this device was removed (§7.4): refused from now on,
    /// and what waits in the outbox is dropped and reported. Nothing is
    /// erased here: the app does that, and tells the person.
    fn unlink(&mut self, body: &str) -> String {
        let reason = strict_json::parse_object(body.as_bytes())
            .ok()
            .and_then(|o| o.opt_string("reason").ok().flatten())
            .filter(|r| r.len() <= MAX_REASON && r.bytes().all(|b| b.is_ascii_graphic() || b == b' '))
            .unwrap_or_default();
        self.state.unlinked.get_or_insert(reason.clone());
        // Nothing else waiting in the inbox is acted on any more.
        self.state.inbox.retain(|e| e.kind == DEVICE_UNLINKED);
        self.state.refused = true;
        let lost: Vec<String> = self.state.outbox.drain(..).map(|o| o.kind).collect();
        self.dropped.extend(lost);
        self.abort_waiting(|_| true);
        reason
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
                    self.arm(&id, RELAY_TOKEN_REFRESH, None);
                    self.refresh_sent = Some(now);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
