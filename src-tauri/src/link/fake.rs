//! A fake vault and relay for testing the [`Link`] (tests only): a paired
//! device's state made by hand, the vault's side of its session epoch, and
//! a transport that answers `vault.status` from that side, or refuses the
//! device (`token_revoked`) on request. It can also lock (it then answers
//! nothing, as a locked vault collects nothing, VAULT-MESSAGING §12.1),
//! hold (`owner_check` in its status, `owner_check_required` answers), send
//! `vault.locking` and `vault.held`, and go out of reach. Its clock is
//! monotonic: each message it stamps is at least 1 ms after the one before
//! (#90). Every key here is TEST-ONLY.

use std::sync::{Arc, Mutex};

use chrono::{DateTime, TimeDelta, Utc};
use ed25519_dalek::SigningKey;
use vettid_device::pairing::SystemClock;
use vettid_device::session::Session;
use vettid_device::access::Access;
use vettid_device::store::{DeviceState, PendingEnd, Phase, VaultRecord};
use vettid_device::transport::Transport;
use vettid_relay::auth::{encode_key, mailbox_id};
use vettid_relay::client::{DepositError, Message, Registration, RelayError};
use vettid_relay::token::Token;
use vettid_vms::envelope::{format_ts, new_ulid, parse_ts, Envelope, Inner, Response, Status};
use vettid_vms::handshake::{Epoch, RelayAddr, Role, Schedule, POLICY_VAULT_TO_DEVICE};
use vettid_vms::strict_json::Builder;
use vettid_vms::suite::kem::PrivateKey;
use zeroize::Zeroizing;

use super::Link;
use crate::credential::device_store;

const VAULT_RELAY: &str = "https://relay.example.test";

/// The `unlock_id` the fake vault opens with (TEST-ONLY).
pub(crate) const UNLOCK_1: &str = "0123456789abcdef0123456789abcdef";

/// How the fake vault treats `device.session.end`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EndMode {
    /// Answer `ok {}` and end the session.
    Answer,
    /// Never answer, and change nothing.
    Silent,
    /// Never answer; an end that names a session (the resend under a new
    /// id) finds this newer session granted meanwhile.
    Replace(String, DateTime<Utc>),
}

struct State {
    /// The vault's side of the session epoch.
    epoch: Epoch,
    vault_relay: SigningKey,
    /// What the device's mailbox holds.
    mailbox: Vec<Message>,
    /// The session `vault.status` names.
    session: Option<(String, DateTime<Utc>)>,
    /// Refuse every deposit with `token_revoked`.
    revoked: bool,
    end_mode: EndMode,
    /// `vault.status` has no `session` member (a vault before 0.41.0).
    absent: bool,
    /// What answering `device.session.request` brings: a grant of this
    /// session, or (`deny`) a denial.
    on_request: Option<(String, DateTime<Utc>)>,
    deny: bool,
    collects: usize,
    n: u64,
    /// The `unlock_id` `vault.status` names (written as is, so a test can
    /// give a malformed one); `None`: no member (a vault before release L).
    unlock_id: Option<String>,
    /// `vault.status`'s `owner_check` member, raw JSON; `None`: no member.
    owner_check: Option<String>,
    /// Locked: deposits are taken by the relay, and nothing is answered.
    locked: bool,
    /// Held: requests other than `vault.status` and `device.session.end`
    /// are answered `owner_check_required` (§3.6.3).
    held: bool,
    /// Out of reach: every deposit and collect fails to connect.
    offline: bool,
    /// The type of every message the relay took from the device.
    deposited: Vec<String>,
    /// The last `ts` this vault put on a message.
    last_ts: DateTime<Utc>,
    /// What happens once the next `device.session.request` is answered.
    after_request: Option<AfterRequest>,
}

/// What the fake vault does once it has answered a request for a session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AfterRequest {
    /// Lock, with its notice ([`FakeVault::lock_vault`]).
    Lock,
    /// Enter the hold, with a `vault.held` of this body.
    Hold(String),
}

/// An `owner_check` member with `state`, `hold` and a deadline an hour
/// ago (or ahead, for `ok`), plus `extra` members (raw, after a comma).
pub(crate) fn owner_check(state: &str, hold: bool, extra: &str) -> String {
    let deadline = if state == "ok" { Utc::now() + TimeDelta::hours(1) } else { Utc::now() - TimeDelta::hours(1) };
    let comma = if extra.is_empty() { "" } else { "," };
    format!(
        r#"{{"state":"{state}","deadline":"{}","interval_seconds":86400,"failures":0,"hold":{hold}{comma}{extra}}}"#,
        format_ts(deadline)
    )
}

impl State {
    /// See [`FakeVault::lock_vault`].
    fn lock_now(&mut self, reason: Option<&str>) -> DateTime<Utc> {
        let mut b = Builder::new();
        if let Some(id) = &self.unlock_id {
            b = b.string("unlock_id", id);
        }
        if let Some(r) = reason {
            b = b.string("reason", r);
        }
        let mut m = self.inner("vault.locking", None, b.finish());
        m.exp = Some(m.ts + TimeDelta::seconds(60));
        let ts = m.ts;
        self.send(m);
        self.locked = true;
        ts
    }

    /// The vault's clock: now, but at least 1 ms after the last message it
    /// stamped (#90), so two of its messages never share a `ts` by chance.
    /// In whole milliseconds, as on the wire.
    fn now(&mut self) -> DateTime<Utc> {
        let wire = parse_ts(&format_ts(Utc::now())).expect("a wire ts");
        let t = wire.max(self.last_ts + TimeDelta::milliseconds(1));
        self.last_ts = t;
        t
    }

    /// Put an inner message from the vault in the device's mailbox.
    fn send(&mut self, mut inner: Inner) {
        self.last_ts = self.last_ts.max(inner.ts);
        let payload = self.epoch.seal(&mut inner).expect("seal");
        self.n += 1;
        self.mailbox.push(Message {
            msg_id: format!("m{}", self.n),
            deposited_at: String::new(),
            sender: encode_key(&self.vault_relay.verifying_key()),
            jti: None,
            payload,
        });
    }

    /// A message stamped by the vault's clock.
    fn inner(&mut self, kind: &str, response: Option<Response>, body: String) -> Inner {
        let ts = self.now();
        Self::inner_at(kind, response, body, ts)
    }

    fn inner_at(kind: &str, response: Option<Response>, body: String, ts: DateTime<Utc>) -> Inner {
        Inner { id: new_ulid(ts).expect("ulid"), kind: kind.into(), ts, seq: None, response, exp: None, body: Zeroizing::new(body) }
    }

    fn session_body(id: &str, exp: DateTime<Utc>) -> String {
        Builder::new().string("session_id", id).string("expires_at", &format_ts(exp)).finish()
    }

    fn status_body(&self) -> String {
        let mut b = Builder::new();
        if let Some(id) = &self.unlock_id {
            b = b.string("unlock_id", id);
        }
        if let Some(oc) = &self.owner_check {
            b = b.raw("owner_check", oc);
        }
        if !self.absent {
            b = match &self.session {
                None => b.raw("session", "null"),
                Some((id, exp)) => b.raw("session", &Self::session_body(id, *exp)),
            };
        }
        b.finish()
    }
}

/// The fake vault, shared with its transport.
#[derive(Clone)]
pub(crate) struct FakeVault(Arc<Mutex<State>>);

impl FakeVault {
    /// A paired device in `dir` (its state saved through the device store
    /// with test keys) and its open [`Link`] against this vault.
    pub(crate) fn paired(dir: &std::path::Path) -> (FakeVault, Link<FakeVault, SystemClock>) {
        Self::paired_with(dir, false)
    }

    /// [`FakeVault::paired`], with a `device.session.end` stored unanswered
    /// by an earlier run if `end_pending`.
    pub(crate) fn paired_with(dir: &std::path::Path, end_pending: bool) -> (FakeVault, Link<FakeVault, SystemClock>) {
        let now = Utc::now();
        let sched = Schedule::derive(&[1; 32], &[2; 32], [3; 32], [4; 32]);
        let (mut device, mut vault) = (
            Epoch::new(&sched, Role::Initiator, 2, POLICY_VAULT_TO_DEVICE, now),
            Epoch::new(&sched, Role::Responder, 2, POLICY_VAULT_TO_DEVICE, now),
        );
        device.activate(now);
        vault.activate(now);
        let vault_relay = SigningKey::from_bytes(&[9; 32]);
        let vault_ik = SigningKey::from_bytes(&[8; 32]);
        let kem = PrivateKey::from_seed(&[7; 32]).expect("kem");
        let state = DeviceState {
            ik_seed: Zeroizing::new([5; 32]),
            kem_seed: Zeroizing::new([6; 32]),
            relay_seed: Zeroizing::new([4; 32]),
            relay_url: VAULT_RELAY.into(),
            vault: VaultRecord {
                ik: vault_ik.verifying_key(),
                kem: kem.public().clone(),
                relay: RelayAddr { url: VAULT_RELAY.into(), mailbox: mailbox_id(&vault_relay.verifying_key()), pk: vault_relay.verifying_key() },
            },
            vault_token: Zeroizing::new("test-token".into()),
            vault_token_exp: now + TimeDelta::days(20),
            issued_exp: now + TimeDelta::days(20),
            phase: Phase::Paired,
            pairing_deadline: now,
            device_id: Some("dev-1".into()),
            vault_id: Some("vault-1".into()),
            epoch: device.snapshot(),
            retired: Vec::new(),
            awaiting: Vec::new(),
            seen: Default::default(),
            seen_inner: Default::default(),
            outbox: Vec::new(),
            asked: Default::default(),
            asked_kinds: Default::default(),
            refused: false,
            unlinked: None,
            inbox: Vec::new(),
            access_end: end_pending.then(|| PendingEnd { id: new_ulid(now).expect("ulid"), session_id: None, attempts: 1 }),
            access_end_unreadable: false,
        };
        let mut store = device_store::tests::store_for_tests(dir);
        state.save(&mut store).expect("save");
        let fake = FakeVault(Arc::new(Mutex::new(State {
            epoch: vault,
            vault_relay,
            mailbox: Vec::new(),
            session: None,
            revoked: false,
            end_mode: EndMode::Answer,
            absent: false,
            on_request: None,
            deny: false,
            collects: 0,
            n: 0,
            unlock_id: Some(UNLOCK_1.into()),
            owner_check: Some(owner_check("ok", false, "")),
            locked: false,
            held: false,
            offline: false,
            deposited: Vec::new(),
            last_ts: now - TimeDelta::minutes(1),
            after_request: None,
        })));
        let t = fake.clone();
        let session = Session::open(&mut store, move |_| t, SystemClock).expect("open").expect("paired");
        let mut link = Link::new(session, store);
        // Unanswered requests (an end the vault ignores) wait 1 s, not 30.
        link.access = Access::with_timeout(TimeDelta::seconds(1));
        (fake, link)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.lock().unwrap()
    }

    /// The session `vault.status` names from now on.
    pub(crate) fn set_session(&self, s: Option<(&str, DateTime<Utc>)>) {
        self.lock().session = s.map(|(id, t)| (id.to_string(), t));
    }

    /// Refuse every deposit from now on; with `unlink`, first put a
    /// `device.unlinked` in the device's mailbox.
    pub(crate) fn revoke(&self, unlink: bool) {
        let mut s = self.lock();
        s.revoked = true;
        if unlink {
            let m = s.inner("device.unlinked", None, "{}".into());
            s.send(m);
        }
        s.collects = 0;
    }

    /// Put a vault event, stamped `ts`, in the device's mailbox.
    pub(crate) fn event(&self, kind: &str, body: &str, ts: DateTime<Utc>) {
        let m = State::inner_at(kind, None, body.into(), ts);
        self.lock().send(m);
    }

    /// Put a vault event stamped by the vault's clock in the mailbox, with
    /// `exp` (an ephemeral type needs one, §8.5); returns its `ts`.
    pub(crate) fn event_now(&self, kind: &str, body: &str, exp: Option<DateTime<Utc>>) -> DateTime<Utc> {
        let mut s = self.lock();
        let mut m = s.inner(kind, None, body.into());
        m.exp = exp;
        let ts = m.ts;
        s.send(m);
        ts
    }

    /// Answer the next `device.session.request`, then grant `session` (and
    /// name it in `vault.status`).
    pub(crate) fn grant_on_request(&self, session: (&str, DateTime<Utc>)) {
        self.lock().on_request = Some((session.0.to_string(), session.1));
    }

    /// Answer the next `device.session.request`, then deny it.
    pub(crate) fn deny_on_request(&self) {
        self.lock().deny = true;
    }

    /// How `device.session.end` is treated from now on.
    pub(crate) fn end_mode(&self, m: EndMode) {
        self.lock().end_mode = m;
    }

    /// `vault.status` without its `session` member from now on.
    pub(crate) fn absent_session_member(&self) {
        self.lock().absent = true;
    }

    /// The `unlock_id` `vault.status` names from now on (`None`: none).
    pub(crate) fn set_unlock_id(&self, id: Option<&str>) {
        self.lock().unlock_id = id.map(str::to_string);
    }

    /// `vault.status`'s `owner_check` from now on (raw; `None`: none).
    /// [`owner_check`] makes one.
    pub(crate) fn set_owner_check(&self, oc: Option<String>) {
        self.lock().owner_check = oc;
    }

    /// Hold: `owner_check` `held` in `vault.status`, with `extra` members,
    /// and every request but `vault.status` and `device.session.end`
    /// answered `owner_check_required` (§3.6.3). `false`: back to `ok`.
    pub(crate) fn hold(&self, on: bool, extra: &str) {
        let mut s = self.lock();
        s.held = on;
        s.owner_check = Some(if on { owner_check("held", true, extra) } else { owner_check("ok", false, "") });
    }

    /// Lock: send `vault.locking {unlock_id, reason?}` naming the current
    /// unlock (exp 60 s ahead, §10.2), then answer nothing. Returns the
    /// notice's `ts`.
    pub(crate) fn lock_vault(&self, reason: Option<&str>) -> DateTime<Utc> {
        self.lock().lock_now(reason)
    }

    /// Lock without a notice (the vault skipped it, or it expired before
    /// it was collected): answer nothing from now on.
    pub(crate) fn lock_silently(&self) {
        self.lock().locked = true;
    }

    /// Unlock under a new `unlock_id`: answering again.
    pub(crate) fn unlock(&self, id: &str) {
        let mut s = self.lock();
        s.locked = false;
        s.unlock_id = Some(id.into());
    }

    /// What happens once the next `device.session.request` is answered.
    pub(crate) fn after_request(&self, a: AfterRequest) {
        self.lock().after_request = Some(a);
    }

    /// Out of reach (`true`) or back (`false`).
    pub(crate) fn offline(&self, on: bool) {
        self.lock().offline = on;
    }

    /// How many collects since [`FakeVault::revoke`].
    pub(crate) fn collects(&self) -> usize {
        self.lock().collects
    }

    /// The type of every message the relay took from the device.
    pub(crate) fn deposited(&self) -> Vec<String> {
        self.lock().deposited.clone()
    }
}

impl Transport for FakeVault {
    async fn register(&self, _base: &str) -> Result<Registration, RelayError> {
        Err(RelayError::Invalid)
    }

    async fn deposit(&self, _base: &str, _mailbox: &str, _token: &Token, payload: &[u8]) -> Result<String, DepositError> {
        let mut s = self.lock();
        if s.offline {
            return Err(DepositError { error: RelayError::Connect, possibly_delivered: false });
        }
        if s.revoked {
            let error = RelayError::Relay { status: 403, code: "token_revoked".into(), retry_after: None, quota: None };
            return Err(DepositError { error, possibly_delivered: false });
        }
        let env = Envelope::parse(payload).expect("an envelope");
        let inner = s.epoch.open(&env).expect("under the session epoch");
        s.deposited.push(inner.kind.clone());
        s.n += 1;
        let taken = format!("d{}", s.n);
        if s.locked {
            // A locked vault collects nothing (§12.1): it waits at the relay.
            return Ok(taken);
        }
        let ok = |inner: &Inner| Some(Response { re: inner.id.clone(), status: Status::Ok });
        if inner.response.is_none() && s.held && !["vault.status", "device.session.end"].contains(&inner.kind.as_str()) {
            let refused = Some(Response { re: inner.id.clone(), status: Status::Error { code: "owner_check_required".into(), message: None } });
            let answer = s.inner(&inner.kind, refused, "{}".into());
            s.send(answer);
            return Ok(taken);
        }
        if inner.response.is_none() && inner.kind == "vault.status" {
            let body = s.status_body();
            let answer = s.inner("vault.status", ok(&inner), body);
            s.send(answer);
        }
        if inner.response.is_none() && inner.kind == "device.session.end" {
            match s.end_mode.clone() {
                EndMode::Answer => {
                    let answer = s.inner("device.session.end", ok(&inner), "{}".into());
                    s.send(answer);
                    s.session = None;
                }
                EndMode::Silent => {}
                EndMode::Replace(id, exp) => {
                    if inner.body.contains("session_id") {
                        s.session = Some((id, exp));
                    }
                }
            }
        }
        if inner.response.is_none() && inner.kind == "device.session.request" {
            let now = s.now();
            let body = Builder::new().string("request_id", "req-1").string("exp", &format_ts(now + TimeDelta::minutes(5))).finish();
            let answer = State::inner_at("device.session.request", ok(&inner), body, now);
            s.send(answer);
            if let Some((id, exp)) = s.on_request.take() {
                let grant = s.inner("device.session.granted", None, State::session_body(&id, exp));
                s.send(grant);
                s.session = Some((id, exp));
            }
            if std::mem::take(&mut s.deny) {
                let denial = s.inner("device.session.ended", None, "{\"reason\":\"denied\"}".into());
                s.send(denial);
            }
            match s.after_request.take() {
                Some(AfterRequest::Lock) => {
                    s.lock_now(None);
                }
                Some(AfterRequest::Hold(body)) => {
                    let held = s.inner("vault.held", None, body);
                    s.send(held);
                    s.held = true;
                    s.owner_check = Some(owner_check("held", true, ""));
                }
                None => {}
            }
        }
        Ok(taken)
    }

    async fn collect(&self, _base: &str, _wait_secs: u64, _max: u32) -> Result<Vec<Message>, RelayError> {
        let mut s = self.lock();
        if s.offline {
            return Err(RelayError::Connect);
        }
        s.collects += 1;
        Ok(std::mem::take(&mut s.mailbox))
    }

    async fn ack(&self, _base: &str, _msg_id: &str) -> Result<(), RelayError> {
        Ok(())
    }

    async fn get_claim(&self, _base: &str, _claim_id: &str) -> Result<Vec<u8>, RelayError> {
        Err(RelayError::Invalid)
    }
}
