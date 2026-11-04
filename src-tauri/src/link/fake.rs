//! A fake vault and relay for testing the [`Link`] (tests only): a paired
//! device's state made by hand, the vault's side of its session epoch, and
//! a transport that answers `vault.status` from that side, or refuses the
//! device (`token_revoked`) on request. Every key here is TEST-ONLY.

use std::sync::{Arc, Mutex};

use chrono::{DateTime, TimeDelta, Utc};
use ed25519_dalek::SigningKey;
use vettid_device::pairing::SystemClock;
use vettid_device::session::Session;
use vettid_device::store::{DeviceState, Phase, VaultRecord};
use vettid_device::transport::Transport;
use vettid_relay::auth::{encode_key, mailbox_id};
use vettid_relay::client::{DepositError, Message, Registration, RelayError};
use vettid_relay::token::Token;
use vettid_vms::envelope::{new_ulid, Envelope, Inner, Response, Status};
use vettid_vms::handshake::{Epoch, RelayAddr, Role, Schedule, POLICY_VAULT_TO_DEVICE};
use vettid_vms::strict_json::Builder;
use vettid_vms::suite::kem::PrivateKey;
use zeroize::Zeroizing;

use super::Link;
use crate::credential::device_store;

const VAULT_RELAY: &str = "https://relay.example.test";

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
    collects: usize,
    n: u64,
}

impl State {
    /// Put an inner message from the vault in the device's mailbox.
    fn send(&mut self, mut inner: Inner) {
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

    fn inner(kind: &str, response: Option<Response>, body: String) -> Inner {
        let now = Utc::now();
        Inner { id: new_ulid(now).expect("ulid"), kind: kind.into(), ts: now, seq: None, response, exp: None, body: Zeroizing::new(body) }
    }

    fn status_body(&self) -> String {
        match &self.session {
            None => "{\"session\":null}".into(),
            Some((id, exp)) => {
                let s = Builder::new().string("session_id", id).string("expires_at", &vettid_vms::envelope::format_ts(*exp)).finish();
                Builder::new().raw("session", &s).finish()
            }
        }
    }
}

/// The fake vault, shared with its transport.
#[derive(Clone)]
pub(crate) struct FakeVault(Arc<Mutex<State>>);

impl FakeVault {
    /// A paired device in `dir` (its state saved through the device store
    /// with test keys) and its open [`Link`] against this vault.
    pub(crate) fn paired(dir: &std::path::Path) -> (FakeVault, Link<FakeVault, SystemClock>) {
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
            access_end: None,
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
            collects: 0,
            n: 0,
        })));
        let t = fake.clone();
        let session = Session::open(&mut store, move |_| t, SystemClock).expect("open").expect("paired");
        (fake, Link::new(session, store))
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
            let m = State::inner("device.unlinked", None, "{}".into());
            s.send(m);
        }
        s.collects = 0;
    }

    /// How many collects since [`FakeVault::revoke`].
    pub(crate) fn collects(&self) -> usize {
        self.lock().collects
    }
}

impl Transport for FakeVault {
    async fn register(&self, _base: &str) -> Result<Registration, RelayError> {
        Err(RelayError::Invalid)
    }

    async fn deposit(&self, _base: &str, _mailbox: &str, _token: &Token, payload: &[u8]) -> Result<String, DepositError> {
        let mut s = self.lock();
        if s.revoked {
            let error = RelayError::Relay { status: 403, code: "token_revoked".into(), retry_after: None, quota: None };
            return Err(DepositError { error, possibly_delivered: false });
        }
        let env = Envelope::parse(payload).expect("an envelope");
        let inner = s.epoch.open(&env).expect("under the session epoch");
        if inner.response.is_none() && inner.kind == "vault.status" {
            let body = s.status_body();
            let answer = State::inner("vault.status", Some(Response { re: inner.id.clone(), status: Status::Ok }), body);
            s.send(answer);
        }
        s.n += 1;
        Ok(format!("d{}", s.n))
    }

    async fn collect(&self, _base: &str, _wait_secs: u64, _max: u32) -> Result<Vec<Message>, RelayError> {
        let mut s = self.lock();
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
