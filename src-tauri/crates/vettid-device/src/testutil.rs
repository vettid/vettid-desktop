//! Test helpers: an in-memory relay with fault injection, a ticking clock,
//! and a test vault written from VAULT-MESSAGING §6.3/§6.4/§6.7 with the
//! vault's test keys.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, TimeDelta, Utc};
use ed25519_dalek::SigningKey;
use vettid_relay::auth::{encode_key, mailbox_id};
use vettid_relay::client::{DepositError, Limits, Message, Registration, RelayError};
use vettid_relay::token::Token;
use vettid_vms::envelope::{new_ulid, open_sealed, Envelope, Inner, Mode, Sealer};
use vettid_vms::handshake::{
    check_sas_commit, sas, sign_resp, th, th1, verify_fin, Epoch, Fin, Init, Principal, Purpose, RelayAddr, Resp, Role, Schedule,
    POLICY_VAULT_TO_DEVICE, TYPE_FIN, TYPE_RESP,
};
use vettid_vms::invite::{Bundle, Kind, Qr};
use vettid_vms::strict_json::Builder;
use vettid_vms::suite::aead::{fresh_nonce, seal_x};
use vettid_vms::suite::kem::PrivateKey;
use vettid_vms::suite::kid::ANONYMOUS;
use vettid_vms::suite::{LABEL_BUNDLE, LABEL_HS_KE, LABEL_HS_KS};
use zeroize::Zeroizing;

use crate::pairing::*;
use crate::store::{Persist, StoreError};
use crate::transport::Transport;
use crate::store::MemStore;
use crate::token::mint_for_vault;

pub(crate) const URL: &str = "https://relay.vettid.org";

/// A relay in memory: mailboxes and claims, no token checks, and a log of
/// what happened, in order.
#[derive(Default)]
pub(crate) struct Relay {
    pub(crate) mailboxes: HashMap<String, Vec<Message>>,
    pub(crate) claims: HashMap<String, Vec<u8>>,
    pub(crate) fetches: usize,
    pub(crate) log: Vec<String>,
}

/// Failures to inject into one party's relay calls.
#[derive(Default)]
pub(crate) struct Faults {
    /// Fail this many collects (retryable).
    pub(crate) collects: usize,
    /// Fail this many acks (retryable).
    pub(crate) acks: usize,
    /// Fail the deposit with this index (0-based), certainly undelivered.
    pub(crate) deposit: Option<usize>,
    /// Fail this many deposits temporarily (no connection: not delivered).
    pub(crate) temporary: usize,
    /// Answer every deposit token_revoked.
    pub(crate) revoked: bool,
    /// Answer this many deposits 429 quota_exceeded.
    pub(crate) quota: usize,
    pub(crate) deposits_seen: usize,
}

#[derive(Clone)]
pub(crate) struct Mem {
    pub(crate) relay: Arc<Mutex<Relay>>,
    pub(crate) key: SigningKey,
    pub(crate) name: &'static str,
    pub(crate) faults: Arc<Mutex<Faults>>,
}

impl Mem {
    pub(crate) fn mailbox(&self) -> String {
        mailbox_id(&self.key.verifying_key())
    }
}

impl Transport for Mem {
    async fn register(&self, _base: &str) -> Result<Registration, RelayError> {
        self.relay.lock().unwrap().mailboxes.entry(self.mailbox()).or_default();
        Ok(Registration { mailbox_id: self.mailbox(), limits: Limits::default(), created: true })
    }
    async fn deposit(&self, _base: &str, mailbox: &str, _token: &Token, payload: &[u8]) -> Result<String, DepositError> {
        {
            let mut f = self.faults.lock().unwrap();
            let n = f.deposits_seen;
            f.deposits_seen += 1;
            if f.deposit == Some(n) {
                let error = RelayError::Relay { status: 400, code: "bad_request".into(), retry_after: None, quota: None };
                return Err(DepositError { error, possibly_delivered: false });
            }
            if f.revoked {
                let error = RelayError::Relay { status: 403, code: "token_revoked".into(), retry_after: None, quota: None };
                return Err(DepositError { error, possibly_delivered: false });
            }
            if f.quota > 0 {
                f.quota -= 1;
                let error = RelayError::Relay { status: 429, code: "quota_exceeded".into(), retry_after: Some(600), quota: Some("mailbox".into()) };
                return Err(DepositError { error, possibly_delivered: false });
            }
            if f.temporary > 0 {
                f.temporary -= 1;
                return Err(DepositError { error: RelayError::Connect, possibly_delivered: false });
            }
        }
        let id = new_ulid(Utc::now()).unwrap();
        let mut r = self.relay.lock().unwrap();
        r.log.push(format!("{} deposit", self.name));
        let Some(mb) = r.mailboxes.get_mut(mailbox) else {
            let error = RelayError::Relay { status: 404, code: "mailbox_unknown".into(), retry_after: None, quota: None };
            return Err(DepositError { error, possibly_delivered: false });
        };
        mb.push(Message { msg_id: id.clone(), deposited_at: "t".into(), sender: encode_key(&self.key.verifying_key()), jti: None, payload: payload.to_vec() });
        Ok(id)
    }
    async fn collect(&self, _base: &str, _wait: u64, max: u32) -> Result<Vec<Message>, RelayError> {
        {
            let mut f = self.faults.lock().unwrap();
            if f.collects > 0 {
                f.collects -= 1;
                return Err(RelayError::Transport);
            }
        }
        let msgs: Vec<Message> = self.relay.lock().unwrap().mailboxes.get(&self.mailbox()).map(|m| m.iter().take(max as usize).cloned().collect()).unwrap_or_default();
        if msgs.is_empty() {
            tokio::task::yield_now().await;
        }
        Ok(msgs)
    }
    async fn ack(&self, _base: &str, msg_id: &str) -> Result<(), RelayError> {
        {
            let mut f = self.faults.lock().unwrap();
            if f.acks > 0 {
                f.acks -= 1;
                return Err(RelayError::Transport);
            }
        }
        let mut r = self.relay.lock().unwrap();
        r.log.push(format!("{} ack", self.name));
        if let Some(mb) = r.mailboxes.get_mut(&self.mailbox()) {
            mb.retain(|m| m.msg_id != msg_id);
        }
        Ok(())
    }
    async fn get_claim(&self, _base: &str, claim_id: &str) -> Result<Vec<u8>, RelayError> {
        let mut r = self.relay.lock().unwrap();
        r.fetches += 1;
        r.claims.remove(claim_id).ok_or(RelayError::Relay { status: 404, code: "claim_unknown".into(), retry_after: None, quota: None })
    }
}

/// A store that logs its saves into the relay's log, to check the order.
pub(crate) struct LoggingStore {
    pub(crate) inner: MemStore,
    pub(crate) relay: Arc<Mutex<Relay>>,
}

impl Persist for LoggingStore {
    fn save(&mut self, data: &[u8]) -> Result<(), StoreError> {
        self.relay.lock().unwrap().log.push("save".into());
        self.inner.save(data)
    }
    fn load(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, StoreError> {
        self.inner.load()
    }
    fn clear(&mut self) -> Result<(), StoreError> {
        self.relay.lock().unwrap().log.push("clear".into());
        self.inner.clear()
    }
}

/// A clock that moves one second per reading (so every wait ends), offset
/// from real time by `offset` seconds.
#[derive(Clone)]
pub(crate) struct Ticking {
    pub(crate) start: DateTime<Utc>,
    pub(crate) ticks: Arc<AtomicI64>,
}

impl Ticking {
    pub(crate) fn new() -> Self {
        Self::offset(0)
    }
    pub(crate) fn offset(secs: i64) -> Self {
        Ticking { start: Utc::now() + TimeDelta::seconds(secs), ticks: Arc::new(AtomicI64::new(0)) }
    }
}

impl Clock for Ticking {
    fn now(&self) -> DateTime<Utc> {
        self.start + TimeDelta::seconds(self.ticks.fetch_add(1, Ordering::SeqCst))
    }
}

pub(crate) fn keys() -> serde_json::Value {
    serde_json::from_str(include_str!("../../vettid-vms/tests/vectors/keys.json")).unwrap()
}

pub(crate) fn seed(v: &serde_json::Value) -> [u8; 32] {
    hex::decode(v.as_str().unwrap()).unwrap().try_into().unwrap()
}

/// The vault's side, from the spec.
pub(crate) struct Vault {
    pub(crate) mem: Mem,
    pub(crate) kem: PrivateKey,
    pub(crate) ik: SigningKey,
    pub(crate) handshake: Option<(Schedule, Epoch, Init, [u8; 32])>,
}

impl Vault {
    pub(crate) fn new(relay: &Arc<Mutex<Relay>>) -> Self {
        let k = keys();
        let v = &k["vault"];
        let mem = Mem { relay: relay.clone(), key: SigningKey::from_bytes(&seed(&v["relay_seed_hex"])), name: "vault", faults: Default::default() };
        relay.lock().unwrap().mailboxes.entry(mem.mailbox()).or_default();
        Vault { mem, kem: PrivateKey::from_seed(&seed(&v["kem_seed_hex"])).unwrap(), ik: SigningKey::from_bytes(&seed(&v["ik_seed_hex"])), handshake: None }
    }

    pub(crate) fn principal(&self) -> Principal {
        Principal {
            ik: self.ik.verifying_key(),
            kem: self.kem.public().clone(),
            relay: RelayAddr { url: URL.into(), mailbox: self.mem.mailbox(), pk: self.mem.key.verifying_key() },
        }
    }

    /// A pairing code: the bundle sealed as a claim, and its link.
    pub(crate) fn invite(&self, kind: Kind, exp: DateTime<Utc>, hint: Option<&str>) -> String {
        let bundle = Bundle {
            kind: kind.purpose(),
            invite_id: new_ulid(Utc::now()).unwrap(),
            remote: false,
            vault: self.principal(),
            token: "v4.public.b3Blbi10b2tlbg".into(),
            exp: DateTime::from_timestamp(exp.timestamp(), 0).unwrap(),
            hint_name: hint.map(str::to_string),
            service: false,
        };
        let key = [7u8; 32];
        let nonce = fresh_nonce().unwrap();
        let mut blob = nonce.to_vec();
        blob.extend(seal_x(&key, &nonce, LABEL_BUNDLE.as_bytes(), bundle.marshal().unwrap().as_bytes()).unwrap());
        use sha2::Digest;
        let hash: [u8; 32] = sha2::Sha256::digest(&blob).into();
        let claim_id = "claimaaaaaaaaaaaaaaaaaaaaa".to_string();
        self.mem.relay.lock().unwrap().claims.insert(claim_id.clone(), blob);
        let qr = Qr { kind, relay: URL.into(), claim_id, hash, key: Zeroizing::new(key), exp: bundle.exp.timestamp() as u64 };
        qr.link().unwrap()
    }

    pub(crate) async fn next(&self) -> Message {
        loop {
            let msgs = self.mem.collect(URL, 0, 1).await.unwrap();
            if let Some(m) = msgs.into_iter().next() {
                self.mem.ack(URL, &m.msg_id).await.unwrap();
                return m;
            }
        }
    }

    /// Answer the desktop's hs.init with hs.resp (§6.3), as the vault does.
    pub(crate) async fn answer_init(&mut self) {
        let m = self.next().await;
        let env = Envelope::parse(&m.payload).unwrap();
        let (padded, ctx) = open_sealed(&env, &self.kem).unwrap();
        let mut ks = [0u8; 32];
        ctx.export(LABEL_HS_KS.as_bytes(), &mut ks).unwrap();
        let init = Init::parse(&Inner::decode(&padded, Mode::Sealed).unwrap().body).unwrap();
        assert_eq!(init.purpose, Purpose::Desktop);
        let mut sealer = Sealer::new(&init.eph, ANONYMOUS).unwrap();
        let mut ke = [0u8; 32];
        sealer.export(LABEL_HS_KE.as_bytes(), &mut ke).unwrap();
        let t = th(&m.payload, sealer.header());
        let sched = Schedule::derive(&ks, &ke, th1(&m.payload), t);
        let n_r = [5u8; 32];
        let (request, _) = mint_for_vault(&self.mem.key, URL, &init.from.relay.pk, Utc::now(), 0).unwrap();
        let resp = Resp { token: Some(request.into_string()), reconnect_token: None, suite: 2, sas_nonce: Some(n_r), sig: sign_resp(&self.ik, &t) };
        let inner = Inner {
            id: new_ulid(Utc::now()).unwrap(),
            kind: TYPE_RESP.into(),
            ts: Utc::now(),
            seq: None,
            response: None,
            exp: None,
            body: Zeroizing::new(resp.marshal(Purpose::Desktop).unwrap()),
        };
        let out = sealer.seal(&inner.encode(Mode::Sealed).unwrap()).unwrap();
        self.mem.deposit(URL, &init.from.relay.mailbox, &Token::from_received("x".into()), &out).await.unwrap();
        let epoch = Epoch::new(&sched, Role::Responder, 2, POLICY_VAULT_TO_DEVICE, Utc::now());
        self.handshake = Some((sched, epoch, init, n_r));
    }

    /// Check hs.fin as §6.3 says, and return the SAS the vault computes.
    pub(crate) async fn check_fin(&mut self) -> String {
        let m = self.next().await;
        let (sched, epoch, init, n_r) = self.handshake.as_mut().unwrap();
        let inner = epoch.open(&Envelope::parse(&m.payload).unwrap()).unwrap();
        assert_eq!(inner.kind, TYPE_FIN);
        let fin = Fin::parse(&inner.body, Purpose::Desktop).unwrap();
        verify_fin(&init.from.ik, &sched.th, &fin.sig).unwrap();
        let n_i = fin.sas_nonce.unwrap();
        assert!(check_sas_commit(&init.sas_commit.unwrap(), &n_i));
        sas(sched, &n_i, &n_r[..]).unwrap()
    }

    /// `kind` with `body`, sealed under the handshake's epoch.
    pub(crate) fn seal(&mut self, kind: &str, body: String) -> Vec<u8> {
        let (_, epoch, _, _) = self.handshake.as_mut().unwrap();
        epoch.activate(Utc::now());
        let mut inner = Inner { id: new_ulid(Utc::now()).unwrap(), kind: kind.into(), ts: Utc::now(), seq: None, response: None, exp: None, body: Zeroizing::new(body) };
        epoch.seal(&mut inner).unwrap()
    }

    pub(crate) fn device_mailbox(&self) -> String {
        self.handshake.as_ref().unwrap().2.from.relay.mailbox.clone()
    }

    /// Send `kind` with `body` to the desktop from the vault's relay key.
    pub(crate) async fn send(&mut self, kind: &str, body: String) {
        let env = self.seal(kind, body);
        let to = self.device_mailbox();
        self.mem.deposit(URL, &to, &Token::from_received("x".into()), &env).await.unwrap();
    }

    pub(crate) fn paired_body(&self, device_relay: &ed25519_dalek::VerifyingKey) -> String {
        let (standing, _) = mint_for_vault(&self.mem.key, URL, device_relay, Utc::now(), 0).unwrap();
        Builder::new()
            .string("device_id", "dev-1")
            .string("role", "desktop")
            .string("vault_id", "vault-1")
            .string("token", standing.as_str())
            .finish()
    }

    pub(crate) fn device_relay_key(&self) -> ed25519_dalek::VerifyingKey {
        self.handshake.as_ref().unwrap().2.from.relay.pk
    }
}

pub(crate) fn setup() -> (Arc<Mutex<Relay>>, Vault, Arc<Mutex<Faults>>) {
    let relay = Arc::new(Mutex::new(Relay::default()));
    let vault = Vault::new(&relay);
    (relay, vault, Default::default())
}

pub(crate) fn mem(relay: &Arc<Mutex<Relay>>, faults: &Arc<Mutex<Faults>>) -> impl FnOnce(SigningKey) -> Mem {
    let (relay, faults) = (relay.clone(), faults.clone());
    move |key| Mem { relay, key, name: "desktop", faults }
}

/// Up to the SAS: the code, the handshake, and both sides' SAS.
pub(crate) async fn handshake_done(
    relay: &Arc<Mutex<Relay>>,
    vault: &mut Vault,
    faults: &Arc<Mutex<Faults>>,
    store: &mut impl Persist,
    clock: Ticking,
) -> Pairing<Mem, Ticking> {
    let code = vault.invite(Kind::Desktop, Utc::now() + TimeDelta::minutes(10), Some("Al's vault"));
    let (pairing, ()) = tokio::join!(start(&code, "Work laptop", mem(relay, faults), store, clock), vault.answer_init());
    let pairing = pairing.unwrap();
    assert_eq!(pairing.sas(), vault.check_fin().await, "both sides show the same code");
    pairing
}

