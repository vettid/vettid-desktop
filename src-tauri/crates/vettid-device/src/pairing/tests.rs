//! Pairing end to end against an in-memory relay and a test vault written
//! from VAULT-MESSAGING §6.3/§6.4/§6.7 with the vault's test keys.

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

use super::*;
use crate::store::MemStore;
use crate::token::mint_for_vault;

const URL: &str = "https://relay.vettid.org";

/// A relay in memory: mailboxes and claims, no token checks, and a log of
/// what happened, in order.
#[derive(Default)]
struct Relay {
    mailboxes: HashMap<String, Vec<Message>>,
    claims: HashMap<String, Vec<u8>>,
    fetches: usize,
    log: Vec<String>,
}

/// Failures to inject into one party's relay calls.
#[derive(Default)]
struct Faults {
    /// Fail this many collects (retryable).
    collects: usize,
    /// Fail this many acks (retryable).
    acks: usize,
    /// Fail the deposit with this index (0-based), certainly undelivered.
    deposit: Option<usize>,
    deposits_seen: usize,
}

#[derive(Clone)]
struct Mem {
    relay: Arc<Mutex<Relay>>,
    key: SigningKey,
    name: &'static str,
    faults: Arc<Mutex<Faults>>,
}

impl Mem {
    fn mailbox(&self) -> String {
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
        if let Some(mb) = self.relay.lock().unwrap().mailboxes.get_mut(&self.mailbox()) {
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
struct LoggingStore {
    inner: MemStore,
    relay: Arc<Mutex<Relay>>,
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
struct Ticking {
    start: DateTime<Utc>,
    ticks: Arc<AtomicI64>,
}

impl Ticking {
    fn new() -> Self {
        Self::offset(0)
    }
    fn offset(secs: i64) -> Self {
        Ticking { start: Utc::now() + TimeDelta::seconds(secs), ticks: Arc::new(AtomicI64::new(0)) }
    }
}

impl Clock for Ticking {
    fn now(&self) -> DateTime<Utc> {
        self.start + TimeDelta::seconds(self.ticks.fetch_add(1, Ordering::SeqCst))
    }
}

fn keys() -> serde_json::Value {
    serde_json::from_str(include_str!("../../../vettid-vms/tests/vectors/keys.json")).unwrap()
}

fn seed(v: &serde_json::Value) -> [u8; 32] {
    hex::decode(v.as_str().unwrap()).unwrap().try_into().unwrap()
}

/// The vault's side, from the spec.
struct Vault {
    mem: Mem,
    kem: PrivateKey,
    ik: SigningKey,
    handshake: Option<(Schedule, Epoch, Init, [u8; 32])>,
}

impl Vault {
    fn new(relay: &Arc<Mutex<Relay>>) -> Self {
        let k = keys();
        let v = &k["vault"];
        let mem = Mem { relay: relay.clone(), key: SigningKey::from_bytes(&seed(&v["relay_seed_hex"])), name: "vault", faults: Default::default() };
        relay.lock().unwrap().mailboxes.entry(mem.mailbox()).or_default();
        Vault { mem, kem: PrivateKey::from_seed(&seed(&v["kem_seed_hex"])).unwrap(), ik: SigningKey::from_bytes(&seed(&v["ik_seed_hex"])), handshake: None }
    }

    fn principal(&self) -> Principal {
        Principal {
            ik: self.ik.verifying_key(),
            kem: self.kem.public().clone(),
            relay: RelayAddr { url: URL.into(), mailbox: self.mem.mailbox(), pk: self.mem.key.verifying_key() },
        }
    }

    /// A pairing code: the bundle sealed as a claim, and its link.
    fn invite(&self, kind: Kind, exp: DateTime<Utc>, hint: Option<&str>) -> String {
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

    async fn next(&self) -> Message {
        loop {
            let msgs = self.mem.collect(URL, 0, 1).await.unwrap();
            if let Some(m) = msgs.into_iter().next() {
                self.mem.ack(URL, &m.msg_id).await.unwrap();
                return m;
            }
        }
    }

    /// Answer the desktop's hs.init with hs.resp (§6.3), as the vault does.
    async fn answer_init(&mut self) {
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
    async fn check_fin(&mut self) -> String {
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
    fn seal(&mut self, kind: &str, body: String) -> Vec<u8> {
        let (_, epoch, _, _) = self.handshake.as_mut().unwrap();
        epoch.activate(Utc::now());
        let mut inner = Inner { id: new_ulid(Utc::now()).unwrap(), kind: kind.into(), ts: Utc::now(), seq: None, response: None, exp: None, body: Zeroizing::new(body) };
        epoch.seal(&mut inner).unwrap()
    }

    fn device_mailbox(&self) -> String {
        self.handshake.as_ref().unwrap().2.from.relay.mailbox.clone()
    }

    /// Send `kind` with `body` to the desktop from the vault's relay key.
    async fn send(&mut self, kind: &str, body: String) {
        let env = self.seal(kind, body);
        let to = self.device_mailbox();
        self.mem.deposit(URL, &to, &Token::from_received("x".into()), &env).await.unwrap();
    }

    fn paired_body(&self, device_relay: &ed25519_dalek::VerifyingKey) -> String {
        let (standing, _) = mint_for_vault(&self.mem.key, URL, device_relay, Utc::now(), 0).unwrap();
        Builder::new()
            .string("device_id", "dev-1")
            .string("role", "desktop")
            .string("vault_id", "vault-1")
            .string("token", standing.as_str())
            .finish()
    }

    fn device_relay_key(&self) -> ed25519_dalek::VerifyingKey {
        self.handshake.as_ref().unwrap().2.from.relay.pk
    }
}

fn setup() -> (Arc<Mutex<Relay>>, Vault, Arc<Mutex<Faults>>) {
    let relay = Arc::new(Mutex::new(Relay::default()));
    let vault = Vault::new(&relay);
    (relay, vault, Default::default())
}

fn mem(relay: &Arc<Mutex<Relay>>, faults: &Arc<Mutex<Faults>>) -> impl FnOnce(SigningKey) -> Mem {
    let (relay, faults) = (relay.clone(), faults.clone());
    move |key| Mem { relay, key, name: "desktop", faults }
}

/// Up to the SAS: the code, the handshake, and both sides' SAS.
async fn handshake_done(
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

/// The whole flow: the code, the handshake, the SAS both sides agree on,
/// the owner's approval, and a stored, active, paired state, in that
/// order.
#[tokio::test]
async fn pairs_end_to_end() {
    let (relay, mut vault, faults) = setup();
    let mut store = LoggingStore { inner: MemStore::default(), relay: relay.clone() };
    let pairing = handshake_done(&relay, &mut vault, &faults, &mut store, Ticking::new()).await;
    assert_eq!(pairing.instruction(), CONFIRM_ON_PHONE);
    assert_eq!(pairing.inviter_name(), Some("Al's vault"));
    assert_eq!(relay.lock().unwrap().fetches, 1, "the claim is fetched once");
    let pending = DeviceState::load(&mut store).unwrap().unwrap();
    assert_eq!((pending.phase, pending.epoch.active), (Phase::Pending, false));

    let body = vault.paired_body(&vault.device_relay_key());
    vault.send(DEVICE_PAIRED, body).await;
    let (paired, state) = pairing.wait_for_approval(&mut store).await.unwrap();
    assert_eq!(paired, Paired { device_id: "dev-1".into(), vault_id: Some("vault-1".into()) });
    // The order: hs.init out, stored, hs.fin out; the vault's device.paired
    // in, stored.
    let log: Vec<String> = relay.lock().unwrap().log.iter().filter(|l| *l != "vault deposit").cloned().collect();
    assert_eq!(log, ["desktop deposit", "save", "desktop deposit", "save"]);
    let stored = DeviceState::load_paired(&mut store).unwrap().unwrap();
    assert_eq!((stored.phase, stored.epoch.active, stored.device_id.as_deref()), (Phase::Paired, true, Some("dev-1")));
    assert_eq!(stored.vault_token.as_str(), state.vault_token.as_str());
    assert!(!format!("{stored:?}").contains("seed"));
    // The stored epoch talks to the vault.
    let mut epoch = Epoch::restore(stored.epoch);
    let mut ping = Inner { id: new_ulid(Utc::now()).unwrap(), kind: "test.ping".into(), ts: Utc::now(), seq: None, response: None, exp: None, body: Zeroizing::new("{}".into()) };
    let env = Envelope::parse(&epoch.seal(&mut ping).unwrap()).unwrap();
    assert_eq!(vault.handshake.as_mut().unwrap().1.open(&env).unwrap().kind, "test.ping");
    // Everything collected was acked.
    assert!(relay.lock().unwrap().mailboxes[&vault.device_mailbox()].is_empty());
}

#[tokio::test]
async fn a_rejection_ends_it_and_forgets_it() {
    let (relay, mut vault, faults) = setup();
    let mut store = MemStore::default();
    let pairing = handshake_done(&relay, &mut vault, &faults, &mut store, Ticking::new()).await;
    vault.send(DEVICE_PAIR_REJECTED, "{}".into()).await;
    assert_eq!(pairing.wait_for_approval(&mut store).await.unwrap_err(), PairError::Rejected);
    assert!(store.data.is_none(), "nothing kept");
}

/// Fail secure: messages that aren't the vault's answer are dropped, and
/// with no answer the window ends "not paired" with nothing kept.
#[tokio::test]
async fn only_the_vault_can_answer() {
    let (relay, mut vault, faults) = setup();
    let mut store = MemStore::default();
    let pairing = handshake_done(&relay, &mut vault, &faults, &mut store, Ticking::new()).await;
    // A properly sealed device.paired, deposited by another relay key, and
    // plain junk: both dropped.
    let body = vault.paired_body(&vault.device_relay_key());
    let sealed = vault.seal(DEVICE_PAIRED, body);
    let stranger = Mem { relay: relay.clone(), key: SigningKey::from_bytes(&[8; 32]), name: "stranger", faults: Default::default() };
    let to = vault.device_mailbox();
    stranger.deposit(URL, &to, &Token::from_received("x".into()), &sealed).await.unwrap();
    stranger.deposit(URL, &to, &Token::from_received("x".into()), b"junk").await.unwrap();
    assert_eq!(pairing.wait_for_approval(&mut store).await.unwrap_err(), PairError::TimedOut);
    assert!(store.data.is_none(), "the pending pairing is forgotten");
}

/// A device.paired from the vault that doesn't check out ends the pairing
/// at once, not paired.
#[tokio::test]
async fn a_bad_device_paired_ends_it() {
    for case in ["token for another device", "role agent", "no token"] {
        let (relay, mut vault, faults) = setup();
        let mut store = MemStore::default();
        let pairing = handshake_done(&relay, &mut vault, &faults, &mut store, Ticking::new()).await;
        let body = match case {
            "token for another device" => vault.paired_body(&SigningKey::from_bytes(&[9; 32]).verifying_key()),
            "role agent" => vault.paired_body(&vault.device_relay_key()).replace(r#""desktop""#, r#""agent""#),
            _ => Builder::new().string("device_id", "dev-1").string("role", "desktop").finish(),
        };
        vault.send(DEVICE_PAIRED, body).await;
        assert_eq!(pairing.wait_for_approval(&mut store).await.unwrap_err(), PairError::BadAnswer, "{case}");
        assert!(store.data.is_none(), "{case}: nothing kept");
    }
}

/// Temporary relay failures while waiting are retried; a failed ack after
/// the answer is stored doesn't undo the pairing.
#[tokio::test]
async fn relay_blips_do_not_end_a_pairing() {
    let (relay, mut vault, faults) = setup();
    let mut store = MemStore::default();
    let pairing = handshake_done(&relay, &mut vault, &faults, &mut store, Ticking::new()).await;
    let body = vault.paired_body(&vault.device_relay_key());
    vault.send(DEVICE_PAIRED, body).await;
    {
        let mut f = faults.lock().unwrap();
        f.collects = 2;
        f.acks = 100;
    }
    let (paired, _) = pairing.wait_for_approval(&mut store).await.unwrap();
    assert_eq!(paired.device_id, "dev-1");
    assert_eq!(DeviceState::load_paired(&mut store).unwrap().unwrap().phase, Phase::Paired);
}

/// An hs.fin that certainly wasn't delivered ends the pairing and removes
/// the pending state, keys included.
#[tokio::test]
async fn an_undelivered_hs_fin_leaves_nothing() {
    let (relay, mut vault, faults) = setup();
    faults.lock().unwrap().deposit = Some(1); // the desktop's second deposit: hs.fin
    let code = vault.invite(Kind::Desktop, Utc::now() + TimeDelta::minutes(10), None);
    let mut store = LoggingStore { inner: MemStore::default(), relay: relay.clone() };
    let (result, ()) = tokio::join!(start(&code, "x", mem(&relay, &faults), &mut store, Ticking::new()), vault.answer_init());
    assert!(matches!(result.unwrap_err(), PairError::NotSent(_)));
    assert!(store.inner.data.is_none());
    assert!(relay.lock().unwrap().log.ends_with(&["save".to_string(), "clear".to_string()]));
}

/// A desktop clock 4 minutes slow still pairs (the vault backdates its
/// tokens' iat by only 60 s).
#[tokio::test]
async fn a_slow_clock_still_pairs() {
    let (relay, mut vault, faults) = setup();
    let mut store = MemStore::default();
    let pairing = handshake_done(&relay, &mut vault, &faults, &mut store, Ticking::offset(-240)).await;
    let body = vault.paired_body(&vault.device_relay_key());
    vault.send(DEVICE_PAIRED, body).await;
    assert!(pairing.wait_for_approval(&mut store).await.is_ok());
}

/// After a restart mid-pairing, a pending state is no pairing: it is
/// removed.
#[tokio::test]
async fn a_pending_state_after_restart_is_not_a_pairing() {
    let (relay, mut vault, faults) = setup();
    let mut store = MemStore::default();
    let pairing = handshake_done(&relay, &mut vault, &faults, &mut store, Ticking::new()).await;
    drop(pairing); // the app stops
    assert_eq!(DeviceState::load(&mut store).unwrap().unwrap().phase, Phase::Pending);
    assert!(DeviceState::load_paired(&mut store).unwrap().is_none());
    assert!(store.data.is_none(), "removed, keys included");
}

/// A paired desktop is never re-paired over its keys: refused before
/// anything is spent. A pending state left behind is removed, and pairing
/// proceeds.
#[tokio::test]
async fn an_already_paired_desktop_is_not_overwritten() {
    let (relay, mut vault, faults) = setup();
    let mut store = MemStore::default();
    let pairing = handshake_done(&relay, &mut vault, &faults, &mut store, Ticking::new()).await;
    let body = vault.paired_body(&vault.device_relay_key());
    vault.send(DEVICE_PAIRED, body).await;
    pairing.wait_for_approval(&mut store).await.unwrap();
    let before = store.data.clone().unwrap();
    let code = vault.invite(Kind::Desktop, Utc::now() + TimeDelta::minutes(10), None);
    let fetches = relay.lock().unwrap().fetches;
    assert_eq!(start(&code, "x", mem(&relay, &faults), &mut store, Ticking::new()).await.unwrap_err(), PairError::AlreadyPaired);
    assert_eq!(relay.lock().unwrap().fetches, fetches, "no claim spent");
    assert_eq!(store.data.as_ref().map(|d| d.as_slice()), Some(before.as_slice()), "the pairing is untouched");
}

/// Cancelling a pending pairing removes it.
#[tokio::test]
async fn cancel_removes_the_pending_pairing() {
    let (relay, mut vault, faults) = setup();
    let mut store = MemStore::default();
    let pairing = handshake_done(&relay, &mut vault, &faults, &mut store, Ticking::new()).await;
    assert!(store.data.is_some());
    pairing.cancel(&mut store).unwrap();
    assert!(store.data.is_none());
}

#[tokio::test]
async fn codes_are_checked_before_anything_is_spent() {
    let (relay, vault, faults) = setup();
    let mut store = MemStore::default();
    let agent = vault.invite(Kind::Agent, Utc::now() + TimeDelta::minutes(10), None);
    assert_eq!(start(&agent, "x", mem(&relay, &faults), &mut store, Ticking::new()).await.unwrap_err(), PairError::NotForDesktop);
    let expired = vault.invite(Kind::Desktop, Utc::now() - TimeDelta::seconds(5), None);
    assert_eq!(start(&expired, "x", mem(&relay, &faults), &mut store, Ticking::new()).await.unwrap_err(), PairError::Expired);
    assert_eq!(start("not a code", "x", mem(&relay, &faults), &mut store, Ticking::new()).await.unwrap_err(), PairError::Code(InviteError::Qr));
    assert_eq!(relay.lock().unwrap().fetches, 0, "no claim spent");
    assert!(store.data.is_none());
}

/// No hs.resp: the window ends, nothing is stored.
#[tokio::test]
async fn no_answer_times_out() {
    let (relay, vault, faults) = setup();
    let code = vault.invite(Kind::Desktop, Utc::now() + TimeDelta::minutes(10), None);
    let mut store = MemStore::default();
    assert_eq!(start(&code, "x", mem(&relay, &faults), &mut store, Ticking::new()).await.unwrap_err(), PairError::TimedOut);
    assert!(store.data.is_none());
}

#[test]
fn stored_state_round_trips() {
    let s = Schedule::derive(&[1; 32], &[2; 32], [3; 32], [4; 32]);
    let epoch = Epoch::new(&s, Role::Initiator, 2, POLICY_VAULT_TO_DEVICE, Utc::now());
    let v = Vault::new(&Arc::new(Mutex::new(Relay::default())));
    let p = v.principal();
    let state = DeviceState {
        ik_seed: Zeroizing::new([1; 32]),
        kem_seed: Zeroizing::new([2; 32]),
        relay_seed: Zeroizing::new([3; 32]),
        relay_url: URL.into(),
        vault: VaultRecord { ik: p.ik, kem: p.kem, relay: p.relay },
        vault_token: Zeroizing::new("v4.public.abc".into()),
        vault_token_exp: vettid_vms::envelope::parse_ts("2026-10-31T12:00:00.000Z").unwrap(),
        issued_exp: vettid_vms::envelope::parse_ts("2026-10-31T11:59:00.000Z").unwrap(),
        phase: Phase::Pending,
        pairing_deadline: vettid_vms::envelope::parse_ts("2026-10-01T12:10:00.000Z").unwrap(),
        device_id: None,
        vault_id: Some("vault-1".into()),
        epoch: epoch.snapshot(),
    };
    let json = state.to_json();
    let back = DeviceState::from_json(json.as_bytes()).unwrap();
    assert_eq!(back.to_json().as_str(), json.as_str());
    assert_eq!(Epoch::restore(back.epoch).id(), epoch.id());
    assert_eq!(DeviceState::from_json(b"{}").unwrap_err(), StoreError::Corrupt);
}
