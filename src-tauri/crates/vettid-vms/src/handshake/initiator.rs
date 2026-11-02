//! The initiator side of one handshake (§6.1–§6.3), for the purposes
//! that pair or connect: `hs.init` sealed to the responder's `ek_R`,
//! `hs.resp` opened with a fresh ephemeral key, `sig_R` verified before
//! any epoch key is used, then `hs.fin` in the new epoch and the SAS.

use chrono::{DateTime, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use super::epoch::{Epoch, Policy, Role};
use super::messages::{Fin, Init, Principal, RelayAddr, Resp};
use super::schedule::{sas, sas_commit, sign_fin, th, th1, verify_resp, Schedule};
use super::{check_chosen, HandshakeError, Purpose, SAS_NONCE_SIZE, TYPE_FIN, TYPE_INIT, TYPE_RESP};
use crate::envelope::{new_ulid, open_sealed, Envelope, EnvelopeError, Inner, Mode, Sealer};
use crate::suite::aead::fresh_nonce;
use crate::suite::kem::{PrivateKey, PublicKey};
use crate::suite::kid::{Kid, ANONYMOUS};
use crate::suite::{random, KEY_SIZE, LABEL_HS_KE, LABEL_HS_KS, SUITE_2, XNONCE_SIZE};

/// What an `hs.init` needs.
pub struct InitiatorConfig {
    /// `app`, `desktop`, `agent` or `connection` (rekeys and reconnects
    /// come with the device engine).
    pub purpose: Purpose,
    /// The pairing id or invite id.
    pub ctx: String,
    /// `ik_I`.
    pub identity: SigningKey,
    /// `from.kem`: this side's static KEM key.
    pub static_kem: PublicKey,
    /// `from.relay`.
    pub relay: RelayAddr,
    /// The token for the responder's deposits to us.
    pub token: Option<String>,
    /// Offered suites; empty means `[2]`.
    pub suites: Vec<u64>,
    /// An optional self-asserted profile object.
    pub profile: Option<String>,
    /// `sender_kid` all zero instead of the kid of `static_kem`.
    pub anonymous_sender: bool,
    /// The pinned `ik_R` (from the claim bundle).
    pub responder_ik: VerifyingKey,
    /// `ek_R`.
    pub responder_ek: PublicKey,
    /// R's relay key: the collect `sender` `hs.resp` must have.
    pub responder_relay_key: VerifyingKey,
    /// The suite on record (0: none yet).
    pub pinned_suite: u8,
    pub policy: Policy,
    /// Inner ids and time; `None` ids are generated.
    pub id: Option<String>,
    pub fin_id: Option<String>,
    pub now: DateTime<Utc>,
}

impl std::fmt::Debug for InitiatorConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitiatorConfig").field("purpose", &self.purpose).finish_non_exhaustive()
    }
}

/// A completed handshake, on the initiator side.
pub struct Outcome {
    /// The new epoch. For a pairing it becomes active at the owner's
    /// approval (§6.7): until then its messages are left unacked.
    pub epoch: Epoch,
    /// `hs.fin`, sealed in the new epoch, to deposit.
    pub fin: Vec<u8>,
    /// The `hs.resp` body (tokens, chosen suite).
    pub resp: Resp,
    /// The `hs.resp` inner plaintext.
    pub inner: Inner,
    /// The SAS, for purposes with one: it exists only now, after `sig_R`
    /// verified (§6.3).
    pub sas: Option<String>,
}

impl std::fmt::Debug for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Outcome").field("epoch", &self.epoch).finish_non_exhaustive()
    }
}

/// Where a handshake's randomness comes from: the OS, except in the
/// known-answer tests.
pub(super) trait Randomness {
    fn ephemeral(&mut self) -> Result<PrivateKey, HandshakeError>;
    fn sas_nonce(&mut self) -> Result<[u8; SAS_NONCE_SIZE], HandshakeError>;
    fn sealer(&mut self, recipient: &PublicKey, sender_kid: Kid) -> Result<Sealer, HandshakeError>;
    fn session_nonce(&mut self) -> Result<[u8; XNONCE_SIZE], HandshakeError>;
}

struct Os;

impl Randomness for Os {
    fn ephemeral(&mut self) -> Result<PrivateKey, HandshakeError> {
        Ok(PrivateKey::generate()?)
    }
    fn sas_nonce(&mut self) -> Result<[u8; SAS_NONCE_SIZE], HandshakeError> {
        let mut n = [0u8; SAS_NONCE_SIZE];
        random(&mut n)?;
        Ok(n)
    }
    fn sealer(&mut self, recipient: &PublicKey, sender_kid: Kid) -> Result<Sealer, HandshakeError> {
        Ok(Sealer::new(recipient, sender_kid)?)
    }
    fn session_nonce(&mut self) -> Result<[u8; XNONCE_SIZE], HandshakeError> {
        Ok(fresh_nonce()?)
    }
}

/// The initiator of one handshake. `Debug` prints nothing secret.
pub struct Initiator {
    cfg: InitiatorConfig,
    body: Init,
    eph: Option<PrivateKey>,
    env: Vec<u8>,
    th1: [u8; 32],
    ks: Option<Zeroizing<[u8; KEY_SIZE]>>,
    n_i: Option<Zeroizing<[u8; SAS_NONCE_SIZE]>>,
    done: bool,
}

impl std::fmt::Debug for Initiator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Initiator").field("purpose", &self.cfg.purpose).field("done", &self.done).finish_non_exhaustive()
    }
}

impl Initiator {
    /// Build and seal `hs.init`, with a fresh ephemeral KEM key (forward
    /// secrecy, §6.5) and, for a purpose with a SAS, the nonce `n_I` it
    /// commits to, chosen before `hs.init` is built (§6.2).
    ///
    /// Only `desktop` and `agent`: an `app` handshake needs a phone's
    /// `device_attest` (§6.7, §11.7), and `connection` is between vaults.
    /// (The known-answer test builds the vector's `connection` through
    /// the same code.)
    pub fn new(cfg: InitiatorConfig) -> Result<Self, HandshakeError> {
        if !matches!(cfg.purpose, Purpose::Desktop | Purpose::Agent) {
            return Err(HandshakeError::Config);
        }
        Self::build(cfg, &mut Os)
    }

    pub(super) fn build(mut cfg: InitiatorConfig, rng: &mut impl Randomness) -> Result<Self, HandshakeError> {
        if matches!(cfg.purpose, Purpose::Rekey | Purpose::Reconnect) {
            return Err(HandshakeError::Config);
        }
        // An epoch without a bound would never be rekeyed (§6.5).
        if cfg.policy.max_age <= chrono::TimeDelta::zero() && cfg.policy.max_messages == 0 {
            return Err(HandshakeError::Config);
        }
        if cfg.suites.is_empty() {
            cfg.suites = vec![u64::from(SUITE_2)];
        }
        let eph = rng.ephemeral()?;
        let n_i = if cfg.purpose.has_sas() { Some(Zeroizing::new(rng.sas_nonce()?)) } else { None };
        let body = Init {
            purpose: cfg.purpose,
            ctx: cfg.ctx.clone(),
            from: Principal { ik: cfg.identity.verifying_key(), kem: cfg.static_kem.clone(), relay: cfg.relay.clone() },
            eph: eph.public().clone(),
            token: cfg.token.clone(),
            reconnect_token: None,
            suites: cfg.suites.clone(),
            profile: cfg.profile.clone(),
            sas_commit: n_i.as_ref().map(|n| sas_commit(n)),
        };
        let id = match &cfg.id {
            Some(id) => id.clone(),
            None => new_ulid(cfg.now)?,
        };
        let inner = Inner {
            id,
            kind: TYPE_INIT.into(),
            ts: cfg.now,
            seq: None,
            response: None,
            exp: None,
            body: Zeroizing::new(body.marshal()?),
        };
        let padded = Zeroizing::new(inner.encode(Mode::Sealed)?);
        let sender_kid = if cfg.anonymous_sender { ANONYMOUS } else { cfg.static_kem.kid() };
        let mut sealer = rng.sealer(&cfg.responder_ek, sender_kid)?;
        let env = sealer.seal(&padded)?;
        let mut ks = Zeroizing::new([0u8; KEY_SIZE]);
        sealer.export(LABEL_HS_KS.as_bytes(), &mut ks[..])?;
        let th1 = th1(&env);
        Ok(Initiator { cfg, body, eph: Some(eph), env, th1, ks: Some(ks), n_i, done: false })
    }

    /// `hs.init`, ready to deposit.
    pub fn envelope(&self) -> &[u8] {
        &self.env
    }

    /// `th1` (it also decides simultaneous rekeys, §6.5).
    pub fn th1(&self) -> [u8; 32] {
        self.th1
    }

    /// The kid `hs.resp` carries as `recipient_kid`.
    pub fn eph_kid(&self) -> Kid {
        self.body.eph.kid()
    }

    /// The `hs.init` body.
    pub fn body(&self) -> &Init {
        &self.body
    }

    /// Destroy the handshake's secrets; any later `handle_resp` fails.
    pub fn abort(&mut self) {
        self.done = true;
        self.eph = None;
        self.ks = None;
        self.n_i = None;
    }

    /// Process `hs.resp`, collected with relay `sender` `collect_sender`.
    ///
    /// A message that doesn't decrypt under `eph` (wrong sender, malformed,
    /// another key) is refused and the handshake stays pending, so
    /// unauthenticated junk can't cancel it. Once one has decrypted, any
    /// failure, a bad `sig_R` above all, aborts the handshake and destroys
    /// its state (§6.3); success ends it too.
    pub fn handle_resp(&mut self, raw: &[u8], collect_sender: &VerifyingKey, now: DateTime<Utc>) -> Result<Outcome, HandshakeError> {
        self.handle_resp_with(raw, collect_sender, now, &mut Os)
    }

    pub(super) fn handle_resp_with(
        &mut self,
        raw: &[u8],
        collect_sender: &VerifyingKey,
        now: DateTime<Utc>,
        rng: &mut impl Randomness,
    ) -> Result<Outcome, HandshakeError> {
        if self.done {
            return Err(HandshakeError::Done);
        }
        if collect_sender.as_bytes() != self.cfg.responder_relay_key.as_bytes() {
            return Err(HandshakeError::Sender);
        }
        let env = Envelope::parse(raw)?;
        if env.mode() != Mode::Sealed {
            return Err(EnvelopeError::WrongMode.into());
        }
        if !env.sender_kid().is_anonymous() {
            return Err(HandshakeError::SenderKid);
        }
        let eph = self.eph.as_ref().ok_or(HandshakeError::Done)?;
        let (padded, ctx) = open_sealed(&env, eph)?;
        // Decrypted under eph: from here on, any outcome ends the handshake.
        let mut ke = Zeroizing::new([0u8; KEY_SIZE]);
        let result = ctx
            .export(LABEL_HS_KE.as_bytes(), &mut ke[..])
            .map_err(HandshakeError::from)
            .and_then(|()| self.complete(&env, &padded, &ke, now, rng));
        self.abort();
        result
    }

    fn complete(
        &self,
        env: &Envelope,
        padded: &[u8],
        ke: &[u8; KEY_SIZE],
        now: DateTime<Utc>,
        rng: &mut impl Randomness,
    ) -> Result<Outcome, HandshakeError> {
        let inner = Inner::decode(padded, Mode::Sealed)?;
        if inner.kind != TYPE_RESP {
            return Err(HandshakeError::Type);
        }
        inner.check_time(now, true)?;
        let resp = Resp::parse(&inner.body, self.cfg.purpose)?;
        check_chosen(resp.suite, &self.cfg.suites, self.cfg.pinned_suite)?;
        let ks = self.ks.as_ref().ok_or(HandshakeError::Done)?;
        let th = th(&self.env, env.header());
        let sched = Schedule::derive(ks, ke, self.th1, th);
        // §6.3: verify sig_R before using any epoch key.
        verify_resp(&self.cfg.responder_ik, &th, &resp.sig)?;
        let sas = match (&self.n_i, &resp.sas_nonce) {
            (Some(n_i), Some(n_r)) => Some(sas(&sched, &n_i[..], n_r)?),
            (None, None) => None,
            _ => return Err(HandshakeError::Body),
        };
        let mut epoch = Epoch::new(&sched, Role::Initiator, resp.suite as u8, self.cfg.policy, now);
        let fin_body = Fin { sig: sign_fin(&self.cfg.identity, &th), sas_nonce: self.n_i.as_deref().copied() }.marshal(self.cfg.purpose)?;
        let fin_id = match &self.cfg.fin_id {
            Some(id) => id.clone(),
            None => new_ulid(now)?,
        };
        let mut fin_inner = Inner {
            id: fin_id,
            kind: TYPE_FIN.into(),
            ts: now,
            seq: None,
            response: None,
            exp: None,
            body: Zeroizing::new(fin_body),
        };
        let fin = epoch.seal_with(&mut fin_inner, &rng.session_nonce()?)?;
        Ok(Outcome { epoch, fin, resp, inner, sas })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::seal_sealed;
    use crate::handshake::POLICY_VAULT_TO_DEVICE;
    use crate::suite::hpke::tests::{setup_sender_with, FixedRng};
    use crate::suite::sign::identity_from_seed;
    use crate::suite::{vectors, INFO_SEALED};
    use base64::Engine;

    /// The vector's fixed randomness, in the order the handshake asks.
    struct Fixed {
        eph: [u8; 32],
        n_i: [u8; 32],
        init_rand: Vec<u8>,
        fin_nonce: [u8; 24],
    }

    impl Randomness for Fixed {
        fn ephemeral(&mut self) -> Result<PrivateKey, HandshakeError> {
            Ok(PrivateKey::from_seed(&self.eph)?)
        }
        fn sas_nonce(&mut self) -> Result<[u8; 32], HandshakeError> {
            Ok(self.n_i)
        }
        fn sealer(&mut self, recipient: &PublicKey, sender_kid: Kid) -> Result<Sealer, HandshakeError> {
            let mut rng = FixedRng(self.init_rand.clone(), 0);
            let (enc, ctx) = setup_sender_with(recipient, INFO_SEALED.as_bytes(), &mut rng);
            Ok(Sealer::from_parts(recipient, sender_kid, &enc, ctx))
        }
        fn session_nonce(&mut self) -> Result<[u8; 24], HandshakeError> {
            Ok(self.fin_nonce)
        }
    }

    fn arr<const N: usize>(v: &serde_json::Value) -> [u8; N] {
        vectors::hex(v).try_into().unwrap()
    }

    fn b64(v: &serde_json::Value) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD.decode(v.as_str().unwrap()).unwrap()
    }

    fn vk(v: &serde_json::Value) -> VerifyingKey {
        VerifyingKey::from_bytes(&b64(v).try_into().unwrap()).unwrap()
    }

    /// The vector's initiator configuration, randomness and the vault's
    /// relay key.
    fn setup() -> (InitiatorConfig, Fixed, VerifyingKey, serde_json::Value) {
        let v = vectors::load("handshake");
        let keys = vectors::load("keys");
        let (ini, vault) = (&keys["initiator"], &keys["vault"]);
        let inputs = &v["inputs"];
        let body: serde_json::Value = serde_json::from_str(v["hs_init_body"].as_str().unwrap()).unwrap();
        let now = crate::envelope::parse_ts(inputs["ts"].as_str().unwrap()).unwrap();
        let cfg = InitiatorConfig {
            purpose: Purpose::Connection,
            ctx: body["ctx"].as_str().unwrap().into(),
            identity: identity_from_seed(&vectors::seed(&ini["ik_seed_hex"])),
            static_kem: PrivateKey::from_seed(&vectors::seed(&ini["kem_seed_hex"])).unwrap().public().clone(),
            relay: RelayAddr {
                url: ini["relay_url"].as_str().unwrap().into(),
                mailbox: ini["mailbox"].as_str().unwrap().into(),
                pk: identity_from_seed(&vectors::seed(&ini["relay_seed_hex"])).verifying_key(),
            },
            token: Some(body["token"].as_str().unwrap().into()),
            suites: vec![],
            profile: None,
            anonymous_sender: false,
            responder_ik: vk(&vault["ik_pk_b64"]),
            responder_ek: PublicKey::parse(&b64(&vault["ek_b64"])).unwrap(),
            responder_relay_key: vk(&vault["relay_pk_b64"]),
            pinned_suite: 0,
            policy: POLICY_VAULT_TO_DEVICE,
            id: Some(inputs["init_id"].as_str().unwrap().into()),
            fin_id: Some(inputs["fin_id"].as_str().unwrap().into()),
            now,
        };
        let fixed = Fixed {
            eph: arr(&inputs["initiator_eph_seed_hex"]),
            n_i: arr(&inputs["n_I_hex"]),
            init_rand: vectors::hex(&inputs["init_encapsulation_randomness_hex"]),
            fin_nonce: arr(&inputs["fin_nonce_hex"]),
        };
        let relay = vk(&vault["relay_pk_b64"]);
        (cfg, fixed, relay, v)
    }

    /// handshake.json from the initiator's side, byte for byte: hs.init,
    /// then hs.resp in, hs.fin out, the epoch and the SAS.
    #[test]
    fn handshake_vector() {
        let (cfg, mut fixed, relay, v) = setup();
        let now = cfg.now;
        let mut i = Initiator::build(cfg, &mut fixed).unwrap();
        assert_eq!(i.envelope(), b64(&v["hs_init_envelope_b64"]).as_slice());
        assert_eq!(i.th1().to_vec(), vectors::hex(&v["th1_hex"]));
        let out = i.handle_resp_with(&b64(&v["hs_resp_envelope_b64"]), &relay, now, &mut fixed).unwrap();
        assert_eq!(out.fin, b64(&v["hs_fin_envelope_b64"]));
        assert_eq!(out.sas.as_deref(), v["sas"].as_str());
        assert_eq!(out.epoch.id().to_vec(), vectors::hex(&v["epoch_id_hex"]));
        assert_eq!(out.resp.sig.to_vec(), b64(&v["sig_R_b64"]));
        assert_eq!(out.inner.marshal(Mode::Sealed).unwrap(), v["hs_resp_inner"].as_str().unwrap());
        // hs.fin carries sig_I and reveals n_I.
        let fin = Fin::parse(&Inner::decode(&crate::envelope::open_session(&Envelope::parse(&out.fin).unwrap(), &arr(&v["k_i2r_hex"])).unwrap(), Mode::Session).unwrap().body, Purpose::Connection).unwrap();
        assert_eq!(fin.sig.to_vec(), b64(&v["sig_I_b64"]));
        assert_eq!(fin.sas_nonce.map(|n| n.to_vec()), Some(vectors::hex(&v["inputs"]["n_I_hex"])));
        // One hs.resp per hs.init: a second is refused.
        assert_eq!(i.handle_resp_with(&b64(&v["hs_resp_envelope_b64"]), &relay, now, &mut fixed).unwrap_err(), HandshakeError::Done);
    }

    /// Junk that doesn't decrypt under eph leaves the handshake pending.
    #[test]
    fn undecryptable_junk_keeps_it_pending() {
        let (cfg, mut fixed, relay, v) = setup();
        let now = cfg.now;
        let mut i = Initiator::build(cfg, &mut fixed).unwrap();
        let resp = b64(&v["hs_resp_envelope_b64"]);
        let stranger = SigningKey::from_bytes(&[9; 32]).verifying_key();
        assert_eq!(i.handle_resp_with(&resp, &stranger, now, &mut fixed).unwrap_err(), HandshakeError::Sender);
        assert!(i.handle_resp_with(b"junk", &relay, now, &mut fixed).is_err());
        let mut tampered = resp.clone();
        tampered[1500] ^= 1;
        assert_eq!(i.handle_resp_with(&tampered, &relay, now, &mut fixed).unwrap_err(), HandshakeError::Envelope(EnvelopeError::Decrypt));
        // Another recipient kid: not for this eph, nothing tried.
        let mut other = resp.clone();
        other[12] ^= 1;
        assert_eq!(i.handle_resp_with(&other, &relay, now, &mut fixed).unwrap_err(), HandshakeError::Envelope(EnvelopeError::Kid));
        let mut named = resp.clone();
        named[5] ^= 1;
        assert_eq!(i.handle_resp_with(&named, &relay, now, &mut fixed).unwrap_err(), HandshakeError::SenderKid);
        // Still pending: the real hs.resp completes it.
        assert!(i.handle_resp_with(&resp, &relay, now, &mut fixed).is_ok());
    }

    /// Once an hs.resp decrypts, a bad sig_R (or type) aborts the handshake.
    #[test]
    fn a_decrypted_failure_aborts() {
        let v = vectors::load("handshake");
        let good: serde_json::Value = serde_json::from_str(v["hs_resp_inner"].as_str().unwrap()).unwrap();
        for (why, edit, want) in [
            ("bad sig_R", "sig", HandshakeError::SigResp),
            ("wrong type", "type", HandshakeError::Type),
            ("suite 3", "suite", HandshakeError::Suite(crate::suite::SuiteError::UnsupportedSuite)),
            ("stale ts", "ts", HandshakeError::Envelope(EnvelopeError::ClockPast)),
            ("malformed body", "body", HandshakeError::Body),
        ] {
            let (cfg, mut fixed, relay, _) = setup();
            let now = cfg.now;
            let mut i = Initiator::build(cfg, &mut fixed).unwrap();
            let mut inner = good.clone();
            match edit {
                "sig" => inner["body"]["sig"] = serde_json::json!(base64::engine::general_purpose::STANDARD.encode([1u8; 64])),
                "type" => inner["type"] = serde_json::json!("hs.fin"),
                "ts" => inner["ts"] = serde_json::json!("2026-09-01T12:00:00.000Z"),
                "body" => inner["body"] = serde_json::json!({}),
                _ => inner["body"]["suite"] = serde_json::json!(3),
            }
            let parsed = Inner::parse(serde_json::to_string(&inner).unwrap().as_bytes(), Mode::Sealed).unwrap();
            let eph_pub = PrivateKey::from_seed(&fixed.eph).unwrap().public().clone();
            let (env, _) = seal_sealed(&eph_pub, ANONYMOUS, &parsed.encode(Mode::Sealed).unwrap()).unwrap();
            assert_eq!(i.handle_resp_with(&env, &relay, now, &mut fixed).unwrap_err(), want, "{why}");
            assert_eq!(i.handle_resp_with(&b64(&v["hs_resp_envelope_b64"]), &relay, now, &mut fixed).unwrap_err(), HandshakeError::Done, "{why}: aborted");
        }
    }

    #[test]
    fn only_desktop_and_agent_are_built() {
        for p in [Purpose::Rekey, Purpose::Reconnect] {
            let (mut cfg, mut fixed, _, _) = setup();
            cfg.purpose = p;
            assert_eq!(Initiator::build(cfg, &mut fixed).unwrap_err(), HandshakeError::Config);
        }
        for p in [Purpose::App, Purpose::Connection, Purpose::Rekey] {
            let (mut cfg, _, _, _) = setup();
            cfg.purpose = p;
            assert_eq!(Initiator::new(cfg).unwrap_err(), HandshakeError::Config, "{p:?}");
        }
        let (mut cfg, mut fixed, _, _) = setup();
        cfg.policy = Policy { max_age: chrono::TimeDelta::zero(), max_messages: 0 };
        assert_eq!(Initiator::build(cfg, &mut fixed).unwrap_err(), HandshakeError::Config, "an unbounded epoch");
    }

    /// Purpose desktop, end to end through the release path, against a
    /// test responder built from §6.3 with the vault's keys: the initiator
    /// completes, and both sides agree on the SAS, sig_I and the
    /// commitment.
    #[test]
    fn desktop_round_trip() {
        use crate::handshake::{check_sas_commit, sign_resp, verify_fin};
        let (mut cfg, _, relay, _) = setup();
        cfg.purpose = Purpose::Desktop;
        cfg.ctx = "01JB2Z6V9K3M4N5P6Q7R8S9T0V".into();
        cfg.profile = Some(r#"{"name":"Laptop"}"#.into());
        cfg.id = None;
        cfg.fin_id = None;
        let now = cfg.now;
        let initiator_ik = cfg.identity.verifying_key();
        let mut i = Initiator::new(cfg).unwrap();

        // The responder: the vault's KEM and identity keys.
        let keys = vectors::load("keys");
        let vault_kem = PrivateKey::from_seed(&vectors::seed(&keys["vault"]["kem_seed_hex"])).unwrap();
        let vault_ik = identity_from_seed(&vectors::seed(&keys["vault"]["ik_seed_hex"]));
        let env_init = i.envelope().to_vec();
        let (padded, r_ctx) = open_sealed(&Envelope::parse(&env_init).unwrap(), &vault_kem).unwrap();
        let mut ks = [0u8; 32];
        r_ctx.export(LABEL_HS_KS.as_bytes(), &mut ks).unwrap();
        let init_inner = Inner::decode(&padded, Mode::Sealed).unwrap();
        let init = Init::parse(&init_inner.body).unwrap();
        assert_eq!((init.purpose, init.profile.as_deref()), (Purpose::Desktop, Some(r#"{"name":"Laptop"}"#)));
        let mut sealer = Sealer::new(&init.eph, ANONYMOUS).unwrap();
        let mut ke = [0u8; 32];
        sealer.export(LABEL_HS_KE.as_bytes(), &mut ke).unwrap();
        let th_r = th(&env_init, sealer.header());
        let sched = Schedule::derive(&ks, &ke, th1(&env_init), th_r);
        let n_r = [5u8; 32];
        let resp = Resp { token: Some("v4.public.resp".into()), reconnect_token: None, suite: 2, sas_nonce: Some(n_r), sig: sign_resp(&vault_ik, &th_r) };
        let resp_inner = Inner {
            id: new_ulid(now).unwrap(),
            kind: TYPE_RESP.into(),
            ts: now,
            seq: None,
            response: None,
            exp: None,
            body: Zeroizing::new(resp.marshal(Purpose::Desktop).unwrap()),
        };
        let env_resp = sealer.seal(&resp_inner.encode(Mode::Sealed).unwrap()).unwrap();

        let out = i.handle_resp(&env_resp, &relay, now).unwrap();
        // The responder checks hs.fin as section 6.3 says.
        let fin_inner = Inner::decode(&crate::envelope::open_session(&Envelope::parse(&out.fin).unwrap(), &sched.k_i2r).unwrap(), Mode::Session).unwrap();
        assert_eq!((fin_inner.kind.as_str(), fin_inner.seq), (TYPE_FIN, Some(1)));
        let fin = Fin::parse(&fin_inner.body, Purpose::Desktop).unwrap();
        verify_fin(&initiator_ik, &th_r, &fin.sig).unwrap();
        let n_i = fin.sas_nonce.unwrap();
        assert!(check_sas_commit(&init.sas_commit.unwrap(), &n_i));
        assert_eq!(out.sas.unwrap(), sas(&sched, &n_i, &n_r).unwrap());
        assert_eq!(out.epoch.id(), sched.epoch_id);
        assert_eq!(out.resp.token.as_deref(), Some("v4.public.resp"));
    }

    #[test]
    fn release_initiators_use_fresh_randomness() {
        let (mut cfg, _, _, _) = setup();
        let (mut cfg2, _, _, _) = setup();
        cfg.purpose = Purpose::Desktop;
        cfg2.purpose = Purpose::Desktop;
        let (a, b) = (Initiator::new(cfg).unwrap(), Initiator::new(cfg2).unwrap());
        assert_ne!(a.eph_kid(), b.eph_kid());
        assert_ne!(a.body().sas_commit, b.body().sas_commit);
        assert_ne!(a.envelope()[20..1140], b.envelope()[20..1140]);
        assert_eq!(format!("{a:?}"), "Initiator { purpose: Desktop, done: false, .. }");
    }
}
