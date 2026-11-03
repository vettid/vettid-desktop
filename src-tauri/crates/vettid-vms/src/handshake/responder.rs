//! The responder side of a **rekey** (§6.2, §6.3, §6.5), as the vault's
//! `vms/handshake` builds it (`AcceptRekey`, `Respond`, `HandleFin`): the
//! vault starts a rekey on every unlock and every 7 days, and the desktop
//! answers it.
//!
//! - `hs.init` travels in session mode under the **current** epoch; the
//!   caller opens it (through its [`Keyring`](super::Keyring)) and hands
//!   over the inner plaintext. Its `ctx` must be that epoch's id, and `K_s`
//!   is that epoch's `rk`.
//! - The collect `sender` must be the initiator's `from.relay.pk` and the
//!   relay key on record; `from.ik` must be the identity on record (§6.3).
//! - `hs.resp` is sealed to the initiator's ephemeral key, with `sig_R`
//!   over `th`. One `hs.resp` per `hs.init`: a retransmitted `hs.init` is
//!   for the caller's inner-id dedupe, and the caller resends the same
//!   bytes.
//! - The epoch is established only once `sig_I` verifies (§6.3). An
//!   `hs.fin` that doesn't decrypt, is malformed, is stale or whose `sig_I`
//!   doesn't verify leaves the handshake pending, so a forged message
//!   can't cancel a genuine rekey. A message that decrypts under the new
//!   epoch's keys but **isn't** `hs.fin` gives [`HandshakeError::Type`]:
//!   the initiator's first message of the new epoch, arrived before its
//!   `hs.fin`. The caller must leave it **unacked**, without processing,
//!   dropping or auditing it (§6.3, 0.23.0), so the relay delivers it again
//!   once the epoch is established.
//!
//! Rekeys carry no SAS, no rotations and no attestation. Other purposes
//! (reconnects, pairings answered by this side) aren't here.

use chrono::{DateTime, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use super::epoch::{Epoch, EpochState, Policy, Role};
use super::initiator::{Os, Randomness};
use super::messages::{Fin, Init, Resp};
use super::schedule::{sign_resp, th, th1, verify_fin, Schedule};
use super::{check_chosen, validate_offer, HandshakeError, Purpose, TYPE_FIN, TYPE_INIT, TYPE_RESP};
use crate::envelope::{new_ulid, Envelope, EnvelopeError, Inner, Mode, MAX_DURABLE_AGE};
use crate::suite::kid::{Kid, ANONYMOUS};
use crate::suite::{KEY_SIZE, LABEL_HS_KE};

/// The `ctx` of a rekey `hs.init`: the standard base64 of the current
/// epoch's id (§6.2).
pub fn epoch_ctx(id: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(id)
}

/// What answering a rekey needs.
pub struct RekeyConfig {
    /// `ik_R`: this side's identity key.
    pub identity: SigningKey,
    /// The initiator's identity on record: `from.ik` must equal it.
    pub peer_ik: VerifyingKey,
    /// The initiator's relay key on record (§6.3).
    pub peer_relay_key: VerifyingKey,
    /// The relay `sender` of the `hs.init` deposit.
    pub collect_sender: VerifyingKey,
    /// The suite on record (0: none).
    pub pinned_suite: u8,
    /// The new epoch's bound (§6.5).
    pub policy: Policy,
    /// The `hs.resp` inner id; `None` generates one.
    pub id: Option<String>,
    pub now: DateTime<Utc>,
}

impl std::fmt::Debug for RekeyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RekeyConfig").field("pinned_suite", &self.pinned_suite).finish_non_exhaustive()
    }
}

/// The responder after `hs.resp`, awaiting `hs.fin`. Its keys wipe
/// themselves; `Debug` prints nothing secret.
pub struct Responder {
    /// The new epoch, not yet established: inactive, this side's role.
    pending: Option<EpochState>,
    th: [u8; 32],
    /// `sig_I` must verify under this (`from.ik`).
    verify_ik: VerifyingKey,
    /// `hs.fin`'s collect `sender` must be this (`from.relay.pk`).
    sender: VerifyingKey,
    /// When `hs.resp` was built.
    since: DateTime<Utc>,
}

impl std::fmt::Debug for Responder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Responder").field("done", &self.pending.is_none()).finish_non_exhaustive()
    }
}

/// A waiting [`Responder`], to store and restore (secret: its keys wipe
/// themselves, and `Debug` prints nothing).
#[derive(Clone)]
pub struct ResponderState {
    /// The pending epoch (inactive, role responder).
    pub pending: EpochState,
    pub th: [u8; 32],
    pub verify_ik: VerifyingKey,
    pub sender: VerifyingKey,
    pub since: DateTime<Utc>,
}

impl std::fmt::Debug for ResponderState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ResponderState(..)")
    }
}

/// An established rekey.
pub struct Established {
    /// The new epoch, **active** at once (§6.3: rekeys don't wait for an
    /// approval). Hand it to [`Keyring::activate`](super::Keyring::activate).
    pub epoch: Epoch,
    /// The `hs.fin` inner plaintext.
    pub inner: Inner,
}

impl std::fmt::Debug for Established {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Established").field("epoch", &self.epoch).finish_non_exhaustive()
    }
}

/// The responder's choice (§4.1): the highest offered suite that is
/// supported and not below the pin.
fn negotiate(offered: &[u64], pinned: u8) -> Result<u8, HandshakeError> {
    validate_offer(offered)?;
    let mut last = Err(HandshakeError::Suite(crate::suite::SuiteError::UnsupportedSuite));
    for s in offered.iter().rev() {
        last = check_chosen(*s, offered, pinned).map(|()| *s as u8);
        if last.is_ok() {
            break;
        }
    }
    last
}

/// Answer a rekey `hs.init` (raw envelope `raw`, inner plaintext `inner`)
/// that opened under `current`, which **must** be the session's current
/// epoch (a rekey is accepted only there, §6.2). Returns the responder
/// awaiting `hs.fin`, and `hs.resp` to deposit.
pub fn answer_rekey(raw: &[u8], inner: &Inner, current: &Epoch, cfg: &RekeyConfig) -> Result<(Responder, Vec<u8>), HandshakeError> {
    answer_rekey_with(raw, inner, current, cfg, &mut Os)
}

pub(super) fn answer_rekey_with(
    raw: &[u8],
    inner: &Inner,
    current: &Epoch,
    cfg: &RekeyConfig,
    rng: &mut impl Randomness,
) -> Result<(Responder, Vec<u8>), HandshakeError> {
    if cfg.policy.max_age <= chrono::TimeDelta::zero() && cfg.policy.max_messages == 0 {
        return Err(HandshakeError::Config);
    }
    if inner.kind != TYPE_INIT {
        return Err(HandshakeError::Type);
    }
    inner.check_time(cfg.now, true)?;
    let body = Init::parse(&inner.body)?;
    if body.purpose != Purpose::Rekey {
        return Err(HandshakeError::Purpose);
    }
    if body.ctx != epoch_ctx(&current.id()) {
        return Err(HandshakeError::Ctx);
    }
    // §6.3: the collect sender is from.relay.pk, and (for a rekey) the
    // relay key on record; from.ik is the identity on record.
    if cfg.collect_sender.as_bytes() != body.from.relay.pk.as_bytes() || cfg.collect_sender.as_bytes() != cfg.peer_relay_key.as_bytes() {
        return Err(HandshakeError::Sender);
    }
    if body.from.ik.as_bytes() != cfg.peer_ik.as_bytes() {
        return Err(HandshakeError::Identity);
    }
    let chosen = negotiate(&body.suites, cfg.pinned_suite)?;
    let ks = current.rk()?;
    let id = match &cfg.id {
        Some(id) => id.clone(),
        None => new_ulid(cfg.now)?,
    };
    let mut sealer = rng.sealer(&body.eph, ANONYMOUS)?;
    let mut ke = Zeroizing::new([0u8; KEY_SIZE]);
    sealer.export(LABEL_HS_KE.as_bytes(), &mut ke[..])?;
    let t = th(raw, sealer.header());
    let sched = Schedule::derive(ks, &ke, th1(raw), t);
    let resp = Resp { token: None, reconnect_token: None, suite: u64::from(chosen), sas_nonce: None, sig: sign_resp(&cfg.identity, &t) };
    let resp_inner = Inner {
        id,
        kind: TYPE_RESP.into(),
        ts: cfg.now,
        seq: None,
        response: None,
        exp: None,
        body: Zeroizing::new(resp.marshal(Purpose::Rekey)?),
    };
    let padded = Zeroizing::new(resp_inner.encode(Mode::Sealed)?);
    let out = sealer.seal(&padded)?;
    let pending = Epoch::new(&sched, Role::Responder, chosen, cfg.policy, cfg.now).snapshot();
    Ok((Responder { pending: Some(pending), th: t, verify_ik: body.from.ik, sender: body.from.relay.pk, since: cfg.now }, out))
}

impl Responder {
    /// The `(recipient_kid, sender_kid)` that `hs.fin` and every message
    /// of the new epoch to this side carry, so the caller can route one
    /// to this responder. `None` once done.
    pub fn kids(&self) -> Option<(Kid, Kid)> {
        self.pending.as_ref().map(|p| (p.recv.1, p.recv.2))
    }

    /// Whether `env` is addressed to the new epoch (by its kids, in
    /// constant time).
    pub fn addressed(&self, env: &Envelope) -> bool {
        self.kids().is_some_and(|(r, s)| env.recipient_kid().ct_eq(&r) & env.sender_kid().ct_eq(&s))
    }

    /// When `hs.resp` was built.
    pub fn since(&self) -> DateTime<Utc> {
        self.since
    }

    /// Whether `hs.fin` can no longer come: past the durable lifetime it
    /// would fail the time check (§8.4), and the new epoch's messages must
    /// not stay unacked for it (§6.5). The caller then aborts it.
    pub fn expired(&self, now: DateTime<Utc>) -> bool {
        now - self.since > MAX_DURABLE_AGE
    }

    /// Whether the handshake has ended (established or aborted).
    pub fn is_done(&self) -> bool {
        self.pending.is_none()
    }

    /// Destroy the pending state; any later `handle_fin` fails.
    pub fn abort(&mut self) {
        self.pending = None;
    }

    /// The stored form, while waiting.
    pub fn snapshot(&self) -> Result<ResponderState, HandshakeError> {
        let pending = self.pending.clone().ok_or(HandshakeError::Done)?;
        Ok(ResponderState { pending, th: self.th, verify_ik: self.verify_ik, sender: self.sender, since: self.since })
    }

    /// A waiting responder from its stored form.
    pub fn restore(s: ResponderState) -> Result<Self, HandshakeError> {
        let p = &s.pending;
        if p.role != Role::Responder || p.active || p.send.is_none() || p.rk.is_none() {
            return Err(HandshakeError::Config);
        }
        Ok(Responder { pending: Some(s.pending), th: s.th, verify_ik: s.verify_ik, sender: s.sender, since: s.since })
    }

    /// Process a message collected with relay `sender` `collect_sender`
    /// that may be `hs.fin`.
    ///
    /// - `Ok`: `sig_I` verified; the new epoch is established and active,
    ///   and the handshake is done.
    /// - [`HandshakeError::Type`]: it decrypted under the new epoch but is
    ///   another message: leave it **unacked** (see the module doc). The
    ///   handshake stays pending.
    /// - Any other error: the message isn't a valid `hs.fin` for this
    ///   handshake (another key, junk, stale, a bad `sig_I`), and the
    ///   handshake stays pending.
    pub fn handle_fin(&mut self, raw: &[u8], collect_sender: &VerifyingKey, now: DateTime<Utc>) -> Result<Established, HandshakeError> {
        let pending = self.pending.as_ref().ok_or(HandshakeError::Done)?;
        if collect_sender.as_bytes() != self.sender.as_bytes() {
            return Err(HandshakeError::Sender);
        }
        let env = Envelope::parse(raw)?;
        if env.mode() != Mode::Session {
            return Err(EnvelopeError::WrongMode.into());
        }
        // A copy, used to decrypt and check: the stored state is kept as
        // it is until hs.fin verifies.
        let mut epoch = Epoch::restore(pending.clone());
        let inner = epoch.open(&env)?;
        if inner.kind != TYPE_FIN {
            return Err(HandshakeError::Type);
        }
        inner.check_time(now, true)?;
        let fin = Fin::parse(&inner.body, Purpose::Rekey)?;
        verify_fin(&self.verify_ik, &self.th, &fin.sig)?;
        self.pending = None;
        epoch.activate(now);
        Ok(Established { epoch, inner })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{Keyring, POLICY_VAULT_TO_DEVICE};
    use crate::suite::hpke::tests::{setup_sender_with, FixedRng};
    use crate::suite::kem::{PrivateKey, PublicKey};
    use crate::suite::sign::identity_from_seed;
    use crate::suite::{vectors, INFO_SEALED};
    use crate::envelope::Sealer;
    use chrono::TimeDelta;

    /// The vector's `hs.resp` randomness; nothing else is asked for.
    struct Fixed(Vec<u8>);

    impl Randomness for Fixed {
        fn ephemeral(&mut self) -> Result<PrivateKey, HandshakeError> {
            unreachable!("a responder makes no ephemeral KEM key")
        }
        fn sas_nonce(&mut self) -> Result<[u8; 32], HandshakeError> {
            unreachable!("a rekey has no SAS")
        }
        fn sealer(&mut self, recipient: &PublicKey, sender_kid: Kid) -> Result<Sealer, HandshakeError> {
            let mut rng = FixedRng(self.0.clone(), 0);
            let (enc, ctx) = setup_sender_with(recipient, INFO_SEALED.as_bytes(), &mut rng);
            Ok(Sealer::from_parts(recipient, sender_kid, &enc, ctx))
        }
        fn session_nonce(&mut self) -> Result<[u8; 24], HandshakeError> {
            unreachable!("a responder seals no session message here")
        }
    }

    fn arr<const N: usize>(v: &serde_json::Value) -> [u8; N] {
        vectors::hex(v).try_into().unwrap()
    }

    fn vk(v: &serde_json::Value) -> VerifyingKey {
        VerifyingKey::from_bytes(&vectors::b64(v).try_into().unwrap()).unwrap()
    }

    fn kid(v: &serde_json::Value) -> Kid {
        Kid(arr(v))
    }

    /// An epoch from the vector's values, for `role`.
    fn epoch(e: &serde_json::Value, role: Role, rk: bool, now: DateTime<Utc>) -> Epoch {
        let i2r = (Zeroizing::new(arr(&e["k_i2r_hex"])), kid(&e["kid_i2r_hex"]), kid(&e["kid_r2i_hex"]));
        let r2i = (Zeroizing::new(arr(&e["k_r2i_hex"])), kid(&e["kid_r2i_hex"]), kid(&e["kid_i2r_hex"]));
        let (send, recv) = match role {
            Role::Initiator => (i2r, r2i),
            Role::Responder => (r2i, i2r),
        };
        Epoch::restore(EpochState {
            id: arr(&e["epoch_id_hex"]),
            role,
            suite: 2,
            policy: POLICY_VAULT_TO_DEVICE,
            created: now,
            active: true,
            send: Some(send),
            recv,
            rk: rk.then(|| Zeroizing::new(arr(&e["rk_hex"]))),
            last_seq: 1,
            sent: 1,
            received: 0,
        })
    }

    struct Setup {
        v: serde_json::Value,
        now: DateTime<Utc>,
        /// The desktop's (keys.json initiator's) epoch before the rekey.
        old: Epoch,
        cfg: RekeyConfig,
        /// The vault's relay key.
        vault_relay: VerifyingKey,
        rng: Fixed,
    }

    fn setup() -> Setup {
        let v = vectors::load("rekey");
        let keys = vectors::load("keys");
        let (ini, vault) = (&keys["initiator"], &keys["vault"]);
        let inputs = &v["inputs"];
        let now = crate::envelope::parse_ts(inputs["ts"].as_str().unwrap()).unwrap();
        let old = epoch(&v["old_epoch"], Role::Initiator, true, now - TimeDelta::days(1));
        let vault_relay = vk(&vault["relay_pk_b64"]);
        let cfg = RekeyConfig {
            identity: identity_from_seed(&vectors::seed(&ini["ik_seed_hex"])),
            peer_ik: vk(&vault["ik_pk_b64"]),
            peer_relay_key: vault_relay,
            collect_sender: vault_relay,
            pinned_suite: 2,
            policy: POLICY_VAULT_TO_DEVICE,
            id: Some(inputs["resp_id"].as_str().unwrap().into()),
            now,
        };
        let rng = Fixed(vectors::hex(&inputs["resp_encapsulation_randomness_hex"]));
        Setup { v, now, old, cfg, vault_relay, rng }
    }

    fn open_init(s: &mut Setup) -> (Vec<u8>, Inner) {
        let raw = vectors::b64(&s.v["hs_init_envelope_b64"]);
        let inner = s.old.open(&Envelope::parse(&raw).unwrap()).unwrap();
        (raw, inner)
    }

    /// The `hs.fin` and first-message envelopes of the vector.
    fn env(s: &Setup, name: &str) -> Vec<u8> {
        match name {
            "fin" => vectors::b64(&s.v["hs_fin_envelope_b64"]),
            m => vectors::b64(&s.v[m]["envelope_b64"]),
        }
    }

    /// rekey.json from the responder's side, byte for byte: the hs.init
    /// opens under the old epoch, hs.resp is the vector's, the new epoch's
    /// first message before hs.fin is left for redelivery, hs.fin
    /// establishes the epoch, and both directions of the new epoch match.
    #[test]
    fn rekey_vector() {
        let mut s = setup();
        let (raw, inner) = open_init(&mut s);
        assert_eq!(inner.marshal(Mode::Session).unwrap(), s.v["hs_init_inner"].as_str().unwrap());
        let (mut r, resp) = answer_rekey_with(&raw, &inner, &s.old, &s.cfg, &mut s.rng).unwrap();
        assert_eq!(resp, vectors::b64(&s.v["hs_resp_envelope_b64"]));
        assert_eq!(r.th.to_vec(), vectors::hex(&s.v["th_hex"]));
        assert_eq!(r.kids(), Some((kid(&s.v["new_epoch"]["kid_i2r_hex"]), kid(&s.v["new_epoch"]["kid_r2i_hex"]))));

        // The vault's first message of the new epoch, before hs.fin.
        let early = env(&s, "message_i2r");
        assert!(r.addressed(&Envelope::parse(&early).unwrap()));
        assert_eq!(r.handle_fin(&early, &s.vault_relay, s.now).unwrap_err(), HandshakeError::Type);
        assert!(!r.is_done(), "still waiting for hs.fin");

        let done = r.handle_fin(&env(&s, "fin"), &s.vault_relay, s.now).unwrap();
        assert!(r.is_done());
        let mut e = done.epoch;
        assert_eq!((done.inner.kind.as_str(), done.inner.seq), (TYPE_FIN, Some(1)));
        assert_eq!(e.id().to_vec(), vectors::hex(&s.v["new_epoch"]["epoch_id_hex"]));
        assert!(e.is_active() && e.role() == Role::Responder);
        assert_eq!(e.rk().unwrap().to_vec(), vectors::hex(&s.v["new_epoch"]["rk_hex"]));

        // Redelivered, the early message now opens, with seq 2.
        let m = e.open(&Envelope::parse(&early).unwrap()).unwrap();
        assert_eq!(m.marshal(Mode::Session).unwrap(), s.v["message_i2r"]["inner"].as_str().unwrap());
        // The other direction, with the vector's nonce, is its message.
        let mut back = Inner::parse(s.v["message_r2i"]["inner"].as_str().unwrap().as_bytes(), Mode::Session).unwrap();
        back.seq = None;
        let out = e.seal_with(&mut back, &arr(&s.v["inputs"]["msg_r2i_nonce_hex"])).unwrap();
        assert_eq!(out, env(&s, "message_r2i"));

        // One hs.fin per handshake.
        assert_eq!(r.handle_fin(&env(&s, "fin"), &s.vault_relay, s.now).unwrap_err(), HandshakeError::Done);
    }

    /// The keyring: activating the new epoch retires the old one's send
    /// key and rk, keeps its receive key 16 days, and routes by kid.
    #[test]
    fn keyring_after_the_rekey() {
        let mut s = setup();
        let (raw, _) = open_init(&mut s);
        let mut ring = Keyring::new(epoch(&s.v["old_epoch"], Role::Initiator, true, s.now - TimeDelta::days(1)));
        let (inner, current) = ring.open(&Envelope::parse(&raw).unwrap(), s.now).unwrap();
        assert!(current, "the hs.init opened under the current epoch");
        let (mut r, _) = answer_rekey_with(&raw, &inner, ring.current(), &s.cfg, &mut s.rng).unwrap();
        // Before hs.fin, the early message has no epoch in the ring.
        let early = Envelope::parse(&env(&s, "message_i2r")).unwrap();
        assert_eq!(ring.open(&early, s.now).unwrap_err(), HandshakeError::Envelope(EnvelopeError::Kid));
        let done = r.handle_fin(&env(&s, "fin"), &s.vault_relay, s.now).unwrap();
        ring.activate(done.epoch, s.now);
        assert_eq!(ring.current().id().to_vec(), vectors::hex(&s.v["new_epoch"]["epoch_id_hex"]));
        assert!(ring.open(&early, s.now).unwrap().1, "the new epoch is current");
        // A late message of the old epoch still opens, as retired.
        let (_, current) = ring.open(&Envelope::parse(&raw).unwrap(), s.now).unwrap();
        assert!(!current);
        // The old epoch can't send or start a rekey any more.
        let snap = ring.snapshot();
        assert_eq!(snap.retired.len(), 1);
        assert!(snap.retired[0].0.send.is_none() && snap.retired[0].0.rk.is_none());
        // The receive key goes after 16 days.
        let later = s.now + TimeDelta::days(16) + TimeDelta::seconds(1);
        let mut ring = Keyring::restore(snap).unwrap();
        assert!(ring.open(&Envelope::parse(&raw).unwrap(), s.now + TimeDelta::days(16)).is_ok());
        assert_eq!(ring.open(&Envelope::parse(&raw).unwrap(), later).unwrap_err(), HandshakeError::Envelope(EnvelopeError::Kid));
        ring.prune(later);
        assert!(ring.snapshot().retired.is_empty());
    }

    /// A rekey is accepted only from the vault on record, for the current
    /// epoch, with purpose rekey.
    #[test]
    fn refused_inits() {
        let stranger = SigningKey::from_bytes(&[9; 32]).verifying_key();
        for (why, want) in [
            ("collect sender", HandshakeError::Sender),
            ("relay key on record", HandshakeError::Sender),
            ("identity on record", HandshakeError::Identity),
            ("another epoch", HandshakeError::Ctx),
            ("retired epoch", HandshakeError::EpochRetired),
            ("stale", HandshakeError::Envelope(EnvelopeError::ClockPast)),
            ("not hs.init", HandshakeError::Type),
            ("pinned above", HandshakeError::Suite(crate::suite::SuiteError::UnsupportedSuite)),
        ] {
            let mut s = setup();
            let (raw, mut inner) = open_init(&mut s);
            let mut current = epoch(&s.v["old_epoch"], Role::Initiator, true, s.now);
            match why {
                "collect sender" => s.cfg.collect_sender = stranger,
                "relay key on record" => s.cfg.peer_relay_key = stranger,
                "identity on record" => s.cfg.peer_ik = stranger,
                "another epoch" => current = epoch(&s.v["new_epoch"], Role::Initiator, true, s.now),
                "retired epoch" => current = epoch(&s.v["old_epoch"], Role::Initiator, false, s.now),
                "stale" => s.cfg.now = s.now + TimeDelta::days(17),
                "not hs.init" => inner.kind = "hs.fin".into(),
                _ => s.cfg.pinned_suite = 3,
            }
            assert_eq!(answer_rekey_with(&raw, &inner, &current, &s.cfg, &mut s.rng).unwrap_err(), want, "{why}");
        }
        // Another purpose under the session: refused.
        let mut s = setup();
        let (raw, mut inner) = open_init(&mut s);
        let body = inner.body.replace(r#""purpose":"rekey""#, r#""purpose":"reconnect""#);
        inner.body = Zeroizing::new(body);
        assert!(answer_rekey_with(&raw, &inner, &s.old, &s.cfg, &mut s.rng).is_err());
    }

    /// Nothing but a verifying hs.fin from the vault's relay key ends the
    /// wait; a forged or stale one leaves it pending.
    #[test]
    fn bad_fins_keep_it_pending() {
        let mut s = setup();
        let (raw, inner) = open_init(&mut s);
        let (mut r, _) = answer_rekey_with(&raw, &inner, &s.old, &s.cfg, &mut s.rng).unwrap();
        let fin = env(&s, "fin");
        let stranger = SigningKey::from_bytes(&[9; 32]).verifying_key();
        assert_eq!(r.handle_fin(&fin, &stranger, s.now).unwrap_err(), HandshakeError::Sender);
        assert!(r.handle_fin(b"junk", &s.vault_relay, s.now).is_err());
        let mut tampered = fin.clone();
        let n = tampered.len();
        tampered[n - 1] ^= 1;
        assert!(r.handle_fin(&tampered, &s.vault_relay, s.now).is_err());
        // An hs.fin of the new epoch whose sig_I doesn't verify.
        let mut vault_side = epoch(&s.v["new_epoch"], Role::Initiator, true, s.now);
        let forged_body = Fin { sig: [1; 64], sas_nonce: None }.marshal(Purpose::Rekey).unwrap();
        let mut forged = Inner { id: new_ulid(s.now).unwrap(), kind: TYPE_FIN.into(), ts: s.now, seq: None, response: None, exp: None, body: Zeroizing::new(forged_body) };
        let forged = vault_side.seal(&mut forged).unwrap();
        assert_eq!(r.handle_fin(&forged, &s.vault_relay, s.now).unwrap_err(), HandshakeError::SigFin);
        // The vector's hs.fin, too late.
        assert_eq!(r.handle_fin(&fin, &s.vault_relay, s.now + TimeDelta::days(17)).unwrap_err(), HandshakeError::Envelope(EnvelopeError::ClockPast));
        assert!(!r.is_done());
        assert!(!r.expired(s.now + TimeDelta::days(16)) && r.expired(s.now + TimeDelta::days(16) + TimeDelta::seconds(1)));
        // A stored and restored responder still takes the real one.
        let mut r = Responder::restore(r.snapshot().unwrap()).unwrap();
        assert!(r.handle_fin(&fin, &s.vault_relay, s.now).is_ok());
        assert_eq!(r.snapshot().unwrap_err(), HandshakeError::Done);
        assert_eq!(format!("{r:?}"), "Responder { done: true, .. }");
    }

    #[test]
    fn aborted_and_restored_states() {
        let mut s = setup();
        let (raw, inner) = open_init(&mut s);
        let (mut r, _) = answer_rekey_with(&raw, &inner, &s.old, &s.cfg, &mut s.rng).unwrap();
        let mut bad = r.snapshot().unwrap();
        assert_eq!(format!("{bad:?}"), "ResponderState(..)");
        bad.pending.active = true;
        assert_eq!(Responder::restore(bad).unwrap_err(), HandshakeError::Config);
        r.abort();
        assert!(r.is_done() && r.kids().is_none());
        assert_eq!(r.handle_fin(&env(&s, "fin"), &s.vault_relay, s.now).unwrap_err(), HandshakeError::Done);
        // The release path draws fresh randomness: another hs.resp.
        let s = setup();
        let mut s2 = setup();
        let (raw, inner) = open_init(&mut s2);
        let (_, a) = answer_rekey(&raw, &inner, &s.old, &s.cfg).unwrap();
        let (_, b) = answer_rekey(&raw, &inner, &s.old, &s.cfg).unwrap();
        assert_ne!(a, b);
    }
}
