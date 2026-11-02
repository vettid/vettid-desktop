//! Sealing and opening envelopes (§5.2): session mode under an epoch's
//! directional key, sealed mode with HPKE to the recipient's KEM key.

use zeroize::Zeroizing;

use super::{header, valid_padded_len, Envelope, EnvelopeError, Mode, HEADER_SEALED, HEADER_SESSION, OFF_BODY};
use crate::suite::aead::{fresh_nonce, open_x, seal_x};
use crate::suite::hpke::{setup_recipient, setup_sender, Recipient, Sender};
use crate::suite::kem::{PrivateKey, PublicKey};
use crate::suite::kid::Kid;
use crate::suite::{INFO_SEALED, KEY_SIZE, XNONCE_SIZE};

/// A session-mode envelope: a fresh random 24-byte nonce, and
/// XChaCha20-Poly1305 under the epoch's directional key with the 44-byte
/// header as AAD. `padded` must be a padded inner plaintext.
pub fn seal_session(key: &[u8; KEY_SIZE], sender_kid: Kid, recipient_kid: Kid, padded: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    seal_session_with(key, sender_kid, recipient_kid, &fresh_nonce()?, padded)
}

/// [`seal_session`] with the nonce given. The nonce must be fresh
/// randomness: only the known-answer tests pass a fixed one.
pub(crate) fn seal_session_with(
    key: &[u8; KEY_SIZE],
    sender_kid: Kid,
    recipient_kid: Kid,
    nonce: &[u8; XNONCE_SIZE],
    padded: &[u8],
) -> Result<Vec<u8>, EnvelopeError> {
    if !valid_padded_len(padded.len()) {
        return Err(EnvelopeError::Length);
    }
    let mut env = header(Mode::Session, sender_kid, recipient_kid, nonce);
    let ct = seal_x(key, nonce, &env, padded)?;
    env.extend_from_slice(&ct);
    Ok(env)
}

/// Open a session-mode envelope: the padded inner plaintext. Choosing the
/// key by kid is the caller's job (the epoch's receive keys).
pub fn open_session(e: &Envelope, key: &[u8; KEY_SIZE]) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
    if e.mode != Mode::Session {
        return Err(EnvelopeError::WrongMode);
    }
    let nonce: &[u8; XNONCE_SIZE] = e.body().try_into().expect("parse checked the header");
    open_x(key, nonce, &e.raw[..HEADER_SESSION], e.ciphertext()).map_err(|_| EnvelopeError::Decrypt)
}

/// One sealed-mode envelope in two steps, so the caller can read the
/// header (and export from the HPKE context) before sealing: the handshake
/// puts `th`, which covers `hs.resp`'s header, inside `hs.resp` (§6.3).
pub struct Sealer {
    header: Vec<u8>,
    ctx: Sender,
}

impl std::fmt::Debug for Sealer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sealer(..)")
    }
}

impl Sealer {
    /// `SetupBaseS(ek_R, info = "vettid/vms/2/sealed")` (§4.3), and the
    /// header: `recipient_kid` is the kid of `ek_R`.
    pub fn new(recipient: &PublicKey, sender_kid: Kid) -> Result<Self, EnvelopeError> {
        let (enc, ctx) = setup_sender(recipient, INFO_SEALED.as_bytes())?;
        Ok(Self::from_parts(recipient, sender_kid, &enc, ctx))
    }

    /// A sealer from an HPKE context set up for `recipient`.
    pub(crate) fn from_parts(recipient: &PublicKey, sender_kid: Kid, enc: &[u8], ctx: Sender) -> Self {
        Sealer { header: header(Mode::Sealed, sender_kid, recipient.kid(), enc), ctx }
    }

    /// The 1,140-byte header (the AAD).
    pub fn header(&self) -> &[u8] {
        &self.header
    }

    /// `Export(exporter_context, L)` from the HPKE context (§4.3, §6.3).
    pub fn export(&self, exporter_context: &[u8], out: &mut [u8]) -> Result<(), EnvelopeError> {
        Ok(self.ctx.export(exporter_context, out)?)
    }

    /// Seal the padded inner plaintext: the envelope. A second call is
    /// refused (one message per context).
    pub fn seal(&mut self, padded: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
        if !valid_padded_len(padded.len()) {
            return Err(EnvelopeError::Length);
        }
        let ct = self.ctx.seal(&self.header, padded)?;
        let mut env = self.header.clone();
        env.extend_from_slice(&ct);
        Ok(env)
    }

    /// The HPKE context, for exports after sealing.
    pub fn into_context(self) -> Sender {
        self.ctx
    }
}

/// [`Sealer::new`] then [`Sealer::seal`]: the envelope, and the context
/// for exports.
pub fn seal_sealed(recipient: &PublicKey, sender_kid: Kid, padded: &[u8]) -> Result<(Vec<u8>, Sender), EnvelopeError> {
    let mut s = Sealer::new(recipient, sender_kid)?;
    let env = s.seal(padded)?;
    Ok((env, s.into_context()))
}

/// Open a sealed-mode envelope with the recipient's private key: the
/// padded inner plaintext and the context. The envelope's
/// `recipient_kid` must be the key's (compared in constant time): the
/// caller picks the key by kid, and no other key is ever tried (§4.4).
pub fn open_sealed(e: &Envelope, sk: &PrivateKey) -> Result<(Zeroizing<Vec<u8>>, Recipient), EnvelopeError> {
    if e.mode != Mode::Sealed {
        return Err(EnvelopeError::WrongMode);
    }
    if !e.recipient_kid.ct_eq(&sk.public().kid()) {
        return Err(EnvelopeError::Kid);
    }
    let mut r = setup_recipient(e.body(), sk, INFO_SEALED.as_bytes()).map_err(|_| EnvelopeError::Decrypt)?;
    let pt = r.open(&e.raw[..HEADER_SEALED], e.ciphertext()).map_err(|_| EnvelopeError::Decrypt)?;
    Ok((pt, r))
}

const _: () = assert!(HEADER_SEALED - OFF_BODY == crate::suite::ENC_SIZE);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{pad, unpad, Envelope};
    use crate::suite::hpke::tests::{setup_sender_with, FixedRng};
    use crate::suite::{vectors, SuiteError};
    use base64::Engine;

    const SPEC_INNER: &str = r#"{"v":1,"id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","type":"test.ping","ts":"2026-10-01T12:00:00.000Z","body":{}}"#;

    fn b64(v: &serde_json::Value) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD.decode(v.as_str().unwrap()).unwrap()
    }

    fn kid(v: &serde_json::Value) -> Kid {
        Kid(vectors::hex(v).try_into().unwrap())
    }

    /// envelope_session.json, byte for byte both ways.
    #[test]
    fn session_vector() {
        let v = vectors::load("envelope_session");
        let key: [u8; 32] = vectors::hex(&v["k_i2r_hex"]).try_into().unwrap();
        let nonce: [u8; 24] = vectors::hex(&v["nonce_hex"]).try_into().unwrap();
        let (sk, rk) = (kid(&v["sender_kid_hex"]), kid(&v["recipient_kid_hex"]));
        let inner = v["inner"].as_str().unwrap();
        let want_inner = SPEC_INNER.replacen(r#","body""#, r#","seq":1,"body""#, 1);
        assert_eq!(inner, want_inner, "the §16 inner with seq 1 after ts");
        let padded = pad(inner.as_bytes()).unwrap();
        assert_eq!(padded.len() as u64, v["padded_len"].as_u64().unwrap());
        let want = b64(&v["envelope_b64"]);
        assert_eq!(want.len() as u64, v["envelope_len"].as_u64().unwrap());

        assert_eq!(seal_session_with(&key, sk, rk, &nonce, &padded).unwrap(), want);
        let e = Envelope::parse(&want).unwrap();
        assert_eq!((e.mode(), e.sender_kid(), e.recipient_kid()), (Mode::Session, sk, rk));
        let opened = open_session(&e, &key).unwrap();
        assert_eq!(unpad(&opened).unwrap(), inner.as_bytes());

        // Any flipped byte fails: the header is the AAD.
        for at in [0usize, 3, 4, 12, 20, 44, want.len() - 1] {
            let mut bad = want.clone();
            bad[at] ^= 1;
            match Envelope::parse(&bad) {
                Ok(e) => assert_eq!(open_session(&e, &key).unwrap_err(), EnvelopeError::Decrypt, "byte {at}"),
                Err(_) => assert!(at < 4, "byte {at}"),
            }
        }
        assert_eq!(open_session(&e, &[7; 32]).unwrap_err(), EnvelopeError::Decrypt);
    }

    /// envelope_sealed.json: the vault opens it, and the same HPKE
    /// randomness seals the same bytes.
    #[test]
    fn sealed_vector() {
        let v = vectors::load("envelope_sealed");
        let h = vectors::load("hpke");
        let keys = vectors::load("keys");
        let vault = PrivateKey::from_seed(&vectors::seed(&keys["vault"]["kem_seed_hex"])).unwrap();
        let want = b64(&v["envelope_b64"]);
        assert_eq!(want.len(), 1668);
        assert_eq!(v["inner"].as_str().unwrap(), SPEC_INNER);

        let e = Envelope::parse(&want).unwrap();
        assert_eq!(e.mode(), Mode::Sealed);
        assert_eq!(e.sender_kid(), kid(&v["sender_kid_hex"]));
        assert!(e.sender_kid().is_anonymous());
        assert_eq!(e.recipient_kid(), kid(&v["recipient_kid_hex"]));
        assert_eq!(&want[20..1140], b64(&h["enc_b64"]).as_slice());
        let (padded, _) = open_sealed(&e, &vault).unwrap();
        assert_eq!(&padded[..], vectors::hex(&v["padded_hex"]).as_slice());
        assert_eq!(unpad(&padded).unwrap(), SPEC_INNER.as_bytes());

        let mut rng = FixedRng(vectors::hex(&h["encapsulation_randomness_hex"]), 0);
        let (enc, ctx) = setup_sender_with(vault.public(), INFO_SEALED.as_bytes(), &mut rng);
        let mut s = Sealer::from_parts(vault.public(), e.sender_kid(), &enc, ctx);
        assert_eq!(s.header(), &want[..1140]);
        assert_eq!(s.seal(&padded).unwrap(), want);
        assert_eq!(s.seal(&padded).unwrap_err(), EnvelopeError::Suite(SuiteError::ContextUsed));
    }

    #[test]
    fn sealed_round_trip_kids_and_modes() {
        let sk = PrivateKey::generate().unwrap();
        let padded = pad(b"{}").unwrap();
        let (env, sender) = seal_sealed(sk.public(), Kid([3; 8]), &padded).unwrap();
        let e = Envelope::parse(&env).unwrap();
        let (pt, recipient) = open_sealed(&e, &sk).unwrap();
        assert_eq!(&pt[..], padded.as_slice());
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        sender.export(b"ctx", &mut a).unwrap();
        recipient.export(b"ctx", &mut b).unwrap();
        assert_eq!(a, b);

        // Another key is never tried: its kid doesn't match.
        let other = PrivateKey::generate().unwrap();
        assert_eq!(open_sealed(&e, &other).unwrap_err(), EnvelopeError::Kid);
        // Wrong mode either way.
        assert_eq!(open_session(&e, &[0; 32]).unwrap_err(), EnvelopeError::WrongMode);
        let s = Envelope::parse(&seal_session(&[1; 32], Kid([1; 8]), Kid([2; 8]), &padded).unwrap()).unwrap();
        assert_eq!(open_sealed(&s, &sk).unwrap_err(), EnvelopeError::WrongMode);
        // A recipient kid that isn't the key's is refused before any
        // decryption.
        let mut wrong_kid = env.clone();
        wrong_kid[12] ^= 1;
        assert_eq!(open_sealed(&Envelope::parse(&wrong_kid).unwrap(), &sk).unwrap_err(), EnvelopeError::Kid);
        // A tampered header fails to open.
        let mut bad = env.clone();
        bad[5] ^= 1;
        assert_eq!(open_sealed(&Envelope::parse(&bad).unwrap(), &sk).unwrap_err(), EnvelopeError::Decrypt);
        // Only padded sizes are sealed.
        assert_eq!(seal_session(&[1; 32], Kid([1; 8]), Kid([2; 8]), b"{}").unwrap_err(), EnvelopeError::Length);
        assert_eq!(seal_sealed(sk.public(), Kid([1; 8]), &[0; 513]).unwrap_err(), EnvelopeError::Length);
    }

    #[test]
    fn session_nonces_are_fresh() {
        let padded = pad(b"{}").unwrap();
        let a = seal_session(&[1; 32], Kid([1; 8]), Kid([2; 8]), &padded).unwrap();
        let b = seal_session(&[1; 32], Kid([1; 8]), Kid([2; 8]), &padded).unwrap();
        assert_ne!(a[20..44], b[20..44]);
    }
}
