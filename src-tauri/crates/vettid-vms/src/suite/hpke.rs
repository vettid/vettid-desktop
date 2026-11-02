//! HPKE base mode, single shot (RFC 9180; VAULT-MESSAGING §4.3), from the
//! `hpke` crate: KEM X-Wing (`0x647a`), KDF HKDF-SHA256, AEAD
//! ChaCha20-Poly1305, `info = "vettid/vms/2/sealed"`. This module only
//! adds the protocol's rule on top: each context seals or opens exactly
//! one message (§4.3).
//!
//! Release code encapsulates with the crate's own OS randomness
//! ([`hpke::setup_sender`]); only the known-answer tests pass fixed
//! randomness (`hpke::setup_sender_with_rng`, called in `#[cfg(test)]`
//! code only). The crate's `clippy.toml` disallows the `_with_rng`
//! functions, and CI runs clippy with `-D warnings`, so any other call is
//! an error.

use hpke::aead::{AeadCtxR, AeadCtxS};
use hpke::kem::XWing;
use hpke::{Deserializable, OpModeR, OpModeS, Serializable};
use zeroize::Zeroizing;

use super::kem::{PrivateKey, PublicKey};
use super::{SuiteError, ENC_SIZE};

type Kdf = hpke::kdf::HkdfSha256;
type Aead = hpke::aead::ChaCha20Poly1305;
type EncappedKey = <XWing as hpke::Kem>::EncappedKey;

/// A sending context, for exactly one message. Prints nothing.
pub struct Sender {
    ctx: AeadCtxS<Aead, Kdf, XWing>,
    used: bool,
}

/// A receiving context, for exactly one message. Prints nothing. It
/// exports only after its message opened (anyone can encapsulate to a
/// public key, so nothing derived is trusted before that).
pub struct Recipient {
    ctx: AeadCtxR<Aead, Kdf, XWing>,
    used: bool,
    opened: bool,
}

/// `SetupBaseS(pk, info)` with fresh OS randomness: `(enc, ctx)`.
///
/// If the operating system's random source fails, the crate panics rather
/// than encapsulate with weak randomness; nothing has been sealed then.
pub fn setup_sender(pk: &PublicKey, info: &[u8]) -> Result<([u8; ENC_SIZE], Sender), SuiteError> {
    let (enc, ctx) = hpke::setup_sender::<Aead, Kdf, XWing>(&OpModeS::Base, pk.inner(), info).map_err(|_| SuiteError::BadKey)?;
    Ok((enc_bytes(&enc)?, Sender { ctx, used: false }))
}

/// `SetupBaseR(enc, sk, info)`.
pub fn setup_recipient(enc: &[u8], sk: &PrivateKey, info: &[u8]) -> Result<Recipient, SuiteError> {
    if enc.len() != ENC_SIZE {
        return Err(SuiteError::KeySize);
    }
    // A low-order ct_X is refused, as Go and Kotlin do (see kem).
    if super::kem::x25519_low_order(enc[super::kem::CT_M_SIZE..].try_into().expect("size")) {
        return Err(SuiteError::Decrypt);
    }
    let enc = EncappedKey::from_bytes(enc).map_err(|_| SuiteError::BadKey)?;
    let ctx = hpke::setup_receiver::<Aead, Kdf, XWing>(&OpModeR::Base, sk.inner(), &enc, info).map_err(|_| SuiteError::Decrypt)?;
    Ok(Recipient { ctx, used: false, opened: false })
}

fn enc_bytes(enc: &EncappedKey) -> Result<[u8; ENC_SIZE], SuiteError> {
    enc.to_bytes().as_slice().try_into().map_err(|_| SuiteError::KeySize)
}

impl Sender {
    /// Seal the context's one message. The plaintext is the caller's to
    /// wipe.
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SuiteError> {
        take(&mut self.used)?;
        self.ctx.seal(plaintext, aad).map_err(|_| SuiteError::Encrypt)
    }

    /// `Export(exporter_context, L)`.
    pub fn export(&self, exporter_context: &[u8], out: &mut [u8]) -> Result<(), SuiteError> {
        self.ctx.export(exporter_context, out).map_err(|_| SuiteError::ExportLength)
    }
}

impl Recipient {
    /// Open the context's one message.
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, SuiteError> {
        take(&mut self.used)?;
        let plaintext = self.ctx.open(ciphertext, aad).map(Zeroizing::new).map_err(|_| SuiteError::Decrypt)?;
        self.opened = true;
        Ok(plaintext)
    }

    /// `Export(exporter_context, L)`, only after the message opened.
    pub fn export(&self, exporter_context: &[u8], out: &mut [u8]) -> Result<(), SuiteError> {
        if !self.opened {
            return Err(SuiteError::NotOpened);
        }
        self.ctx.export(exporter_context, out).map_err(|_| SuiteError::ExportLength)
    }
}

/// One message per context: the first call takes it, any later one
/// (also after a failed open) is refused.
fn take(used: &mut bool) -> Result<(), SuiteError> {
    if std::mem::replace(used, true) {
        Err(SuiteError::ContextUsed)
    } else {
        Ok(())
    }
}

impl std::fmt::Debug for Sender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("hpke::Sender(..)")
    }
}

impl std::fmt::Debug for Recipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("hpke::Recipient(..)")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::suite::{vectors, INFO_SEALED};
    use std::convert::Infallible;

    /// Fixed randomness for the known-answer tests: hands out its bytes in
    /// order, and panics if asked for more.
    pub(crate) struct FixedRng(pub Vec<u8>, pub usize);

    impl rand_core::TryRng for FixedRng {
        type Error = Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Infallible> {
            let mut b = [0u8; 4];
            self.try_fill_bytes(&mut b)?;
            Ok(u32::from_le_bytes(b))
        }
        fn try_next_u64(&mut self) -> Result<u64, Infallible> {
            let mut b = [0u8; 8];
            self.try_fill_bytes(&mut b)?;
            Ok(u64::from_le_bytes(b))
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
            for d in dst {
                *d = self.0[self.1];
                self.1 += 1;
            }
            Ok(())
        }
    }
    impl rand_core::TryCryptoRng for FixedRng {}

    /// `SetupBaseS` with fixed randomness (tests only; the crate's
    /// clippy.toml disallows it everywhere else).
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn setup_sender_with(pk: &PublicKey, info: &[u8], rng: &mut FixedRng) -> ([u8; ENC_SIZE], Sender) {
        let (enc, ctx) = hpke::setup_sender_with_rng::<Aead, Kdf, XWing>(&OpModeS::Base, pk.inner(), info, rng).unwrap();
        (enc_bytes(&enc).unwrap(), Sender { ctx, used: false })
    }

    /// RFC 9180 §4 `LabeledExpand`, written here only to check the
    /// vector's exporter secret against the crate's `Export`.
    fn labeled_expand(prk: &[u8], label: &str, info: &[u8], out: &mut [u8]) {
        let mut l = (out.len() as u16).to_be_bytes().to_vec();
        l.extend_from_slice(b"HPKE-v1HPKE");
        l.extend_from_slice(&[0x64, 0x7a, 0x00, 0x01, 0x00, 0x03]);
        l.extend_from_slice(label.as_bytes());
        l.extend_from_slice(info);
        hkdf::Hkdf::<sha2::Sha256>::from_prk(prk).unwrap().expand(&l, out).unwrap();
    }

    /// hpke.json, through the crate's public API: the vault's `ek` and the
    /// fixed randomness give exactly the vector's `enc`; the key and base
    /// nonce (sealing with the crate and with the vector's key and nonce
    /// directly give the same bytes); the exporter secret (one export
    /// recomputed from it); and the vault's key, from its seed, opens it.
    #[test]
    fn hpke_vector() {
        use chacha20poly1305::aead::{Aead as _, KeyInit, Payload};
        let v = vectors::load("hpke");
        assert_eq!(v["kem_id"], "0x647a");
        assert_eq!(v["info"], INFO_SEALED);
        let pk = PublicKey::parse(&vectors::b64(&v["recipient_ek_b64"])).unwrap();
        let mut rng = FixedRng(vectors::hex(&v["encapsulation_randomness_hex"]), 0);
        let (enc, mut sender) = setup_sender_with(&pk, INFO_SEALED.as_bytes(), &mut rng);
        assert_eq!(rng.1, 64, "the KEM takes exactly the 64 bytes of randomness");
        assert_eq!(enc.len(), v["enc_len"].as_u64().unwrap() as usize);
        assert_eq!(enc[..], vectors::b64(&v["enc_b64"])[..], "enc");

        let mut want = [0u8; 32];
        labeled_expand(&vectors::hex(&v["exporter_secret_hex"]), "sec", b"ctx", &mut want);
        let mut got = [0u8; 32];
        sender.export(b"ctx", &mut got).unwrap();
        assert_eq!(got, want, "exporter secret");

        let ct = sender.seal(b"aad", b"hello vault").unwrap();
        let direct = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&vectors::hex(&v["key_hex"]))
            .unwrap()
            .encrypt(vectors::hex(&v["base_nonce_hex"]).as_slice().into(), Payload { msg: b"hello vault", aad: b"aad" })
            .unwrap();
        assert_eq!(ct, direct, "key and base nonce");

        let keys = vectors::load("keys");
        let sk = PrivateKey::from_seed(&vectors::seed(&keys["vault"]["kem_seed_hex"])).unwrap();
        let mut recipient = setup_recipient(&enc, &sk, INFO_SEALED.as_bytes()).unwrap();
        let mut theirs = [0u8; 32];
        assert!(matches!(recipient.export(b"ctx", &mut theirs), Err(SuiteError::NotOpened)), "not before it opens");
        assert_eq!(&recipient.open(b"aad", &ct).unwrap()[..], b"hello vault");
        recipient.export(b"ctx", &mut theirs).unwrap();
        assert_eq!(theirs, want);
    }

    /// One message per context; a wrong AAD, info, key or ciphertext fails.
    #[test]
    fn one_message_per_context_and_authentication() {
        let sk = PrivateKey::generate().unwrap();
        let (enc, mut sender) = setup_sender(sk.public(), b"info").unwrap();
        let ct = sender.seal(b"aad", b"m").unwrap();
        assert!(matches!(sender.seal(b"aad", b"m2"), Err(SuiteError::ContextUsed)));

        let mut wrong_aad = setup_recipient(&enc, &sk, b"info").unwrap();
        assert!(matches!(wrong_aad.open(b"other", &ct), Err(SuiteError::Decrypt)));
        assert!(matches!(wrong_aad.open(b"aad", &ct), Err(SuiteError::ContextUsed)), "even after a failure");

        let mut wrong_info = setup_recipient(&enc, &sk, b"other info").unwrap();
        assert!(matches!(wrong_info.open(b"aad", &ct), Err(SuiteError::Decrypt)));

        let other = PrivateKey::generate().unwrap();
        let mut wrong_key = setup_recipient(&enc, &other, b"info").unwrap();
        assert!(matches!(wrong_key.open(b"aad", &ct), Err(SuiteError::Decrypt)));

        let mut tampered = ct.clone();
        tampered[0] ^= 1;
        let mut ok = setup_recipient(&enc, &sk, b"info").unwrap();
        assert!(matches!(ok.open(b"aad", &tampered), Err(SuiteError::Decrypt)));
        assert!(matches!(setup_recipient(&enc[..ENC_SIZE - 1], &sk, b"info"), Err(SuiteError::KeySize)));
        assert_eq!(format!("{ok:?}"), "hpke::Recipient(..)");
    }

    /// A changed `enc` decapsulates to another secret (ML-KEM's implicit
    /// rejection), so the message doesn't open; an over-long export is
    /// refused.
    #[test]
    fn a_tampered_enc_fails_to_open() {
        let sk = PrivateKey::generate().unwrap();
        let (mut enc, mut sender) = setup_sender(sk.public(), b"info").unwrap();
        let ct = sender.seal(b"aad", b"m").unwrap();
        enc[17] ^= 0x01;
        let mut r = setup_recipient(&enc, &sk, b"info").unwrap();
        assert!(matches!(r.open(b"aad", &ct), Err(SuiteError::Decrypt)));
        let mut out = [0u8; 32];
        assert!(matches!(r.export(b"ctx", &mut out), Err(SuiteError::NotOpened)), "nor after a failed open");
    }

    /// An `enc` whose X25519 part has low order is refused (Go and Kotlin
    /// refuse it too); an over-long export after a good open is refused.
    #[test]
    fn low_order_enc_and_long_exports_are_refused() {
        let sk = PrivateKey::generate().unwrap();
        let (enc, mut sender) = setup_sender(sk.public(), b"info").unwrap();
        let ct = sender.seal(b"aad", b"m").unwrap();
        for u in [[0u8; 32], { let mut one = [0u8; 32]; one[0] = 1; one }] {
            let mut bad = enc;
            bad[crate::suite::kem::CT_M_SIZE..].copy_from_slice(&u);
            assert!(matches!(setup_recipient(&bad, &sk, b"info"), Err(SuiteError::Decrypt)));
        }
        let mut r = setup_recipient(&enc, &sk, b"info").unwrap();
        r.open(b"aad", &ct).unwrap();
        let mut too_long = vec![0u8; 255 * 32 + 1];
        assert!(matches!(r.export(b"ctx", &mut too_long), Err(SuiteError::ExportLength)));
    }

    /// Two senders to the same key never share an `enc`: release code
    /// draws fresh randomness.
    #[test]
    fn release_senders_use_fresh_randomness() {
        let sk = PrivateKey::generate().unwrap();
        let (a, _) = setup_sender(sk.public(), b"info").unwrap();
        let (b, _) = setup_sender(sk.public(), b"info").unwrap();
        assert_ne!(a, b);
    }
}
