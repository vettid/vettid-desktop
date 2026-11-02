//! MLKEM768X25519, X-Wing (VAULT-MESSAGING §3.2, §4.3), from the `hpke`
//! crate (`hpke::kem::XWing`, on RustCrypto's `x-wing`). A private key is
//! its 32-byte seed (X-Wing's decapsulation key), as §3.2 says; `ek` is
//! the 1,216-byte encapsulation key. This module only wraps the crate's
//! types: it adds the kid, constant-time comparison and redacted `Debug`.

use hpke::kem::XWing;
use hpke::{Deserializable, Kem as _, Serializable};
use zeroize::Zeroizing;

use super::kid::{kid_of, Kid};
use super::{random, SuiteError, EK_SIZE, SEED_SIZE};

pub(crate) type XPublic = <XWing as hpke::Kem>::PublicKey;
pub(crate) type XPrivate = <XWing as hpke::Kem>::PrivateKey;

/// A static or ephemeral KEM public key (`ek`, 1,216 bytes).
#[derive(Clone)]
pub struct PublicKey {
    inner: XPublic,
    raw: Box<[u8; EK_SIZE]>,
    kid: Kid,
}

impl PublicKey {
    /// Parse an encapsulation key: the right size, accepted by the crate
    /// (its ML-KEM modulus check), and re-encoding to the same bytes, so a
    /// key has one spelling.
    pub fn parse(ek: &[u8]) -> Result<Self, SuiteError> {
        let raw: [u8; EK_SIZE] = ek.try_into().map_err(|_| SuiteError::KeySize)?;
        let inner = XPublic::from_bytes(&raw).map_err(|_| SuiteError::BadKey)?;
        if !super::ct_eq(inner.to_bytes().as_slice(), &raw) {
            return Err(SuiteError::BadKey);
        }
        Ok(Self { inner, kid: kid_of(&raw), raw: Box::new(raw) })
    }

    pub fn as_bytes(&self) -> &[u8; EK_SIZE] {
        &self.raw
    }

    pub fn kid(&self) -> Kid {
        self.kid
    }

    pub(crate) fn inner(&self) -> &XPublic {
        &self.inner
    }

    /// Constant-time equality of the encoded keys.
    pub fn ct_eq(&self, other: &Self) -> bool {
        super::ct_eq(&self.raw[..], &other.raw[..])
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "kem::PublicKey({})", self.kid)
    }
}

/// A KEM private key: its 32-byte seed (§3.2). The crate's key wipes itself
/// when dropped (`x-wing`'s `zeroize`); this prints nothing.
pub struct PrivateKey {
    inner: XPrivate,
    seed: Zeroizing<[u8; SEED_SIZE]>,
    public: PublicKey,
}

impl PrivateKey {
    /// The key for a seed.
    pub fn from_seed(seed: &[u8; SEED_SIZE]) -> Result<Self, SuiteError> {
        let inner = XPrivate::from_bytes(seed).map_err(|_| SuiteError::BadKey)?;
        let public = PublicKey::parse(XWing::sk_to_pk(&inner).to_bytes().as_slice())?;
        Ok(Self { inner, seed: Zeroizing::new(*seed), public })
    }

    /// A fresh key from the system's random source.
    pub fn generate() -> Result<Self, SuiteError> {
        let mut seed = Zeroizing::new([0u8; SEED_SIZE]);
        random(&mut seed[..])?;
        Self::from_seed(&seed)
    }

    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    /// The seed, for storage under the device's protector.
    pub fn seed(&self) -> &[u8; SEED_SIZE] {
        &self.seed
    }

    pub(crate) fn inner(&self) -> &XPrivate {
        &self.inner
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "kem::PrivateKey({})", self.public.kid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suite::vectors;

    /// keys.json: every party's seed gives its `ek` and kid.
    #[test]
    fn keys_vector() {
        let v = vectors::load("keys");
        for party in ["vault", "initiator", "initiator_ephemeral", "etk"] {
            let p = &v[party];
            let key = PrivateKey::from_seed(&vectors::seed(&p["kem_seed_hex"])).unwrap();
            assert_eq!(key.public().as_bytes()[..], vectors::b64(&p["ek_b64"])[..], "{party} ek");
            assert_eq!(key.public().kid().to_string(), p["kid_hex"].as_str().unwrap(), "{party} kid");
            let parsed = PublicKey::parse(&vectors::b64(&p["ek_b64"])).unwrap();
            assert!(parsed.ct_eq(key.public()));
        }
    }

    /// A wrong size or a non-canonical ML-KEM coefficient is refused.
    #[test]
    fn bad_keys_are_refused() {
        let v = vectors::load("keys");
        let ek = vectors::b64(&v["vault"]["ek_b64"]);
        assert!(matches!(PublicKey::parse(&ek[..EK_SIZE - 1]), Err(SuiteError::KeySize)));
        let mut bad = ek.clone();
        // The first 12-bit coefficient set to 0xfff (> q = 3329).
        bad[0] = 0xff;
        bad[1] |= 0x0f;
        assert!(matches!(PublicKey::parse(&bad), Err(SuiteError::BadKey)));
    }

    #[test]
    fn debug_prints_no_seed() {
        let k = PrivateKey::generate().unwrap();
        assert!(!format!("{k:?}").contains(&hex::encode(k.seed())));
    }
}
