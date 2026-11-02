//! Labelled Ed25519 signatures (VAULT-MESSAGING §4.1): the signature is
//! over `label ‖ msg`, so a signature for one purpose never verifies for
//! another.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use super::SuiteError;

/// The identity key `ik` for a 32-byte seed (§3.2).
pub fn identity_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

fn labelled(label: &str, msg: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(label.len() + msg.len());
    m.extend_from_slice(label.as_bytes());
    m.extend_from_slice(msg);
    m
}

/// Sign `label ‖ msg`.
pub fn sign(key: &SigningKey, label: &str, msg: &[u8]) -> [u8; 64] {
    key.sign(&labelled(label, msg)).to_bytes()
}

/// Verify a signature over `label ‖ msg`. `verify_strict`: as Go's
/// `ed25519.Verify` (S < L), and also refusing small-order keys and R,
/// which an honest key never produces.
pub fn verify(key: &VerifyingKey, label: &str, msg: &[u8], sig: &[u8]) -> Result<(), SuiteError> {
    let sig = Signature::from_slice(sig).map_err(|_| SuiteError::Signature)?;
    key.verify_strict(&labelled(label, msg), &sig).map_err(|_| SuiteError::Signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suite::vectors;

    /// keys.json: each identity seed gives its `ik` public key.
    #[test]
    fn identity_keys_vector() {
        use base64::Engine;
        let v = vectors::load("keys");
        for party in ["vault", "initiator"] {
            let ik = identity_from_seed(&vectors::seed(&v[party]["ik_seed_hex"]));
            assert_eq!(
                base64::engine::general_purpose::STANDARD.encode(ik.verifying_key().as_bytes()),
                v[party]["ik_pk_b64"].as_str().unwrap(),
                "{party}"
            );
        }
    }

    /// keys.json: each relay seed gives its relay key and mailbox id (the
    /// relay crate's §3.2 derivation).
    #[test]
    fn relay_keys_vector() {
        let v = vectors::load("keys");
        for party in ["vault", "initiator"] {
            let key = ed25519_dalek::SigningKey::from_bytes(&vectors::seed(&v[party]["relay_seed_hex"]));
            assert_eq!(vettid_relay::auth::encode_key(&key.verifying_key()), v[party]["relay_pk_b64"].as_str().unwrap(), "{party}");
            assert_eq!(vettid_relay::auth::mailbox_id(&key.verifying_key()), v[party]["mailbox"].as_str().unwrap(), "{party}");
        }
    }

    /// A signature verifies only for its own label, message and key.
    #[test]
    fn labels_bind_signatures() {
        let k = identity_from_seed(&[4; 32]);
        let sig = sign(&k, "vettid/vms/2/sig-resp", b"th");
        assert_eq!(verify(&k.verifying_key(), "vettid/vms/2/sig-resp", b"th", &sig), Ok(()));
        assert_eq!(verify(&k.verifying_key(), "vettid/vms/2/sig-fin", b"th", &sig), Err(SuiteError::Signature));
        assert_eq!(verify(&k.verifying_key(), "vettid/vms/2/sig-resp", b"tx", &sig), Err(SuiteError::Signature));
        let other = identity_from_seed(&[5; 32]);
        assert_eq!(verify(&other.verifying_key(), "vettid/vms/2/sig-resp", b"th", &sig), Err(SuiteError::Signature));
        assert_eq!(verify(&k.verifying_key(), "vettid/vms/2/sig-resp", b"th", &sig[..63]), Err(SuiteError::Signature));
    }
}
