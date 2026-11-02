//! Session mode: XChaCha20-Poly1305 with a fresh random 24-byte nonce per
//! message (VAULT-MESSAGING §4.2). Random nonces of this length need no
//! counters.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use super::{random, SuiteError, KEY_SIZE, XNONCE_SIZE};

/// A fresh random nonce.
pub fn fresh_nonce() -> Result<[u8; XNONCE_SIZE], SuiteError> {
    let mut n = [0u8; XNONCE_SIZE];
    random(&mut n)?;
    Ok(n)
}

/// Seal under `key` with `nonce`.
pub fn seal_x(key: &[u8; KEY_SIZE], nonce: &[u8; XNONCE_SIZE], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SuiteError> {
    XChaCha20Poly1305::new(key.into())
        .encrypt(XNonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| SuiteError::Decrypt)
}

/// Open under `key` with `nonce`.
pub fn open_x(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; XNONCE_SIZE],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SuiteError> {
    XChaCha20Poly1305::new(key.into())
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map(Zeroizing::new)
        .map_err(|_| SuiteError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// draft-irtf-cfrg-xchacha-03 §A.3.1: the AEAD_XChaCha20_Poly1305 test
    /// vector.
    #[test]
    fn xchacha_draft_vector() {
        let key: [u8; 32] = hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap().try_into().unwrap();
        let nonce: [u8; 24] = hex::decode("404142434445464748494a4b4c4d4e4f5051525354555657").unwrap().try_into().unwrap();
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let ct = seal_x(&key, &nonce, &aad, pt).unwrap();
        assert_eq!(
            hex::encode(&ct),
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52ec0875924c1c7987947deafd8780acf49"
        );
        assert_eq!(&open_x(&key, &nonce, &aad, &ct).unwrap()[..], &pt[..]);
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(matches!(open_x(&key, &nonce, &aad, &bad), Err(SuiteError::Decrypt)));
        assert!(matches!(open_x(&key, &nonce, b"", &ct), Err(SuiteError::Decrypt)));
    }

    #[test]
    fn fresh_nonces_differ() {
        assert_ne!(fresh_nonce().unwrap(), fresh_nonce().unwrap());
    }
}
