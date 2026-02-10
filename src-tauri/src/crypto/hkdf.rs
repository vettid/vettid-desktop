use hkdf::Hkdf;
use sha2::Sha256;

use crate::crypto::encrypt::CryptoError;

/// Derive a 32-byte encryption key from a shared secret using HKDF-SHA256.
///
/// Parameters:
/// - `shared_secret`: The input key material (e.g., from X25519 ECDH)
/// - `domain`: Domain separation string used as the HKDF salt
///
/// HKDF configuration:
/// - Hash: SHA-256
/// - Salt: domain string bytes (provides domain separation)
/// - Info: empty (domain in salt provides sufficient separation)
/// - Output: 32 bytes
///
/// This matches the Go `encryptWithDomain` / `decryptWithDomain` HKDF usage:
/// ```go
/// hkdfReader := hkdf.New(sha256.New, sharedSecret, []byte(domain), nil)
/// ```
///
/// SECURITY: The output key should be zeroized after use.
pub fn derive_key_hkdf(shared_secret: &[u8], domain: &str) -> Result<[u8; 32], CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(domain.as_bytes()), shared_secret);

    let mut okm = [0u8; 32];
    hk.expand(&[], &mut okm).map_err(|e| {
        CryptoError::KeyDerivationFailed(format!("HKDF expand failed: {}", e))
    })?;

    Ok(okm)
}

/// Derive a 32-byte connection key from a shared secret.
///
/// Convenience wrapper around [`derive_key_hkdf`] using the
/// `"vettid-connection-v1"` domain constant.
pub fn derive_connection_key(shared_secret: &[u8]) -> Result<[u8; 32], CryptoError> {
    derive_key_hkdf(shared_secret, "vettid-connection-v1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_hkdf_deterministic() {
        let secret = [0x42u8; 32];
        let key1 = derive_key_hkdf(&secret, "test-domain").expect("derivation should succeed");
        let key2 = derive_key_hkdf(&secret, "test-domain").expect("derivation should succeed");
        assert_eq!(key1, key2, "same inputs must produce same output");
    }

    #[test]
    fn test_different_domains_produce_different_keys() {
        let secret = [0x42u8; 32];
        let key1 =
            derive_key_hkdf(&secret, "vettid-device-v1").expect("derivation should succeed");
        let key2 = derive_key_hkdf(&secret, "vettid-connection-v1")
            .expect("derivation should succeed");
        assert_ne!(
            key1, key2,
            "different domains must produce different keys"
        );
    }

    #[test]
    fn test_different_secrets_produce_different_keys() {
        let secret1 = [0x42u8; 32];
        let secret2 = [0x43u8; 32];
        let key1 =
            derive_key_hkdf(&secret1, "same-domain").expect("derivation should succeed");
        let key2 =
            derive_key_hkdf(&secret2, "same-domain").expect("derivation should succeed");
        assert_ne!(
            key1, key2,
            "different secrets must produce different keys"
        );
    }

    #[test]
    fn test_derive_connection_key() {
        let secret = [0x42u8; 32];
        let key1 = derive_connection_key(&secret).expect("derivation should succeed");
        let key2 = derive_key_hkdf(&secret, "vettid-connection-v1")
            .expect("derivation should succeed");
        assert_eq!(
            key1, key2,
            "derive_connection_key must use vettid-connection-v1 domain"
        );
    }

    #[test]
    fn test_output_is_32_bytes() {
        let secret = [0xFFu8; 64]; // non-standard length input
        let key = derive_key_hkdf(&secret, "any-domain").expect("derivation should succeed");
        assert_eq!(key.len(), 32);
    }
}
