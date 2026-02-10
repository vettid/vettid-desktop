use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use std::fmt;

/// XChaCha20-Poly1305 nonce size in bytes (24 bytes).
pub const NONCE_SIZE: usize = 24;

/// Encryption key size in bytes (256-bit).
pub const KEY_SIZE: usize = 32;

/// Minimum ciphertext size: nonce (24) + Poly1305 tag (16).
const MIN_CIPHERTEXT_SIZE: usize = NONCE_SIZE + 16;

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Clone)]
pub enum CryptoError {
    /// The encryption operation failed.
    EncryptionFailed(String),
    /// The decryption operation failed (e.g., authentication tag mismatch).
    DecryptionFailed(String),
    /// The input data is malformed or too short.
    InvalidInput(String),
    /// Key derivation failed.
    KeyDerivationFailed(String),
    /// Random number generation failed.
    RngFailed(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::EncryptionFailed(msg) => write!(f, "encryption failed: {}", msg),
            CryptoError::DecryptionFailed(msg) => write!(f, "decryption failed: {}", msg),
            CryptoError::InvalidInput(msg) => write!(f, "invalid input: {}", msg),
            CryptoError::KeyDerivationFailed(msg) => write!(f, "key derivation failed: {}", msg),
            CryptoError::RngFailed(msg) => write!(f, "RNG failed: {}", msg),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Encrypt plaintext using XChaCha20-Poly1305.
///
/// Generates a random 24-byte nonce and prepends it to the ciphertext.
///
/// Output format: `nonce (24 bytes) || ciphertext + authentication tag`
///
/// SECURITY: The key must be exactly 32 bytes of high-entropy material,
/// ideally derived via HKDF from a shared secret.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CryptoError::EncryptionFailed(format!("cipher creation failed: {}", e)))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(format!("AEAD seal failed: {}", e)))?;

    // Format: nonce || ciphertext+tag
    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt ciphertext produced by [`encrypt`].
///
/// Input format: `nonce (24 bytes) || ciphertext + authentication tag`
///
/// The minimum input size is 40 bytes (24 nonce + 16 tag with zero-length plaintext).
///
/// SECURITY: Returns `CryptoError::DecryptionFailed` on authentication failure.
/// Do not reveal whether the error was due to tag mismatch vs. other causes
/// to external callers (prevents oracle attacks).
pub fn decrypt(key: &[u8; 32], ciphertext_with_nonce: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if ciphertext_with_nonce.len() < MIN_CIPHERTEXT_SIZE {
        return Err(CryptoError::InvalidInput(format!(
            "ciphertext too short: need at least {} bytes, got {}",
            MIN_CIPHERTEXT_SIZE,
            ciphertext_with_nonce.len()
        )));
    }

    let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(NONCE_SIZE);
    let nonce = XNonce::from_slice(nonce_bytes);

    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CryptoError::DecryptionFailed(format!("cipher creation failed: {}", e)))?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| CryptoError::DecryptionFailed(format!("AEAD open failed: {}", e)))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"hello, VettID!";

        let encrypted = encrypt(&key, plaintext).expect("encryption should succeed");

        // Output should be nonce + ciphertext + tag
        assert!(encrypted.len() >= NONCE_SIZE + 16 + plaintext.len());

        let decrypted = decrypt(&key, &encrypted).expect("decryption should succeed");
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let plaintext = b"secret data";

        let encrypted = encrypt(&key1, plaintext).expect("encryption should succeed");
        let result = decrypt(&key2, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_too_short() {
        let key = [0x42u8; 32];
        let short_data = [0u8; 39]; // less than 40

        let result = decrypt(&key, &short_data);
        assert!(matches!(result, Err(CryptoError::InvalidInput(_))));
    }

    #[test]
    fn test_decrypt_tampered_ciphertext() {
        let key = [0x42u8; 32];
        let plaintext = b"important data";

        let mut encrypted = encrypt(&key, plaintext).expect("encryption should succeed");
        // Flip a bit in the ciphertext portion (after nonce)
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0x01;

        let result = decrypt(&key, &encrypted);
        assert!(matches!(result, Err(CryptoError::DecryptionFailed(_))));
    }

    #[test]
    fn test_encrypt_empty_plaintext() {
        let key = [0x42u8; 32];
        let plaintext = b"";

        let encrypted = encrypt(&key, plaintext).expect("encryption should succeed");
        assert_eq!(encrypted.len(), NONCE_SIZE + 16); // nonce + tag only

        let decrypted = decrypt(&key, &encrypted).expect("decryption should succeed");
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_unique_nonces() {
        let key = [0x42u8; 32];
        let plaintext = b"same plaintext";

        let enc1 = encrypt(&key, plaintext).expect("encryption should succeed");
        let enc2 = encrypt(&key, plaintext).expect("encryption should succeed");

        // Nonces (first 24 bytes) should differ
        assert_ne!(&enc1[..NONCE_SIZE], &enc2[..NONCE_SIZE]);
        // Therefore ciphertexts should differ
        assert_ne!(enc1, enc2);
    }
}
