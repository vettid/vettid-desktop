use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::crypto::encrypt::{CryptoError, NONCE_SIZE};
use crate::crypto::hkdf::derive_key_hkdf;

/// Domain constant for device-level encryption contexts.
pub const DOMAIN_DEVICE: &str = "vettid-device-v1";

/// Domain constant for connection-level encryption contexts.
pub const DOMAIN_CONNECTION: &str = "vettid-connection-v1";

/// Ephemeral public key size in bytes.
const EPHEMERAL_PUBLIC_SIZE: usize = 32;

/// Poly1305 authentication tag size in bytes.
const TAG_SIZE: usize = 16;

/// Minimum ECIES ciphertext size: ephemeral_public (32) + nonce (24) + tag (16) = 72 bytes.
const MIN_ECIES_SIZE: usize = EPHEMERAL_PUBLIC_SIZE + NONCE_SIZE + TAG_SIZE;

/// Encrypt plaintext using ECIES (Elliptic Curve Integrated Encryption Scheme).
///
/// Protocol:
/// 1. Generate ephemeral X25519 keypair
/// 2. Compute shared secret via ECDH with recipient's public key
/// 3. Derive encryption key via HKDF-SHA256 (salt = domain bytes, info = empty)
/// 4. Encrypt with XChaCha20-Poly1305
///
/// Output format: `ephemeral_public (32) || nonce (24) || ciphertext + tag`
///
/// The `domain` parameter provides cryptographic domain separation -- different
/// domains produce different derived keys even with the same shared secret,
/// preventing key confusion attacks between encryption contexts.
///
/// SECURITY: All intermediate key material (ephemeral private key, shared secret,
/// derived key) is zeroized after use.
pub fn ecies_encrypt(
    recipient_public: &[u8; 32],
    plaintext: &[u8],
    domain: &str,
) -> Result<Vec<u8>, CryptoError> {
    // Generate ephemeral keypair
    let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    // Reconstruct recipient public key
    let recipient_key = PublicKey::from(*recipient_public);

    // X25519 ECDH: compute shared secret
    let shared_secret_point = ephemeral_secret.diffie_hellman(&recipient_key);
    let mut shared_secret = *shared_secret_point.as_bytes();

    // Derive encryption key via HKDF-SHA256
    // Salt = domain bytes, Info = empty (domain in salt provides sufficient separation)
    let derive_result = derive_key_hkdf(&shared_secret, domain);

    // SECURITY: Zeroize shared secret immediately after derivation
    shared_secret.zeroize();

    let mut enc_key = derive_result?;

    // Encrypt using XChaCha20-Poly1305
    let cipher = XChaCha20Poly1305::new_from_slice(&enc_key)
        .map_err(|e| CryptoError::EncryptionFailed(format!("cipher creation failed: {}", e)))?;

    // SECURITY: Zeroize encryption key after cipher creation
    enc_key.zeroize();

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(format!("AEAD seal failed: {}", e)))?;

    // Format: ephemeral_public (32) || nonce (24) || ciphertext+tag
    let mut result =
        Vec::with_capacity(EPHEMERAL_PUBLIC_SIZE + NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(ephemeral_public.as_bytes());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt ciphertext produced by [`ecies_encrypt`].
///
/// Input format: `ephemeral_public (32) || nonce (24) || ciphertext + tag`
///
/// The minimum input size is 72 bytes (32 + 24 + 16 with zero-length plaintext).
///
/// The `domain` parameter must match the domain used during encryption.
///
/// SECURITY: All intermediate key material is zeroized after use.
/// Returns `CryptoError::DecryptionFailed` on authentication failure.
pub fn ecies_decrypt(
    private_key: &[u8; 32],
    data: &[u8],
    domain: &str,
) -> Result<Vec<u8>, CryptoError> {
    if data.len() < MIN_ECIES_SIZE {
        return Err(CryptoError::InvalidInput(format!(
            "ciphertext too short: need at least {} bytes, got {}",
            MIN_ECIES_SIZE,
            data.len()
        )));
    }

    // Parse components
    let ephemeral_public_bytes: [u8; 32] = data[0..32]
        .try_into()
        .map_err(|_| CryptoError::InvalidInput("failed to parse ephemeral public key".into()))?;
    let nonce_bytes = &data[32..56];
    let ciphertext = &data[56..];

    let nonce = XNonce::from_slice(nonce_bytes);

    // Reconstruct keys
    let ephemeral_public = PublicKey::from(ephemeral_public_bytes);
    let secret = StaticSecret::from(*private_key);

    // X25519 ECDH: compute shared secret
    let shared_secret_point = secret.diffie_hellman(&ephemeral_public);
    let mut shared_secret = *shared_secret_point.as_bytes();

    // Derive encryption key via HKDF-SHA256
    let derive_result = derive_key_hkdf(&shared_secret, domain);

    // SECURITY: Zeroize shared secret immediately after derivation
    shared_secret.zeroize();

    let mut enc_key = derive_result?;

    // Decrypt using XChaCha20-Poly1305
    let cipher = XChaCha20Poly1305::new_from_slice(&enc_key)
        .map_err(|e| CryptoError::DecryptionFailed(format!("cipher creation failed: {}", e)))?;

    // SECURITY: Zeroize encryption key after cipher creation
    enc_key.zeroize();

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| CryptoError::DecryptionFailed(format!("AEAD open failed: {}", e)))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::generate_x25519_keypair;

    #[test]
    fn test_ecies_roundtrip_device_domain() {
        let (secret, public) = generate_x25519_keypair();
        let plaintext = b"hello from device encryption";

        let encrypted = ecies_encrypt(public.as_bytes(), plaintext, DOMAIN_DEVICE)
            .expect("ECIES encryption should succeed");

        // Output: 32 (ephemeral pub) + 24 (nonce) + plaintext.len() + 16 (tag)
        assert_eq!(
            encrypted.len(),
            EPHEMERAL_PUBLIC_SIZE + NONCE_SIZE + plaintext.len() + TAG_SIZE
        );

        let private_bytes: [u8; 32] = secret.to_bytes();
        let decrypted = ecies_decrypt(&private_bytes, &encrypted, DOMAIN_DEVICE)
            .expect("ECIES decryption should succeed");

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_ecies_roundtrip_connection_domain() {
        let (secret, public) = generate_x25519_keypair();
        let plaintext = b"connection payload";

        let encrypted = ecies_encrypt(public.as_bytes(), plaintext, DOMAIN_CONNECTION)
            .expect("ECIES encryption should succeed");

        let private_bytes: [u8; 32] = secret.to_bytes();
        let decrypted = ecies_decrypt(&private_bytes, &encrypted, DOMAIN_CONNECTION)
            .expect("ECIES decryption should succeed");

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_ecies_wrong_domain_fails() {
        let (secret, public) = generate_x25519_keypair();
        let plaintext = b"domain separation test";

        let encrypted = ecies_encrypt(public.as_bytes(), plaintext, DOMAIN_DEVICE)
            .expect("ECIES encryption should succeed");

        let private_bytes: [u8; 32] = secret.to_bytes();
        let result = ecies_decrypt(&private_bytes, &encrypted, DOMAIN_CONNECTION);
        assert!(
            result.is_err(),
            "decryption with wrong domain should fail"
        );
    }

    #[test]
    fn test_ecies_wrong_key_fails() {
        let (_secret1, public1) = generate_x25519_keypair();
        let (secret2, _public2) = generate_x25519_keypair();
        let plaintext = b"wrong key test";

        let encrypted = ecies_encrypt(public1.as_bytes(), plaintext, DOMAIN_DEVICE)
            .expect("ECIES encryption should succeed");

        let private_bytes: [u8; 32] = secret2.to_bytes();
        let result = ecies_decrypt(&private_bytes, &encrypted, DOMAIN_DEVICE);
        assert!(
            result.is_err(),
            "decryption with wrong private key should fail"
        );
    }

    #[test]
    fn test_ecies_too_short() {
        let private_key = [0u8; 32];
        let short_data = [0u8; 71]; // less than 72

        let result = ecies_decrypt(&private_key, &short_data, DOMAIN_DEVICE);
        assert!(matches!(result, Err(CryptoError::InvalidInput(_))));
    }

    #[test]
    fn test_ecies_tampered_ciphertext() {
        let (secret, public) = generate_x25519_keypair();
        let plaintext = b"tamper test";

        let mut encrypted = ecies_encrypt(public.as_bytes(), plaintext, DOMAIN_DEVICE)
            .expect("ECIES encryption should succeed");

        // Flip a bit in the ciphertext portion
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0x01;

        let private_bytes: [u8; 32] = secret.to_bytes();
        let result = ecies_decrypt(&private_bytes, &encrypted, DOMAIN_DEVICE);
        assert!(matches!(result, Err(CryptoError::DecryptionFailed(_))));
    }

    #[test]
    fn test_ecies_empty_plaintext() {
        let (secret, public) = generate_x25519_keypair();
        let plaintext = b"";

        let encrypted = ecies_encrypt(public.as_bytes(), plaintext, DOMAIN_DEVICE)
            .expect("ECIES encryption should succeed");

        assert_eq!(
            encrypted.len(),
            EPHEMERAL_PUBLIC_SIZE + NONCE_SIZE + TAG_SIZE
        );

        let private_bytes: [u8; 32] = secret.to_bytes();
        let decrypted = ecies_decrypt(&private_bytes, &encrypted, DOMAIN_DEVICE)
            .expect("ECIES decryption should succeed");

        assert!(decrypted.is_empty());
    }
}
