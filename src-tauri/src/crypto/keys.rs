use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

/// Generate a random X25519 keypair for ECDH key exchange.
///
/// Uses OS-provided cryptographic randomness via `OsRng`.
/// The private key implements `Zeroize` and will be cleared on drop.
pub fn generate_x25519_keypair() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// Compute a shared secret using X25519 ECDH.
///
/// Takes our private key and the peer's public key, returns the 32-byte
/// shared secret. The caller is responsible for deriving an encryption key
/// from this shared secret (e.g., via HKDF) -- never use it directly as
/// an encryption key.
///
/// SECURITY: The returned bytes should be zeroized after use.
pub fn compute_shared_secret(private: &StaticSecret, peer_public: &PublicKey) -> [u8; 32] {
    let shared = private.diffie_hellman(peer_public);
    *shared.as_bytes()
}

/// Generate `n` cryptographically random bytes.
///
/// Uses OS-provided randomness. Panics if the OS RNG fails, which
/// indicates a catastrophic system-level failure.
pub fn generate_random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    OsRng.fill_bytes(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let (secret1, public1) = generate_x25519_keypair();
        let (secret2, public2) = generate_x25519_keypair();

        // Two keypairs should produce different public keys
        assert_ne!(public1.as_bytes(), public2.as_bytes());

        // ECDH should be commutative: A*b == B*a
        let shared1 = compute_shared_secret(&secret1, &public2);
        let shared2 = compute_shared_secret(&secret2, &public1);
        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_generate_random_bytes() {
        let bytes = generate_random_bytes(32);
        assert_eq!(bytes.len(), 32);

        // Two calls should produce different output (with overwhelming probability)
        let bytes2 = generate_random_bytes(32);
        assert_ne!(bytes, bytes2);
    }

    #[test]
    fn test_generate_random_bytes_zero_length() {
        let bytes = generate_random_bytes(0);
        assert!(bytes.is_empty());
    }
}
