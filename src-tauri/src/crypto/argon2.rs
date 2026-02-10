use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroize;

use crate::crypto::encrypt::CryptoError;

/// Argon2id time cost (iterations). OWASP recommended minimum: 3.
pub const ARGON2_TIME: u32 = 3;

/// Argon2id memory cost in KB (65536 KB = 64 MB). OWASP recommended minimum.
/// 64 MB chosen for device compatibility (works on 2GB RAM phones).
pub const ARGON2_MEMORY: u32 = 65536;

/// Argon2id parallelism (threads).
pub const ARGON2_THREADS: u32 = 4;

/// Output key size in bytes (256-bit).
pub const ARGON2_KEY_SIZE: usize = 32;

/// Salt size in bytes.
pub const ARGON2_SALT_SIZE: usize = 16;

/// Configurable Argon2id parameters.
///
/// Use `Default::default()` for the standard VettID parameters
/// matching OWASP recommendations and cross-platform compatibility.
#[derive(Debug, Clone)]
pub struct Argon2Params {
    /// Time cost (number of iterations).
    pub time: u32,
    /// Memory cost in KB.
    pub memory: u32,
    /// Parallelism (number of threads).
    pub threads: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            time: ARGON2_TIME,
            memory: ARGON2_MEMORY,
            threads: ARGON2_THREADS,
        }
    }
}

/// Derive a 32-byte key from a passphrase and platform key using Argon2id.
///
/// The input key material is the concatenation of `passphrase || platform_key`,
/// which binds the derived key to both the user's passphrase and the device's
/// platform-specific key material.
///
/// Parameters:
/// - `passphrase`: The user's passphrase (PIN, password, etc.)
/// - `platform_key`: Device-specific key material (e.g., from secure enclave)
/// - `salt`: Random 16-byte salt (use [`generate_salt`] to create one)
/// - `params`: Optional Argon2id parameters (defaults to OWASP recommended values)
///
/// This matches the Go `hashAuthInput` function:
/// ```go
/// argon2.IDKey(input, salt, Argon2idTime, Argon2idMemory, Argon2idThreads, Argon2idKeyLen)
/// ```
///
/// SECURITY: The output key should be zeroized after use. The concatenated input
/// is zeroized internally before the function returns.
pub fn derive_key(
    passphrase: &[u8],
    platform_key: &[u8],
    salt: &[u8],
    params: Option<&Argon2Params>,
) -> Result<[u8; ARGON2_KEY_SIZE], CryptoError> {
    let p = params.cloned().unwrap_or_default();

    // Concatenate: input = passphrase || platform_key
    let mut input = Vec::with_capacity(passphrase.len() + platform_key.len());
    input.extend_from_slice(passphrase);
    input.extend_from_slice(platform_key);

    let argon2_params = Params::new(p.memory, p.time, p.threads, Some(ARGON2_KEY_SIZE)).map_err(
        |e| {
            // SECURITY: Zeroize input on error path
            input.zeroize();
            CryptoError::KeyDerivationFailed(format!("invalid Argon2 params: {}", e))
        },
    )?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut output = [0u8; ARGON2_KEY_SIZE];
    argon2
        .hash_password_into(&input, salt, &mut output)
        .map_err(|e| {
            // SECURITY: Zeroize input on error path
            input.zeroize();
            output.zeroize();
            CryptoError::KeyDerivationFailed(format!("Argon2id hashing failed: {}", e))
        })?;

    // SECURITY: Zeroize concatenated input after use
    input.zeroize();

    Ok(output)
}

/// Generate a cryptographically random 16-byte salt for Argon2id.
///
/// Uses OS-provided randomness via `OsRng`.
pub fn generate_salt() -> Result<[u8; ARGON2_SALT_SIZE], CryptoError> {
    let mut salt = [0u8; ARGON2_SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    Ok(salt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_deterministic() {
        let passphrase = b"my-passphrase";
        let platform_key = b"platform-secret";
        let salt = [0x42u8; 16];

        let key1 =
            derive_key(passphrase, platform_key, &salt, None).expect("derivation should succeed");
        let key2 =
            derive_key(passphrase, platform_key, &salt, None).expect("derivation should succeed");

        assert_eq!(key1, key2, "same inputs must produce same output");
        assert_eq!(key1.len(), ARGON2_KEY_SIZE);
    }

    #[test]
    fn test_derive_key_different_passphrase() {
        let platform_key = b"platform-secret";
        let salt = [0x42u8; 16];

        let key1 =
            derive_key(b"pass1", platform_key, &salt, None).expect("derivation should succeed");
        let key2 =
            derive_key(b"pass2", platform_key, &salt, None).expect("derivation should succeed");

        assert_ne!(key1, key2, "different passphrases must produce different keys");
    }

    #[test]
    fn test_derive_key_different_platform_key() {
        let passphrase = b"my-passphrase";
        let salt = [0x42u8; 16];

        let key1 =
            derive_key(passphrase, b"platform1", &salt, None).expect("derivation should succeed");
        let key2 =
            derive_key(passphrase, b"platform2", &salt, None).expect("derivation should succeed");

        assert_ne!(
            key1, key2,
            "different platform keys must produce different keys"
        );
    }

    #[test]
    fn test_derive_key_different_salt() {
        let passphrase = b"my-passphrase";
        let platform_key = b"platform-secret";

        let key1 = derive_key(passphrase, platform_key, &[0x01u8; 16], None)
            .expect("derivation should succeed");
        let key2 = derive_key(passphrase, platform_key, &[0x02u8; 16], None)
            .expect("derivation should succeed");

        assert_ne!(key1, key2, "different salts must produce different keys");
    }

    #[test]
    fn test_derive_key_custom_params() {
        let passphrase = b"my-passphrase";
        let platform_key = b"platform-secret";
        let salt = [0x42u8; 16];

        let custom_params = Argon2Params {
            time: 1,
            memory: 16384,
            threads: 2,
        };

        let key_custom = derive_key(passphrase, platform_key, &salt, Some(&custom_params))
            .expect("derivation should succeed");
        let key_default =
            derive_key(passphrase, platform_key, &salt, None).expect("derivation should succeed");

        // Different params should produce different keys
        assert_ne!(
            key_custom, key_default,
            "different params must produce different keys"
        );
        assert_eq!(key_custom.len(), ARGON2_KEY_SIZE);
    }

    #[test]
    fn test_generate_salt() {
        let salt1 = generate_salt().expect("salt generation should succeed");
        let salt2 = generate_salt().expect("salt generation should succeed");

        assert_eq!(salt1.len(), ARGON2_SALT_SIZE);
        assert_eq!(salt2.len(), ARGON2_SALT_SIZE);
        assert_ne!(salt1, salt2, "two salts should differ");
    }

    #[test]
    fn test_default_params() {
        let params = Argon2Params::default();
        assert_eq!(params.time, ARGON2_TIME);
        assert_eq!(params.memory, ARGON2_MEMORY);
        assert_eq!(params.threads, ARGON2_THREADS);
    }
}
