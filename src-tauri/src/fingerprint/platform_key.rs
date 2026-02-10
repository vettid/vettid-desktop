//! Platform key derivation from machine attributes.
//!
//! The platform key binds encrypted credential stores to the specific machine
//! where they were created. It is combined with the user's passphrase via Argon2id
//! to derive the credential encryption key, ensuring credentials cannot be decrypted
//! on a different machine even if the passphrase is known.
//!
//! Requires at least 3 of 5 machine attributes to be non-empty to prevent
//! weak fingerprints in minimal environments (containers, early-boot, etc.).

use super::platform_linux::{
    collect_machine_attributes, compute_machine_fingerprint, FingerprintError, MachineAttributes,
};

/// Minimum number of non-empty machine attributes required for key derivation.
const MIN_ATTRIBUTES: usize = 3;

/// Derive the platform key from machine attributes.
///
/// Collects machine attributes and computes the HMAC-SHA256 fingerprint.
/// Returns an error if fewer than 3 attributes could be collected.
///
/// The returned 32-byte key is used as additional input to Argon2id alongside
/// the user's passphrase when encrypting/decrypting the credential store.
pub fn derive_platform_key() -> Result<[u8; 32], FingerprintError> {
    let attrs = collect_machine_attributes()?;

    let count = attrs.attribute_count();
    if count < MIN_ATTRIBUTES {
        return Err(FingerprintError::InsufficientAttributes {
            found: count,
            required: MIN_ATTRIBUTES,
        });
    }

    Ok(compute_machine_fingerprint(&attrs))
}

/// Derive the platform key and also return the collected machine attributes.
///
/// This variant is used during registration, where the attributes need to be
/// sent to the vault as part of the device metadata (hostname, platform, etc.).
pub fn derive_platform_key_with_attrs(
) -> Result<([u8; 32], MachineAttributes), FingerprintError> {
    let attrs = collect_machine_attributes()?;

    let count = attrs.attribute_count();
    if count < MIN_ATTRIBUTES {
        return Err(FingerprintError::InsufficientAttributes {
            found: count,
            required: MIN_ATTRIBUTES,
        });
    }

    let key = compute_machine_fingerprint(&attrs);
    Ok((key, attrs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_platform_key_succeeds_on_linux() {
        // On a real Linux system, we expect at least 3 attributes
        // This test may fail in very minimal containers
        match derive_platform_key() {
            Ok(key) => {
                assert_eq!(key.len(), 32);
                // Should not be all zeros
                assert!(key.iter().any(|&b| b != 0));
            }
            Err(FingerprintError::InsufficientAttributes { found, .. }) => {
                // Acceptable in minimal test environments
                eprintln!(
                    "WARNING: Only {} machine attributes available, skipping test",
                    found
                );
            }
            Err(e) => panic!("unexpected error: {}", e),
        }
    }

    #[test]
    fn test_derive_platform_key_with_attrs_returns_both() {
        match derive_platform_key_with_attrs() {
            Ok((key, attrs)) => {
                assert_eq!(key.len(), 32);
                assert!(attrs.attribute_count() >= MIN_ATTRIBUTES);
            }
            Err(FingerprintError::InsufficientAttributes { .. }) => {
                // Acceptable in minimal test environments
            }
            Err(e) => panic!("unexpected error: {}", e),
        }
    }

    #[test]
    fn test_derive_platform_key_deterministic() {
        // Two calls should return the same key (machine attributes don't change)
        match (derive_platform_key(), derive_platform_key()) {
            (Ok(key1), Ok(key2)) => assert_eq!(key1, key2),
            _ => {
                // Skip if insufficient attributes
            }
        }
    }
}
