//! Platform key derivation from machine attributes.
//!
//! Two values are derived from the same machine attributes, under different
//! HMAC labels:
//!
//! - the **platform key** ([`derive_platform_key`]): the machine fingerprint.
//!   It is not secret: Settings displays it, pairing sends it to the vault,
//!   and the credential store mixes it into its AEAD associated data so a
//!   blob only opens on the machine that wrote it;
//! - the **machine-bound key** ([`derive_machine_bound_key`]): the credential
//!   store's master key when the OS keyring is unavailable. It is key
//!   material, but anyone who can read the same attributes on this machine
//!   can recompute it.
//!
//! Both require at least 3 of 5 machine attributes to be non-empty to prevent
//! weak fingerprints in minimal environments (containers, early-boot, etc.).

use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
use super::platform_linux::{
    collect_machine_attributes, compute_machine_bound_key, compute_machine_fingerprint,
    FingerprintError,
};

#[cfg(target_os = "macos")]
use super::platform_macos::{
    collect_machine_attributes_macos as collect_machine_attributes, compute_machine_bound_key,
    compute_machine_fingerprint, FingerprintError,
};

/// Minimum number of non-empty machine attributes required for key derivation.
const MIN_ATTRIBUTES: usize = 3;

/// Derive the platform key (the machine fingerprint) from machine attributes.
///
/// Collects machine attributes and computes the HMAC-SHA256 fingerprint.
/// Returns an error if fewer than 3 attributes could be collected.
///
/// The credential store uses it in its AEAD associated data. It is not
/// secret; see the module documentation.
pub fn derive_platform_key() -> Result<Zeroizing<[u8; 32]>, FingerprintError> {
    let attrs = collect_machine_attributes()?;

    let count = attrs.attribute_count();
    if count < MIN_ATTRIBUTES {
        return Err(FingerprintError::InsufficientAttributes {
            found: count,
            required: MIN_ATTRIBUTES,
        });
    }

    Ok(Zeroizing::new(compute_machine_fingerprint(&attrs)))
}

/// Derive the machine-bound storage key: the credential store's master key
/// when the OS keyring is unavailable.
///
/// Uses this platform's collector and the same 3-attribute minimum as
/// [`derive_platform_key`], but a different HMAC label.
///
/// SECURITY: [`derive_platform_key`] returns a value that is displayed and
/// sent to the vault, so it must never be used as this key.
pub fn derive_machine_bound_key() -> Result<Zeroizing<[u8; 32]>, FingerprintError> {
    let attrs = collect_machine_attributes()?;

    let count = attrs.attribute_count();
    if count < MIN_ATTRIBUTES {
        return Err(FingerprintError::InsufficientAttributes {
            found: count,
            required: MIN_ATTRIBUTES,
        });
    }

    Ok(Zeroizing::new(compute_machine_bound_key(&attrs)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::platform_linux::MachineAttributes;

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

    /// The two derivations must never coincide, whatever this machine's
    /// attributes are: checked on fixed attributes, so it cannot pass by
    /// skipping on a machine with too few of them.
    #[test]
    fn test_machine_bound_key_is_not_the_platform_key() {
        let attrs = MachineAttributes {
            hostname: "testhost".to_string(),
            machine_id: "test-machine-id".to_string(),
            cpu: "Test CPU".to_string(),
            disk_serial: "TEST-SERIAL".to_string(),
            mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
        };
        let platform = compute_machine_fingerprint(&attrs);
        let bound = compute_machine_bound_key(&attrs);
        assert_ne!(platform, bound);
        assert_eq!(bound, compute_machine_bound_key(&attrs));
    }

    /// On this machine, both derivations succeed or fail together.
    #[test]
    fn test_derivations_agree_on_availability() {
        match (derive_platform_key(), derive_machine_bound_key()) {
            (Ok(platform), Ok(bound)) => assert_ne!(*platform, *bound),
            (Err(FingerprintError::InsufficientAttributes { .. }), Err(_)) => {}
            (p, b) => panic!(
                "derivations disagree: platform ok={}, machine-bound ok={}",
                p.is_ok(),
                b.is_ok()
            ),
        }
    }

    #[test]
    fn test_derive_platform_key_deterministic() {
        // Two calls should return the same key (machine attributes don't change)
        match (derive_platform_key(), derive_platform_key()) {
            (Ok(key1), Ok(key2)) => assert_eq!(*key1, *key2),
            _ => {
                // Skip if insufficient attributes
            }
        }
    }
}
