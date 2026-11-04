//! The machine fingerprint (the "platform key"), from machine attributes.
//!
//! [`derive_platform_key`] is the machine fingerprint over all five
//! attributes. It is not secret: Settings displays it and pairing sends it
//! to the vault. Nothing derives a key or associated data from the machine
//! attributes any more (#13, #19): the saved pairing is protected by a
//! platform protector (`credential::protector`).
//!
//! The fingerprint requires at least 3 of 5 machine attributes to be
//! non-empty to prevent weak fingerprints in minimal environments
//! (containers, early-boot, etc.). It is not unique to one computer: a
//! cloned disk image or VM gives the same attributes.

use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
use super::platform_linux::{
    collect_machine_attributes, compute_machine_fingerprint, FingerprintError, MachineAttributes,
};

#[cfg(target_os = "macos")]
use super::platform_macos::{
    collect_machine_attributes_macos as collect_machine_attributes, compute_machine_fingerprint, FingerprintError,
    MachineAttributes,
};

#[cfg(windows)]
use super::platform_windows::{
    collect_machine_attributes_windows as collect_machine_attributes, compute_machine_fingerprint, FingerprintError,
    MachineAttributes,
};

/// Minimum number of non-empty machine attributes for the fingerprint.
const MIN_ATTRIBUTES: usize = 3;

/// Derive the platform key (the machine fingerprint) from machine attributes.
///
/// Collects machine attributes and computes the HMAC-SHA256 fingerprint.
/// Returns an error if fewer than 3 attributes could be collected.
///
/// It is not secret; see the module documentation. SECURITY: never a key.
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

/// This machine's attributes, from this platform's collector (for the
/// displayed fingerprint, #17).
pub(crate) fn collect_attributes() -> Result<MachineAttributes, FingerprintError> {
    collect_machine_attributes()
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

    /// On a real Windows machine the collector must yield a MachineGuid
    /// and a fingerprint. Asserts only; no attribute value is printed.
    #[cfg(windows)]
    #[test]
    fn test_windows_collector_gives_a_fingerprint() {
        let attrs = collect_attributes().expect("collect Windows attributes");
        assert!(!attrs.machine_id.trim().is_empty(), "the MachineGuid read is empty");
        let fp = derive_platform_key().expect("fingerprint");
        assert!(fp.iter().any(|&b| b != 0));
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
