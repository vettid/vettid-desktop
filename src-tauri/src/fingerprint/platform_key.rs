//! Platform key derivation from machine attributes.
//!
//! Two values are derived from the same machine attributes, under different
//! HMAC labels:
//!
//! - the **platform key** ([`derive_platform_key`]): the machine fingerprint.
//!   It is not secret: Settings displays it, pairing sends it to the vault,
//!   and the credential store mixes it into its AEAD associated data so a
//!   blob only opens on the machine that wrote it;
//! - the **machine-bound key** ([`machine_bound_key_from`]): the credential
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
    FingerprintError, MachineAttributes,
};

#[cfg(target_os = "macos")]
use super::platform_macos::{
    collect_machine_attributes_macos as collect_machine_attributes, compute_machine_bound_key,
    compute_machine_fingerprint, FingerprintError, MachineAttributes,
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

/// This machine's attributes, from this platform's collector. The keystore
/// derives the machine-bound key from them with [`machine_bound_key_from`].
pub(crate) fn collect_attributes() -> Result<MachineAttributes, FingerprintError> {
    collect_machine_attributes()
}

/// The machine-bound storage key for `attrs`: the credential store's master
/// key when the OS keyring is unavailable. Same attributes as
/// [`derive_platform_key`], under a different HMAC label.
///
/// SECURITY: [`derive_platform_key`] returns a value that is displayed and
/// sent to the vault, so it must never be used as this key.
///
/// Requires a real machine id as well as the 3-attribute minimum
/// (owner decision, 2026-10-31). Without the machine id, the remaining
/// attributes can be hostname, CPU and MAC: the hostname is sent at
/// pairing, CPU models are few and a MAC can be searched, so the key could
/// be guessed offline. Failing here means nothing is written: with no
/// keyring and no machine id, the desktop cannot store a pairing.
pub(crate) fn machine_bound_key_from(
    attrs: &MachineAttributes,
) -> Result<Zeroizing<[u8; 32]>, FingerprintError> {
    if !machine_id_is_usable(&attrs.machine_id) {
        return Err(FingerprintError::MissingMachineId);
    }

    let count = attrs.attribute_count();
    if count < MIN_ATTRIBUTES {
        return Err(FingerprintError::InsufficientAttributes {
            found: count,
            required: MIN_ATTRIBUTES,
        });
    }

    Ok(Zeroizing::new(compute_machine_bound_key(attrs)))
}

/// Minimum number of non-zero hex digits in a usable machine id. A real one
/// (systemd's 32 hex digits, a Windows `MachineGuid`, a macOS
/// `IOPlatformUUID`) has about 30.
const MIN_MACHINE_ID_NONZERO_HEX: usize = 16;

/// Whether `id` looks like a real machine id rather than a placeholder:
/// empty, systemd's `uninitialized`, all zeros (with or without UUID
/// dashes), or too little randomness to be one.
fn machine_id_is_usable(id: &str) -> bool {
    let id = id.trim();
    if id.is_empty() || id.eq_ignore_ascii_case("uninitialized") {
        return false;
    }
    let nonzero_hex = id
        .chars()
        .filter(|c| c.is_ascii_hexdigit() && *c != '0')
        .count();
    nonzero_hex >= MIN_MACHINE_ID_NONZERO_HEX
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_attrs() -> MachineAttributes {
        MachineAttributes {
            hostname: "testhost".to_string(),
            machine_id: "4c4c4544003a3610804db7c04f4d3732".to_string(),
            cpu: "Test CPU".to_string(),
            disk_serial: "TEST-SERIAL".to_string(),
            mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
        }
    }

    #[test]
    fn machine_bound_key_requires_a_machine_id() {
        let mut attrs = fixed_attrs();
        attrs.machine_id = String::new();
        // Four attributes remain, above the minimum: refused anyway.
        assert_eq!(attrs.attribute_count(), 4);
        assert!(matches!(
            machine_bound_key_from(&attrs),
            Err(FingerprintError::MissingMachineId)
        ));

        for placeholder in [
            "   ",
            "uninitialized",
            "UNINITIALIZED\n",
            "00000000000000000000000000000000",
            "00000000-0000-0000-0000-000000000000",
            "0000000000000000000000000000000a",
            "test-machine-id",
            "abcdef",
        ] {
            attrs.machine_id = placeholder.to_string();
            assert!(
                matches!(machine_bound_key_from(&attrs), Err(FingerprintError::MissingMachineId)),
                "{placeholder:?} must be refused"
            );
        }
    }

    #[test]
    fn machine_id_nonzero_hex_boundary() {
        // 15 non-zero hex digits among zeros and dashes: refused.
        let fifteen = "11111111-1111-1110-0000-000000000000";
        // 16: accepted.
        let sixteen = "11111111-1111-1111-0000-000000000000";
        let count = |s: &str| s.chars().filter(|c| c.is_ascii_hexdigit() && *c != '0').count();
        assert_eq!(count(fifteen), 15);
        assert_eq!(count(sixteen), 16);
        assert!(!machine_id_is_usable(fifteen));
        assert!(machine_id_is_usable(sixteen));
    }

    #[test]
    fn real_machine_id_shapes_are_accepted() {
        for id in [
            // systemd /etc/machine-id: 32 lowercase hex digits
            "4c4c4544003a3610804db7c04f4d3732",
            // Windows MachineGuid
            "6f1a2b3c-4d5e-4f60-8a9b-0c1d2e3f4a5b",
            // macOS IOPlatformUUID, upper case
            "8E3D5C2A-1B4F-4A6E-9C7D-2F1E0A3B4C5D",
        ] {
            assert!(machine_id_is_usable(id), "{id} must be accepted");
        }
    }

    #[test]
    fn machine_bound_key_with_a_machine_id_still_needs_three_attributes() {
        let attrs = MachineAttributes {
            hostname: String::new(),
            machine_id: "4c4c4544003a3610804db7c04f4d3732".to_string(),
            cpu: "Test CPU".to_string(),
            disk_serial: String::new(),
            mac_address: String::new(),
        };
        assert!(matches!(
            machine_bound_key_from(&attrs),
            Err(FingerprintError::InsufficientAttributes { found: 2, required: 3 })
        ));
    }

    #[test]
    fn machine_bound_key_from_full_attributes() {
        let attrs = fixed_attrs();
        let key = machine_bound_key_from(&attrs).expect("key");
        assert_eq!(*key, compute_machine_bound_key(&attrs));
    }

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
        let attrs = fixed_attrs();
        let platform = compute_machine_fingerprint(&attrs);
        let bound = compute_machine_bound_key(&attrs);
        assert_ne!(platform, bound);
        assert_eq!(bound, compute_machine_bound_key(&attrs));
    }

    /// On this machine, both derivations succeed or fail together, except
    /// that the machine-bound key alone is refused without a machine id.
    #[test]
    fn test_derivations_agree_on_availability() {
        let bound = collect_attributes().and_then(|attrs| machine_bound_key_from(&attrs));
        match (derive_platform_key(), bound) {
            (Ok(platform), Ok(bound)) => assert_ne!(*platform, *bound),
            (_, Err(FingerprintError::MissingMachineId)) => {}
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
