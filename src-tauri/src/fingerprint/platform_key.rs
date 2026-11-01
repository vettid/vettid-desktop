//! Platform key derivation from machine attributes.
//!
//! Two values are derived from the same machine attributes, under different
//! HMAC labels:
//!
//! - the **platform key** ([`derive_platform_key`]): the machine fingerprint
//!   over all five attributes. It is not secret: Settings displays it and
//!   pairing sends it to the vault;
//! - the **storage binding** ([`derive_storage_binding`]): from the machine
//!   id alone (#14). The credential store mixes it into its AEAD associated
//!   data, so a blob only opens on the machine that wrote it, and a
//!   rename, a dock or a new disk doesn't stop it opening;
//! - the **machine-bound key** ([`machine_bound_key_from`]): the credential
//!   store's master key when the OS keyring is unavailable, derived from the
//!   machine id alone (#14). It is key material, but anyone who can read the
//!   machine id on this machine can recompute it.
//!
//! The fingerprint requires at least 3 of 5 machine attributes to be
//! non-empty to prevent weak fingerprints in minimal environments
//! (containers, early-boot, etc.). The machine-bound key requires a real
//! machine id instead.

use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
use super::platform_linux::{
    collect_machine_attributes, compute_machine_bound_key, compute_machine_fingerprint, compute_storage_binding,
    FingerprintError, MachineAttributes,
};

#[cfg(target_os = "macos")]
use super::platform_macos::{
    collect_machine_attributes_macos as collect_machine_attributes, compute_machine_bound_key,
    compute_machine_fingerprint, compute_storage_binding, FingerprintError, MachineAttributes,
};

#[cfg(windows)]
use super::platform_windows::{
    collect_machine_attributes_windows as collect_machine_attributes, compute_machine_bound_key,
    compute_machine_fingerprint, compute_storage_binding, FingerprintError, MachineAttributes,
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

/// This machine's storage binding, for the credential store's AEAD
/// associated data (#14, owner decision (a), 2026-11-01): derived from the
/// machine id alone, under its own label.
///
/// Requires a real machine id, like the machine-bound key: a placeholder
/// (`uninitialized`, all zeros) can be the same on many machines, and then
/// it wouldn't bind the file to this one. Without it nothing is saved or
/// opened, on either the keyring or the machine-bound path.
pub fn derive_storage_binding() -> Result<Zeroizing<[u8; 32]>, FingerprintError> {
    storage_binding_from(&collect_machine_attributes()?)
}

pub(crate) fn storage_binding_from(
    attrs: &MachineAttributes,
) -> Result<Zeroizing<[u8; 32]>, FingerprintError> {
    if !machine_id_is_usable(&attrs.machine_id) {
        return Err(FingerprintError::MissingMachineId);
    }
    Ok(Zeroizing::new(compute_storage_binding(attrs)))
}

/// This machine's attributes, from this platform's collector. The keystore
/// derives the machine-bound key from them with [`machine_bound_key_from`].
pub(crate) fn collect_attributes() -> Result<MachineAttributes, FingerprintError> {
    collect_machine_attributes()
}

/// The machine-bound storage key for `attrs`: the credential store's master
/// key when the OS keyring is unavailable. It is derived from the machine
/// id alone, under its own HMAC label (#14, owner decision (a),
/// 2026-11-01). The hostname, CPU, disk serial and MAC are not used: they
/// add no secrecy the machine id doesn't give, and they change.
///
/// SECURITY: [`derive_platform_key`] returns a value that is displayed and
/// sent to the vault, so it must never be used as this key.
///
/// Requires a real machine id (owner decision, 2026-10-31): not empty and
/// not a placeholder. Failing here means nothing is written: with no
/// keyring and no machine id, the desktop cannot store a pairing.
pub(crate) fn machine_bound_key_from(
    attrs: &MachineAttributes,
) -> Result<Zeroizing<[u8; 32]>, FingerprintError> {
    if !machine_id_is_usable(&attrs.machine_id) {
        return Err(FingerprintError::MissingMachineId);
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

    /// The storage binding needs a real machine id, and nothing else.
    #[test]
    fn storage_binding_needs_a_real_machine_id_only() {
        let mut attrs = fixed_attrs();
        let binding = storage_binding_from(&attrs).expect("binding");
        attrs.hostname = String::new();
        attrs.cpu = String::new();
        attrs.disk_serial = String::new();
        attrs.mac_address = String::new();
        assert_eq!(*storage_binding_from(&attrs).unwrap(), *binding);
        for placeholder in ["", "uninitialized", "00000000-0000-0000-0000-000000000000"] {
            attrs.machine_id = placeholder.to_string();
            assert!(matches!(storage_binding_from(&attrs), Err(FingerprintError::MissingMachineId)));
        }
    }

    /// #14: a real machine id is enough; the other attributes may be
    /// missing or change, and the key stays the same.
    #[test]
    fn machine_bound_key_needs_only_a_machine_id() {
        let only_id = MachineAttributes {
            hostname: String::new(),
            machine_id: "4c4c4544003a3610804db7c04f4d3732".to_string(),
            cpu: String::new(),
            disk_serial: String::new(),
            mac_address: String::new(),
        };
        let key = machine_bound_key_from(&only_id).expect("a machine id is enough");
        assert_eq!(*key, *machine_bound_key_from(&fixed_attrs()).unwrap());
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

    /// On this machine the two derivations never coincide. Either may be
    /// unavailable on its own: the fingerprint needs three attributes, the
    /// machine-bound key a real machine id.
    #[test]
    fn test_derivations_agree_on_availability() {
        let bound = collect_attributes().and_then(|attrs| machine_bound_key_from(&attrs));
        match (derive_platform_key(), bound) {
            (Ok(platform), Ok(bound)) => assert_ne!(*platform, *bound),
            (_, Err(FingerprintError::MissingMachineId)) => {}
            (Err(FingerprintError::InsufficientAttributes { .. }), _) => {}
            (p, b) => panic!(
                "derivations disagree: platform ok={}, machine-bound ok={}",
                p.is_ok(),
                b.is_ok()
            ),
        }
    }

    /// On a real Windows machine the collector must yield a usable
    /// MachineGuid and a machine-bound key. The availability test above
    /// accepts `MissingMachineId`, so it would not catch a broken
    /// MachineGuid read. Asserts only; no attribute value is printed.
    #[cfg(windows)]
    #[test]
    fn test_windows_collector_gives_a_machine_bound_key() {
        let attrs = collect_attributes().expect("collect Windows attributes");
        assert!(
            machine_id_is_usable(&attrs.machine_id),
            "the MachineGuid read is empty or a placeholder"
        );
        let key = machine_bound_key_from(&attrs).expect("machine-bound key");
        assert!(key.iter().any(|&b| b != 0));
        // Every save and load needs the storage binding (#14), keyring
        // path included.
        let binding = derive_storage_binding().expect("storage binding");
        assert_ne!(*binding, *key);
        assert_eq!(*binding, *derive_storage_binding().unwrap());
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
