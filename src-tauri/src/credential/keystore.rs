//! Master-key store for the on-disk credential blob.
//!
//! The desktop persists a small set of long-lived NATS credentials
//! (`connection.enc`) so the user can resume their pairing on the next
//! launch without re-pairing on the phone. That blob is encrypted with
//! a 32-byte master key fetched from this module.
//!
//! ## Key sources, in order
//!
//! 1. **OS keyring** (Secret Service on Linux, Keychain on macOS).
//!    The keyring itself is unlocked by the user's OS login session,
//!    so we inherit the OS's "is this really you" gate without
//!    asking the user for anything.
//! 2. **Machine-bound fallback** (`platform_key`). If the keyring
//!    isn't available (kiosk Linux, missing Secret Service daemon,
//!    locked Keychain on macOS first launch), we derive a key from
//!    machine attributes via `platform_key::machine_bound_key_from`. It uses its
//!    own HMAC label, so it is not the machine fingerprint that is
//!    displayed and sent at pairing.
//!    A binding mode marker lands on the encrypted store so callers
//!    can show the user a "we couldn't reach your keyring" notice.
//!
//!    There is no fallback on Windows ([`MACHINE_BOUND_FALLBACK`]): a
//!    Credential Manager failure fails the save. On every platform, a
//!    store that is already keyring-bound is never re-saved machine-bound
//!    (see `credential::store::save`).
//!
//! ## Why no passphrase
//!
//! Every privileged vault operation already requires phone
//! authorization (see DESKTOP-REWORK-PLAN.md §4). The on-disk blob,
//! even decrypted, only lets the attacker publish
//! `device.request-session` — which the phone has to authorize before
//! it becomes a working session. The passphrase added friction without
//! a load-bearing protection benefit.

use std::fmt;

use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::fingerprint::platform_key;
use crate::fingerprint::platform_linux::{FingerprintError, MachineAttributes};

const KEYRING_SERVICE: &str = "vettid-desktop";
const KEYRING_ACCOUNT: &str = "master-key-v1";

/// How the master key was sourced. Stamped into the on-disk store so a
/// future load knows which path to retry, and so the UI can surface
/// the binding mode to the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingMode {
    /// Key fetched from the OS keyring. Safest at-rest posture: disk
    /// theft alone can't decrypt; the attacker also needs the user's
    /// OS account.
    Keyring,
    /// Key derived from machine attributes (no keyring available).
    /// Weaker than the keyring: anyone who can read this machine's
    /// attributes can re-derive the key. That includes any local user
    /// and anyone holding a full disk image, since the machine id and
    /// hostname are stored on the disk itself. It only protects
    /// `connection.enc` copied on its own, without the rest of the disk.
    MachineBound,
}

impl fmt::Display for BindingMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BindingMode::Keyring => f.write_str("keyring"),
            BindingMode::MachineBound => f.write_str("machine"),
        }
    }
}

impl BindingMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            BindingMode::Keyring => "keyring",
            BindingMode::MachineBound => "machine",
        }
    }

    pub fn from_str(s: &str) -> Option<BindingMode> {
        match s {
            "keyring" => Some(BindingMode::Keyring),
            "machine" => Some(BindingMode::MachineBound),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum KeystoreError {
    /// All key sources failed. Should be rare — the machine-bound
    /// fallback typically works on any reachable filesystem.
    NoSource(String),
    /// The OS keyring failed and no machine-bound fallback is allowed:
    /// on a platform without one ([`MACHINE_BOUND_FALLBACK`]), or for a
    /// store that is already keyring-bound.
    KeyringUnavailable(String),
}

impl fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeystoreError::NoSource(msg) => write!(f, "keystore: no usable key source ({})", msg),
            KeystoreError::KeyringUnavailable(msg) => {
                write!(f, "keystore: OS keyring unavailable, no fallback allowed ({})", msg)
            }
        }
    }
}

impl std::error::Error for KeystoreError {}

/// Returned 32-byte key, zeroized on drop. The `binding` field tells the
/// caller which source was used.
pub struct MasterKey {
    pub key: Zeroizing<[u8; 32]>,
    pub binding: BindingMode,
}

/// The key sources, as a seam: production uses [`System`]; tests replace
/// the keyring and this machine's attributes, so the real fallback logic
/// below is what they exercise.
pub(crate) trait Sources {
    /// Read the keyring entry: `Ok(None)` when there is none.
    fn keyring_read(&self) -> Result<Option<Zeroizing<[u8; 32]>>, String>;
    /// Store a new keyring entry.
    fn keyring_write(&self, key: &[u8; 32]) -> Result<(), String>;
    /// This machine's attributes, for the machine-bound key.
    fn machine_attributes(&self) -> Result<MachineAttributes, FingerprintError>;
}

/// The OS keyring and this machine's real attributes.
pub(crate) struct System;

impl Sources for System {
    fn keyring_read(&self) -> Result<Option<Zeroizing<[u8; 32]>>, String> {
        read_keyring_key()
    }
    fn keyring_write(&self, key: &[u8; 32]) -> Result<(), String> {
        write_keyring_key(key)
    }
    fn machine_attributes(&self) -> Result<MachineAttributes, FingerprintError> {
        platform_key::collect_attributes()
    }
}

/// Get the master key the on-disk credential blob is/should be
/// encrypted with. Creates a fresh key the first time it's called on
/// a system that doesn't have one yet.
///
/// The lookup order is keyring → machine-bound. Callers don't need to
/// know which path was used unless they want to surface it; the
/// returned `binding` field reflects the source.
pub fn fetch_or_create_master_key() -> Result<MasterKey, KeystoreError> {
    fetch_or_create_master_key_with(&System)
}

/// Whether this platform may fall back to the machine-bound key when the
/// OS keyring fails.
///
/// SECURITY: not on Windows. Every input to the machine-bound key
/// (MachineGuid, CPU, disk serial, MAC, hostname) can be read by any
/// standard user there (HKLM\SOFTWARE\Microsoft\Cryptography grants
/// BUILTIN\Users read), so the key would add nothing beyond the file's
/// ACL, while Credential Manager is DPAPI-protected and present for every
/// interactive user. A Credential Manager failure therefore fails the
/// save instead of silently storing the pairing under a weaker key.
pub(crate) const MACHINE_BOUND_FALLBACK: bool = cfg!(not(windows));

pub(crate) fn fetch_or_create_master_key_with(src: &dyn Sources) -> Result<MasterKey, KeystoreError> {
    fetch_or_create_master_key_with_policy(src, MACHINE_BOUND_FALLBACK)
}

/// [`fetch_or_create_master_key_with`] with the fallback policy given, so
/// both policies can be tested on every platform.
pub(crate) fn fetch_or_create_master_key_with_policy(
    src: &dyn Sources,
    allow_machine_bound: bool,
) -> Result<MasterKey, KeystoreError> {
    // Try keyring first.
    match fetch_or_create_keyring_key(src) {
        Ok(key) => {
            return Ok(MasterKey {
                key,
                binding: BindingMode::Keyring,
            })
        }
        Err(e) if !allow_machine_bound => {
            log::warn!("Keystore: OS keyring unavailable ({}); no fallback on this platform", e);
            return Err(KeystoreError::KeyringUnavailable(e));
        }
        Err(e) => {
            log::warn!(
                "Keystore: OS keyring unavailable ({}); falling back to machine-bound key",
                e,
            );
        }
    }

    // Fallback: derive a key from machine attributes.
    //
    // SECURITY: this is not the machine fingerprint. The fingerprint is
    // shown in Settings and sent to the vault at pairing; the key is
    // derived from the same attributes under its own label, and is refused
    // without a real machine id.
    machine_bound(src).map_err(|e| {
        KeystoreError::NoSource(format!("machine attribute collection failed: {}", e))
    })
}

/// Re-fetch a key for an existing store that was encrypted under a
/// specific binding. Used on load — we know the binding from the
/// store's header, so we go straight to the right source rather than
/// retrying the keyring on a machine-bound install.
pub fn fetch_for_binding(binding: BindingMode) -> Result<MasterKey, KeystoreError> {
    fetch_for_binding_with(&System, binding)
}

pub(crate) fn fetch_for_binding_with(
    src: &dyn Sources,
    binding: BindingMode,
) -> Result<MasterKey, KeystoreError> {
    match binding {
        BindingMode::Keyring => match src.keyring_read() {
            Ok(Some(key)) => Ok(MasterKey {
                key,
                binding: BindingMode::Keyring,
            }),
            Ok(None) => Err(KeystoreError::NoSource(
                "keyring entry missing — was it deleted?".to_string(),
            )),
            Err(e) => Err(KeystoreError::NoSource(format!("keyring read: {}", e))),
        },
        BindingMode::MachineBound => machine_bound(src)
            .map_err(|e| KeystoreError::NoSource(format!("machine attrs: {}", e))),
    }
}

fn machine_bound(src: &dyn Sources) -> Result<MasterKey, FingerprintError> {
    let attrs = src.machine_attributes()?;
    Ok(MasterKey {
        key: platform_key::machine_bound_key_from(&attrs)?,
        binding: BindingMode::MachineBound,
    })
}

/// Wipe the keyring entry. Called from `logout` so the next pairing
/// gets a fresh master key — a paranoid attacker who later compromises
/// the disk image can't decrypt the previous-install blob even if
/// `connection.enc` slipped past the local wipe.
pub fn delete_keyring_key() {
    if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT) {
        let _ = entry.delete_credential();
    }
}

// ---------------------------------------------------------------------------
// Keyring helpers
// ---------------------------------------------------------------------------

fn fetch_or_create_keyring_key(src: &dyn Sources) -> Result<Zeroizing<[u8; 32]>, String> {
    if let Some(key) = src.keyring_read()? {
        return Ok(key);
    }
    // No existing entry — generate + store.
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut key[..]);
    src.keyring_write(&key)?;
    Ok(key)
}

fn read_keyring_key() -> Result<Option<Zeroizing<[u8; 32]>>, String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)
        .map_err(|e| format!("entry: {}", e))?;
    match entry.get_password() {
        Ok(b64) => {
            let b64 = Zeroizing::new(b64);
            let bytes = Zeroizing::new(
                base64::engine::general_purpose::STANDARD
                    .decode(b64.trim())
                    .map_err(|e| format!("decode: {}", e))?,
            );
            if bytes.len() != 32 {
                return Err(format!("unexpected key length: {}", bytes.len()));
            }
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(&bytes);
            Ok(Some(key))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("get: {}", e)),
    }
}

fn write_keyring_key(key: &[u8; 32]) -> Result<(), String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)
        .map_err(|e| format!("entry: {}", e))?;
    let b64 = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(key));
    entry
        .set_password(&b64)
        .map_err(|e| format!("set: {}", e))?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::cell::RefCell;

    /// A keyring and a set of machine attributes under the test's control.
    pub(crate) struct TestSources {
        /// `None`: the keyring is unavailable (every call fails).
        pub keyring: Option<RefCell<Option<[u8; 32]>>>,
        pub attrs: MachineAttributes,
    }

    impl TestSources {
        pub fn no_keyring(attrs: MachineAttributes) -> Self {
            Self { keyring: None, attrs }
        }
    }

    impl Sources for TestSources {
        fn keyring_read(&self) -> Result<Option<Zeroizing<[u8; 32]>>, String> {
            match &self.keyring {
                None => Err("keyring unavailable (test)".to_string()),
                Some(cell) => Ok(cell.borrow().map(Zeroizing::new)),
            }
        }
        fn keyring_write(&self, key: &[u8; 32]) -> Result<(), String> {
            match &self.keyring {
                None => Err("keyring unavailable (test)".to_string()),
                Some(cell) => {
                    *cell.borrow_mut() = Some(*key);
                    Ok(())
                }
            }
        }
        fn machine_attributes(&self) -> Result<MachineAttributes, FingerprintError> {
            Ok(self.attrs.clone())
        }
    }

    pub(crate) fn attrs_with_machine_id(machine_id: &str) -> MachineAttributes {
        MachineAttributes {
            hostname: "testhost".to_string(),
            machine_id: machine_id.to_string(),
            cpu: "Test CPU".to_string(),
            disk_serial: "TEST-SERIAL".to_string(),
            mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
        }
    }

    const MACHINE_ID: &str = "4c4c4544003a3610804db7c04f4d3732";

    #[test]
    fn keyring_available_creates_one_key_and_reuses_it() {
        let src = TestSources { keyring: Some(RefCell::new(None)), attrs: attrs_with_machine_id(MACHINE_ID) };
        let first = fetch_or_create_master_key_with(&src).expect("key");
        assert_eq!(first.binding, BindingMode::Keyring);
        let second = fetch_or_create_master_key_with(&src).expect("key");
        assert_eq!(*first.key, *second.key);
        let loaded = fetch_for_binding_with(&src, BindingMode::Keyring).expect("load");
        assert_eq!(*loaded.key, *first.key);
    }

    #[test]
    fn no_keyring_falls_back_to_the_machine_bound_key() {
        let attrs = attrs_with_machine_id(MACHINE_ID);
        let src = TestSources::no_keyring(attrs.clone());
        let key = fetch_or_create_master_key_with_policy(&src, true).expect("key");
        assert_eq!(key.binding, BindingMode::MachineBound);
        assert_eq!(*key.key, *platform_key::machine_bound_key_from(&attrs).unwrap());
    }

    #[test]
    fn no_keyring_and_no_machine_id_gives_no_key() {
        let src = TestSources::no_keyring(attrs_with_machine_id(""));
        let err = fetch_or_create_master_key_with_policy(&src, true).err().expect("must fail");
        assert!(err.to_string().contains("no machine id"), "got {err}");
        assert!(fetch_for_binding_with(&src, BindingMode::MachineBound).is_err());
    }

    /// Without the fallback (Windows), a keyring failure is an error, even
    /// with a usable machine id, and no machine-bound key is returned.
    #[test]
    fn no_keyring_without_fallback_is_an_error() {
        let src = TestSources::no_keyring(attrs_with_machine_id(MACHINE_ID));
        let err = fetch_or_create_master_key_with_policy(&src, false).err().expect("must fail");
        assert!(matches!(err, KeystoreError::KeyringUnavailable(_)), "got {err}");
    }

    /// The platform policy: no fallback on Windows, a fallback elsewhere.
    #[test]
    fn platform_fallback_policy() {
        assert_eq!(MACHINE_BOUND_FALLBACK, !cfg!(windows));
        let src = TestSources::no_keyring(attrs_with_machine_id(MACHINE_ID));
        let result = fetch_or_create_master_key_with(&src);
        if cfg!(windows) {
            assert!(matches!(result, Err(KeystoreError::KeyringUnavailable(_))));
        } else {
            assert_eq!(result.expect("key").binding, BindingMode::MachineBound);
        }
    }

    #[test]
    fn missing_keyring_entry_for_a_keyring_store_is_an_error() {
        let src = TestSources { keyring: Some(RefCell::new(None)), attrs: attrs_with_machine_id(MACHINE_ID) };
        assert!(fetch_for_binding_with(&src, BindingMode::Keyring).is_err());
    }
}
