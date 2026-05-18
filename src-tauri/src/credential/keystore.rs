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
//!    machine attributes via the existing `compute_machine_fingerprint`.
//!    A binding mode marker lands on the encrypted store so callers
//!    can show the user a "we couldn't reach your keyring" notice.
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
use zeroize::Zeroize;

use crate::fingerprint::platform_linux::{
    collect_machine_attributes, compute_machine_fingerprint,
};

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
    /// Disk-theft-without-machine-access is still safe (the
    /// fingerprint depends on attributes the disk doesn't carry),
    /// but disk + access to the running machine can re-derive.
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
}

impl fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeystoreError::NoSource(msg) => write!(f, "keystore: no usable key source ({})", msg),
        }
    }
}

impl std::error::Error for KeystoreError {}

/// Returned 32-byte key, sealed with `Zeroize` so callers can wipe
/// after use. The `binding` field tells the caller which source was
/// used.
pub struct MasterKey {
    pub key: [u8; 32],
    pub binding: BindingMode,
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        self.key.zeroize();
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
    // Try keyring first.
    match fetch_or_create_keyring_key() {
        Ok(key) => return Ok(MasterKey {
            key,
            binding: BindingMode::Keyring,
        }),
        Err(e) => {
            log::warn!(
                "Keystore: OS keyring unavailable ({}); falling back to machine-bound key",
                e,
            );
        }
    }

    // Fallback: derive a key from machine attributes. Same 32-byte
    // output as compute_machine_fingerprint — that function is already
    // used by the credential store for hardware-fingerprint binding,
    // so reusing it keeps the binding consistent.
    match collect_machine_attributes() {
        Ok(attrs) => {
            let key = compute_machine_fingerprint(&attrs);
            Ok(MasterKey {
                key,
                binding: BindingMode::MachineBound,
            })
        }
        Err(e) => Err(KeystoreError::NoSource(format!(
            "machine attribute collection failed: {}",
            e
        ))),
    }
}

/// Re-fetch a key for an existing store that was encrypted under a
/// specific binding. Used on load — we know the binding from the
/// store's header, so we go straight to the right source rather than
/// retrying the keyring on a machine-bound install.
pub fn fetch_for_binding(binding: BindingMode) -> Result<MasterKey, KeystoreError> {
    match binding {
        BindingMode::Keyring => match read_keyring_key() {
            Ok(Some(key)) => Ok(MasterKey {
                key,
                binding: BindingMode::Keyring,
            }),
            Ok(None) => Err(KeystoreError::NoSource(
                "keyring entry missing — was it deleted?".to_string(),
            )),
            Err(e) => Err(KeystoreError::NoSource(format!("keyring read: {}", e))),
        },
        BindingMode::MachineBound => {
            let attrs = collect_machine_attributes()
                .map_err(|e| KeystoreError::NoSource(format!("machine attrs: {}", e)))?;
            let key = compute_machine_fingerprint(&attrs);
            Ok(MasterKey {
                key,
                binding: BindingMode::MachineBound,
            })
        }
    }
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

fn fetch_or_create_keyring_key() -> Result<[u8; 32], String> {
    if let Some(key) = read_keyring_key()? {
        return Ok(key);
    }
    // No existing entry — generate + store.
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    write_keyring_key(&key)?;
    Ok(key)
}

fn read_keyring_key() -> Result<Option<[u8; 32]>, String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)
        .map_err(|e| format!("entry: {}", e))?;
    match entry.get_password() {
        Ok(b64) => {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .map_err(|e| format!("decode: {}", e))?;
            if bytes.len() != 32 {
                return Err(format!("unexpected key length: {}", bytes.len()));
            }
            let mut key = [0u8; 32];
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
    let b64 = base64::engine::general_purpose::STANDARD.encode(key);
    entry
        .set_password(&b64)
        .map_err(|e| format!("set: {}", e))?;
    Ok(())
}
