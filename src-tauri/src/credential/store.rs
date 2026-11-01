//! Encrypted credential storage for the VettID desktop app.
//!
//! Credentials are encrypted at rest with a 32-byte master key fetched
//! from the OS keyring (Linux Secret Service / macOS Keychain), with a
//! machine-bound fallback when the keyring isn't reachable. The user
//! never enters a passphrase: every privileged vault operation already
//! requires phone authorization, and the on-disk blob — even decrypted
//! — only lets the attacker publish `device.request-session`, which
//! the phone has to authorize before it becomes a working session.
//!
//! See [`keystore`](super::keystore) for the key-source details and
//! [`DESKTOP-REWORK-PLAN.md`](../../../../DESKTOP-REWORK-PLAN.md) §4 for
//! the threat-model rationale.
//!
//! On-disk format: JSON-serialized `EncryptedStore` at
//! `~/.config/vettid-desktop/connection.enc` (Linux) or
//! `~/Library/Application Support/vettid-desktop/connection.enc` (macOS).

use std::fmt;
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::credential::keystore::{self, BindingMode, KeystoreError, MasterKey};
use crate::fingerprint::platform_key;
use crate::fingerprint::platform_linux::FingerprintError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Current version of the encrypted store format.
///
/// - v1: legacy passphrase + Argon2id. Rejected outright (see
///   DESKTOP-REWORK-PLAN.md §7).
/// - v2: 32-byte master key from [`crate::credential::keystore`], no
///   AEAD associated data. Decryptable for backwards-compat but a
///   v2 read triggers an automatic re-seal to v3 on next save.
/// - v3: same master key, but the AEAD now binds the ciphertext to
///   the local machine via [`compute_blob_aad`]. A blob copied to a
///   different machine — even with the original keyring entry — no
///   longer decrypts. See SECURITY-REVIEW-2026-05-25.md D-HIGH-3.
const STORE_VERSION: i32 = 3;
const LEGACY_STORE_VERSION_V2: i32 = 2;

/// Domain-separation label baked into the AEAD AAD.
const AAD_LABEL: &[u8] = b"vettid-desktop-credential-v3";

/// Credential file name within the config directory.
const CREDENTIAL_FILE: &str = "connection.enc";

/// Subdirectory name appended to the OS config dir.
const CONFIG_SUBDIR: &str = "vettid-desktop";

/// XChaCha20-Poly1305 nonce size (24 bytes).
const NONCE_SIZE: usize = 24;

/// What the person is told when a saved pairing can't be opened. Shown
/// as is, so it must stay plain: no error codes, no crypto terms.
pub const UNREADABLE_NOTICE: &str =
    "This desktop's saved pairing can't be opened. Remove this desktop on your phone, then pair again.";

/// Shown when the pairing can't be saved because the system keyring
/// (Credential Manager on Windows) can't be reached and a weaker key is
/// not allowed. Nothing on disk has changed. At pairing, the vault may
/// already list the desktop, hence the phone step.
pub const KEYRING_UNAVAILABLE_NOTICE: &str =
    "This desktop can't reach your computer's keyring, so it couldn't save the pairing safely, and nothing was saved. If your phone lists this desktop, remove it there. Then sign out of your computer and back in, and pair again.";

/// Shown when the per-user folder for the pairing can't be found.
pub const NO_CONFIG_DIR_NOTICE: &str =
    "This desktop can't find your user folder, so it can't keep a pairing on this computer. Nothing was saved.";

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during credential store operations.
#[derive(Debug)]
pub enum CredentialError {
    /// The credential file could not be read or written.
    IoError(String),
    /// JSON serialization or deserialization failed.
    SerializationError(String),
    /// Encryption or decryption failed.
    CryptoError(String),
    /// Fingerprint collection or computation failed.
    FingerprintError(FingerprintError),
    /// The keystore couldn't fetch a master key (keyring unavailable
    /// AND machine-bound fallback failed).
    KeystoreError(String),
    /// The credential file does not exist.
    NotFound(String),
    /// The store version is not supported.
    UnsupportedVersion(i32),
    /// A machine-bound store did not decrypt with this machine's key.
    /// `load` deleted the file if an earlier build sealed it under the
    /// public fingerprint, and kept it otherwise. Displays
    /// [`UNREADABLE_NOTICE`].
    Unreadable,
    /// The keyring failed and the save may not fall back to the
    /// machine-bound key: on Windows, or because the store on disk is
    /// keyring-bound. Nothing was written. Displays
    /// [`KEYRING_UNAVAILABLE_NOTICE`].
    KeyringUnavailable,
    /// The platform's per-user folder is unknown or not absolute, so
    /// there is nowhere safe to keep a pairing. Displays
    /// [`NO_CONFIG_DIR_NOTICE`].
    NoConfigDir,
}

impl fmt::Display for CredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CredentialError::IoError(msg) => write!(f, "I/O error: {}", msg),
            CredentialError::SerializationError(msg) => {
                write!(f, "serialization error: {}", msg)
            }
            CredentialError::CryptoError(msg) => write!(f, "crypto error: {}", msg),
            CredentialError::FingerprintError(e) => write!(f, "fingerprint error: {}", e),
            CredentialError::KeystoreError(msg) => write!(f, "keystore error: {}", msg),
            CredentialError::NotFound(path) => write!(f, "credential file not found: {}", path),
            CredentialError::UnsupportedVersion(v) => {
                write!(f, "unsupported store version: {}", v)
            }
            CredentialError::Unreadable => f.write_str(UNREADABLE_NOTICE),
            CredentialError::KeyringUnavailable => f.write_str(KEYRING_UNAVAILABLE_NOTICE),
            CredentialError::NoConfigDir => f.write_str(NO_CONFIG_DIR_NOTICE),
        }
    }
}

impl std::error::Error for CredentialError {}

impl From<KeystoreError> for CredentialError {
    fn from(e: KeystoreError) -> Self {
        match e {
            KeystoreError::KeyringUnavailable(_) => CredentialError::KeyringUnavailable,
            // Shown as "can't be opened": remove on the phone, pair again.
            // The file is kept, as for any other unreadable store.
            KeystoreError::MachineBoundRefused => CredentialError::Unreadable,
            other => CredentialError::KeystoreError(other.to_string()),
        }
    }
}

impl From<FingerprintError> for CredentialError {
    fn from(e: FingerprintError) -> Self {
        CredentialError::FingerprintError(e)
    }
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// All sensitive material for an active desktop-to-vault connection.
///
/// This struct is JSON-serialized before encryption. The `Zeroize` derive
/// ensures that sensitive byte fields are overwritten when the struct is dropped.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct ConnectionCredentials {
    pub connection_id: String,
    /// Session key derived from X25519 + HKDF. Zeroized on expiry.
    #[serde(with = "serde_bytes")]
    pub connection_key: Vec<u8>,
    pub key_id: String,
    #[serde(with = "serde_bytes")]
    pub device_private_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub device_public_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub vault_public_key: Vec<u8>,
    /// JWT+seed block for the device's scoped NATS account.
    pub message_space_token: String,
    pub message_space_url: String,
    pub owner_guid: String,
    pub owner_name: String,
    pub session_id: String,
    /// Unix seconds at which the current session expires. 0 = unknown/expired.
    #[serde(default)]
    pub session_expires_at: i64,
    /// User-approved session duration in seconds, for re-request on extension.
    #[serde(default)]
    pub session_duration_seconds: i64,
}

/// The on-disk JSON format for encrypted credentials. v2.
///
/// `binding` records which keystore path was used to encrypt the
/// store so a subsequent `load` can go straight to the right source
/// (the keyring path on a system whose keyring is now broken would
/// otherwise silently fall back to the machine-bound key and fail to
/// decrypt the keyring-bound blob).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedStore {
    pub version: i32,
    /// "keyring" or "machine". See [`BindingMode`].
    pub binding: String,
    /// 24-byte XChaCha20-Poly1305 nonce. Fresh per save.
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Returns the OS-appropriate config directory path for credentials.
///
/// - Linux: `$XDG_CONFIG_HOME/vettid-desktop` (typically `~/.config/vettid-desktop`)
/// - macOS: `~/Library/Application Support/vettid-desktop`
/// - Windows: `%LOCALAPPDATA%\vettid-desktop`, which stays on this machine.
///   Not the roaming `%APPDATA%`: a machine-bound store can't open on
///   another PC, and a roamed copy would sit on the profile server.
///
/// SECURITY: fails with [`CredentialError::NoConfigDir`] when the
/// platform folder is unknown or not an absolute path. There is no
/// fallback to the current directory, whose permissions are unknown and
/// which `logout` would then wipe (owner decision, 2026-11-01).
pub fn default_config_dir() -> Result<PathBuf, CredentialError> {
    config_dir_under(platform_config_base())
}

#[cfg(windows)]
fn platform_config_base() -> Option<PathBuf> {
    dirs::config_local_dir()
}

#[cfg(not(windows))]
fn platform_config_base() -> Option<PathBuf> {
    dirs::config_dir()
}

fn config_dir_under(base: Option<PathBuf>) -> Result<PathBuf, CredentialError> {
    match base {
        Some(base) if base.is_absolute() => Ok(base.join(CONFIG_SUBDIR)),
        _ => Err(CredentialError::NoConfigDir),
    }
}

/// Encrypt credentials and write them to `connection.enc` in `config_dir`.
///
/// The encryption key comes from the OS keyring (or the machine-bound
/// fallback when the keyring is unavailable). No user input. The file
/// is written with mode 0600 (owner read/write only) on unix. On Windows
/// it gets the ACL it inherits from the config directory.
///
/// SECURITY: Intermediate key material is zeroized after use; the
/// `MasterKey` returned by the keystore zeroizes on drop.
pub fn save(config_dir: &Path, creds: &ConnectionCredentials) -> Result<BindingMode, CredentialError> {
    save_with(&SystemKeys, config_dir, creds)
}

/// Read and decrypt credentials from `connection.enc` in `config_dir`.
///
/// Uses the master key from the same keystore source the file was
/// encrypted under (recorded in the file's `binding` header).
/// Returns `(credentials, binding_mode)`.
///
/// A machine-bound file that does not decrypt is reported as
/// [`CredentialError::Unreadable`]. It is deleted only if it was sealed by an
/// earlier build under the public fingerprint (it opens with that as the
/// key); otherwise it is kept, since a changed machine attribute may change
/// back. A keyring-bound file that does not decrypt is left in place.
pub fn load(config_dir: &Path) -> Result<(ConnectionCredentials, BindingMode), CredentialError> {
    load_with(&SystemKeys, config_dir)
}

/// Where [`save`] and [`load`] get their keys. Production uses
/// [`SystemKeys`]; tests pass fixed keys, so a store round trip can be
/// tested without a keyring or real machine attributes.
pub(crate) trait KeySource {
    /// The master key for a new save (keyring, else machine-bound).
    fn master_for_save(&self) -> Result<MasterKey, KeystoreError>;
    /// The master key for a store sealed under `binding`.
    fn master_for_load(&self, binding: BindingMode) -> Result<MasterKey, KeystoreError>;
    /// This machine's platform key, mixed into the AAD.
    fn platform_key(&self) -> Result<Zeroizing<[u8; 32]>, FingerprintError>;
}

/// The keyring and this machine's attributes.
struct SystemKeys;

impl KeySource for SystemKeys {
    fn master_for_save(&self) -> Result<MasterKey, KeystoreError> {
        keystore::fetch_or_create_master_key()
    }
    fn master_for_load(&self, binding: BindingMode) -> Result<MasterKey, KeystoreError> {
        keystore::fetch_for_binding(binding)
    }
    fn platform_key(&self) -> Result<Zeroizing<[u8; 32]>, FingerprintError> {
        platform_key::derive_platform_key()
    }
}

fn load_with(
    keys: &dyn KeySource,
    config_dir: &Path,
) -> Result<(ConnectionCredentials, BindingMode), CredentialError> {
    let store = read_store(config_dir)?;
    let binding = BindingMode::from_str(&store.binding).ok_or_else(|| {
        CredentialError::SerializationError(format!("unknown binding mode: {}", store.binding))
    })?;
    let master = keys.master_for_load(binding)?;
    let platform_key = keys.platform_key()?;
    match decrypt_store(&store, &master.key, &platform_key) {
        Ok(creds) => Ok((creds, binding)),
        Err(CredentialError::CryptoError(e)) if binding == BindingMode::MachineBound => {
            // Delete the file only when it is positively one written by an
            // earlier build, which used the public fingerprint as its key.
            // Any other failure may be a machine attribute that changed and
            // will change back (a disk enumerated in another order, a dock's
            // MAC, a DHCP hostname), so the file is kept: pairing again or
            // "Remove this desktop" replaces it.
            if decrypt_store(&store, &platform_key, &platform_key).is_ok() {
                log::warn!(
                    "credential store: machine-bound file was sealed under the public fingerprint by an earlier build; deleting it"
                );
                if let Err(de) = delete(config_dir) {
                    log::error!("credential store: could not delete the old file: {}", de);
                }
            } else {
                log::warn!(
                    "credential store: machine-bound file does not decrypt on this machine ({}); keeping it",
                    e
                );
            }
            Err(CredentialError::Unreadable)
        }
        Err(e) => Err(e),
    }
}

fn save_with(
    keys: &dyn KeySource,
    config_dir: &Path,
    creds: &ConnectionCredentials,
) -> Result<BindingMode, CredentialError> {
    let master = keys.master_for_save()?;
    // SECURITY: never downgrade. If the store on disk is keyring-bound
    // and the keyring fails now, the keystore falls back to the
    // machine-bound key; re-sealing under it would silently move the
    // pairing to a key any local user can recompute. Fail the save and
    // leave the file as it is. A file that exists but can't be read or
    // parsed may be keyring-bound too, so it is not overwritten either.
    if master.binding != BindingMode::Keyring {
        match on_disk_store(config_dir) {
            OnDisk::Absent | OnDisk::Bound(BindingMode::MachineBound) => {}
            OnDisk::Bound(BindingMode::Keyring) | OnDisk::Unreadable => {
                log::warn!("Credential store: keyring unavailable; not overwriting a keyring-bound or unreadable store under a weaker key");
                return Err(CredentialError::KeyringUnavailable);
            }
        }
    }
    let binding = master.binding;
    let platform_key = keys.platform_key()?;

    let mut plaintext = serde_json::to_vec(creds)
        .map_err(|e| CredentialError::SerializationError(format!("marshal credentials: {}", e)))?;

    let aad = compute_blob_aad(binding.as_str(), &platform_key);
    let (nonce, ciphertext) = encrypt_xchacha20(&master.key, &plaintext, &aad)?;
    plaintext.zeroize();
    // `master` zeroizes on drop.

    let store = EncryptedStore {
        version: STORE_VERSION,
        binding: binding.as_str().to_string(),
        nonce,
        ciphertext,
    };

    let data = serde_json::to_vec(&store)
        .map_err(|e| CredentialError::SerializationError(format!("marshal store: {}", e)))?;

    fs::create_dir_all(config_dir)
        .map_err(|e| CredentialError::IoError(format!("create config dir: {}", e)))?;

    let path = config_dir.join(CREDENTIAL_FILE);
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    // Mode bits are not an access control on Windows. There the file
    // gets the ACL it inherits from its folder. In the default folder
    // under %LOCALAPPDATA% that is the user, SYSTEM and Administrators,
    // but a redirected or pre-made folder can grant more. An explicit
    // user-only DACL is required before a Windows release (owner
    // decision 1a, 2026-11-01; #16).
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(&path)
        .map_err(|e| CredentialError::IoError(format!("open {}: {}", path.display(), e)))?;

    file.write_all(&data)
        .map_err(|e| CredentialError::IoError(format!("write {}: {}", path.display(), e)))?;

    Ok(binding)
}

/// Check whether a credential file exists in `config_dir`.
pub fn exists(config_dir: &Path) -> bool {
    let path = config_dir.join(CREDENTIAL_FILE);
    path.exists()
}

/// Delete the credential file from `config_dir`.
pub fn delete(config_dir: &Path) -> Result<(), CredentialError> {
    let path = config_dir.join(CREDENTIAL_FILE);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(CredentialError::IoError(format!(
            "remove {}: {}",
            path.display(),
            e
        ))),
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// What is on disk where the store goes.
#[derive(Debug, PartialEq, Eq)]
enum OnDisk {
    /// No credential file.
    Absent,
    /// A store with this binding.
    Bound(BindingMode),
    /// A file that exists but can't be read, parsed or understood.
    Unreadable,
}

fn on_disk_store(config_dir: &Path) -> OnDisk {
    match read_store(config_dir) {
        Ok(store) => BindingMode::from_str(&store.binding).map_or(OnDisk::Unreadable, OnDisk::Bound),
        Err(CredentialError::NotFound(_)) => OnDisk::Absent,
        Err(_) => OnDisk::Unreadable,
    }
}

/// Read and parse the encrypted store from disk.
fn read_store(config_dir: &Path) -> Result<EncryptedStore, CredentialError> {
    let path = config_dir.join(CREDENTIAL_FILE);
    let data = fs::read(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            CredentialError::NotFound(path.display().to_string())
        } else {
            CredentialError::IoError(format!("read {}: {}", path.display(), e))
        }
    })?;

    let store: EncryptedStore = serde_json::from_slice(&data)
        .map_err(|e| CredentialError::SerializationError(format!("parse store: {}", e)))?;

    if store.version != STORE_VERSION && store.version != LEGACY_STORE_VERSION_V2 {
        return Err(CredentialError::UnsupportedVersion(store.version));
    }

    Ok(store)
}

/// Compute the AEAD associated-data used to bind a v3 credential blob
/// to its origin machine. The 32-byte platform key (HMAC of machine
/// attributes) is mixed in along with the binding mode and a version
/// label. A blob whose AAD doesn't match the current machine will
/// fail to decrypt even when the master key is correct — closing the
/// "copied the file + the keyring entry to my own laptop" path.
/// See SECURITY-REVIEW-2026-05-25.md D-HIGH-3.
fn compute_blob_aad(binding: &str, platform_key: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_LABEL.len() + 1 + binding.len() + 1 + platform_key.len());
    aad.extend_from_slice(AAD_LABEL);
    aad.push(b'|');
    aad.extend_from_slice(binding.as_bytes());
    aad.push(b'|');
    aad.extend_from_slice(platform_key);
    aad
}

/// Decrypt the store with the given 32-byte master key. `platform_key`
/// goes into the v3 AAD.
fn decrypt_store(
    store: &EncryptedStore,
    key: &[u8; 32],
    platform_key: &[u8; 32],
) -> Result<ConnectionCredentials, CredentialError> {
    if store.nonce.len() != NONCE_SIZE {
        return Err(CredentialError::CryptoError(format!(
            "bad nonce length: expected {}, got {}",
            NONCE_SIZE,
            store.nonce.len(),
        )));
    }
    let nonce = XNonce::from_slice(&store.nonce);
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CredentialError::CryptoError(format!("cipher: {}", e)))?;
    // Zeroized on drop, so also when parsing below fails.
    let plaintext: Zeroizing<Vec<u8>> = Zeroizing::new(if store.version >= STORE_VERSION {
        let aad = compute_blob_aad(&store.binding, platform_key);
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: store.ciphertext.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|e| CredentialError::CryptoError(format!("decrypt v3: {}", e)))?
    } else {
        // v2 legacy path — no AAD. Subsequent save() rewrites this
        // blob as v3 with current-machine AAD.
        cipher
            .decrypt(nonce, store.ciphertext.as_slice())
            .map_err(|e| CredentialError::CryptoError(format!("decrypt v2: {}", e)))?
    });

    let creds: ConnectionCredentials = serde_json::from_slice(&plaintext)
        .map_err(|e| CredentialError::SerializationError(format!("parse credentials: {}", e)))?;
    Ok(creds)
}

/// Encrypt plaintext with XChaCha20-Poly1305, binding the ciphertext
/// to `aad` (machine-derived AAD — see [`compute_blob_aad`]). Returns
/// `(nonce, ciphertext)`.
fn encrypt_xchacha20(
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CredentialError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CredentialError::CryptoError(format!("cipher: {}", e)))?;
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|e| CredentialError::CryptoError(format!("encrypt: {}", e)))?;

    Ok((nonce_bytes.to_vec(), ciphertext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xchacha20_roundtrip() {
        let key = [0x42u8; 32];
        let aad = b"test-aad";
        let plaintext = b"hello, VettID desktop!";
        let (nonce, ct) = encrypt_xchacha20(&key, plaintext, aad).expect("encrypt");
        assert_eq!(nonce.len(), NONCE_SIZE);

        // Re-decrypt by hand (the public `decrypt_store` requires a
        // round-trip through the keystore, which the CI tests can't
        // exercise without a real Secret Service).
        let cipher = XChaCha20Poly1305::new_from_slice(&key).unwrap();
        let pt = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload { msg: ct.as_slice(), aad },
            )
            .expect("decrypt");
        assert_eq!(&pt, plaintext);
    }

    #[test]
    fn aad_mismatch_fails_decrypt() {
        let key = [0x42u8; 32];
        let (nonce, ct) = encrypt_xchacha20(&key, b"secret", b"aad-A").expect("encrypt");
        let cipher = XChaCha20Poly1305::new_from_slice(&key).unwrap();
        // Same key, same nonce, different AAD → AEAD must reject.
        let result = cipher.decrypt(
            XNonce::from_slice(&nonce),
            Payload { msg: ct.as_slice(), aad: b"aad-B" },
        );
        assert!(result.is_err(), "AEAD must reject mismatched AAD");
    }

    /// Fixed keys in place of the keyring and the machine attributes.
    struct FixedKeys {
        binding: BindingMode,
        master: [u8; 32],
        platform: [u8; 32],
    }

    impl KeySource for FixedKeys {
        fn master_for_save(&self) -> Result<MasterKey, KeystoreError> {
            Ok(MasterKey { key: Zeroizing::new(self.master), binding: self.binding })
        }
        fn master_for_load(&self, binding: BindingMode) -> Result<MasterKey, KeystoreError> {
            Ok(MasterKey { key: Zeroizing::new(self.master), binding })
        }
        fn platform_key(&self) -> Result<Zeroizing<[u8; 32]>, FingerprintError> {
            Ok(Zeroizing::new(self.platform))
        }
    }

    fn sample_creds() -> ConnectionCredentials {
        ConnectionCredentials {
            connection_id: "conn-1".into(),
            connection_key: vec![7u8; 32],
            key_id: "key-1".into(),
            device_private_key: vec![1u8; 32],
            device_public_key: vec![2u8; 32],
            vault_public_key: vec![3u8; 32],
            message_space_token: "token".into(),
            message_space_url: "nats://example.invalid:4222".into(),
            owner_guid: "owner".into(),
            owner_name: "Owner".into(),
            session_id: "session-1".into(),
            session_expires_at: 1_900_000_000,
            session_duration_seconds: 3600,
        }
    }

    const PLATFORM: [u8; 32] = [0x11; 32];
    const BOUND_KEY: [u8; 32] = [0x22; 32];

    #[test]
    fn machine_bound_store_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let keys = FixedKeys { binding: BindingMode::MachineBound, master: BOUND_KEY, platform: PLATFORM };
        let creds = sample_creds();

        let binding = save_with(&keys, dir.path(), &creds).expect("save");
        assert_eq!(binding, BindingMode::MachineBound);
        assert_eq!(read_store(dir.path()).unwrap().binding, "machine");

        let (loaded, binding) = load_with(&keys, dir.path()).expect("load");
        assert_eq!(binding, BindingMode::MachineBound);
        assert_eq!(loaded.connection_id, creds.connection_id);
        assert_eq!(loaded.connection_key, creds.connection_key);
        assert_eq!(loaded.device_private_key, creds.device_private_key);
        assert_eq!(loaded.session_expires_at, creds.session_expires_at);
    }

    /// A file sealed by an earlier build, whose machine-bound key was the
    /// public machine fingerprint, gives the plain notice and is deleted.
    #[test]
    fn blob_sealed_under_the_fingerprint_is_unreadable_and_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let old_build = FixedKeys { binding: BindingMode::MachineBound, master: PLATFORM, platform: PLATFORM };
        save_with(&old_build, dir.path(), &sample_creds()).expect("save");

        let this_build = FixedKeys { binding: BindingMode::MachineBound, master: BOUND_KEY, platform: PLATFORM };
        let err = load_with(&this_build, dir.path()).err().expect("must not load");
        assert!(matches!(err, CredentialError::Unreadable), "got {err}");
        assert_eq!(err.to_string(), UNREADABLE_NOTICE);
        assert!(!err.to_string().contains("decrypt"));
        assert!(!exists(dir.path()), "the unreadable file must be deleted");
    }

    /// A machine attribute changed (a disk serial, a MAC, a hostname): the
    /// machine-bound key and the fingerprint both differ. The pairing is
    /// unreadable for now but must not be deleted, since the attribute may
    /// change back, and then it opens again.
    #[test]
    fn attribute_drift_keeps_the_file_and_it_opens_again() {
        let dir = tempfile::tempdir().unwrap();
        let before = FixedKeys { binding: BindingMode::MachineBound, master: BOUND_KEY, platform: PLATFORM };
        save_with(&before, dir.path(), &sample_creds()).expect("save");

        let drifted = FixedKeys { binding: BindingMode::MachineBound, master: [0x66; 32], platform: [0x33; 32] };
        let err = load_with(&drifted, dir.path()).err().expect("must not load");
        assert!(matches!(err, CredentialError::Unreadable), "got {err}");
        assert_eq!(err.to_string(), UNREADABLE_NOTICE);
        assert!(exists(dir.path()), "a drifted pairing must be kept");

        let (loaded, _) = load_with(&before, dir.path()).expect("opens once the attribute is back");
        assert_eq!(loaded.connection_id, "conn-1");
    }

    /// Only the AAD differs (same master key, different fingerprint): also
    /// kept.
    #[test]
    fn machine_bound_aad_mismatch_keeps_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let there = FixedKeys { binding: BindingMode::MachineBound, master: BOUND_KEY, platform: [0x33; 32] };
        save_with(&there, dir.path(), &sample_creds()).expect("save");

        let here = FixedKeys { binding: BindingMode::MachineBound, master: BOUND_KEY, platform: PLATFORM };
        assert!(matches!(load_with(&here, dir.path()), Err(CredentialError::Unreadable)));
        assert!(exists(dir.path()));
    }

    /// A keyring-bound file that does not decrypt is not deleted: the
    /// keyring entry may come back, and this change is about
    /// machine-bound files only.
    #[test]
    fn keyring_bound_decrypt_failure_keeps_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let saved = FixedKeys { binding: BindingMode::Keyring, master: [0x44; 32], platform: PLATFORM };
        save_with(&saved, dir.path(), &sample_creds()).expect("save");

        let other = FixedKeys { binding: BindingMode::Keyring, master: [0x55; 32], platform: PLATFORM };
        assert!(matches!(load_with(&other, dir.path()), Err(CredentialError::CryptoError(_))));
        assert!(exists(dir.path()));
    }

    /// The real keystore logic (`fetch_or_create_master_key_with`) over
    /// test sources: the store asks the keystore exactly as in production.
    /// The fallback is allowed here, as on Linux and macOS, so these tests
    /// cover the machine-bound path on every platform; the Windows policy
    /// has its own test below.
    struct ThroughKeystore(keystore::tests::TestSources);

    impl KeySource for ThroughKeystore {
        fn master_for_save(&self) -> Result<MasterKey, KeystoreError> {
            keystore::fetch_or_create_master_key_with_policy(&self.0, true)
        }
        fn master_for_load(&self, binding: BindingMode) -> Result<MasterKey, KeystoreError> {
            keystore::fetch_for_binding_with_policy(&self.0, binding, true)
        }
        fn platform_key(&self) -> Result<Zeroizing<[u8; 32]>, FingerprintError> {
            Ok(Zeroizing::new(PLATFORM))
        }
    }

    /// No keyring, and a machine without a usable machine id: the
    /// machine-bound key is refused, so the save fails and nothing is
    /// written, not even the directory.
    #[test]
    fn missing_machine_id_fails_the_save_and_writes_no_file() {
        for machine_id in ["", "uninitialized", "00000000-0000-0000-0000-000000000000"] {
            let dir = tempfile::tempdir().unwrap();
            let config_dir = dir.path().join("vettid-desktop");
            let keys = ThroughKeystore(keystore::tests::TestSources::no_keyring(
                keystore::tests::attrs_with_machine_id(machine_id),
            ));
            let err = save_with(&keys, &config_dir, &sample_creds())
                .err()
                .expect("save must fail");
            assert!(matches!(err, CredentialError::KeystoreError(_)), "got {err}");
            assert!(err.to_string().contains("no machine id"), "got {err}");
            assert!(!config_dir.exists(), "{machine_id:?}: nothing may be written");
        }
    }

    /// The same path with a real machine id works end to end.
    #[test]
    fn no_keyring_with_a_machine_id_round_trips_through_the_keystore() {
        let dir = tempfile::tempdir().unwrap();
        let keys = ThroughKeystore(keystore::tests::TestSources::no_keyring(
            keystore::tests::attrs_with_machine_id("4c4c4544003a3610804db7c04f4d3732"),
        ));
        assert_eq!(save_with(&keys, dir.path(), &sample_creds()).unwrap(), BindingMode::MachineBound);
        let (loaded, binding) = load_with(&keys, dir.path()).expect("load");
        assert_eq!(binding, BindingMode::MachineBound);
        assert_eq!(loaded.connection_id, "conn-1");
    }

    fn with_keyring() -> keystore::tests::TestSources {
        keystore::tests::TestSources {
            keyring: Some(std::cell::RefCell::new(None)),
            attrs: keystore::tests::attrs_with_machine_id("4c4c4544003a3610804db7c04f4d3732"),
        }
    }

    fn without_keyring() -> keystore::tests::TestSources {
        keystore::tests::TestSources::no_keyring(keystore::tests::attrs_with_machine_id(
            "4c4c4544003a3610804db7c04f4d3732",
        ))
    }

    /// A keyring-bound store, then the keyring fails: the keystore would
    /// fall back, but the save refuses to re-seal under the machine-bound
    /// key, and the file on disk is left byte for byte as it was.
    #[test]
    fn keyring_store_is_never_resaved_machine_bound() {
        let dir = tempfile::tempdir().unwrap();
        let first = ThroughKeystore(with_keyring());
        assert_eq!(save_with(&first, dir.path(), &sample_creds()).unwrap(), BindingMode::Keyring);
        let before = fs::read(dir.path().join(CREDENTIAL_FILE)).unwrap();

        let broken = ThroughKeystore(without_keyring());
        let err = save_with(&broken, dir.path(), &sample_creds()).err().expect("save must fail");
        assert!(matches!(err, CredentialError::KeyringUnavailable), "got {err}");
        assert_eq!(err.to_string(), KEYRING_UNAVAILABLE_NOTICE);

        let after = fs::read(dir.path().join(CREDENTIAL_FILE)).unwrap();
        assert_eq!(before, after, "the keyring-bound file must be left as it was");
        assert_eq!(read_store(dir.path()).unwrap().binding, "keyring");
    }

    /// A file that exists but can't be parsed, or names an unknown
    /// binding, may be keyring-bound: a machine-bound save leaves it as it
    /// is. With the keyring working, the save replaces it.
    #[test]
    fn unreadable_store_is_not_overwritten_machine_bound() {
        let unknown_binding = br#"{"version":3,"binding":"future","nonce":[],"ciphertext":[]}"#;
        for contents in [&b"not json"[..], &b""[..], &unknown_binding[..]] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(CREDENTIAL_FILE);
            fs::write(&path, contents).unwrap();
            assert_eq!(on_disk_store(dir.path()), OnDisk::Unreadable);

            let broken = ThroughKeystore(without_keyring());
            let err = save_with(&broken, dir.path(), &sample_creds()).err().expect("save must fail");
            assert!(matches!(err, CredentialError::KeyringUnavailable), "got {err}");
            assert_eq!(fs::read(&path).unwrap(), contents, "the file must be left as it was");

            let keyring = ThroughKeystore(with_keyring());
            assert_eq!(save_with(&keyring, dir.path(), &sample_creds()).unwrap(), BindingMode::Keyring);
        }
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(on_disk_store(empty.path()), OnDisk::Absent);
    }

    /// The other direction is allowed: a machine-bound store is re-saved
    /// under the keyring once the keyring works.
    #[test]
    fn machine_bound_store_moves_to_the_keyring_when_it_works() {
        let dir = tempfile::tempdir().unwrap();
        let bound = ThroughKeystore(without_keyring());
        assert_eq!(save_with(&bound, dir.path(), &sample_creds()).unwrap(), BindingMode::MachineBound);
        let keyring = ThroughKeystore(with_keyring());
        assert_eq!(save_with(&keyring, dir.path(), &sample_creds()).unwrap(), BindingMode::Keyring);
        assert_eq!(read_store(dir.path()).unwrap().binding, "keyring");
        let (loaded, binding) = load_with(&keyring, dir.path()).expect("load");
        assert_eq!(binding, BindingMode::Keyring);
        assert_eq!(loaded.connection_id, "conn-1");
    }

    /// The Windows policy: no keyring means no save at all, with the plain
    /// notice, even with a usable machine id; nothing is written.
    #[test]
    fn without_the_fallback_no_keyring_fails_the_save_and_writes_nothing() {
        struct NoFallback(keystore::tests::TestSources);
        impl KeySource for NoFallback {
            fn master_for_save(&self) -> Result<MasterKey, KeystoreError> {
                keystore::fetch_or_create_master_key_with_policy(&self.0, false)
            }
            fn master_for_load(&self, binding: BindingMode) -> Result<MasterKey, KeystoreError> {
                keystore::fetch_for_binding_with_policy(&self.0, binding, false)
            }
            fn platform_key(&self) -> Result<Zeroizing<[u8; 32]>, FingerprintError> {
                Ok(Zeroizing::new(PLATFORM))
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join("vettid-desktop");
        let err = save_with(&NoFallback(without_keyring()), &config_dir, &sample_creds())
            .err()
            .expect("save must fail");
        assert!(matches!(err, CredentialError::KeyringUnavailable), "got {err}");
        assert!(!config_dir.exists(), "nothing may be written");

        // A machine-bound file (from an earlier build) is not opened under
        // this policy either: it reads as unreadable, and is kept.
        let other = tempfile::tempdir().unwrap();
        save_with(&ThroughKeystore(without_keyring()), other.path(), &sample_creds()).unwrap();
        let before = fs::read(other.path().join(CREDENTIAL_FILE)).unwrap();
        let err = load_with(&NoFallback(without_keyring()), other.path()).err().expect("load must fail");
        assert!(matches!(err, CredentialError::Unreadable), "got {err}");
        assert_eq!(fs::read(other.path().join(CREDENTIAL_FILE)).unwrap(), before, "kept");
    }

    /// No known folder, or a relative one, is refused: never the current
    /// directory.
    #[test]
    fn config_dir_requires_an_absolute_platform_folder() {
        assert!(matches!(config_dir_under(None), Err(CredentialError::NoConfigDir)));
        for relative in [".", "", "relative/dir", "./vettid"] {
            assert!(
                matches!(config_dir_under(Some(PathBuf::from(relative))), Err(CredentialError::NoConfigDir)),
                "{relative:?} must be refused"
            );
        }
        let base = tempfile::tempdir().unwrap();
        let dir = config_dir_under(Some(base.path().to_path_buf())).expect("absolute base");
        assert_eq!(dir, base.path().join(CONFIG_SUBDIR));
        assert_eq!(CredentialError::NoConfigDir.to_string(), NO_CONFIG_DIR_NOTICE);
    }

    /// On Windows the folder is the local, non-roaming one.
    #[cfg(windows)]
    #[test]
    fn windows_config_dir_is_local_app_data() {
        let dir = default_config_dir().expect("config dir");
        assert_eq!(dir, dirs::config_local_dir().unwrap().join(CONFIG_SUBDIR));
        assert_ne!(dir.parent(), dirs::config_dir().as_deref(), "must not be the roaming folder");
    }

    #[test]
    fn wrong_key_fails_decrypt() {
        let key = [0x42u8; 32];
        let bad = [0x43u8; 32];
        let (nonce, ct) = encrypt_xchacha20(&key, b"secret", b"aad").expect("encrypt");
        let cipher = XChaCha20Poly1305::new_from_slice(&bad).unwrap();
        let result = cipher.decrypt(XNonce::from_slice(&nonce), ct.as_slice());
        assert!(result.is_err());
    }
}
