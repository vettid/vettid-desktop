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
#[cfg(not(windows))]
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

/// Shown when the pairing's folder or file could be opened by another
/// account on this computer (Windows).
#[cfg(windows)]
pub const NOT_PRIVATE_NOTICE: &str =
    "The folder this desktop keeps its pairing in (vettid-desktop, in your local app data) can be opened by another account on this computer, so nothing was saved there. Delete that folder, then pair again.";

/// Unix: shown when the pairing's folder is owned by another account or
/// another account can write to it (#28, owner decision (a), 2026-11-01).
/// That account can't read the `0600` file, but it could remove or replace
/// it (AEAD refuses a replaced one).
#[cfg(not(windows))]
pub const NOT_PRIVATE_NOTICE: &str =
    "The folder this desktop keeps its pairing in (vettid-desktop, in your settings folder) can be changed by another account on this computer, so nothing was saved there. Delete that folder, then pair again.";

/// Unix: shown after unlock when the saved pairing's file is private but
/// its folder is owned by, or writable by, another account (#28).
#[cfg(unix)]
pub const NOT_PRIVATE_FOLDER_NOTICE: &str =
    "Another account on this computer can change the folder this desktop keeps its pairing in. It can't read your pairing, but it could remove it. To be safe: in Settings, open Danger zone and choose Log out this desktop, then pair again.";

/// Shown after unlock when another account can open the saved pairing's
/// folder or file, and the pairing is keyring-bound (#24).
///
/// Log out (Settings > Danger zone) is the way out: it sends the revoke,
/// removes the folder and deletes the keyring key, and says if a step
/// failed. Pairing again into the same folder would not fix it (Windows
/// refuses the folder; on unix the file's mode is kept on rewrite).
pub const NOT_PRIVATE_KEYRING_NOTICE: &str =
    "Another account on this computer can open this desktop's saved pairing. It is still locked by your keyring, but to be safe: in Settings, open Danger zone and choose Log out this desktop. Then check on your phone that this desktop is gone, and pair again.";

/// The same for a machine-bound pairing, which may have been read.
pub const NOT_PRIVATE_MACHINE_NOTICE: &str =
    "Another account on this computer can open this desktop's saved pairing, and it isn't locked by a keyring, so it may have been read. In Settings, open Danger zone and choose Log out this desktop. Then check on your phone that this desktop is gone, and pair again.";

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
    /// The folder or file for the pairing is not private to the current
    /// user. Windows: another account owns it or can open it, or it is a
    /// symlink or junction. Unix: another account owns the folder or can
    /// write to it. Nothing was changed. Displays [`NOT_PRIVATE_NOTICE`].
    NotPrivate,
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
            CredentialError::NotPrivate => f.write_str(NOT_PRIVATE_NOTICE),
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

/// Create `config_dir` if needed, for keeping a pairing in.
///
/// On Windows the folder is made private to the current user (a
/// protected DACL for the user and SYSTEM), and an existing folder that
/// another account owns or can open, or that is a symlink or junction, is
/// refused with [`CredentialError::NotPrivate`] (#16). On unix it is
/// created as before.
pub fn ensure_config_dir(config_dir: &Path) -> Result<(), CredentialError> {
    #[cfg(windows)]
    {
        super::winacl::ensure_private_dir(config_dir).map_err(|e| acl_error(config_dir, e))
    }
    // Unix: a new folder is created 0700 (#12). Its parents are created as
    // usual, with their default modes. An existing folder is left as it is,
    // but refused if another account owns it or can write to it (#28).
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let err = |e: std::io::Error| CredentialError::IoError(format!("create config dir: {}", e));
        if let Some(parent) = config_dir.parent() {
            fs::create_dir_all(parent).map_err(err)?;
        }
        match fs::DirBuilder::new().mode(0o700).create(config_dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && config_dir.is_dir() => {}
            Err(e) => return Err(err(e)),
        }
        match unix_folder_check(config_dir) {
            Ok(()) => Ok(()),
            Err(FolderCheck::NotPrivate(why)) => {
                log::error!("Credential store: {} {}; refusing to use it", config_dir.display(), why);
                Err(CredentialError::NotPrivate)
            }
            Err(FolderCheck::Failed(e)) => Err(err(e)),
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        fs::create_dir_all(config_dir)
            .map_err(|e| CredentialError::IoError(format!("create config dir: {}", e)))
    }
}

/// Why a unix folder check refused.
#[cfg(unix)]
enum FolderCheck {
    /// Another account owns the folder or can write to it.
    NotPrivate(&'static str),
    /// The folder couldn't be checked.
    Failed(std::io::Error),
}

/// Unix: the pairing folder must be owned by this process's effective
/// user and not writable by group or others (#28), matching the Windows
/// policy. Another account that could write to it could remove or replace
/// the pairing; it still couldn't read the `0600` file. The folder's own
/// path is followed if it is a symlink: what matters is the folder the
/// file goes in.
///
/// A folder the user owns but group or others can write to is tightened
/// to `0700` here, and the check is made again: builds before #27 made the
/// folder `0777 & ~umask`, which is `0775` under the common user-private-
/// group umask `002`. Only a folder owned by another account, or one that
/// can't be tightened, is refused.
///
/// If `config_dir` is a symlink, the link itself must also be the user's:
/// another account could otherwise plant `vettid-desktop` pointing at a
/// folder of the user's (say `~/public_html`), and this check would pass
/// on it, chmod it and put the pairing there.
///
/// Not seen by this check: a macOS extended ACL (`chmod +a`) that grants
/// write without a mode bit. On Linux a POSIX ACL entry for another user
/// raises the group-class bits, so it is seen.
#[cfg(unix)]
fn unix_folder_check(config_dir: &Path) -> Result<(), FolderCheck> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    // SAFETY: geteuid has no preconditions and cannot fail.
    let me = unsafe { libc::geteuid() };
    let link = fs::symlink_metadata(config_dir).map_err(FolderCheck::Failed)?;
    if link.file_type().is_symlink() && link.uid() != me {
        return Err(FolderCheck::NotPrivate("is a link made by another account"));
    }
    let meta = fs::metadata(config_dir).map_err(FolderCheck::Failed)?;
    if !meta.is_dir() {
        return Err(FolderCheck::Failed(std::io::Error::other("not a folder")));
    }
    if meta.uid() != me {
        return Err(FolderCheck::NotPrivate("is owned by another account"));
    }
    if meta.mode() & 0o022 == 0 {
        return Ok(());
    }
    log::warn!(
        "Credential store: {} could be written by other accounts (mode {:o}); setting it to 0700",
        config_dir.display(),
        meta.mode() & 0o7777
    );
    if let Err(e) = fs::set_permissions(config_dir, fs::Permissions::from_mode(0o700)) {
        log::warn!("Credential store: could not tighten {}: {}", config_dir.display(), e);
    }
    // Confirm, rather than trust the chmod.
    let meta = fs::metadata(config_dir).map_err(FolderCheck::Failed)?;
    if meta.uid() != me {
        return Err(FolderCheck::NotPrivate("is owned by another account"));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(FolderCheck::NotPrivate("can be written by other accounts"));
    }
    Ok(())
}

/// Log the detail of a refused folder or file. A policy refusal gives the
/// person the "another account can open it" notice; a failure to check or
/// set it up is reported as an I/O error, since the folder may well be
/// private. Both leave it unchanged.
#[cfg(windows)]
fn acl_error(path: &Path, e: super::winacl::AclError) -> CredentialError {
    use super::winacl::AclError;
    log::error!("Credential store: {} {}; refusing to use it", path.display(), e);
    match e {
        AclError::NotPrivate(_) => CredentialError::NotPrivate,
        AclError::Failed(what) => CredentialError::IoError(format!("folder or file permissions: {}", what)),
    }
}

/// Encrypt credentials and write them to `connection.enc` in `config_dir`.
///
/// The encryption key comes from the OS keyring (or the machine-bound
/// fallback when the keyring is unavailable). No user input. The file
/// is written atomically through a temporary file: mode 0600 on unix, and
/// on Windows a protected DACL for the user and SYSTEM (see `winacl`).
///
/// SECURITY: Intermediate key material is zeroized after use; the
/// `MasterKey` returned by the keystore zeroizes on drop.
pub fn save(config_dir: &Path, creds: &ConnectionCredentials) -> Result<BindingMode, CredentialError> {
    save_with(&SystemKeys, config_dir, creds)
}

/// Like [`save`], for updating a pairing that is already saved (clearing
/// the session at end_session). Fails with [`CredentialError::NotFound`],
/// writing nothing and creating no folder, if `connection.enc` isn't there
/// when the write lock is taken: a log-out that wiped the pairing must not
/// be undone by an update that loaded it just before (#28).
pub fn save_existing(config_dir: &Path, creds: &ConnectionCredentials) -> Result<BindingMode, CredentialError> {
    save_with_mode(&SystemKeys, config_dir, creds, Mode::UpdateExisting)
}

/// Whether a save may create the pairing or only update it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    CreateOrReplace,
    UpdateExisting,
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
/// key); otherwise it is kept. A keyring-bound file that does not decrypt
/// is left in place. Files sealed before #14, when the key and the AAD
/// covered all five machine attributes, don't open: the person pairs again.
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
    /// This machine's storage binding, mixed into the AAD (#14).
    fn platform_key(&self) -> Result<Zeroizing<[u8; 32]>, FingerprintError>;
    /// The public machine fingerprint. Only used to recognize a file an
    /// earlier build sealed with the fingerprint as its key, and under it
    /// in the AAD. Tests use the AAD value.
    fn legacy_fingerprint(&self) -> Result<Zeroizing<[u8; 32]>, FingerprintError> {
        self.platform_key()
    }
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
        platform_key::derive_storage_binding()
    }
    fn legacy_fingerprint(&self) -> Result<Zeroizing<[u8; 32]>, FingerprintError> {
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
            // Any other failure is kept: a file sealed before #14 (key and
            // AAD over all five attributes), or a machine id that changed
            // and may change back. Pairing again or "Remove this desktop"
            // replaces it.
            let sealed_by_old_build = keys
                .legacy_fingerprint()
                .map(|fp| decrypt_store(&store, &fp, &fp).is_ok())
                .unwrap_or(false);
            if sealed_by_old_build {
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

/// One writer at a time in this process: a save, a delete or a wipe
/// removes temporary files a crashed earlier save left behind, and must not
/// remove another save's while it is running (e.g. end_session racing a
/// pairing). A wipe holding it also can't be undone by a save that started
/// first: [`save_existing`] fails once the file is gone (#28). The app runs
/// as a single instance, so this covers every writer.
///
/// A save holds it while it fetches the master key, which may wait on a
/// keyring prompt; a log-out started meanwhile waits for that save.
fn writer_lock() -> std::sync::MutexGuard<'static, ()> {
    static WRITER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    WRITER_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn save_with(
    keys: &dyn KeySource,
    config_dir: &Path,
    creds: &ConnectionCredentials,
) -> Result<BindingMode, CredentialError> {
    save_with_mode(keys, config_dir, creds, Mode::CreateOrReplace)
}

fn save_with_mode(
    keys: &dyn KeySource,
    config_dir: &Path,
    creds: &ConnectionCredentials,
    mode: Mode,
) -> Result<BindingMode, CredentialError> {
    let _one_at_a_time = writer_lock();
    if mode == Mode::UpdateExisting {
        match pairing_present(config_dir) {
            Ok(true) => {}
            Ok(false) => {
                return Err(CredentialError::NotFound(config_dir.join(CREDENTIAL_FILE).display().to_string()))
            }
            Err(e) => {
                return Err(CredentialError::IoError(format!(
                    "check {}: {}",
                    config_dir.join(CREDENTIAL_FILE).display(),
                    e
                )))
            }
        }
    }

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

    ensure_config_dir(config_dir)?;

    // SECURITY: written to a new temporary file in the same folder, then
    // moved over `connection.enc`, so a crash or a full disk leaves the
    // old pairing whole (#12). On Windows the temporary file is created
    // with the user-only DACL, inside the folder held open (#16, #23).
    #[cfg(windows)]
    super::winacl::write_private_file(config_dir, CREDENTIAL_FILE, &data)
        .map_err(|e| acl_error(&config_dir.join(CREDENTIAL_FILE), e))?;
    #[cfg(not(windows))]
    write_atomically(config_dir, &data)?;

    Ok(binding)
}

/// Unix: write `data` as `connection.enc` through a new `0600` temporary
/// file in the same folder: write, fsync, rename over the old file, fsync
/// the folder. A failure before the rename keeps the old file and removes
/// the temporary one. Renaming also means a file whose mode was widened
/// is replaced by a `0600` one.
#[cfg(not(windows))]
fn write_atomically(config_dir: &Path, data: &[u8]) -> Result<(), CredentialError> {
    let path = config_dir.join(CREDENTIAL_FILE);
    let io = |what: &str, e: std::io::Error| CredentialError::IoError(format!("{} {}: {}", what, path.display(), e));

    // Temporary files a crashed earlier save left behind.
    let prefix = format!("{CREDENTIAL_FILE}{TEMP_INFIX}");
    if let Ok(entries) = fs::read_dir(config_dir) {
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().starts_with(&prefix) {
                let _ = fs::remove_file(entry.path());
            }
        }
    }

    let temp = config_dir.join(format!(
        "{prefix}{}-{:016x}",
        std::process::id(),
        rand::RngCore::next_u64(&mut OsRng)
    ));
    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temp).map_err(|e| io("create temporary file for", e))?;
        file.write_all(data).map_err(|e| io("write", e))?;
        file.sync_all().map_err(|e| io("flush", e))?;
        drop(file);
        fs::rename(&temp, &path).map_err(|e| io("replace", e))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
        return result;
    }
    // Make the rename itself durable. Best effort: the file is in place.
    // (On macOS fsync is not F_FULLFSYNC, so this is weaker there.)
    #[cfg(unix)]
    if let Ok(dir) = fs::File::open(config_dir) {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Marks a temporary file next to `connection.enc`.
#[cfg(not(windows))]
const TEMP_INFIX: &str = ".tmp-";

/// Whether a credential file may be in `config_dir`. True when it is,
/// and also when that can't be ruled out (a stat error other than "not
/// found"): nothing may treat the pairing as gone on a guess (#28).
pub fn exists(config_dir: &Path) -> bool {
    !matches!(pairing_present(config_dir), Ok(false))
}

/// Whether `connection.enc` is in `config_dir`: Ok(false) only when the
/// file system says it isn't there. The file itself is not followed if it
/// is a link: a link is present too.
fn pairing_present(config_dir: &Path) -> std::io::Result<bool> {
    match fs::symlink_metadata(config_dir.join(CREDENTIAL_FILE)) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// Delete the credential file from `config_dir`.
pub fn delete(config_dir: &Path) -> Result<(), CredentialError> {
    let _one_at_a_time = writer_lock();
    delete_locked(config_dir)
}

/// Remove `config_dir` and everything in it, for log-out, holding the
/// write lock so no save runs at the same time (#28). If the folder can't
/// be removed, the pairing file itself is removed. Ok only if neither the
/// pairing file nor a temporary copy of it is left; the caller must not
/// report "removed" otherwise.
///
/// If `config_dir` is a symlink (a dotfile manager may link it), the
/// pairing is removed from the folder it points to, that is confirmed,
/// and then the link itself is removed. `remove_dir_all` would remove only
/// the link and leave the pairing behind.
pub fn wipe(config_dir: &Path) -> Result<(), CredentialError> {
    let _one_at_a_time = writer_lock();
    let is_link = fs::symlink_metadata(config_dir).map(|m| m.file_type().is_symlink()).unwrap_or(false);
    if is_link {
        delete_locked(config_dir)?;
        confirm_wiped(config_dir)?;
        // The pairing is gone; the link is tidied up on a best-effort basis.
        if fs::remove_file(config_dir).or_else(|_| fs::remove_dir(config_dir)).is_err() {
            log::warn!("Credential store: could not remove the link {}", config_dir.display());
        }
        return Ok(());
    }
    if config_dir.exists() {
        if let Err(e) = fs::remove_dir_all(config_dir) {
            log::warn!("Credential store: could not remove {}: {}", config_dir.display(), e);
            delete_locked(config_dir)?;
        }
    }
    confirm_wiped(config_dir)
}

/// Ok only if the file system confirms that neither the pairing file nor
/// a temporary copy of it is in `config_dir`. Anything that can't be
/// checked (a stat or listing error other than "not found") is an error:
/// the pairing is not reported gone on a guess.
fn confirm_wiped(config_dir: &Path) -> Result<(), CredentialError> {
    let not_confirmed = |what: String| {
        Err(CredentialError::IoError(format!("the pairing in {} {}", config_dir.display(), what)))
    };
    match pairing_present(config_dir) {
        Ok(false) => {}
        Ok(true) => return not_confirmed("is still there".into()),
        Err(e) => return not_confirmed(format!("could not be checked: {}", e)),
    }
    let prefix = format!("{CREDENTIAL_FILE}.tmp-");
    match fs::read_dir(config_dir) {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(e) if e.file_name().to_string_lossy().starts_with(&prefix) => {
                        return not_confirmed("still has a temporary copy".into())
                    }
                    Ok(_) => {}
                    Err(e) => return not_confirmed(format!("could not be listed: {}", e)),
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return not_confirmed(format!("could not be listed: {}", e)),
    }
    Ok(())
}

fn delete_locked(config_dir: &Path) -> Result<(), CredentialError> {
    let path = config_dir.join(CREDENTIAL_FILE);
    // Temporary files from an interrupted save hold the same ciphertext.
    let prefix = format!("{CREDENTIAL_FILE}.tmp-");
    if let Ok(entries) = fs::read_dir(config_dir) {
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().starts_with(&prefix) {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
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

/// A warning for the person when another account can open the saved
/// pairing's folder or file (#24), worded for how the pairing is sealed.
/// Called after a successful load; it warns and never refuses, since
/// refusing would not undo a disclosure and would lock out the pairing.
/// AEAD already prevents a planted or edited file from being used.
///
/// On unix a private file in a folder another account can change gets
/// [`NOT_PRIVATE_FOLDER_NOTICE`] (#28); a file others can read gets the
/// stronger notice whatever the folder. Not read-only on unix: the user's
/// own folder that others can write to is set to `0700` here (see
/// `unix_folder_check`).
pub fn privacy_warning(config_dir: &Path, binding: BindingMode) -> Option<&'static str> {
    if !is_private(config_dir) {
        return Some(match binding {
            BindingMode::Keyring => NOT_PRIVATE_KEYRING_NOTICE,
            BindingMode::MachineBound => NOT_PRIVATE_MACHINE_NOTICE,
        });
    }
    #[cfg(unix)]
    match unix_folder_check(config_dir) {
        Ok(()) => {}
        Err(FolderCheck::NotPrivate(why)) => {
            log::warn!("Credential store: {} {}", config_dir.display(), why);
            return Some(NOT_PRIVATE_FOLDER_NOTICE);
        }
        Err(FolderCheck::Failed(e)) => {
            log::warn!("Credential store: could not check {}: {}", config_dir.display(), e);
        }
    }
    None
}

/// Whether the folder and file are private to the current user, as far
/// as can be told. A check that fails to run is logged and not reported
/// as a warning: the file was just read, so this is not a refusal path.
/// Nothing may present `true` to the person as "private"; it only means
/// "no warning".
///
/// On Windows every winacl refusal counts, including a reparse point and
/// an entry type the policy doesn't interpret. That errs toward warning.
#[cfg(windows)]
fn is_private(config_dir: &Path) -> bool {
    use super::winacl::{check_private, AclError};
    for path in [config_dir.to_path_buf(), config_dir.join(CREDENTIAL_FILE)] {
        match check_private(&path) {
            Ok(()) => {}
            Err(AclError::NotPrivate(why)) => {
                log::warn!("Credential store: {} {}", path.display(), why);
                return false;
            }
            Err(AclError::Failed(what)) => {
                log::warn!("Credential store: could not check {}: {}", path.display(), what);
            }
        }
    }
    true
}

/// Unix: the file must not grant group or other any access. The folder
/// is checked separately in [`privacy_warning`], since it gets its own
/// notice (#28).
#[cfg(unix)]
fn is_private(config_dir: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let path = config_dir.join(CREDENTIAL_FILE);
    match fs::metadata(&path) {
        Ok(meta) if meta.permissions().mode() & 0o077 != 0 => {
            log::warn!("Credential store: {} is readable by other accounts", path.display());
            false
        }
        Ok(_) => true,
        Err(e) => {
            log::warn!("Credential store: could not check {}: {}", path.display(), e);
            true
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn is_private(_config_dir: &Path) -> bool {
    true
}

/// Which key protects the saved pairing, for the person to see (#11):
/// "keyring", "machine", "none" (no file) or "unknown".
///
/// The file is parsed but nothing is decrypted and no key is fetched, so
/// this says how the file is sealed, not that it opens. Editing the
/// `binding` field doesn't let anyone in: the binding is part of the AEAD
/// associated data, so an edited file fails to open.
pub fn stored_key_protection(config_dir: &Path) -> &'static str {
    match on_disk_store(config_dir) {
        OnDisk::Absent => "none",
        // On a platform without the machine-bound key (Windows), such a
        // file (from an earlier development build) is refused at load, so
        // it is shown as unreadable rather than as a binding in use.
        OnDisk::Bound(BindingMode::MachineBound) if !keystore::MACHINE_BOUND_FALLBACK => "unknown",
        OnDisk::Bound(binding) => binding.as_str(),
        OnDisk::Unreadable => "unknown",
    }
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
/// to its origin machine. The 32-byte storage binding (an HMAC of the
/// machine id, #14) is mixed in along with the binding mode and a version
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

    /// Deleting the pairing also removes temporary files an interrupted
    /// save left behind.
    #[test]
    fn delete_removes_leftover_temporary_files() {
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        save_with(&ThroughKeystore(with_keyring()), &config_dir, &sample_creds()).unwrap();
        let stale = config_dir.join(format!("{CREDENTIAL_FILE}.tmp-1-00"));
        fs::write(&stale, b"ciphertext").unwrap();
        delete(&config_dir).unwrap();
        assert!(!exists(&config_dir));
        assert!(!stale.exists());
    }

    /// A pairing saved normally is private: no warning.
    #[test]
    fn privately_saved_pairing_gives_no_warning() {
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        save_with(&ThroughKeystore(with_keyring()), &config_dir, &sample_creds()).unwrap();
        assert_eq!(privacy_warning(&config_dir, BindingMode::Keyring), None);
        assert_eq!(privacy_warning(&config_dir, BindingMode::MachineBound), None);
    }

    /// Windows: a folder or file another account can open gives the
    /// warning for the binding, and nothing is changed.
    #[cfg(windows)]
    #[test]
    fn windows_shared_pairing_gives_the_warning() {
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        save_with(&ThroughKeystore(with_keyring()), &config_dir, &sample_creds()).unwrap();
        let file = config_dir.join(CREDENTIAL_FILE);
        let before = fs::read(&file).unwrap();
        super::super::winacl::test_share_with_everyone(&file);
        assert_eq!(privacy_warning(&config_dir, BindingMode::Keyring), Some(NOT_PRIVATE_KEYRING_NOTICE));
        assert_eq!(privacy_warning(&config_dir, BindingMode::MachineBound), Some(NOT_PRIVATE_MACHINE_NOTICE));
        assert_eq!(fs::read(&file).unwrap(), before, "a warning changes nothing");

        // A shared folder with a private file warns too.
        let other = base.path().join("other");
        save_with(&ThroughKeystore(with_keyring()), &other, &sample_creds()).unwrap();
        super::super::winacl::test_share_with_everyone(&other);
        assert_eq!(privacy_warning(&other, BindingMode::Keyring), Some(NOT_PRIVATE_KEYRING_NOTICE));
    }

    /// Unix (#12): a new folder is 0700 and the file 0600; a rewrite goes
    /// through a temporary file and replaces a widened file with a 0600 one;
    /// no temporary file is left.
    #[cfg(unix)]
    #[test]
    fn unix_folder_0700_file_0600_and_atomic_rewrite() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        let keys = ThroughKeystore(with_keyring());
        save_with(&keys, &config_dir, &sample_creds()).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&config_dir), 0o700);
        let file = config_dir.join(CREDENTIAL_FILE);
        assert_eq!(mode(&file), 0o600);

        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(config_dir.join(format!("{CREDENTIAL_FILE}{TEMP_INFIX}1-00")), b"stale").unwrap();
        save_with(&keys, &config_dir, &sample_creds()).unwrap();
        assert_eq!(mode(&file), 0o600, "replaced by a 0600 file");
        let temps = fs::read_dir(&config_dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(TEMP_INFIX))
            .count();
        assert_eq!(temps, 0);
        assert!(load_with(&keys, &config_dir).is_ok());
    }

    /// Unix: a file group or others can read gives the warning.
    #[cfg(unix)]
    #[test]
    fn unix_readable_file_gives_the_warning() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        save_with(&ThroughKeystore(with_keyring()), dir.path(), &sample_creds()).unwrap();
        let file = dir.path().join(CREDENTIAL_FILE);
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(privacy_warning(dir.path(), BindingMode::Keyring), Some(NOT_PRIVATE_KEYRING_NOTICE));
        assert_eq!(privacy_warning(dir.path(), BindingMode::MachineBound), Some(NOT_PRIVATE_MACHINE_NOTICE));
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(privacy_warning(dir.path(), BindingMode::Keyring), None);
    }

    /// Unix (#28): the user's own folder that others can write to (as
    /// earlier builds made it under umask 002) is tightened to 0700 and the
    /// save goes through. The refusal is for another owner, which needs a
    /// second account to test.
    #[cfg(unix)]
    #[test]
    fn unix_save_tightens_the_users_own_folder_others_can_write() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        let keys = ThroughKeystore(with_keyring());
        save_with(&keys, &config_dir, &sample_creds()).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        for wide in [0o775, 0o720, 0o702, 0o777, 0o1777] {
            fs::set_permissions(&config_dir, fs::Permissions::from_mode(wide)).unwrap();
            save_with(&keys, &config_dir, &sample_creds()).expect("tightened, then saved");
            assert_eq!(mode(&config_dir), 0o700, "{wide:o}");
            assert!(load_with(&keys, &config_dir).is_ok());
        }
        // Read and search access for others is not a refusal (the file is
        // 0600), and the folder is left as it is.
        fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o755)).unwrap();
        save_with(&keys, &config_dir, &sample_creds()).expect("0755 is accepted");
        assert_eq!(fs::metadata(&config_dir).unwrap().permissions().mode() & 0o7777, 0o755);
    }

    /// Unix (#28): at unlock, the user's own folder that others can write
    /// to is tightened and gives no warning; a file others can read still
    /// gives the stronger one. (The folder warning itself is for another
    /// owner, which needs a second account to test.)
    #[cfg(unix)]
    #[test]
    fn unix_own_folder_others_can_write_is_tightened_at_unlock() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        save_with(&ThroughKeystore(with_keyring()), &config_dir, &sample_creds()).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o770)).unwrap();
        assert_eq!(privacy_warning(&config_dir, BindingMode::Keyring), None);
        assert_eq!(mode(&config_dir), 0o700);
        let file = config_dir.join(CREDENTIAL_FILE);
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o770)).unwrap();
        assert_eq!(privacy_warning(&config_dir, BindingMode::Keyring), Some(NOT_PRIVATE_KEYRING_NOTICE));
    }

    /// Unix (#28): a folder owned by another account (root's `/usr`) is
    /// refused before anything is changed, directly and through the
    /// user's own link to it; the user's own link to the user's own folder
    /// is accepted. (A link made by another account needs a second account
    /// to test.)
    #[cfg(unix)]
    #[test]
    fn unix_folder_check_refuses_another_owner_and_checks_links() {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: as in unix_folder_check.
        if unsafe { libc::geteuid() } == 0 {
            return; // root owns /usr: nothing to check
        }
        let usr = Path::new("/usr");
        let before = fs::metadata(usr).unwrap().mode();
        assert!(matches!(unix_folder_check(usr), Err(FolderCheck::NotPrivate("is owned by another account"))));
        assert!(matches!(ensure_config_dir(usr), Err(CredentialError::NotPrivate)));
        assert_eq!(privacy_warning_folder_only(usr), Some(NOT_PRIVATE_FOLDER_NOTICE));
        assert_eq!(fs::metadata(usr).unwrap().mode(), before, "not changed");

        let base = tempfile::tempdir().unwrap();
        let to_usr = base.path().join("to-usr");
        std::os::unix::fs::symlink(usr, &to_usr).unwrap();
        assert!(matches!(unix_folder_check(&to_usr), Err(FolderCheck::NotPrivate(_))));
        let mine = base.path().join("mine");
        fs::create_dir(&mine).unwrap();
        let to_mine = base.path().join("to-mine");
        std::os::unix::fs::symlink(&mine, &to_mine).unwrap();
        assert!(unix_folder_check(&to_mine).is_ok());
    }

    /// The folder part of [`privacy_warning`], for a folder with no
    /// pairing file in it.
    #[cfg(unix)]
    fn privacy_warning_folder_only(dir: &Path) -> Option<&'static str> {
        match unix_folder_check(dir) {
            Err(FolderCheck::NotPrivate(_)) => Some(NOT_PRIVATE_FOLDER_NOTICE),
            _ => None,
        }
    }

    /// Unix (#28): when the folder can't be read, the pairing is not
    /// reported gone: exists() says it may be there, an update refuses,
    /// and a wipe is not confirmed. (Root ignores the mode, and then the
    /// test has nothing to check.)
    #[cfg(unix)]
    #[test]
    fn unix_an_unreadable_folder_is_not_reported_gone() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        let keys = ThroughKeystore(with_keyring());
        save_with(&keys, &config_dir, &sample_creds()).unwrap();
        fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o000)).unwrap();
        let root_ignores_modes = fs::read_dir(&config_dir).is_ok();
        let present = exists(&config_dir);
        let update = save_with_mode(&keys, &config_dir, &sample_creds(), Mode::UpdateExisting);
        let confirmed = confirm_wiped(&config_dir);
        fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700)).unwrap();
        if root_ignores_modes {
            return;
        }
        assert!(present, "can't be ruled out, so it may be there");
        assert!(matches!(update, Err(CredentialError::IoError(_))), "no update on a guess");
        assert!(confirmed.is_err(), "not confirmed gone");
    }

    /// Unix (#28): a symlinked pairing folder is wiped through the link:
    /// the pairing and its temporary copies are removed from the folder it
    /// points to, then the link goes.
    #[cfg(unix)]
    #[test]
    fn wipe_through_a_symlinked_folder_removes_the_pairing() {
        let base = tempfile::tempdir().unwrap();
        let real = base.path().join("dotfiles-vettid-desktop");
        let link = base.path().join("vettid-desktop");
        let keys = ThroughKeystore(with_keyring());
        save_with(&keys, &real, &sample_creds()).unwrap();
        fs::write(real.join(format!("{CREDENTIAL_FILE}{TEMP_INFIX}1-00")), b"stale").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(exists(&link));
        wipe(&link).expect("wipe");
        assert!(fs::symlink_metadata(&link).is_err(), "link removed");
        assert!(!real.join(CREDENTIAL_FILE).exists(), "pairing removed from the target");
        assert_eq!(fs::read_dir(&real).unwrap().count(), 0, "no temporary copy left");
    }

    /// Windows: the same through a junction.
    #[cfg(windows)]
    #[test]
    fn wipe_through_a_junction_removes_the_pairing() {
        let base = tempfile::tempdir().unwrap();
        let real = base.path().join("elsewhere");
        let link = base.path().join("vettid-desktop");
        save_with(&ThroughKeystore(with_keyring()), &real, &sample_creds()).unwrap();
        fs::write(real.join(format!("{CREDENTIAL_FILE}.tmp-1-00")), b"stale").unwrap();
        let out = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&real)
            .output()
            .expect("mklink");
        assert!(out.status.success(), "mklink /J failed");
        assert!(exists(&link));
        wipe(&link).expect("wipe");
        assert!(fs::symlink_metadata(&link).is_err(), "junction removed");
        assert!(real.exists(), "the target folder itself is not removed");
        assert_eq!(fs::read_dir(&real).unwrap().count(), 0, "pairing and temporary copy removed");
    }

    /// An update after a wipe writes nothing and doesn't recreate the
    /// folder (#28): log-out must not be undone by end_session.
    #[test]
    fn update_after_a_wipe_writes_nothing() {
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        let keys = ThroughKeystore(with_keyring());
        assert!(matches!(
            save_with_mode(&keys, &config_dir, &sample_creds(), Mode::UpdateExisting),
            Err(CredentialError::NotFound(_))
        ));
        assert!(!config_dir.exists(), "no folder created");
        save_with(&keys, &config_dir, &sample_creds()).unwrap();
        save_with_mode(&keys, &config_dir, &sample_creds(), Mode::UpdateExisting).expect("update");
        wipe(&config_dir).expect("wipe");
        assert!(!config_dir.exists());
        assert!(matches!(
            save_with_mode(&keys, &config_dir, &sample_creds(), Mode::UpdateExisting),
            Err(CredentialError::NotFound(_))
        ));
        assert!(!config_dir.exists(), "not recreated");
        assert!(wipe(&config_dir).is_ok(), "nothing there is wiped");
    }

    /// The key protection shown in Settings follows the file's header.
    #[test]
    fn stored_key_protection_reports_the_binding_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(stored_key_protection(dir.path()), "none");

        save_with(&ThroughKeystore(with_keyring()), dir.path(), &sample_creds()).unwrap();
        assert_eq!(stored_key_protection(dir.path()), "keyring");

        // Machine-bound: shown as such where that key is used; on Windows,
        // where such a file is refused at load, as unknown.
        let bound = tempfile::tempdir().unwrap();
        save_with(&ThroughKeystore(without_keyring()), bound.path(), &sample_creds()).unwrap();
        let want = if keystore::MACHINE_BOUND_FALLBACK { "machine" } else { "unknown" };
        assert_eq!(stored_key_protection(bound.path()), want);

        let garbage = tempfile::tempdir().unwrap();
        fs::write(garbage.path().join(CREDENTIAL_FILE), b"not json").unwrap();
        assert_eq!(stored_key_protection(garbage.path()), "unknown");

        let future = tempfile::tempdir().unwrap();
        fs::write(
            future.path().join(CREDENTIAL_FILE),
            br#"{"version":99,"binding":"keyring","nonce":[],"ciphertext":[]}"#,
        )
        .unwrap();
        assert_eq!(stored_key_protection(future.path()), "unknown", "unsupported version");
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

    /// Windows: a save makes the folder and the file private to the user.
    #[cfg(windows)]
    #[test]
    fn windows_save_makes_folder_and_file_user_only() {
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        let keys = ThroughKeystore(with_keyring());
        save_with(&keys, &config_dir, &sample_creds()).expect("save");
        assert!(super::super::winacl::test_is_user_only(&config_dir), "folder");
        assert!(super::super::winacl::test_is_user_only(&config_dir.join(CREDENTIAL_FILE)), "file");
        // A second save over the private file works.
        save_with(&keys, &config_dir, &sample_creds()).expect("second save");
    }

    /// Windows: a folder another account can open is refused, and nothing
    /// is written into it.
    #[cfg(windows)]
    #[test]
    fn windows_save_refuses_a_shared_folder() {
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        fs::create_dir(&config_dir).unwrap();
        super::super::winacl::test_share_with_everyone(&config_dir);
        let err = save_with(&ThroughKeystore(with_keyring()), &config_dir, &sample_creds())
            .err()
            .expect("save must fail");
        assert!(matches!(err, CredentialError::NotPrivate), "got {err}");
        assert_eq!(err.to_string(), NOT_PRIVATE_NOTICE);
        assert!(!config_dir.join(CREDENTIAL_FILE).exists(), "nothing may be written");
    }

    /// Windows: an existing file another account can open is refused
    /// before it is truncated.
    #[cfg(windows)]
    #[test]
    fn windows_save_refuses_a_shared_file_and_keeps_it() {
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        let keys = ThroughKeystore(with_keyring());
        save_with(&keys, &config_dir, &sample_creds()).expect("save");
        let file = config_dir.join(CREDENTIAL_FILE);
        let before = fs::read(&file).unwrap();
        super::super::winacl::test_share_with_everyone(&file);
        let err = save_with(&keys, &config_dir, &sample_creds()).err().expect("save must fail");
        assert!(matches!(err, CredentialError::NotPrivate), "got {err}");
        assert_eq!(fs::read(&file).unwrap(), before, "not truncated");
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
