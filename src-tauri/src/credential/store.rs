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

/// Marks the saved pairing's session as live (#26). A session is treated
/// as live only while this file holds the tag of the saved session id: it
/// is written, privately, with a pairing or session that has an expiry,
/// and removed when the session ends. Removing a file works where a save
/// is refused (a folder that isn't private, an unreachable keyring), so a
/// session ended in that state isn't reloaded as live from the expiry the
/// refused save couldn't clear. No key is needed to read or remove it.
const SESSION_LIVE_FILE: &str = "session.live";

/// Subdirectory name appended to the OS config dir.
const CONFIG_SUBDIR: &str = "vettid-desktop";

/// XChaCha20-Poly1305 nonce size (24 bytes).
const NONCE_SIZE: usize = 24;

/// What the person is told when a saved pairing can't be opened. Shown
/// as is, so it must stay plain: no error codes, no crypto terms.
pub const UNREADABLE_NOTICE: &str =
    "This desktop's saved pairing can't be opened. Remove this desktop on your phone, then pair again.";

/// Shown when a pairing saved by an earlier build was found and deleted,
/// and `device.revoke` was sent with its credentials (#15). The vault
/// doesn't acknowledge a revoke, so this says only that it was asked.
pub const OLD_BUILD_REVOKED_NOTICE: &str =
    "This desktop's saved pairing was made by an earlier version and can't be used, so it was deleted, and this desktop asked your vault to remove it. Check on your phone that this desktop is gone, then pair again.";

/// Shown when the pairing can't be saved because the system keyring
/// (Credential Manager on Windows) can't be reached and a weaker key is
/// not allowed. Nothing on disk has changed. At pairing, the vault may
/// already list the desktop, hence the phone step.
pub const KEYRING_UNAVAILABLE_NOTICE: &str =
    "This desktop can't reach your computer's keyring, so it couldn't save the pairing safely, and nothing was saved. If your phone lists this desktop, remove it there. Then sign out of your computer and back in, and pair again.";

/// Shown when this computer has no usable machine id (#14): the saved
/// pairing is bound to it, so without one nothing can be kept or opened,
/// keyring or not. Checked before pairing starts and at unlock.
pub const NO_MACHINE_ID_NOTICE: &str =
    "This computer has no machine id, so this desktop can't keep or open a saved pairing on it. If your phone lists this desktop, remove it there.";

/// Shown after End session when this desktop couldn't record on disk that
/// the session ended (#26): the live marker couldn't be removed, so the
/// next launch may show the old session as open.
pub const SESSION_END_NOT_RECORDED_NOTICE: &str =
    "The session ended, but this desktop couldn't record that on this computer, so next time it may show the old session as still open. If it does, end the session again.";

/// Shown when a pairing or Start New Session got a session from the vault
/// but couldn't record it on this computer (#33, owner decision (a),
/// 2026-11-01). The pairing itself is saved, so pairing again would only
/// leave a stale device on the phone.
pub const SESSION_NOT_RECORDED_NOTICE: &str =
    "This desktop is paired, but it couldn't record the new session on this computer. Choose Start New Session to try again. You don't need to pair again.";

/// Windows: shown when the folder that holds the pairing folder
/// (`%LOCALAPPDATA%`) lets another account remove, rename or replace what
/// is in it, or is owned by another account or is a link (#21). Deleting
/// the pairing folder wouldn't help, so this says who has to act.
pub const PARENT_NOT_PRIVATE_NOTICE: &str =
    "The folder this desktop keeps its pairing in is inside a folder (your local app data) that another account on this computer can change, so nothing was saved. Whoever manages this computer needs to fix that folder's permissions.";

/// Windows: shown when `%LOCALAPPDATA%` itself is a symlink or junction
/// (#21), e.g. moved to another drive with `mklink /J`. It could be
/// pointed elsewhere after the check, so nothing is kept there.
pub const PARENT_IS_LINK_NOTICE: &str =
    "This desktop can't keep its pairing on this computer because your local app data folder is a link to another place, so nothing was saved.";

/// Shown when this desktop was logged out while a pairing or a Start New
/// Session was under way, so what it got from the vault wasn't saved (#30,
/// owner decision (a), 2026-11-02). The vault may still list the desktop.
pub const LOGGED_OUT_MEANWHILE_NOTICE: &str =
    "This desktop was logged out while it was connecting to your vault, so nothing was saved. If your phone still lists this desktop, remove it there.";

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
    /// From [`load`] only: the file was sealed by an earlier build under the
    /// public fingerprint, and its deletion was attempted; `deleted` is
    /// true only if the file system confirms it gone. It carries the
    /// credentials it held, so the caller can send `device.revoke` with
    /// them (#15): use `registration::pairing::load_saved`, which does.
    /// Displays [`UNREADABLE_NOTICE`].
    OldBuildPairing { creds: OldBuildCredentials, deleted: bool },
    /// An earlier build's pairing was found (#15): `revoke_sent` says
    /// whether `device.revoke` was sent with it, `deleted` whether it is
    /// confirmed gone. Displays [`OLD_BUILD_REVOKED_NOTICE`] only if both
    /// are true, else [`UNREADABLE_NOTICE`], which claims neither. A file
    /// that is still there is found, and revoked, again at the next load.
    OldBuildRemoved { revoke_sent: bool, deleted: bool },
    /// The keyring failed and the save may not fall back to the
    /// machine-bound key: on Windows, or because the store on disk is
    /// keyring-bound. Nothing was written. Displays
    /// [`KEYRING_UNAVAILABLE_NOTICE`].
    KeyringUnavailable,
    /// The platform's per-user folder is unknown or not absolute, so
    /// there is nowhere safe to keep a pairing. Displays
    /// [`NO_CONFIG_DIR_NOTICE`].
    NoConfigDir,
    /// Windows: the folder that holds the pairing folder lets another
    /// account change what is in it (#21). Nothing was changed. Displays
    /// [`PARENT_NOT_PRIVATE_NOTICE`].
    ParentNotPrivate,
    /// Windows: `%LOCALAPPDATA%` is a symlink or junction (#21). Nothing
    /// was changed. Displays [`PARENT_IS_LINK_NOTICE`].
    ParentIsLink,
    /// This computer has no usable machine id, which the saved pairing is
    /// bound to (#14). Nothing was saved or opened. Displays
    /// [`NO_MACHINE_ID_NOTICE`].
    NoMachineId,
    /// The folder or file for the pairing is not private to the current
    /// user. Windows: another account owns it or can open it, or it is a
    /// symlink or junction. Unix: another account owns the folder or can
    /// write to it. Nothing was changed. Displays [`NOT_PRIVATE_NOTICE`].
    NotPrivate,
    /// A log-out wiped the pairing after the save's command started (#30).
    /// Nothing was written. Displays [`LOGGED_OUT_MEANWHILE_NOTICE`].
    LoggedOutMeanwhile,
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
            CredentialError::OldBuildPairing { .. } => f.write_str(UNREADABLE_NOTICE),
            CredentialError::OldBuildRemoved { revoke_sent: true, deleted: true } => {
                f.write_str(OLD_BUILD_REVOKED_NOTICE)
            }
            CredentialError::OldBuildRemoved { .. } => f.write_str(UNREADABLE_NOTICE),
            CredentialError::KeyringUnavailable => f.write_str(KEYRING_UNAVAILABLE_NOTICE),
            CredentialError::NoConfigDir => f.write_str(NO_CONFIG_DIR_NOTICE),
            CredentialError::NoMachineId => f.write_str(NO_MACHINE_ID_NOTICE),
            CredentialError::ParentNotPrivate => f.write_str(PARENT_NOT_PRIVATE_NOTICE),
            CredentialError::ParentIsLink => f.write_str(PARENT_IS_LINK_NOTICE),
            CredentialError::NotPrivate => f.write_str(NOT_PRIVATE_NOTICE),
            CredentialError::LoggedOutMeanwhile => f.write_str(LOGGED_OUT_MEANWHILE_NOTICE),
        }
    }
}

impl std::error::Error for CredentialError {}

/// The credentials of an earlier build's pairing, carried out of [`load`]
/// so `device.revoke` can be sent with them (#15). Its `Debug` shows
/// nothing of them, so an error logged with `{:?}` leaks no key. They are
/// zeroized when dropped, as all `ConnectionCredentials` are. The field is
/// private, so they can't be printed through it by mistake either.
pub struct OldBuildCredentials(Box<ConnectionCredentials>);

impl OldBuildCredentials {
    pub(crate) fn new(creds: Box<ConnectionCredentials>) -> Self {
        Self(creds)
    }

    /// The credentials, for the revoke.
    pub(crate) fn into_inner(self) -> Box<ConnectionCredentials> {
        self.0
    }
}

impl fmt::Debug for OldBuildCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OldBuildCredentials(..)")
    }
}

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
    use super::winacl::{AclError, NotPrivate};
    log::error!("Credential store: {} {}; refusing to use it", path.display(), e);
    match e {
        AclError::NotPrivate(NotPrivate::ParentLink) => CredentialError::ParentIsLink,
        AclError::NotPrivate(why) if why.is_about_the_parent() => CredentialError::ParentNotPrivate,
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
///
/// `since` is [`wipe_epoch`] as recorded when the command that saves
/// started (a pairing, a Start New Session). If a log-out has wiped the
/// pairing since, the save fails with [`CredentialError::LoggedOutMeanwhile`]
/// and writes nothing: it must not recreate a pairing the log-out reported
/// removed (#30).
pub fn save(
    config_dir: &Path,
    creds: &ConnectionCredentials,
    since: WipeEpoch,
) -> Result<BindingMode, CredentialError> {
    save_since(&SystemKeys, config_dir, creds, Mode::CreateOrReplace, Some(since))
}

/// Like [`save`], for updating a pairing that is already saved (clearing
/// the session at end_session). Fails with [`CredentialError::NotFound`],
/// writing nothing and creating no folder, if `connection.enc` isn't there
/// when the write lock is taken: a log-out that wiped the pairing must not
/// be undone by an update that loaded it just before (#28). It fails with
/// [`CredentialError::LoggedOutMeanwhile`] if a log-out wiped the pairing
/// after `since`, even if a new pairing has been saved since: the update
/// carries the old pairing's credentials and must not overwrite the new one
/// (#30).
pub fn save_existing(
    config_dir: &Path,
    creds: &ConnectionCredentials,
    since: WipeEpoch,
) -> Result<BindingMode, CredentialError> {
    save_since(&SystemKeys, config_dir, creds, Mode::UpdateExisting, Some(since))
}

/// [`ensure_config_dir`] for the start of a pairing (#30): under the writer
/// lock, and refused with [`CredentialError::LoggedOutMeanwhile`] if a
/// log-out has wiped the pairing since `since`, so it can't recreate the
/// folder after a log-out's wipe.
pub fn ensure_config_dir_since(config_dir: &Path, since: WipeEpoch) -> Result<(), CredentialError> {
    let _one_at_a_time = writer_lock();
    if wipe_epoch() != since {
        return Err(CredentialError::LoggedOutMeanwhile);
    }
    ensure_config_dir(config_dir)
}

/// How many wipes this process has run (#30). Bumped by every wipe while
/// it holds the writer lock, before it removes anything; compared by a
/// save while it holds the lock, before it writes anything. So a save
/// whose command started before a wipe began can't write after it.
static WIPES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A point in this process's wipes, from [`wipe_epoch`]. A command that
/// saves records it when it starts and hands it to [`save`] or
/// [`save_existing`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WipeEpoch(u64);

/// The current [`WipeEpoch`]. Record it at the start of the command that
/// will save, before anything that could wait.
pub fn wipe_epoch() -> WipeEpoch {
    WipeEpoch(WIPES.load(std::sync::atomic::Ordering::SeqCst))
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
    fn storage_binding(&self) -> Result<Zeroizing<[u8; 32]>, FingerprintError>;
    /// The public machine fingerprint. Only used to recognize a file a
    /// pre-#10 build sealed with the fingerprint as both its key and its
    /// AAD value, so it can be deleted.
    fn legacy_fingerprint(&self) -> Result<Zeroizing<[u8; 32]>, FingerprintError>;
}

/// The storage binding's failure as the store reports it: no machine id
/// gets its own plain notice.
fn binding_error(e: FingerprintError) -> CredentialError {
    match e {
        FingerprintError::MissingMachineId => CredentialError::NoMachineId,
        e => CredentialError::FingerprintError(e),
    }
}

/// Whether this computer can keep a pairing at all: it needs a machine id
/// for the storage binding (#14). Called before pairing starts, so the
/// vault never lists a desktop that can't save its pairing.
pub fn check_machine_binding() -> Result<(), CredentialError> {
    SystemKeys.storage_binding().map(|_| ()).map_err(binding_error)
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
    fn storage_binding(&self) -> Result<Zeroizing<[u8; 32]>, FingerprintError> {
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
    let platform_key = keys.storage_binding().map_err(binding_error)?;
    let master = keys.master_for_load(binding)?;
    match decrypt_store(&store, &master.key, &platform_key) {
        Ok(mut creds) => {
            // #26: the expiry counts only while the live marker names this
            // session. Only the expiry is cleared; nothing reads the id of
            // a session that isn't live.
            if creds.session_expires_at != 0 && !session_marked_live(config_dir, &creds.session_id) {
                log::info!("credential store: the saved session is not marked live; treating it as ended");
                creds.session_expires_at = 0;
                creds.session_duration_seconds = 0;
            }
            Ok((creds, binding))
        }
        Err(CredentialError::CryptoError(e)) if binding == BindingMode::MachineBound => {
            // Delete the file only when it is positively one written by an
            // earlier build, which used the public fingerprint as its key.
            // Any other failure is kept: a file sealed before #14 (key and
            // AAD over all five attributes), or a machine id that changed
            // and may change back. Pairing again or "Remove this desktop"
            // replaces it.
            let old_build = keys
                .legacy_fingerprint()
                .ok()
                .and_then(|fp| decrypt_store(&store, &fp, &fp).ok());
            if let Some(old) = old_build {
                log::warn!(
                    "credential store: machine-bound file was sealed under the public fingerprint by an earlier build; deleting it"
                );
                if let Err(de) = delete(config_dir) {
                    log::error!("credential store: could not delete the old file: {}", de);
                }
                // #15: only what the file system confirms counts as deleted.
                let deleted = matches!(pairing_present(config_dir), Ok(false));
                // Its credentials go to the caller, for the revoke.
                return Err(CredentialError::OldBuildPairing {
                    creds: OldBuildCredentials::new(Box::new(old)),
                    deleted,
                });
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

/// A save with no log-out check, for tests that don't concern log-out.
#[cfg(test)]
fn save_with(
    keys: &dyn KeySource,
    config_dir: &Path,
    creds: &ConnectionCredentials,
) -> Result<BindingMode, CredentialError> {
    save_with_mode(keys, config_dir, creds, Mode::CreateOrReplace)
}

#[cfg(test)]
fn save_with_mode(
    keys: &dyn KeySource,
    config_dir: &Path,
    creds: &ConnectionCredentials,
    mode: Mode,
) -> Result<BindingMode, CredentialError> {
    save_since(keys, config_dir, creds, mode, None)
}

/// A save, refused if a wipe has run since `since` (#30). `None` only in
/// tests that don't concern log-out.
fn save_since(
    keys: &dyn KeySource,
    config_dir: &Path,
    creds: &ConnectionCredentials,
    mode: Mode,
    since: Option<WipeEpoch>,
) -> Result<BindingMode, CredentialError> {
    let _one_at_a_time = writer_lock();
    if let Some(since) = since {
        if wipe_epoch() != since {
            log::warn!("Credential store: a log-out wiped the pairing after this save's command started; nothing written");
            return Err(CredentialError::LoggedOutMeanwhile);
        }
    }
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

    // The storage binding first: without a machine id nothing can be
    // saved, and no keyring key should be created for it (#14).
    let platform_key = keys.storage_binding().map_err(binding_error)?;
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

    write_private(config_dir, CREDENTIAL_FILE, &data)?;

    // #26: the session is live only with the marker. If it can't be
    // written the pairing is still saved, and the session is treated as
    // ended: the person starts a new one.
    if creds.session_expires_at > 0 && !creds.session_id.is_empty() {
        if let Err(e) = write_private(config_dir, SESSION_LIVE_FILE, session_tag(&creds.session_id).as_bytes()) {
            log::warn!("credential store: could not mark the session live ({}); it will be treated as ended", e);
            remove_session_marker(config_dir);
        }
    } else {
        remove_session_marker(config_dir);
    }

    Ok(binding)
}

/// Write `data` as `config_dir/name`, privately and atomically.
///
/// SECURITY: written to a new temporary file in the same folder, then
/// moved over `name`, so a crash or a full disk leaves the old file whole
/// (#12). On Windows the temporary file is created with the user-only
/// DACL, inside the folder held open (#16, #23).
fn write_private(config_dir: &Path, name: &str, data: &[u8]) -> Result<(), CredentialError> {
    #[cfg(windows)]
    {
        super::winacl::write_private_file(config_dir, name, data).map_err(|e| acl_error(&config_dir.join(name), e))
    }
    #[cfg(not(windows))]
    {
        write_atomically(config_dir, name, data)
    }
}

/// The live marker's content for `session_id`: a hash, so the id itself
/// isn't written outside the encrypted pairing.
fn session_tag(session_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"vettid-desktop-session-live-v1|");
    h.update(session_id.as_bytes());
    hex::encode(h.finalize())
}

/// Whether the live marker names `session_id`. Anything else is "not
/// live": no marker, another session's, an unreadable one, a link or a
/// folder in its place, one larger than a tag, and on Windows one that
/// another account can open (a shared folder lets another account plant
/// or restore it). A copy restored by an account that can write the
/// folder can't be told apart without a key; the warning after unlock
/// already covers that folder.
fn session_marked_live(config_dir: &Path, session_id: &str) -> bool {
    use std::io::Read;
    const MAX_MARKER: u64 = 128;
    if session_id.is_empty() {
        return false;
    }
    let path = config_dir.join(SESSION_LIVE_FILE);
    match fs::symlink_metadata(&path) {
        Ok(m) if m.file_type().is_file() && m.len() <= MAX_MARKER => {}
        _ => return false,
    }
    #[cfg(windows)]
    if super::winacl::check_private(&path).is_err() {
        return false;
    }
    let mut tag = String::new();
    match fs::File::open(&path).and_then(|f| f.take(MAX_MARKER).read_to_string(&mut tag)) {
        Ok(_) => tag.trim() == session_tag(session_id),
        Err(_) => false,
    }
}

/// Whether the saved session `session_id` is recorded as live (#26). A
/// pairing or extension checks this after its save, so it never reports
/// a session as started that the next load would treat as ended.
pub fn session_is_recorded(config_dir: &Path, session_id: &str) -> bool {
    session_marked_live(config_dir, session_id)
}

/// Best-effort removal of the live marker, for paths that report nothing.
fn remove_session_marker(config_dir: &Path) {
    let _ = fs::remove_file(config_dir.join(SESSION_LIVE_FILE));
}

/// End the saved session on disk (#26): remove the live marker, so the
/// next launch treats the session as ended even if the cleared session
/// can't be saved. Ok only if the marker is confirmed gone; the caller
/// tells the person otherwise ([`SESSION_END_NOT_RECORDED_NOTICE`]).
pub fn end_saved_session(config_dir: &Path) -> Result<(), CredentialError> {
    end_saved_session_locked(config_dir, &writer_lock())
}

/// Like [`end_saved_session`], for End session (#30): if a log-out has
/// wiped the pairing since `since`, it fails with
/// [`CredentialError::LoggedOutMeanwhile`] and removes nothing, since the
/// marker there now may belong to a pairing made after that log-out.
/// End a session the vault ended (#45): remove the live marker only if it
/// still names `session_id`, under the writer lock, so a marker written
/// since for another session (a Start New Session, a new pairing) is left
/// alone. The pairing itself is never touched. `Ok(true)` if the marker
/// was removed and is confirmed gone, `Ok(false)` if it named another
/// session or none.
pub fn end_saved_session_if(config_dir: &Path, session_id: &str) -> Result<bool, CredentialError> {
    let guard = writer_lock();
    if !session_marked_live(config_dir, session_id) {
        return Ok(false);
    }
    end_saved_session_locked(config_dir, &guard).map(|()| true)
}

pub fn end_saved_session_since(config_dir: &Path, since: WipeEpoch) -> Result<(), CredentialError> {
    let guard = writer_lock();
    if wipe_epoch() != since {
        return Err(CredentialError::LoggedOutMeanwhile);
    }
    end_saved_session_locked(config_dir, &guard)
}

fn end_saved_session_locked(
    config_dir: &Path,
    _one_at_a_time: &std::sync::MutexGuard<'static, ()>,
) -> Result<(), CredentialError> {
    let path = config_dir.join(SESSION_LIVE_FILE);
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(CredentialError::IoError(format!("remove {}: {}", path.display(), e))),
    }
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(CredentialError::IoError(format!("{} is still there", path.display()))),
        Err(e) => Err(CredentialError::IoError(format!("check {}: {}", path.display(), e))),
    }
}

/// Unix: write `data` as `config_dir/name` through a new `0600` temporary
/// file in the same folder: write, fsync, rename over the old file, fsync
/// the folder. A failure before the rename keeps the old file and removes
/// the temporary one. Renaming also means a file whose mode was widened
/// is replaced by a `0600` one.
#[cfg(not(windows))]
fn write_atomically(config_dir: &Path, name: &str, data: &[u8]) -> Result<(), CredentialError> {
    let path = config_dir.join(name);
    let io = |what: &str, e: std::io::Error| CredentialError::IoError(format!("{} {}: {}", what, path.display(), e));

    // Temporary files a crashed earlier save left behind.
    let prefix = format!("{name}{TEMP_INFIX}");
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

/// Delete the credential file from `config_dir`. Used only by [`load`] for
/// an earlier build's file; it isn't a log-out, so it doesn't move the
/// wipe count (#30). The app logs out through [`wipe_for_logout`].
fn delete(config_dir: &Path) -> Result<(), CredentialError> {
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
///
/// Every save whose command started before this is refused afterwards,
/// even if this fails (#30). The app wipes through [`wipe_for_logout`].
#[cfg(test)]
pub(crate) fn wipe(config_dir: &Path) -> Result<(), CredentialError> {
    let _one_at_a_time = writer_lock();
    WIPES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    wipe_locked(config_dir)
}

/// Log-out's local half (#30): as [`wipe`] when the folder is known, then,
/// still holding the writer lock, delete the keyring key. A save can't run
/// between the two, so none is sealed under a key that is then deleted.
/// The key is deleted even if the wipe fails or there is no folder. Ok
/// only if the pairing is confirmed gone; with no folder, `NoConfigDir`.
pub fn wipe_for_logout(config_dir: Option<&Path>) -> Result<(), CredentialError> {
    wipe_then(config_dir, super::keystore::delete_keyring_key)
}

fn wipe_then(config_dir: Option<&Path>, delete_key: impl FnOnce()) -> Result<(), CredentialError> {
    let _one_at_a_time = writer_lock();
    WIPES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let wiped = match config_dir {
        Some(dir) => wipe_locked(dir),
        None => Err(CredentialError::NoConfigDir),
    };
    delete_key();
    wiped
}

/// [`wipe`]'s work; the caller holds the writer lock.
fn wipe_locked(config_dir: &Path) -> Result<(), CredentialError> {
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
    remove_session_marker(config_dir);
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

/// The notice for a session extension refused because the folder or file
/// isn't private (#26). Pairing again into the same folder wouldn't help,
/// so it points at Log out, as the warnings after unlock do (#24, #28):
/// on Windows worded for how the pairing is sealed, on unix the folder
/// notice (the only refusal there is the folder's owner).
pub fn not_private_extension_notice(config_dir: &Path) -> &'static str {
    #[cfg(unix)]
    {
        let _ = config_dir;
        NOT_PRIVATE_FOLDER_NOTICE
    }
    #[cfg(not(unix))]
    {
        match on_disk_store(config_dir) {
            OnDisk::Bound(BindingMode::MachineBound) => NOT_PRIVATE_MACHINE_NOTICE,
            _ => NOT_PRIVATE_KEYRING_NOTICE,
        }
    }
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
pub(crate) mod tests {
    use super::*;

    /// For tests elsewhere in the crate (#15): an earlier build's pairing
    /// (`sample_creds`, sealed under the public fingerprint) in `dir`.
    /// It names the legacy message server, as such pairings did.
    /// For tests elsewhere in the crate (#45): a pairing in `dir` whose
    /// session `session_id` is marked live.
    pub(crate) fn save_pairing_with_live_session(dir: &Path, session_id: &str) {
        let keys = FixedKeys { binding: BindingMode::Keyring, master: [0x44; 32], platform: PLATFORM };
        save_with(&keys, dir, &creds_with_session(session_id, 1_900_000_000)).expect("save");
        assert!(session_is_recorded(dir, session_id));
    }

    /// #45: a vault-ended session's marker goes only if it still names
    /// that session; the pairing stays either way.
    #[test]
    fn a_vault_ended_sessions_marker_goes_only_if_it_names_it() {
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        save_pairing_with_live_session(&config_dir, "s2");
        assert_eq!(end_saved_session_if(&config_dir, "s1").unwrap(), false, "another session's marker");
        assert!(session_is_recorded(&config_dir, "s2"));
        assert_eq!(end_saved_session_if(&config_dir, "s2").unwrap(), true);
        assert!(!session_is_recorded(&config_dir, "s2"));
        assert!(exists(&config_dir), "the pairing stays");
        assert_eq!(end_saved_session_if(&config_dir, "s2").unwrap(), false, "already gone");
        let none = base.path().join("absent");
        assert_eq!(end_saved_session_if(&none, "s2").unwrap(), false, "no folder");
    }

    pub(crate) fn save_old_build_pairing(dir: &Path) {
        let old_build = FixedKeys { binding: BindingMode::MachineBound, master: FINGERPRINT, platform: FINGERPRINT };
        let mut creds = sample_creds();
        creds.message_space_url = "tls://nats.vettid.dev:443".into();
        save_with(&old_build, dir, &creds).expect("save");
    }

    /// For tests elsewhere in the crate (#15): `load` as this build, with
    /// fixed keys.
    pub(crate) fn load_as_this_build(dir: &Path) -> Result<(ConnectionCredentials, BindingMode), CredentialError> {
        load_with(&FixedKeys { binding: BindingMode::MachineBound, master: BOUND_KEY, platform: PLATFORM }, dir)
    }

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
        fn storage_binding(&self) -> Result<Zeroizing<[u8; 32]>, FingerprintError> {
            Ok(Zeroizing::new(self.platform))
        }
        fn legacy_fingerprint(&self) -> Result<Zeroizing<[u8; 32]>, FingerprintError> {
            Ok(Zeroizing::new(FINGERPRINT))
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

    /// This build's storage binding (the AAD value).
    const PLATFORM: [u8; 32] = [0x11; 32];
    /// This build's machine-bound key.
    const BOUND_KEY: [u8; 32] = [0x22; 32];
    /// The public five-attribute fingerprint: never the binding or a key
    /// in this build, as in production.
    const FINGERPRINT: [u8; 32] = [0x99; 32];

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
    /// Its credentials come back with the error, for the revoke (#15), and
    /// don't show in its `Debug`.
    #[test]
    fn blob_sealed_under_the_fingerprint_is_unreadable_and_deleted() {
        let dir = tempfile::tempdir().unwrap();
        // Pre-#10: the public fingerprint as the key and in the AAD. Not
        // this build's storage binding (PLATFORM), as in production.
        let old_build = FixedKeys { binding: BindingMode::MachineBound, master: FINGERPRINT, platform: FINGERPRINT };
        save_with(&old_build, dir.path(), &sample_creds()).expect("save");

        let this_build = FixedKeys { binding: BindingMode::MachineBound, master: BOUND_KEY, platform: PLATFORM };
        let err = load_with(&this_build, dir.path()).err().expect("must not load");
        assert_eq!(err.to_string(), UNREADABLE_NOTICE);
        assert!(!err.to_string().contains("decrypt"));
        assert!(!exists(dir.path()), "the unreadable file must be deleted");
        let debug = format!("{err:?}");
        match err {
            CredentialError::OldBuildPairing { creds, deleted } => {
                assert!(deleted);
                let old = creds.into_inner();
                let want = sample_creds();
                assert_eq!(old.connection_id, want.connection_id);
                assert_eq!(old.message_space_token, want.message_space_token);
                assert_eq!(old.owner_guid, want.owner_guid);
                assert!(!debug.contains(&want.connection_id), "{debug}");
                assert!(!debug.contains(&want.message_space_token), "{debug}");
            }
            other => panic!("got {other:?}"),
        }
    }

    /// #15: an earlier build's file that can't be deleted (held open for
    /// reading without delete sharing, as antivirus may) is reported as not
    /// deleted, and is still there.
    #[cfg(windows)]
    #[test]
    fn an_old_build_file_that_cant_be_deleted_says_so() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = tempfile::tempdir().unwrap();
        let old_build = FixedKeys { binding: BindingMode::MachineBound, master: FINGERPRINT, platform: FINGERPRINT };
        save_with(&old_build, dir.path(), &sample_creds()).expect("save");
        let held = fs::OpenOptions::new().read(true).share_mode(0x1).open(dir.path().join(CREDENTIAL_FILE)).unwrap(); // FILE_SHARE_READ only
        let this_build = FixedKeys { binding: BindingMode::MachineBound, master: BOUND_KEY, platform: PLATFORM };
        let err = load_with(&this_build, dir.path()).err().expect("must not load");
        drop(held);
        assert!(matches!(err, CredentialError::OldBuildPairing { deleted: false, .. }), "got {err:?}");
        assert!(exists(dir.path()));
    }

    /// #15: the notice says the pairing was deleted and the vault asked
    /// only if both happened; otherwise it claims neither.
    #[test]
    fn old_build_notice_follows_the_revoke_and_the_delete() {
        for (revoke_sent, deleted, want) in [
            (true, true, OLD_BUILD_REVOKED_NOTICE),
            (true, false, UNREADABLE_NOTICE),
            (false, true, UNREADABLE_NOTICE),
            (false, false, UNREADABLE_NOTICE),
        ] {
            assert_eq!(CredentialError::OldBuildRemoved { revoke_sent, deleted }.to_string(), want);
        }
    }

    /// The machine id changed (since #14 the only input): the machine-bound
    /// key and the storage binding both differ. The pairing is unreadable
    /// for now but must not be deleted, since the id may change back, and
    /// then it opens again.
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

    /// Only the AAD differs (same master key, different storage binding):
    /// also kept.
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

    fn creds_with_session(session_id: &str, expires_at: i64) -> ConnectionCredentials {
        let mut c = sample_creds();
        c.session_id = session_id.to_string();
        c.session_expires_at = expires_at;
        c.session_duration_seconds = 3600;
        c
    }

    /// #26: a saved session with an expiry is live only with the marker.
    /// Ending it removes the marker, and the next load treats it as ended
    /// even though the expiry is still in the file, as after a refused
    /// save. The session id is kept for telling the vault.
    #[test]
    fn an_ended_session_is_not_reloaded_as_live() {
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        let keys = FixedKeys { binding: BindingMode::Keyring, master: [0x44; 32], platform: PLATFORM };
        save_with(&keys, &config_dir, &creds_with_session("sess-1", 1_900_000_000)).unwrap();
        let (live, _) = load_with(&keys, &config_dir).unwrap();
        assert_eq!(live.session_expires_at, 1_900_000_000, "marked live");

        end_saved_session(&config_dir).expect("ended");
        assert!(!config_dir.join(SESSION_LIVE_FILE).exists());
        let (ended, _) = load_with(&keys, &config_dir).unwrap();
        assert_eq!(ended.session_expires_at, 0, "not live without the marker");
        assert_eq!(ended.session_duration_seconds, 0);
        assert_eq!(ended.session_id, "sess-1", "kept for the vault");
        assert!(end_saved_session(&config_dir).is_ok(), "ending twice is fine");
    }

    /// #26: the marker names one session. A marker for another session,
    /// or one that can't be parsed, is not live; a new session's save
    /// replaces it; a save with the session cleared removes it.
    #[test]
    fn the_live_marker_names_one_session() {
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        let keys = FixedKeys { binding: BindingMode::Keyring, master: [0x44; 32], platform: PLATFORM };
        save_with(&keys, &config_dir, &creds_with_session("sess-1", 1_900_000_000)).unwrap();
        let marker = fs::read_to_string(config_dir.join(SESSION_LIVE_FILE)).unwrap();
        assert!(!marker.contains("sess-1"), "the id itself is not written");

        fs::write(config_dir.join(SESSION_LIVE_FILE), session_tag("sess-other")).unwrap();
        assert_eq!(load_with(&keys, &config_dir).unwrap().0.session_expires_at, 0);
        fs::write(config_dir.join(SESSION_LIVE_FILE), b"garbage").unwrap();
        assert_eq!(load_with(&keys, &config_dir).unwrap().0.session_expires_at, 0);

        save_with(&keys, &config_dir, &creds_with_session("sess-2", 1_900_000_001)).unwrap();
        assert_eq!(load_with(&keys, &config_dir).unwrap().0.session_expires_at, 1_900_000_001);

        save_with(&keys, &config_dir, &creds_with_session("sess-2", 0)).unwrap();
        assert!(!config_dir.join(SESSION_LIVE_FILE).exists(), "cleared session removes it");
        delete(&config_dir).unwrap();
        assert!(!config_dir.join(SESSION_LIVE_FILE).exists());
    }

    /// #26: a save that fails leaves the old marker as it was; a delete
    /// and a wipe remove it.
    #[test]
    fn a_failed_save_keeps_the_marker_and_wipe_removes_it() {
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        let keys = FixedKeys { binding: BindingMode::Keyring, master: [0x44; 32], platform: PLATFORM };
        save_with(&keys, &config_dir, &creds_with_session("sess-1", 1_900_000_000)).unwrap();
        let before = fs::read(config_dir.join(SESSION_LIVE_FILE)).unwrap();
        struct NoBinding;
        impl KeySource for NoBinding {
            fn master_for_save(&self) -> Result<MasterKey, KeystoreError> {
                unreachable!()
            }
            fn master_for_load(&self, _: BindingMode) -> Result<MasterKey, KeystoreError> {
                unreachable!()
            }
            fn storage_binding(&self) -> Result<Zeroizing<[u8; 32]>, FingerprintError> {
                Err(FingerprintError::MissingMachineId)
            }
            fn legacy_fingerprint(&self) -> Result<Zeroizing<[u8; 32]>, FingerprintError> {
                Ok(Zeroizing::new(FINGERPRINT))
            }
        }
        assert!(save_with(&NoBinding, &config_dir, &creds_with_session("sess-2", 1)).is_err());
        assert_eq!(fs::read(config_dir.join(SESSION_LIVE_FILE)).unwrap(), before, "unchanged");
        assert!(session_is_recorded(&config_dir, "sess-1"));

        wipe(&config_dir).unwrap();
        assert!(!config_dir.join(SESSION_LIVE_FILE).exists());
    }

    /// #26: only a small regular file counts as the marker.
    #[test]
    fn a_marker_that_is_a_folder_or_too_large_is_not_live() {
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        let keys = FixedKeys { binding: BindingMode::Keyring, master: [0x44; 32], platform: PLATFORM };
        save_with(&keys, &config_dir, &creds_with_session("sess-1", 1_900_000_000)).unwrap();
        let marker = config_dir.join(SESSION_LIVE_FILE);
        let mut big = session_tag("sess-1");
        big.push_str(&" ".repeat(200));
        fs::write(&marker, big).unwrap();
        assert!(!session_is_recorded(&config_dir, "sess-1"), "too large");
        fs::remove_file(&marker).unwrap();
        fs::create_dir(&marker).unwrap();
        assert!(!session_is_recorded(&config_dir, "sess-1"), "a folder");
        assert_eq!(load_with(&keys, &config_dir).unwrap().0.session_expires_at, 0);
    }

    /// Windows (#21): a save under a parent another account controls is
    /// refused with the parent notice, writes neither file, and leaves an
    /// existing pairing and its marker as they were.
    #[cfg(windows)]
    #[test]
    fn windows_a_save_under_an_unsafe_parent_changes_nothing() {
        let base = tempfile::tempdir().unwrap();
        let parent = base.path().join("local");
        let config_dir = parent.join("vettid-desktop");
        let keys = FixedKeys { binding: BindingMode::Keyring, master: [0x44; 32], platform: PLATFORM };
        save_with(&keys, &config_dir, &creds_with_session("sess-1", 1_900_000_000)).unwrap();
        let file = fs::read(config_dir.join(CREDENTIAL_FILE)).unwrap();
        let marker = fs::read(config_dir.join(SESSION_LIVE_FILE)).unwrap();
        super::super::winacl::test_let_everyone_delete_children(&parent);
        let err = save_with(&keys, &config_dir, &creds_with_session("sess-2", 1_900_000_001)).err().expect("refused");
        assert!(matches!(err, CredentialError::ParentNotPrivate), "got {err}");
        assert_eq!(err.to_string(), PARENT_NOT_PRIVATE_NOTICE);
        assert!(matches!(
            save_with_mode(&keys, &config_dir, &creds_with_session("sess-1", 0), Mode::UpdateExisting),
            Err(CredentialError::ParentNotPrivate)
        ));
        assert_eq!(fs::read(config_dir.join(CREDENTIAL_FILE)).unwrap(), file);
        assert_eq!(fs::read(config_dir.join(SESSION_LIVE_FILE)).unwrap(), marker);
    }

    /// Windows (#21): a parent that is a junction gives the link notice,
    /// not the "another account" one, and nothing is created through it.
    #[cfg(windows)]
    #[test]
    fn windows_a_linked_parent_gives_the_link_notice() {
        let base = tempfile::tempdir().unwrap();
        let real = base.path().join("real");
        fs::create_dir(&real).unwrap();
        let link = base.path().join("local");
        let out = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&real)
            .output()
            .expect("mklink");
        assert!(out.status.success(), "mklink /J failed");
        let keys = FixedKeys { binding: BindingMode::Keyring, master: [0x44; 32], platform: PLATFORM };
        let err = save_with(&keys, &link.join("vettid-desktop"), &sample_creds()).err().expect("refused");
        assert!(matches!(err, CredentialError::ParentIsLink), "got {err}");
        assert_eq!(err.to_string(), PARENT_IS_LINK_NOTICE);
        assert!(!real.join("vettid-desktop").exists());
    }

    /// Windows (#26): the case from the issue. The folder becomes shared,
    /// so the save that clears the session is refused, but ending the
    /// session still removes the marker, and the session isn't reloaded
    /// as live.
    #[cfg(windows)]
    #[test]
    fn windows_a_refused_save_still_ends_the_session() {
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        let keys = FixedKeys { binding: BindingMode::Keyring, master: [0x44; 32], platform: PLATFORM };
        save_with(&keys, &config_dir, &creds_with_session("sess-1", 1_900_000_000)).unwrap();
        super::super::winacl::test_share_with_everyone(&config_dir);
        assert!(matches!(
            save_with_mode(&keys, &config_dir, &creds_with_session("sess-1", 0), Mode::UpdateExisting),
            Err(CredentialError::NotPrivate)
        ));
        assert!(session_is_recorded(&config_dir, "sess-1"), "the refused save left it");
        end_saved_session(&config_dir).expect("the marker can still be removed");
        assert_eq!(load_with(&keys, &config_dir).unwrap().0.session_expires_at, 0);
        assert_eq!(not_private_extension_notice(&config_dir), NOT_PRIVATE_KEYRING_NOTICE);
    }

    /// #14: a machine-bound file saved before #14 (the v1 key over all five
    /// attributes, the fingerprint in the AAD) doesn't open, gets the plain
    /// notice and is kept. It is not taken for a pre-#10 file.
    #[test]
    fn machine_bound_file_from_before_14_is_unreadable_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        let v1 = FixedKeys { binding: BindingMode::MachineBound, master: [0x61; 32], platform: FINGERPRINT };
        save_with(&v1, dir.path(), &sample_creds()).expect("save");
        let now = FixedKeys { binding: BindingMode::MachineBound, master: BOUND_KEY, platform: PLATFORM };
        let err = load_with(&now, dir.path()).err().expect("must not load");
        assert!(matches!(err, CredentialError::Unreadable), "got {err}");
        assert!(exists(dir.path()), "kept");
    }

    /// #14: a keyring-bound file saved before #14 (the fingerprint in the
    /// AAD) doesn't open with the same keyring key, and is kept.
    #[test]
    fn keyring_file_from_before_14_does_not_open_and_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let before = FixedKeys { binding: BindingMode::Keyring, master: [0x44; 32], platform: FINGERPRINT };
        save_with(&before, dir.path(), &sample_creds()).expect("save");
        let now = FixedKeys { binding: BindingMode::Keyring, master: [0x44; 32], platform: PLATFORM };
        assert!(matches!(load_with(&now, dir.path()), Err(CredentialError::CryptoError(_))));
        assert!(exists(dir.path()), "kept");
    }

    /// #14: without a machine id there is no storage binding: a save fails
    /// with the plain notice before any key is fetched, writing nothing and
    /// creating no folder; a load fails the same way and keeps the file.
    #[test]
    fn no_machine_id_saves_nothing_and_opens_nothing() {
        struct NoMachineId(std::cell::Cell<bool>);
        impl KeySource for NoMachineId {
            fn master_for_save(&self) -> Result<MasterKey, KeystoreError> {
                self.0.set(true);
                Ok(MasterKey { key: Zeroizing::new([0x44; 32]), binding: BindingMode::Keyring })
            }
            fn master_for_load(&self, _: BindingMode) -> Result<MasterKey, KeystoreError> {
                self.0.set(true);
                Ok(MasterKey { key: Zeroizing::new([0x44; 32]), binding: BindingMode::Keyring })
            }
            fn storage_binding(&self) -> Result<Zeroizing<[u8; 32]>, FingerprintError> {
                Err(FingerprintError::MissingMachineId)
            }
            fn legacy_fingerprint(&self) -> Result<Zeroizing<[u8; 32]>, FingerprintError> {
                Ok(Zeroizing::new(FINGERPRINT))
            }
        }
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        let keys = NoMachineId(std::cell::Cell::new(false));
        let err = save_with(&keys, &config_dir, &sample_creds()).err().expect("must fail");
        assert!(matches!(err, CredentialError::NoMachineId), "got {err}");
        assert_eq!(err.to_string(), NO_MACHINE_ID_NOTICE);
        assert!(!keys.0.get(), "no key fetched or created");
        assert!(!config_dir.exists(), "nothing written");

        let saved = FixedKeys { binding: BindingMode::Keyring, master: [0x44; 32], platform: PLATFORM };
        save_with(&saved, &config_dir, &sample_creds()).unwrap();
        let err = load_with(&keys, &config_dir).err().expect("must fail");
        assert!(matches!(err, CredentialError::NoMachineId), "got {err}");
        assert!(exists(&config_dir), "kept");
    }

    /// Production values: the storage binding is neither the fingerprint
    /// nor, where there is one, the machine-bound key. Skipped on a machine
    /// without a machine id (the error is then the one the person sees).
    #[test]
    fn system_storage_binding_is_not_the_fingerprint() {
        match SystemKeys.storage_binding() {
            Ok(binding) => {
                if let Ok(fp) = SystemKeys.legacy_fingerprint() {
                    assert_ne!(*binding, *fp);
                }
                assert!(check_machine_binding().is_ok());
            }
            Err(e) => assert!(matches!(binding_error(e), CredentialError::NoMachineId)),
        }
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
        // From the test attributes, as production derives it from the
        // real ones: a missing machine id fails here first.
        fn storage_binding(&self) -> Result<Zeroizing<[u8; 32]>, FingerprintError> {
            use keystore::Sources;
            platform_key::storage_binding_from(&self.0.machine_attributes()?)
        }
        fn legacy_fingerprint(&self) -> Result<Zeroizing<[u8; 32]>, FingerprintError> {
            Ok(Zeroizing::new(FINGERPRINT))
        }
    }

    /// No keyring, and a machine without a usable machine id: the storage
    /// binding is refused before any key is fetched (#14), so the save
    /// fails with the plain notice and nothing is written, not even the
    /// directory.
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
            assert!(matches!(err, CredentialError::NoMachineId), "got {err}");
            assert_eq!(err.to_string(), NO_MACHINE_ID_NOTICE);
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

    /// #30: a pairing or Start New Session whose command started before a
    /// log-out's wipe saves nothing afterwards, and creates no folder.
    #[test]
    fn a_save_that_started_before_a_wipe_writes_nothing() {
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        let keys = FixedKeys { binding: BindingMode::Keyring, master: [0x44; 32], platform: PLATFORM };
        let since = wipe_epoch();
        wipe(&config_dir).expect("wipe");
        let err = save_since(&keys, &config_dir, &creds_with_session("sess-1", 1_900_000_000), Mode::CreateOrReplace, Some(since))
            .err()
            .expect("refused");
        assert!(matches!(err, CredentialError::LoggedOutMeanwhile), "got {err}");
        assert_eq!(err.to_string(), LOGGED_OUT_MEANWHILE_NOTICE);
        assert!(!config_dir.exists(), "nothing recreated");
    }

    /// #30, from #29's review: end_session loaded the old pairing, then a
    /// log-out and a new pairing both completed. Its update is refused and
    /// the new pairing and its marker are left as they were.
    #[test]
    fn an_end_session_update_is_not_written_over_a_pairing_made_after_a_logout() {
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        let keys = FixedKeys { binding: BindingMode::Keyring, master: [0x44; 32], platform: PLATFORM };
        save_with(&keys, &config_dir, &creds_with_session("old", 1_900_000_000)).unwrap();
        let since = wipe_epoch();
        let (mut old, _) = load_with(&keys, &config_dir).unwrap();
        wipe(&config_dir).expect("log-out");
        save_with(&keys, &config_dir, &creds_with_session("new", 1_900_000_001)).unwrap();
        let file = fs::read(config_dir.join(CREDENTIAL_FILE)).unwrap();
        let marker = fs::read(config_dir.join(SESSION_LIVE_FILE)).unwrap();
        old.session_id.clear();
        old.session_expires_at = 0;
        assert!(matches!(
            save_since(&keys, &config_dir, &old, Mode::UpdateExisting, Some(since)),
            Err(CredentialError::LoggedOutMeanwhile)
        ));
        assert_eq!(fs::read(config_dir.join(CREDENTIAL_FILE)).unwrap(), file);
        assert_eq!(fs::read(config_dir.join(SESSION_LIVE_FILE)).unwrap(), marker);
        assert!(session_is_recorded(&config_dir, "new"));
    }

    /// #30: with no wipe since its command started, a save goes ahead as
    /// before, both a create and an update. Other tests wipe at the same
    /// time (the count is per process), so an attempt one of them overtook
    /// is tried again.
    #[test]
    fn with_no_wipe_since_it_started_a_save_goes_ahead() {
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        let keys = FixedKeys { binding: BindingMode::Keyring, master: [0x44; 32], platform: PLATFORM };
        for mode in [Mode::CreateOrReplace, Mode::UpdateExisting] {
            let mut saved = false;
            for _ in 0..100 {
                let since = wipe_epoch();
                match save_since(&keys, &config_dir, &creds_with_session("sess-1", 1_900_000_000), mode, Some(since)) {
                    Ok(_) => {
                        saved = true;
                        break;
                    }
                    Err(CredentialError::LoggedOutMeanwhile) => assert_ne!(wipe_epoch(), since, "refused with no wipe"),
                    Err(e) => panic!("{e}"),
                }
            }
            assert!(saved);
        }
        assert!(session_is_recorded(&config_dir, "sess-1"));
    }

    /// #30: log-out deletes the keyring key while it still holds the writer
    /// lock, so a save that starts meanwhile runs only after the key is
    /// gone (it then mints a new one) and is never sealed under the deleted
    /// key.
    #[test]
    fn logout_deletes_the_key_before_any_waiting_save_runs() {
        use std::sync::{Arc, Mutex};
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        let other = base.path().join("other");
        let keys = FixedKeys { binding: BindingMode::Keyring, master: [0x44; 32], platform: PLATFORM };
        save_with(&keys, &config_dir, &sample_creds()).unwrap();
        let order = Arc::new(Mutex::new(Vec::new()));
        let mut saver = None;
        wipe_then(Some(&config_dir), || {
            let (order2, other2) = (order.clone(), other.clone());
            let handle = std::thread::spawn(move || {
                let keys = FixedKeys { binding: BindingMode::Keyring, master: [0x44; 32], platform: PLATFORM };
                save_with(&keys, &other2, &sample_creds()).unwrap();
                order2.lock().unwrap().push("saved");
            });
            std::thread::sleep(std::time::Duration::from_millis(150));
            assert!(!handle.is_finished(), "a save ran while log-out held the lock");
            order.lock().unwrap().push("key deleted");
            saver = Some(handle);
        })
        .expect("wiped");
        saver.unwrap().join().unwrap();
        assert_eq!(*order.lock().unwrap(), ["key deleted", "saved"]);
        assert!(!config_dir.exists());
    }

    /// #30: End session's marker removal after a log-out leaves the marker
    /// of a pairing made since alone.
    #[test]
    fn end_session_after_a_logout_leaves_a_new_pairings_marker() {
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        let keys = FixedKeys { binding: BindingMode::Keyring, master: [0x44; 32], platform: PLATFORM };
        let since = wipe_epoch();
        wipe(&config_dir).expect("log-out");
        save_with(&keys, &config_dir, &creds_with_session("new", 1_900_000_000)).unwrap();
        assert!(matches!(
            end_saved_session_since(&config_dir, since),
            Err(CredentialError::LoggedOutMeanwhile)
        ));
        assert!(session_is_recorded(&config_dir, "new"));
    }

    /// #30: the folder check at the start of a pairing doesn't recreate the
    /// folder after a log-out it didn't start before.
    #[test]
    fn the_pairing_folder_isnt_made_after_a_logout() {
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        let since = wipe_epoch();
        wipe(&config_dir).expect("log-out");
        assert!(matches!(
            ensure_config_dir_since(&config_dir, since),
            Err(CredentialError::LoggedOutMeanwhile)
        ));
        assert!(!config_dir.exists());
    }

    /// #30: with no folder, log-out still deletes the key, and doesn't
    /// report the pairing removed.
    #[test]
    fn logout_with_no_folder_still_deletes_the_key() {
        let mut deleted = false;
        let since = wipe_epoch();
        assert!(matches!(wipe_then(None, || deleted = true), Err(CredentialError::NoConfigDir)));
        assert!(deleted);
        assert_ne!(wipe_epoch(), since, "a save that started before is still refused");
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
            fn storage_binding(&self) -> Result<Zeroizing<[u8; 32]>, FingerprintError> {
                Ok(Zeroizing::new(PLATFORM))
            }
            fn legacy_fingerprint(&self) -> Result<Zeroizing<[u8; 32]>, FingerprintError> {
                Ok(Zeroizing::new(FINGERPRINT))
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
