//! The parts the device store (`device_store`) is built from, and the
//! local half of log-out.
//!
//! - the private, atomic write of a file in the config folder
//!   ([`write_private`]; `winacl` on Windows), the folder check
//!   ([`ensure_config_dir`]), the one-writer lock and the wipe count
//!   ([`WipeEpoch`]) that stop a save from outliving a log-out (#30), and
//!   the confirmed removal of a file and its temporary copies;
//! - the wipe ([`wipe_for_logout`]): the folder, then every protector's
//!   external key and the earlier format's entry, each confirmed gone;
//! - the warning when another account can open the folder or file
//!   ([`privacy_warning`]);
//! - the earlier builds' pairing, `connection.enc`, which this build can't
//!   open: [`exists`] finds it and [`remove_legacy_pairing`] deletes it
//!   without decrypting it. Nothing here reads or writes its contents.
//!
//! See [`protector`](super::protector) for what protects the device file.

use std::fmt;
use std::fs;
#[cfg(not(windows))]
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

#[cfg(not(windows))]
use rand::rngs::OsRng;

use super::protector::ProtectorError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Credential file name within the config directory: the pairing of the
/// builds that reached the vault over NATS. This build doesn't use it: it
/// is removed at unlock (`commands::auth`) and by log-out.
const CREDENTIAL_FILE: &str = "connection.enc";

/// The paired device's state (vettid-device's `DeviceState`), sealed by
/// [`super::device_store`]. Log-out removes it with the folder.
pub(super) const DEVICE_FILE: &str = "device.enc";

/// An earlier build's marker that its pairing's session was live (#26).
/// This build neither writes nor reads it; it is removed with the legacy
/// pairing so none is left behind.
const SESSION_LIVE_FILE: &str = "session.live";

/// Subdirectory name appended to the OS config dir.
const CONFIG_SUBDIR: &str = "vettid-desktop";

/// What the person is told when a saved pairing can't be opened. Shown
/// as is, so it must stay plain: no error codes, no crypto terms.
pub const UNREADABLE_NOTICE: &str =
    "This desktop's saved pairing can't be opened. Remove this desktop on your phone. Then, in Settings, open Danger zone and choose Log out this desktop, and pair again.";

/// NEW TEXT (owner approval needed): shown when the protector this
/// computer offers is there but failed, so nothing was saved (#13). `by`
/// is its plain name ("Windows data protection", "your computer's
/// keyring"). At pairing, the vault may already list the desktop, hence
/// the phone step. Replaces the keyring-unavailable notice.
///
/// NEW TEXT (#13, Linux, owner approval needed): for the TPM, signing out
/// doesn't help (it may be busy or in lockout, its storage hierarchy may
/// have a password, or a libtss2 library may be missing), so the advice is
/// to retry and then whoever manages the computer.
fn not_protected_notice(by: &str) -> String {
    if by == super::protector::TPM_NAME {
        return format!("This desktop couldn't lock its pairing with {by}, so nothing was saved. If your phone lists this desktop, remove it there. Then try pairing again. If it keeps happening, whoever manages this computer needs to check its TPM and the TPM software: the TPM may be busy or set up with a password this desktop can't use, or a library this desktop needs may be missing.");
    }
    format!("This desktop couldn't lock its pairing with {by}, so nothing was saved. If your phone lists this desktop, remove it there. Then sign out of your computer and back in, and pair again.")
}

/// NEW TEXT (owner approval needed): shown at unlock when the saved
/// pairing's protector is there but couldn't open it (#13). The file is
/// kept: it may open later (after signing in again), or the person re-pairs.
///
/// NEW TEXT (#13, Linux, owner approval needed): for the TPM, "restart this
/// desktop" in place of signing out.
fn not_opened_notice(by: &str) -> String {
    if by == super::protector::TPM_NAME {
        return format!("This desktop couldn't open its saved pairing with {by} just now. The pairing is kept. Restart this desktop to try again. If it keeps happening, remove this desktop on your phone; then, in Settings, open Danger zone and choose Log out this desktop, and pair again.");
    }
    format!("This desktop couldn't open its saved pairing with {by} just now. The pairing is kept. Sign out of your computer and back in to try again. If it keeps happening, remove this desktop on your phone; then, in Settings, open Danger zone and choose Log out this desktop, and pair again.")
}

/// NEW TEXT (owner approval needed): shown when this computer offers no
/// protector at all (#13). Not reachable on Windows or macOS (each has one
/// that is never absent). The passphrase protector will take this case.
#[cfg(not(target_os = "linux"))]
pub const NO_PROTECTOR_NOTICE: &str =
    "This computer offers no way for this desktop to lock its pairing, so nothing was saved. If your phone lists this desktop, remove it there.";

/// NEW TEXT (#13, Linux, owner approval needed): shown at pairing when this
/// account can't use the TPM (`/dev/tpmrm0` missing or not permitted) and no
/// Secret Service is on the session bus. Pairing is refused before the
/// vault lists the desktop; the phone step covers a later save. Says only
/// what the person can do now (the passphrase protector comes later).
#[cfg(target_os = "linux")]
pub const NO_PROTECTOR_NOTICE: &str =
    "This computer offers no way for this desktop to lock its pairing: your account can't use the computer's TPM, and this desktop couldn't find a keyring service, such as GNOME Keyring or KWallet. Nothing was saved. If your phone lists this desktop, remove it there. To pair, start your keyring service, or ask whoever manages this computer to give your account access to the TPM, then pair again.";

/// NEW TEXT (owner approval needed): shown at unlock when the saved pairing
/// was made by an earlier version, whose format this one can't read, and it
/// was deleted with its key, both confirmed (#13, "Migration: none"). The
/// vault still lists the old desktop, hence the phone step.
pub const LEGACY_REMOVED_NOTICE: &str =
    "This desktop's saved pairing was made by an earlier version and can't be used, so it was deleted. Remove this desktop on your phone, then pair again.";

/// NEW TEXT (owner approval needed): the same when the earlier version's
/// file or key couldn't be confirmed deleted.
pub const LEGACY_NOT_REMOVED_NOTICE: &str =
    "This desktop's saved pairing was made by an earlier version and can't be used, and it couldn't be deleted from this computer. In Settings, open Danger zone and choose Log out this desktop. Then remove this desktop on your phone and pair again.";

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
/// folder or file (#24). CHANGED TEXT (#13, owner approval needed): "locked
/// by your keyring" is now "locked to your account", since on Windows it
/// is DPAPI.
///
/// Log out (Settings > Danger zone) is the way out: it removes the folder
/// and the keys, and says if a step failed. Pairing again into the same folder would not fix it (Windows
/// refuses the folder; on unix the file's mode is kept on rewrite).
pub const NOT_PRIVATE_LOCKED_NOTICE: &str =
    "Another account on this computer can open this desktop's saved pairing. It is still locked to your account, but to be safe: in Settings, open Danger zone and choose Log out this desktop. Then check on your phone that this desktop is gone, and pair again.";

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
    /// A saved pairing can't be opened: a device file that does not open
    /// with its data key, or the earlier builds' `connection.enc`.
    /// Displays [`UNREADABLE_NOTICE`].
    Unreadable,
    /// Every protector is absent here: nothing was written. Displays
    /// [`NO_PROTECTOR_NOTICE`].
    NoProtector,
    /// The protector `by` (its plain name) is present but failed: nothing
    /// was written, and there is no fallback (#13).
    NotProtected { by: &'static str },
    /// The protector `by` is present but couldn't open the saved pairing,
    /// which is kept (#13).
    NotOpened { by: &'static str },
    /// The earlier format's device file or key couldn't be confirmed
    /// deleted. Displays [`LEGACY_NOT_REMOVED_NOTICE`].
    LegacyNotRemoved,
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
            CredentialError::Unreadable => f.write_str(UNREADABLE_NOTICE),
            CredentialError::NoProtector => f.write_str(NO_PROTECTOR_NOTICE),
            CredentialError::NotProtected { by } => f.write_str(&not_protected_notice(by)),
            CredentialError::NotOpened { by } => f.write_str(&not_opened_notice(by)),
            CredentialError::LegacyNotRemoved => f.write_str(LEGACY_NOT_REMOVED_NOTICE),
            CredentialError::NoConfigDir => f.write_str(NO_CONFIG_DIR_NOTICE),
            CredentialError::ParentNotPrivate => f.write_str(PARENT_NOT_PRIVATE_NOTICE),
            CredentialError::ParentIsLink => f.write_str(PARENT_IS_LINK_NOTICE),
            CredentialError::NotPrivate => f.write_str(NOT_PRIVATE_NOTICE),
            CredentialError::LoggedOutMeanwhile => f.write_str(LOGGED_OUT_MEANWHILE_NOTICE),
        }
    }
}

impl std::error::Error for CredentialError {}

/// A protector's failure outside a save or a load (a wipe's key removal):
/// not a plain notice, so the caller says "not removed".
impl From<ProtectorError> for CredentialError {
    fn from(e: ProtectorError) -> Self {
        CredentialError::IoError(e.to_string())
    }
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
/// saves records it when it starts and hands it to its store
/// ([`super::device_store::DeviceStore::new`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WipeEpoch(u64);

/// The current [`WipeEpoch`]. Record it at the start of the command that
/// will save, before anything that could wait.
pub fn wipe_epoch() -> WipeEpoch {
    WipeEpoch(WIPES.load(std::sync::atomic::Ordering::SeqCst))
}

/// One writer at a time in this process: a save, a delete or a wipe
/// removes temporary files a crashed earlier save left behind, and must not
/// remove another save's while it is running (e.g. an update racing a
/// pairing). A wipe holding it also can't be undone by a save that started
/// first (#28). The app runs as a single instance, so this covers every
/// writer.
///
/// A save holds it while its protector wraps a new data key, which may
/// wait on a keyring prompt; a log-out started meanwhile waits for that
/// save.
pub(super) fn writer_lock() -> std::sync::MutexGuard<'static, ()> {
    static WRITER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    WRITER_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Write `data` as `config_dir/name`, privately and atomically.
///
/// SECURITY: written to a new temporary file in the same folder, then
/// moved over `name`, so a crash or a full disk leaves the old file whole
/// (#12). On Windows the temporary file is created with the user-only
/// DACL, inside the folder held open (#16, #23).
pub(super) fn write_private(config_dir: &Path, name: &str, data: &[u8]) -> Result<(), CredentialError> {
    #[cfg(windows)]
    {
        super::winacl::write_private_file(config_dir, name, data).map_err(|e| acl_error(&config_dir.join(name), e))
    }
    #[cfg(not(windows))]
    {
        write_atomically(config_dir, name, data)
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
    // The error's text (with the OS error code) and its kind, for the logs.
    let io = |what: &str, e: std::io::Error| CredentialError::IoError(format!("{} {}: {} (kind {:?})", what, path.display(), e, e.kind()));

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

/// Remove an earlier build's pairing (`connection.enc`, from the builds
/// that reached the vault over NATS), which this build can't use, with its
/// live marker. The folder, the keyring key and this build's device file
/// are left. Ok only if the file system confirms it gone.
///
/// The earlier builds kept that pairing's key as `master-key-v1`, which this
/// doesn't remove (log-out does): the pending-wipe marker records that an
/// earlier format was here, first, and stays until a log-out confirms the
/// key gone.
pub fn remove_legacy_pairing(config_dir: &Path) -> Result<(), CredentialError> {
    let _one_at_a_time = writer_lock();
    let legacy = super::protector::Wiping { legacy: true, ..super::protector::Wiping::nothing() };
    let wiping = match pending_wipe(config_dir) {
        Some(pending) => pending.and(legacy),
        None => legacy,
    };
    // #13 (review M1): with no marker on disk, deleting `connection.enc`
    // would leave `master-key-v1` known only to this process; after a
    // restart nothing would say an earlier format was here, and a log-out
    // would skip the full keyring sweep. Kept until the marker can be
    // written (its key is removed by log-out, which reads the file again).
    if !record_wipe(config_dir, &wiping) {
        return Err(CredentialError::IoError("the earlier pairing is kept: its removal couldn't be recorded".into()));
    }
    delete_locked(config_dir)?;
    confirm_gone(config_dir, CREDENTIAL_FILE)
}

/// Log-out's local half (#30): as [`wipe`] when the folder is known, then,
/// still holding the writer lock, remove every protector's external key
/// and the earlier format's `master-key-v1` entry, each confirmed gone. A
/// save can't run between the two, so none is sealed under a key that is
/// then deleted. The keys are removed even if the wipe fails or there is
/// no folder. Ok only if the pairing and the keys are confirmed gone; with
/// no folder, `NoConfigDir`.
pub fn wipe_for_logout(config_dir: Option<&Path>) -> Result<(), CredentialError> {
    wipe_then(config_dir, |wiping| super::protector::Protectors::system().remove_external_keys(wiping).map_err(CredentialError::from))
}

/// The wipe, then `remove_keys` with what the device file's header said
/// before it (read under the lock; no folder: nothing known).
fn wipe_then(
    config_dir: Option<&Path>,
    remove_keys: impl FnOnce(&super::protector::Wiping) -> Result<(), CredentialError>,
) -> Result<(), CredentialError> {
    let _one_at_a_time = writer_lock();
    WIPES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let (wiping, recorded) = match config_dir {
        Some(dir) => begin_wipe(dir, super::device_store::what_is_sealed(dir)),
        None => (super::protector::Wiping::unknown(), true),
    };
    let done = file_then_keys(
        recorded,
        || match config_dir {
            Some(dir) => wipe_locked(dir),
            None => Err(CredentialError::NoConfigDir),
        },
        || {
            let keys = remove_keys(&wiping);
            if let Err(e) = &keys {
                log::error!("Credential store: a key was not removed: {}", e);
            }
            keys
        },
    );
    if let (Ok(()), Some(dir)) = (&done, config_dir) {
        finish_wipe(dir);
    }
    done
}

/// A wipe's two parts, the device file (and folder) and the protectors'
/// external keys, in the fail-secure order (#13, lead decision):
/// - **`recorded`** (the wipe's marker is on disk): the file, then the keys,
///   both always tried. A key left behind is still known after a restart,
///   from the marker, and the next log-out removes it.
/// - **Not recorded** (no marker could be written, so a restart would
///   forget which protector kept a key): the keys **first**. If removing
///   them fails, the file is left as it is: it is the retry signal, since
///   the next log-out reads its header again. If the keys go and the file
///   then can't be removed: for a protector that keeps its key outside the
///   file (the Secret Service, the earlier format's `master-key-v1`), the
///   file is left with no key and can't be opened; the next launch fails
///   to open it and the person is told, and the next log-out removes it.
///   A TPM- or DPAPI-sealed file keeps its key inside the file, so it still
///   opens; there the result is the plain "not removed", as before.
///
/// Either way the result is Ok only if both are confirmed gone. On
/// Windows the marker is never written (DPAPI keeps nothing outside the
/// file) and `wipe_marker::write` is a no-op Ok, so `recorded` is always
/// true there and the order is the first one.
pub(super) fn file_then_keys(
    recorded: bool,
    remove_file: impl FnOnce() -> Result<(), CredentialError>,
    remove_keys: impl FnOnce() -> Result<(), CredentialError>,
) -> Result<(), CredentialError> {
    if recorded {
        let file = remove_file();
        let keys = remove_keys();
        file.and(keys)
    } else {
        remove_keys()?;
        remove_file()
    }
}

/// Wipes of `config_dir`s that haven't finished, in this process: kept
/// as well as the marker, for when the marker couldn't be written.
static PENDING_WIPES: std::sync::LazyLock<std::sync::Mutex<std::collections::HashMap<PathBuf, super::protector::Wiping>>> =
    std::sync::LazyLock::new(Default::default);

/// Before a wipe of `config_dir` (log-out, a store's clear on
/// device.unlinked, an earlier format's retirement) removes anything: what
/// it removes, `on_disk` together with any wipe of it that hasn't finished
/// (its marker, or this process's memory), recorded in the marker and in
/// memory. The caller holds the writer lock, and calls [`finish_wipe`]
/// only once every part is confirmed gone. Also whether the marker is on
/// disk (see [`file_then_keys`]).
pub(super) fn begin_wipe(config_dir: &Path, on_disk: super::protector::Wiping) -> (super::protector::Wiping, bool) {
    let wiping = match pending_wipe(config_dir) {
        Some(pending) => pending.and(on_disk),
        None => on_disk,
    };
    let recorded = record_wipe(config_dir, &wiping);
    (wiping, recorded)
}

/// A wipe of `config_dir` that hasn't finished: its marker and this
/// process's memory of it, together. The caller holds the writer lock.
pub(super) fn pending_wipe(config_dir: &Path) -> Option<super::protector::Wiping> {
    let remembered = PENDING_WIPES.lock().unwrap_or_else(|e| e.into_inner()).get(config_dir).cloned();
    match (wipe_marker::read(config_dir), remembered) {
        (Some(m), Some(r)) => Some(m.and(r)),
        (m, r) => m.or(r),
    }
}

/// Record `wiping` as the pending wipe of `config_dir` (the marker, and
/// memory). The caller holds the writer lock. True if the marker is on
/// disk (next to the folder, or in the fallback place); false if only this
/// process remembers it.
pub(super) fn record_wipe(config_dir: &Path, wiping: &super::protector::Wiping) -> bool {
    let recorded = match wipe_marker::write(config_dir, wiping) {
        Ok(()) => true,
        Err(e) => {
            log::warn!("Credential store: the wipe's marker wasn't written ({}); this process remembers it, a restart loses it", e);
            false
        }
    };
    PENDING_WIPES.lock().unwrap_or_else(|e| e.into_inner()).insert(config_dir.to_path_buf(), wiping.clone());
    recorded
}

/// After a wipe of `config_dir` whose every part is confirmed gone: the
/// marker goes (last), and the memory of it.
pub(super) fn finish_wipe(config_dir: &Path) {
    if let Err(e) = wipe_marker::remove(config_dir) {
        log::warn!("Credential store: the wipe's marker wasn't removed: {}", e);
    }
    PENDING_WIPES.lock().unwrap_or_else(|e| e.into_inner()).remove(config_dir);
}

/// The marker of a log-out's wipe that hasn't finished
/// (`vettid-desktop.wipe-pending`, next to the pairing folder, which the
/// wipe removes): what the device file's header said before it, so a retry
/// after the file is gone still knows which protector kept a key. Holds no
/// secret (a protector id and a flag), written `0600` and synced. It is not
/// a pairing: nothing else reads it. Written on Linux and macOS
/// (`cfg(unix)`); only Linux's Secret Service protector reads what it
/// says, so on macOS it is harmless and unused. Not written on Windows,
/// where DPAPI keeps nothing outside the file.
mod wipe_marker {
    use super::super::protector::Wiping;
    use std::path::{Path, PathBuf};

    const SUFFIX: &str = ".wipe-pending";
    const TAG: &str = "vettid-desktop-wipe-v1";

    pub(super) fn path(config_dir: &Path) -> Option<PathBuf> {
        let mut name = config_dir.file_name()?.to_os_string();
        name.push(SUFFIX);
        Some(config_dir.with_file_name(name))
    }

    fn encode(w: &Wiping) -> String {
        let id = match w.sealed_by.as_deref() {
            Some(id) if !id.is_empty() && id != "?" && !id.contains(['\n', '\r']) => id,
            _ => "?",
        };
        format!("{TAG}\n{id}\n{}\n", u8::from(w.legacy))
    }

    fn decode(text: &str) -> Wiping {
        let mut lines = text.lines();
        match (lines.next(), lines.next(), lines.next(), lines.next()) {
            (Some(TAG), Some(id), Some(legacy @ ("0" | "1")), None) => {
                Wiping { sealed_by: (id != "?").then(|| id.to_string()), legacy: legacy == "1" }
            }
            _ => Wiping::unknown(),
        }
    }

    /// The fallback place for the marker (#13), for when it can't be
    /// written next to the pairing folder: `$XDG_STATE_HOME` (if absolute)
    /// or `~/.local/state`, then `vettid-desktop-wipe/`, a folder made
    /// `0700`. Tests use none unless they set one ([`set_fallback_for_tests`]),
    /// so they never write to the developer's real state folder.
    ///
    /// The place follows the environment at launch: a later launch with
    /// another `XDG_STATE_HOME` won't see a marker left here. Then a key
    /// left in the Secret Service (whose file is already gone) is skipped
    /// only if the keyring is locked; accepted, as the rarer case.
    #[cfg(unix)]
    fn fallback_path(config_dir: &Path) -> Option<PathBuf> {
        #[cfg(test)]
        let base = FALLBACK_FOR_TESTS.with(|b| b.borrow().clone())?;
        #[cfg(not(test))]
        let base = match std::env::var_os("XDG_STATE_HOME").map(PathBuf::from).filter(|p| p.is_absolute()) {
            Some(p) => p,
            // Review L3: never a relative (or empty) HOME.
            None => Some(PathBuf::from(std::env::var_os("HOME")?)).filter(|p| p.is_absolute())?.join(".local").join("state"),
        };
        // The name is the folder's name plus a hash of its full path (review
        // L3), so two config folders never share a fallback marker.
        use sha2::Digest;
        use std::os::unix::ffi::OsStrExt;
        let digest = sha2::Sha256::digest(config_dir.as_os_str().as_bytes());
        let mut name = config_dir.file_name()?.to_os_string();
        name.push(format!(".{}{SUFFIX}", hex::encode(&digest[..8])));
        Some(base.join("vettid-desktop-wipe").join(name))
    }

    /// The fallback folder (review L3): made `0700` if missing (and its
    /// entry synced), then checked: a real folder (not a symlink), owned by
    /// this user, not open to the group or others. Anything else isn't used.
    #[cfg(unix)]
    fn fallback_folder(dir: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::DirBuilderExt;
        match std::fs::symlink_metadata(dir) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
                if let Some(parent) = dir.parent() {
                    std::fs::File::open(parent)?.sync_all()?;
                }
            }
            Err(e) => return Err(e),
            Ok(_) => {}
        }
        private_folder(dir)
    }

    /// A real folder (not a symlink), this user's, not open to the group or
    /// others: else an error.
    #[cfg(unix)]
    fn private_folder(dir: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::symlink_metadata(dir)?;
        // SAFETY: geteuid has no preconditions.
        let me = unsafe { libc::geteuid() };
        if !m.file_type().is_dir() || m.uid() != me || m.mode() & 0o077 != 0 {
            return Err(std::io::Error::other("the fallback folder isn't this user's private folder"));
        }
        Ok(())
    }

    /// `dir` made `0700` through a handle opened without following a
    /// symlink (`O_DIRECTORY|O_NOFOLLOW`), checked on that handle (a folder,
    /// this user's) and changed with `fchmod`: no path is followed between
    /// the check and the change. False if it isn't this user's folder.
    #[cfg(unix)]
    fn make_private(dir: &Path) -> std::io::Result<bool> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        let f = match std::fs::OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NOCTTY).open(dir) {
            Ok(f) => f,
            // Not a folder, or a symlink: not this user's folder.
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTDIR) | Some(libc::ELOOP)) => return Ok(false),
            Err(e) => return Err(e),
        };
        let m = f.metadata()?;
        // SAFETY: geteuid has no preconditions.
        let me = unsafe { libc::geteuid() };
        if !m.file_type().is_dir() || m.uid() != me {
            return Ok(false);
        }
        f.set_permissions(std::fs::Permissions::from_mode(0o700))?;
        Ok(true)
    }

    /// The fallback marker, if any (review: read only from a private
    /// folder). A folder that's there but not private gives "nothing known",
    /// so the sweep stays full: a marker someone else could have written
    /// must never narrow it.
    #[cfg(unix)]
    fn read_fallback(config_dir: &Path) -> Option<Wiping> {
        let path = fallback_path(config_dir)?;
        let dir = path.parent()?;
        match std::fs::symlink_metadata(dir) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => Some(Wiping::unknown()),
            Ok(_) => match private_folder(dir) {
                Ok(()) => read_at(&path),
                Err(_) => {
                    // Lead review (Opus L1): a folder of ours left open to
                    // others is made private again, so later log-outs can
                    // trust what this build writes there. What is in it now
                    // may not be ours: "nothing known" this time, and a file
                    // that isn't ours is never trusted later either (`ours`).
                    match make_private(dir) {
                        Ok(true) => {
                            log::warn!("Credential store: the wipe marker's fallback folder was open to others; made private");
                            // Lead review: whatever is there now (even a
                            // marker of ours renamed into place by someone
                            // else) is replaced with "nothing known".
                            if let Err(e) = write_at(&path, &Wiping::unknown()) {
                                log::warn!("Credential store: the fallback marker couldn't be reset: {e}");
                            }
                        }
                        Ok(false) => log::warn!("Credential store: the wipe marker's fallback folder isn't this user's folder; not used"),
                        Err(e) => log::warn!("Credential store: the wipe marker's fallback folder is open to others and couldn't be made private: {e}"),
                    }
                    Some(Wiping::unknown())
                }
            },
        }
    }

    #[cfg(all(unix, test))]
    thread_local! {
        static FALLBACK_FOR_TESTS: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
    }

    /// Tests: where the fallback marker goes, on this thread (`None`: no
    /// fallback).
    #[cfg(all(unix, test))]
    pub(crate) fn set_fallback_for_tests(base: Option<PathBuf>) {
        FALLBACK_FOR_TESTS.with(|b| *b.borrow_mut() = base);
    }

    #[cfg(all(unix, test))]
    pub(crate) fn fallback_path_for_tests(config_dir: &Path) -> Option<PathBuf> {
        fallback_path(config_dir)
    }

    /// The pending wipe, if a marker is there (next to the folder, or in
    /// the fallback place; both: together); one that can't be read or
    /// parsed is "nothing known".
    #[cfg(unix)]
    pub(super) fn read(config_dir: &Path) -> Option<Wiping> {
        let here = path(config_dir).and_then(|p| read_at(&p));
        let there = read_fallback(config_dir);
        match (here, there) {
            (Some(a), Some(b)) => Some(a.and(b)),
            (a, b) => a.or(b),
        }
    }

    /// A marker this build could have written: an open file (checked on the
    /// handle, not the path) that is a regular file, this user's, with one
    /// link (lead review: never a FIFO, a device, a hard link or another
    /// user's file, whatever a folder once open to others holds).
    #[cfg(unix)]
    fn ours(f: &std::fs::File) -> bool {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no preconditions.
        let me = unsafe { libc::geteuid() };
        // Private too (lead review): `O_TRUNC` keeps an existing file's mode,
        // so a marker of ours that others could write isn't trusted.
        f.metadata().is_ok_and(|m| m.file_type().is_file() && m.uid() == me && m.nlink() == 1 && m.mode() & 0o077 == 0)
    }

    /// The flags for opening a marker that may not be ours: no symlink
    /// followed, never blocking (a FIFO), never a controlling terminal.
    #[cfg(unix)]
    const UNTRUSTED_OPEN: i32 = libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY;

    /// Opened without following a symlink and without blocking (a FIFO
    /// can't hang the wipe under the writer lock), then checked with
    /// [`ours`]; anything else is "nothing known", so the sweep stays full.
    #[cfg(unix)]
    fn read_at(path: &Path) -> Option<Wiping> {
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new().read(true).custom_flags(UNTRUSTED_OPEN).open(path) {
            Ok(f) if !ours(&f) => Some(Wiping::unknown()),
            Ok(f) => {
                let mut text = String::new();
                Some(match f.take(256).read_to_string(&mut text) {
                    Ok(_) => decode(&text),
                    Err(_) => Wiping::unknown(),
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => Some(Wiping::unknown()),
        }
    }

    /// Next to the folder, or else in the fallback place (#13). Ok if either
    /// is on disk and synced.
    #[cfg(unix)]
    pub(super) fn write(config_dir: &Path, w: &Wiping) -> std::io::Result<()> {
        let path = path(config_dir).ok_or_else(|| std::io::Error::other("no folder name"))?;
        let here = match write_at(&path, w) {
            Ok(()) => return Ok(()),
            Err(e) => e,
        };
        let Some(fallback) = fallback_path(config_dir) else { return Err(here) };
        let made = match fallback.parent() {
            Some(dir) => fallback_folder(dir),
            None => Ok(()),
        };
        match made.and_then(|()| write_at(&fallback, w)) {
            Ok(()) => {
                log::warn!("Credential store: the wipe's marker went to the fallback place ({here})");
                Ok(())
            }
            Err(e) => Err(std::io::Error::other(format!("{here}; the fallback too: {e}"))),
        }
    }

    /// A marker that is [`ours`] is emptied and rewritten through the same
    /// handle that passed the check. Anything else at `path` (a FIFO,
    /// another user's file, a hard link, a symlink, one others can write) is
    /// removed, and a new marker is made with `O_EXCL` ([`create_marker`]),
    /// without following a symlink or blocking, and checked again on its
    /// handle before it is written (lead reviews).
    #[cfg(unix)]
    fn write_at(path: &Path, w: &Wiping) -> std::io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        // One handle, opened read-write without following a symlink or
        // blocking, checked with `ours`, and only then emptied and written
        // (round-4 review): the file checked is the file written.
        let existing = std::fs::OpenOptions::new().read(true).write(true).custom_flags(UNTRUSTED_OPEN).open(path);
        let mut f = match existing {
            Ok(f) if ours(&f) => {
                f.set_len(0)?;
                f
            }
            other => {
                // Not ours (a FIFO, another user's file, a hard link, a
                // symlink, one others can write), or absent: whatever is
                // there is removed, and a new file is made with O_EXCL, so
                // nothing raced into place meanwhile is ever written: the
                // create fails instead.
                let exists = !matches!(&other, Err(e) if e.kind() == std::io::ErrorKind::NotFound);
                drop(other);
                if exists {
                    match std::fs::remove_file(path) {
                        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
                        _ => {}
                    }
                }
                create_marker(path)?
            }
        };
        f.write_all(encode(w).as_bytes())?;
        f.sync_all()?;
        if let Some(parent) = path.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    }

    /// A new marker file: `O_EXCL` (`create_new`), so it fails with
    /// `AlreadyExists` rather than opening anything already at `path`;
    /// `0600`, no symlink followed, never blocking; checked with `ours`.
    #[cfg(unix)]
    fn create_marker(path: &Path) -> std::io::Result<std::fs::File> {
        use std::os::unix::fs::OpenOptionsExt;
        let f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(UNTRUSTED_OPEN).open(path)?;
        if !ours(&f) {
            return Err(std::io::Error::other("the marker isn't this user's own file"));
        }
        Ok(f)
    }

    /// Round-4 review: a new marker is never made over something already
    /// there (a file raced into place keeps its bytes, and the create fails).
    #[cfg(all(unix, test))]
    #[test]
    fn a_new_marker_never_opens_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.wipe-pending");
        std::fs::write(&path, b"someone else's").unwrap();
        let e = create_marker(&path).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), b"someone else's");
    }

    /// Both places; an error if either is still there.
    #[cfg(unix)]
    pub(super) fn remove(config_dir: &Path) -> std::io::Result<()> {
        let gone = |p: Option<PathBuf>| match p.map(std::fs::remove_file) {
            Some(Err(e)) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        };
        let here = gone(path(config_dir));
        let there = gone(fallback_path(config_dir));
        here.and(there)
    }

    #[cfg(not(unix))]
    pub(super) fn read(_: &Path) -> Option<Wiping> {
        None
    }
    #[cfg(not(unix))]
    pub(super) fn write(_: &Path, _: &Wiping) -> std::io::Result<()> {
        Ok(())
    }
    #[cfg(not(unix))]
    pub(super) fn remove(_: &Path) -> std::io::Result<()> {
        Ok(())
    }

    #[cfg(test)]
    #[test]
    fn the_marker_round_trips() {
        for w in [Wiping::unknown(), Wiping::nothing(), Wiping::legacy_file(), Wiping { sealed_by: Some("secret-service".into()), legacy: false }] {
            assert_eq!(decode(&encode(&w)), w);
        }
        assert_eq!(decode(&encode(&Wiping { sealed_by: Some("a\nb".into()), legacy: false })).sealed_by, None);
        assert_eq!(decode("garbage"), Wiping::unknown());
        assert_eq!(path(Path::new("/x/vettid-desktop")).unwrap(), Path::new("/x/vettid-desktop.wipe-pending"));
    }
}

/// [`wipe`]'s work; the caller holds the writer lock.
fn wipe_locked(config_dir: &Path) -> Result<(), CredentialError> {
    let is_link = fs::symlink_metadata(config_dir).map(|m| m.file_type().is_symlink()).unwrap_or(false);
    if is_link {
        let legacy = delete_locked(config_dir);
        remove_file_locked(config_dir, DEVICE_FILE)?;
        legacy?;
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
            // Both, even if the first fails.
            let legacy = delete_locked(config_dir);
            remove_file_locked(config_dir, DEVICE_FILE)?;
            legacy?;
        }
    }
    confirm_wiped(config_dir)
}

/// Whether a pairing may be saved in `config_dir`: this build's device
/// file, the earlier builds' `connection.enc`, or a temporary copy of
/// either. True also when that can't be ruled out (a stat or listing error
/// other than "not found"), as [`exists`]. For the uninstaller's wipe
/// (`uninstall`), which says "this desktop was paired" only on this.
pub fn pairing_may_be_present(config_dir: &Path) -> bool {
    confirm_wiped(config_dir).is_err()
}

/// Ok only if the file system confirms that neither the pairing file nor
/// a temporary copy of it is in `config_dir`. Anything that can't be
/// checked (a stat or listing error other than "not found") is an error:
/// the pairing is not reported gone on a guess.
fn confirm_wiped(config_dir: &Path) -> Result<(), CredentialError> {
    confirm_gone(config_dir, CREDENTIAL_FILE)?;
    confirm_gone(config_dir, DEVICE_FILE)
}

/// Ok only if the file system confirms that neither `config_dir/name` nor
/// a temporary copy of it is there (see [`confirm_wiped`]).
pub(super) fn confirm_gone(config_dir: &Path, name: &str) -> Result<(), CredentialError> {
    let not_confirmed = |what: String| {
        Err(CredentialError::IoError(format!("the pairing in {} {}", config_dir.display(), what)))
    };
    match fs::symlink_metadata(config_dir.join(name)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => return not_confirmed("is still there".into()),
        Err(e) => return not_confirmed(format!("could not be checked: {}", e)),
    }
    let prefix = format!("{name}.tmp-");
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
    // An earlier build's live marker; best effort, it holds no secret.
    let _ = fs::remove_file(config_dir.join(SESSION_LIVE_FILE));
    remove_file_locked(config_dir, CREDENTIAL_FILE)
}

/// Remove `config_dir/name` and its temporary copies; the caller holds the
/// writer lock. Ok if it is removed or wasn't there.
pub(super) fn remove_file_locked(config_dir: &Path, name: &str) -> Result<(), CredentialError> {
    let path = config_dir.join(name);
    // Temporary files from an interrupted save hold the same ciphertext.
    let prefix = format!("{name}.tmp-");
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

/// A warning for the person when another account can open the saved
/// pairing's folder or file (#24).
/// Called after a successful load; it warns and never refuses, since
/// refusing would not undo a disclosure and would lock out the pairing.
/// AEAD already prevents a planted or edited file from being used.
///
/// On unix a private file in a folder another account can change gets
/// [`NOT_PRIVATE_FOLDER_NOTICE`] (#28); a file others can read gets the
/// stronger notice whatever the folder. Not read-only on unix: the user's
/// own folder that others can write to is set to `0700` here (see
/// `unix_folder_check`).
pub fn privacy_warning(config_dir: &Path) -> Option<&'static str> {
    if !is_private(config_dir) {
        return Some(NOT_PRIVATE_LOCKED_NOTICE);
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
    for path in [config_dir.to_path_buf(), config_dir.join(CREDENTIAL_FILE), config_dir.join(DEVICE_FILE)] {
        // A pairing file that isn't there has nothing to warn about.
        if path.as_path() != config_dir && matches!(fs::symlink_metadata(&path), Err(ref e) if e.kind() == std::io::ErrorKind::NotFound) {
            continue;
        }
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
    for path in [config_dir.join(CREDENTIAL_FILE), config_dir.join(DEVICE_FILE)] {
        match fs::metadata(&path) {
            Ok(meta) if meta.permissions().mode() & 0o077 != 0 => {
                log::warn!("Credential store: {} is readable by other accounts", path.display());
                return false;
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => log::warn!("Credential store: could not check {}: {}", path.display(), e),
        }
    }
    true
}

#[cfg(not(any(unix, windows)))]
fn is_private(_config_dir: &Path) -> bool {
    true
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::credential::device_store::tests::{store_for_tests, store_since_for_tests};
    use vettid_device::store::Persist;

    /// For tests elsewhere in the crate: an earlier build's pairing in
    /// `dir` (a `connection.enc` this build can't open, and its live
    /// marker). The bytes are not a valid store: nothing may need to read
    /// them to find and delete the file.
    pub(crate) fn legacy_pairing_for_tests(dir: &Path) {
        ensure_config_dir(dir).expect("folder");
        write_private(dir, CREDENTIAL_FILE, b"sealed by an earlier build").expect("legacy pairing");
        write_private(dir, SESSION_LIVE_FILE, b"marker").expect("legacy marker");
        assert!(exists(dir));
    }

    /// This build's pairing in `dir`: a `device.enc` sealed by the device
    /// store under fixed test keys, with no log-out check.
    fn device_pairing(dir: &Path) {
        store_for_tests(dir).save_raw_for_tests();
        assert!(dir.join(DEVICE_FILE).exists());
    }

    /// An earlier build's pairing is removed with its live marker and
    /// temporary copies, without being opened; this build's device file
    /// stays. (Was: the same, with a pairing made by the deleted
    /// `ConnectionCredentials` save; now the legacy file is plain bytes.)
    #[test]
    fn removing_the_legacy_pairing_leaves_the_device_file() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        legacy_pairing_for_tests(&dir);
        fs::write(dir.join(format!("{CREDENTIAL_FILE}.tmp-1-00")), b"ciphertext").unwrap();
        device_pairing(&dir);
        remove_legacy_pairing(&dir).unwrap();
        assert!(!exists(&dir));
        assert!(!dir.join(SESSION_LIVE_FILE).exists());
        assert!(!dir.join(format!("{CREDENTIAL_FILE}.tmp-1-00")).exists());
        assert!(dir.join(DEVICE_FILE).exists());
        remove_legacy_pairing(&dir).unwrap();
    }

    /// A device pairing saved normally is private: no warning.
    #[test]
    fn privately_saved_pairing_gives_no_warning() {
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        device_pairing(&config_dir);
        assert_eq!(privacy_warning(&config_dir), None);
    }

    /// Windows: a folder or file another account can open gives the
    /// warning for the binding, and nothing is changed. (Now on
    /// `device.enc`.)
    #[cfg(windows)]
    #[test]
    fn windows_shared_pairing_gives_the_warning() {
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        device_pairing(&config_dir);
        let file = config_dir.join(DEVICE_FILE);
        let before = fs::read(&file).unwrap();
        super::super::winacl::test_share_with_everyone(&file);
        assert_eq!(privacy_warning(&config_dir), Some(NOT_PRIVATE_LOCKED_NOTICE));
        assert_eq!(fs::read(&file).unwrap(), before, "a warning changes nothing");

        // A shared folder with a private file warns too.
        let other = base.path().join("other");
        device_pairing(&other);
        super::super::winacl::test_share_with_everyone(&other);
        assert_eq!(privacy_warning(&other), Some(NOT_PRIVATE_LOCKED_NOTICE));
    }

    /// Unix (#12): a new folder is 0700 and the file 0600; a rewrite goes
    /// through a temporary file and replaces a widened file with a 0600 one;
    /// no temporary file is left. (Now on `device.enc`.)
    #[cfg(unix)]
    #[test]
    fn unix_folder_0700_file_0600_and_atomic_rewrite() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        device_pairing(&config_dir);
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&config_dir), 0o700);
        let file = config_dir.join(DEVICE_FILE);
        assert_eq!(mode(&file), 0o600);

        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(config_dir.join(format!("{DEVICE_FILE}{TEMP_INFIX}1-00")), b"stale").unwrap();
        device_pairing(&config_dir);
        assert_eq!(mode(&file), 0o600, "replaced by a 0600 file");
        let temps = fs::read_dir(&config_dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(TEMP_INFIX))
            .count();
        assert_eq!(temps, 0);
        assert!(store_for_tests(&config_dir).load().unwrap().is_some());
    }

    /// Unix: a file group or others can read gives the warning. (Now on
    /// `device.enc`.)
    #[cfg(unix)]
    #[test]
    fn unix_readable_file_gives_the_warning() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        device_pairing(&dir);
        let file = dir.join(DEVICE_FILE);
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(privacy_warning(&dir), Some(NOT_PRIVATE_LOCKED_NOTICE));
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(privacy_warning(&dir), None);
    }

    /// Unix (#28): the user's own folder that others can write to (as
    /// earlier builds made it under umask 002) is tightened to 0700 and the
    /// save goes through. The refusal is for another owner, which needs a
    /// second account to test. (Now saving `device.enc`.)
    #[cfg(unix)]
    #[test]
    fn unix_save_tightens_the_users_own_folder_others_can_write() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        device_pairing(&config_dir);
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        for wide in [0o775, 0o720, 0o702, 0o777, 0o1777] {
            fs::set_permissions(&config_dir, fs::Permissions::from_mode(wide)).unwrap();
            device_pairing(&config_dir);
            assert_eq!(mode(&config_dir), 0o700, "{wide:o}");
            assert!(store_for_tests(&config_dir).load().unwrap().is_some());
        }
        // Read and search access for others is not a refusal (the file is
        // 0600), and the folder is left as it is.
        fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o755)).unwrap();
        device_pairing(&config_dir);
        assert_eq!(fs::metadata(&config_dir).unwrap().permissions().mode() & 0o7777, 0o755);
    }

    /// Unix (#28): at unlock, the user's own folder that others can write
    /// to is tightened and gives no warning; a file others can read still
    /// gives the stronger one. (The folder warning itself is for another
    /// owner, which needs a second account to test.) Now on `device.enc`.
    #[cfg(unix)]
    #[test]
    fn unix_own_folder_others_can_write_is_tightened_at_unlock() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        device_pairing(&config_dir);
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o770)).unwrap();
        assert_eq!(privacy_warning(&config_dir), None);
        assert_eq!(mode(&config_dir), 0o700);
        let file = config_dir.join(DEVICE_FILE);
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o770)).unwrap();
        assert_eq!(privacy_warning(&config_dir), Some(NOT_PRIVATE_LOCKED_NOTICE));
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
    /// reported gone: exists() says it may be there, a save refuses, and
    /// a wipe is not confirmed. (Root ignores the mode, and then the test
    /// has nothing to check.) The pairing is an earlier build's file for
    /// `exists`, and this build's device file for the save.
    #[cfg(unix)]
    #[test]
    fn unix_an_unreadable_folder_is_not_reported_gone() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        legacy_pairing_for_tests(&config_dir);
        device_pairing(&config_dir);
        fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o000)).unwrap();
        let root_ignores_modes = fs::read_dir(&config_dir).is_ok();
        let present = exists(&config_dir);
        let mut s = store_for_tests(&config_dir);
        let update = s.save(b"update");
        let why = s.take_failure();
        let confirmed = confirm_wiped(&config_dir);
        fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700)).unwrap();
        if root_ignores_modes {
            return;
        }
        assert!(present, "can't be ruled out, so it may be there");
        assert!(update.is_err(), "no save on a guess");
        assert!(matches!(why, Some(CredentialError::IoError(_))), "said as an I/O error: {why:?}");
        assert!(confirmed.is_err(), "not confirmed gone");
    }

    /// Unix (#28): a symlinked pairing folder is wiped through the link:
    /// the pairing (this build's and an earlier build's) and their
    /// temporary copies are removed from the folder it points to, then the
    /// link goes.
    #[cfg(unix)]
    #[test]
    fn wipe_through_a_symlinked_folder_removes_the_pairing() {
        let base = tempfile::tempdir().unwrap();
        let real = base.path().join("dotfiles-vettid-desktop");
        let link = base.path().join("vettid-desktop");
        device_pairing(&real);
        legacy_pairing_for_tests(&real);
        fs::write(real.join(format!("{DEVICE_FILE}{TEMP_INFIX}1-00")), b"stale").unwrap();
        fs::write(real.join(format!("{CREDENTIAL_FILE}{TEMP_INFIX}1-00")), b"stale").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(super::super::device_store::exists(&link));
        wipe(&link).expect("wipe");
        assert!(fs::symlink_metadata(&link).is_err(), "link removed");
        assert!(!real.join(DEVICE_FILE).exists(), "pairing removed from the target");
        assert!(!real.join(CREDENTIAL_FILE).exists(), "legacy pairing removed from the target");
        assert_eq!(fs::read_dir(&real).unwrap().count(), 0, "no temporary copy left");
    }

    /// Windows: the same through a junction.
    #[cfg(windows)]
    #[test]
    fn wipe_through_a_junction_removes_the_pairing() {
        let base = tempfile::tempdir().unwrap();
        let real = base.path().join("elsewhere");
        let link = base.path().join("vettid-desktop");
        device_pairing(&real);
        legacy_pairing_for_tests(&real);
        fs::write(real.join(format!("{DEVICE_FILE}.tmp-1-00")), b"stale").unwrap();
        fs::write(real.join(format!("{CREDENTIAL_FILE}.tmp-1-00")), b"stale").unwrap();
        let out = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&real)
            .output()
            .expect("mklink");
        assert!(out.status.success(), "mklink /J failed");
        assert!(super::super::device_store::exists(&link));
        wipe(&link).expect("wipe");
        assert!(fs::symlink_metadata(&link).is_err(), "junction removed");
        assert!(real.exists(), "the target folder itself is not removed");
        assert_eq!(fs::read_dir(&real).unwrap().count(), 0, "pairing and temporary copies removed");
    }

    /// A wipe removes the folder, a second wipe of nothing is fine, and a
    /// store that clears afterwards doesn't recreate the folder (#28):
    /// log-out must not be undone by a later End session. (Was: an
    /// update of the NATS-era pairing refused with `NotFound`; there is no
    /// update-only save for `device.enc`, so this checks the wipe and the
    /// clear.)
    #[test]
    fn nothing_is_recreated_after_a_wipe() {
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        let mut s = store_for_tests(&config_dir);
        s.save(b"state").unwrap();
        wipe(&config_dir).expect("wipe");
        assert!(!config_dir.exists());
        s.clear().expect("clearing what is gone");
        assert!(!config_dir.exists(), "not recreated");
        assert!(wipe(&config_dir).is_ok(), "nothing there is wiped");
    }

    /// #30: a pairing or Start New Session whose command started before a
    /// log-out's wipe saves nothing afterwards, and creates no folder.
    /// (Now through a `DeviceStore`.)
    #[test]
    fn a_save_that_started_before_a_wipe_writes_nothing() {
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        let since = wipe_epoch();
        wipe(&config_dir).expect("wipe");
        let mut s = store_since_for_tests(&config_dir, Some(since));
        assert!(s.save(b"state").is_err());
        let err = s.take_failure().expect("why");
        assert!(matches!(err, CredentialError::LoggedOutMeanwhile), "got {err}");
        assert_eq!(err.to_string(), LOGGED_OUT_MEANWHILE_NOTICE);
        assert!(!config_dir.exists(), "nothing recreated");
    }

    /// #30: with no wipe since its command started, a save goes ahead as
    /// before. Other tests wipe at the same time (the count is per
    /// process), so an attempt one of them overtook is tried again.
    #[test]
    fn with_no_wipe_since_it_started_a_save_goes_ahead() {
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        let mut saved = false;
        for _ in 0..100 {
            let since = wipe_epoch();
            let mut s = store_since_for_tests(&config_dir, Some(since));
            match s.save(b"state") {
                Ok(()) => {
                    saved = true;
                    break;
                }
                Err(_) => {
                    let err = s.take_failure().expect("why");
                    assert!(matches!(err, CredentialError::LoggedOutMeanwhile), "{err}");
                    assert_ne!(wipe_epoch(), since, "refused with no wipe");
                }
            }
        }
        assert!(saved);
        assert!(super::super::device_store::exists(&config_dir));
    }

    /// #30: log-out deletes the keyring key while it still holds the writer
    /// lock, so a save that starts meanwhile runs only after the key is
    /// gone (it then mints a new one) and is never sealed under the deleted
    /// key. (The waiting save is now a `DeviceStore` save.)
    #[test]
    fn logout_deletes_the_key_before_any_waiting_save_runs() {
        use std::sync::{Arc, Mutex};
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        let other = base.path().join("other");
        device_pairing(&config_dir);
        let order = Arc::new(Mutex::new(Vec::new()));
        let mut saver = None;
        wipe_then(Some(&config_dir), |_| {
            let (order2, other2) = (order.clone(), other.clone());
            let handle = std::thread::spawn(move || {
                store_for_tests(&other2).save_raw_for_tests();
                order2.lock().unwrap().push("saved");
            });
            std::thread::sleep(std::time::Duration::from_millis(150));
            assert!(!handle.is_finished(), "a save ran while log-out held the lock");
            order.lock().unwrap().push("key deleted");
            saver = Some(handle);
            Ok(())
        })
        .expect("wiped");
        saver.unwrap().join().unwrap();
        assert_eq!(*order.lock().unwrap(), ["key deleted", "saved"]);
        assert!(!config_dir.exists());
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
        let wiped = wipe_then(None, |_| {
            deleted = true;
            Ok(())
        });
        assert!(matches!(wiped, Err(CredentialError::NoConfigDir)));
        assert!(deleted);
        assert_ne!(wipe_epoch(), since, "a save that started before is still refused");
    }

    /// #13: a key that can't be confirmed gone fails the log-out's wipe,
    /// even when the folder went: never "removed" on a guess. Every key is
    /// tried.
    #[test]
    fn logout_reports_a_key_not_removed() {
        use crate::credential::protector::testing::{protectors, Behaviour};
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        let b = std::sync::Arc::new(Behaviour::default());
        let remove = |w: &super::super::protector::Wiping| protectors(&b).remove_external_keys(w).map_err(CredentialError::from);
        device_pairing(&config_dir);
        Behaviour::set(&b.fail_remove, true);
        assert!(matches!(wipe_then(Some(&config_dir), remove), Err(CredentialError::IoError(_))));
        assert!(!config_dir.exists(), "the folder itself went");
        assert_eq!(Behaviour::count(&b.legacy_removes), 1, "the legacy entry was tried too");
        Behaviour::set(&b.fail_remove, false);
        device_pairing(&config_dir);
        assert!(wipe_then(Some(&config_dir), remove).is_ok());
        assert_eq!(Behaviour::count(&b.removes), 2);
    }

    /// Windows (#21): a save under a parent another account controls is
    /// refused with the parent notice and leaves an existing pairing as it
    /// was. (Now `device.enc`.)
    #[cfg(windows)]
    #[test]
    fn windows_a_save_under_an_unsafe_parent_changes_nothing() {
        let base = tempfile::tempdir().unwrap();
        let parent = base.path().join("local");
        let config_dir = parent.join("vettid-desktop");
        device_pairing(&config_dir);
        let file = fs::read(config_dir.join(DEVICE_FILE)).unwrap();
        super::super::winacl::test_let_everyone_delete_children(&parent);
        let mut s = store_for_tests(&config_dir);
        assert!(s.save(b"newer state").is_err());
        let err = s.take_failure().expect("why");
        assert!(matches!(err, CredentialError::ParentNotPrivate), "got {err}");
        assert_eq!(err.to_string(), PARENT_NOT_PRIVATE_NOTICE);
        assert_eq!(fs::read(config_dir.join(DEVICE_FILE)).unwrap(), file);
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
        let mut s = store_for_tests(&link.join("vettid-desktop"));
        assert!(s.save(b"state").is_err());
        let err = s.take_failure().expect("why");
        assert!(matches!(err, CredentialError::ParentIsLink), "got {err}");
        assert_eq!(err.to_string(), PARENT_IS_LINK_NOTICE);
        assert!(!real.join("vettid-desktop").exists());
    }

    /// Windows: a save makes the folder and the file private to the user.
    /// (Now `device.enc`.)
    #[cfg(windows)]
    #[test]
    fn windows_save_makes_folder_and_file_user_only() {
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        device_pairing(&config_dir);
        assert!(super::super::winacl::test_is_user_only(&config_dir), "folder");
        assert!(super::super::winacl::test_is_user_only(&config_dir.join(DEVICE_FILE)), "file");
        // A second save over the private file works.
        device_pairing(&config_dir);
    }

    /// Windows: a folder another account can open is refused, and nothing
    /// is written into it. (Now `device.enc`.)
    #[cfg(windows)]
    #[test]
    fn windows_save_refuses_a_shared_folder() {
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        fs::create_dir(&config_dir).unwrap();
        super::super::winacl::test_share_with_everyone(&config_dir);
        let mut s = store_for_tests(&config_dir);
        assert!(s.save(b"state").is_err());
        let err = s.take_failure().expect("why");
        assert!(matches!(err, CredentialError::NotPrivate), "got {err}");
        assert_eq!(err.to_string(), NOT_PRIVATE_NOTICE);
        assert!(!config_dir.join(DEVICE_FILE).exists(), "nothing may be written");
    }

    /// Windows: an existing file another account can open is refused
    /// before it is truncated. (Now `device.enc`.)
    #[cfg(windows)]
    #[test]
    fn windows_save_refuses_a_shared_file_and_keeps_it() {
        let base = tempfile::tempdir().unwrap();
        let config_dir = base.path().join("vettid-desktop");
        device_pairing(&config_dir);
        let file = config_dir.join(DEVICE_FILE);
        let before = fs::read(&file).unwrap();
        super::super::winacl::test_share_with_everyone(&file);
        let mut s = store_for_tests(&config_dir);
        assert!(s.save(b"newer state").is_err());
        let err = s.take_failure().expect("why");
        assert!(matches!(err, CredentialError::NotPrivate), "got {err}");
        assert_eq!(fs::read(&file).unwrap(), before, "not truncated");
    }

    /// The TPM failing gets advice that fits it (signing out doesn't help);
    /// the keyring keeps its own. None claims anything was saved.
    #[test]
    fn a_failing_tpm_is_not_told_to_sign_out() {
        let tpm = super::super::protector::TPM_NAME;
        for e in [CredentialError::NotProtected { by: tpm }, CredentialError::NotOpened { by: tpm }] {
            let text = e.to_string();
            assert!(text.contains(tpm) && !text.to_lowercase().contains("sign out"), "{text}");
        }
        assert!(CredentialError::NotProtected { by: tpm }.to_string().contains("nothing was saved"));
        assert!(CredentialError::NotOpened { by: tpm }.to_string().contains("The pairing is kept"));
        let keyring = CredentialError::NotProtected { by: "your computer's keyring" }.to_string();
        assert!(keyring.contains("sign out of your computer and back in"), "{keyring}");
        assert!(CredentialError::NoProtector.to_string().to_lowercase().contains("nothing was saved"));
    }

    /// A device file whose header names `protector` (nothing else of it is
    /// read by a wipe).
    #[cfg(target_os = "linux")]
    fn sealed_by(dir: &Path, protector: &str) {
        ensure_config_dir(dir).unwrap();
        let header = format!(
            r#"{{"header":{{"v":2,"protector":"{protector}","wrapped_key":"","nonce":"","created_at":0,"notice_shown":false}},"ciphertext":""}}"#
        );
        fs::write(dir.join(DEVICE_FILE), header).unwrap();
    }

    /// The real Linux protectors' removal, with the Secret Service
    /// unreachable (no bus; nothing is connected to).
    #[cfg(target_os = "linux")]
    fn remove_unreachable(w: &super::super::protector::Wiping) -> Result<(), CredentialError> {
        let (ss, legacy) = super::super::secret_service::unreachable_for_tests();
        super::super::protector::Protectors::new(vec![Box::new(ss)], Box::new(legacy)).remove_external_keys(w).map_err(CredentialError::from)
    }

    #[cfg(target_os = "linux")]
    fn marker(dir: &Path) -> PathBuf {
        wipe_marker::path(dir).unwrap()
    }

    /// A wipe that removed the file but not a key, retried: the marker says
    /// what the file was (TPM), so the retry with the Secret Service
    /// unreachable is Ok, and the marker goes last.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_partial_wipe_retried_is_ok() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        sealed_by(&dir, "tpm");
        let first = wipe_then(Some(&dir), |_| Err(CredentialError::IoError("a key, this time".into())));
        assert!(first.is_err());
        assert!(!dir.exists(), "the file went");
        assert!(marker(&dir).exists(), "the marker stays for the retry");
        wipe_then(Some(&dir), |w| {
            assert_eq!(w.sealed_by.as_deref(), Some("tpm"));
            remove_unreachable(w)
        })
        .unwrap();
        assert!(!marker(&dir).exists(), "removed once everything is gone");
    }

    /// No device file and no marker: nothing of a pairing; Ok with the
    /// Secret Service unreachable.
    #[cfg(target_os = "linux")]
    #[test]
    fn no_file_and_no_marker_is_ok() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        wipe_then(Some(&dir), remove_unreachable).unwrap();
        ensure_config_dir(&dir).unwrap();
        wipe_then(Some(&dir), remove_unreachable).unwrap();
        assert!(!marker(&dir).exists());
    }

    /// A file sealed by the Secret Service, with it unreachable: "not
    /// removed", and still so on the retry (from the marker).
    #[cfg(target_os = "linux")]
    #[test]
    fn a_secret_service_file_unreachable_is_not_removed_on_retry_too() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        sealed_by(&dir, "secret-service");
        assert!(wipe_then(Some(&dir), remove_unreachable).is_err());
        assert!(!dir.exists());
        assert!(marker(&dir).exists());
        assert!(wipe_then(Some(&dir), remove_unreachable).is_err(), "the marker remembers");
        assert!(marker(&dir).exists());
        // The marker isn't a pairing.
        assert!(!exists(&dir));
        assert!(!super::super::device_store::exists(&dir));
    }

    /// An earlier format's file with the Secret Service unreachable: its
    /// retirement can't confirm the legacy key (LEGACY_NOT_REMOVED), and
    /// the log-out after it remembers (the marker): "not removed", never a
    /// guess. (A v1 file exists only where an earlier build had a keyring.)
    #[cfg(target_os = "linux")]
    #[test]
    fn legacy_retirement_without_a_secret_service_then_log_out() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        ensure_config_dir(&dir).unwrap();
        fs::write(dir.join(DEVICE_FILE), br#"{"version":1,"binding":"keyring","nonce":[7,7],"ciphertext":[9]}"#).unwrap();
        let (ss, legacy) = super::super::secret_service::unreachable_for_tests();
        let p = super::super::protector::Protectors::new(vec![Box::new(ss)], Box::new(legacy));
        let retired = super::super::device_store::retire_legacy_with(&dir, &p);
        assert!(matches!(retired, Err(CredentialError::LegacyNotRemoved)));
        assert!(!dir.join(DEVICE_FILE).exists(), "the file itself went");
        assert!(marker(&dir).exists());
        assert!(matches!(wipe_then(Some(&dir), remove_unreachable), Err(CredentialError::IoError(_))));
        assert!(marker(&dir).exists());
    }

    /// `connection.enc` removed at unlock: its `master-key-v1` isn't, so the
    /// marker records it, and a log-out with the Secret Service unreachable
    /// is "not removed".
    #[cfg(target_os = "linux")]
    #[test]
    fn removing_connection_enc_leaves_the_legacy_key_to_log_out() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        ensure_config_dir(&dir).unwrap();
        fs::write(dir.join(CREDENTIAL_FILE), b"old").unwrap();
        remove_legacy_pairing(&dir).unwrap();
        assert!(!exists(&dir));
        assert!(marker(&dir).exists());
        assert!(matches!(wipe_then(Some(&dir), remove_unreachable), Err(CredentialError::IoError(_))));
        // With the key confirmed gone (the test protectors), the marker goes.
        let b = std::sync::Arc::new(crate::credential::protector::testing::Behaviour::default());
        wipe_then(Some(&dir), |w| crate::credential::protector::testing::protectors(&b).remove_external_keys(w).map_err(CredentialError::from)).unwrap();
        assert!(!marker(&dir).exists());
    }

    /// Retiring a v1 file doesn't clear the marker of an earlier wipe that
    /// left a Secret Service key: it is restored after, so log-out still
    /// checks.
    #[cfg(target_os = "linux")]
    #[test]
    fn retiring_a_v1_file_keeps_an_earlier_wipes_marker() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        sealed_by(&dir, "secret-service");
        assert!(wipe_then(Some(&dir), remove_unreachable).is_err(), "left the key");
        ensure_config_dir(&dir).unwrap();
        fs::write(dir.join(DEVICE_FILE), br#"{"version":1,"binding":"keyring","nonce":[7,7],"ciphertext":[9]}"#).unwrap();
        let b = std::sync::Arc::new(crate::credential::protector::testing::Behaviour::default());
        let retired = super::super::device_store::retire_legacy_with(&dir, &crate::credential::protector::testing::protectors(&b));
        assert!(retired.unwrap(), "the v1 parts confirmed gone");
        assert!(marker(&dir).exists(), "the earlier wipe's marker stays");
        let err = wipe_then(Some(&dir), |w| {
            assert_eq!(w.sealed_by.as_deref(), Some("secret-service"));
            remove_unreachable(w)
        });
        assert!(err.is_err());
    }

    /// device.unlinked's clear of a Secret Service file that left the key:
    /// the log-out after it remembers it (the marker).
    #[cfg(target_os = "linux")]
    #[test]
    fn a_clear_that_left_a_key_then_log_out_is_not_removed() {
        use vettid_device::store::Persist;
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        sealed_by(&dir, "secret-service");
        let (ss, legacy) = super::super::secret_service::unreachable_for_tests();
        let p = super::super::protector::Protectors::new(vec![Box::new(ss)], Box::new(legacy));
        let mut store = super::super::device_store::DeviceStore::with_protectors(&dir, None, p);
        assert!(store.clear().is_err());
        assert!(!dir.join(DEVICE_FILE).exists(), "the file went");
        assert!(marker(&dir).exists());
        assert!(wipe_then(Some(&dir), remove_unreachable).is_err());
        assert!(marker(&dir).exists());
    }

    /// The marker couldn't be written and the wipe failed partway: a retry
    /// in the same process still knows (memory).
    #[cfg(target_os = "linux")]
    #[test]
    fn a_wipe_whose_marker_wasnt_written_is_remembered() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let parent = base.path().join("parent");
        let dir = parent.join("vettid-desktop");
        sealed_by(&dir, "secret-service");
        // A parent this user can't write to: no marker, and the folder
        // can't be removed either (the wipe fails partway).
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o500)).unwrap();
        // SAFETY: geteuid has no preconditions.
        let root = unsafe { libc::geteuid() } == 0;
        let first = wipe_then(Some(&dir), remove_unreachable);
        let second = wipe_then(Some(&dir), |w| {
            assert_eq!(w.sealed_by.as_deref(), Some("secret-service"), "remembered");
            remove_unreachable(w)
        });
        let marker_written = marker(&dir).exists();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(first.is_err() && second.is_err());
        assert!(root || !marker_written, "root can write it anyway");
    }

    /// #13 (lead decision): the two failure orders of a wipe's parts.
    #[test]
    fn a_wipe_without_a_marker_removes_the_key_first() {
        use std::cell::RefCell;
        let fail = || Err(CredentialError::IoError("no".into()));
        // Recorded: the file, then the keys, both always tried.
        let order = RefCell::new(Vec::new());
        let r = file_then_keys(true, || { order.borrow_mut().push("file"); Ok(()) }, || { order.borrow_mut().push("keys"); fail() });
        assert!(r.is_err());
        assert_eq!(*order.borrow(), ["file", "keys"]);
        // Not recorded, the keys fail: the file is left, as the retry signal.
        let order = RefCell::new(Vec::new());
        let r = file_then_keys(false, || { order.borrow_mut().push("file"); Ok(()) }, || { order.borrow_mut().push("keys"); fail() });
        assert!(r.is_err());
        assert_eq!(*order.borrow(), ["keys"], "the file isn't touched");
        // Not recorded, the keys go, the file can't be removed: an error
        // (the file is left with no key).
        let order = RefCell::new(Vec::new());
        let r = file_then_keys(false, || { order.borrow_mut().push("file"); fail() }, || { order.borrow_mut().push("keys"); Ok(()) });
        assert!(r.is_err());
        assert_eq!(*order.borrow(), ["keys", "file"]);
        assert!(file_then_keys(false, || Ok(()), || Ok(())).is_ok());
    }

    /// #13: no marker could be written and the Secret Service key couldn't
    /// be removed: the device file is kept (the next log-out reads its
    /// header again), where it used to be deleted first.
    #[cfg(target_os = "linux")]
    #[test]
    fn with_no_marker_a_key_not_removed_keeps_the_file() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let parent = base.path().join("parent");
        let dir = parent.join("vettid-desktop");
        sealed_by(&dir, "secret-service");
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o500)).unwrap();
        // SAFETY: geteuid has no preconditions.
        let root = unsafe { libc::geteuid() } == 0;
        let r = wipe_then(Some(&dir), remove_unreachable);
        let kept = dir.join(DEVICE_FILE).exists();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(r.is_err());
        assert!(root || kept, "the file is the retry signal");
    }

    /// #13: the marker can't go next to the folder, so it goes to the
    /// fallback place, and a later process (no memory) still finds it.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_marker_falls_back_and_is_found_after_a_restart() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        wipe_marker::set_fallback_for_tests(Some(state.path().to_path_buf()));
        let parent = base.path().join("parent");
        let dir = parent.join("vettid-desktop");
        sealed_by(&dir, "secret-service");
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o500)).unwrap();
        // SAFETY: geteuid has no preconditions.
        let root = unsafe { libc::geteuid() } == 0;
        let first = wipe_then(Some(&dir), remove_unreachable);
        // A restart: this process's memory of it is gone.
        PENDING_WIPES.lock().unwrap().remove(&dir);
        let found = wipe_marker::read(&dir);
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        wipe_marker::set_fallback_for_tests(None);
        assert!(first.is_err());
        if !root {
            assert_eq!(found.and_then(|w| w.sealed_by).as_deref(), Some("secret-service"), "from the fallback marker");
            let names: Vec<String> = fs::read_dir(state.path().join("vettid-desktop-wipe"))
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            assert!(matches!(&names[..], [n] if n.starts_with("vettid-desktop.") && n.ends_with(".wipe-pending")), "{names:?}");
        }
        // Two config folders of the same name don't share a fallback marker.
        wipe_marker::set_fallback_for_tests(Some(state.path().to_path_buf()));
        let a = wipe_marker::fallback_path_for_tests(Path::new("/one/vettid-desktop"));
        let b = wipe_marker::fallback_path_for_tests(Path::new("/two/vettid-desktop"));
        wipe_marker::set_fallback_for_tests(None);
        assert_ne!(a, b);
    }

    /// #13 (review L3): a fallback folder open to the group isn't used.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_fallback_folder_open_to_others_isnt_used() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let shared = state.path().join("vettid-desktop-wipe");
        fs::create_dir(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o770)).unwrap();
        wipe_marker::set_fallback_for_tests(Some(state.path().to_path_buf()));
        let parent = base.path().join("parent");
        let dir = parent.join("vettid-desktop");
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o500)).unwrap();
        // SAFETY: geteuid has no preconditions.
        let root = unsafe { libc::geteuid() } == 0;
        let written = wipe_marker::write(&dir, &super::super::protector::Wiping::unknown());
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        wipe_marker::set_fallback_for_tests(None);
        assert!(root || written.is_err(), "not written to a folder others can write");
        assert_eq!(fs::read_dir(&shared).unwrap().count(), 0);
        // A marker someone else put there (saying "tpm") isn't believed: it
        // reads as "nothing known", so the sweep stays full.
        wipe_marker::set_fallback_for_tests(Some(state.path().to_path_buf()));
        let forged = wipe_marker::fallback_path_for_tests(&dir).unwrap();
        fs::write(&forged, "vettid-desktop-wipe-v1\ntpm\n0\n").unwrap();
        // Another user's file can't be made without root: a second link to
        // it stands in for "not this build's own file".
        fs::hard_link(&forged, state.path().join("elsewhere")).unwrap();
        let first = wipe_marker::read(&dir);
        let mode = fs::metadata(&shared).unwrap().permissions().mode() & 0o777;
        // After the repair the folder is private, but the planted file is
        // still not trusted (lead review M1): read twice.
        let second = wipe_marker::read(&dir);
        wipe_marker::set_fallback_for_tests(None);
        let unknown = Some(super::super::protector::Wiping::unknown());
        assert_eq!(first, unknown);
        assert_eq!(mode, 0o700, "made private");
        assert_eq!(second, unknown, "still not trusted after the repair");
    }

    /// Round-4 review: a marker that passes every check of `ours` (0600,
    /// one link, this user's, saying "secret-service") but sat in a folder
    /// open to others (so someone could have renamed it into place) reads
    /// as "nothing known" after the repair too: the repair resets it.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_genuine_looking_marker_in_an_open_folder_is_reset() {
        use std::os::unix::fs::PermissionsExt;
        let state = tempfile::tempdir().unwrap();
        let shared = state.path().join("vettid-desktop-wipe");
        fs::create_dir(&shared).unwrap();
        wipe_marker::set_fallback_for_tests(Some(state.path().to_path_buf()));
        let dir = Path::new("/nonexistent-parent-for-test/vettid-desktop");
        let marker = wipe_marker::fallback_path_for_tests(dir).unwrap();
        fs::write(&marker, "vettid-desktop-wipe-v1\nsecret-service\n0\n").unwrap();
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o770)).unwrap();
        let first = wipe_marker::read(dir);
        let mode = fs::metadata(&shared).unwrap().permissions().mode() & 0o777;
        let text = fs::read_to_string(&marker).unwrap();
        let second = wipe_marker::read(dir);
        wipe_marker::set_fallback_for_tests(None);
        let unknown = Some(super::super::protector::Wiping::unknown());
        assert_eq!(first, unknown);
        // The repair ran (so the second read went through it, not the
        // "not private" branch), and rewrote the marker as "nothing known".
        assert_eq!(mode, 0o700, "made private");
        assert_eq!(text, "vettid-desktop-wipe-v1\n?\n1\n", "reset");
        assert_eq!(second, unknown, "reset by the repair, not trusted on the second read");
    }

    /// #13 (lead review): a FIFO where the marker goes neither hangs a read
    /// nor a write (`O_NONBLOCK`), reads as "nothing known", and is replaced
    /// by a real marker when one is written.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_planted_fifo_marker_doesnt_hang_and_isnt_trusted() {
        let state = tempfile::tempdir().unwrap();
        wipe_marker::set_fallback_for_tests(Some(state.path().to_path_buf()));
        let dir = Path::new("/nonexistent-parent-for-test/vettid-desktop");
        let fifo = wipe_marker::fallback_path_for_tests(dir).unwrap();
        fs::create_dir_all(fifo.parent().unwrap()).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(fifo.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path; mkfifo has no other preconditions.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let read = wipe_marker::read(dir);
        // The marker can't go next to a folder whose parent doesn't exist,
        // so it goes to the fallback place, replacing the FIFO.
        let written = wipe_marker::write(dir, &super::super::protector::Wiping { sealed_by: Some("secret-service".into()), legacy: false });
        let after = wipe_marker::read(dir);
        let is_file = fs::symlink_metadata(&fifo).map(|m| m.file_type().is_file()).unwrap_or(false);
        // A marker of ours that others could write isn't trusted either.
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&fifo, fs::Permissions::from_mode(0o644)).unwrap();
        }
        let open_mode = wipe_marker::read(dir);
        wipe_marker::set_fallback_for_tests(None);
        assert_eq!(open_mode, Some(super::super::protector::Wiping::unknown()), "a marker others can write");
        assert_eq!(read, Some(super::super::protector::Wiping::unknown()));
        assert!(written.is_ok(), "{written:?}");
        assert!(is_file);
        assert_eq!(after.and_then(|w| w.sealed_by).as_deref(), Some("secret-service"));
    }

    /// #13 (review M1): retiring an earlier build's `connection.enc` when no
    /// marker can be written keeps it (an error), so a restart still knows
    /// an earlier format was here and log-out sweeps for its key.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_legacy_pairing_is_kept_when_its_removal_cant_be_recorded() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let parent = base.path().join("parent");
        let dir = parent.join("vettid-desktop");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(CREDENTIAL_FILE), b"{}").unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o500)).unwrap();
        // SAFETY: geteuid has no preconditions.
        let root = unsafe { libc::geteuid() } == 0;
        let r = remove_legacy_pairing(&dir);
        let kept = dir.join(CREDENTIAL_FILE).exists();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        PENDING_WIPES.lock().unwrap().remove(&dir);
        if !root {
            assert!(r.is_err());
            assert!(kept, "kept until its removal can be recorded");
        }
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
}
