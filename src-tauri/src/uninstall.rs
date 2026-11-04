//! The uninstaller's wipe of the saved pairing: `vettid-desktop.exe
//! --uninstall-wipe`, run by the Windows uninstaller's hook
//! (`windows/installer-hooks.nsh`) before it removes the program.
//!
//! It is log-out's local half ([`store::wipe_for_logout`]): the pairing
//! folder, the device file and its temporary copies, the earlier builds'
//! pairing, every protector's external key (none for DPAPI) and the
//! earlier format's Credential Manager entry, each confirmed gone. It does
//! not contact the vault: a desktop can't unlink itself (VAULT-MESSAGING
//! §7.4), and an uninstall must not wait on the network. The person is
//! told to remove the desktop on their phone.
//!
//! `main` handles it before anything else (no Tauri, no window, no
//! single-instance plugin, no logger), so it never reaches a running
//! app. It prints nothing.
//!
//! Who can run it: anyone who can run a program as this Windows user. That
//! person can already delete the user's files and Credential Manager
//! entries, which is all this does, so it grants nothing new.

use std::path::{Path, PathBuf};

use crate::credential::store::{self, CredentialError};

/// The command-line switch, the only argument.
pub const ARG: &str = "--uninstall-wipe";

/// Exit code: nothing was paired here (no pairing file), and nothing that
/// was asked to be removed is left.
pub const NOTHING_PAIRED: i32 = 0;
/// Exit code: a pairing was saved here, and every part of it is confirmed
/// gone.
pub const PAIRING_REMOVED: i32 = 10;
/// Exit code: something couldn't be removed, or its removal couldn't be
/// confirmed (also: no user folder, or a panic). Never reported as gone.
pub const NOT_REMOVED: i32 = 20;

/// Whether the command line asks for the wipe: exactly the program and
/// [`ARG`].
pub fn requested<I: IntoIterator<Item = std::ffi::OsString>>(args: I) -> bool {
    let mut args = args.into_iter().skip(1);
    matches!((args.next(), args.next()), (Some(a), None) if a == ARG)
}

/// Run the wipe and return the exit code. A panic is [`NOT_REMOVED`], and
/// prints nothing.
pub fn run() -> i32 {
    std::panic::set_hook(Box::new(|_| {}));
    std::panic::catch_unwind(|| {
        outcome(store::default_config_dir(), store::pairing_may_be_present, store::wipe_for_logout)
    })
    .unwrap_or(NOT_REMOVED)
}

/// [`run`]'s work, with the folder, the presence check and the wipe passed
/// in, so tests never reach the real folder or keys. "Paired" is decided
/// before the wipe, from the files (one that can't be checked counts as
/// there). With no folder the keys are still removed, and the result is
/// [`NOT_REMOVED`], as at log-out.
fn outcome(
    config_dir: Result<PathBuf, CredentialError>,
    present: impl FnOnce(&Path) -> bool,
    wipe: impl FnOnce(Option<&Path>) -> Result<(), CredentialError>,
) -> i32 {
    // SECURITY: never wipe a relative path; `default_config_dir` returns
    // only absolute ones, this guards the destructive step on its own.
    let config_dir = config_dir.ok().filter(|dir| dir.is_absolute());
    let paired = config_dir.as_deref().map(present);
    match (wipe(config_dir.as_deref()), paired) {
        (Ok(()), Some(true)) => PAIRING_REMOVED,
        (Ok(()), Some(false)) => NOTHING_PAIRED,
        _ => NOT_REMOVED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("vettid-uninstall-test-{}-{:016x}", std::process::id(), rand::random::<u64>()));
        d.join("vettid-desktop")
    }

    fn failed() -> CredentialError {
        CredentialError::IoError("test".into())
    }

    #[test]
    fn the_switch_must_be_the_only_argument() {
        let args = |a: &[&str]| a.iter().map(std::ffi::OsString::from).collect::<Vec<_>>();
        assert!(requested(args(&["vettid-desktop.exe", "--uninstall-wipe"])));
        assert!(!requested(args(&["vettid-desktop.exe"])));
        assert!(!requested(args(&["vettid-desktop.exe", "--uninstall-wipe", "x"])));
        assert!(!requested(args(&["vettid-desktop.exe", "x", "--uninstall-wipe"])));
        assert!(!requested(args(&["vettid-desktop.exe", "--uninstall-wipe=1"])));
        assert!(!requested(args(&["--uninstall-wipe"])));
    }

    #[test]
    fn the_exit_code_says_what_was_there_and_what_is_gone() {
        let d = dir();
        assert_eq!(outcome(Ok(d.clone()), |_| false, |_| Ok(())), NOTHING_PAIRED);
        assert_eq!(outcome(Ok(d.clone()), |_| true, |_| Ok(())), PAIRING_REMOVED);
        assert_eq!(outcome(Ok(d.clone()), |_| true, |_| Err(failed())), NOT_REMOVED);
        // A key not removed with no file there is still not removed.
        assert_eq!(outcome(Ok(d), |_| false, |_| Err(failed())), NOT_REMOVED);
    }

    #[test]
    fn no_folder_still_removes_the_keys_and_is_not_removed() {
        let wiped = Cell::new(false);
        let code = outcome(Err(CredentialError::NoConfigDir), |_| panic!("no folder to check"), |dir| {
            assert!(dir.is_none());
            wiped.set(true);
            Ok(())
        });
        assert_eq!(code, NOT_REMOVED);
        assert!(wiped.get());
    }

    #[test]
    fn a_relative_folder_is_never_wiped() {
        let code = outcome(Ok(PathBuf::from("vettid-desktop")), |_| panic!("not checked"), |dir| {
            assert!(dir.is_none(), "a relative folder reached the wipe");
            Ok(())
        });
        assert_eq!(code, NOT_REMOVED);
    }

    #[test]
    fn presence_is_decided_before_the_wipe() {
        let d = dir();
        let order = Cell::new(0);
        let code = outcome(
            Ok(d),
            |_| {
                assert_eq!(order.replace(1), 0);
                true
            },
            |_| {
                assert_eq!(order.replace(2), 1);
                Ok(())
            },
        );
        assert_eq!(code, PAIRING_REMOVED);
    }

    /// With the real presence check and the store's file wipe (not the
    /// keys: tests never reach the real Credential Manager) on a temporary
    /// folder.
    #[test]
    fn the_files_decide_paired() {
        let d = dir();
        let wipe = |dir: Option<&Path>| store::wipe(dir.expect("a folder"));
        // No folder at all.
        assert_eq!(outcome(Ok(d.clone()), store::pairing_may_be_present, wipe), NOTHING_PAIRED);
        // An empty folder.
        std::fs::create_dir_all(&d).unwrap();
        assert_eq!(outcome(Ok(d.clone()), store::pairing_may_be_present, wipe), NOTHING_PAIRED);
        assert!(!d.exists());
        // The device file, the earlier builds' file, or only a temporary copy.
        for name in ["device.enc", "connection.enc", "device.enc.tmp-1-0000000000000000"] {
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join(name), b"x").unwrap();
            assert_eq!(outcome(Ok(d.clone()), store::pairing_may_be_present, wipe), PAIRING_REMOVED, "{name}");
            assert!(!d.exists(), "{name}");
        }
        let _ = std::fs::remove_dir_all(d.parent().unwrap());
    }

    /// A device file held open without delete sharing can't be removed:
    /// not removed, and the file is kept.
    #[cfg(windows)]
    #[test]
    fn a_file_that_cant_be_removed_is_not_removed() {
        use std::os::windows::fs::OpenOptionsExt;
        let d = dir();
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("device.enc"), b"x").unwrap();
        let held = std::fs::OpenOptions::new().read(true).share_mode(0).open(d.join("device.enc")).unwrap();
        let wipe = |dir: Option<&Path>| store::wipe(dir.expect("a folder"));
        assert_eq!(outcome(Ok(d.clone()), store::pairing_may_be_present, wipe), NOT_REMOVED);
        drop(held);
        assert!(d.join("device.enc").exists());
        let _ = std::fs::remove_dir_all(d.parent().unwrap());
    }
}
