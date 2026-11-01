//! The master key in Windows Credential Manager, kept on this machine.
//!
//! The `keyring` crate (3.6.3) writes every credential with
//! `CRED_PERSIST_ENTERPRISE`, which roams with a domain profile: the key
//! follows the user to other PCs and the profile server, and a logout on
//! one PC deletes the key another PC uses. This module writes the entry
//! itself with `CRED_PERSIST_LOCAL_MACHINE` (owner decision 3a,
//! 2026-11-01). It is still per user: Credential Manager protects it with
//! the user's DPAPI keys, and other users can't read it. Any process
//! running as the same user can.
//!
//! The entry is a generic credential whose blob is the 32-byte key.

use std::ffi::c_void;
use std::ptr;

use windows_sys::Win32::Foundation::{GetLastError, ERROR_NOT_FOUND};
use windows_sys::Win32::Security::Credentials::{
    CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE,
    CRED_TYPE_GENERIC,
};
use zeroize::Zeroizing;

/// The credential's target name. Distinct from the name the `keyring`
/// crate used (`master-key-v1.vettid-desktop`), so an entry left by an
/// earlier development build is never read as this one.
const TARGET: &str = "vettid-desktop/master-key-v1/local";

const KEY_LEN: usize = 32;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The stored key: `Ok(None)` when there is no entry.
pub(crate) fn read() -> Result<Option<Zeroizing<[u8; KEY_LEN]>>, String> {
    read_target(TARGET)
}

/// Store `key`, replacing any entry, persisted on this machine only.
pub(crate) fn write(key: &[u8; KEY_LEN]) -> Result<(), String> {
    write_target(TARGET, key)
}

/// Delete the entry. A missing entry counts as deleted.
pub(crate) fn delete() -> Result<(), String> {
    delete_target(TARGET)
}

fn read_target(target: &str) -> Result<Option<Zeroizing<[u8; KEY_LEN]>>, String> {
    let target_w = wide(target);
    let mut cred: *mut CREDENTIALW = ptr::null_mut();
    // SAFETY: `target_w` is NUL-terminated and outlives the call; `cred`
    // receives a pointer that is freed with CredFree below.
    let ok = unsafe { CredReadW(target_w.as_ptr(), CRED_TYPE_GENERIC, 0, &mut cred) };
    if ok == 0 {
        // SAFETY: reads the calling thread's last-error value.
        let err = unsafe { GetLastError() };
        return if err == ERROR_NOT_FOUND {
            Ok(None)
        } else {
            Err(format!("CredReadW failed (error {})", err))
        };
    }

    // SAFETY: CredReadW succeeded, so `cred` points to a CREDENTIALW whose
    // blob holds `CredentialBlobSize` bytes; both stay valid until CredFree.
    let result = unsafe {
        let c = &*cred;
        let size = c.CredentialBlobSize as usize;
        let blob: &mut [u8] = if c.CredentialBlob.is_null() || size == 0 {
            &mut []
        } else {
            std::slice::from_raw_parts_mut(c.CredentialBlob, size)
        };
        let result = if blob.len() == KEY_LEN {
            let mut key = Zeroizing::new([0u8; KEY_LEN]);
            key.copy_from_slice(blob);
            Ok(Some(key))
        } else {
            Err(format!("unexpected key length: {}", blob.len()))
        };
        // SECURITY: wipe the system's copy of the key before freeing it.
        for b in blob.iter_mut() {
            ptr::write_volatile(b, 0);
        }
        result
    };
    // SAFETY: `cred` came from CredReadW and is freed once.
    unsafe { CredFree(cred as *const c_void) };
    result
}

fn write_target(target: &str, key: &[u8; KEY_LEN]) -> Result<(), String> {
    let mut target_w = wide(target);
    // CredWriteW takes a mutable blob pointer but does not write to it;
    // the copy is wiped on drop.
    let mut blob = Zeroizing::new(*key);
    // SAFETY: CREDENTIALW is plain data, valid when zeroed.
    let mut cred: CREDENTIALW = unsafe { std::mem::zeroed() };
    cred.Type = CRED_TYPE_GENERIC;
    cred.TargetName = target_w.as_mut_ptr();
    cred.CredentialBlobSize = KEY_LEN as u32;
    cred.CredentialBlob = blob.as_mut_ptr();
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE;
    // SAFETY: every pointer in `cred` points to a live local buffer.
    let ok = unsafe { CredWriteW(&cred, 0) };
    if ok == 0 {
        // SAFETY: reads the calling thread's last-error value.
        let err = unsafe { GetLastError() };
        return Err(format!("CredWriteW failed (error {})", err));
    }
    Ok(())
}

fn delete_target(target: &str) -> Result<(), String> {
    let target_w = wide(target);
    // SAFETY: `target_w` is NUL-terminated and outlives the call.
    let ok = unsafe { CredDeleteW(target_w.as_ptr(), CRED_TYPE_GENERIC, 0) };
    if ok == 0 {
        // SAFETY: reads the calling thread's last-error value.
        let err = unsafe { GetLastError() };
        if err != ERROR_NOT_FOUND {
            return Err(format!("CredDeleteW failed (error {})", err));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::Credentials::CRED_PERSIST_ENTERPRISE;

    /// A target of its own per test run, so the real entry is never
    /// touched and parallel runs don't collide.
    fn test_target(name: &str) -> String {
        format!("vettid-desktop/test/{}/{}", name, std::process::id())
    }

    /// The persistence the entry was stored with.
    fn persist_of(target: &str) -> Option<u32> {
        let target_w = wide(target);
        let mut cred: *mut CREDENTIALW = ptr::null_mut();
        // SAFETY: as in read_target.
        let ok = unsafe { CredReadW(target_w.as_ptr(), CRED_TYPE_GENERIC, 0, &mut cred) };
        if ok == 0 {
            return None;
        }
        // SAFETY: CredReadW succeeded; `cred` is valid until CredFree.
        let persist = unsafe { (*cred).Persist };
        // SAFETY: `cred` came from CredReadW and is freed once; it is not
        // used afterwards.
        unsafe { CredFree(cred as *const c_void) };
        Some(persist)
    }

    /// Deletes the test entry when dropped, so a failing assertion does
    /// not leave it in the user's Credential Manager.
    struct Cleanup<'a>(&'a str);

    impl Drop for Cleanup<'_> {
        fn drop(&mut self) {
            let _ = delete_target(self.0);
        }
    }

    /// Against the real Credential Manager of the user running the tests.
    /// The key is a fixed test value and is never printed.
    #[test]
    fn round_trip_is_local_machine_and_delete_removes_it() {
        let target = test_target("round-trip");
        let _ = delete_target(&target);
        let _cleanup = Cleanup(&target);
        assert!(read_target(&target).unwrap().is_none(), "no entry before the write");

        let key = [0x5au8; KEY_LEN];
        write_target(&target, &key).expect("write");
        let read = read_target(&target).unwrap().expect("entry after the write");
        assert_eq!(*read, key);
        assert_eq!(persist_of(&target), Some(CRED_PERSIST_LOCAL_MACHINE));
        assert_ne!(persist_of(&target), Some(CRED_PERSIST_ENTERPRISE), "must not roam");

        // A second write replaces the key.
        let other = [0xa5u8; KEY_LEN];
        write_target(&target, &other).expect("rewrite");
        assert_eq!(*read_target(&target).unwrap().unwrap(), other);

        delete_target(&target).expect("delete");
        assert!(read_target(&target).unwrap().is_none(), "deleted");
        // Deleting again is not an error.
        delete_target(&target).expect("delete twice");
    }

    #[test]
    fn missing_entry_reads_as_none() {
        let target = test_target("missing");
        let _ = delete_target(&target);
        let _cleanup = Cleanup(&target);
        assert!(read_target(&target).unwrap().is_none());
    }
}
