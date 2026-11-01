//! A user-only folder and file for the saved pairing on Windows (#16,
//! owner decision 1a, 2026-11-01).
//!
//! Unix uses mode bits (`0600`). On Windows a new file inherits its
//! folder's ACL, which is fine in the default `%LOCALAPPDATA%` but not in
//! a redirected folder or one someone else made in advance. So:
//!
//! - **New folder:** created owned by the current user, with a protected
//!   DACL that grants only the current user and SYSTEM (inherited by what
//!   is created inside it).
//! - **The file:** given the same protected, user-and-SYSTEM DACL right
//!   after it is opened and before any data is written.
//! - **An existing folder or file** is checked first and refused (nothing
//!   is changed or written) when:
//!   - it is a reparse point (a symlink or junction could point anywhere);
//!   - its owner is not the current user, SYSTEM or Administrators;
//!   - it has a NULL DACL (everyone has full access);
//!   - an allow entry grants anyone other than the current user, SYSTEM or
//!     Administrators, or is an allow type other than a plain one (object
//!     and callback entries are not interpreted here, so they are refused).
//!
//!   Deny entries only take access away, so they are accepted.
//!   Administrators are accepted in an existing ACL because they can take
//!   ownership of any file on the machine anyway; the folder and file this
//!   module creates do not grant them access.
//!
//! The check reads security information, which needs no rights beyond
//! READ_CONTROL; an object the user can't even read the ACL of is refused.

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_ALREADY_EXISTS, ERROR_SUCCESS, HANDLE, HLOCAL,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    GetNamedSecurityInfoW, SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    EqualSid, GetAce, GetSecurityDescriptorDacl, GetTokenInformation,
    IsWellKnownSid, TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid, ACCESS_ALLOWED_ACE,
    ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// ACE types (ACE_HEADER.AceType).
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x0;
const ACCESS_DENIED_ACE_TYPE: u8 = 0x1;
const SYSTEM_AUDIT_ACE_TYPE: u8 = 0x2;
const SYSTEM_ALARM_ACE_TYPE: u8 = 0x3;
const ACCESS_DENIED_OBJECT_ACE_TYPE: u8 = 0x6;
const ACCESS_DENIED_CALLBACK_ACE_TYPE: u8 = 0xA;
const ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE: u8 = 0xC;

/// Why a folder or file is not private to the current user. The detail is
/// for the log; the person sees one plain notice.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NotPrivate {
    ReparsePoint,
    ForeignOwner,
    NullDacl,
    ForeignAccess,
    UnknownAllowEntry,
    Unreadable(String),
}

impl std::fmt::Display for NotPrivate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReparsePoint => f.write_str("is a symlink or junction"),
            Self::ForeignOwner => f.write_str("is owned by another account"),
            Self::NullDacl => f.write_str("has no access list (everyone has access)"),
            Self::ForeignAccess => f.write_str("grants access to another account"),
            Self::UnknownAllowEntry => f.write_str("has an access entry this app does not check"),
            Self::Unreadable(e) => write!(f, "its permissions could not be read ({})", e),
        }
    }
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

fn wide_str(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Frees a LocalAlloc'd pointer on drop.
struct LocalBox(*mut c_void);

impl Drop for LocalBox {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer was allocated by the system with
            // LocalAlloc (documented for each call that fills a LocalBox)
            // and is freed once.
            unsafe { LocalFree(self.0 as HLOCAL) };
        }
    }
}

/// The current process user's SID, as a byte copy.
fn current_user_sid() -> Result<Vec<u8>, String> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo-handle; `token` receives a
    // real handle, closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(format!("OpenProcessToken failed (error {})", unsafe { GetLastError() }));
    }
    let mut needed: u32 = 0;
    // SAFETY: a size query with no buffer.
    unsafe { GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut needed) };
    // u64 elements keep the buffer aligned for TOKEN_USER.
    let mut buf = vec![0u64; (needed as usize).div_ceil(8).max(1)];
    // SAFETY: `buf` holds at least `needed` bytes.
    let ok = unsafe {
        GetTokenInformation(token, TokenUser, buf.as_mut_ptr() as *mut c_void, needed, &mut needed)
    };
    // SAFETY: `token` was opened above and is closed once.
    unsafe { CloseHandle(token) };
    if ok == 0 {
        return Err(format!("GetTokenInformation failed (error {})", unsafe { GetLastError() }));
    }
    // SAFETY: on success `buf` holds a TOKEN_USER whose SID points inside it.
    let sid = unsafe { (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid };
    sid_bytes(sid)
}

/// A copy of the SID at `sid`.
fn sid_bytes(sid: PSID) -> Result<Vec<u8>, String> {
    // SID layout: revision (1), sub-authority count (1), authority (6),
    // then 4 bytes per sub-authority.
    // SAFETY: `sid` points to a valid SID, whose length follows from its
    // second byte.
    unsafe {
        let count = *(sid as *const u8).add(1) as usize;
        let len = 8 + 4 * count;
        Ok(std::slice::from_raw_parts(sid as *const u8, len).to_vec())
    }
}

fn sid_string(sid: &[u8]) -> Result<String, String> {
    let mut out: *mut u16 = ptr::null_mut();
    // SAFETY: `sid` is a valid SID; `out` receives a LocalAlloc'd string.
    if unsafe { ConvertSidToStringSidW(sid.as_ptr() as PSID, &mut out) } == 0 {
        return Err(format!("ConvertSidToStringSidW failed (error {})", unsafe { GetLastError() }));
    }
    let _free = LocalBox(out as *mut c_void);
    // SAFETY: `out` is a NUL-terminated wide string.
    let len = (0..).take_while(|&i| unsafe { *out.add(i) } != 0).count();
    Ok(String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(out, len) }))
}

/// A parsed security descriptor from SDDL, freed on drop.
struct Descriptor(LocalBox);

impl Descriptor {
    fn from_sddl(sddl: &str) -> Result<Self, String> {
        let sddl_w = wide_str(sddl);
        let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: `sddl_w` is NUL-terminated; `sd` receives a LocalAlloc'd
        // descriptor.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_w.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(format!("SDDL conversion failed (error {})", unsafe { GetLastError() }));
        }
        Ok(Self(LocalBox(sd)))
    }

    fn ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.0 .0
    }

    fn dacl(&self) -> Result<*mut ACL, String> {
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl: *mut ACL = ptr::null_mut();
        // SAFETY: `self` holds a valid descriptor; the DACL points inside it.
        let ok = unsafe { GetSecurityDescriptorDacl(self.ptr(), &mut present, &mut dacl, &mut defaulted) };
        if ok == 0 || present == 0 || dacl.is_null() {
            return Err("descriptor has no DACL".to_string());
        }
        Ok(dacl)
    }
}

/// SDDL for the folder: owned by `user`, protected DACL, full access for
/// `user` and SYSTEM, inherited by files and subfolders.
fn folder_sddl(user: &str) -> String {
    format!("O:{user}D:P(A;OICI;FA;;;{user})(A;OICI;FA;;;SY)")
}

/// SDDL for the file: protected DACL, full access for `user` and SYSTEM.
fn file_sddl(user: &str) -> String {
    format!("D:P(A;;FA;;;{user})(A;;FA;;;SY)")
}

fn is_trusted(sid: PSID, user: &[u8]) -> bool {
    // SAFETY: `sid` and `user` are valid SIDs.
    unsafe {
        EqualSid(sid, user.as_ptr() as PSID) != 0
            || IsWellKnownSid(sid, WinLocalSystemSid) != 0
            || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
    }
}

/// The owner and DACL of `path`, judged against `user`.
fn check_private_with(path: &Path, user: &[u8]) -> Result<(), NotPrivate> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| NotPrivate::Unreadable(e.to_string()))?;
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || meta.file_type().is_symlink() {
            return Err(NotPrivate::ReparsePoint);
        }
    }

    let path_w = wide_path(path);
    let mut owner: PSID = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `path_w` is NUL-terminated; on success `sd` is a LocalAlloc'd
    // descriptor that `owner` and `dacl` point into, freed by `_sd`.
    let status = unsafe {
        GetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut sd,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(NotPrivate::Unreadable(format!("GetNamedSecurityInfoW error {}", status)));
    }
    let _sd = LocalBox(sd);

    if owner.is_null() || !is_trusted(owner, user) {
        return Err(NotPrivate::ForeignOwner);
    }
    if dacl.is_null() {
        return Err(NotPrivate::NullDacl);
    }
    // SAFETY: `dacl` points to a valid ACL inside `sd`.
    let count = unsafe { (*dacl).AceCount } as u32;
    for index in 0..count {
        let mut ace: *mut c_void = ptr::null_mut();
        // SAFETY: `index` is below the ACL's entry count.
        if unsafe { GetAce(dacl, index, &mut ace) } == 0 || ace.is_null() {
            return Err(NotPrivate::Unreadable("GetAce failed".to_string()));
        }
        // SAFETY: every ACE starts with an ACE_HEADER.
        let header = unsafe { *(ace as *const ACE_HEADER) };
        match header.AceType {
            ACCESS_ALLOWED_ACE_TYPE => {
                // SAFETY: a plain allow ACE is an ACCESS_ALLOWED_ACE whose
                // SID starts at SidStart.
                let sid = unsafe { &(*(ace as *const ACCESS_ALLOWED_ACE)).SidStart as *const u32 as PSID };
                if !is_trusted(sid, user) {
                    return Err(NotPrivate::ForeignAccess);
                }
            }
            ACCESS_DENIED_ACE_TYPE
            | ACCESS_DENIED_OBJECT_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
            | SYSTEM_AUDIT_ACE_TYPE
            | SYSTEM_ALARM_ACE_TYPE => {}
            _ => return Err(NotPrivate::UnknownAllowEntry),
        }
    }
    Ok(())
}

/// Check an existing folder or file: see the module documentation.
pub(crate) fn check_private(path: &Path) -> Result<(), NotPrivate> {
    let user = current_user_sid().map_err(NotPrivate::Unreadable)?;
    check_private_with(path, &user)
}

/// Make sure `dir` exists and is private to the current user. Its parent
/// folders are created as usual if missing. A new `dir` gets the user-only
/// DACL; an existing one is only checked.
pub(crate) fn ensure_private_dir(dir: &Path) -> Result<(), NotPrivate> {
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent).map_err(|e| NotPrivate::Unreadable(e.to_string()))?;
    }
    let user = current_user_sid().map_err(NotPrivate::Unreadable)?;
    let sd = Descriptor::from_sddl(&folder_sddl(&sid_string(&user).map_err(NotPrivate::Unreadable)?))
        .map_err(NotPrivate::Unreadable)?;
    let attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.ptr(),
        bInheritHandle: 0,
    };
    let dir_w = wide_path(dir);
    // SAFETY: `dir_w` is NUL-terminated and `attrs` points to a valid
    // descriptor that outlives the call.
    if unsafe { CreateDirectoryW(dir_w.as_ptr(), &attrs) } == 0 {
        // SAFETY: reads the calling thread's last-error value.
        let err = unsafe { GetLastError() };
        if err != ERROR_ALREADY_EXISTS {
            return Err(NotPrivate::Unreadable(format!("CreateDirectoryW error {}", err)));
        }
    }
    // Checked whether it was just made or already there.
    check_private_with(dir, &user)
}

/// Give the file at `path` the protected, user-and-SYSTEM DACL, then check
/// it. Called after the file is opened and before any data is written.
pub(crate) fn protect_file(path: &Path) -> Result<(), NotPrivate> {
    let user = current_user_sid().map_err(NotPrivate::Unreadable)?;
    let sd = Descriptor::from_sddl(&file_sddl(&sid_string(&user).map_err(NotPrivate::Unreadable)?))
        .map_err(NotPrivate::Unreadable)?;
    let dacl = sd.dacl().map_err(NotPrivate::Unreadable)?;
    let path_w = wide_path(path);
    // SAFETY: `path_w` is NUL-terminated; `dacl` points into `sd`, which
    // outlives the call.
    let status = unsafe {
        SetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(NotPrivate::Unreadable(format!("SetNamedSecurityInfoW error {}", status)));
    }
    check_private_with(path, &user)
}

/// Whether `path`'s DACL is protected (does not inherit). For tests.
#[cfg(test)]
fn dacl_is_protected(path: &Path) -> bool {
    use windows_sys::Win32::Security::{GetSecurityDescriptorControl, SE_DACL_PROTECTED};
    let path_w = wide_path(path);
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    // SAFETY: as in check_private_with.
    let status = unsafe {
        GetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut sd,
        )
    };
    if status != ERROR_SUCCESS {
        return false;
    }
    let _sd = LocalBox(sd);
    let mut control: u16 = 0;
    let mut revision: u32 = 0;
    // SAFETY: `sd` is a valid descriptor.
    unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) };
    control & SE_DACL_PROTECTED != 0
}

/// The SIDs granted access by `path`'s allow entries, as strings. For tests.
#[cfg(test)]
fn allowed_sids(path: &Path) -> Vec<String> {
    let path_w = wide_path(path);
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    // SAFETY: as in check_private_with.
    let status = unsafe {
        GetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut sd,
        )
    };
    assert_eq!(status, ERROR_SUCCESS);
    let _sd = LocalBox(sd);
    let mut out = Vec::new();
    // SAFETY: as in check_private_with.
    let count = unsafe { (*dacl).AceCount } as u32;
    for index in 0..count {
        let mut ace: *mut c_void = ptr::null_mut();
        unsafe { GetAce(dacl, index, &mut ace) };
        let header = unsafe { *(ace as *const ACE_HEADER) };
        if header.AceType == ACCESS_ALLOWED_ACE_TYPE {
            let sid = unsafe { &(*(ace as *const ACCESS_ALLOWED_ACE)).SidStart as *const u32 as PSID };
            out.push(sid_string(&sid_bytes(sid).unwrap()).unwrap());
        }
    }
    out
}

/// For tests elsewhere in the crate: give `path` a DACL that also grants
/// Everyone read access.
#[cfg(test)]
pub(crate) fn test_share_with_everyone(path: &Path) {
    let me = sid_string(&current_user_sid().unwrap()).unwrap();
    tests::set_dacl(path, &format!("D:P(A;OICI;FA;;;{me})(A;OICI;FA;;;SY)(A;OICI;FR;;;WD)"));
}

/// For tests elsewhere in the crate: whether `path` is protected and
/// grants only the current user and SYSTEM.
#[cfg(test)]
pub(crate) fn test_is_user_only(path: &Path) -> bool {
    let me = sid_string(&current_user_sid().unwrap()).unwrap();
    let mut sids = allowed_sids(path);
    sids.sort();
    sids.dedup();
    let mut want = vec![me, "S-1-5-18".to_string()];
    want.sort();
    dacl_is_protected(path) && sids == want
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Replace `path`'s DACL with one from `dacl_sddl` (e.g. "D:P(...)").
    pub(super) fn set_dacl(path: &Path, dacl_sddl: &str) {
        let sd = Descriptor::from_sddl(dacl_sddl).expect("sddl");
        let dacl = sd.dacl().expect("dacl");
        let path_w = wide_path(path);
        let status = unsafe {
            SetNamedSecurityInfoW(
                path_w.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                dacl,
                ptr::null(),
            )
        };
        assert_eq!(status, ERROR_SUCCESS, "SetNamedSecurityInfoW");
    }

    fn me() -> String {
        sid_string(&current_user_sid().unwrap()).unwrap()
    }

    #[test]
    fn new_folder_is_owned_by_the_user_and_grants_only_user_and_system() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        ensure_private_dir(&dir).expect("private dir");
        assert!(dir.is_dir());
        assert!(dacl_is_protected(&dir), "the DACL must not inherit");
        let mut sids = allowed_sids(&dir);
        sids.sort();
        sids.dedup();
        let mut want = vec![me(), "S-1-5-18".to_string()];
        want.sort();
        assert_eq!(sids, want);
        // Calling it again on the existing folder passes the check.
        ensure_private_dir(&dir).expect("existing private dir");
    }

    #[test]
    fn file_gets_the_user_only_dacl() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        ensure_private_dir(&dir).unwrap();
        let file = dir.join("connection.enc");
        std::fs::write(&file, b"").unwrap();
        protect_file(&file).expect("protect");
        assert!(dacl_is_protected(&file));
        let mut sids = allowed_sids(&file);
        sids.sort();
        let mut want = vec![me(), "S-1-5-18".to_string()];
        want.sort();
        assert_eq!(sids, want);
    }

    #[test]
    fn existing_folder_granting_another_account_is_refused() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        std::fs::create_dir(&dir).unwrap();
        // Everyone (WD) and Authenticated Users (AU) may read.
        for extra in ["(A;OICI;FR;;;WD)", "(A;OICI;FR;;;AU)", "(A;OICI;FA;;;BU)"] {
            set_dacl(&dir, &format!("D:P(A;OICI;FA;;;{})(A;OICI;FA;;;SY){}", me(), extra));
            assert_eq!(ensure_private_dir(&dir), Err(NotPrivate::ForeignAccess), "{extra}");
            assert_eq!(check_private(&dir), Err(NotPrivate::ForeignAccess), "{extra}");
        }
    }

    #[test]
    fn existing_file_granting_another_account_is_refused() {
        let base = tempfile::tempdir().unwrap();
        let file = base.path().join("connection.enc");
        std::fs::write(&file, b"x").unwrap();
        set_dacl(&file, &format!("D:P(A;;FA;;;{})(A;;FR;;;WD)", me()));
        assert_eq!(check_private(&file), Err(NotPrivate::ForeignAccess));
    }

    #[test]
    fn administrators_and_deny_entries_are_accepted() {
        let base = tempfile::tempdir().unwrap();
        let file = base.path().join("f");
        std::fs::write(&file, b"x").unwrap();
        set_dacl(&file, &format!("D:P(D;;FW;;;WD)(A;;FA;;;{})(A;;FA;;;SY)(A;;FA;;;BA)", me()));
        assert_eq!(check_private(&file), Ok(()));
    }

    #[test]
    fn junction_is_refused() {
        let base = tempfile::tempdir().unwrap();
        let target = base.path().join("elsewhere");
        std::fs::create_dir(&target).unwrap();
        let link = base.path().join("vettid-desktop");
        // A directory junction needs no privilege.
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&target)
            .output()
            .expect("mklink");
        assert!(status.status.success(), "mklink /J failed");
        assert_eq!(check_private(&link), Err(NotPrivate::ReparsePoint));
        assert_eq!(ensure_private_dir(&link), Err(NotPrivate::ReparsePoint));
    }

    #[test]
    fn sddl_strings() {
        assert_eq!(folder_sddl("S-1-5-21-1"), "O:S-1-5-21-1D:P(A;OICI;FA;;;S-1-5-21-1)(A;OICI;FA;;;SY)");
        assert_eq!(file_sddl("S-1-5-21-1"), "D:P(A;;FA;;;S-1-5-21-1)(A;;FA;;;SY)");
    }
}
