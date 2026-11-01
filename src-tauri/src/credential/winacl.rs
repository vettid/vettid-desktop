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
//! - **The file:** opened without truncating, given the protected
//!   user-and-SYSTEM DACL through the open handle and checked again on that
//!   handle; only then is it emptied and written ([`open_private_file`]).
//! - **An existing folder or file** is checked first and refused (nothing
//!   is changed or written) when:
//!   - it is a reparse point (a symlink or junction could point anywhere);
//!   - its owner is not the current user, SYSTEM or Administrators;
//!   - it has a NULL DACL (everyone has full access);
//!   - an allow entry grants anyone other than the current user, SYSTEM or
//!     Administrators (inherit-only entries included, since new files
//!     would get them; CREATOR OWNER and OWNER RIGHTS count as others), or
//!     is an allow type other than a plain one (object, callback and
//!     compound entries are not interpreted here, so they are refused).
//!
//!   Deny entries only take access away, so they are accepted.
//!   Administrators are accepted in an existing ACL because they can take
//!   ownership of any file on the machine anyway, and the default
//!   `%LOCALAPPDATA%` grants them access; the folder and file this module
//!   creates do not.
//!
//! A policy refusal is [`AclError::NotPrivate`], shown to the person as
//! "another account can open this folder". Anything that merely failed
//! (a security call, creating the folder, a stat error) is
//! [`AclError::Failed`]: still a refusal, with a different message.
//!
//! Not covered: the parent of the folder (`%LOCALAPPDATA%` itself) is not
//! checked. If it is redirected somewhere another account can delete or
//! rename entries, that account could swap the folder between the check
//! and the write.

use std::ffi::c_void;
use std::fs::File;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_ALREADY_EXISTS, ERROR_SUCCESS, HANDLE, HLOCAL,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    GetNamedSecurityInfoW, GetSecurityInfo, SetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    EqualSid, GetAce, GetLengthSid, GetSecurityDescriptorDacl, GetTokenInformation, IsValidSid,
    IsWellKnownSid, TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid, ACCESS_ALLOWED_ACE,
    ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES,
    READ_CONTROL, WRITE_DAC,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// ACE types (ACE_HEADER.AceType).
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x0;
const ACCESS_DENIED_ACE_TYPE: u8 = 0x1;
const SYSTEM_AUDIT_ACE_TYPE: u8 = 0x2;
const SYSTEM_ALARM_ACE_TYPE: u8 = 0x3;
const ACCESS_DENIED_OBJECT_ACE_TYPE: u8 = 0x6;
const ACCESS_DENIED_CALLBACK_ACE_TYPE: u8 = 0xA;
const ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE: u8 = 0xC;

/// Why a folder or file is not private to the current user.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NotPrivate {
    ReparsePoint,
    ForeignOwner,
    NullDacl,
    ForeignAccess,
    UnknownAllowEntry,
    HardLinked,
}

impl std::fmt::Display for NotPrivate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ReparsePoint => "is a symlink or junction",
            Self::ForeignOwner => "is owned by another account",
            Self::NullDacl => "has no access list (everyone has access)",
            Self::ForeignAccess => "grants access to another account",
            Self::UnknownAllowEntry => "has an access entry this app does not check",
            Self::HardLinked => "has more than one name (a hard link)",
        })
    }
}

/// A refusal: either the policy said no, or something could not be done
/// or confirmed. Both leave the folder and file as they were.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AclError {
    NotPrivate(NotPrivate),
    Failed(String),
}

impl std::fmt::Display for AclError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotPrivate(why) => write!(f, "{}", why),
            Self::Failed(what) => write!(f, "could not be checked or set up ({})", what),
        }
    }
}

impl From<NotPrivate> for AclError {
    fn from(why: NotPrivate) -> Self {
        Self::NotPrivate(why)
    }
}

fn failed(what: impl Into<String>) -> AclError {
    AclError::Failed(what.into())
}

/// The calling thread's last error, read before anything else can change it.
fn last_error() -> u32 {
    // SAFETY: reads the calling thread's last-error value.
    unsafe { GetLastError() }
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
fn current_user_sid() -> Result<Vec<u8>, AclError> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo-handle; `token` receives a
    // real handle, closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(failed(format!("OpenProcessToken error {}", last_error())));
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
    let err = last_error();
    // SAFETY: `token` was opened above and is closed once.
    unsafe { CloseHandle(token) };
    if ok == 0 {
        return Err(failed(format!("GetTokenInformation error {}", err)));
    }
    // SAFETY: on success `buf` holds a TOKEN_USER whose SID points inside it.
    let sid = unsafe { (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid };
    sid_bytes(sid)
}

/// A copy of the SID at `sid`.
fn sid_bytes(sid: PSID) -> Result<Vec<u8>, AclError> {
    // SAFETY: IsValidSid and GetLengthSid only read the SID they are given;
    // `sid` points to a SID that stays alive for this call.
    unsafe {
        if sid.is_null() || IsValidSid(sid) == 0 {
            return Err(failed("invalid SID"));
        }
        let len = GetLengthSid(sid) as usize;
        Ok(std::slice::from_raw_parts(sid as *const u8, len).to_vec())
    }
}

fn sid_string(sid: &[u8]) -> Result<String, AclError> {
    let mut out: *mut u16 = ptr::null_mut();
    // SAFETY: `sid` is a valid SID; `out` receives a LocalAlloc'd string.
    if unsafe { ConvertSidToStringSidW(sid.as_ptr() as PSID, &mut out) } == 0 {
        return Err(failed(format!("ConvertSidToStringSidW error {}", last_error())));
    }
    let _free = LocalBox(out as *mut c_void);
    // SAFETY: `out` is a NUL-terminated wide string, freed by `_free`.
    let len = (0..).take_while(|&i| unsafe { *out.add(i) } != 0).count();
    Ok(String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(out, len) }))
}

/// A parsed security descriptor from SDDL, freed on drop.
struct Descriptor(LocalBox);

impl Descriptor {
    fn from_sddl(sddl: &str) -> Result<Self, AclError> {
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
            return Err(failed(format!("SDDL conversion error {}", last_error())));
        }
        Ok(Self(LocalBox(sd)))
    }

    fn ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.0 .0
    }

    fn dacl(&self) -> Result<*mut ACL, AclError> {
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl: *mut ACL = ptr::null_mut();
        // SAFETY: `self` holds a valid descriptor; the DACL points inside it.
        let ok = unsafe { GetSecurityDescriptorDacl(self.ptr(), &mut present, &mut dacl, &mut defaulted) };
        if ok == 0 || present == 0 || dacl.is_null() {
            return Err(failed("descriptor has no DACL"));
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

/// The SID of an ACCESS_ALLOWED_ACE: it starts at `SidStart`, so it is
/// addressed from the ACE pointer, not through a reference to that field.
///
/// SAFETY: `ace` must point to a valid ACCESS_ALLOWED_ACE.
unsafe fn allowed_ace_sid(ace: *const c_void) -> PSID {
    ptr::addr_of!((*(ace as *const ACCESS_ALLOWED_ACE)).SidStart) as PSID
}

/// Judge an owner and DACL read from one security descriptor.
///
/// SAFETY: `owner` and `dacl` must be null or point into a descriptor that
/// stays alive for this call.
unsafe fn judge(owner: PSID, dacl: *const ACL, user: &[u8]) -> Result<(), AclError> {
    if owner.is_null() || !is_trusted(owner, user) {
        return Err(NotPrivate::ForeignOwner.into());
    }
    if dacl.is_null() {
        return Err(NotPrivate::NullDacl.into());
    }
    let count = (*dacl).AceCount as u32;
    for index in 0..count {
        let mut ace: *mut c_void = ptr::null_mut();
        // `index` is below the ACL's entry count.
        if GetAce(dacl, index, &mut ace) == 0 || ace.is_null() {
            return Err(failed("GetAce failed"));
        }
        // Every ACE starts with a DWORD-aligned ACE_HEADER.
        let header = *(ace as *const ACE_HEADER);
        match header.AceType {
            ACCESS_ALLOWED_ACE_TYPE => {
                if !is_trusted(allowed_ace_sid(ace), user) {
                    return Err(NotPrivate::ForeignAccess.into());
                }
            }
            ACCESS_DENIED_ACE_TYPE
            | ACCESS_DENIED_OBJECT_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
            | SYSTEM_AUDIT_ACE_TYPE
            | SYSTEM_ALARM_ACE_TYPE => {}
            _ => return Err(NotPrivate::UnknownAllowEntry.into()),
        }
    }
    Ok(())
}

/// What is at a path, without following it.
enum Entry {
    Absent,
    Present,
}

/// Stat `path` without following it. A reparse point is a refusal; any
/// stat error other than NotFound is a failure, never "absent".
fn entry_at(path: &Path) -> Result<Entry, AclError> {
    use std::os::windows::fs::MetadataExt;
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || meta.file_type().is_symlink() => {
            Err(NotPrivate::ReparsePoint.into())
        }
        Ok(_) => Ok(Entry::Present),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Entry::Absent),
        Err(e) => Err(failed(format!("stat: {}", e))),
    }
}

/// The owner and DACL of `path`, judged against `user`.
fn check_private_with(path: &Path, user: &[u8]) -> Result<(), AclError> {
    if let Entry::Absent = entry_at(path)? {
        return Err(failed("not found"));
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
        return Err(failed(format!("GetNamedSecurityInfoW error {}", status)));
    }
    let _sd = LocalBox(sd);
    // SAFETY: `owner` and `dacl` point into `sd`, alive until `_sd` drops.
    unsafe { judge(owner, dacl, user) }
}

/// The same check on an open handle, so it is about the file that was
/// opened, whatever the path now names.
fn check_handle_with(handle: HANDLE, user: &[u8]) -> Result<(), AclError> {
    let mut owner: PSID = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `handle` is an open file handle with READ_CONTROL; on success
    // `sd` is LocalAlloc'd and `owner`/`dacl` point into it.
    let status = unsafe {
        GetSecurityInfo(
            handle,
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
        return Err(failed(format!("GetSecurityInfo error {}", status)));
    }
    let _sd = LocalBox(sd);
    // SAFETY: `owner` and `dacl` point into `sd`, alive until `_sd` drops.
    unsafe { judge(owner, dacl, user) }
}

/// Check an existing folder or file: see the module documentation. Used at
/// load to warn (#24); the save path checks through `open_private_file`.
pub(crate) fn check_private(path: &Path) -> Result<(), AclError> {
    let user = current_user_sid()?;
    check_private_with(path, &user)
}

/// Make sure `dir` exists and is private to the current user. Its parent
/// folders are created as usual if missing. A new `dir` gets the user-only
/// DACL; an existing one is only checked.
pub(crate) fn ensure_private_dir(dir: &Path) -> Result<(), AclError> {
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent).map_err(|e| failed(format!("create parent: {}", e)))?;
    }
    let user = current_user_sid()?;
    let sd = Descriptor::from_sddl(&folder_sddl(&sid_string(&user)?))?;
    let attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.ptr(),
        bInheritHandle: 0,
    };
    let dir_w = wide_path(dir);
    // SAFETY: `dir_w` is NUL-terminated and `attrs` points to a valid
    // descriptor that outlives the call.
    if unsafe { CreateDirectoryW(dir_w.as_ptr(), &attrs) } == 0 {
        let err = last_error();
        if err != ERROR_ALREADY_EXISTS {
            return Err(failed(format!("CreateDirectoryW error {}", err)));
        }
    }
    // Checked whether it was just made or already there.
    check_private_with(dir, &user)?;
    if !dir.is_dir() {
        return Err(failed("not a folder"));
    }
    Ok(())
}

/// What [`open_private_file_with`] does to the open handle before it is
/// emptied. The production step is [`protect_handle`]; tests replace it.
type ProtectStep = fn(HANDLE, &[u8]) -> Result<(), AclError>;

/// Give the open file the protected, user-and-SYSTEM DACL, then check it
/// again on the same handle.
fn protect_handle(handle: HANDLE, user: &[u8]) -> Result<(), AclError> {
    let sd = Descriptor::from_sddl(&file_sddl(&sid_string(user)?))?;
    let dacl = sd.dacl()?;
    // SAFETY: `handle` is open with WRITE_DAC; `dacl` points into `sd`,
    // which outlives the call.
    let status = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(failed(format!("SetSecurityInfo error {}", status)));
    }
    check_handle_with(handle, user)
}

/// Open `path` for writing the pairing, private to the current user.
///
/// SECURITY: an existing file is checked first (a stat error other than
/// NotFound is a refusal). The file is opened without truncating, with
/// WRITE_DAC and READ_CONTROL, given the user-only DACL on that handle and
/// checked again; only then is it emptied. Any failure leaves an existing
/// file's contents as they were.
pub(crate) fn open_private_file(path: &Path) -> Result<File, AclError> {
    open_private_file_with(path, protect_handle)
}

fn open_private_file_with(path: &Path, protect: ProtectStep) -> Result<File, AclError> {
    let user = current_user_sid()?;
    if let Entry::Present = entry_at(path)? {
        check_private_with(path, &user)?;
    }
    let file = open_no_follow(path)?;
    protect(file.as_raw_handle() as HANDLE, &user)?;
    file.set_len(0).map_err(|e| failed(format!("truncate: {}", e)))?;
    Ok(file)
}

/// Open (or create) `path` for writing without following a link, and
/// refuse the handle if it is a reparse point or has more than one name.
/// Nothing is truncated here.
fn open_no_follow(path: &Path) -> Result<File, AclError> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .access_mode(FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES | WRITE_DAC | READ_CONTROL)
        .create(true)
        // Open a link itself rather than its target, so a symlink or
        // junction swapped in after the check is caught on the handle.
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|e| failed(format!("open: {}", e)))?;
    // SAFETY: BY_HANDLE_FILE_INFORMATION is plain data, valid when zeroed;
    // the handle is open with FILE_READ_ATTRIBUTES.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) } == 0 {
        return Err(failed(format!("GetFileInformationByHandle error {}", last_error())));
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(NotPrivate::ReparsePoint.into());
    }
    // A second name for the same file could sit in a folder that other
    // accounts can list or that has other rules.
    if info.nNumberOfLinks > 1 {
        return Err(NotPrivate::HardLinked.into());
    }
    Ok(file)
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
    // SAFETY: as in judge.
    let count = unsafe { (*dacl).AceCount } as u32;
    for index in 0..count {
        let mut ace: *mut c_void = ptr::null_mut();
        unsafe { GetAce(dacl, index, &mut ace) };
        let header = unsafe { *(ace as *const ACE_HEADER) };
        if header.AceType == ACCESS_ALLOWED_ACE_TYPE {
            let sid = unsafe { allowed_ace_sid(ace) };
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
    use std::io::Write;
    use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;

    /// Replace `path`'s DACL with one from `sddl` ("D:P(...)" or "D:(...)").
    /// A "D:P" DACL is protected; a "D:" one keeps inheriting.
    pub(super) fn set_dacl(path: &Path, sddl: &str) {
        let sd = Descriptor::from_sddl(sddl).expect("sddl");
        let dacl = sd.dacl().expect("dacl");
        let protect = if sddl.starts_with("D:P") { PROTECTED_DACL_SECURITY_INFORMATION } else { 0 };
        let path_w = wide_path(path);
        // SAFETY: `path_w` is NUL-terminated; `dacl` points into `sd`.
        let status = unsafe {
            SetNamedSecurityInfoW(
                path_w.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | protect,
                ptr::null_mut(),
                ptr::null_mut(),
                dacl,
                ptr::null(),
            )
        };
        assert_eq!(status, ERROR_SUCCESS, "SetNamedSecurityInfoW");
    }

    /// Give `path` a NULL DACL (everyone has full access).
    fn set_null_dacl(path: &Path) {
        let path_w = wide_path(path);
        // SAFETY: a NULL DACL pointer with DACL_SECURITY_INFORMATION sets a
        // NULL DACL.
        let status = unsafe {
            SetNamedSecurityInfoW(
                path_w.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
            )
        };
        assert_eq!(status, ERROR_SUCCESS);
    }

    fn me() -> String {
        sid_string(&current_user_sid().unwrap()).unwrap()
    }

    fn refused(why: NotPrivate) -> Result<(), AclError> {
        Err(AclError::NotPrivate(why))
    }

    #[test]
    fn new_folder_is_owned_by_the_user_and_grants_only_user_and_system() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        ensure_private_dir(&dir).expect("private dir");
        assert!(dir.is_dir());
        assert!(test_is_user_only(&dir));
        // Calling it again on the existing folder passes the check.
        ensure_private_dir(&dir).expect("existing private dir");
    }

    #[test]
    fn private_file_gets_the_user_only_dacl_and_is_emptied() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        ensure_private_dir(&dir).unwrap();
        let path = dir.join("connection.enc");
        std::fs::write(&path, b"old contents").unwrap();
        let mut file = open_private_file(&path).expect("open");
        assert!(test_is_user_only(&path));
        assert_eq!(std::fs::read(&path).unwrap(), b"", "emptied after protecting");
        file.write_all(b"new").unwrap();
        drop(file);
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
    }

    /// B1: if protecting the open file fails, the existing contents are
    /// kept (the file is not truncated before it is protected).
    #[test]
    fn a_failed_protect_step_leaves_the_file_as_it_was() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        ensure_private_dir(&dir).unwrap();
        let path = dir.join("connection.enc");
        std::fs::write(&path, b"the old pairing").unwrap();
        fn fail(_: HANDLE, _: &[u8]) -> Result<(), AclError> {
            Err(failed("injected"))
        }
        assert_eq!(open_private_file_with(&path, fail).err(), Some(failed("injected")));
        assert_eq!(std::fs::read(&path).unwrap(), b"the old pairing");
    }

    #[test]
    fn existing_folder_granting_another_account_is_refused() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        std::fs::create_dir(&dir).unwrap();
        let me = me();
        for extra in [
            "(A;OICI;FR;;;WD)",   // Everyone
            "(A;OICI;FR;;;AU)",   // Authenticated Users
            "(A;OICI;FA;;;BU)",   // Users
            "(A;OICIIO;FA;;;WD)", // inherit-only: new files would get it
            "(A;OICIIO;FA;;;CO)", // CREATOR OWNER
            "(A;;FA;;;OW)",       // OWNER RIGHTS
        ] {
            set_dacl(&dir, &format!("D:P(A;OICI;FA;;;{me})(A;OICI;FA;;;SY){extra}"));
            assert_eq!(ensure_private_dir(&dir), refused(NotPrivate::ForeignAccess), "{extra}");
            assert_eq!(check_private(&dir), refused(NotPrivate::ForeignAccess), "{extra}");
        }
    }

    #[test]
    fn existing_file_granting_another_account_is_refused_and_kept() {
        let base = tempfile::tempdir().unwrap();
        let path = base.path().join("connection.enc");
        std::fs::write(&path, b"x").unwrap();
        set_dacl(&path, &format!("D:P(A;;FA;;;{})(A;;FR;;;WD)", me()));
        assert_eq!(check_private(&path), refused(NotPrivate::ForeignAccess));
        assert_eq!(open_private_file(&path).err(), Some(AclError::NotPrivate(NotPrivate::ForeignAccess)));
        assert_eq!(std::fs::read(&path).unwrap(), b"x");
    }

    #[test]
    fn null_dacl_is_refused() {
        let base = tempfile::tempdir().unwrap();
        let path = base.path().join("f");
        std::fs::write(&path, b"x").unwrap();
        set_null_dacl(&path);
        assert_eq!(check_private(&path), refused(NotPrivate::NullDacl));
    }

    #[test]
    fn callback_allow_entry_is_refused() {
        let base = tempfile::tempdir().unwrap();
        let path = base.path().join("f");
        std::fs::write(&path, b"x").unwrap();
        // A conditional (callback) allow entry for the user themself: still
        // refused, since this code does not interpret conditions.
        set_dacl(&path, &format!("D:P(A;;FA;;;{me})(XA;;FR;;;{me};(Exists TITLE))", me = me()));
        assert_eq!(check_private(&path), refused(NotPrivate::UnknownAllowEntry));
    }

    #[test]
    fn administrators_and_deny_entries_are_accepted() {
        let base = tempfile::tempdir().unwrap();
        let path = base.path().join("f");
        std::fs::write(&path, b"x").unwrap();
        set_dacl(&path, &format!("D:P(D;;FW;;;WD)(A;;FA;;;{})(A;;FA;;;SY)(A;;FA;;;BA)", me()));
        assert_eq!(check_private(&path), Ok(()));
    }

    /// A folder made by an earlier build, inheriting the default
    /// %LOCALAPPDATA% ACL (SYSTEM, Administrators, the user; not protected):
    /// accepted as it is, and the file written in it is user-only.
    #[test]
    fn inherited_local_app_data_style_folder_is_accepted() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        std::fs::create_dir(&dir).unwrap();
        set_dacl(&dir, &format!("D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{})", me()));
        ensure_private_dir(&dir).expect("accepted");
        let path = dir.join("connection.enc");
        drop(open_private_file(&path).expect("open"));
        assert!(test_is_user_only(&path));
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
        assert_eq!(check_private(&link), refused(NotPrivate::ReparsePoint));
        assert_eq!(ensure_private_dir(&link), refused(NotPrivate::ReparsePoint));
    }

    /// A junction at connection.enc itself, reaching the open step without
    /// the path check that normally runs first (as if swapped in after
    /// it): the open refuses it and nothing is written through the link.
    /// Windows already fails the write open of a junction ("Access is
    /// denied"); a file symlink would open and be refused by the handle
    /// check, but creating one needs a privilege the tests don't have.
    #[test]
    fn junction_at_the_file_is_refused_on_the_handle() {
        let base = tempfile::tempdir().unwrap();
        let target = base.path().join("elsewhere");
        std::fs::create_dir(&target).unwrap();
        let link = base.path().join("connection.enc");
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&target)
            .output()
            .expect("mklink");
        assert!(status.status.success(), "mklink /J failed");
        assert!(open_no_follow(&link).is_err(), "the open step must refuse a junction");
        // Through the normal path, the path check names it.
        assert_eq!(open_private_file(&link).err(), Some(AclError::NotPrivate(NotPrivate::ReparsePoint)));
        assert!(std::fs::read_dir(&target).unwrap().next().is_none(), "nothing written through the link");
    }

    /// A file with a second name (hard link) is refused and kept.
    #[test]
    fn hard_linked_file_is_refused_and_kept() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        ensure_private_dir(&dir).unwrap();
        let path = dir.join("connection.enc");
        std::fs::write(&path, b"the old pairing").unwrap();
        std::fs::hard_link(&path, base.path().join("second-name")).unwrap();
        assert_eq!(open_private_file(&path).err(), Some(AclError::NotPrivate(NotPrivate::HardLinked)));
        assert_eq!(std::fs::read(&path).unwrap(), b"the old pairing");
    }

    /// A file where the folder should be is not taken for the folder.
    #[test]
    fn a_file_named_like_the_folder_is_refused() {
        let base = tempfile::tempdir().unwrap();
        let path = base.path().join("vettid-desktop");
        std::fs::write(&path, b"").unwrap();
        assert_eq!(ensure_private_dir(&path), Err(failed("not a folder")));
    }

    #[test]
    fn sddl_strings() {
        assert_eq!(folder_sddl("S-1-5-21-1"), "O:S-1-5-21-1D:P(A;OICI;FA;;;S-1-5-21-1)(A;OICI;FA;;;SY)");
        assert_eq!(file_sddl("S-1-5-21-1"), "D:P(A;;FA;;;S-1-5-21-1)(A;;FA;;;SY)");
    }
}
