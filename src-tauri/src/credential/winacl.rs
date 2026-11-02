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
//! - **The file:** written to a new temporary file created in one step with
//!   the protected user-and-SYSTEM DACL, inside the folder held open, then
//!   renamed over the pairing file by its handle, relative to the folder's
//!   handle ([`write_private_file`]).
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
//! The parent of the folder (`%LOCALAPPDATA%`) is checked too (#21): its
//! owner must be trusted, and no other account may hold delete-child,
//! delete, `WRITE_DAC` or `WRITE_OWNER` on it, since with any of those it
//! could remove or rename the pairing folder and put its own in its place.
//! The parent is held open (no delete sharing) and judged on that handle
//! while the folder is created and during every write, and the folder must
//! be directly inside it; a parent that is a link is refused. Folders
//! further up are not judged, but the held parent can't be renamed while
//! held. A folder swap is also closed for the duration of a write: the
//! folder is held open with data access and no delete sharing, so it can't
//! be renamed, nor can its parent (both tested); the new file is renamed
//! relative to the held folder's handle, and its final path must be inside
//! that folder before and after. A folder swapped in before the write
//! is checked on its own handle like any other, so it is refused unless it
//! is private to the user (#21).

use std::ffi::c_void;
use std::fs::File;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_ALREADY_EXISTS, ERROR_SUCCESS, HANDLE, HLOCAL,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    GetNamedSecurityInfoW, GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    EqualSid, GetAce, GetLengthSid, GetTokenInformation, IsValidSid,
    IsWellKnownSid, TokenUser, WinBuiltinAdministratorsSid, WinCreatorOwnerRightsSid, WinCreatorOwnerSid,
    WinLocalSystemSid, ACCESS_ALLOWED_ACE,
    ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    PSID, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, GetFileInformationByHandle, GetFinalPathNameByHandleW,
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, DELETE, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY, FILE_NAME_NORMALIZED,
    FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL,
    VOLUME_NAME_DOS,
};
use windows_sys::Wdk::Storage::FileSystem::{
    FileRenameInformation, FileRenameInformationEx, NtSetInformationFile, FILE_INFORMATION_CLASS,
    FILE_RENAME_INFORMATION,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
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
    /// The pairing folder's parent is owned by another account (#21).
    ParentForeignOwner,
    /// Another account can delete or rename what is in the pairing
    /// folder's parent, or change its permissions or owner (#21).
    ParentForeignControl,
    /// The pairing folder's parent is a symlink or junction, which could be
    /// pointed elsewhere after the check (#21).
    ParentLink,
}

impl NotPrivate {
    /// Whether the refusal is about the pairing folder's parent rather
    /// than the folder or file: it gets its own notice.
    pub(crate) fn is_about_the_parent(&self) -> bool {
        matches!(self, Self::ParentForeignOwner | Self::ParentForeignControl | Self::ParentLink)
    }
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
            Self::ParentForeignOwner => "is in a folder owned by another account",
            Self::ParentForeignControl => "is in a folder where another account can delete, rename or replace it",
            Self::ParentLink => "is in a folder that is a symlink or junction",
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

    #[cfg(test)]
    fn dacl(&self) -> Result<*mut ACL, AclError> {
        use windows_sys::Win32::Security::GetSecurityDescriptorDacl;
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

/// Rights on a folder that let an account remove, rename or replace an
/// entry in it whatever the entry's own permissions say (delete-child), or
/// give itself that right (change the permissions or the owner), or move
/// the folder itself (delete). `GENERIC_ALL` covers all of them.
const PARENT_CONTROL_RIGHTS: u32 = 0x0000_0040 // FILE_DELETE_CHILD
    | 0x0001_0000 // DELETE
    | 0x0004_0000 // WRITE_DAC
    | 0x0008_0000 // WRITE_OWNER
    | 0x1000_0000; // GENERIC_ALL

/// INHERIT_ONLY_ACE: the entry applies only to what is created inside, not
/// to the folder itself.
const INHERIT_ONLY_ACE: u8 = 0x08;

/// Judge the pairing folder's parent (#21). Its owner must be trusted (the
/// user, SYSTEM or Administrators), and no other account may hold
/// [`PARENT_CONTROL_RIGHTS`] on it. Other access (listing it, reading it,
/// creating entries in it) is accepted: the pairing folder itself is
/// checked and protected, and its protected DACL doesn't inherit from here.
/// Inherit-only entries don't apply to the parent and are skipped; allow
/// entries of a type this module doesn't interpret are refused.
///
/// SAFETY: as for [`judge`].
unsafe fn judge_parent(owner: PSID, dacl: *const ACL, user: &[u8]) -> Result<(), AclError> {
    if owner.is_null() || !is_trusted(owner, user) {
        return Err(NotPrivate::ParentForeignOwner.into());
    }
    if dacl.is_null() {
        return Err(NotPrivate::ParentForeignControl.into());
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
        if header.AceFlags & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        match header.AceType {
            ACCESS_ALLOWED_ACE_TYPE => {
                let mask = (*(ace as *const ACCESS_ALLOWED_ACE)).Mask;
                let sid = allowed_ace_sid(ace);
                // OWNER RIGHTS applies to the owner, already checked as
                // trusted; CREATOR OWNER grants nothing on the object it
                // sits on (it is a template for what is created inside).
                let inert = IsWellKnownSid(sid, WinCreatorOwnerRightsSid) != 0
                    || IsWellKnownSid(sid, WinCreatorOwnerSid) != 0;
                if mask & PARENT_CONTROL_RIGHTS != 0 && !inert && !is_trusted(sid, user) {
                    return Err(NotPrivate::ParentForeignControl.into());
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

/// The pairing folder's parent, held open while the folder is created or
/// written (#21). Like [`HeldFolder`] it is opened without following a
/// link, with data access and **without delete sharing**, so neither it
/// nor (tested) its own parent can be renamed while held, and it is judged
/// on this handle. The folder must then be directly inside its final path.
struct HeldParent {
    handle: HANDLE,
    final_path: String,
}

impl Drop for HeldParent {
    fn drop(&mut self) {
        // SAFETY: `handle` was returned by CreateFileW and is closed once.
        unsafe { CloseHandle(self.handle) };
    }
}

fn hold_parent(parent: &Path, user: &[u8]) -> Result<HeldParent, AclError> {
    let handle = open_folder_held(parent).map_err(|err| failed(format!("open parent folder: error {}", err)))?;
    let mut held = HeldParent { handle, final_path: String::new() };
    let info = handle_info(held.handle)?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(NotPrivate::ParentLink.into());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(failed("parent is not a folder"));
    }
    check_parent_handle(held.handle, user)?;
    held.final_path = final_path(held.handle)?;
    Ok(held)
}

/// [`judge_parent`] on an open handle.
fn check_parent_handle(handle: HANDLE, user: &[u8]) -> Result<(), AclError> {
    let mut owner: PSID = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: as in check_handle_with.
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
        return Err(failed(format!("parent: GetSecurityInfo error {}", status)));
    }
    let _sd = LocalBox(sd);
    // SAFETY: `owner` and `dacl` point into `sd`, alive until `_sd` drops.
    unsafe { judge_parent(owner, dacl, user) }
}

/// Hold `dir`'s parent, judged (#21).
fn hold_parent_of(dir: &Path, user: &[u8]) -> Result<HeldParent, AclError> {
    let parent = dir.parent().ok_or_else(|| failed("the pairing folder has no parent"))?;
    hold_parent(parent, user)
}

/// The held folder must be directly inside the held parent.
fn require_inside(folder: &HeldFolder, parent: &HeldParent) -> Result<(), AclError> {
    if is_directly_inside(&folder.final_path, &parent.final_path) {
        Ok(())
    } else {
        Err(failed("the pairing folder is not in its checked parent"))
    }
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
/// load to warn (#24); the save path checks through `write_private_file`.
pub(crate) fn check_private(path: &Path) -> Result<(), AclError> {
    let user = current_user_sid()?;
    check_private_with(path, &user)
}

/// Make sure `dir` exists and is private to the current user. Its parent
/// folders are created as usual if missing. A new `dir` gets the user-only
/// DACL; an existing one is only checked. The parent is held and checked
/// first (#21): if another account could delete, rename or replace entries
/// in it, the pairing folder isn't created or used. (A missing parent is
/// still created first, as before.)
pub(crate) fn ensure_private_dir(dir: &Path) -> Result<(), AclError> {
    let user = current_user_sid()?;
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent).map_err(|e| failed(format!("create parent: {}", e)))?;
    }
    let parent = hold_parent_of(dir, &user)?;
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
    // Checked whether it was just made or already there, on a handle, and
    // it must be the folder inside the parent that was checked.
    let folder = hold_folder(dir, &user)?;
    require_inside(&folder, &parent)?;
    Ok(())
}

/// An open handle to the pairing folder, held while the file is written.
///
/// It is opened without following a link and **without delete sharing**,
/// so while it is held the folder cannot be renamed, moved or deleted, and
/// nothing can be swapped in at its path. Its permissions are checked on
/// this handle, and its final path is what the new file must sit in.
struct HeldFolder {
    handle: HANDLE,
    final_path: String,
}

impl Drop for HeldFolder {
    fn drop(&mut self) {
        // SAFETY: `handle` was returned by CreateFileW and is closed once.
        unsafe { CloseHandle(self.handle) };
    }
}

/// Open a folder to hold it: no link followed, data access, and no
/// FILE_SHARE_DELETE, so it can't be renamed while held. Another program
/// (a backup or antivirus scanner) that has it open with delete access for
/// a moment makes this fail with a sharing violation, so that is retried a
/// few times (#37 review). Returns the Win32 error otherwise.
fn open_folder_held(dir: &Path) -> Result<HANDLE, u32> {
    const ERROR_SHARING_VIOLATION: u32 = 32;
    const ATTEMPTS: u32 = 5;
    let dir_w = wide_path(dir);
    for attempt in 1..=ATTEMPTS {
        // SAFETY: `dir_w` is NUL-terminated. FILE_FLAG_BACKUP_SEMANTICS is
        // needed to open a directory; FILE_FLAG_OPEN_REPARSE_POINT opens a
        // link itself.
        let handle = unsafe {
            CreateFileW(
                dir_w.as_ptr(),
                // FILE_LIST_DIRECTORY is data access: share modes are only
                // enforced against handles that have some, so it is what
                // makes the missing FILE_SHARE_DELETE stop a rename.
                FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE && !handle.is_null() {
            return Ok(handle);
        }
        let err = last_error();
        if err != ERROR_SHARING_VIOLATION || attempt == ATTEMPTS {
            return Err(err);
        }
        std::thread::sleep(std::time::Duration::from_millis(50 * u64::from(attempt)));
    }
    unreachable!("the loop returns")
}

fn hold_folder(dir: &Path, user: &[u8]) -> Result<HeldFolder, AclError> {
    let handle = open_folder_held(dir).map_err(|err| failed(format!("open folder: error {}", err)))?;
    // Owns the handle from here on, so every early return closes it once.
    let mut held = HeldFolder { handle, final_path: String::new() };
    let info = handle_info(held.handle)?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(NotPrivate::ReparsePoint.into());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(failed("not a folder"));
    }
    check_handle_with(held.handle, user)?;
    held.final_path = final_path(held.handle)?;
    Ok(held)
}

fn handle_info(handle: HANDLE) -> Result<BY_HANDLE_FILE_INFORMATION, AclError> {
    // SAFETY: BY_HANDLE_FILE_INFORMATION is plain data, valid when zeroed;
    // the handle is open with FILE_READ_ATTRIBUTES.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        return Err(failed(format!("GetFileInformationByHandle error {}", last_error())));
    }
    Ok(info)
}

/// The normalized, DOS-style final path of an open handle
/// (`\\?\C:\Users\...`), with every link resolved.
fn final_path(handle: HANDLE) -> Result<String, AclError> {
    let mut buf = vec![0u16; 512];
    loop {
        // SAFETY: `buf` holds `buf.len()` characters.
        let len = unsafe {
            GetFinalPathNameByHandleW(handle, buf.as_mut_ptr(), buf.len() as u32, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS)
        } as usize;
        if len == 0 {
            return Err(failed(format!("GetFinalPathNameByHandleW error {}", last_error())));
        }
        if len < buf.len() {
            return Ok(String::from_utf16_lossy(&buf[..len]));
        }
        // Too small: `len` is the size needed, including the terminator.
        if len > 32 * 1024 {
            return Err(failed("final path too long"));
        }
        buf = vec![0u16; len + 1];
    }
}

/// Whether `child` names an entry directly inside `folder` (both final
/// paths). Both come from GetFinalPathNameByHandleW with
/// FILE_NAME_NORMALIZED, so they carry the on-disk case and are compared
/// exactly: Unicode case folding is not NTFS's and could match a
/// different name.
fn is_directly_inside(child: &str, folder: &str) -> bool {
    let folder = folder.trim_end_matches('\\');
    match child.rsplit_once('\\') {
        Some((parent, name)) => !name.is_empty() && parent == folder,
        None => false,
    }
}

/// FILE_RENAME_INFORMATION flags for FileRenameInformationEx (ntifs.h);
/// not in windows-sys 0.59.
const FILE_RENAME_REPLACE_IF_EXISTS: u32 = 0x1;
const FILE_RENAME_POSIX_SEMANTICS: u32 = 0x2;

/// NTSTATUS values the rename handles.
const STATUS_ACCESS_DENIED: i32 = 0xC000_0022_u32 as i32;
const STATUS_SHARING_VIOLATION: i32 = 0xC000_0043_u32 as i32;
const STATUS_INVALID_INFO_CLASS: i32 = 0xC000_0003_u32 as i32;
const STATUS_INVALID_PARAMETER: i32 = 0xC000_000D_u32 as i32;
const STATUS_NOT_SUPPORTED: i32 = 0xC000_00BB_u32 as i32;

/// Rename the open file `file` to `name` inside `folder`, replacing an
/// existing `name` (#28). The rename is by handle, and the new name is
/// relative to the held folder's handle, so no path is resolved: the file
/// that was written and checked is the one that ends up at `name`, in the
/// folder that was checked.
///
/// This is NtSetInformationFile: SetFileInformationByHandle refuses a
/// RootDirectory (error 87, tested). FileRenameInformationEx with POSIX
/// semantics is tried first; a file system or Windows version without it
/// gets the plain FileRenameInformation with ReplaceIfExists, which is
/// still by handle and relative. Another program (an antivirus scanner,
/// the search indexer, a sync client) can hold the old file open for a
/// moment, so a sharing violation or access denial is retried a few times.
fn rename_by_handle(file: HANDLE, folder: HANDLE, name: &str) -> Result<(), AclError> {
    const ATTEMPTS: u32 = 5;

    let name_w: Vec<u16> = std::ffi::OsStr::new(name).encode_wide().collect();
    // A plain Win32 file name: no separator, stream, wildcard or control
    // character, and no trailing dot or space (which NT keeps but Win32
    // can't open).
    if name_w.is_empty()
        || name_w.iter().any(|&c| c < 0x20 || "\\/:*?\"<>|".encode_utf16().any(|bad| bad == c))
        || name.ends_with('.')
        || name.ends_with(' ')
    {
        return Err(failed("rename: not a plain file name"));
    }
    // FILE_RENAME_INFORMATION ends in a variable-length name. A u64 buffer
    // keeps it aligned for the HANDLE field.
    let header = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
    let size = (header + name_w.len() * 2).max(std::mem::size_of::<FILE_RENAME_INFORMATION>());
    let mut buf = vec![0u64; size.div_ceil(8)];
    let info = buf.as_mut_ptr() as *mut FILE_RENAME_INFORMATION;

    let try_rename = |class: FILE_INFORMATION_CLASS| -> i32 {
        // SAFETY: `buf` is aligned and at least `size` bytes, enough for the
        // header and `name_w`, which is copied within it. `iosb` is written
        // by the call.
        unsafe {
            (*info).Anonymous.Flags = 0;
            if class == FileRenameInformationEx {
                (*info).Anonymous.Flags = FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS;
            } else {
                (*info).Anonymous.ReplaceIfExists = 1;
            }
            (*info).RootDirectory = folder;
            (*info).FileNameLength = (name_w.len() * 2) as u32;
            ptr::copy_nonoverlapping(name_w.as_ptr(), ptr::addr_of_mut!((*info).FileName) as *mut u16, name_w.len());
            let mut iosb: IO_STATUS_BLOCK = std::mem::zeroed();
            NtSetInformationFile(file, &mut iosb, info as *const c_void, size as u32, class)
        }
    };

    let mut class = FileRenameInformationEx;
    let mut attempt = 1;
    loop {
        let status = try_rename(class);
        if status >= 0 {
            return Ok(());
        }
        if class == FileRenameInformationEx
            && matches!(status, STATUS_INVALID_INFO_CLASS | STATUS_INVALID_PARAMETER | STATUS_NOT_SUPPORTED)
        {
            class = FileRenameInformation;
            continue;
        }
        let busy = status == STATUS_SHARING_VIOLATION || status == STATUS_ACCESS_DENIED;
        if !busy || attempt == ATTEMPTS {
            return Err(failed(format!(
                "replace: error 0x{:08X} after {} attempts",
                status as u32, attempt
            )));
        }
        std::thread::sleep(std::time::Duration::from_millis(50 * u64::from(attempt)));
        attempt += 1;
    }
}

/// Removes the temporary file on drop unless the write succeeded.
struct TempFile<'a> {
    path: &'a Path,
    keep: bool,
}

impl Drop for TempFile<'_> {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_file(self.path);
        }
    }
}

/// Remove temporary files a crashed earlier save left behind. They hold
/// ciphertext only, in the private folder; this keeps it tidy.
pub(crate) fn remove_stale_temps(dir: &Path, name: &str) {
    let prefix = format!("{name}{TEMP_INFIX}");
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().starts_with(&prefix) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

/// Marks a temporary file next to the pairing file.
pub(crate) const TEMP_INFIX: &str = ".tmp-";

/// A test hook run after the temporary file is written and flushed, just
/// before it is renamed over the pairing file; it gets the temporary
/// file's path and its open handle. Production uses [`no_hook`].
type BeforeReplace = fn(&Path, &File) -> Result<(), AclError>;

fn no_hook(_: &Path, _: &File) -> Result<(), AclError> {
    Ok(())
}

/// Write `data` as `dir\name`, privately and atomically (#23, #12).
///
/// SECURITY, in order:
/// 1. the folder is held open (no delete sharing, no link followed) and
///    checked on that handle, so it can't be swapped during the write;
/// 2. an existing `name` is checked, and the write is refused (and the
///    file kept) if another account can open it;
/// 3. a new temporary file is created in one step, `CREATE_NEW` with the
///    protected user-and-SYSTEM DACL in its SECURITY_ATTRIBUTES, so it never
///    exists with an inherited ACL and no existing file or link is opened;
/// 4. its handle is checked (no reparse point, one name, the policy) and
///    its final path must be directly inside the held folder;
/// 5. the data is written and flushed, and the file is renamed over
///    `name` **by its handle, relative to the held folder's handle** (#28),
///    so no path is looked up again between the checks and the rename. A
///    rename keeps the file's own DACL;
/// 6. the same handle's final path and policy are checked again.
///
/// Any failure before the rename leaves an existing `name` as it was and
/// removes the temporary file.
pub(crate) fn write_private_file(dir: &Path, name: &str, data: &[u8]) -> Result<(), AclError> {
    write_private_file_with(dir, name, data, no_hook)
}

fn write_private_file_with(
    dir: &Path,
    name: &str,
    data: &[u8],
    before_replace: BeforeReplace,
) -> Result<(), AclError> {
    use std::io::Write;
    use std::os::windows::io::FromRawHandle;

    let user = current_user_sid()?;
    // #21: the parent is held and judged for the whole write too, so it
    // can't be swapped between ensure_private_dir and here.
    let parent = hold_parent_of(dir, &user)?;
    let folder = hold_folder(dir, &user)?;
    require_inside(&folder, &parent)?;

    let target = dir.join(name);
    if let Entry::Present = entry_at(&target)? {
        check_private_with(&target, &user)?;
        let existing = open_for_check(&target)?;
        // A rename never writes through another name for the old file, so
        // this refusal is conservative: a second name is unexpected here.
        if handle_info(existing.as_raw_handle() as HANDLE)?.nNumberOfLinks > 1 {
            return Err(NotPrivate::HardLinked.into());
        }
    }
    remove_stale_temps(dir, name);

    let temp_path = dir.join(format!(
        "{name}{TEMP_INFIX}{}-{:016x}",
        std::process::id(),
        rand::RngCore::next_u64(&mut rand::rngs::OsRng)
    ));
    let sd = Descriptor::from_sddl(&file_sddl(&sid_string(&user)?))?;
    let attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.ptr(),
        bInheritHandle: 0,
    };
    let temp_w = wide_path(&temp_path);
    // SAFETY: `temp_w` is NUL-terminated and `attrs` points to a valid
    // descriptor that outlives the call. CREATE_NEW never opens an existing
    // file or link; no sharing while it is written. DELETE is for renaming
    // it by handle.
    let handle = unsafe {
        CreateFileW(
            temp_w.as_ptr(),
            FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES | READ_CONTROL | DELETE,
            0,
            &attrs,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(failed(format!("create temporary file: error {}", last_error())));
    }
    let mut temp = TempFile { path: &temp_path, keep: false };
    // SAFETY: `handle` is a valid, owned file handle; `File` closes it.
    // Declared after `temp`, so on an early return it is closed first and
    // the temporary file can then be removed.
    let mut file = unsafe { File::from_raw_handle(handle as _) };

    let info = handle_info(handle)?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(NotPrivate::ReparsePoint.into());
    }
    if info.nNumberOfLinks > 1 {
        return Err(NotPrivate::HardLinked.into());
    }
    check_handle_with(handle, &user)?;
    if !is_directly_inside(&final_path(handle)?, &folder.final_path) {
        return Err(failed("temporary file is not in the pairing folder"));
    }

    file.write_all(data).map_err(|e| failed(format!("write: {}", e)))?;
    file.sync_all().map_err(|e| failed(format!("flush: {}", e)))?;

    before_replace(&temp_path, &file)?;

    rename_by_handle(handle, folder.handle, name)?;
    temp.keep = true;

    // Detection, not prevention: the old file is already replaced. The
    // renamed handle must now be directly inside the held folder and still
    // private; if that can't be confirmed, say so plainly rather than
    // "saved" or "failed".
    let confirm = || -> Result<(), AclError> {
        let now = final_path(handle)?;
        if !is_directly_inside(&now, &folder.final_path) {
            return Err(failed("not in the pairing folder"));
        }
        if now.rsplit_once('\\').map(|(_, n)| n) != Some(name) {
            return Err(failed("not under the pairing's name"));
        }
        check_handle_with(handle, &user)
    };
    let confirmed = confirm();
    drop(file);
    drop(folder);
    drop(parent);
    if let Err(e) = confirmed {
        return Err(failed(format!(
            "the pairing was replaced, but the result could not be confirmed ({})",
            e
        )));
    }
    Ok(())
}

/// Open `path` only to check it: attributes and security, no data, no
/// link followed.
fn open_for_check(path: &Path) -> Result<File, AclError> {
    std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES | READ_CONTROL)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|e| failed(format!("open {}: {}", path.display(), e)))
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

/// For tests elsewhere in the crate: let Everyone delete what is in
/// `path` (FILE_DELETE_CHILD), as on a parent another account controls.
#[cfg(test)]
pub(crate) fn test_let_everyone_delete_children(path: &Path) {
    let me = sid_string(&current_user_sid().unwrap()).unwrap();
    tests::set_dacl(path, &format!("D:P(A;OICI;FA;;;{me})(A;OICI;FA;;;SY)(A;;0x40;;;WD)"));
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
    use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;
    use windows_sys::Win32::Security::PROTECTED_DACL_SECURITY_INFORMATION;

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

    fn temps_in(dir: &Path) -> usize {
        std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(TEMP_INFIX))
            .count()
    }

    #[test]
    fn written_file_is_user_only_replaces_the_old_one_and_leaves_no_temp() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        ensure_private_dir(&dir).unwrap();
        let path = dir.join("connection.enc");
        write_private_file(&dir, "connection.enc", b"first").expect("write");
        assert!(test_is_user_only(&path));
        write_private_file(&dir, "connection.enc", b"second").expect("rewrite");
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        assert!(test_is_user_only(&path));
        assert_eq!(temps_in(&dir), 0, "no temporary file left");
    }

    /// A failure after the temporary file is written but before it replaces
    /// the pairing: the old pairing is kept and the temporary file removed.
    #[test]
    fn a_failure_before_the_replace_keeps_the_old_file() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        ensure_private_dir(&dir).unwrap();
        let path = dir.join("connection.enc");
        write_private_file(&dir, "connection.enc", b"the old pairing").unwrap();
        fn fail(temp: &Path, file: &File) -> Result<(), AclError> {
            // The temporary file exists, private, with the new data. It is
            // open without sharing, so its length is read on the handle.
            assert!(test_is_user_only(temp));
            assert_eq!(file.metadata().unwrap().len(), 3);
            assert!(std::fs::read(temp).is_err(), "no one else can open it while it is written");
            Err(failed("injected"))
        }
        assert_eq!(
            write_private_file_with(&dir, "connection.enc", b"new", fail).err(),
            Some(failed("injected"))
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"the old pairing");
        assert_eq!(temps_in(&dir), 0, "temporary file removed");
    }

    /// While the write runs, the folder is held without delete sharing, so
    /// it can't be renamed away.
    #[test]
    fn the_folder_cannot_be_renamed_while_held() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        ensure_private_dir(&dir).unwrap();
        let held = hold_folder(&dir, &current_user_sid().unwrap()).expect("hold");
        assert!(std::fs::rename(&dir, base.path().join("moved")).is_err(), "rename must fail while held");
        drop(held);
        std::fs::rename(&dir, base.path().join("moved")).expect("rename works once released");
    }

    /// The folder's parent can't be renamed while the folder is held either
    /// (#28): NTFS refuses to rename a folder with an open descendant, so the
    /// held folder can't be moved away through its parent.
    #[test]
    fn the_parent_cannot_be_renamed_while_the_folder_is_held() {
        let base = tempfile::tempdir().unwrap();
        let parent = base.path().join("local");
        let dir = parent.join("vettid-desktop");
        std::fs::create_dir(&parent).unwrap();
        ensure_private_dir(&dir).unwrap();
        let held = hold_folder(&dir, &current_user_sid().unwrap()).expect("hold");
        assert!(
            std::fs::rename(&parent, base.path().join("moved")).is_err(),
            "the parent must not be renamable while the folder is held"
        );
        drop(held);
        std::fs::rename(&parent, base.path().join("moved")).expect("rename works once released");
    }

    /// The rename takes a plain name inside the held folder, nothing else.
    #[test]
    fn rename_by_handle_takes_only_a_plain_name() {
        for name in ["", "a\\b", "..\\x", "a/b", "a\0b", "a:b", ".", "..", "a*", "a?", "a\"b", "a<", "a>", "a|", "a.", "a ", "a\tb"] {
            assert_eq!(
                rename_by_handle(ptr::null_mut(), ptr::null_mut(), name).err(),
                Some(failed("rename: not a plain file name")),
                "{name:?}"
            );
        }
    }

    /// Another program holding connection.enc open without delete sharing:
    /// the replace is retried, then fails; the old pairing is kept and no
    /// temporary file is left.
    #[test]
    fn a_file_held_open_elsewhere_fails_the_write_and_is_kept() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        ensure_private_dir(&dir).unwrap();
        let path = dir.join("connection.enc");
        write_private_file(&dir, "connection.enc", b"the old pairing").unwrap();
        let holder = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&path)
            .unwrap();
        let err = write_private_file(&dir, "connection.enc", b"new").err().expect("must fail");
        assert!(matches!(&err, AclError::Failed(what) if what.starts_with("replace: error")), "got {err}");
        drop(holder);
        assert_eq!(std::fs::read(&path).unwrap(), b"the old pairing");
        assert_eq!(temps_in(&dir), 0, "temporary file removed");
        // Once released, the write goes through.
        write_private_file(&dir, "connection.enc", b"new").expect("write");
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
    }

    /// Temporary files from a crashed save are removed by the next save.
    #[test]
    fn stale_temporary_files_are_removed() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        ensure_private_dir(&dir).unwrap();
        std::fs::write(dir.join(format!("connection.enc{TEMP_INFIX}1-00")), b"old").unwrap();
        write_private_file(&dir, "connection.enc", b"x").unwrap();
        assert_eq!(temps_in(&dir), 0);
    }

    #[test]
    fn is_directly_inside_compares_the_parent_exactly() {
        assert!(is_directly_inside(r"\\?\C:\Users\a\AppData\Local\vettid-desktop\f", r"\\?\C:\Users\a\AppData\Local\vettid-desktop"));
        // Both sides are normalized final paths, so a case difference is a
        // different name, not the same one.
        assert!(!is_directly_inside(r"\\?\C:\Users\a\AppData\Local\vettid-desktop\f", r"\\?\C:\Users\A\appdata\local\vettid-desktop"));
        // KELVIN SIGN lowercases to "k" in Unicode but is a different NTFS name.
        assert!(!is_directly_inside("\\\\?\\C:\\\u{212A}\\f", r"\\?\C:\k"));
        assert!(is_directly_inside(r"\\?\C:\x\f", r"\\?\C:\x\"));
        assert!(!is_directly_inside(r"\\?\C:\x\y\f", r"\\?\C:\x"));
        assert!(!is_directly_inside(r"\\?\D:\x\f", r"\\?\C:\x"));
        assert!(!is_directly_inside(r"\\?\C:\x\", r"\\?\C:\x"));
        assert!(!is_directly_inside("f", r"\\?\C:\x"));
    }

    /// #21: a parent where another account can delete, rename or replace
    /// entries (delete-child), delete the folder, or change its permissions
    /// or owner is refused, and nothing is created in it.
    #[test]
    fn a_parent_another_account_controls_is_refused() {
        let base = tempfile::tempdir().unwrap();
        let parent = base.path().join("local");
        std::fs::create_dir(&parent).unwrap();
        let dir = parent.join("vettid-desktop");
        let me = me();
        for extra in [
            "(A;;0x40;;;WD)",    // FILE_DELETE_CHILD for Everyone
            "(A;;0x10000;;;WD)", // DELETE
            "(A;;WD;;;AU)",      // WRITE_DAC for Authenticated Users
            "(A;;WO;;;BU)",      // WRITE_OWNER for Users
            "(A;;FA;;;WD)",      // full control
            "(A;;GA;;;WD)",      // GENERIC_ALL
        ] {
            set_dacl(&parent, &format!("D:P(A;OICI;FA;;;{me})(A;OICI;FA;;;SY){extra}"));
            assert_eq!(
                ensure_private_dir(&dir),
                refused(NotPrivate::ParentForeignControl),
                "{extra}"
            );
            assert!(!dir.exists(), "{extra}: nothing created");
        }
    }

    /// #21: other access to the parent is accepted: reading and listing,
    /// creating entries, an inherit-only grant (it doesn't apply to the
    /// parent), a deny entry, and Administrators. So is the default
    /// %LOCALAPPDATA% shape (inherited user, SYSTEM, Administrators).
    #[test]
    fn a_parent_others_can_only_read_or_add_to_is_accepted() {
        let base = tempfile::tempdir().unwrap();
        let parent = base.path().join("local");
        std::fs::create_dir(&parent).unwrap();
        let dir = parent.join("vettid-desktop");
        let me = me();
        for extra in [
            "(A;OICI;FR;;;WD)",    // read for Everyone
            "(A;;0x6;;;AU)",       // add file and add subfolder
            "(A;OICIIO;FA;;;WD)",  // inherit-only
            "(D;;0x40;;;WD)",      // a deny entry
            "(A;OICI;FA;;;BA)",    // Administrators
        ] {
            set_dacl(&parent, &format!("D:P(A;OICI;FA;;;{me})(A;OICI;FA;;;SY){extra}"));
            assert_eq!(ensure_private_dir(&dir), Ok(()), "{extra}");
            assert!(test_is_user_only(&dir), "{extra}: the folder is still user-only");
        }
        // The real one on this machine.
        let local = dirs::config_local_dir().expect("LOCALAPPDATA");
        assert!(hold_parent(&local, &current_user_sid().unwrap()).is_ok());
    }

    /// Judge a parent described by SDDL directly, for shapes that can't
    /// be set on a real folder without a privilege (another owner).
    fn judge_parent_sddl(sddl: &str) -> Result<(), AclError> {
        use windows_sys::Win32::Security::GetSecurityDescriptorOwner;
        let sd = Descriptor::from_sddl(sddl).expect("sddl");
        let mut owner: PSID = ptr::null_mut();
        let mut defaulted = 0;
        // SAFETY: `sd` is a valid descriptor; `owner` points into it.
        assert_ne!(unsafe { GetSecurityDescriptorOwner(sd.ptr(), &mut owner, &mut defaulted) }, 0);
        let dacl = sd.dacl().map(|d| d as *const ACL).unwrap_or(ptr::null());
        // SAFETY: `owner` and `dacl` point into `sd`, alive for the call.
        unsafe { judge_parent(owner, dacl, &current_user_sid().unwrap()) }
    }

    /// #21: the parent policy on shapes from the review.
    #[test]
    fn parent_policy_shapes() {
        let me = me();
        let ok = format!("O:{me}D:(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;FA;;;{me})");
        assert_eq!(judge_parent_sddl(&ok), Ok(()), "the default %LOCALAPPDATA% shape");
        let cases = [
            (format!("O:WDD:(A;;FA;;;{me})"), refused(NotPrivate::ParentForeignOwner), "another owner"),
            (format!("O:{me}D:NO_ACCESS_CONTROL"), refused(NotPrivate::ParentForeignControl), "a NULL DACL"),
            (format!("O:{me}D:(A;OICIID;0x1301bf;;;AU)"), refused(NotPrivate::ParentForeignControl), "inherited Modify (a second drive)"),
            (format!("O:{me}D:(A;;GW;;;WD)"), Ok(()), "GENERIC_WRITE only"),
            (format!("O:{me}D:(A;;FA;;;OW)"), Ok(()), "OWNER RIGHTS (the trusted owner)"),
            (format!("O:{me}D:(A;;FA;;;CO)"), Ok(()), "CREATOR OWNER on the folder itself is inert"),
            (format!("O:{me}D:(XA;;FA;;;WD;(WIN://SYSAPPID Contains \"x\"))"), refused(NotPrivate::UnknownAllowEntry), "a callback allow entry"),
            (format!("O:{me}D:(XA;OICIIO;FA;;;WD;(WIN://SYSAPPID Contains \"x\"))"), Ok(()), "an inherit-only callback entry"),
        ];
        for (sddl, want, what) in cases {
            assert_eq!(judge_parent_sddl(&sddl), want, "{what}: {sddl}");
        }
    }

    /// A folder another program holds open with delete access only for a
    /// moment is retried, not refused.
    #[test]
    fn a_folder_held_briefly_by_another_program_is_retried() {
        use std::os::windows::fs::OpenOptionsExt;
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        ensure_private_dir(&dir).unwrap();
        let busy = std::fs::OpenOptions::new()
            .access_mode(DELETE | FILE_LIST_DIRECTORY)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | 0x4)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&dir)
            .unwrap();
        let release = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(120));
            drop(busy);
        });
        write_private_file(&dir, "connection.enc", b"x").expect("retried until released");
        release.join().unwrap();
    }

    /// #21: a parent that is a junction is refused, and so is a pairing
    /// folder that isn't inside the held parent.
    #[test]
    fn a_parent_that_is_a_junction_is_refused() {
        let base = tempfile::tempdir().unwrap();
        let real = base.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = base.path().join("local");
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&real)
            .output()
            .expect("mklink");
        assert!(status.status.success(), "mklink /J failed");
        assert_eq!(ensure_private_dir(&link.join("vettid-desktop")), refused(NotPrivate::ParentLink));
        assert!(!real.join("vettid-desktop").exists(), "nothing created through it");
    }

    /// #21: the write path holds and judges the parent too: once the parent
    /// lets another account delete entries, a write is refused and the old
    /// file is kept.
    #[test]
    fn a_write_under_a_parent_another_account_controls_is_refused_and_kept() {
        let base = tempfile::tempdir().unwrap();
        let parent = base.path().join("local");
        std::fs::create_dir(&parent).unwrap();
        let dir = parent.join("vettid-desktop");
        ensure_private_dir(&dir).unwrap();
        write_private_file(&dir, "connection.enc", b"the old pairing").unwrap();
        let me = me();
        set_dacl(&parent, &format!("D:P(A;OICI;FA;;;{me})(A;OICI;FA;;;SY)(A;;0x40;;;WD)"));
        assert_eq!(
            write_private_file(&dir, "connection.enc", b"new"),
            refused(NotPrivate::ParentForeignControl)
        );
        assert_eq!(std::fs::read(dir.join("connection.enc")).unwrap(), b"the old pairing");
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
        assert_eq!(
            write_private_file(base.path(), "connection.enc", b"new").err(),
            Some(AclError::NotPrivate(NotPrivate::ForeignAccess))
        );
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
        write_private_file(&dir, "connection.enc", b"x").expect("write");
        assert!(test_is_user_only(&dir.join("connection.enc")));
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

    /// A junction where connection.enc should be: refused, and nothing is
    /// written through it. The write never opens the target path for
    /// writing (it creates a new temporary file and moves it), and the
    /// existing entry is checked first.
    #[test]
    fn junction_at_the_file_is_refused() {
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
        assert_eq!(
            write_private_file(base.path(), "connection.enc", b"new").err(),
            Some(AclError::NotPrivate(NotPrivate::ReparsePoint))
        );
        assert!(std::fs::read_dir(&target).unwrap().next().is_none(), "nothing written through the link");
    }

    /// The folder itself as a junction is refused when held, on its handle.
    #[test]
    fn junction_as_the_folder_is_refused_when_held() {
        let base = tempfile::tempdir().unwrap();
        let target = base.path().join("elsewhere");
        std::fs::create_dir(&target).unwrap();
        let link = base.path().join("vettid-desktop");
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&target)
            .output()
            .expect("mklink");
        assert!(status.status.success(), "mklink /J failed");
        assert_eq!(
            hold_folder(&link, &current_user_sid().unwrap()).err(),
            Some(AclError::NotPrivate(NotPrivate::ReparsePoint))
        );
        assert_eq!(
            write_private_file(&link, "connection.enc", b"new").err(),
            Some(AclError::NotPrivate(NotPrivate::ReparsePoint))
        );
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
        assert_eq!(
            write_private_file(&dir, "connection.enc", b"new").err(),
            Some(AclError::NotPrivate(NotPrivate::HardLinked))
        );
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
