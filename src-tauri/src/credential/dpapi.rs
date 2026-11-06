//! Windows: the DPAPI protector, user scope (DESKTOP-REWORK-PLAN §4
//! "At-rest protectors").
//!
//! `CryptProtectData` with `CRYPTPROTECT_UI_FORBIDDEN` and an app-specific
//! entropy label; `CRYPTPROTECT_LOCAL_MACHINE` is **not** set, so only this
//! Windows account can unwrap (any process running as it can; the entropy
//! label is domain separation, not a secret). The wrapped key lives in the
//! file's header: DPAPI keeps nothing outside the file, so a wipe has no
//! key of its own to remove. It replaces the Credential Manager master key
//! (`wincred`), which is kept only to delete the earlier format's entry
//! ([`LegacyCredential`]).

use std::ptr;

use windows_sys::Win32::Foundation::{GetLastError, LocalFree, ERROR_INVALID_DATA, NTE_BAD_DATA};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetFreeAadJoinInformation, NetGetAadJoinInformation, NetGetJoinInformation, NetSetupDomainName, DSREG_DEVICE_JOIN,
    DSREG_JOIN_INFO,
};
use windows_sys::Win32::System::GroupPolicy::{PT_ROAMING, PT_ROAMING_PREEXISTING};
use windows_sys::Win32::UI::Shell::GetProfileType;
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};
use zeroize::Zeroizing;

use super::protector::{Availability, DataKey, LegacyKey, Protector, ProtectorError};

/// The entropy label: binds a wrapped key to this use, so a DPAPI blob made
/// for anything else (by this or another app) doesn't unwrap as one.
const ENTROPY: &[u8] = b"vettid-desktop-device-key-v1";

const NAME: &str = "Windows data protection";

/// DPAPI, user scope.
pub(crate) struct Dpapi {
    entropy: &'static [u8],
}

impl Dpapi {
    pub(crate) fn user() -> Self {
        Dpapi { entropy: ENTROPY }
    }

    #[cfg(test)]
    fn with_entropy(entropy: &'static [u8]) -> Self {
        Dpapi { entropy }
    }

    fn failing(what: &str, code: u32) -> ProtectorError {
        ProtectorError::Failing { by: NAME, detail: format!("{what} failed (error {code})") }
    }
}

/// How a `CryptUnprotectData` error is taken: a blob that is bad (garbled,
/// cut short, or not made with this entropy) won't open later either;
/// anything else (a profile or password problem, a busy system) may.
fn unprotect_error(code: u32) -> ProtectorError {
    if code == ERROR_INVALID_DATA || code == NTE_BAD_DATA as u32 {
        ProtectorError::WontOpen(format!("CryptUnprotectData: a bad blob (error {code})"))
    } else {
        Dpapi::failing("CryptUnprotectData", code)
    }
}

fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
    // The API takes a mutable pointer for its input blobs but doesn't write
    // through it.
    CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 }
}

/// `CryptProtectData`, user scope, no UI.
fn protect(data: &[u8], entropy: &[u8]) -> Result<Vec<u8>, u32> {
    let input = blob(data);
    let entropy = blob(entropy);
    let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: ptr::null_mut() };
    // SAFETY: the input blobs point to live slices for the call; `out`
    // receives a LocalAlloc'd buffer, freed below.
    let ok = unsafe {
        CryptProtectData(&input, ptr::null(), &entropy, ptr::null(), ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out)
    };
    if ok == 0 {
        // SAFETY: reads the calling thread's last-error value.
        return Err(unsafe { GetLastError() });
    }
    // SAFETY: on success `out` holds `cbData` bytes at `pbData`.
    let wrapped = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
    // SAFETY: allocated by CryptProtectData; freed once.
    unsafe { LocalFree(out.pbData as _) };
    Ok(wrapped)
}

/// `CryptUnprotectData` with `entropy`, no UI. The system's copy of the
/// plaintext is wiped before it is freed.
fn unprotect(wrapped: &[u8], entropy: &[u8]) -> Result<Zeroizing<Vec<u8>>, u32> {
    let input = blob(wrapped);
    let entropy = blob(entropy);
    let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: ptr::null_mut() };
    // SAFETY: as in `protect`; no description is asked for.
    let ok = unsafe {
        CryptUnprotectData(&input, ptr::null_mut(), &entropy, ptr::null(), ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out)
    };
    if ok == 0 {
        // SAFETY: reads the calling thread's last-error value.
        return Err(unsafe { GetLastError() });
    }
    // SAFETY: on success `out` holds `cbData` bytes at `pbData`, ours until
    // LocalFree.
    let plain = unsafe {
        let bytes = std::slice::from_raw_parts_mut(out.pbData, out.cbData as usize);
        let plain = Zeroizing::new(bytes.to_vec());
        // SECURITY: wipe the system's copy of the key before freeing it.
        for b in bytes.iter_mut() {
            ptr::write_volatile(b, 0);
        }
        LocalFree(out.pbData as _);
        plain
    };
    Ok(plain)
}

impl Protector for Dpapi {
    fn id(&self) -> &'static str {
        "dpapi"
    }
    /// Part of Windows: never absent.
    fn availability(&self) -> Availability {
        Availability::Present
    }
    /// Wraps and unwraps a fixed, non-secret value.
    fn probe(&self) -> Result<(), ProtectorError> {
        const PROBE: [u8; 32] = [0u8; 32];
        let wrapped = protect(&PROBE, self.entropy).map_err(|c| Self::failing("CryptProtectData", c))?;
        let back = unprotect(&wrapped, self.entropy).map_err(|c| Self::failing("CryptUnprotectData", c))?;
        if back[..] != PROBE {
            return Err(ProtectorError::Failing { by: NAME, detail: "the probe didn't round-trip".into() });
        }
        Ok(())
    }
    fn wrap(&self, key: &[u8; 32]) -> Result<Vec<u8>, ProtectorError> {
        protect(key, self.entropy).map_err(|c| Self::failing("CryptProtectData", c))
    }
    /// A bad blob won't open ([`unprotect_error`]); any other DPAPI error is
    /// failing: a reset password or a profile problem may be put right. The
    /// file is kept either way.
    fn unwrap(&self, wrapped: &[u8]) -> Result<DataKey, ProtectorError> {
        let plain = unprotect(wrapped, self.entropy).map_err(unprotect_error)?;
        if plain.len() != 32 {
            return Err(ProtectorError::WontOpen(format!("a wrapped key of {} bytes", plain.len())));
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&plain);
        Ok(key)
    }
    /// DPAPI keeps nothing outside the file.
    fn remove_external(&self) -> Result<(), ProtectorError> {
        Ok(())
    }
}

/// Who else may open a DPAPI-wrapped key of this account (the plan's DPAPI
/// row): a notice for the person, never a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Reach {
    /// This computer is joined to a domain: its administrators can recover
    /// the account's DPAPI keys.
    pub domain: bool,
    /// The profile roams: the DPAPI master keys travel with it.
    pub roaming: bool,
    /// This computer is joined to an organization's Microsoft Entra ID
    /// (#13; `NetGetJoinInformation` doesn't see that join): its
    /// administrators are this computer's administrators, who can run code
    /// as the user.
    pub entra: bool,
}

/// NEW TEXT (owner approval needed): Settings, when this computer is
/// joined to a domain.
pub(crate) const DOMAIN_NOTICE: &str =
    "This computer is joined to your organization's domain. An administrator of that domain may be able to open this desktop's saved pairing.";

/// Owner-approved text (#13, 2026-11-06): Settings, when this computer is
/// joined to an organization's Microsoft Entra ID. It claims only what §4
/// says of any administrator: they can run code as the user while the user
/// is logged on.
pub(crate) const ENTRA_NOTICE: &str =
    "This computer is joined to your organization's Microsoft Entra ID. Its administrators can manage this computer, and may be able to open this desktop's saved pairing while you're signed in.";

/// NEW TEXT (owner approval needed): Settings, when the profile roams.
pub(crate) const ROAMING_NOTICE: &str =
    "Your Windows profile roams. Someone with a copy of the saved pairing file, a copy of your profile and your password could open it on another computer.";

impl Reach {
    /// This account's reach. SECURITY: a check that fails counts as false
    /// and gives no notice, so no notice is not a guarantee (the plan says
    /// so); the failure is logged by its code.
    pub fn here() -> Self {
        Self::from_checks(domain_joined(), roaming_profile(), entra_joined())
    }

    fn from_checks(domain: Result<bool, u32>, roaming: Result<bool, u32>, entra: Result<bool, u32>) -> Self {
        let checked = |what: &str, r: Result<bool, u32>| {
            r.unwrap_or_else(|code| {
                log::warn!("dpapi: the {what} check failed (error {code}, {code:#010x}); no notice");
                false
            })
        };
        Reach { domain: checked("domain", domain), roaming: checked("roaming profile", roaming), entra: checked("Entra join", entra) }
    }

    /// The notices for Settings, in order.
    pub fn notices(self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.domain {
            out.push(DOMAIN_NOTICE);
        }
        if self.entra {
            out.push(ENTRA_NOTICE);
        }
        if self.roaming {
            out.push(ROAMING_NOTICE);
        }
        out
    }
}

/// `NetGetJoinInformation`: joined to a domain (not a workgroup).
fn domain_joined() -> Result<bool, u32> {
    let mut name: windows_sys::core::PWSTR = ptr::null_mut();
    let mut status = 0;
    // SAFETY: both out-pointers are live locals; the name buffer is freed
    // with NetApiBufferFree below.
    let code = unsafe { NetGetJoinInformation(ptr::null(), &mut name, &mut status) };
    if !name.is_null() {
        // SAFETY: allocated by NetGetJoinInformation; freed once.
        unsafe { NetApiBufferFree(name as *const _) };
    }
    if code != 0 {
        return Err(code);
    }
    Ok(status == NetSetupDomainName)
}

/// `NetGetAadJoinInformation`: this computer is joined to Microsoft Entra ID
/// (a device join; a work account merely registered on a personal computer,
/// `DSREG_WORKPLACE_JOIN`, doesn't make its administrators this computer's).
/// Not joined: no information, and `S_FALSE`. `NetGetAadJoinInformation`
/// is imported at load time, so the app needs Windows 10 1607 or later (no
/// supported Windows is older). A hybrid join shows both this notice and
/// the domain one.
fn entra_joined() -> Result<bool, u32> {
    let mut info: *mut DSREG_JOIN_INFO = ptr::null_mut();
    // SAFETY: `info` is a live local out-pointer; a non-null result is freed
    // with NetFreeAadJoinInformation below, once.
    let hr = unsafe { NetGetAadJoinInformation(ptr::null(), &mut info) };
    let joined = if info.is_null() {
        false
    } else {
        // SAFETY: non-null, allocated by NetGetAadJoinInformation; read
        // before it is freed.
        let device = unsafe { (*info).joinType } == DSREG_DEVICE_JOIN;
        // SAFETY: as above; freed once.
        unsafe { NetFreeAadJoinInformation(info) };
        device
    };
    // Success is any non-negative HRESULT: S_OK, or S_FALSE (1), which is
    // what a computer joined to nothing answers (seen on tempe, where
    // `dsregcmd /status` says AzureAdJoined NO).
    if hr < 0 {
        return Err(hr as u32);
    }
    Ok(joined)
}

/// `GetProfileType`: the current user's profile roams.
fn roaming_profile() -> Result<bool, u32> {
    let mut flags = 0u32;
    // SAFETY: `flags` is a live local.
    if unsafe { GetProfileType(&mut flags) } == 0 {
        // SAFETY: reads the calling thread's last-error value.
        return Err(unsafe { GetLastError() });
    }
    Ok(flags & (PT_ROAMING | PT_ROAMING_PREEXISTING) != 0)
}

/// The earlier format's Credential Manager entry
/// (`vettid-desktop/master-key-v1/local`): deleted, then read back.
pub(crate) struct LegacyCredential;

impl LegacyKey for LegacyCredential {
    fn remove(&self) -> Result<(), ProtectorError> {
        // Tests must never touch this machine's real Credential Manager
        // entry; one that gets here is a test bug.
        if cfg!(test) {
            panic!("a test reached the real Credential Manager entry");
        }
        let what = "the earlier version's Credential Manager key";
        super::wincred::delete().map_err(|detail| ProtectorError::NotRemoved { what, detail })?;
        match super::wincred::is_present() {
            Ok(false) => Ok(()),
            Ok(true) => Err(ProtectorError::NotRemoved { what, detail: "still there".into() }),
            Err(detail) => Err(ProtectorError::NotRemoved { what, detail: format!("could not be checked: {detail}") }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Through the real DPAPI of the user running the tests (DPAPI keeps no
    /// state). The key is a fixed test value and is never printed.
    #[test]
    fn dpapi_round_trip_and_refusals() {
        let p = Dpapi::user();
        p.probe().expect("DPAPI works for this user");
        let key = [0x42u8; 32];
        let wrapped = p.wrap(&key).unwrap();
        assert!(!wrapped.windows(32).any(|w| w == key), "the key isn't in the wrapped form");
        assert_eq!(*p.unwrap(&wrapped).unwrap(), key);
        // Wrapped twice, two different blobs, both open.
        let again = p.wrap(&key).unwrap();
        assert_ne!(again, wrapped);
        assert_eq!(*p.unwrap(&again).unwrap(), key);

        // Another entropy label doesn't open it.
        let other = Dpapi::with_entropy(b"vettid-desktop-something-else");
        assert!(other.unwrap(&wrapped).is_err());
        // Nor does a changed blob.
        let mut tampered = wrapped.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(p.unwrap(&tampered).is_err());
        assert!(p.unwrap(&[]).is_err());
        // A garbled blob won't open (Unreadable), not "try again".
        let garbled = vec![0x17u8; wrapped.len()];
        match p.unwrap(&garbled) {
            Err(ProtectorError::WontOpen(_)) => {}
            Err(e) => panic!("a garbled blob: {e}"),
            Ok(_) => panic!("a garbled blob opened"),
        }
        // Not absent, nothing outside the file.
        assert_eq!(p.availability(), Availability::Present);
        p.remove_external().unwrap();
    }

    #[test]
    fn bad_blob_errors_wont_open_and_others_fail() {
        assert!(matches!(unprotect_error(ERROR_INVALID_DATA), ProtectorError::WontOpen(_)));
        assert!(matches!(unprotect_error(NTE_BAD_DATA as u32), ProtectorError::WontOpen(_)));
        // NTE_BAD_KEY_STATE (a reset password), access denied: may work later.
        for other in [0x8009000Bu32, 5] {
            assert!(matches!(unprotect_error(other), ProtectorError::Failing { .. }));
        }
    }

    /// A failed check gives no notice; either check alone gives its own.
    #[test]
    fn reach_notices_follow_the_checks() {
        assert_eq!(Reach::from_checks(Ok(false), Ok(false), Ok(false)).notices(), Vec::<&str>::new());
        assert_eq!(Reach::from_checks(Ok(true), Ok(false), Ok(false)).notices(), vec![DOMAIN_NOTICE]);
        assert_eq!(Reach::from_checks(Ok(false), Ok(true), Ok(false)).notices(), vec![ROAMING_NOTICE]);
        assert_eq!(Reach::from_checks(Ok(true), Ok(true), Ok(false)).notices(), vec![DOMAIN_NOTICE, ROAMING_NOTICE]);
        assert_eq!(Reach::from_checks(Err(5), Err(5), Err(5)), Reach::default());
        assert_eq!(Reach::from_checks(Err(5), Ok(true), Err(5)).notices(), vec![ROAMING_NOTICE]);
        // #13: an Entra-only join (NetGetJoinInformation says workgroup).
        assert_eq!(Reach::from_checks(Ok(false), Ok(false), Ok(true)).notices(), vec![ENTRA_NOTICE]);
        assert_eq!(Reach::from_checks(Ok(true), Ok(true), Ok(true)).notices(), vec![DOMAIN_NOTICE, ENTRA_NOTICE, ROAMING_NOTICE]);
        // This machine's own check runs; its answer isn't asserted (a
        // developer's laptop may well be joined).
        let _ = entra_joined();
    }

    /// The real checks run on this machine (their answer isn't asserted).
    #[test]
    fn the_real_reach_checks_return() {
        let _ = domain_joined();
        let _ = roaming_profile();
        let _ = Reach::here();
    }
}
