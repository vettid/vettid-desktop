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

use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
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
    /// Any DPAPI error is failing, not "won't open": a reset password or a
    /// profile problem may be put right, and the file is kept either way.
    fn unwrap(&self, wrapped: &[u8]) -> Result<DataKey, ProtectorError> {
        let plain = unprotect(wrapped, self.entropy).map_err(|c| Self::failing("CryptUnprotectData", c))?;
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
        assert!(matches!(other.unwrap(&wrapped), Err(ProtectorError::Failing { .. })));
        // Nor does a changed blob.
        let mut tampered = wrapped.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(p.unwrap(&tampered).is_err());
        assert!(p.unwrap(&[]).is_err());
        // Not absent, nothing outside the file.
        assert_eq!(p.availability(), Availability::Present);
        p.remove_external().unwrap();
    }
}
