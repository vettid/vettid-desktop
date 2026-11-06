//! At-rest protectors (AG3, #13; DESKTOP-REWORK-PLAN §4 "At-rest
//! protectors"): what wraps the random data key that seals `device.enc`.
//!
//! - **Windows: DPAPI, user scope** (`super::dpapi`). The wrapped key is in
//!   the file's header; DPAPI keeps nothing outside it. Bound to this
//!   computer and this account.
//! - **Linux: the TPM 2.0** (`super::tpm`), through `/dev/tpmrm0`: the data
//!   key sealed under the storage root key, the sealed object in the
//!   header. Bound to this computer.
//! - **Linux without a TPM this user can use: the Secret Service**
//!   (`super::secret_service`, the owner's choice (b)): one keyring item
//!   per file, named by an id in the header. Not bound to this computer.
//! - **macOS, for now: the OS keyring** through the `keyring` crate (the
//!   login keychain, until the keychain and passphrase protectors land).
//!   The data key is the keyring entry itself, so the header's wrapped key
//!   is empty. Not bound to this computer: Settings says so.
//!
//! **Absent and failing are different.** A protector says it is absent
//! only from a fixed, detected condition ([`Availability::Absent`]), never
//! from an error; the next one is then tried. Every error of a protector
//! that is present is [`ProtectorError::Failing`]: pairing or loading stops
//! with the reason and never falls back. DPAPI and the macOS keyring are
//! never absent. On Linux the TPM is absent when `/dev/tpmrm0` is missing
//! or not usable by this user, and the Secret Service when there is no
//! session bus or no `org.freedesktop.secrets` on it; with both absent,
//! pairing is refused with the no-protector notice.
//!
//! The legacy `master-key-v1` entry of the earlier format is only ever
//! deleted here ([`LegacyKey`]); nothing reads it.
//!
//! Test protectors are `#[cfg(test)]` only: no flag or environment
//! variable selects one in a build a member could run. Errors are logged
//! by their code, never with key bytes.

use zeroize::Zeroizing;

/// A data key: 256 random bits, wiped on drop.
pub(crate) type DataKey = Zeroizing<[u8; 32]>;

/// Whether a protector is there to be used, detected (not inferred from an
/// error).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Availability {
    Present,
    /// Detected as not there, with what was detected (for the log).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))] // only Linux's protectors can be absent
    Absent(&'static str),
}

#[derive(Debug)]
pub(crate) enum ProtectorError {
    /// Every protector is absent on this computer.
    NoneAvailable,
    /// A protector that is present failed. `by` is its plain name, for the
    /// person; `detail` is for the log only and holds no key material.
    Failing { by: &'static str, detail: String },
    /// The wrapped key or the protector's entry doesn't open this file and
    /// won't later (no entry, a wrapped key of the wrong shape): the file
    /// is unreadable here.
    WontOpen(String),
    /// A key kept outside the file couldn't be confirmed gone.
    NotRemoved { what: &'static str, detail: String },
    /// The secret the person gave (the passphrase, #13) doesn't open the
    /// key: a wrong one, or a changed file, which can't be told apart. The
    /// file is kept and the person can try again; never "won't open", which
    /// would tell them to re-pair.
    #[cfg_attr(not(test), allow(dead_code))] // the passphrase protector is wired in by #13 item 4
    NotThisSecret { by: &'static str },
}

impl std::fmt::Display for ProtectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtectorError::NoneAvailable => f.write_str("no protector is available on this computer"),
            ProtectorError::Failing { by, detail } => write!(f, "{by} failed: {detail}"),
            ProtectorError::WontOpen(detail) => write!(f, "the data key doesn't open: {detail}"),
            ProtectorError::NotRemoved { what, detail } => write!(f, "{what} not removed: {detail}"),
            ProtectorError::NotThisSecret { by } => write!(f, "{by} doesn't open the data key"),
        }
    }
}

/// One way of protecting the data key.
pub(crate) trait Protector: Send + Sync {
    /// The header's `protector` value.
    fn id(&self) -> &'static str;
    fn availability(&self) -> Availability;
    /// Checked before pairing starts: Ok if this protector works now.
    /// Creates and keeps nothing.
    fn probe(&self) -> Result<(), ProtectorError>;
    /// Protect a new data key; returns what goes in the header's
    /// `wrapped_key` (empty when the protector keeps the key itself).
    fn wrap(&self, key: &[u8; 32]) -> Result<Vec<u8>, ProtectorError>;
    /// The data key from the header's `wrapped_key`.
    fn unwrap(&self, wrapped: &[u8]) -> Result<DataKey, ProtectorError>;
    /// Remove any key this protector keeps outside the file, and confirm
    /// it is gone. Ok when it keeps none.
    fn remove_external(&self) -> Result<(), ProtectorError>;
    /// As [`Protector::remove_external`], knowing what is being wiped. A
    /// protector that can't be reached here may then say there is nothing
    /// of its to confirm (the Secret Service); the rest ignore it.
    fn remove_external_for(&self, wiping: &Wiping) -> Result<(), ProtectorError> {
        let _ = wiping;
        self.remove_external()
    }
}

/// The earlier format's master key entry (`master-key-v1`): deleted and
/// confirmed gone, never read for use.
pub(crate) trait LegacyKey: Send + Sync {
    fn remove(&self) -> Result<(), ProtectorError>;
    /// As [`LegacyKey::remove`], knowing what is being wiped.
    fn remove_for(&self, wiping: &Wiping) -> Result<(), ProtectorError> {
        let _ = wiping;
        self.remove()
    }
}

/// What a wipe removes, read before it from the device file's header
/// (unauthenticated: nothing is decrypted), so that a protector that can't
/// be reached knows whether it could hold anything of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Wiping {
    /// The header's `protector`; `None` when there is no device file, or
    /// one that can't be read or parsed: then anything could have been
    /// kept, by any protector.
    pub(crate) sealed_by: Option<String>,
    /// Whether an earlier format's pairing (a v1 `device.enc`, or
    /// `connection.enc`) is involved, or can't be ruled out.
    pub(crate) legacy: bool,
}

impl Wiping {
    /// Nothing known: every protector confirms.
    pub(crate) fn unknown() -> Self {
        Wiping { sealed_by: None, legacy: true }
    }

    /// Retiring an earlier format's file.
    pub(crate) fn legacy_file() -> Self {
        Wiping { sealed_by: Some("legacy".into()), legacy: true }
    }

    /// No device file, and no earlier format's pairing: nothing of a
    /// pairing can be in any protector (a key left without its file is an
    /// orphan, see `secret_service`).
    pub(crate) fn nothing() -> Self {
        Wiping { sealed_by: Some("none".into()), legacy: false }
    }

    /// Both together (a pending wipe's marker and what is on disk now):
    /// the same protector, or one side with no file, keeps it; two
    /// different ones are unknown. Legacy if either is.
    pub(crate) fn and(self, other: Wiping) -> Wiping {
        let sealed_by = match (self.sealed_by, other.sealed_by) {
            (Some(a), Some(b)) if a == b => Some(a),
            (Some(a), Some(b)) if b == "none" => Some(a),
            (Some(a), Some(b)) if a == "none" => Some(b),
            _ => None,
        };
        Wiping { sealed_by, legacy: self.legacy || other.legacy }
    }

    /// Whether a file sealed by one of `ids` may be involved.
    pub(crate) fn may_be_sealed_by(&self, ids: &[&str]) -> bool {
        self.sealed_by.as_deref().is_none_or(|id| ids.contains(&id))
    }
}

/// The TPM protector's plain name, for the person (the notices give other
/// advice for it than for the keyring, see `store`).
pub(crate) const TPM_NAME: &str = "this computer's TPM";

/// What a header's `protector` says, for Settings: the id as shown, and
/// whether it binds the file to this computer. `None` for an id this build
/// doesn't know.
pub(crate) fn describe(id: &str) -> Option<(&'static str, bool)> {
    match id {
        "dpapi" => Some(("dpapi", true)),
        "tpm" => Some(("tpm", true)),
        "secret-service" => Some(("secret-service", false)),
        // Linux has no keyring protector (a file of the build before this
        // one, sealed by it, is unreadable here: re-pair).
        #[cfg(not(target_os = "linux"))]
        "keyring" => Some(("keyring", false)),
        #[cfg(test)]
        "test" => Some(("test", true)),
        _ => None,
    }
}

/// The protectors of this platform, best first, and the legacy entry.
pub(crate) struct Protectors {
    ranked: Vec<Box<dyn Protector>>,
    legacy: Box<dyn LegacyKey>,
}

impl Protectors {
    /// This platform's real protectors.
    pub(crate) fn system() -> Self {
        #[cfg(windows)]
        {
            Protectors { ranked: vec![Box::new(super::dpapi::Dpapi::user())], legacy: Box::new(super::dpapi::LegacyCredential) }
        }
        #[cfg(target_os = "linux")]
        {
            Protectors {
                ranked: vec![Box::new(super::tpm::Tpm::system()), Box::new(super::secret_service::SecretService::system())],
                legacy: Box::new(super::secret_service::LegacyEntry::system()),
            }
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            Protectors { ranked: vec![Box::new(keyring_store::Keyring)], legacy: Box::new(keyring_store::LegacyEntry) }
        }
    }

    #[cfg(test)]
    pub(crate) fn new(ranked: Vec<Box<dyn Protector>>, legacy: Box<dyn LegacyKey>) -> Self {
        Protectors { ranked, legacy }
    }

    /// The best protector present. Only an absent one is passed over.
    pub(crate) fn choose(&self) -> Result<&dyn Protector, ProtectorError> {
        for p in &self.ranked {
            match p.availability() {
                Availability::Present => return Ok(p.as_ref()),
                Availability::Absent(why) => log::info!("protector {}: absent ({})", p.id(), why),
            }
        }
        Err(ProtectorError::NoneAvailable)
    }

    /// The protector a header names, if this build has it here.
    pub(crate) fn by_id(&self, id: &str) -> Option<&dyn Protector> {
        self.ranked.iter().find(|p| p.id() == id).map(|p| p.as_ref())
    }

    /// Whether pairing can save its keys: the chosen protector works now.
    pub(crate) fn ready(&self) -> Result<(), ProtectorError> {
        self.choose()?.probe()
    }

    /// Remove every external key (each protector's, then the legacy entry),
    /// each confirmed gone, for the wipe of `wiping`. All are tried; the
    /// first failure is returned.
    pub(crate) fn remove_external_keys(&self, wiping: &Wiping) -> Result<(), ProtectorError> {
        let mut first = None;
        let results = self.ranked.iter().map(|p| p.remove_external_for(wiping)).chain(std::iter::once(self.legacy.remove_for(wiping)));
        for r in results {
            if let Err(e) = r {
                log::error!("key store: {}", e);
                first.get_or_insert(e);
            }
        }
        first.map_or(Ok(()), Err)
    }

    /// Remove the legacy entry alone, confirmed gone.
    pub(crate) fn remove_legacy_key(&self, wiping: &Wiping) -> Result<(), ProtectorError> {
        self.legacy.remove_for(wiping)
    }
}

/// The OS keyring through the `keyring` crate: the interim protector on
/// macOS (see the module doc).
#[cfg(not(any(windows, target_os = "linux")))]
mod keyring_store {
    use super::{Availability, DataKey, LegacyKey, Protector, ProtectorError};
    use zeroize::Zeroizing;

    const SERVICE: &str = "vettid-desktop";
    /// The data key's entry. Not `master-key-v1`, the earlier format's.
    const ACCOUNT: &str = "device-key-v2";
    /// The earlier format's entry, only ever deleted.
    const LEGACY_ACCOUNT: &str = "master-key-v1";
    const NAME: &str = "your computer's keyring";

    /// Tests must never touch this machine's real keyring; one that gets
    /// here is a test bug.
    fn not_in_tests() {
        if cfg!(test) {
            panic!("a test reached the real keyring");
        }
    }

    fn entry(account: &str) -> Result<keyring::Entry, ProtectorError> {
        not_in_tests();
        keyring::Entry::new(SERVICE, account).map_err(|e| ProtectorError::Failing { by: NAME, detail: format!("entry: {e}") })
    }

    fn failing(what: &str, e: keyring::Error) -> ProtectorError {
        ProtectorError::Failing { by: NAME, detail: format!("{what}: {e}") }
    }

    /// Delete `account`'s entry, then read it back: Ok only on "no entry".
    fn remove_confirmed(account: &str, what: &'static str) -> Result<(), ProtectorError> {
        let not_removed = |detail: String| ProtectorError::NotRemoved { what, detail };
        let entry = entry(account).map_err(|e| not_removed(e.to_string()))?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => {}
            Err(e) => return Err(not_removed(format!("delete: {e}"))),
        }
        match entry.get_secret() {
            Err(keyring::Error::NoEntry) => Ok(()),
            Ok(secret) => {
                drop(Zeroizing::new(secret));
                Err(not_removed("still there".into()))
            }
            Err(e) => Err(not_removed(format!("could not be checked: {e}"))),
        }
    }

    pub(super) struct Keyring;

    impl Protector for Keyring {
        fn id(&self) -> &'static str {
            "keyring"
        }
        fn availability(&self) -> Availability {
            Availability::Present
        }
        fn probe(&self) -> Result<(), ProtectorError> {
            match entry(ACCOUNT)?.get_secret() {
                Ok(secret) => {
                    drop(Zeroizing::new(secret));
                    Ok(())
                }
                Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(failing("read", e)),
            }
        }
        fn wrap(&self, key: &[u8; 32]) -> Result<Vec<u8>, ProtectorError> {
            entry(ACCOUNT)?.set_secret(key).map_err(|e| failing("write", e))?;
            Ok(Vec::new())
        }
        fn unwrap(&self, wrapped: &[u8]) -> Result<DataKey, ProtectorError> {
            if !wrapped.is_empty() {
                return Err(ProtectorError::WontOpen("a wrapped key where the keyring keeps it".into()));
            }
            let secret = match entry(ACCOUNT)?.get_secret() {
                Ok(s) => Zeroizing::new(s),
                Err(keyring::Error::NoEntry) => return Err(ProtectorError::WontOpen("no keyring entry".into())),
                Err(e) => return Err(failing("read", e)),
            };
            if secret.len() != 32 {
                return Err(ProtectorError::WontOpen(format!("a keyring entry of {} bytes", secret.len())));
            }
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(&secret);
            Ok(key)
        }
        fn remove_external(&self) -> Result<(), ProtectorError> {
            remove_confirmed(ACCOUNT, "the keyring's device key")
        }
    }

    pub(super) struct LegacyEntry;

    impl LegacyKey for LegacyEntry {
        fn remove(&self) -> Result<(), ProtectorError> {
            remove_confirmed(LEGACY_ACCOUNT, "the earlier version's keyring key")
        }
    }
}

/// Test protectors: fixed keys, and failures on demand.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    /// What the test protectors do, shared with the test.
    #[derive(Default)]
    pub(crate) struct Behaviour {
        pub absent: AtomicBool,
        pub fail_probe: AtomicBool,
        pub fail_wrap: AtomicBool,
        pub fail_unwrap: AtomicBool,
        pub fail_remove: AtomicBool,
        pub fail_legacy_remove: AtomicBool,
        pub wraps: AtomicUsize,
        pub removes: AtomicUsize,
        pub legacy_removes: AtomicUsize,
    }

    impl Behaviour {
        pub(crate) fn set(flag: &AtomicBool, on: bool) {
            flag.store(on, Ordering::SeqCst);
        }
        pub(crate) fn count(n: &AtomicUsize) -> usize {
            n.load(Ordering::SeqCst)
        }
    }

    /// The test protector's plain name.
    const TEST_NAME: &str = "the test protector";

    /// A fixed, public test mask: the wrapped key is the key XOR it.
    const MASK: [u8; 32] = [0x5a; 32];

    /// Wraps with a fixed mask; keeps nothing outside the file, but counts
    /// (and can fail) its removals.
    pub(crate) struct TestProtector(pub Arc<Behaviour>);

    impl Protector for TestProtector {
        fn id(&self) -> &'static str {
            "test"
        }
        fn availability(&self) -> Availability {
            if self.0.absent.load(Ordering::SeqCst) {
                Availability::Absent("test")
            } else {
                Availability::Present
            }
        }
        fn probe(&self) -> Result<(), ProtectorError> {
            if self.0.fail_probe.load(Ordering::SeqCst) {
                return Err(ProtectorError::Failing { by: TEST_NAME, detail: "test".into() });
            }
            Ok(())
        }
        fn wrap(&self, key: &[u8; 32]) -> Result<Vec<u8>, ProtectorError> {
            if self.0.fail_wrap.load(Ordering::SeqCst) {
                return Err(ProtectorError::Failing { by: TEST_NAME, detail: "test".into() });
            }
            self.0.wraps.fetch_add(1, Ordering::SeqCst);
            Ok(key.iter().zip(MASK).map(|(k, m)| k ^ m).collect())
        }
        fn unwrap(&self, wrapped: &[u8]) -> Result<DataKey, ProtectorError> {
            if self.0.fail_unwrap.load(Ordering::SeqCst) {
                return Err(ProtectorError::Failing { by: TEST_NAME, detail: "test".into() });
            }
            if wrapped.len() != 32 {
                return Err(ProtectorError::WontOpen("length".into()));
            }
            let mut key = Zeroizing::new([0u8; 32]);
            for (k, (w, m)) in key.iter_mut().zip(wrapped.iter().zip(MASK)) {
                *k = w ^ m;
            }
            Ok(key)
        }
        fn remove_external(&self) -> Result<(), ProtectorError> {
            self.0.removes.fetch_add(1, Ordering::SeqCst);
            if self.0.fail_remove.load(Ordering::SeqCst) {
                return Err(ProtectorError::NotRemoved { what: "the test key", detail: "test".into() });
            }
            Ok(())
        }
    }

    pub(crate) struct TestLegacy(pub Arc<Behaviour>);

    impl LegacyKey for TestLegacy {
        fn remove(&self) -> Result<(), ProtectorError> {
            self.0.legacy_removes.fetch_add(1, Ordering::SeqCst);
            if self.0.fail_legacy_remove.load(Ordering::SeqCst) {
                return Err(ProtectorError::NotRemoved { what: "the test legacy key", detail: "test".into() });
            }
            Ok(())
        }
    }

    /// The test protector and test legacy entry, sharing `b`.
    pub(crate) fn protectors(b: &Arc<Behaviour>) -> Protectors {
        Protectors::new(vec![Box::new(TestProtector(b.clone()))], Box::new(TestLegacy(b.clone())))
    }

    #[test]
    fn only_an_absent_protector_is_passed_over() {
        let first = Arc::new(Behaviour::default());
        let second = Arc::new(Behaviour::default());
        struct Second(TestProtector);
        impl Protector for Second {
            fn id(&self) -> &'static str {
                "second"
            }
            fn availability(&self) -> Availability {
                self.0.availability()
            }
            fn probe(&self) -> Result<(), ProtectorError> {
                self.0.probe()
            }
            fn wrap(&self, key: &[u8; 32]) -> Result<Vec<u8>, ProtectorError> {
                self.0.wrap(key)
            }
            fn unwrap(&self, wrapped: &[u8]) -> Result<DataKey, ProtectorError> {
                self.0.unwrap(wrapped)
            }
            fn remove_external(&self) -> Result<(), ProtectorError> {
                self.0.remove_external()
            }
        }
        let p = Protectors::new(
            vec![Box::new(TestProtector(first.clone())), Box::new(Second(TestProtector(second.clone())))],
            Box::new(TestLegacy(first.clone())),
        );
        assert_eq!(p.choose().unwrap().id(), "test");
        // Failing is not absent: no fallback to the second.
        Behaviour::set(&first.fail_probe, true);
        assert!(matches!(p.ready(), Err(ProtectorError::Failing { .. })));
        assert_eq!(p.choose().unwrap().id(), "test");
        // Absent (detected) is passed over.
        Behaviour::set(&first.absent, true);
        assert_eq!(p.choose().unwrap().id(), "second");
        assert!(p.ready().is_ok());
        Behaviour::set(&second.absent, true);
        assert!(matches!(p.choose(), Err(ProtectorError::NoneAvailable)));
        assert!(matches!(p.ready(), Err(ProtectorError::NoneAvailable)));
    }

    /// Every external key is tried even when one fails, and the failure is
    /// reported.
    #[test]
    fn removing_external_keys_tries_them_all_and_reports_a_failure() {
        let b = Arc::new(Behaviour::default());
        let p = protectors(&b);
        let w = Wiping::unknown();
        p.remove_external_keys(&w).unwrap();
        Behaviour::set(&b.fail_remove, true);
        assert!(matches!(p.remove_external_keys(&w), Err(ProtectorError::NotRemoved { .. })));
        assert_eq!(Behaviour::count(&b.removes), 2);
        assert_eq!(Behaviour::count(&b.legacy_removes), 2, "the legacy entry too, after the failure");
        Behaviour::set(&b.fail_remove, false);
        Behaviour::set(&b.fail_legacy_remove, true);
        assert!(matches!(p.remove_external_keys(&w), Err(ProtectorError::NotRemoved { .. })));
    }

    #[test]
    fn what_a_wipe_may_involve() {
        let unknown = Wiping::unknown();
        assert!(unknown.may_be_sealed_by(&["secret-service"]) && unknown.legacy);
        let tpm = Wiping { sealed_by: Some("tpm".into()), legacy: false };
        assert!(!tpm.may_be_sealed_by(&["secret-service", "keyring"]));
        assert!(tpm.may_be_sealed_by(&["tpm"]));
        assert!(Wiping::legacy_file().legacy);
        assert!(!Wiping::nothing().may_be_sealed_by(&["secret-service"]) && !Wiping::nothing().legacy);
        let ss = Wiping { sealed_by: Some("secret-service".into()), legacy: false };
        assert_eq!(ss.clone().and(Wiping::nothing()), ss);
        assert_eq!(Wiping::nothing().and(ss.clone()), ss);
        assert_eq!(ss.clone().and(tpm.clone()).sealed_by, None);
        assert!(tpm.and(Wiping::legacy_file()).legacy);
    }

    #[test]
    fn settings_knows_which_protectors_bind() {
        assert_eq!(describe("dpapi"), Some(("dpapi", true)));
        assert_eq!(describe("tpm"), Some(("tpm", true)));
        assert_eq!(describe("secret-service"), Some(("secret-service", false)));
        #[cfg(not(target_os = "linux"))]
        assert_eq!(describe("keyring"), Some(("keyring", false)));
        #[cfg(target_os = "linux")]
        assert_eq!(describe("keyring"), None);
        assert_eq!(describe("passphrase"), None);
        assert_eq!(describe(""), None);
    }
}
