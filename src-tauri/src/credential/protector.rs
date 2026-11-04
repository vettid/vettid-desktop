//! At-rest protectors (AG3, #13; DESKTOP-REWORK-PLAN §4 "At-rest
//! protectors"): what wraps the random data key that seals `device.enc`.
//!
//! - **Windows: DPAPI, user scope** (`super::dpapi`). The wrapped key is in
//!   the file's header; DPAPI keeps nothing outside it. Bound to this
//!   computer and this account.
//! - **Elsewhere, for now: the OS keyring** through the `keyring` crate
//!   (Secret Service on Linux, the owner's choice (b); the login keychain
//!   on macOS until the keychain and passphrase protectors land). The data
//!   key is the keyring entry itself, so the header's wrapped key is empty.
//!   Not bound to this computer: a copy of the keyring opens elsewhere with
//!   the login password. Settings says so.
//!
//! **Absent and failing are different.** A protector says it is absent
//! only from a fixed, detected condition ([`Availability::Absent`]), never
//! from an error; the next one is then tried. Every error of a protector
//! that is present is [`ProtectorError::Failing`]: pairing or loading stops
//! with the reason and never falls back. Neither protector here is ever
//! absent: DPAPI is part of Windows, and the keyring's "no Secret Service
//! on the session bus" check comes with the Linux protectors.
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
    #[allow(dead_code)] // no protector of this build is ever absent (see the module doc)
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
}

impl std::fmt::Display for ProtectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtectorError::NoneAvailable => f.write_str("no protector is available on this computer"),
            ProtectorError::Failing { by, detail } => write!(f, "{by} failed: {detail}"),
            ProtectorError::WontOpen(detail) => write!(f, "the data key doesn't open: {detail}"),
            ProtectorError::NotRemoved { what, detail } => write!(f, "{what} not removed: {detail}"),
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
}

/// The earlier format's master key entry (`master-key-v1`): deleted and
/// confirmed gone, never read for use.
pub(crate) trait LegacyKey: Send + Sync {
    fn remove(&self) -> Result<(), ProtectorError>;
}

/// What a header's `protector` says, for Settings: the id as shown, and
/// whether it binds the file to this computer. `None` for an id this build
/// doesn't know.
pub(crate) fn describe(id: &str) -> Option<(&'static str, bool)> {
    match id {
        "dpapi" => Some(("dpapi", true)),
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
        #[cfg(not(windows))]
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
    /// each confirmed gone. All are tried; the first failure is returned.
    pub(crate) fn remove_external_keys(&self) -> Result<(), ProtectorError> {
        let mut first = None;
        let results = self.ranked.iter().map(|p| p.remove_external()).chain(std::iter::once(self.legacy.remove()));
        for r in results {
            if let Err(e) = r {
                log::error!("key store: {}", e);
                first.get_or_insert(e);
            }
        }
        first.map_or(Ok(()), Err)
    }

    /// Remove the legacy entry alone, confirmed gone.
    pub(crate) fn remove_legacy_key(&self) -> Result<(), ProtectorError> {
        self.legacy.remove()
    }
}

/// The OS keyring through the `keyring` crate: the interim protector off
/// Windows (see the module doc).
#[cfg(not(windows))]
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
        p.remove_external_keys().unwrap();
        Behaviour::set(&b.fail_remove, true);
        assert!(matches!(p.remove_external_keys(), Err(ProtectorError::NotRemoved { .. })));
        assert_eq!(Behaviour::count(&b.removes), 2);
        assert_eq!(Behaviour::count(&b.legacy_removes), 2, "the legacy entry too, after the failure");
        Behaviour::set(&b.fail_remove, false);
        Behaviour::set(&b.fail_legacy_remove, true);
        assert!(matches!(p.remove_external_keys(), Err(ProtectorError::NotRemoved { .. })));
    }

    #[test]
    fn settings_knows_which_protectors_bind() {
        assert_eq!(describe("dpapi"), Some(("dpapi", true)));
        assert_eq!(describe("keyring"), Some(("keyring", false)));
        assert_eq!(describe("tpm"), None);
        assert_eq!(describe(""), None);
    }
}
