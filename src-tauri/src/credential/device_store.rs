//! Where the paired device's state is kept: vettid-device's
//! [`Persist`] for its `DeviceState` (keys, the vault's record, tokens,
//! the session epoch). The bytes are secret through and through.
//!
//! They are sealed as the NATS-era pairing was (`store`), reusing its
//! parts rather than adding any: XChaCha20-Poly1305 under the master key
//! in the OS keyring (Credential Manager on Windows, `wincred`), the AAD
//! binding the blob to this machine's storage binding (#14), and the
//! private, atomic write (`winacl` on Windows, a `0600` temporary file
//! renamed into place on unix) into the same private folder. The AAD has
//! its own label, so a `connection.enc` blob can't be opened as this one
//! or the other way round.
//!
//! **Keyring only.** There is no machine-bound key here, on any platform:
//! if the keyring can't be reached, nothing is saved and pairing fails
//! with [`super::store::KEYRING_UNAVAILABLE_NOTICE`]. (The machine-bound
//! key of `keystore` is being retired, #13; nothing here uses it.)
//!
//! **Log-out** (#30): a store made before a log-out's wipe saves nothing
//! after it, and its `clear` leaves alone what is there now (a pairing
//! made after the log-out).
//!
//! Nothing here logs what it stores, and `Debug` shows nothing of it.

use std::fs;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use vettid_device::store::{Persist, StoreError};
use zeroize::Zeroizing;

use super::keystore::{self, BindingMode, KeystoreError, MasterKey};
use super::store::{self, CredentialError, EncryptedStore, WipeEpoch, DEVICE_FILE, NONCE_SIZE};
use crate::fingerprint::platform_key;
use crate::fingerprint::platform_linux::FingerprintError;

/// The device file's format version.
const DEVICE_STORE_VERSION: i32 = 1;

/// The AAD's domain-separation label (see [`store::aad_with_label`]).
const DEVICE_AAD_LABEL: &[u8] = b"vettid-desktop-device-state-v1";

/// The longest device file read (a device state is a few tens of KiB at
/// most: its outbox and inbox are capped).
const MAX_FILE: u64 = 8 * 1024 * 1024;

/// Where a device store gets its keys: the keyring and this machine's
/// storage binding, or fixed keys in tests.
pub(crate) trait DeviceKeys: Send + Sync {
    /// The master key for a save: from the keyring only.
    fn master_for_save(&self) -> Result<MasterKey, KeystoreError>;
    /// The master key for a load: from the keyring only.
    fn master_for_load(&self) -> Result<MasterKey, KeystoreError>;
    /// This machine's storage binding, mixed into the AAD (#14).
    fn storage_binding(&self) -> Result<Zeroizing<[u8; 32]>, FingerprintError>;
}

/// The OS keyring, never the machine-bound key, on every platform.
struct KeyringOnly;

impl DeviceKeys for KeyringOnly {
    fn master_for_save(&self) -> Result<MasterKey, KeystoreError> {
        keystore::fetch_or_create_master_key_with_policy(&keystore::System, false)
    }
    fn master_for_load(&self) -> Result<MasterKey, KeystoreError> {
        keystore::fetch_for_binding(BindingMode::Keyring)
    }
    fn storage_binding(&self) -> Result<Zeroizing<[u8; 32]>, FingerprintError> {
        platform_key::derive_storage_binding()
    }
}

/// Whether the keyring holds (or can make) the master key now: checked
/// before a pairing starts, so the vault never lists a desktop that
/// can't save its keys. A key it makes is kept, as the first save would.
pub fn keyring_ready() -> Result<(), CredentialError> {
    match KeyringOnly.master_for_save() {
        Ok(m) if m.binding == BindingMode::Keyring => Ok(()),
        Ok(_) | Err(KeystoreError::KeyringUnavailable(_)) => Err(CredentialError::KeyringUnavailable),
        Err(e) => Err(e.into()),
    }
}

/// The paired device's state in `config_dir/device.enc`. One per command
/// that pairs or unlocks; see the module doc.
pub struct DeviceStore {
    dir: PathBuf,
    /// The wipes when the command that made this store started (#30).
    /// `None` only in tests that don't concern log-out (other tests' wipes
    /// run in parallel and move the count).
    since: Option<WipeEpoch>,
    keys: Box<dyn DeviceKeys>,
    /// Why the last operation failed, for the person (a [`StoreError`]
    /// says only Io or Corrupt).
    failure: Option<CredentialError>,
}

impl std::fmt::Debug for DeviceStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceStore(..)")
    }
}

impl DeviceStore {
    /// The store in `config_dir`, for a command that started at `since`
    /// ([`store::wipe_epoch`], read before anything that could wait).
    pub fn new(config_dir: &Path, since: WipeEpoch) -> Self {
        Self::with_keys(config_dir, Some(since), Box::new(KeyringOnly))
    }

    pub(crate) fn with_keys(config_dir: &Path, since: Option<WipeEpoch>, keys: Box<dyn DeviceKeys>) -> Self {
        DeviceStore { dir: config_dir.to_path_buf(), since, keys, failure: None }
    }

    /// Why the last failed operation failed, if it said more than
    /// [`StoreError`] can; taken.
    pub fn take_failure(&mut self) -> Option<CredentialError> {
        self.failure.take()
    }

    fn fail<T>(&mut self, e: CredentialError, as_: StoreError) -> Result<T, StoreError> {
        self.failure = Some(e);
        Err(as_)
    }

    /// Whether a log-out has wiped the pairing since this store was made.
    fn logged_out_since(&self) -> bool {
        self.since.is_some_and(|since| store::wipe_epoch() != since)
    }

    fn try_save(&self, data: &[u8]) -> Result<(), CredentialError> {
        let _one_at_a_time = store::writer_lock();
        if self.logged_out_since() {
            return Err(CredentialError::LoggedOutMeanwhile);
        }
        // The storage binding first: without a machine id nothing can be
        // saved, and no keyring key should be created for it (#14).
        let platform = self.keys.storage_binding().map_err(store::binding_error)?;
        let master = self.keys.master_for_save().map_err(|e| match e {
            KeystoreError::KeyringUnavailable(_) => CredentialError::KeyringUnavailable,
            e => e.into(),
        })?;
        // SECURITY: never under anything but the keyring's key.
        if master.binding != BindingMode::Keyring {
            return Err(CredentialError::KeyringUnavailable);
        }
        let aad = store::aad_with_label(DEVICE_AAD_LABEL, BindingMode::Keyring.as_str(), &platform);
        let (nonce, ciphertext) = store::encrypt_xchacha20(&master.key, data, &aad)?;
        let sealed = EncryptedStore { version: DEVICE_STORE_VERSION, binding: BindingMode::Keyring.as_str().to_string(), nonce, ciphertext };
        let bytes = serde_json::to_vec(&sealed).map_err(|e| CredentialError::SerializationError(format!("marshal device store: {}", e)))?;
        store::ensure_config_dir(&self.dir)?;
        store::write_private(&self.dir, DEVICE_FILE, &bytes)
    }

    fn try_load(&self) -> Result<Option<Zeroizing<Vec<u8>>>, (CredentialError, StoreError)> {
        use std::io::Read;
        let path = self.dir.join(DEVICE_FILE);
        let io = |e: std::io::Error| (CredentialError::IoError(format!("read {}: {}", path.display(), e)), StoreError::Io);
        let mut raw = Vec::new();
        match fs::File::open(&path) {
            Ok(f) => {
                f.take(MAX_FILE + 1).read_to_end(&mut raw).map_err(io)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io(e)),
        }
        let corrupt = |what: &str| (CredentialError::SerializationError(format!("device store: {}", what)), StoreError::Corrupt);
        if raw.len() as u64 > MAX_FILE {
            return Err(corrupt("too large"));
        }
        let sealed: EncryptedStore = serde_json::from_slice(&raw).map_err(|_| corrupt("unreadable"))?;
        if sealed.version != DEVICE_STORE_VERSION || sealed.binding != BindingMode::Keyring.as_str() || sealed.nonce.len() != NONCE_SIZE {
            return Err(corrupt("unknown format"));
        }
        let platform = self.keys.storage_binding().map_err(|e| (store::binding_error(e), StoreError::Io))?;
        // A keyring that can't be read now may work later: Io, not Corrupt.
        let master = self.keys.master_for_load().map_err(|e| (e.into(), StoreError::Io))?;
        let aad = store::aad_with_label(DEVICE_AAD_LABEL, &sealed.binding, &platform);
        let cipher = XChaCha20Poly1305::new_from_slice(&master.key[..]).map_err(|_| corrupt("cipher"))?;
        let plain = cipher
            .decrypt(XNonce::from_slice(&sealed.nonce), Payload { msg: &sealed.ciphertext, aad: &aad })
            .map_err(|_| (CredentialError::Unreadable, StoreError::Corrupt))?;
        Ok(Some(Zeroizing::new(plain)))
    }

    fn try_clear(&self) -> Result<(), CredentialError> {
        let _one_at_a_time = store::writer_lock();
        // A log-out since removed this store's file; what is there now, if
        // anything, is a later pairing's.
        if self.logged_out_since() {
            return Ok(());
        }
        store::remove_file_locked(&self.dir, DEVICE_FILE)?;
        store::confirm_gone(&self.dir, DEVICE_FILE)
    }
}

impl Persist for DeviceStore {
    fn save(&mut self, data: &[u8]) -> Result<(), StoreError> {
        match self.try_save(data) {
            Ok(()) => Ok(()),
            Err(e) => {
                log::warn!("device store: not saved: {}", e);
                self.fail(e, StoreError::Io)
            }
        }
    }

    fn load(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, StoreError> {
        match self.try_load() {
            Ok(v) => Ok(v),
            Err((e, kind)) => {
                log::warn!("device store: not opened: {}", e);
                self.fail(e, kind)
            }
        }
    }

    fn clear(&mut self) -> Result<(), StoreError> {
        match self.try_clear() {
            Ok(()) => Ok(()),
            Err(e) => {
                log::error!("device store: not removed: {}", e);
                self.fail(e, StoreError::Io)
            }
        }
    }
}

/// Whether a device file may be in `config_dir`: true also when that can't
/// be ruled out (nothing treats the pairing as gone on a guess).
pub fn exists(config_dir: &Path) -> bool {
    !matches!(fs::symlink_metadata(config_dir.join(DEVICE_FILE)), Err(ref e) if e.kind() == std::io::ErrorKind::NotFound)
}

/// Which key protects the device file, for Settings (#11): "keyring",
/// "none" (no file) or "unknown" (one that can't be read). Nothing is
/// decrypted.
pub fn stored_key_protection(config_dir: &Path) -> &'static str {
    let path = config_dir.join(DEVICE_FILE);
    match fs::read(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => "none",
        Err(_) => "unknown",
        Ok(raw) => match serde_json::from_slice::<EncryptedStore>(&raw) {
            Ok(s) if s.version == DEVICE_STORE_VERSION && s.binding == BindingMode::Keyring.as_str() => "keyring",
            _ => "unknown",
        },
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// For tests elsewhere in the crate: a store in `dir` with fixed test
    /// keys (never the real keyring) and no log-out check.
    pub(crate) fn store_for_tests(dir: &Path) -> DeviceStore {
        DeviceStore::with_keys(dir, None, keys())
    }

    impl DeviceStore {
        /// Save some bytes (tests elsewhere only need a device file).
        pub(crate) fn save_raw_for_tests(&mut self) {
            self.save(STATE).unwrap();
        }
    }

    const MASTER: [u8; 32] = [0x5a; 32];
    const PLATFORM: [u8; 32] = [0x17; 32];

    struct Fixed {
        binding: BindingMode,
        master: [u8; 32],
        platform: [u8; 32],
        keyring_up: bool,
    }

    impl DeviceKeys for Fixed {
        fn master_for_save(&self) -> Result<MasterKey, KeystoreError> {
            if !self.keyring_up {
                return Err(KeystoreError::KeyringUnavailable("test".into()));
            }
            Ok(MasterKey { key: Zeroizing::new(self.master), binding: self.binding })
        }
        fn master_for_load(&self) -> Result<MasterKey, KeystoreError> {
            if !self.keyring_up {
                return Err(KeystoreError::NoSource("test".into()));
            }
            Ok(MasterKey { key: Zeroizing::new(self.master), binding: self.binding })
        }
        fn storage_binding(&self) -> Result<Zeroizing<[u8; 32]>, FingerprintError> {
            Ok(Zeroizing::new(self.platform))
        }
    }

    fn keys() -> Box<Fixed> {
        Box::new(Fixed { binding: BindingMode::Keyring, master: MASTER, platform: PLATFORM, keyring_up: true })
    }

    fn store_in(dir: &Path) -> DeviceStore {
        DeviceStore::with_keys(dir, None, keys())
    }

    const STATE: &[u8] = b"{\"v\":1,\"ik_seed\":\"c2VjcmV0LXNlZWQtYnl0ZXM\"}";

    #[test]
    fn a_saved_state_loads_back_and_is_sealed_on_disk() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        let mut s = store_in(&dir);
        assert_eq!(s.load().unwrap(), None, "nothing yet");
        s.save(STATE).unwrap();
        assert_eq!(s.load().unwrap().as_deref().map(|v| &v[..]), Some(STATE));
        let raw = fs::read(dir.join(DEVICE_FILE)).unwrap();
        assert!(!raw.windows(8).any(|w| w == b"c2VjcmV0"), "no plaintext on disk");
        assert!(exists(&dir));
        assert_eq!(stored_key_protection(&dir), "keyring");
        // A fresh store for the same folder opens it too (a restart).
        assert_eq!(store_in(&dir).load().unwrap().as_deref().map(|v| &v[..]), Some(STATE));
    }

    /// Fail secure: without the keyring nothing is written, and the person
    /// gets the keyring notice. A key from anything but the keyring is
    /// refused as well.
    #[test]
    fn without_the_keyring_nothing_is_saved() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        let down = Fixed { binding: BindingMode::Keyring, master: MASTER, platform: PLATFORM, keyring_up: false };
        let mut s = DeviceStore::with_keys(&dir, None, Box::new(down));
        assert_eq!(s.save(STATE), Err(StoreError::Io));
        assert!(matches!(s.take_failure(), Some(CredentialError::KeyringUnavailable)));
        assert!(!exists(&dir));
        let machine = Fixed { binding: BindingMode::MachineBound, master: MASTER, platform: PLATFORM, keyring_up: true };
        let mut s = DeviceStore::with_keys(&dir, None, Box::new(machine));
        assert_eq!(s.save(STATE), Err(StoreError::Io));
        assert!(matches!(s.take_failure(), Some(CredentialError::KeyringUnavailable)));
        assert!(!exists(&dir));
        assert_eq!(stored_key_protection(&dir), "none");
    }

    /// A keyring that can't be read at load is Io (it may work later), and
    /// the file is kept.
    #[test]
    fn a_keyring_down_at_load_keeps_the_file() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        store_in(&dir).save(STATE).unwrap();
        let down = Fixed { binding: BindingMode::Keyring, master: MASTER, platform: PLATFORM, keyring_up: false };
        let mut s = DeviceStore::with_keys(&dir, None, Box::new(down));
        assert_eq!(s.load(), Err(StoreError::Io));
        assert!(exists(&dir));
    }

    /// Another master key, another machine, or a blob sealed under the
    /// NATS-era label doesn't open: Corrupt, and nothing is deleted.
    #[test]
    fn a_blob_that_isnt_this_ones_doesnt_open() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        store_in(&dir).save(STATE).unwrap();
        for (master, platform) in [([0x01; 32], PLATFORM), (MASTER, [0x02; 32])] {
            let other = Fixed { binding: BindingMode::Keyring, master, platform, keyring_up: true };
            let mut s = DeviceStore::with_keys(&dir, None, Box::new(other));
            assert_eq!(s.load(), Err(StoreError::Corrupt));
            assert!(matches!(s.take_failure(), Some(CredentialError::Unreadable)));
        }
        // The same key and machine, under the credential store's label.
        let aad = store::aad_with_label(b"vettid-desktop-credential-v3", "keyring", &PLATFORM);
        let (nonce, ciphertext) = store::encrypt_xchacha20(&MASTER, STATE, &aad).unwrap();
        let sealed = EncryptedStore { version: DEVICE_STORE_VERSION, binding: "keyring".into(), nonce, ciphertext };
        fs::write(dir.join(DEVICE_FILE), serde_json::to_vec(&sealed).unwrap()).unwrap();
        assert_eq!(store_in(&dir).load(), Err(StoreError::Corrupt));
        // A machine-bound header isn't read at all.
        let sealed = EncryptedStore { version: DEVICE_STORE_VERSION, binding: "machine".into(), nonce: vec![0; NONCE_SIZE], ciphertext: vec![0; 32] };
        fs::write(dir.join(DEVICE_FILE), serde_json::to_vec(&sealed).unwrap()).unwrap();
        assert_eq!(store_in(&dir).load(), Err(StoreError::Corrupt));
        assert_eq!(stored_key_protection(&dir), "unknown");
        assert!(exists(&dir));
    }

    #[test]
    fn clear_removes_the_file_and_says_so() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        let mut s = store_in(&dir);
        s.save(STATE).unwrap();
        s.clear().unwrap();
        assert!(!exists(&dir));
        assert_eq!(s.load().unwrap(), None);
        s.clear().unwrap();
    }

    /// #30: after a log-out's wipe, a store made before it saves nothing,
    /// and its clear doesn't touch a pairing made after the log-out.
    #[test]
    fn a_store_from_before_a_log_out_neither_saves_nor_clears() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        // Other tests' wipes run in parallel and move the count: a store
        // they overtook before its first save is made again.
        let mut before = (0..1000)
            .find_map(|_| {
                let mut s = DeviceStore::with_keys(&dir, Some(store::wipe_epoch()), keys());
                s.save(STATE).is_ok().then_some(s)
            })
            .expect("a save between other tests' wipes");
        store::wipe(&dir).unwrap();
        assert!(!exists(&dir), "the wipe removed the device file");
        assert_eq!(before.save(STATE), Err(StoreError::Io));
        assert!(matches!(before.take_failure(), Some(CredentialError::LoggedOutMeanwhile)));
        assert!(!exists(&dir), "nothing was written back");
        let mut after = store_in(&dir);
        after.save(STATE).unwrap();
        before.clear().unwrap();
        assert!(exists(&dir), "the later pairing stays");
    }

    #[test]
    fn debug_shows_nothing() {
        let base = tempfile::tempdir().unwrap();
        let s = store_in(&base.path().join("vettid-desktop"));
        assert_eq!(format!("{s:?}"), "DeviceStore(..)");
    }
}
