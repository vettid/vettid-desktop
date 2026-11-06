//! Where the paired device's state is kept: vettid-device's
//! [`Persist`] for its `DeviceState` (keys, the vault's record, tokens,
//! the session epoch). The bytes are secret through and through.
//!
//! **Format** (v2, DESKTOP-REWORK-PLAN §4 "At-rest protectors"): the state
//! is sealed with XChaCha20-Poly1305 under a random 256-bit **data key**,
//! made when a store with nothing on disk first saves (a new one for each
//! pairing). The data key is wrapped by a [`protector`](super::protector)
//! and the wrapped form kept in the file's header. The file is JSON:
//!
//! ```text
//! {"header":{"v":2,"protector":"dpapi","wrapped_key":"<b64>","nonce":"<b64>",
//!            "created_at":<unix s>,"notice_shown":false},
//!  "ciphertext":"<b64>"}
//! ```
//!
//! The associated data is the header's canonical bytes (`serde_json` of
//! [`Header`], whose fields serialize in a fixed order, so a load computes
//! the same bytes again) followed by the label `vettid-desktop-device-v1`.
//! Nothing else goes in: no machine id, no storage binding (#14 dropped,
//! #19), no path.
//!
//! A store that has loaded or saved keeps its data key in memory (wiped on
//! drop) and saves under it again; a clear forgets it.
//!
//! **No migration.** A `device.enc` in the earlier format (an
//! `EncryptedStore` with `version: 1`, `binding: "keyring"` and nothing
//! else) is deleted unread, with the earlier format's `master-key-v1`
//! entry ([`retire_legacy`]). Anything else this build can't read is kept
//! and reported, never deleted.
//!
//! The write is private and atomic (`winacl` on Windows, a `0600`
//! temporary file renamed into place on unix), into the private folder.
//!
//! **Log-out** (#30): a store made before a log-out's wipe saves nothing
//! after it, and its `clear` leaves alone what is there now (a pairing
//! made after the log-out).
//!
//! Nothing here logs what it stores, and `Debug` shows nothing of it.

use std::fs;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use vettid_device::store::{Persist, StoreError};
use zeroize::Zeroizing;

use super::protector::{self, DataKey, ProtectorError, Protectors, Wiping};
use super::store::{self, CredentialError, WipeEpoch, DEVICE_FILE};

/// The device file's format version.
const FORMAT_VERSION: u32 = 2;

/// Appended to the header's bytes to make the associated data.
const AAD_LABEL: &[u8] = b"vettid-desktop-device-v1";

/// XChaCha20-Poly1305 nonce size.
const NONCE_SIZE: usize = 24;

/// The longest device file read (a device state is a few tens of KiB at
/// most: its outbox and inbox are capped).
const MAX_FILE: u64 = 8 * 1024 * 1024;

/// The file's header: in the clear, and all of it authenticated.
///
/// SECURITY: the field order is the canonical order of the associated
/// data. Don't reorder, rename or add fields without a new `v`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    v: u32,
    /// The protector's id (see `protector::describe`).
    protector: String,
    /// The wrapped data key, base64: what the protector returned (DPAPI's
    /// blob, the TPM's sealed object, the Secret Service entry's id);
    /// empty when the protector keeps the key itself (the macOS keyring).
    wrapped_key: String,
    /// The nonce, base64. Fresh for each save.
    nonce: String,
    /// Unix seconds: when the data key was made (the pairing).
    created_at: i64,
    /// Whether the "below the best protector" notice was shown for this
    /// file. No protector of this build is below another, so it stays
    /// false; it is kept across saves.
    notice_shown: bool,
}

impl Header {
    /// The associated data: the header's canonical bytes, then the label.
    fn aad(&self) -> Vec<u8> {
        let mut aad = serde_json::to_vec(self).expect("a header always serializes");
        aad.extend_from_slice(AAD_LABEL);
        aad
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedFile {
    header: Header,
    /// base64.
    ciphertext: String,
}

/// The earlier format, exactly: recognised only to be deleted unread.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)] // its fields are matched, never used
struct LegacyFile {
    version: i32,
    binding: String,
    #[serde(with = "serde_bytes")]
    nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    ciphertext: Vec<u8>,
}

/// Whether `raw` is the earlier format: `version: 1`, `binding:
/// "keyring"`, and no other field (so no `protector`).
fn is_legacy(raw: &[u8]) -> bool {
    serde_json::from_slice::<LegacyFile>(raw).is_ok_and(|f| f.version == 1 && f.binding == "keyring")
}

/// The data key and what the header says about it, kept between saves.
struct Sealing {
    key: DataKey,
    protector: &'static str,
    wrapped_key: String,
    created_at: i64,
    notice_shown: bool,
}

/// Whether this computer can protect a pairing now: checked before a
/// pairing starts, so the vault never lists a desktop that can't save its
/// keys. Creates and keeps nothing.
pub fn protection_ready() -> Result<(), CredentialError> {
    Protectors::system().ready().map_err(save_error)
}

/// A protector's failure while saving, as the person is told it.
fn save_error(e: ProtectorError) -> CredentialError {
    log::warn!("device store: {}", e);
    match e {
        ProtectorError::NoneAvailable => CredentialError::NoProtector,
        ProtectorError::Failing { by, .. } => CredentialError::NotProtected { by },
        ProtectorError::WontOpen(_) | ProtectorError::NotRemoved { .. } => CredentialError::IoError(e.to_string()),
    }
}

/// A protector's failure while loading: the file is kept either way.
/// Failing may work later (Io); won't-open won't (Corrupt).
fn load_error(e: ProtectorError) -> (CredentialError, StoreError) {
    log::warn!("device store: {}", e);
    match e {
        ProtectorError::Failing { by, .. } => (CredentialError::NotOpened { by }, StoreError::Io),
        ProtectorError::WontOpen(_) => (CredentialError::Unreadable, StoreError::Corrupt),
        ProtectorError::NoneAvailable | ProtectorError::NotRemoved { .. } => (CredentialError::IoError(e.to_string()), StoreError::Io),
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
    protectors: Protectors,
    sealing: Option<Sealing>,
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
        Self::with_protectors(config_dir, Some(since), Protectors::system())
    }

    pub(crate) fn with_protectors(config_dir: &Path, since: Option<WipeEpoch>, protectors: Protectors) -> Self {
        DeviceStore { dir: config_dir.to_path_buf(), since, protectors, sealing: None, failure: None }
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

    /// A new data key, wrapped by the best protector present.
    fn new_sealing(&self) -> Result<Sealing, CredentialError> {
        let p = self.protectors.choose().map_err(save_error)?;
        let mut key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut key[..]);
        let wrapped = p.wrap(&key).map_err(save_error)?;
        Ok(Sealing {
            key,
            protector: p.id(),
            wrapped_key: B64.encode(wrapped),
            created_at: chrono::Utc::now().timestamp(),
            notice_shown: false,
        })
    }

    fn try_save(&mut self, data: &[u8]) -> Result<(), CredentialError> {
        let _one_at_a_time = store::writer_lock();
        if self.logged_out_since() {
            return Err(CredentialError::LoggedOutMeanwhile);
        }
        // The folder first: one that is refused gets no key made for it.
        store::ensure_config_dir(&self.dir)?;
        if self.sealing.is_none() {
            self.sealing = Some(self.new_sealing()?);
        }
        let s = self.sealing.as_ref().expect("just set");
        let mut nonce = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);
        let header = Header {
            v: FORMAT_VERSION,
            protector: s.protector.to_string(),
            wrapped_key: s.wrapped_key.clone(),
            nonce: B64.encode(nonce),
            created_at: s.created_at,
            notice_shown: s.notice_shown,
        };
        let cipher = XChaCha20Poly1305::new_from_slice(&s.key[..]).map_err(|e| CredentialError::IoError(format!("cipher: {e}")))?;
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: data, aad: &header.aad() })
            .map_err(|_| CredentialError::IoError("seal".into()))?;
        let file = SealedFile { header, ciphertext: B64.encode(ciphertext) };
        let bytes = serde_json::to_vec(&file).map_err(|e| CredentialError::SerializationError(format!("device store: {e}")))?;
        store::write_private(&self.dir, DEVICE_FILE, &bytes)
    }

    fn try_load(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, (CredentialError, StoreError)> {
        let Some(raw) = read_file(&self.dir).map_err(|e| (e, StoreError::Io))? else {
            self.sealing = None;
            return Ok(None);
        };
        let corrupt = |what: &str| (CredentialError::SerializationError(format!("device store: {}", what)), StoreError::Corrupt);
        let file: SealedFile = match serde_json::from_slice(&raw) {
            Ok(f) => f,
            // The earlier format goes, unread; then there is nothing here.
            Err(_) if is_legacy(&raw) => {
                let retired = retire_legacy_with(&self.dir, &self.protectors);
                self.sealing = None;
                return after_retiring(&self.dir, retired).map(|()| None).map_err(|e| (e, StoreError::Io));
            }
            Err(_) => return Err(corrupt("unreadable")),
        };
        let h = &file.header;
        if h.v != FORMAT_VERSION {
            return Err(corrupt("unknown format"));
        }
        let nonce = B64.decode(&h.nonce).ok().filter(|n| n.len() == NONCE_SIZE).ok_or_else(|| corrupt("nonce"))?;
        let wrapped = Zeroizing::new(B64.decode(&h.wrapped_key).map_err(|_| corrupt("wrapped key"))?);
        let ciphertext = B64.decode(&file.ciphertext).map_err(|_| corrupt("ciphertext"))?;
        // A protector this build doesn't have here: kept, reported.
        // (#69's Linux `keyring` is one.) Unreadable: the person is told to
        // log out and pair again.
        let p = self.protectors.by_id(&h.protector).ok_or_else(|| {
            log::warn!("device store: a protector this build doesn't have here");
            (CredentialError::Unreadable, StoreError::Corrupt)
        })?;
        let key = p.unwrap(&wrapped).map_err(load_error)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| corrupt("cipher"))?;
        let plain = cipher
            .decrypt(XNonce::from_slice(&nonce), Payload { msg: &ciphertext, aad: &h.aad() })
            .map_err(|_| (CredentialError::Unreadable, StoreError::Corrupt))?;
        self.sealing = Some(Sealing {
            key,
            protector: p.id(),
            wrapped_key: h.wrapped_key.clone(),
            created_at: h.created_at,
            notice_shown: h.notice_shown,
        });
        Ok(Some(Zeroizing::new(plain)))
    }

    /// The file and its temporary copies, then the protectors' external
    /// keys and the legacy entry: each confirmed gone, or an error.
    fn try_clear(&mut self) -> Result<(), CredentialError> {
        let _one_at_a_time = store::writer_lock();
        // A log-out since removed this store's file and keys; what is there
        // now, if anything, is a later pairing's.
        if self.logged_out_since() {
            return Ok(());
        }
        self.sealing = None;
        // The marker first (`store::begin_wipe`), so a log-out after a
        // clear that left a key knows what the file was.
        let (wiping, recorded) = store::begin_wipe(&self.dir, what_is_sealed(&self.dir));
        // The fail-secure order when no marker could be written (#13).
        let dir = self.dir.clone();
        let protectors = &self.protectors;
        let done = store::file_then_keys(
            recorded,
            || store::remove_file_locked(&dir, DEVICE_FILE).and_then(|()| store::confirm_gone(&dir, DEVICE_FILE)),
            || protectors.remove_external_keys(&wiping).map_err(CredentialError::from),
        );
        if done.is_ok() {
            store::finish_wipe(&self.dir);
        }
        done
    }
}

/// The device file's bytes: `None` if it isn't there.
fn read_file(dir: &Path) -> Result<Option<Vec<u8>>, CredentialError> {
    use std::io::Read;
    let path = dir.join(DEVICE_FILE);
    let io = |e: std::io::Error| CredentialError::IoError(format!("read {}: {}", path.display(), e));
    let mut raw = Vec::new();
    match fs::File::open(&path) {
        Ok(f) => {
            f.take(MAX_FILE + 1).read_to_end(&mut raw).map_err(io)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io(e)),
    }
    if raw.len() as u64 > MAX_FILE {
        return Err(CredentialError::SerializationError("device store: too large".into()));
    }
    Ok(Some(raw))
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

/// Delete an earlier format's device file unread, with the earlier
/// format's `master-key-v1` entry. `Ok(false)`: there is no such file
/// (nothing else is touched, whatever is there). `Ok(true)`: both are
/// confirmed gone. An error: something may be left, and the person is told.
pub(super) fn retire_legacy_with(dir: &Path, protectors: &Protectors) -> Result<bool, CredentialError> {
    let _one_at_a_time = store::writer_lock();
    // A file that can't be read isn't known to be the earlier format: the
    // load reports it.
    match read_file(dir) {
        Ok(Some(raw)) if is_legacy(&raw) => {}
        _ => return Ok(false),
    }
    // The marker first, so a log-out after a retirement that left the key
    // knows an earlier format was here. An earlier wipe's marker is kept
    // in it, and restored once the v1 parts are confirmed gone: this
    // removes only those, never what that wipe left.
    let earlier = store::pending_wipe(dir);
    let this = Wiping::legacy_file();
    let recorded = store::record_wipe(dir, &earlier.clone().map_or_else(|| this.clone(), |e| e.and(this.clone())));
    let remove_file = || store::remove_file_locked(dir, DEVICE_FILE).and_then(|()| store::confirm_gone(dir, DEVICE_FILE));
    // With no marker on disk, the key first (#13; see `store::file_then_keys`):
    // if it isn't removed, the file stays as the retry signal.
    let (file, key) = if recorded {
        (remove_file(), protectors.remove_legacy_key(&this))
    } else {
        let key = protectors.remove_legacy_key(&this);
        let file = if key.is_ok() { remove_file() } else { Ok(()) };
        (file, key)
    };
    match (file, key) {
        (Ok(()), Ok(())) => {
            match earlier {
                Some(e) => {
                    store::record_wipe(dir, &e);
                }
                None => store::finish_wipe(dir),
            }
            Ok(true)
        }
        (file, key) => {
            if let Err(e) = file {
                log::error!("device store: the earlier version's file: {}", e);
            }
            if let Err(e) = key {
                log::error!("device store: {}", e);
            }
            Err(CredentialError::LegacyNotRemoved)
        }
    }
}

/// A load that found the earlier format: nothing is there only once the
/// retirement confirmed it. `Ok(false)` (the file couldn't be read again
/// under the lock, or changed) while a file may still be there is an I/O
/// error: the file is kept, and "not paired" isn't said on a guess (a
/// pairing would otherwise write over it).
fn after_retiring(dir: &Path, retired: Result<bool, CredentialError>) -> Result<(), CredentialError> {
    match retired? {
        true => Ok(()),
        false if exists(dir) => Err(CredentialError::IoError("the earlier version's device file couldn't be checked again".into())),
        false => Ok(()),
    }
}

/// [`retire_legacy_with`] with this platform's protectors, for unlock.
pub fn retire_legacy(config_dir: &Path) -> Result<bool, CredentialError> {
    retire_legacy_with(config_dir, &Protectors::system())
}

/// Whether a device file may be in `config_dir`: true also when that can't
/// be ruled out (nothing treats the pairing as gone on a guess).
pub fn exists(config_dir: &Path) -> bool {
    !matches!(fs::symlink_metadata(config_dir.join(DEVICE_FILE)), Err(ref e) if e.kind() == std::io::ErrorKind::NotFound)
}

/// What a wipe of `config_dir` removes, from the device file's header
/// read unauthenticated (nothing is decrypted). A file that can't be read
/// or parsed: nothing is known ([`Wiping::unknown`]). No file: nothing of
/// a pairing ([`Wiping::nothing`]), unless a `connection.enc` may be there.
/// An earlier format's file, or a `connection.enc`, involves the legacy
/// entry. A wipe that was interrupted is known from its marker
/// (`store::wipe_for_logout`), not from this.
pub(crate) fn what_is_sealed(config_dir: &Path) -> Wiping {
    let legacy_pairing = store::exists(config_dir);
    let raw = match read_file(config_dir) {
        Ok(Some(raw)) => raw,
        Ok(None) => return Wiping { legacy: legacy_pairing, ..Wiping::nothing() },
        Err(_) => return Wiping::unknown(),
    };
    match serde_json::from_slice::<SealedFile>(&raw) {
        Ok(f) if f.header.v == FORMAT_VERSION => Wiping { sealed_by: Some(f.header.protector), legacy: legacy_pairing },
        Err(_) if is_legacy(&raw) => Wiping::legacy_file(),
        _ => Wiping::unknown(),
    }
}

/// What protects the device file, for Settings (#11), from its header;
/// nothing is decrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyProtection {
    /// "dpapi", "tpm", "secret-service", "keyring", "none" (no file),
    /// "legacy" (the earlier format, deleted at the next unlock) or
    /// "unknown" (a file that can't be read).
    pub protector: &'static str,
    /// Whether that protector binds the file to this computer.
    pub bound: bool,
}

/// Notices for Settings about who else may open the saved pairing under
/// its protector: on Windows with DPAPI, a domain-joined computer or a
/// roaming profile (`dpapi::Reach`). A check that fails gives none, so none
/// is not a guarantee.
pub fn protection_notices(protection: KeyProtection) -> Vec<&'static str> {
    #[cfg(windows)]
    if protection.protector == "dpapi" {
        return super::dpapi::Reach::here().notices();
    }
    let _ = protection;
    Vec::new()
}

pub fn stored_key_protection(config_dir: &Path) -> KeyProtection {
    let of = |protector, bound| KeyProtection { protector, bound };
    match read_file(config_dir) {
        Ok(None) => of("none", false),
        Err(_) => of("unknown", false),
        Ok(Some(raw)) => match serde_json::from_slice::<SealedFile>(&raw) {
            Ok(f) if f.header.v == FORMAT_VERSION => match protector::describe(&f.header.protector) {
                Some((id, bound)) => of(id, bound),
                None => of("unknown", false),
            },
            Ok(_) => of("unknown", false),
            Err(_) if is_legacy(&raw) => of("legacy", false),
            Err(_) => of("unknown", false),
        },
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::credential::protector::testing::{self, Behaviour};
    use std::sync::Arc;

    /// For tests elsewhere in the crate: a store in `dir` with the test
    /// protector (never DPAPI or the real keyring) and no log-out check.
    pub(crate) fn store_for_tests(dir: &Path) -> DeviceStore {
        DeviceStore::with_protectors(dir, None, testing::protectors(&Arc::default()))
    }

    /// For the store tests: like [`store_for_tests`], but for a command
    /// that started at `since` (`None`: no log-out check).
    pub(crate) fn store_since_for_tests(dir: &Path, since: Option<WipeEpoch>) -> DeviceStore {
        DeviceStore::with_protectors(dir, since, testing::protectors(&Arc::default()))
    }

    impl DeviceStore {
        /// Save some bytes (tests elsewhere only need a device file).
        pub(crate) fn save_raw_for_tests(&mut self) {
            self.save(STATE).unwrap();
        }
    }

    fn store_with(dir: &Path, b: &Arc<Behaviour>) -> DeviceStore {
        DeviceStore::with_protectors(dir, None, testing::protectors(b))
    }

    fn store_in(dir: &Path) -> DeviceStore {
        store_for_tests(dir)
    }

    const STATE: &[u8] = b"{\"v\":1,\"ik_seed\":\"c2VjcmV0LXNlZWQtYnl0ZXM\"}";

    /// #13 (DESKTOP-REWORK-PLAN §4 "Done": DPAPI copy refusal as a second
    /// Windows user). One step of the two-account run in
    /// docs/WINDOWS-TESTING.md, with the **real** DPAPI protector, so it is
    /// ignored in normal runs. `VETTID_COPY_TEST=seal` saves a fixture state
    /// in `VETTID_COPY_TEST_DIR`; `=open` loads the file there and prints
    /// the outcome (never key or state bytes) for the harness to check.
    #[cfg(windows)]
    #[test]
    #[ignore = "needs two Windows accounts; see docs/WINDOWS-TESTING.md"]
    fn dpapi_copy_refusal_step() {
        let (Ok(mode), Ok(dir)) = (std::env::var("VETTID_COPY_TEST"), std::env::var("VETTID_COPY_TEST_DIR")) else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        // Never the real store: this must not touch a member's pairing.
        // Canonical paths, compared case-insensitively (Windows), so another
        // spelling of the same folder can't slip past (lead review).
        let same = |a: &Path, b: &Path| {
            let canon = |p: &Path| fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf()).to_string_lossy().to_lowercase();
            canon(a) == canon(b)
        };
        assert!(store::default_config_dir().map_or(true, |d| !same(&d, &dir)), "not the real store");
        let mut s = DeviceStore::new(&dir, store::wipe_epoch());
        match mode.as_str() {
            "seal" => {
                assert!(!dir.join(DEVICE_FILE).exists(), "seal won't overwrite a device file");
                s.save(STATE).expect("sealed");
                println!("COPYTEST sealed protector={}", read_sealed(&dir).header.protector);
            }
            "open" => match s.load() {
                Ok(Some(v)) => println!("COPYTEST opened same_state={}", &v[..] == STATE),
                Ok(None) => println!("COPYTEST no_file"),
                Err(kind) => println!("COPYTEST refused store_error={kind:?} failure={:?}", s.take_failure()),
            },
            other => panic!("unknown mode {other}"),
        }
    }

    fn read_sealed(dir: &Path) -> SealedFile {
        serde_json::from_slice(&fs::read(dir.join(DEVICE_FILE)).unwrap()).unwrap()
    }

    fn write_sealed(dir: &Path, f: &SealedFile) {
        fs::write(dir.join(DEVICE_FILE), serde_json::to_vec(f).unwrap()).unwrap();
    }

    /// The earlier format, as the earlier build wrote it.
    fn legacy_bytes() -> Vec<u8> {
        #[derive(Serialize)]
        struct Earlier {
            version: i32,
            binding: &'static str,
            #[serde(with = "serde_bytes")]
            nonce: Vec<u8>,
            #[serde(with = "serde_bytes")]
            ciphertext: Vec<u8>,
        }
        serde_json::to_vec(&Earlier { version: 1, binding: "keyring", nonce: vec![7; 24], ciphertext: vec![9; 48] }).unwrap()
    }

    #[test]
    fn a_saved_state_loads_back_and_is_sealed_on_disk() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        let b = Arc::new(Behaviour::default());
        let mut s = store_with(&dir, &b);
        assert_eq!(s.load().unwrap(), None, "nothing yet");
        s.save(STATE).unwrap();
        s.save(STATE).unwrap();
        assert_eq!(Behaviour::count(&b.wraps), 1, "one data key for the store");
        assert_eq!(s.load().unwrap().as_deref().map(|v| &v[..]), Some(STATE));
        let raw = fs::read(dir.join(DEVICE_FILE)).unwrap();
        assert!(!raw.windows(8).any(|w| w == b"c2VjcmV0"), "no plaintext on disk");
        assert!(exists(&dir));
        assert_eq!(stored_key_protection(&dir), KeyProtection { protector: "test", bound: true });
        let h = read_sealed(&dir).header;
        assert_eq!((h.v, h.protector.as_str(), h.notice_shown), (2, "test", false));
        // A fresh store for the same folder opens it too (a restart), and
        // saves under the same key.
        let b2 = Arc::new(Behaviour::default());
        let mut again = store_with(&dir, &b2);
        assert_eq!(again.load().unwrap().as_deref().map(|v| &v[..]), Some(STATE));
        again.save(b"newer").unwrap();
        assert_eq!(Behaviour::count(&b2.wraps), 0, "no new key after a load");
        let h2 = read_sealed(&dir).header;
        assert_eq!((h2.wrapped_key.as_str(), h2.created_at), (h.wrapped_key.as_str(), h.created_at));
        assert_ne!(h2.nonce, h.nonce, "a fresh nonce for each save");
    }

    /// A clear forgets the data key: the next pairing gets a new one.
    #[test]
    fn a_new_data_key_after_a_clear() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        let b = Arc::new(Behaviour::default());
        let mut s = store_with(&dir, &b);
        s.save(STATE).unwrap();
        let first = read_sealed(&dir).header.wrapped_key;
        s.clear().unwrap();
        s.save(STATE).unwrap();
        assert_eq!(Behaviour::count(&b.wraps), 2);
        assert_ne!(read_sealed(&dir).header.wrapped_key, first);
    }

    /// #19: the associated data is exactly the header's bytes and the
    /// label, so no machine id (or anything else of this computer) goes
    /// into the key or the AAD. A file copied elsewhere opens there with
    /// the same protector.
    #[test]
    fn the_aad_is_the_header_and_the_label_only() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        store_in(&dir).save(STATE).unwrap();
        let raw = fs::read(dir.join(DEVICE_FILE)).unwrap();
        let file: SealedFile = serde_json::from_slice(&raw).unwrap();
        let header_text = serde_json::to_string(&file.header).unwrap();
        assert!(String::from_utf8_lossy(&raw).contains(&header_text), "the header is written in its canonical form");
        let mut expected = header_text.into_bytes();
        expected.extend_from_slice(b"vettid-desktop-device-v1");
        assert_eq!(file.header.aad(), expected);
        // Opened by hand with that AAD and the data key.
        let wrapped = B64.decode(&file.header.wrapped_key).unwrap();
        let key = protector::Protector::unwrap(&testing::TestProtector(Arc::default()), &wrapped).unwrap();
        let cipher = XChaCha20Poly1305::new_from_slice(&key[..]).unwrap();
        let nonce = B64.decode(&file.header.nonce).unwrap();
        let plain = cipher
            .decrypt(XNonce::from_slice(&nonce), Payload { msg: &B64.decode(&file.ciphertext).unwrap(), aad: &expected })
            .unwrap();
        assert_eq!(plain, STATE);
        // Elsewhere (another folder: another computer, as far as the file
        // goes).
        let other = base.path().join("elsewhere");
        fs::create_dir(&other).unwrap();
        fs::write(other.join(DEVICE_FILE), &raw).unwrap();
        assert_eq!(store_in(&other).load().unwrap().as_deref().map(|v| &v[..]), Some(STATE));
    }

    /// Any change to the header, or the label, and the file doesn't open:
    /// Corrupt, and the file is kept.
    #[test]
    fn a_changed_header_doesnt_open() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        store_in(&dir).save(STATE).unwrap();
        let good = read_sealed(&dir);
        let changes: [fn(&mut Header); 3] = [|h| h.created_at += 1, |h| h.notice_shown = true, |h| {
            let mut n = B64.decode(&h.nonce).unwrap();
            n[0] ^= 1;
            h.nonce = B64.encode(n);
        }];
        for change in changes {
            let mut f = SealedFile { header: good.header.clone(), ciphertext: good.ciphertext.clone() };
            change(&mut f.header);
            write_sealed(&dir, &f);
            let mut s = store_in(&dir);
            assert_eq!(s.load(), Err(StoreError::Corrupt));
            assert!(matches!(s.take_failure(), Some(CredentialError::Unreadable)));
            assert!(exists(&dir), "kept");
        }
        // Another format version or protector isn't opened at all.
        for change in [|h: &mut Header| h.v = 3, |h: &mut Header| h.protector = "passphrase".into()] {
            let mut f = SealedFile { header: good.header.clone(), ciphertext: good.ciphertext.clone() };
            change(&mut f.header);
            write_sealed(&dir, &f);
            assert_eq!(store_in(&dir).load(), Err(StoreError::Corrupt));
            assert_eq!(stored_key_protection(&dir).protector, "unknown");
            assert!(exists(&dir));
        }
        // An extra header field is refused, not dropped.
        let mut v: serde_json::Value = serde_json::to_value(SealedFile { header: good.header.clone(), ciphertext: good.ciphertext.clone() }).unwrap();
        v["header"]["extra"] = serde_json::json!(1);
        fs::write(dir.join(DEVICE_FILE), serde_json::to_vec(&v).unwrap()).unwrap();
        assert_eq!(store_in(&dir).load(), Err(StoreError::Corrupt));
        // The original still opens.
        write_sealed(&dir, &good);
        assert!(store_in(&dir).load().unwrap().is_some());
    }

    /// A header that names another protector that is present here doesn't
    /// open: a file sealed by one isn't handed to the other. Corrupt, and
    /// the file is kept.
    #[test]
    fn a_header_naming_another_present_protector_doesnt_open() {
        use protector::{Availability, DataKey, Protector, ProtectorError, Protectors};
        /// Present, with its own wrapping (the test protector's, inverted).
        struct Other(testing::TestProtector);
        impl Protector for Other {
            fn id(&self) -> &'static str {
                "other"
            }
            fn availability(&self) -> Availability {
                self.0.availability()
            }
            fn probe(&self) -> Result<(), ProtectorError> {
                self.0.probe()
            }
            fn wrap(&self, key: &[u8; 32]) -> Result<Vec<u8>, ProtectorError> {
                Ok(self.0.wrap(key)?.into_iter().map(|b| !b).collect())
            }
            fn unwrap(&self, wrapped: &[u8]) -> Result<DataKey, ProtectorError> {
                let inverted: Vec<u8> = wrapped.iter().map(|b| !b).collect();
                self.0.unwrap(&inverted)
            }
            fn remove_external(&self) -> Result<(), ProtectorError> {
                self.0.remove_external()
            }
        }
        let both = |first: &Arc<Behaviour>, second: &Arc<Behaviour>| {
            Protectors::new(
                vec![Box::new(testing::TestProtector(first.clone())), Box::new(Other(testing::TestProtector(second.clone())))],
                Box::new(testing::TestLegacy(first.clone())),
            )
        };
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        let (first, second) = (Arc::new(Behaviour::default()), Arc::new(Behaviour::default()));
        // Sealed by "test", renamed to "other"; then sealed by "other"
        // ("test" absent), renamed to "test".
        for (sealer_absent, renamed_to) in [(false, "other"), (true, "test")] {
            fs::remove_dir_all(&dir).ok();
            Behaviour::set(&first.absent, sealer_absent);
            DeviceStore::with_protectors(&dir, None, both(&first, &second)).save(STATE).unwrap();
            Behaviour::set(&first.absent, false);
            let mut f = read_sealed(&dir);
            assert_ne!(f.header.protector, renamed_to);
            f.header.protector = renamed_to.into();
            write_sealed(&dir, &f);
            let mut s = DeviceStore::with_protectors(&dir, None, both(&first, &second));
            assert_eq!(s.load(), Err(StoreError::Corrupt), "renamed to {renamed_to}");
            assert!(matches!(s.take_failure(), Some(CredentialError::Unreadable)));
            assert!(exists(&dir), "kept");
        }
    }

    /// Fail secure: a protector that fails at save writes nothing and says
    /// so; with none present, the no-protector notice. Never a fallback.
    #[test]
    fn a_failing_protector_saves_nothing() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        let b = Arc::new(Behaviour::default());
        Behaviour::set(&b.fail_wrap, true);
        let mut s = store_with(&dir, &b);
        assert_eq!(s.save(STATE), Err(StoreError::Io));
        let err = s.take_failure().expect("why");
        assert!(matches!(err, CredentialError::NotProtected { by: "the test protector" }), "{err}");
        assert!(!exists(&dir));
        Behaviour::set(&b.fail_wrap, false);
        Behaviour::set(&b.absent, true);
        assert_eq!(s.save(STATE), Err(StoreError::Io));
        assert!(matches!(s.take_failure(), Some(CredentialError::NoProtector)));
        assert!(!exists(&dir));
        assert_eq!(stored_key_protection(&dir).protector, "none");
    }

    /// A protector that fails at load keeps the file and says why (Io: it
    /// may work later); it never falls back.
    #[test]
    fn a_failing_protector_at_load_keeps_the_file() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        store_in(&dir).save(STATE).unwrap();
        let b = Arc::new(Behaviour::default());
        Behaviour::set(&b.fail_unwrap, true);
        let mut s = store_with(&dir, &b);
        assert_eq!(s.load(), Err(StoreError::Io));
        assert!(matches!(s.take_failure(), Some(CredentialError::NotOpened { by: "the test protector" })));
        assert!(exists(&dir));
    }

    /// No migration: the earlier format is deleted unread, with the legacy
    /// entry, and then there is nothing to load.
    #[test]
    fn the_earlier_format_is_deleted_unread() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        store::ensure_config_dir(&dir).unwrap();
        fs::write(dir.join(DEVICE_FILE), legacy_bytes()).unwrap();
        fs::write(dir.join(format!("{DEVICE_FILE}.tmp-1-00")), legacy_bytes()).unwrap();
        assert_eq!(stored_key_protection(&dir), KeyProtection { protector: "legacy", bound: false });
        let b = Arc::new(Behaviour::default());
        assert!(retire_legacy_with(&dir, &testing::protectors(&b)).unwrap());
        assert_eq!(Behaviour::count(&b.legacy_removes), 1);
        assert!(!exists(&dir));
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0, "temporary copies too");
        assert!(!retire_legacy_with(&dir, &testing::protectors(&b)).unwrap(), "nothing left to retire");

        // Through a load (a pairing that starts over it).
        fs::write(dir.join(DEVICE_FILE), legacy_bytes()).unwrap();
        let mut s = store_with(&dir, &b);
        assert_eq!(s.load().unwrap(), None);
        assert_eq!(Behaviour::count(&b.legacy_removes), 2);
        assert!(!exists(&dir));
    }

    /// The legacy entry not confirmed gone: reported, never "removed".
    #[test]
    fn a_legacy_key_not_removed_is_reported() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        store::ensure_config_dir(&dir).unwrap();
        fs::write(dir.join(DEVICE_FILE), legacy_bytes()).unwrap();
        let b = Arc::new(Behaviour::default());
        Behaviour::set(&b.fail_legacy_remove, true);
        assert!(matches!(retire_legacy_with(&dir, &testing::protectors(&b)), Err(CredentialError::LegacyNotRemoved)));
        let mut s = store_with(&dir, &b);
        fs::write(dir.join(DEVICE_FILE), legacy_bytes()).unwrap();
        assert_eq!(s.load(), Err(StoreError::Io));
        assert!(matches!(s.take_failure(), Some(CredentialError::LegacyNotRemoved)));
    }

    /// A retirement that couldn't confirm anything while the file may still
    /// be there is an error, not "nothing here".
    #[test]
    fn a_retirement_that_couldnt_check_is_not_nothing_here() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        store::ensure_config_dir(&dir).unwrap();
        assert!(after_retiring(&dir, Ok(false)).is_ok(), "no file: nothing here");
        fs::write(dir.join(DEVICE_FILE), legacy_bytes()).unwrap();
        assert!(matches!(after_retiring(&dir, Ok(false)), Err(CredentialError::IoError(_))));
        assert!(matches!(after_retiring(&dir, Err(CredentialError::LegacyNotRemoved)), Err(CredentialError::LegacyNotRemoved)));
        assert!(after_retiring(&dir, Ok(true)).is_ok());
        assert!(exists(&dir), "nothing here removes the file");
    }

    /// Only the earlier format exactly is deleted: anything else this build
    /// can't read is kept.
    #[test]
    fn anything_else_unreadable_is_kept() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        store::ensure_config_dir(&dir).unwrap();
        let b = Arc::new(Behaviour::default());
        let others: [&[u8]; 5] = [
            b"not json",
            b"{}",
            br#"{"version":1,"binding":"machine","nonce":[1],"ciphertext":[2]}"#,
            br#"{"version":1,"binding":"keyring","protector":"dpapi","nonce":[1],"ciphertext":[2]}"#,
            br#"{"version":2,"binding":"keyring","nonce":[1],"ciphertext":[2]}"#,
        ];
        for other in others {
            fs::write(dir.join(DEVICE_FILE), other).unwrap();
            assert!(!retire_legacy_with(&dir, &testing::protectors(&b)).unwrap());
            assert_eq!(store_with(&dir, &b).load(), Err(StoreError::Corrupt));
            assert_eq!(fs::read(dir.join(DEVICE_FILE)).unwrap(), other, "kept as it was");
            assert_eq!(stored_key_protection(&dir).protector, "unknown");
        }
        assert_eq!(Behaviour::count(&b.legacy_removes), 0);
    }

    /// A protector this build doesn't have here (#69's Linux `keyring`):
    /// kept, and reported unreadable, so the notice says to log out and
    /// pair again. Settings can't tell what protects it.
    #[test]
    fn an_unknown_protector_is_unreadable_and_kept() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        store_in(&dir).save(STATE).unwrap();
        let mut f = read_sealed(&dir);
        f.header.protector = "keyring-of-another-build".into();
        write_sealed(&dir, &f);
        let mut s = store_in(&dir);
        assert_eq!(s.load(), Err(StoreError::Corrupt));
        assert!(matches!(s.take_failure(), Some(CredentialError::Unreadable)));
        assert!(exists(&dir));
        assert_eq!(stored_key_protection(&dir), KeyProtection { protector: "unknown", bound: false });
    }

    /// What a wipe learns from the header, before removing anything.
    #[test]
    fn a_wipe_reads_what_the_file_was_sealed_with() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        assert_eq!(what_is_sealed(&dir), Wiping::nothing(), "no file: nothing of a pairing");
        store::ensure_config_dir(&dir).unwrap();
        fs::write(dir.join("connection.enc"), b"old").unwrap();
        assert_eq!(what_is_sealed(&dir), Wiping { legacy: true, ..Wiping::nothing() });
        fs::remove_file(dir.join("connection.enc")).unwrap();
        store_in(&dir).save(STATE).unwrap();
        assert_eq!(what_is_sealed(&dir), Wiping { sealed_by: Some("test".into()), legacy: false });
        fs::write(dir.join("connection.enc"), b"old").unwrap();
        assert_eq!(what_is_sealed(&dir), Wiping { sealed_by: Some("test".into()), legacy: true });
        fs::remove_file(dir.join("connection.enc")).unwrap();
        fs::write(dir.join(DEVICE_FILE), legacy_bytes()).unwrap();
        assert_eq!(what_is_sealed(&dir), Wiping::legacy_file());
        fs::write(dir.join(DEVICE_FILE), b"not json").unwrap();
        assert_eq!(what_is_sealed(&dir), Wiping::unknown());
    }

    #[test]
    fn clear_removes_the_file_and_the_keys_and_says_so() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        let b = Arc::new(Behaviour::default());
        let mut s = store_with(&dir, &b);
        s.save(STATE).unwrap();
        s.clear().unwrap();
        assert!(!exists(&dir));
        assert_eq!((Behaviour::count(&b.removes), Behaviour::count(&b.legacy_removes)), (1, 1));
        assert_eq!(s.load().unwrap(), None);
        s.clear().unwrap();
    }

    /// A key that can't be confirmed gone fails the clear (device.unlinked
    /// then says "couldn't be deleted"), even though the file went.
    #[test]
    fn a_clear_with_a_key_not_removed_is_not_reported_done() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        for flag in [|b: &Behaviour| Behaviour::set(&b.fail_remove, true), |b: &Behaviour| Behaviour::set(&b.fail_legacy_remove, true)] {
            let b = Arc::new(Behaviour::default());
            let mut s = store_with(&dir, &b);
            s.save(STATE).unwrap();
            flag(&b);
            assert_eq!(s.clear(), Err(StoreError::Io));
            assert!(s.take_failure().is_some());
            assert!(!exists(&dir), "the file itself went");
        }
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
                let mut s = store_since_for_tests(&dir, Some(store::wipe_epoch()));
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
        let later = fs::read(dir.join(DEVICE_FILE)).unwrap();
        // The old store still can't write over the later pairing.
        assert_eq!(before.save(b"{\"v\":1,\"ik_seed\":\"b2xkLXN0b3Jl\"}"), Err(StoreError::Io));
        assert!(matches!(before.take_failure(), Some(CredentialError::LoggedOutMeanwhile)));
        assert_eq!(fs::read(dir.join(DEVICE_FILE)).unwrap(), later, "the later pairing is byte for byte as it was");
        before.clear().unwrap();
        assert!(exists(&dir), "the later pairing stays");
        assert_eq!(fs::read(dir.join(DEVICE_FILE)).unwrap(), later, "and untouched by the clear");
    }

    #[test]
    fn debug_shows_nothing() {
        let base = tempfile::tempdir().unwrap();
        let mut s = store_in(&base.path().join("vettid-desktop"));
        assert_eq!(format!("{s:?}"), "DeviceStore(..)");
        s.save(STATE).unwrap();
        assert_eq!(format!("{s:?}"), "DeviceStore(..)", "nor with a data key in memory");
    }

    /// Linux: the whole store through the real TPM protector, against a
    /// software TPM (the legacy entry is the test one, so no Secret Service
    /// is touched). Needs swtpm; CI runs it by name.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs swtpm; CI runs it"]
    fn linux_round_trip_through_the_tpm() {
        use super::super::tpm::tests::Swtpm;
        let swtpm = Swtpm::start();
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        let b = Arc::new(Behaviour::default());
        let tpm = || Protectors::new(vec![Box::new(swtpm.protector())], Box::new(testing::TestLegacy(b.clone())));
        DeviceStore::with_protectors(&dir, None, tpm()).save(STATE).unwrap();
        assert_eq!(stored_key_protection(&dir), KeyProtection { protector: "tpm", bound: true });
        let good = read_sealed(&dir);
        assert!(!good.header.wrapped_key.is_empty());
        assert_eq!(DeviceStore::with_protectors(&dir, None, tpm()).load().unwrap().as_deref().map(|v| &v[..]), Some(STATE));
        // A changed sealed object: the TPM refuses it, the file is kept.
        let mut f = SealedFile { header: good.header.clone(), ciphertext: good.ciphertext.clone() };
        let mut w = B64.decode(&f.header.wrapped_key).unwrap();
        let last = w.len() - 1;
        w[last] ^= 1;
        f.header.wrapped_key = B64.encode(w);
        write_sealed(&dir, &f);
        let mut s = DeviceStore::with_protectors(&dir, None, tpm());
        assert_eq!(s.load(), Err(StoreError::Corrupt));
        assert!(matches!(s.take_failure(), Some(CredentialError::Unreadable)));
        assert!(exists(&dir));
        // The clear: the file, and the (test) legacy entry; the TPM keeps
        // nothing outside the file.
        write_sealed(&dir, &good);
        let mut s = DeviceStore::with_protectors(&dir, None, tpm());
        assert!(s.load().unwrap().is_some());
        s.clear().unwrap();
        assert!(!exists(&dir));
        assert_eq!(Behaviour::count(&b.legacy_removes), 1);
    }

    /// Windows: the whole store through the real DPAPI protector (DPAPI
    /// keeps no state; the legacy entry is the test one, so the real
    /// Credential Manager is not touched).
    #[cfg(windows)]
    #[test]
    fn windows_round_trip_through_dpapi() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        let b = Arc::new(Behaviour::default());
        let dpapi = || Protectors::new(vec![Box::new(super::super::dpapi::Dpapi::user())], Box::new(testing::TestLegacy(b.clone())));
        let mut s = DeviceStore::with_protectors(&dir, None, dpapi());
        s.save(STATE).unwrap();
        assert_eq!(stored_key_protection(&dir), KeyProtection { protector: "dpapi", bound: true });
        let good = read_sealed(&dir);
        assert!(!good.header.wrapped_key.is_empty());
        let mut fresh = DeviceStore::with_protectors(&dir, None, dpapi());
        assert_eq!(fresh.load().unwrap().as_deref().map(|v| &v[..]), Some(STATE));
        // A changed wrapped key: DPAPI refuses it as a bad blob, the file is
        // kept.
        let mut f = SealedFile { header: good.header.clone(), ciphertext: good.ciphertext.clone() };
        let mut w = B64.decode(&f.header.wrapped_key).unwrap();
        let last = w.len() - 1;
        w[last] ^= 1;
        f.header.wrapped_key = B64.encode(w);
        write_sealed(&dir, &f);
        let mut s = DeviceStore::with_protectors(&dir, None, dpapi());
        assert_eq!(s.load(), Err(StoreError::Corrupt));
        assert!(matches!(s.take_failure(), Some(CredentialError::Unreadable)));
        assert!(exists(&dir));
        // A changed header field: the AEAD refuses it.
        let mut f = SealedFile { header: good.header.clone(), ciphertext: good.ciphertext.clone() };
        f.header.created_at -= 1;
        write_sealed(&dir, &f);
        assert_eq!(DeviceStore::with_protectors(&dir, None, dpapi()).load(), Err(StoreError::Corrupt));
        assert!(exists(&dir));
        // The clear: the file, and the (test) legacy entry; DPAPI has none.
        write_sealed(&dir, &good);
        let mut s = DeviceStore::with_protectors(&dir, None, dpapi());
        assert!(s.load().unwrap().is_some());
        s.clear().unwrap();
        assert!(!exists(&dir));
        assert_eq!(Behaviour::count(&b.legacy_removes), 1);
    }
}
