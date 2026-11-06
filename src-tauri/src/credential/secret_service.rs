//! Linux: the Secret Service (GNOME Keyring, KWallet) as a protector,
//! ranked after the TPM (DESKTOP-REWORK-PLAN §4 "At-rest protectors", the
//! owner's choice (b)). Not bound to this computer: a copy of the keyring
//! file opens elsewhere with the login password, and any process of this
//! user can read an unlocked collection. Settings says so.
//!
//! **One entry per file.** Each pairing's data key is its own item, named
//! `device-key-v2.<id>` with a random 128-bit id. The id is what the
//! header's `wrapped_key` holds (`[1, id…]`), so a new pairing never writes
//! over another file's key.
//!
//! **Absent** is detected, never inferred from an error: no session bus
//! (no `DBUS_SESSION_BUS_ADDRESS` and no `$XDG_RUNTIME_DIR/bus`, or the
//! bus's socket is missing or refuses the connection), or
//! `org.freedesktop.secrets` is neither owned on it nor activatable. Any
//! other error is failing.
//!
//! **Removal** (log-out) deletes every device key item of this app (this
//! build's per-file entries, found by their `kind` attribute, and the
//! single `device-key-v2` entry of the build before it, by name) and then
//! searches again: Ok only when none is left. Searches are by exact
//! attributes only, which the Secret Service matches on locked items too. The earlier format's `master-key-v1` entry
//! ([`LegacyEntry`]) is swept the same way. The earlier builds used the
//! `keyring` crate 3.6 with `linux-native` and `sync-secret-service`, whose
//! default store is the Secret Service (keyutils was only compiled in), so
//! that entry can only ever have been written there.
//!
//! Before searching, every locked collection is unlocked: one Unlock call
//! for all of them, so one prompt, waited for at most `PROMPT_TIMEOUT_S`
//! (120 s) in all, while log-out holds the store's writer lock. One that
//! stays locked makes removal "not removed" and a load failing, never "no
//! entry".
//!
//! When the Secret Service is absent (as far as this process can see: it
//! may only be unreachable from here), removal succeeds only when nothing
//! being wiped could have an item there: the device file's header, read
//! before the wipe, names another protector, and no earlier format's
//! pairing is involved; with no device file, and no marker of an
//! interrupted wipe (`store`), there is nothing of a pairing. Otherwise it
//! is "not removed". Only GNOME Keyring has been tried; KWallet is
//! untested.
//!
//! Every wipe of this build (log-out, the clear on device.unlinked, the
//! earlier format's retirement) records what it removes in a marker before
//! removing anything, so a later log-out still knows. What that leaves,
//! disclosed: with the Secret Service unreachable, an item orphaned by a
//! crash between `wrap` and the file's save, or a `master-key-v1` that an
//! earlier build failed to remove after deleting its own file, stays in
//! the keyring, and log-out reports nothing to remove. The
//! header is read unauthenticated, so a forged one (`"protector":"tpm"`
//! over a file the Secret Service sealed) makes log-out skip that item
//! while the Secret Service is unreachable: a false "removed". Forging it
//! needs write access to the `0700` folder, so this user or root, who can
//! already read the unlocked keyring.
//!
//! Tests never reach this computer's Secret Service: a test that gets as
//! far as connecting to it panics.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use dbus_secret_service::{EncryptionType, Item, SecretService as Service};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

use super::protector::{Availability, DataKey, LegacyKey, Protector, ProtectorError, Wiping};

/// The protector's plain name, for the person.
pub(super) const NAME: &str = "your computer's keyring";

/// The `service` attribute of every item this app keeps.
const SERVICE: &str = "vettid-desktop";
/// Device key entries: `device-key-v2.<hex id>`, and the build before
/// this one's single `device-key-v2`.
const ENTRY_PREFIX: &str = "device-key-v2";
/// The `kind` attribute of this build's device key entries, which removal
/// searches by.
const ENTRY_KIND: &str = "device-key-v2";
/// The earlier format's entry, only ever deleted.
const LEGACY_ACCOUNT: &str = "master-key-v1";
/// The Secret Service's well-known bus name.
const SECRETS_NAME: &str = "org.freedesktop.secrets";
/// The first byte of the header's `wrapped_key` for this protector.
const WRAPPED_VERSION: u8 = 1;
/// Random bytes in an entry id.
const ENTRY_ID_LEN: usize = 16;
/// How long an unlock prompt may stay open before it is dismissed.
const PROMPT_TIMEOUT_S: u64 = 120;
/// How long the bus may take to answer the presence checks.
const BUS_TIMEOUT: Duration = Duration::from_secs(5);

/// Where the session bus is, found as libdbus finds it (which is how the
/// Secret Service connection finds it), without starting one.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Bus {
    Address(String),
    /// No session bus address (libdbus would try X11 autolaunch here,
    /// which this app doesn't use).
    None,
}

/// `DBUS_SESSION_BUS_ADDRESS` if set, else `$XDG_RUNTIME_DIR/bus` if it is
/// a socket of this user's.
fn session_bus(env_address: Option<String>, runtime_dir: Option<PathBuf>) -> Bus {
    if let Some(a) = env_address.filter(|a| !a.trim().is_empty()) {
        return Bus::Address(a);
    }
    let Some(socket) = runtime_dir.filter(|d| d.is_absolute()).map(|d| d.join("bus")) else {
        return Bus::None;
    };
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    match std::fs::symlink_metadata(&socket) {
        // SAFETY: geteuid has no preconditions and can't fail.
        Ok(m) if m.file_type().is_socket() && m.uid() == unsafe { libc::geteuid() } => Bus::Address(unix_path_address(&socket)),
        _ => Bus::None,
    }
}

/// A D-Bus `unix:path=` address for `path`, escaped as the D-Bus
/// specification asks (bytes outside `[-0-9A-Za-z_/.\*]` as `%XX`).
fn unix_path_address(path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    let mut a = String::from("unix:path=");
    for &b in path.as_os_str().as_bytes() {
        if b.is_ascii_alphanumeric() || b"-_/.\\*".contains(&b) {
            a.push(b as char);
        } else {
            a.push_str(&format!("%{b:02x}"));
        }
    }
    a
}

/// The bus errors that mean nothing is listening at the address: the
/// socket isn't there (ENOENT) or refuses the connection (ECONNREFUSED).
fn is_no_bus(error_name: Option<&str>) -> bool {
    matches!(error_name, Some("org.freedesktop.DBus.Error.NoServer" | "org.freedesktop.DBus.Error.FileNotFound"))
}

/// Whether the Secret Service is on the session bus at `bus`. Absent only
/// for the detected conditions of the module doc; anything that can't be
/// checked is Present, so that the protector's own calls then fail with the
/// reason (failing, never a quiet fallback).
fn detect(bus: &Bus) -> Availability {
    let Bus::Address(address) = bus else {
        return Availability::Absent("no session bus");
    };
    let mut channel = match dbus::channel::Channel::open_private(address) {
        Ok(c) => c,
        Err(e) if is_no_bus(e.name()) => return Availability::Absent("the session bus isn't running"),
        Err(e) => {
            log::warn!("protector secret-service: the session bus: {}", e.name().unwrap_or("error"));
            return Availability::Present;
        }
    };
    if let Err(e) = channel.register() {
        log::warn!("protector secret-service: the session bus: {}", e.name().unwrap_or("error"));
        return Availability::Present;
    }
    let conn = dbus::blocking::Connection::from(channel);
    let bus = conn.with_proxy("org.freedesktop.DBus", "/org/freedesktop/DBus", BUS_TIMEOUT);
    let owned: Result<(bool,), _> = bus.method_call("org.freedesktop.DBus", "NameHasOwner", (SECRETS_NAME,));
    match owned {
        Ok((true,)) => return Availability::Present,
        Ok((false,)) => {}
        Err(e) => {
            log::warn!("protector secret-service: NameHasOwner: {}", e.name().unwrap_or("error"));
            return Availability::Present;
        }
    }
    let activatable: Result<(Vec<String>,), _> = bus.method_call("org.freedesktop.DBus", "ListActivatableNames", ());
    match activatable {
        Ok((names,)) if names.iter().any(|n| n == SECRETS_NAME) => Availability::Present,
        Ok(_) => Availability::Absent("no Secret Service on the session bus"),
        Err(e) => {
            log::warn!("protector secret-service: ListActivatableNames: {}", e.name().unwrap_or("error"));
            Availability::Present
        }
    }
}

/// Where this protector looks for the session bus.
enum BusSource {
    /// As libdbus would: the environment of this process.
    System,
    /// A fixed address (tests only).
    #[cfg(test)]
    Fixed(Bus),
}

impl BusSource {
    fn bus(&self) -> Bus {
        match self {
            BusSource::System => {
                session_bus(std::env::var("DBUS_SESSION_BUS_ADDRESS").ok(), std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from))
            }
            #[cfg(test)]
            BusSource::Fixed(b) => b.clone(),
        }
    }

    fn availability(&self) -> Availability {
        detect(&self.bus())
    }
}

fn failing(what: &str, e: dbus_secret_service::Error) -> ProtectorError {
    ProtectorError::Failing { by: NAME, detail: format!("{what}: {e}") }
}

/// The Secret Service of this session, with an encrypted transfer session.
fn connect() -> Result<Service, dbus_secret_service::Error> {
    if cfg!(test) {
        panic!("a test reached the real Secret Service");
    }
    Service::connect_with_max_prompt_timeout(EncryptionType::Dh, PROMPT_TIMEOUT_S)
}

/// An attribute search: every item having all of these attributes.
type Search = &'static [(&'static str, &'static str)];

/// The device key entries: this build's (marked by `kind`) and the single
/// entry of the build before it.
const DEVICE_ENTRIES: &[Search] = &[&[("service", SERVICE), ("kind", ENTRY_KIND)], &[("service", SERVICE), ("username", ENTRY_PREFIX)]];
/// The earlier format's entry, as `keyring` 3.6 wrote it.
const LEGACY_ENTRIES: &[Search] = &[&[("service", SERVICE), ("username", LEGACY_ACCOUNT)]];

/// The items the searches find, locked or not, each once. Only searches by
/// exact attributes: the Secret Service matches them on locked items too,
/// where it may not show their attributes.
fn matching<'a>(ss: &'a Service, searches: &[&[(&str, &str)]]) -> Result<Vec<Item<'a>>, dbus_secret_service::Error> {
    let mut items: Vec<Item<'a>> = Vec::new();
    for search in searches {
        let found = ss.search_items(search.iter().copied().collect())?;
        for item in found.unlocked.into_iter().chain(found.locked) {
            if !items.iter().any(|i| i.path == item.path) {
                items.push(item);
            }
        }
    }
    Ok(items)
}

/// Whether any collection is locked (an error counts as locked).
fn any_locked(ss: &Service) -> bool {
    match ss.get_all_collections() {
        Ok(all) => all.iter().any(|c| c.is_locked().unwrap_or(true)),
        Err(_) => true,
    }
}

/// Unlock every locked collection, so that a search sees every item: one
/// Unlock call for all of them, so one prompt wait, bounded by the
/// connection's prompt timeout (`PROMPT_TIMEOUT_S` in all). Err if one
/// stays locked.
fn unlock_all_collections(ss: &Service) -> Result<(), dbus_secret_service::Error> {
    let mut locked = Vec::new();
    for c in ss.get_all_collections()? {
        if c.is_locked()? {
            locked.push(Item::new(ss, c.path.clone()));
        }
    }
    if !locked.is_empty() {
        ss.unlock_all(&locked.iter().collect::<Vec<_>>())?;
    }
    if any_locked(ss) {
        return Err(dbus_secret_service::Error::Locked);
    }
    Ok(())
}

/// Delete every item the searches find, then search again: Ok only when
/// none is left and no collection is locked. With the Secret Service
/// absent, Ok only when nothing being wiped could have an item there
/// (`could_hold` false); otherwise "not removed", never a guess.
fn sweep(bus: &BusSource, searches: &[Search], what: &'static str, could_hold: bool) -> Result<(), ProtectorError> {
    let not_removed = |detail: String| ProtectorError::NotRemoved { what, detail };
    if let Availability::Absent(why) = bus.availability() {
        if could_hold {
            return Err(not_removed(format!("the Secret Service can't be reached here ({why}), so it can't be checked")));
        }
        log::info!("protector secret-service: {what}: nothing of the wiped pairing was kept there ({why})");
        return Ok(());
    }
    // #13 (lead review of #70): nothing being wiped could have an item here
    // (its header named another protector, and no earlier format was
    // there). Tidy up what can be seen without unlocking, and never ask the
    // person to unlock a keyring for it: a dismissed prompt would make a
    // log-out "not removed" for a key that was never there. A wipe whose
    // header is unknown keeps `could_hold` and the full sweep below.
    if !could_hold {
        best_effort_sweep(searches, what);
        return Ok(());
    }
    let ss = connect().map_err(|e| not_removed(format!("connect: {e}")))?;
    unlock_all_collections(&ss).map_err(|e| not_removed(format!("unlock: {e}")))?;
    let items = matching(&ss, searches).map_err(|e| not_removed(format!("search: {e}")))?;
    if !items.is_empty() {
        let mut locked = Vec::new();
        for item in &items {
            if item.is_locked().map_err(|e| not_removed(format!("lock state: {e}")))? {
                locked.push(item);
            }
        }
        if !locked.is_empty() {
            ss.unlock_all(&locked).map_err(|e| not_removed(format!("unlock: {e}")))?;
        }
        for item in &items {
            item.delete().map_err(|e| not_removed(format!("delete: {e}")))?;
        }
    }
    match matching(&ss, searches) {
        Ok(left) if left.is_empty() && any_locked(&ss) => Err(not_removed("a keyring collection is locked, so it can't be checked".into())),
        Ok(left) if left.is_empty() => Ok(()),
        Ok(left) => Err(not_removed(format!("{} still there", left.len()))),
        Err(e) => Err(not_removed(format!("could not be checked: {e}"))),
    }
}

/// [`sweep`] when nothing wiped could have an item in the Secret Service:
/// delete the matching items that are already unlocked, without unlocking
/// anything (no prompt), and only log what happens. It decides nothing.
fn best_effort_sweep(searches: &[Search], what: &'static str) {
    let ss = match connect() {
        Ok(ss) => ss,
        Err(e) => return log::info!("protector secret-service: {what}: not checked ({e}); nothing of the wiped pairing was kept there"),
    };
    match matching(&ss, searches) {
        Ok(items) => {
            for item in &items {
                if matches!(item.is_locked(), Ok(false)) {
                    if let Err(e) = item.delete() {
                        log::info!("protector secret-service: {what}: a stray item wasn't removed: {e}");
                    }
                }
            }
        }
        Err(e) => log::info!("protector secret-service: {what}: not searched ({e}); nothing of the wiped pairing was kept there"),
    }
}

/// The entry name in a header's `wrapped_key`, or why it isn't one.
fn entry_name(wrapped: &[u8]) -> Result<String, ProtectorError> {
    match wrapped {
        [WRAPPED_VERSION, id @ ..] if id.len() == ENTRY_ID_LEN => Ok(format!("{ENTRY_PREFIX}.{}", hex::encode(id))),
        _ => Err(ProtectorError::WontOpen(format!("a keyring entry id of {} bytes", wrapped.len()))),
    }
}

pub(super) struct SecretService {
    bus: BusSource,
}

impl SecretService {
    pub(super) fn system() -> Self {
        SecretService { bus: BusSource::System }
    }
}

impl Protector for SecretService {
    fn id(&self) -> &'static str {
        "secret-service"
    }
    fn availability(&self) -> Availability {
        self.bus.availability()
    }
    fn probe(&self) -> Result<(), ProtectorError> {
        let ss = connect().map_err(|e| failing("connect", e))?;
        ss.get_default_collection().map_err(|e| failing("default collection", e))?;
        Ok(())
    }
    fn wrap(&self, key: &[u8; 32]) -> Result<Vec<u8>, ProtectorError> {
        let mut id = [0u8; ENTRY_ID_LEN];
        OsRng.fill_bytes(&mut id);
        let mut wrapped = vec![WRAPPED_VERSION];
        wrapped.extend_from_slice(&id);
        let name = entry_name(&wrapped)?;
        let ss = connect().map_err(|e| failing("connect", e))?;
        let collection = ss.get_default_collection().map_err(|e| failing("default collection", e))?;
        collection.ensure_unlocked().map_err(|e| failing("unlock", e))?;
        let attrs = HashMap::from([("service", SERVICE), ("kind", ENTRY_KIND), ("username", name.as_str())]);
        let item = collection
            .create_item("VettID Desktop device key", attrs, key, false, "application/octet-stream")
            .map_err(|e| failing("write", e))?;
        // Read back: the pairing is saved only under a key that is there.
        // One that doesn't read back is deleted (best effort; log-out
        // removes any left).
        let read_back = match item.get_secret().map(Zeroizing::new) {
            Ok(back) if back.as_slice() == key.as_slice() => Ok(()),
            Ok(_) => Err(ProtectorError::Failing { by: NAME, detail: "the entry read back differs".into() }),
            Err(e) => Err(failing("read back", e)),
        };
        if let Err(e) = read_back {
            if let Err(d) = item.delete() {
                log::warn!("protector secret-service: the entry that didn't read back wasn't deleted: {d}");
            }
            return Err(e);
        }
        Ok(wrapped)
    }
    fn unwrap(&self, wrapped: &[u8]) -> Result<DataKey, ProtectorError> {
        let name = entry_name(wrapped)?;
        let ss = connect().map_err(|e| failing("connect", e))?;
        // Unlocked first: a locked or unanswering keyring is failing (it
        // may open later), never "no entry".
        ss.get_default_collection().and_then(|c| c.ensure_unlocked()).map_err(|e| failing("unlock", e))?;
        let search = [("service", SERVICE), ("kind", ENTRY_KIND), ("username", name.as_str())];
        let mut items = matching(&ss, &[&search]).map_err(|e| failing("search", e))?;
        let item = match items.len() {
            0 if any_locked(&ss) => return Err(ProtectorError::Failing { by: NAME, detail: "no entry found while a collection is locked".into() }),
            0 => return Err(ProtectorError::WontOpen("no keyring entry".into())),
            1 => items.remove(0),
            n => return Err(ProtectorError::Failing { by: NAME, detail: format!("{n} entries for one file") }),
        };
        item.ensure_unlocked().map_err(|e| failing("unlock", e))?;
        let secret = Zeroizing::new(item.get_secret().map_err(|e| failing("read", e))?);
        if secret.len() != 32 {
            return Err(ProtectorError::WontOpen(format!("a keyring entry of {} bytes", secret.len())));
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&secret);
        Ok(key)
    }
    fn remove_external(&self) -> Result<(), ProtectorError> {
        self.remove_external_for(&Wiping::unknown())
    }
    /// Unreachable is Ok only when the wiped file was sealed by another
    /// protector (#69's Linux `keyring` was this one too).
    fn remove_external_for(&self, wiping: &Wiping) -> Result<(), ProtectorError> {
        sweep(&self.bus, DEVICE_ENTRIES, "the keyring's device keys", wiping.may_be_sealed_by(&["secret-service", "keyring"]))
    }
}

/// The earlier format's `master-key-v1` entry (module doc).
pub(super) struct LegacyEntry {
    bus: BusSource,
}

impl LegacyEntry {
    pub(super) fn system() -> Self {
        LegacyEntry { bus: BusSource::System }
    }
}

impl LegacyKey for LegacyEntry {
    fn remove(&self) -> Result<(), ProtectorError> {
        self.remove_for(&Wiping::unknown())
    }
    /// Unreachable is Ok only when no earlier format's pairing is involved.
    fn remove_for(&self, wiping: &Wiping) -> Result<(), ProtectorError> {
        sweep(&self.bus, LEGACY_ENTRIES, "the earlier version's keyring key", wiping.legacy)
    }
}

/// The Secret Service protector and legacy entry with no session bus
/// (absent; nothing is connected to), for other modules' tests.
#[cfg(test)]
pub(super) fn unreachable_for_tests() -> (SecretService, LegacyEntry) {
    (SecretService { bus: BusSource::Fixed(Bus::None) }, LegacyEntry { bus: BusSource::Fixed(Bus::None) })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed(bus: Bus) -> BusSource {
        BusSource::Fixed(bus)
    }

    #[test]
    fn the_bus_is_found_as_libdbus_finds_it() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(session_bus(Some("unix:path=/x".into()), None), Bus::Address("unix:path=/x".into()));
        assert_eq!(session_bus(None, None), Bus::None);
        assert_eq!(session_bus(Some(" ".into()), Some(dir.path().into())), Bus::None, "no socket there");
        assert_eq!(session_bus(None, Some("relative".into())), Bus::None);
        // A socket of ours in the runtime folder.
        let socket = dir.path().join("bus");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        assert_eq!(session_bus(None, Some(dir.path().into())), Bus::Address(unix_path_address(&socket)));
        // A plain file isn't a bus.
        let other = tempfile::tempdir().unwrap();
        std::fs::write(other.path().join("bus"), b"").unwrap();
        assert_eq!(session_bus(None, Some(other.path().into())), Bus::None);
    }

    #[test]
    fn addresses_are_escaped() {
        assert_eq!(unix_path_address(Path::new("/run/user/1000/bus")), "unix:path=/run/user/1000/bus");
        assert_eq!(unix_path_address(Path::new("/tmp/a b,c=d")), "unix:path=/tmp/a%20b%2cc%3dd");
    }

    #[test]
    fn only_no_server_and_no_socket_mean_no_bus() {
        assert!(is_no_bus(Some("org.freedesktop.DBus.Error.NoServer")));
        assert!(is_no_bus(Some("org.freedesktop.DBus.Error.FileNotFound")));
        for other in [None, Some("org.freedesktop.DBus.Error.AccessDenied"), Some("org.freedesktop.DBus.Error.AuthFailed"), Some("org.freedesktop.DBus.Error.BadAddress")] {
            assert!(!is_no_bus(other), "{other:?}");
        }
    }

    /// No session bus reachable: absent. Log-out then succeeds for the
    /// Secret Service only when nothing wiped could have an item there (a
    /// TPM-sealed file, no earlier format); otherwise "not removed". It
    /// never connects to a Secret Service.
    #[test]
    fn with_no_bus_it_is_absent_and_removal_is_confirmed_or_not_removed() {
        let dir = tempfile::tempdir().unwrap();
        // A socket path with nothing there, and one that refuses.
        let missing = Bus::Address(unix_path_address(&dir.path().join("dead")));
        let refusing_path = dir.path().join("refusing");
        drop(std::os::unix::net::UnixListener::bind(&refusing_path).unwrap());
        let refusing = Bus::Address(unix_path_address(&refusing_path));
        for bus in [Bus::None, missing, refusing] {
            let ss = SecretService { bus: fixed(bus.clone()) };
            assert!(matches!(ss.availability(), Availability::Absent(_)), "{bus:?}");
            let legacy = LegacyEntry { bus: fixed(bus.clone()) };
            let tpm_only = Wiping { sealed_by: Some("tpm".into()), legacy: false };
            ss.remove_external_for(&tpm_only).unwrap();
            legacy.remove_for(&tpm_only).unwrap();
            let not_removed = |r: Result<(), ProtectorError>| matches!(r, Err(ProtectorError::NotRemoved { .. }));
            for sealed_by in [Some("secret-service"), Some("keyring"), None] {
                let w = Wiping { sealed_by: sealed_by.map(String::from), legacy: false };
                assert!(not_removed(ss.remove_external_for(&w)), "{sealed_by:?}");
                legacy.remove_for(&w).unwrap();
            }
            for w in [Wiping { sealed_by: Some("tpm".into()), legacy: true }, Wiping::legacy_file(), Wiping::unknown()] {
                assert!(not_removed(legacy.remove_for(&w)), "{w:?}");
            }
            assert!(not_removed(ss.remove_external()), "nothing known: not removed");
            assert!(not_removed(legacy.remove()));
        }
    }

    /// A bus address this build can't use is not "absent": it is checked
    /// by the protector's own calls, which then fail with the reason.
    #[test]
    fn a_bad_bus_address_is_not_absent() {
        assert_eq!(detect(&Bus::Address("nonsense".into())), Availability::Present);
    }

    #[test]
    fn entries_are_named_per_file() {
        let a = entry_name(&[[1u8].as_slice(), &[0xab; 16]].concat()).unwrap();
        assert_eq!(a, format!("device-key-v2.{}", "ab".repeat(16)));
        for bad in [&b""[..], &[1u8; 16], &[1u8; 18], &[2u8; 17]] {
            assert!(matches!(entry_name(bad), Err(ProtectorError::WontOpen(_))), "{bad:?}");
        }
        // Removal finds this build's entries by `kind`, the build before's
        // by its one name, and the earlier format's by its name: all exact.
        assert_eq!(DEVICE_ENTRIES, &[&[("service", "vettid-desktop"), ("kind", "device-key-v2")][..], &[("service", "vettid-desktop"), ("username", "device-key-v2")][..]]);
        assert_eq!(LEGACY_ENTRIES, &[&[("service", "vettid-desktop"), ("username", "master-key-v1")][..]]);
    }

    /// A live session bus with no Secret Service on it: absent. Needs
    /// `dbus-daemon`; run by CI (ci.yml) by name.
    #[test]
    #[ignore = "needs dbus-daemon; CI runs it"]
    fn a_bus_without_a_secret_service_is_absent() {
        let config = tempfile::tempdir().unwrap();
        let socket = config.path().join("bus");
        let conf = config.path().join("session.conf");
        std::fs::write(
            &conf,
            format!(
                "<!DOCTYPE busconfig PUBLIC \"-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN\" \"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">\n<busconfig><type>session</type><listen>{}</listen><servicedir>{}</servicedir><policy context=\"default\"><allow send_destination=\"*\" eavesdrop=\"true\"/><allow eavesdrop=\"true\"/><allow own=\"*\"/></policy></busconfig>\n",
                unix_path_address(&socket),
                config.path().display()
            ),
        )
        .unwrap();
        let mut daemon = std::process::Command::new("dbus-daemon")
            .arg(format!("--config-file={}", conf.display()))
            .arg("--nofork")
            .spawn()
            .expect("dbus-daemon");
        let bus = Bus::Address(unix_path_address(&socket));
        let mut seen = Availability::Present;
        for _ in 0..100 {
            if socket.exists() {
                seen = detect(&bus);
                if seen != Availability::Absent("the session bus isn't running") {
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = daemon.kill();
        let _ = daemon.wait();
        assert_eq!(seen, Availability::Absent("no Secret Service on the session bus"));
    }
}
