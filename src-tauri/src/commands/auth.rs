use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use tauri::{AppHandle, Emitter, State};

use crate::credential::device_store::{self, DeviceStore};
use crate::credential::store::{self, CredentialError, WipeEpoch};
use crate::link::{self, Link, Snapshot};
use crate::state::AppState;
use vettid_device::access::EndOutcome;
use vettid_device::pairing::{PairError, SystemClock};
use vettid_device::transport::Http;

#[derive(Debug, Serialize)]
pub struct AuthStatus {
    pub is_registered: bool,
    /// A pairing is waiting for the phone (#79): a pairing view that
    /// didn't start it (after a reload) says so instead of the code form.
    pub pairing_under_way: bool,
    pub is_unlocked: bool,
    pub has_active_session: bool,
    // Device-identity fields surfaced in the Settings view so the
    // user can confirm which desktop they're looking at.
    pub hostname: String,
    pub platform: String,
    pub os_name: String,
    pub os_version: String,
    pub binary_fingerprint: String,
    pub machine_fingerprint: String,
    pub app_version: String,
    /// What protects the saved pairing, from the file's header (#11, #13):
    /// "dpapi", "keyring", "none" (no pairing saved), "legacy" (an earlier
    /// version's file, deleted at the next unlock) or "unknown" (a file
    /// that can't be read). Shown in Settings.
    pub key_protection: String,
    /// Whether that protection binds the saved pairing to this computer.
    pub key_bound: bool,
    /// Plain notices on who else may open it (Windows: a domain-joined
    /// computer, a roaming profile). None is not a guarantee.
    pub key_notices: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    /// The desktop pairing code the member's phone shows (VAULT-MESSAGING
    /// §6.4: a link or the QR's text), pasted as it is.
    pub invite_code: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub success: bool,
    pub error: Option<String>,
    /// The id the vault gave this device.
    pub connection_id: Option<String>,
    /// The access session (§6.8), when one is live.
    pub session_id: Option<String>,
    /// Unix seconds: when this desktop stops treating the session as live,
    /// a margin before the vault's `expires_at` (#82: not the freshness cap).
    pub expires_at: Option<i64>,
    /// Not a success, but the pairing is saved: there is no access session
    /// (yet). The pairing screen shows `error` and continues to Start New
    /// Session instead of offering to pair again.
    pub paired_without_session: bool,
    /// Unix seconds: when the person may ask again after `too_soon` (#83),
    /// for the frontend to show in the computer's own locale.
    pub retry_at: Option<i64>,
    /// Unix seconds: the phone declined a new session while the current one
    /// is live (#96), and this is when that one ends, as the session timer
    /// shows it, for the frontend to name in the computer's own locale.
    pub continues_until: Option<i64>,
}

impl RegisterResponse {
    fn failed(error: impl Into<String>) -> Self {
        RegisterResponse {
            success: false,
            error: Some(error.into()),
            connection_id: None,
            session_id: None,
            expires_at: None,
            paired_without_session: false,
            retry_at: None,
            continues_until: None,
        }
    }

    fn paired_without_session(error: impl Into<String>) -> Self {
        RegisterResponse { paired_without_session: true, ..Self::failed(error) }
    }

    /// A live session, from `snap` (which must be active).
    fn live(snap: &Snapshot) -> Self {
        RegisterResponse {
            success: true,
            error: None,
            connection_id: snap.device_id.clone(),
            session_id: snap.session_id.clone(),
            expires_at: snap.shown_expiry(chrono::Utc::now()).map(|t| t.timestamp()),
            paired_without_session: false,
            retry_at: None,
            continues_until: None,
        }
    }
}

/// Event emitted once the pairing handshake is done: the six-digit code
/// the member compares with their phone (§6.7), and what to do.
pub const PAIRING_SAS_EVENT: &str = "pairing:sas";

#[derive(Debug, Clone, Serialize)]
pub struct PairingSasEvent {
    pub sas: String,
    pub instruction: String,
}

/// Event emitted when the vault has taken a request for access: the
/// owner's phone is being asked.
pub const ACCESS_REQUESTED_EVENT: &str = "session:requested";

/// A second Connect while a pairing still waits for the phone (#79).
const PAIR_UNDER_WAY_NOTICE: &str =
    "This desktop is still waiting for your phone to approve a pairing. Approve or reject it on your phone first.";

/// What a failed pairing tells the person. The SAS mismatch and the
/// timeout keep the engine's own texts (`vettid_device::display`).
fn pair_notice(e: &PairError, store: Option<&CredentialError>) -> String {
    // #107 (review M2): the relay refused this computer's clock, the most
    // likely first-run cause; the relay's Date is for the notice only.
    if let Some(date) = e.clock_skew() {
        return link::pair_clock_notice(link::clock_offset(date));
    }
    match e {
        PairError::Code(_) | PairError::NotForDesktop | PairError::Expired => link::PAIR_CODE_NOTICE.into(),
        PairError::AlreadyPaired => link::PAIR_ALREADY_NOTICE.into(),
        PairError::Rejected | PairError::TimedOut => e.to_string(),
        PairError::Store(_) => store.and_then(link::plain_store_notice).unwrap_or_else(|| link::PAIR_FAILED_NOTICE.into()),
        // The pending pairing's keys are removed at the next start too.
        PairError::NotCleared(inner) => pair_notice(inner, store),
        _ => link::PAIR_FAILED_NOTICE.into(),
    }
}

/// Pair this desktop with its vault (VAULT-MESSAGING §6.7), through the
/// relay: read the code the member's phone shows, run the handshake, show
/// the SAS (`pairing:sas`) and wait for the owner's approval on the phone.
/// Then open the session and read `vault.status`: an access session the
/// approval granted is reported live only once the vault names it there.
///
/// Fail secure: the desktop is paired only once the vault's
/// `device.paired` is stored (see `vettid_device::pairing`); nothing is
/// stored unless a protector wraps its data key (#13).
#[tauri::command]
pub async fn register(
    app: AppHandle,
    state: State<'_, AppState>,
    request: RegisterRequest,
) -> Result<RegisterResponse, String> {
    // #30: first, before anything that waits. A log-out from here on means
    // this pairing is not saved.
    let since = store::wipe_epoch();
    let mark = reset_mark(&state);
    // Review MEDIUM 3: an unlock meanwhile leaves the device store alone.
    // #79: and a second pairing waits for this one to end.
    let Some(_pairing) = PairingUnderWay::only(&state.pairing) else {
        log::warn!("register: refused, a pairing is already under way");
        return Ok(RegisterResponse::failed(PAIR_UNDER_WAY_NOTICE));
    };
    // #97: a new pairing; an earlier launch's notice was about the old one.
    set_unlock_notice(&state, None);
    let config_dir = store::default_config_dir().map_err(|e| e.to_string())?;
    // Checked before pairing starts, so a folder another account can open,
    // or a protector that fails or isn't there (#13), is refused before the
    // vault ever lists this desktop.
    store::ensure_config_dir_since(&config_dir, since).map_err(|e| e.to_string())?;
    device_store::protection_ready().map_err(|e| e.to_string())?;

    // The code is read as it is (it holds base64): only surrounding
    // whitespace from a paste is dropped.
    let code = request.invite_code.trim();
    if code.is_empty() {
        return Ok(RegisterResponse::failed(link::PAIR_CODE_NOTICE));
    }
    let name = collect_device_fingerprint().hostname;

    let mut store = DeviceStore::new(&config_dir, since);
    // Until the first save (the pending pairing, stored by start): no unlock
    // opens the store meanwhile. After it, the pairing count keeps unlock
    // away.
    let opening = state.opening.lock().await;
    let started = vettid_device::pairing::start(code, &name, Http::new, &mut store, SystemClock).await;
    drop(opening);
    let pairing = match started {
        Ok(p) => p,
        Err(e) => {
            log::warn!("register: pairing not started: {}", e);
            return Ok(RegisterResponse::failed(pair_notice(&e, store.take_failure().as_ref())));
        }
    };
    let _ = app.emit(
        PAIRING_SAS_EVENT,
        PairingSasEvent { sas: pairing.sas().to_string(), instruction: pairing.instruction().to_string() },
    );
    let paired = match pairing.wait_for_approval(&mut store).await {
        // The returned state is dropped (its keys wipe themselves): the
        // session opens it from the store.
        Ok((paired, _state)) => paired,
        Err(e) => {
            log::warn!("register: not paired: {}", e);
            return Ok(RegisterResponse::failed(pair_notice(&e, store.take_failure().as_ref())));
        }
    };
    log::info!("register: paired");
    *state.is_registered.write().await = true;

    let mut link = match Link::open(store) {
        Ok(Some(l)) => l,
        Ok(None) | Err(_) => {
            log::error!("register: paired, but the saved pairing couldn't be opened");
            return Ok(RegisterResponse::paired_without_session(link::PAIRED_NO_ACCESS_NOTICE));
        }
    };
    if link.session.device_id() != Some(paired.device_id.as_str()) {
        log::warn!("register: the stored device id isn't the one device.paired named");
    }
    if let Err(e) = link.read_status().await {
        log::info!("register: vault.status: {}", e);
    }
    // As at unlock: the vault removed this device already.
    if link.unlinked() {
        return Ok(RegisterResponse::failed(erase_unlinked(&state, link).await));
    }
    match install(&state, link, since, mark).await {
        Some(snap) if snap.active_at(chrono::Utc::now()) => Ok(RegisterResponse::live(&snap)),
        Some(_) => Ok(RegisterResponse::paired_without_session(link::PAIRED_NO_ACCESS_NOTICE)),
        None if store::wipe_epoch() != since => {
            // A log-out ran meanwhile (and, if it ran after the save,
            // removed it): nothing is paired.
            *state.is_registered.write().await = false;
            Ok(RegisterResponse::failed(store::LOGGED_OUT_MEANWHILE_NOTICE))
        }
        // An End session meanwhile: the pairing is saved, the
        // session not shown.
        None => Ok(RegisterResponse::paired_without_session(link::PAIRED_NO_ACCESS_NOTICE)),
    }
}

/// Put `link` in place as the open pairing and show what it knows, unless
/// a log-out (since `since`) or a reset (since `mark`) happened meanwhile:
/// then it is dropped (its keys wipe themselves) and `None` returned. The
/// background refresh is started if there is something to keep up.
async fn install(state: &AppState, link: Link, since: WipeEpoch, mark: ResetMark) -> Option<Snapshot> {
    let mut slot = state.link.lock().await;
    if store::wipe_epoch() != since || overtaken_by_reset(state, mark) {
        log::warn!("a log-out or End session overlapped this; not opened");
        return None;
    }
    let now = chrono::Utc::now();
    let snap = link.snapshot(now);
    let keep = link.keep_refreshing(now);
    // An end an earlier run left unanswered is settled at once, in the
    // background (§6.8: after vault.status).
    let end_pending = link.session.access_end().is_some();
    *slot = Some(link);
    // #97: opened, so an earlier launch's "couldn't open" no longer applies.
    set_unlock_notice(state, None);
    state.publish(snap.clone());
    // With the link locked: an old refresh isn't mid-operation.
    if keep {
        state.start_refresh(end_pending);
    } else {
        state.stop_refresh();
    }
    Some(snap)
}

/// The vault removed this device (`device.unlinked`): erase its stored
/// state and the protector's key, each confirmed gone (not the folder),
/// and say what happened.
async fn erase_unlinked(state: &AppState, link: Link) -> String {
    state.publish(Snapshot::default());
    // #97: the vault removed this desktop; an earlier "couldn't open, the
    // pairing is kept" no longer applies.
    set_unlock_notice(state, None);
    if link.erase() {
        *state.is_registered.write().await = false;
        link::UNLINKED_ERASED_NOTICE.into()
    } else {
        link::UNLINKED_NOT_ERASED_NOTICE.into()
    }
}

/// The device fingerprint shown in Settings. The device name sent at
/// pairing is its hostname.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceFingerprint {
    pub hostname: String,
    pub platform: String,
    pub os_name: String,
    pub os_version: String,
    pub app_version: String,
    pub binary_fingerprint: String,
    pub machine_fingerprint: String,
}

/// Cached device fingerprint. `compute_device_fingerprint` hashes the
/// whole executable with SHA-256 — several seconds on a debug build —
/// so it is computed exactly once. `warm_device_fingerprint()` kicks
/// that off at app startup (see lib.rs) so a pairing's request-session
/// never blocks on it; the value is known before the request is made.
static DEVICE_FINGERPRINT: OnceLock<DeviceFingerprint> =
    OnceLock::new();

/// Return the device fingerprint, computing it once and caching it.
/// Effectively instant after `warm_device_fingerprint()` has run.
pub(crate) fn collect_device_fingerprint() -> DeviceFingerprint {
    DEVICE_FINGERPRINT
        .get_or_init(compute_device_fingerprint)
        .clone()
}

/// Compute the device fingerprint on a background thread at app
/// startup so it is ready before the user can reach the pairing flow.
pub(crate) fn warm_device_fingerprint() {
    std::thread::spawn(|| {
        let _ = collect_device_fingerprint();
        log::info!("Device fingerprint warmed");
    });
}

fn compute_device_fingerprint() -> DeviceFingerprint {
    use crate::fingerprint::binary::binary_fingerprint;

    let hostname = hostname::get()
        .ok()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_default();
    let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let binary_fp = binary_fingerprint().unwrap_or_default();
    // Hex SHA-256 over a stable set of machine attributes (hostname,
    // CPU brand, primary MAC, OS release fingerprint). Surfacing it
    // here lets the phone-side authorize screen show a value the user
    // can compare against Settings → Device on the desktop. This value
    // is public; the credential store's machine-bound fallback key is
    // derived separately and is never this value.
    let machine_fp = machine_fingerprint_hex();

    // os_name + os_version are surfaced verbatim in the phone-side
    // detail screen so the user can verify which physical machine is
    // talking to the vault. `std::env::consts::OS` only gives the
    // kernel family ("linux", "macos", "windows"), which is already
    // redundant with `platform`. Resolve the real distribution name
    // and version per-OS so the row reads "Fedora · 43" instead of
    // "linux".
    let (os_name, os_version) = resolve_os_details();

    DeviceFingerprint {
        hostname,
        platform,
        os_name,
        os_version,
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        binary_fingerprint: binary_fp,
        machine_fingerprint: machine_fp,
    }
}

/// The machine fingerprint shown in Settings and sent at pairing, from
/// this platform's collector: the one `platform_key` uses (#17). Before,
/// every platform but Windows used the Linux collector, so on macOS the
/// value was computed from attributes a Mac doesn't have (such as
/// `/etc/machine-id`). Empty if the attributes can't be collected.
pub(crate) fn machine_fingerprint_hex() -> String {
    fingerprint_hex_of(crate::fingerprint::platform_key::collect_attributes())
}

/// The displayed fingerprint for collected attributes; empty if they
/// couldn't be collected.
fn fingerprint_hex_of(
    attrs: Result<crate::fingerprint::platform_linux::MachineAttributes, crate::fingerprint::platform_linux::FingerprintError>,
) -> String {
    use crate::fingerprint::platform_linux::compute_machine_fingerprint_hex;
    attrs.ok().map(|attrs| compute_machine_fingerprint_hex(&attrs)).unwrap_or_default()
}

/// Best-effort distribution name + version for the current OS. The
/// values are display-only — surfaced to the user in the phone's
/// device-detail screen so they can verify what machine paired.
///
/// Linux: parses `/etc/os-release` (the freedesktop standard) for
///   NAME + VERSION_ID, falling back to PRETTY_NAME on either.
/// macOS / Windows: returns the kernel family for now; we can
///   shell out to `sw_vers` or read the Windows registry later if
///   the desktop ever ships on those platforms.
fn resolve_os_details() -> (String, String) {
    #[cfg(target_os = "linux")]
    {
        if let Ok(text) = std::fs::read_to_string("/etc/os-release") {
            let mut name = String::new();
            let mut version = String::new();
            let mut pretty = String::new();
            for line in text.lines() {
                let line = line.trim();
                if let Some(rest) = line.strip_prefix("NAME=") {
                    name = unquote(rest);
                } else if let Some(rest) = line.strip_prefix("VERSION_ID=") {
                    version = unquote(rest);
                } else if let Some(rest) = line.strip_prefix("PRETTY_NAME=") {
                    pretty = unquote(rest);
                }
            }
            if !name.is_empty() {
                return (name, version);
            }
            if !pretty.is_empty() {
                return (pretty, version);
            }
        }
    }
    (std::env::consts::OS.to_string(), String::new())
}

/// Strip surrounding double-quotes from a /etc/os-release value.
/// Values may be unquoted, double-quoted, or single-quoted per
/// the spec — we handle the first two; single-quoted is rare in
/// practice.
fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// Result of [`unlock`].
#[derive(Debug, Serialize)]
pub struct UnlockResponse {
    pub unlocked: bool,
    /// Plain text to show the person when the saved pairing could not be
    /// opened.
    pub notice: Option<String>,
}

/// What the person is told when the saved pairing could not be opened for
/// a reason without a plain notice of its own. The detail goes to the log
/// only. Owner-approved text (#97, 2026-11-06): the failure may pass, so
/// quitting and reopening comes first; closing the window only hides the
/// app, hence "Quit" from the tray icon's menu.
const UNLOCK_FAILED_NOTICE: &str = "This desktop couldn't open its saved pairing. Quit VettID Desktop and open it again: right-click its icon in the system tray or menu bar and choose Quit, or sign out of your computer and back in. If it keeps happening, remove this desktop on your phone; then, in Settings, open Danger zone and choose Log out this desktop, and pair again.";

/// Start New Session's notice when no pairing is open (#97): the launch's
/// own unlock notice if it gave one, else [`UNLOCK_FAILED_NOTICE`].
fn unlock_failed_notice(state: &AppState) -> String {
    state.unlock_notice.lock().unwrap_or_else(|e| e.into_inner()).clone().unwrap_or_else(|| UNLOCK_FAILED_NOTICE.to_string())
}

/// Keep (or, with `None`, forget) the unlock notice Start New Session
/// repeats (#97). Forgotten whenever it may no longer be true: each open
/// attempt, a pairing that opens, a log-out, an erase after the vault
/// removed this desktop, a new pairing.
fn set_unlock_notice(state: &AppState, notice: Option<String>) {
    *state.unlock_notice.lock().unwrap_or_else(|e| e.into_inner()) = notice;
}

/// Open the saved pairing: the device state, sealed under a data key that
/// a protector wraps (DPAPI on Windows, the keyring elsewhere; no user
/// input: both are unlocked by the user's OS login session). Then read `vault.status`, and settle an end
/// left unanswered by an earlier run (§6.8). A session counts as live only
/// once this run's own `vault.status` names it.
///
/// A pairing saved by an earlier build (the NATS-era `connection.enc`)
/// can't be used by this one: it is removed, with the plain "can't be
/// opened" notice. Nothing is sent for it (#39's revoke went to a server
/// that no longer exists). A `device.enc` in the earlier format is deleted
/// unread, with its key, and the person told to re-pair (#13).
///
/// A saved pairing that can't be opened is not an error here: the response
/// carries a plain notice for the person, and the detail goes to the log.
#[tauri::command]
pub async fn unlock(state: State<'_, AppState>) -> Result<UnlockResponse, String> {
    // #30: first. A log-out from here on means nothing stays unlocked.
    let since = store::wipe_epoch();
    // #43: likewise an End session, including one under way now.
    let mark = reset_mark(&state);

    // One opening at a time, from this check to the install below (two
    // unlocks can't both open the store), and none while a pairing is under
    // way.
    let Some(_opening) = begin_opening(&state.pairing, &state.opening).await else {
        return Ok(UnlockResponse { unlocked: false, notice: None });
    };
    // Review MEDIUM 3: open already, or a pairing under way: the store is
    // left alone. A busy link (a Start New Session waiting for the phone)
    // is not waited for.
    if let Some(r) = already_open(&state.pairing, &state.link, state.snapshot().link_open).await {
        return Ok(r);
    }
    // #97: a fresh attempt; what an earlier one said is set again below only
    // if this one fails the same way.
    set_unlock_notice(&state, None);

    let config_dir = match store::default_config_dir() {
        Ok(dir) => dir,
        Err(e) => return Ok(UnlockResponse { unlocked: false, notice: Some(e.to_string()) }),
    };

    if let Some(notice) = retire_legacy_pairing(&config_dir) {
        return Ok(UnlockResponse { unlocked: false, notice: Some(notice.to_string()) });
    }
    if !device_store::exists(&config_dir) {
        // Not paired: nothing to open and nothing to say.
        return Ok(UnlockResponse { unlocked: false, notice: None });
    }

    let mut link = match Link::open(DeviceStore::new(&config_dir, since)) {
        Ok(Some(l)) => l,
        // A pairing interrupted before the owner approved it was removed.
        Ok(None) => return Ok(UnlockResponse { unlocked: false, notice: None }),
        Err((e, failure)) => {
            log::warn!("unlock: saved pairing could not be opened: {}", e);
            let notice = failure.as_ref().and_then(link::plain_store_notice).unwrap_or_else(|| UNLOCK_FAILED_NOTICE.to_string());
            // #97: Start New Session repeats it, unless a log-out wiped the
            // pairing meanwhile ("the pairing is kept" would be false) or a
            // new pairing has started (the notice is about the old one).
            // Checked under the notice's lock: log-out and register clear
            // it after they change what's checked, so either order ends
            // right.
            let mut kept = state.unlock_notice.lock().unwrap_or_else(|e| e.into_inner());
            if store::wipe_epoch() == since && state.pairing.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                *kept = Some(notice.clone());
            }
            drop(kept);
            return Ok(UnlockResponse { unlocked: false, notice: Some(notice) });
        }
    };
    if let Err(e) = link.read_status().await {
        // Still unlocked: the session just isn't shown as live.
        log::info!("unlock: vault.status: {}", e);
    }
    if link.unlinked() {
        let notice = erase_unlinked(&state, link).await;
        return Ok(UnlockResponse { unlocked: false, notice: Some(notice) });
    }
    // HIGH 1: a device the vault's mailbox refuses (§8.6) opens, with no
    // session, and says so (Log out is the way on).
    let refused = link.refused();
    if install(&state, link, since, mark).await.is_none() {
        return Ok(UnlockResponse { unlocked: false, notice: None });
    }
    *state.is_registered.write().await = true;
    if refused {
        return Ok(UnlockResponse { unlocked: true, notice: Some(link::REFUSED_NOTICE.to_string()) });
    }

    // Warn (never refuse) when another account can open the saved
    // pairing's folder or file (#24).
    Ok(UnlockResponse { unlocked: true, notice: store::privacy_warning(&config_dir).map(str::to_string) })
}

/// Counts a pairing under way while it lives (see `AppState::pairing`).
struct PairingUnderWay<'a>(&'a std::sync::atomic::AtomicUsize);

impl<'a> PairingUnderWay<'a> {
    /// Counted unconditionally: for tests (`register` uses [`Self::only`]).
    #[cfg(test)]
    fn new(n: &'a std::sync::atomic::AtomicUsize) -> Self {
        n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        PairingUnderWay(n)
    }

    /// Counted only if no other pairing is under way (#79): two at once
    /// would race over the pending state on disk (`pairing::start`
    /// removes an earlier pending one).
    fn only(n: &'a std::sync::atomic::AtomicUsize) -> Option<Self> {
        use std::sync::atomic::Ordering::SeqCst;
        // From 0 to 1 only: a refused call never touches the count.
        n.compare_exchange(0, 1, SeqCst, SeqCst).ok().map(|_| PairingUnderWay(n))
    }
}

impl Drop for PairingUnderWay<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// The right to open the device store (see `AppState::opening`), or
/// `None` while a pairing is under way. The count is read before waiting
/// (a pairing's start isn't waited for) and again after.
async fn begin_opening<'a>(
    pairing: &std::sync::atomic::AtomicUsize,
    opening: &'a tokio::sync::Mutex<()>,
) -> Option<tokio::sync::MutexGuard<'a, ()>> {
    use std::sync::atomic::Ordering::SeqCst;
    if pairing.load(SeqCst) > 0 {
        return None;
    }
    let guard = opening.lock().await;
    (pairing.load(SeqCst) == 0).then_some(guard)
}

/// What unlock answers without touching the device store: the link that
/// is open (a second unlock reopens nothing), or nothing while a pairing
/// is under way (opening the store would remove its pending state). A
/// link someone holds (a Start New Session waits for the phone with it) is
/// not waited for: it is open, as the last snapshot says (`busy_unlocked`).
async fn already_open<T: vettid_device::transport::Transport, C: vettid_device::pairing::Clock>(
    pairing: &std::sync::atomic::AtomicUsize,
    link: &tokio::sync::Mutex<Option<Link<T, C>>>,
    busy_unlocked: bool,
) -> Option<UnlockResponse> {
    if pairing.load(std::sync::atomic::Ordering::SeqCst) > 0 {
        return Some(UnlockResponse { unlocked: false, notice: None });
    }
    let Ok(slot) = link.try_lock() else {
        return Some(UnlockResponse { unlocked: busy_unlocked, notice: None });
    };
    let l = slot.as_ref()?;
    let notice = l.refused().then(|| link::REFUSED_NOTICE.to_string());
    Some(UnlockResponse { unlocked: true, notice })
}

/// Review LOW 11: remove an earlier build's pairing (`connection.enc`)
/// whenever it is there. Then (#13) a `device.enc` in the earlier format,
/// with its key: the person is told to re-pair once both are confirmed
/// gone, or that they couldn't be. Otherwise the person is told only if
/// `connection.enc` was the only pairing (this build's `device.enc`
/// absent): the plain "can't be opened" notice. Next to a device file it
/// goes silently.
fn retire_legacy_pairing(config_dir: &std::path::Path) -> Option<&'static str> {
    retire_legacy_pairing_with(config_dir, device_store::retire_legacy)
}

fn retire_legacy_pairing_with(
    config_dir: &std::path::Path,
    retire_device_file: impl FnOnce(&std::path::Path) -> Result<bool, CredentialError>,
) -> Option<&'static str> {
    let connection = store::exists(config_dir);
    if connection {
        if let Err(e) = store::remove_legacy_pairing(config_dir) {
            log::error!("unlock: an earlier build's pairing couldn't be removed: {}", e);
        }
    }
    match retire_device_file(config_dir) {
        Ok(true) => return Some(store::LEGACY_REMOVED_NOTICE),
        Ok(false) => {}
        Err(e) => {
            log::error!("unlock: {}", e);
            return Some(store::LEGACY_NOT_REMOVED_NOTICE);
        }
    }
    (connection && !device_store::exists(config_dir)).then_some(store::UNREADABLE_NOTICE)
}

/// Session info the frontend uses to decide which view to render
/// (active / expiring-soon / expired).
#[derive(Debug, Serialize)]
pub struct SessionInfoResponse {
    /// The id the vault gave this device.
    pub connection_id: String,
    pub session_id: String,
    /// Unix seconds at which this desktop stops treating the live session
    /// as live, a margin before the vault's `expires_at` (#82). 0 when not
    /// live. Whether it is live now is `is_active` (which also stops once
    /// the vault goes quiet).
    pub expires_at: i64,
    pub seconds_remaining: i64,
    pub is_active: bool,
    /// Why a session this desktop knows of isn't shown as active: the vault
    /// hasn't confirmed it lately (`link::STALE_NOTICE`).
    pub notice: Option<String>,
    /// An End session the vault hasn't answered yet (#80): the UI shows
    /// "Ending your session…" until it is false.
    pub end_pending: bool,
    /// The refresh settled a stored end and the vault confirmed it (#80):
    /// End session's not-confirmed notice may go. Not set by a stored end
    /// merely going away.
    pub end_confirmed: bool,
    /// The refresh settled a stored end without that confirmation: what to
    /// tell the person instead.
    pub end_notice: Option<String>,
    /// The vault's lock and hold as of now (VAULT-LOCK-PLAN §3.1, §3.3):
    /// always [`Snapshot::vault_at`], so a stored Open past its
    /// confirmation is Unknown.
    pub vault: link::VaultView,
    /// The snapshot's publish counter ([`Snapshot::seq`]): the frontend
    /// applies a read only if this isn't older than the last it applied.
    pub seq: u64,
}

/// What the frontend polls (cheap, no network) to drive the expiry UI:
/// from the last snapshot of the link.
#[tauri::command]
pub async fn get_session_info(state: State<'_, AppState>) -> Result<SessionInfoResponse, String> {
    session_info(&state.snapshot(), chrono::Utc::now())
}

fn session_info(snap: &Snapshot, now: chrono::DateTime<chrono::Utc>) -> Result<SessionInfoResponse, String> {
    if !snap.link_open {
        return Err("not unlocked".to_string());
    }
    let active = snap.active_at(now);
    let until = snap.shown_expiry(now);
    Ok(SessionInfoResponse {
        connection_id: snap.device_id.clone().unwrap_or_default(),
        session_id: snap.session_id.clone().filter(|_| active).unwrap_or_default(),
        expires_at: until.map_or(0, |t| t.timestamp()),
        seconds_remaining: until.map_or(0, |t| (t - now).num_seconds().max(0)),
        is_active: active,
        // Not while an end is pending: that one's state is shown (#80, L3).
        // #107: when the relay refused this computer's clock, that's why
        // nothing is confirmed: say so, not "hasn't heard from your vault".
        notice: match snap.clock_refused {
            Some(offset) if !active && !snap.end_pending => Some(link::clock_notice(offset)),
            _ => (snap.stale_at(now) && !active && !snap.end_pending).then(|| link::STALE_NOTICE.to_string()),
        },
        end_pending: snap.end_pending,
        end_confirmed: snap.end_settled == Some(link::EndSettled::Confirmed),
        // With no end pending: what to say unless the end was confirmed. An
        // end that went away without an outcome here (settled inside a
        // request, or by a late answer) was not confirmed (#80).
        end_notice: match &snap.end_settled {
            _ if snap.end_pending => None,
            Some(link::EndSettled::Confirmed) => None,
            Some(link::EndSettled::NotConfirmed(n)) => Some(n.to_string()),
            // No outcome seen here: not confirmed, if there was an end at all.
            None => snap.end_seen.then(|| link::END_UNCONFIRMED_NOTICE.to_string()),
        },
        vault: snap.vault_at(now),
        seq: snap.seq,
    })
}

/// The window gained focus (VAULT-LOCK-PLAN §3.1, "reads `vault.status` on
/// wake and when the window gains focus"): the frontend calls this, then
/// reads `get_session_info`. True if it read the status.
#[tauri::command]
pub async fn check_vault(state: State<'_, AppState>) -> Result<bool, String> {
    Ok(check_vault_now(&state).await)
}

/// [`check_vault`]: a sleep the refresh loop's marks show is taken as a
/// resume ([`Link::focused`]), and if the vault's word is old (or a read
/// is asked for) the link refreshes: `vault.status`, and a stored
/// unanswered end settled (#80), as the background refresh does. Then the
/// snapshot is published. The refresh loop is left as it is: its schedule
/// and its backoff stay (lead review). Not while an operation holds the
/// link (a request waiting for the phone reads the vault itself), nor for
/// a refused device.
pub(crate) async fn check_vault_now(state: &AppState) -> bool {
    let mark = reset_mark(state);
    let Ok(mut slot) = state.link.try_lock() else { return false };
    let Some(link) = slot.as_mut() else { return false };
    if !link.focus_read().await {
        return false;
    }
    if link.unlinked() {
        let link = slot.take().expect("checked above");
        let notice = erase_unlinked(state, link).await;
        state.shared().tell(&notice);
        return true;
    }
    if !overtaken_by_reset(state, mark) {
        state.publish(link.snapshot(chrono::Utc::now()));
    }
    true
}

/// Start New Session: ask the owner's phone for an access session
/// (`device.session.request`, §6.8), tell the frontend the phone is asked
/// (`session:requested`), and wait for the answer until the request
/// lapses. Success only once `vault.status` shows the new session.
///
/// A log-out or End session meanwhile stops the wait (checked
/// between polls).
#[tauri::command]
pub async fn extend_session(app: AppHandle, state: State<'_, AppState>) -> Result<RegisterResponse, String> {
    let requested = || {
        let _ = app.emit(ACCESS_REQUESTED_EVENT, ());
    };
    Ok(extend_with(&state, requested).await)
}

/// [`extend_session`]'s work; `requested` tells the frontend the phone is
/// asked. With no link open (a launch whose unlock failed) nothing is sent,
/// the phone isn't asked and nothing is shown as live, even if the vault's
/// session is (#76).
async fn extend_with(state: &AppState, requested: impl FnOnce()) -> RegisterResponse {
    // #33: never overlaps End session; see AppState::session_op.
    let _session_op = state.session_op.lock().await;
    let mark = reset_mark(state);
    // As in end_access: a refused device's mailbox rechecks aren't waited for.
    // This reads the snapshot before taking the link, so a collect that has
    // just begun (or a refusal found since) can still be waited out once.
    // That doesn't fail open: the link is checked again under its lock, and
    // a refused one sends nothing.
    if state.snapshot().refused {
        state.stop_refresh();
    }
    let mut slot = state.link.lock().await;
    let Some(link) = slot.as_mut() else {
        // #97: what this launch's unlock said, if anything (it may be the
        // specific advice for a failure that passes), else the general one.
        // Nothing is opened here (#94/#76).
        return RegisterResponse::failed(unlock_failed_notice(state));
    };
    let result = link.request_access(requested, || overtaken_by_reset(state, mark)).await;
    if link.unlinked() {
        let link = slot.take().expect("checked above");
        return RegisterResponse::failed(erase_unlinked(state, link).await);
    }
    let now = chrono::Utc::now();
    let snap = link.snapshot(now);
    // A reset that started meanwhile has cleared what the UI shows, and
    // shows its own result.
    let overtaken = overtaken_by_reset(state, mark);
    if !overtaken {
        state.publish(snap.clone());
        if link.keep_refreshing(now) {
            state.start_refresh(false);
        }
    }
    if let Err(f) = &result {
        log::info!("extend_session: no session: {:?}", f);
    }
    let failure = link.store.take_failure();
    extend_response(result, overtaken, &snap, now, failure.as_ref())
}

/// What Start New Session answers. Review LOW 5: a log-out or End
/// session that overtook it (even after the grant) means it is not shown
/// live: the person is told it stopped.
fn extend_response(
    result: Result<(), link::RequestFailed>,
    overtaken: bool,
    snap: &Snapshot,
    now: chrono::DateTime<chrono::Utc>,
    failure: Option<&CredentialError>,
) -> RegisterResponse {
    match result {
        _ if overtaken => RegisterResponse::failed(link::REQUEST_STOPPED_NOTICE),
        Ok(()) if snap.active_at(now) => RegisterResponse::live(snap),
        Ok(()) => RegisterResponse::failed(link::ACCESS_NOT_CONFIRMED_NOTICE),
        // One `now` for both, so the time and the text agree (#83).
        Err(link::RequestFailed::TooSoon(at)) => match link::too_soon_retry_at(at, now) {
            Some(t) => RegisterResponse { retry_at: Some(t.timestamp()), ..RegisterResponse::failed(link::REQUEST_TOO_SOON_NOTICE) },
            None => RegisterResponse::failed(link::REQUEST_TOO_SOON_NOW_NOTICE),
        },
        // #96: the time the current session ends, from the same snapshot
        // and `now` the screen shows, so the notice and the timer agree. No
        // time (the session no longer counts as live): the text alone, which
        // claims nothing about the session.
        Err(link::RequestFailed::DeniedWhileLive) => RegisterResponse {
            continues_until: snap.shown_expiry(now).map(|t| t.timestamp()),
            ..RegisterResponse::failed(link::RENEWAL_DENIED_NOTICE)
        },
        Err(f) => RegisterResponse::failed(link::request_notice(&f, failure)),
    }
}

/// What the person is told when logout could not send the revoke.
const REVOKE_NOT_SENT_NOTICE: &str = "This desktop has been logged out here, but your vault was not told. Remove this desktop on your phone.";
/// ... when the saved pairing could not be deleted from this computer.
const NOT_WIPED_NOTICE: &str = "This desktop's saved pairing could not be deleted from this computer. Remove this desktop on your phone, then try logging out again.";
/// ... when neither happened.
const NOT_WIPED_NOR_SENT_NOTICE: &str = "This desktop's saved pairing could not be deleted from this computer, and your vault was not told. Remove this desktop on your phone, then try logging out again.";

/// NEW TEXT (owner approval needed): logout ended this desktop's access at
/// the vault and the pairing is gone from this computer. The vault still
/// lists the desktop: a desktop can't unlink itself (VAULT-MESSAGING §7.4,
/// `device.unlink` is an app-only type).
const ACCESS_ENDED_LOGOUT_NOTICE: &str = "This desktop has been logged out, and its access to your vault was ended. Your phone still lists this desktop: remove it there.";
/// NEW TEXT (owner approval needed): access ended at the vault, but the
/// saved pairing could not be deleted from this computer.
const ACCESS_ENDED_NOT_WIPED_NOTICE: &str = "This desktop's access to your vault was ended, but its saved pairing could not be deleted from this computer. Remove this desktop on your phone, then try logging out again.";

/// How long logout tries to end this desktop's access at the vault (and
/// to get the link for it) before it wipes anyway: a dead relay can't
/// block a log-out.
const LOGOUT_END_BOUND: std::time::Duration = std::time::Duration::from_secs(10);

/// Result of [`logout`].
#[derive(Debug, Serialize)]
pub struct LogoutResponse {
    /// Whether the vault was told to remove this desktop. Always false: a
    /// desktop can't unlink itself (`device.unlink` is app-only, §7.4).
    pub revoke_sent: bool,
    /// The vault confirmed that this desktop's access ended (an unnamed
    /// `device.session.end`, answered). False on anything less.
    pub access_ended: bool,
    /// The saved pairing is gone from this computer.
    pub local_wiped: bool,
    /// Plain text to show the person when either of the above is false.
    pub notice: Option<String>,
}

/// How logout's end of access came out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LogoutEnd {
    /// No open pairing: nothing to end.
    NoLink,
    /// The vault confirmed the end ([`EndOutcome::Ended`]).
    Ended,
    /// Anything else: unconfirmed, replaced, refused by the ordering rule,
    /// not sent, or not done within [`LOGOUT_END_BOUND`]. Nothing is claimed.
    NotConfirmed,
}

/// `r`: `None` with no link; `Some(None)` if the end didn't finish within
/// the bound; else the end's result.
fn logout_end(r: Option<Option<Result<EndOutcome, vettid_device::access::AccessError>>>) -> LogoutEnd {
    match r {
        None => LogoutEnd::NoLink,
        Some(Some(Ok(EndOutcome::Ended))) => LogoutEnd::Ended,
        Some(_) => LogoutEnd::NotConfirmed,
    }
}

/// Logout's end of access on `l`, cut short at `deadline`.
async fn end_for_logout<T: vettid_device::transport::Transport, C: vettid_device::pairing::Clock>(
    l: &mut Link<T, C>,
    deadline: tokio::time::Instant,
) -> LogoutEnd {
    logout_end(Some(tokio::time::timeout_at(deadline, l.end()).await.ok()))
}

/// What logout tells the person: "access ended" only when the vault
/// confirmed it; otherwise the "your vault was not told" texts.
fn logout_end_notice(end: LogoutEnd, local_wiped: bool) -> Option<&'static str> {
    match (end, local_wiped) {
        (LogoutEnd::Ended, true) => Some(ACCESS_ENDED_LOGOUT_NOTICE),
        (LogoutEnd::Ended, false) => Some(ACCESS_ENDED_NOT_WIPED_NOTICE),
        (_, wiped) => logout_notice(false, wiped),
    }
}

fn logout_notice(revoke_sent: bool, local_wiped: bool) -> Option<&'static str> {
    match (revoke_sent, local_wiped) {
        (true, true) => None,
        (false, true) => Some(REVOKE_NOT_SENT_NOTICE),
        (true, false) => Some(NOT_WIPED_NOTICE),
        (false, false) => Some(NOT_WIPED_NOR_SENT_NOTICE),
    }
}

/// Delete the desktop's config directory and the protectors' keys (and the
/// earlier format's). Returns whether the saved pairing and the keys are
/// gone afterwards: checked, not assumed. With no usable folder only the
/// keys are deleted, and false is returned.
fn wipe_local_pairing(config_dir: Option<&std::path::Path>) -> bool {
    wipe_local_pairing_with(config_dir, crate::credential::store::wipe_for_logout)
}

/// [`wipe_local_pairing`] with the store step passed in, so tests can run
/// it without deleting this machine's real keys.
fn wipe_local_pairing_with(
    config_dir: Option<&std::path::Path>,
    wipe: impl FnOnce(Option<&std::path::Path>) -> Result<(), crate::credential::store::CredentialError>,
) -> bool {
    // SECURITY: never remove a relative path, which would resolve against
    // whatever the current directory is. `default_config_dir` only returns
    // absolute paths; this guards the destructive step on its own.
    let config_dir = config_dir.filter(|dir| {
        let absolute = dir.is_absolute();
        if !absolute {
            log::error!("Refusing to wipe a relative config path on logout");
        }
        absolute
    });

    // Holds the store's write lock across the wipe and the key deletion,
    // so a save running at the same time can't put the pairing back after
    // this reports it gone (#28), and a pairing or Start New Session that
    // started before can't save afterwards (#30). Ok only when the file
    // system confirms it is gone.
    match wipe(config_dir) {
        Ok(()) => true,
        Err(e) => {
            log::error!("Failed to remove the saved pairing on logout: {}", e);
            false
        }
    }
}

/// Log out: end this desktop's access at the vault (an unnamed
/// `device.session.end`, within [`LOGOUT_END_BOUND`]), then wipe the saved
/// pairing (folder and keys) whatever came of that, and drop the
/// link. The vault can't be told to remove the desktop (see
/// [`LogoutResponse::revoke_sent`]); the response says what happened, and
/// says access ended only if the vault confirmed it.
#[tauri::command]
pub async fn logout(state: State<'_, AppState>) -> Result<LogoutResponse, String> {
    // With no known folder there is nothing to wipe, and that can't be
    // confirmed: reported as not done.
    let config_dir = store::default_config_dir();
    if let Err(e) = &config_dir {
        log::warn!("logout: {}", e);
    }
    Ok(log_out(&state, config_dir.as_deref().ok(), wipe_local_pairing, LOGOUT_END_BOUND).await)
}

/// [`logout`]'s work, with the wipe (tests keep the real key) and the
/// bound passed in.
async fn log_out(
    state: &AppState,
    config_dir: Option<&std::path::Path>,
    wipe: impl FnOnce(Option<&std::path::Path>) -> bool,
    bound: std::time::Duration,
) -> LogoutResponse {
    // A Start New Session waiting for the phone stops (it checks this).
    begin_reset(state);
    state.publish(Snapshot::default());
    // Review LOW 6: the refresh first, so the bound goes to
    // the end itself. Stopped mid-operation, it may leave the link's memory
    // part way through a status read (on disk it is as after a crash): the
    // link is used once more, for the end, then dropped.
    state.stop_refresh();
    let deadline = tokio::time::Instant::now() + bound;
    // The link, if it can be had within the bound: a Start New Session may
    // hold it (it stops at its next check).
    let mut guard = tokio::time::timeout_at(deadline, state.link.lock()).await.ok();
    let end = match guard.as_mut() {
        None => {
            log::warn!("logout: the link was busy; access not ended at the vault");
            LogoutEnd::NotConfirmed
        }
        Some(slot) => match slot.as_mut() {
            None => LogoutEnd::NoLink,
            // Unnamed: all of this desktop's access (§6.8). An end cut short
            // by the bound is dropped with the link.
            Some(l) => end_for_logout(l, deadline).await,
        },
    };
    // Whatever the outcome. From here, no save of a pairing or session
    // started before can write (#30).
    let local_wiped = wipe(config_dir);
    let mut slot = match guard {
        Some(g) => g,
        None => state.link.lock().await,
    };
    drop(slot.take());
    drop(slot);
    *state.is_registered.write().await = false;
    set_unlock_notice(state, None);
    state.publish(Snapshot::default());
    finish_reset(state);
    LogoutResponse {
        revoke_sent: false,
        access_ended: end == LogoutEnd::Ended,
        local_wiped,
        notice: logout_end_notice(end, local_wiped).map(str::to_string),
    }
}

/// End this desktop's access session (§6.8, "End access": all of it, no
/// session named), keeping the pairing so Start New Session needs no
/// re-pair. The session stops being shown as live at once. `notice` says
/// when the vault didn't confirm the end, or ended it only in part: the
/// frontend shows "Session ended." only without one.
#[tauri::command]
pub async fn end_session(state: State<'_, AppState>) -> Result<EndSessionResponse, String> {
    Ok(end_access(&state).await)
}

async fn end_access(state: &AppState) -> EndSessionResponse {
    begin_reset(state);
    // A refused device's refresh is only collecting its mailbox, which can
    // hold the link for a poll (25 s): stop it first, so this doesn't wait.
    // It is restarted below if still needed. The snapshot is read before the
    // link is taken, so this can still wait out one collect if the refusal
    // was found after it; that doesn't fail open (the link is checked again
    // under its lock, and a refused one sends nothing).
    if state.snapshot().refused {
        state.stop_refresh();
    }
    // Not live from here on, whatever the vault answers.
    state.publish(state.snapshot().without_session());
    // #80 (review L1): whether this end still waits, read from the link
    // while it is held, not from a later snapshot a reset may have cleared.
    let mut end_pending = false;
    let notice = {
        // #33: no Start New Session runs while this does; one under way
        // stops waiting (the reset above) and releases these.
        let _session_op = state.session_op.lock().await;
        let mut slot = state.link.lock().await;
        // With the link locked, the refresh isn't mid-operation.
        state.stop_refresh();
        // A refresh that finished meanwhile may have shown it again.
        state.publish(state.snapshot().without_session());
        match slot.as_mut() {
            None => {
                // No link: nothing was sent and nothing stays pending (lead
                // review L5); the notice says it wasn't confirmed.
                state.publish(Snapshot { end_pending: false, ..state.snapshot() });
                Some(link::END_UNCONFIRMED_NOTICE.to_string())
            }
            Some(l) => {
                let result = l.end().await;
                let notice = end_notice(&result, l);
                if l.unlinked() {
                    let l = slot.take().expect("checked above");
                    Some(erase_unlinked(state, l).await)
                } else {
                    let now = chrono::Utc::now();
                    let snap = l.snapshot(now);
                    end_pending = snap.end_pending;
                    state.publish(snap);
                    // An end still waiting for its answer is sent again.
                    if l.keep_refreshing(now) {
                        state.start_refresh(false);
                    }
                    notice
                }
            }
        }
    };
    finish_reset(state);
    EndSessionResponse { notice, end_pending }
}

/// What End session tells the person about `result`: nothing for a
/// confirmed end; otherwise why not. A refused device (§8.6) never sends
/// again, so it says so rather than that it keeps trying.
fn end_notice<T: vettid_device::transport::Transport, C: vettid_device::pairing::Clock>(
    result: &Result<EndOutcome, vettid_device::access::AccessError>,
    l: &mut Link<T, C>,
) -> Option<String> {
    match result {
        Ok(EndOutcome::Ended) => None,
        Ok(EndOutcome::Unconfirmed) => Some(link::END_UNCONFIRMED_NOTICE.to_string()),
        Ok(EndOutcome::Replaced) => Some(link::END_REPLACED_NOTICE.to_string()),
        Err(_) if l.refused() => Some(link::REFUSED_NOTICE.to_string()),
        Err(vettid_device::access::AccessError::EndUnconfirmed) => Some(link::END_UNCONFIRMED_NOTICE.to_string()),
        // #107 (review M1): the end is stored and kept being sent, but it
        // can't go through until the clock is right: say that, not "couldn't
        // reach your vault".
        Err(vettid_device::access::AccessError::Session(s)) if s.clock_skew().is_some() => {
            log::warn!("end_session: not confirmed: {}", s);
            Some(link::end_clock_notice(link::clock_offset(s.clock_skew().flatten())))
        }
        Err(e) => {
            log::warn!("end_session: not confirmed: {}", e);
            if l.session.access_end().is_some() {
                Some(link::END_NOT_SENT_NOTICE.to_string())
            } else {
                let failure = l.store.take_failure();
                Some(link::access_notice(e, failure.as_ref()))
            }
        }
    }
}

/// #43: a memory reset is starting; see [`AppState::resets_started`].
/// First, before anything is cleared.
fn begin_reset(state: &AppState) {
    state.resets_started.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

/// #43: a memory reset is done, after everything is cleared.
fn finish_reset(state: &AppState) {
    state.resets_finished.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

/// Where the resets stood when an [`unlock`] started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ResetMark {
    started: u64,
    under_way: bool,
}

/// Read `finished` first, then `started`: a reset that starts between the
/// two reads counts as under way.
fn reset_mark(state: &AppState) -> ResetMark {
    use std::sync::atomic::Ordering::SeqCst;
    let finished = state.resets_finished.load(SeqCst);
    let started = state.resets_started.load(SeqCst);
    ResetMark { started, under_way: started != finished }
}

/// Whether a reset was under way when `mark` was taken, or has started
/// since: then what an unlock set may be what that reset meant to clear.
fn overtaken_by_reset(state: &AppState, mark: ResetMark) -> bool {
    mark.under_way || state.resets_started.load(std::sync::atomic::Ordering::SeqCst) != mark.started
}

/// What [`end_session`] tells the person: `notice` is set when the end
/// isn't confirmed, or this desktop still has access, so the frontend
/// shows it instead of "Session ended." (#26).
#[derive(Debug, Serialize)]
pub struct EndSessionResponse {
    pub notice: Option<String>,
    /// The end is still waiting for the vault (#80): the UI keeps showing it
    /// as pending. False when nothing stays pending (answered, or no link).
    pub end_pending: bool,
}

/// Whether `get_status` reports this desktop as paired: known in memory
/// (`register` confirmed it, or unlock opened it), or else a pairing on
/// disk: this build's or an earlier build's, which unlock removes with a
/// notice. Not while a pairing is under way (`pairings` > 0, #79): its
/// pending `device.enc` is not a pairing until the vault's `device.paired`,
/// and `register` itself reports the outcome.
fn registered(known: bool, pairings: usize, on_disk: impl FnOnce() -> bool) -> bool {
    known || (pairings == 0 && on_disk())
}

/// Get current authentication/registration status.
#[tauri::command]
pub async fn get_status(state: State<'_, AppState>) -> Result<AuthStatus, String> {
    let snap = state.snapshot();
    let config_dir = store::default_config_dir().ok();
    let pairings = state.pairing.load(std::sync::atomic::Ordering::SeqCst);
    let is_registered = registered(
        *state.is_registered.read().await || snap.link_open,
        pairings,
        || config_dir.as_deref().is_some_and(|dir| device_store::exists(dir) || store::exists(dir)),
    );

    let fp = collect_device_fingerprint();

    // With no known folder nothing can have been saved.
    let protection = config_dir
        .as_deref()
        .map_or(device_store::KeyProtection { protector: "none", bound: false }, device_store::stored_key_protection);

    Ok(AuthStatus {
        key_protection: protection.protector.to_string(),
        key_bound: protection.bound,
        key_notices: device_store::protection_notices(protection).into_iter().map(str::to_string).collect(),
        is_registered,
        pairing_under_way: pairings > 0,
        is_unlocked: snap.link_open,
        has_active_session: snap.active_at(chrono::Utc::now()),
        hostname: fp.hostname,
        platform: fp.platform,
        os_name: fp.os_name,
        os_version: fp.os_version,
        binary_fingerprint: fp.binary_fingerprint,
        machine_fingerprint: fp.machine_fingerprint,
        app_version: fp.app_version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logout_notice_never_claims_what_did_not_happen() {
        assert_eq!(logout_notice(true, true), None);
        let not_sent = logout_notice(false, true).unwrap();
        assert!(not_sent.contains("not told"));
        let not_wiped = logout_notice(true, false).unwrap();
        assert!(not_wiped.contains("could not be deleted"));
        let neither = logout_notice(false, false).unwrap();
        assert!(neither.contains("could not be deleted") && neither.contains("not told"));
    }

    /// #17: the fingerprint shown and sent is computed from this
    /// platform's collector, the one `platform_key` uses. On Linux and
    /// Windows the old code used that collector too, so only a macOS run
    /// tells the old and new code apart (see the macOS test below). The
    /// attributes are read once, so a hostname or adapter that changes
    /// between two reads can't make this flake.
    #[test]
    fn displayed_machine_fingerprint_uses_this_platforms_collector() {
        use crate::fingerprint::platform_linux::{compute_machine_fingerprint, FingerprintError, MachineAttributes};
        let attrs = MachineAttributes {
            hostname: "testhost".to_string(),
            machine_id: "4c4c4544003a3610804db7c04f4d3732".to_string(),
            cpu: "Test CPU".to_string(),
            disk_serial: "TEST-SERIAL".to_string(),
            mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
        };
        assert_eq!(fingerprint_hex_of(Ok(attrs.clone())), hex::encode(compute_machine_fingerprint(&attrs)));
        assert_eq!(fingerprint_hex_of(Err(FingerprintError::CollectionFailed("test".into()))), "");
        // Live: a 64-digit hex value, or empty if nothing could be collected.
        let shown = machine_fingerprint_hex();
        assert!(shown.is_empty() || (shown.len() == 64 && shown.bytes().all(|b| b.is_ascii_hexdigit())));
    }

    /// macOS: the displayed fingerprint comes from the macOS collector,
    /// not the Linux one (#17). Ready for a macOS CI job; not run today.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_fingerprint_uses_the_macos_collector() {
        use crate::fingerprint::platform_linux::compute_machine_fingerprint_hex;
        use crate::fingerprint::platform_macos::collect_machine_attributes_macos;
        let attrs = collect_machine_attributes_macos().expect("macOS attributes");
        assert_eq!(machine_fingerprint_hex(), compute_machine_fingerprint_hex(&attrs));
    }

    /// #43, M1: an unlock is overtaken by a reset that started after it
    /// did, and by one already under way when it started, but not by one
    /// that had finished before.
    #[test]
    fn an_unlock_sees_every_reset_it_overlapped() {
        let state = AppState::new();
        let quiet = reset_mark(&state);
        assert!(!overtaken_by_reset(&state, quiet), "no reset");

        begin_reset(&state);
        assert!(overtaken_by_reset(&state, quiet), "a reset started since");
        let during = reset_mark(&state);
        assert!(overtaken_by_reset(&state, during), "a reset under way at the start");
        finish_reset(&state);
        assert!(overtaken_by_reset(&state, during), "still, once it finished");

        let after = reset_mark(&state);
        assert!(!overtaken_by_reset(&state, after), "one that finished before doesn't count");
    }

    /// A refresh task that records being dropped.
    fn tracked_task(state: &AppState) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        struct Held(Arc<AtomicBool>);
        impl Drop for Held {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let held = Held(dropped.clone());
        *state.refresh_task.lock().unwrap() = Some(tokio::spawn(async move {
            let _held = held;
            std::future::pending::<()>().await;
        }));
        dropped
    }

    /// Every session-ending path stops the background refresh: log-out
    /// and End session each end its task and empty the slot, and
    /// nothing is shown as live or unlocked afterwards.
    #[tokio::test]
    async fn logout_and_end_session_stop_the_refresh() {
        use std::sync::atomic::Ordering;
        for which in ["logout", "end session"] {
            let state = AppState::new();
            let live = Snapshot {
                link_open: true,
                session_id: Some("s".into()),
                live_until: Some(chrono::Utc::now() + chrono::TimeDelta::hours(1)),
                vault: link::VaultView::open(chrono::Utc::now() + chrono::TimeDelta::hours(1)),
                ..Default::default()
            };
            state.publish(live);
            let dropped = tracked_task(&state);
            match which {
                "logout" => {
                    let r = log_out(&state, None, |_| false, LOGOUT_END_BOUND).await;
                    assert!(!r.revoke_sent && !r.local_wiped);
                    assert_eq!(r.notice.as_deref(), Some(NOT_WIPED_NOR_SENT_NOTICE));
                }
                _ => {
                    // No link: the end can't be confirmed, and says so.
                    let r = end_access(&state).await;
                    assert_eq!(r.notice.as_deref(), Some(link::END_UNCONFIRMED_NOTICE));
                }
            }
            tokio::task::yield_now().await;
            assert!(dropped.load(Ordering::SeqCst), "{which}: the refresh task ended");
            assert!(state.refresh_task.lock().unwrap().is_none(), "{which}: the slot is empty");
            assert!(!state.snapshot().active_at(chrono::Utc::now()), "{which}: nothing live");
            assert!(state.link.lock().await.is_none());
        }
    }

    /// Log-out always says the vault wasn't told, and says the pairing is
    /// gone only when the wipe confirms it.
    #[tokio::test]
    async fn logout_reports_what_happened() {
        let state = AppState::new();
        *state.is_registered.write().await = true;
        let r = log_out(&state, None, |_| true, LOGOUT_END_BOUND).await;
        assert!(!r.revoke_sent);
        assert!(!r.access_ended, "no link: nothing ended");
        assert!(r.local_wiped);
        assert_eq!(r.notice.as_deref(), Some(REVOKE_NOT_SENT_NOTICE));
        assert!(!*state.is_registered.read().await);
        // Cleared (the publish counter aside, which every publish moves).
        assert_eq!(Snapshot { seq: 0, ..state.snapshot() }, Snapshot::default());
    }

    /// Logout's end of access: "ended" only for the vault's confirmed end;
    /// every other outcome, and no link, gets the "not told" texts.
    #[test]
    fn logout_says_access_ended_only_when_the_vault_confirmed_it() {
        use vettid_device::access::AccessError;
        use vettid_device::session::SessionError;
        assert_eq!(logout_end(None), LogoutEnd::NoLink);
        assert_eq!(logout_end(Some(Some(Ok(EndOutcome::Ended)))), LogoutEnd::Ended);
        for not in [
            Some(Ok(EndOutcome::Unconfirmed)),
            Some(Ok(EndOutcome::Replaced)),
            Some(Err(AccessError::EndUnconfirmed)),
            Some(Err(AccessError::Session(SessionError::TimedOut))),
            Some(Err(AccessError::Session(SessionError::Refused))),
            // Not done within the bound.
            None,
        ] {
            assert_eq!(logout_end(Some(not.clone())), LogoutEnd::NotConfirmed, "{not:?}");
        }
        assert_eq!(logout_end_notice(LogoutEnd::Ended, true), Some(ACCESS_ENDED_LOGOUT_NOTICE));
        assert_eq!(logout_end_notice(LogoutEnd::Ended, false), Some(ACCESS_ENDED_NOT_WIPED_NOTICE));
        for end in [LogoutEnd::NotConfirmed, LogoutEnd::NoLink] {
            assert_eq!(logout_end_notice(end, true), Some(REVOKE_NOT_SENT_NOTICE));
            assert_eq!(logout_end_notice(end, false), Some(NOT_WIPED_NOR_SENT_NOTICE));
        }
        assert!(ACCESS_ENDED_LOGOUT_NOTICE.contains("remove it there"));
    }

    /// A busy link (a refresh or Start New Session stuck on a dead relay)
    /// doesn't hold up the wipe beyond the bound, and nothing is claimed.
    #[tokio::test]
    async fn a_busy_link_doesnt_block_the_wipe() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        let state = Arc::new(AppState::new());
        let held = state.link.clone().lock_owned().await;
        let wiped = Arc::new(AtomicBool::new(false));
        let run = {
            let (state, wiped) = (state.clone(), wiped.clone());
            tokio::spawn(async move {
                log_out(&state, None, move |_| {
                    wiped.store(true, Ordering::SeqCst);
                    true
                }, std::time::Duration::from_millis(50))
                .await
            })
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !wiped.load(Ordering::SeqCst) {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("wiped while the link was still busy");
        drop(held);
        let r = run.await.unwrap();
        assert!(!r.access_ended && !r.revoke_sent && r.local_wiped);
        assert_eq!(r.notice.as_deref(), Some(REVOKE_NOT_SENT_NOTICE));
        assert!(state.link.lock().await.is_none());
    }

    /// MEDIUM 3: while a pairing is under way unlock opens nothing; an open
    /// link answers for itself (refused: with its notice).
    #[tokio::test]
    async fn unlock_leaves_a_pairing_under_way_and_an_open_link_alone() {
        use crate::link::fake::FakeVault;
        use std::sync::atomic::AtomicUsize;
        let pairing = AtomicUsize::new(0);
        let none: tokio::sync::Mutex<Option<Link>> = tokio::sync::Mutex::new(None);
        assert!(already_open(&pairing, &none, false).await.is_none(), "nothing open: unlock goes on");
        {
            let _p = PairingUnderWay::new(&pairing);
            let r = already_open(&pairing, &none, false).await.expect("left alone");
            assert!(!r.unlocked && r.notice.is_none());
        }
        assert!(already_open(&pairing, &none, false).await.is_none(), "the count drops with the pairing");

        let dir = tempfile::tempdir().unwrap();
        let (vault, l) = FakeVault::paired(dir.path());
        let open = tokio::sync::Mutex::new(Some(l));
        let r = already_open(&pairing, &open, false).await.expect("open already");
        assert!(r.unlocked && r.notice.is_none());
        vault.revoke(false);
        let _ = open.lock().await.as_mut().unwrap().read_status().await;
        let r = already_open(&pairing, &open, false).await.unwrap();
        assert_eq!(r.notice.as_deref(), Some(link::REFUSED_NOTICE));
    }

    /// Re-check 1: a link held for the whole phone wait (Start New
    /// Session) isn't waited for: it counts as open, as the snapshot says.
    #[tokio::test]
    async fn unlock_doesnt_wait_for_a_busy_link() {
        use std::sync::atomic::AtomicUsize;
        let pairing = AtomicUsize::new(0);
        let link: tokio::sync::Mutex<Option<Link>> = tokio::sync::Mutex::new(None);
        let _held = link.lock().await;
        let r = tokio::time::timeout(std::time::Duration::from_secs(1), already_open(&pairing, &link, true))
            .await
            .expect("not blocked by the held link")
            .expect("answered");
        assert!(r.unlocked && r.notice.is_none());
        let r = already_open(&pairing, &link, false).await.unwrap();
        assert!(!r.unlocked, "as the snapshot says");
    }

    /// Re-check 2: one opening at a time. A second unlock waits for the
    /// first; one that waited out a pairing's start (which counted itself
    /// first) leaves the store alone; with a pairing counted it doesn't
    /// wait at all.
    #[tokio::test]
    async fn openings_dont_overlap_and_yield_to_a_pairing() {
        use std::sync::atomic::AtomicUsize;
        use std::sync::Arc;
        let pairing = Arc::new(AtomicUsize::new(0));
        let opening = Arc::new(tokio::sync::Mutex::new(()));
        let first = begin_opening(&pairing, &opening).await.expect("free");
        let second = {
            let (p, o) = (pairing.clone(), opening.clone());
            tokio::spawn(async move { begin_opening(&p, &o).await.is_some() })
        };
        tokio::task::yield_now().await;
        assert!(!second.is_finished(), "waits for the first");
        // A pairing counts itself, then waits for the opening (as register).
        let counted = PairingUnderWay::new(&pairing);
        drop(first);
        assert!(!second.await.unwrap(), "after the wait, the pairing is seen");
        // With a pairing counted, no wait at all, even if the opening is held.
        let _held = opening.lock().await;
        let r = tokio::time::timeout(std::time::Duration::from_secs(1), begin_opening(&pairing, &opening)).await;
        assert!(r.expect("not waited").is_none());
        drop(counted);
    }

    /// #79: a second pairing is refused while one is under way, and the
    /// first's count is untouched by the refusal.
    #[test]
    fn only_one_pairing_at_a_time() {
        let n = std::sync::atomic::AtomicUsize::new(0);
        let first = PairingUnderWay::only(&n).expect("the first is counted");
        assert!(PairingUnderWay::only(&n).is_none(), "a second is refused");
        assert_eq!(n.load(std::sync::atomic::Ordering::SeqCst), 1, "the refusal left no count");
        drop(first);
        assert_eq!(n.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(PairingUnderWay::only(&n).is_some(), "after it, a new one may start");
    }

    /// #79: while a pairing is under way, its pending `device.enc` doesn't
    /// count as a pairing (the disk isn't even read); a confirmed one
    /// always does.
    #[test]
    fn a_pairing_under_way_is_not_reported_as_paired() {
        let read = std::cell::Cell::new(false);
        let on_disk = || {
            read.set(true);
            true
        };
        assert!(!registered(false, 1, on_disk), "pending, not paired");
        assert!(!read.get(), "the disk isn't read while pairing");
        assert!(!registered(false, 2, || true));
        assert!(registered(false, 0, || true), "a saved pairing, no pairing under way");
        assert!(!registered(false, 0, || false));
        assert!(registered(true, 1, || false), "register confirmed it, still finishing");
    }

    /// LOW 11: an earlier build's pairing goes whenever it is there; the
    /// notice only when it was the only one.
    #[test]
    fn the_legacy_pairing_goes_and_says_so_only_when_alone() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        assert_eq!(retire_legacy_pairing(&dir), None);
        store::tests::legacy_pairing_for_tests(&dir);
        assert_eq!(retire_legacy_pairing(&dir), Some(store::UNREADABLE_NOTICE));
        assert!(!store::exists(&dir));
        store::tests::legacy_pairing_for_tests(&dir);
        crate::credential::device_store::tests::store_for_tests(&dir).save_raw_for_tests();
        assert_eq!(retire_legacy_pairing(&dir), None, "silent next to a device file");
        assert!(!store::exists(&dir));
        assert!(device_store::exists(&dir));
    }

    /// #13: an earlier format's device file is reported as removed only
    /// once that is confirmed; otherwise as not removed. (The removal
    /// itself is `device_store`'s, tested there; here it is the seam.)
    #[test]
    fn the_earlier_device_file_is_reported_as_retired_only_when_confirmed() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("vettid-desktop");
        assert_eq!(retire_legacy_pairing_with(&dir, |_| Ok(true)), Some(store::LEGACY_REMOVED_NOTICE));
        assert_eq!(retire_legacy_pairing_with(&dir, |_| Err(CredentialError::LegacyNotRemoved)), Some(store::LEGACY_NOT_REMOVED_NOTICE));
        assert_eq!(retire_legacy_pairing_with(&dir, |_| Ok(false)), None);
        store::tests::legacy_pairing_for_tests(&dir);
        assert_eq!(retire_legacy_pairing_with(&dir, |_| Ok(true)), Some(store::LEGACY_REMOVED_NOTICE));
        assert!(!store::exists(&dir), "connection.enc goes too");
    }

    /// LOW 5: Start New Session overtaken by a reset says it stopped, even
    /// with a live grant.
    #[test]
    fn an_overtaken_start_new_session_isnt_shown_live() {
        let now = chrono::Utc::now();
        let live = Snapshot {
            link_open: true,
            session_id: Some("s".into()),
            live_until: Some(now + chrono::TimeDelta::minutes(5)),
            vault: link::VaultView::open(now + chrono::TimeDelta::minutes(5)),
            ..Default::default()
        };
        let r = extend_response(Ok(()), true, &live, now, None);
        assert!(!r.success);
        assert_eq!(r.error.as_deref(), Some(link::REQUEST_STOPPED_NOTICE));
        assert!(extend_response(Ok(()), false, &live, now, None).success);
        let r = extend_response(Ok(()), false, &Snapshot::default(), now, None);
        assert_eq!(r.error.as_deref(), Some(link::ACCESS_NOT_CONFIRMED_NOTICE));
    }

    /// #96: the phone declined a new session while the current one is
    /// live. Not shown as a success (no new session), and the notice names
    /// the time the timer shows; with no live session it names none.
    #[test]
    fn a_declined_new_session_names_when_the_current_one_ends() {
        let now = chrono::Utc::now();
        let until = now + chrono::TimeDelta::minutes(5);
        let live = Snapshot {
            link_open: true,
            session_id: Some("s".into()),
            live_until: Some(until),
            vault: link::VaultView::open(until),
            ..Default::default()
        };
        let r = extend_response(Err(link::RequestFailed::DeniedWhileLive), false, &live, now, None);
        assert!(!r.success);
        assert!(r.session_id.is_none() && r.expires_at.is_none());
        assert_eq!(r.error.as_deref(), Some(link::RENEWAL_DENIED_NOTICE));
        assert_eq!(r.continues_until, Some(until.timestamp()));
        // The vault's own end, when known, as the timer shows it.
        let ends = now + chrono::TimeDelta::minutes(3);
        let known = Snapshot { ends_at: Some(ends), ..live.clone() };
        let r = extend_response(Err(link::RequestFailed::DeniedWhileLive), false, &known, now, None);
        assert_eq!(r.continues_until, Some(ends.timestamp()));
        // No longer live here (ended a moment ago, or never): no time, and a
        // text that claims nothing about a session.
        let lapsed = Snapshot { live_until: Some(now - chrono::TimeDelta::seconds(1)), ..live.clone() };
        for snap in [&lapsed, &Snapshot::default()] {
            let r = extend_response(Err(link::RequestFailed::DeniedWhileLive), false, snap, now, None);
            assert_eq!((r.error.as_deref(), r.continues_until), (Some(link::RENEWAL_DENIED_NOTICE), None));
        }
        assert!(!link::RENEWAL_DENIED_NOTICE.contains("continues"));
        // A plain decline, and an overtaken one, name no time.
        assert_eq!(extend_response(Err(link::RequestFailed::Denied), false, &live, now, None).continues_until, None);
        assert_eq!(extend_response(Err(link::RequestFailed::DeniedWhileLive), true, &live, now, None).continues_until, None);
    }

    /// #76: Start New Session with no link open (a launch whose unlock
    /// failed) asks nothing of the phone, opens nothing and shows nothing
    /// as live, whatever the vault's session is: it doesn't reopen the
    /// saved pairing (that would show a still-live session with no phone).
    /// Limit: this drives the no-link branch with no vault and no saved
    /// pairing. A change that makes Start New Session open the saved
    /// pairing would need its own test against a paired store with a live
    /// session; this one might still pass.
    #[tokio::test]
    async fn start_new_session_without_a_link_shows_nothing() {
        let state = AppState::new();
        let mut asked = false;
        let r = extend_with(&state, || asked = true).await;
        assert!(!asked, "the phone isn't asked");
        assert!(!r.success);
        assert!(r.session_id.is_none() && r.expires_at.is_none());
        assert_eq!(r.error.as_deref(), Some(UNLOCK_FAILED_NOTICE));
        assert!(state.link.lock().await.is_none(), "nothing was opened");
        let snap = state.snapshot();
        assert!(!snap.link_open && !snap.active_at(chrono::Utc::now()));
        assert!(session_info(&snap, chrono::Utc::now()).is_err(), "nothing to show");
    }

    /// #97: with no link open, Start New Session repeats what this launch's
    /// unlock said (it may be the specific advice for a failure that
    /// passes), and still asks and opens nothing. The general notice says
    /// to quit and reopen first.
    #[tokio::test]
    async fn start_new_session_repeats_the_launchs_unlock_notice() {
        let state = AppState::new();
        let specific = "This desktop couldn't open its saved pairing with the keyring just now.";
        *state.unlock_notice.lock().unwrap() = Some(specific.to_string());
        let mut asked = false;
        let r = extend_with(&state, || asked = true).await;
        assert!(!asked && !r.success);
        assert_eq!(r.error.as_deref(), Some(specific));
        assert!(state.link.lock().await.is_none(), "nothing was opened");
        *state.unlock_notice.lock().unwrap() = None;
        assert_eq!(unlock_failed_notice(&state), UNLOCK_FAILED_NOTICE);
        assert!(UNLOCK_FAILED_NOTICE.contains("Quit VettID Desktop") && UNLOCK_FAILED_NOTICE.contains("open it again"));
        // A log-out forgets it, whether or not its wipe is confirmed: the
        // pairing it spoke of may be gone.
        for wiped in [true, false] {
            set_unlock_notice(&state, Some(specific.to_string()));
            *state.is_registered.write().await = true;
            log_out(&state, None, move |_| wiped, LOGOUT_END_BOUND).await;
            assert_eq!(unlock_failed_notice(&state), UNLOCK_FAILED_NOTICE, "wiped {wiped}");
        }
    }

    /// LOW 6: logout stops the refresh before it waits for the link, so a
    /// refresh holding the link doesn't eat the bound.
    #[tokio::test]
    async fn logout_stops_the_refresh_before_waiting_for_the_link() {
        let state = AppState::new();
        let link = state.link.clone();
        let (held_tx, held_rx) = tokio::sync::oneshot::channel();
        *state.refresh_task.lock().unwrap() = Some(tokio::spawn(async move {
            let _slot = link.lock().await;
            let _ = held_tx.send(());
            std::future::pending::<()>().await;
        }));
        held_rx.await.unwrap();
        let started = std::time::Instant::now();
        let r = log_out(&state, None, |_| true, std::time::Duration::from_secs(5)).await;
        assert!(started.elapsed() < std::time::Duration::from_secs(2), "the bound wasn't spent waiting");
        assert!(r.local_wiped);
    }

    /// Item 1: End session on a refused device says it is refused, not that
    /// it keeps trying. Item 4: the other outcomes, from the fake vault.
    #[tokio::test]
    async fn end_session_notices_follow_the_outcome() {
        use crate::link::fake::{EndMode, FakeVault};
        let live = |v: &FakeVault| v.set_session(Some(("s-1", chrono::Utc::now() + chrono::TimeDelta::hours(1))));

        let dir = tempfile::tempdir().unwrap();
        let (vault, mut l) = FakeVault::paired(dir.path());
        live(&vault);
        l.read_status().await.unwrap();
        vault.revoke(false);
        let r = l.end().await;
        assert!(r.is_err());
        assert_eq!(end_notice(&r, &mut l).as_deref(), Some(link::REFUSED_NOTICE));

        let dir = tempfile::tempdir().unwrap();
        let (vault, mut l) = FakeVault::paired(dir.path());
        live(&vault);
        l.read_status().await.unwrap();
        let r = l.end().await;
        assert_eq!(end_notice(&r, &mut l), None, "Ended: the frontend says Session ended.");

        let dir = tempfile::tempdir().unwrap();
        let (vault, mut l) = FakeVault::paired(dir.path());
        live(&vault);
        l.read_status().await.unwrap();
        vault.end_mode(EndMode::Replace("s-2".into(), chrono::Utc::now() + chrono::TimeDelta::hours(1)));
        let r = l.end().await;
        assert_eq!(end_notice(&r, &mut l).as_deref(), Some(link::END_REPLACED_NOTICE));

        let dir = tempfile::tempdir().unwrap();
        let (vault, mut l) = FakeVault::paired(dir.path());
        live(&vault);
        l.read_status().await.unwrap();
        vault.end_mode(EndMode::Silent);
        vault.absent_session_member();
        let r = l.end().await;
        assert_eq!(end_notice(&r, &mut l).as_deref(), Some(link::END_UNCONFIRMED_NOTICE));
    }

    /// Item 4: logout's end, against the fake vault: Ended when it answers,
    /// NotConfirmed when it doesn't (within the bound).
    #[tokio::test]
    async fn logout_ends_access_when_the_vault_answers() {
        use crate::link::fake::{EndMode, FakeVault};
        let deadline = || tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        let dir = tempfile::tempdir().unwrap();
        let (vault, mut l) = FakeVault::paired(dir.path());
        vault.set_session(Some(("s-1", chrono::Utc::now() + chrono::TimeDelta::hours(1))));
        l.read_status().await.unwrap();
        assert_eq!(end_for_logout(&mut l, deadline()).await, LogoutEnd::Ended);
        assert_eq!(logout_end_notice(LogoutEnd::Ended, true), Some(ACCESS_ENDED_LOGOUT_NOTICE));

        let dir = tempfile::tempdir().unwrap();
        let (vault, mut l) = FakeVault::paired(dir.path());
        vault.set_session(Some(("s-1", chrono::Utc::now() + chrono::TimeDelta::hours(1))));
        l.read_status().await.unwrap();
        vault.end_mode(EndMode::Silent);
        let short = tokio::time::Instant::now() + std::time::Duration::from_millis(300);
        assert_eq!(end_for_logout(&mut l, short).await, LogoutEnd::NotConfirmed, "cut short by the bound");
    }

    /// #43: every memory reset is counted as started and finished, so an
    /// unlock that one overtook can tell.
    #[tokio::test]
    async fn every_reset_is_counted() {
        use std::sync::atomic::Ordering::SeqCst;
        let state = AppState::new();
        log_out(&state, None, |_| false, LOGOUT_END_BOUND).await;
        end_access(&state).await;
        assert_eq!(state.resets_started.load(SeqCst), 2);
        assert_eq!(state.resets_finished.load(SeqCst), 2);
    }

    /// #107 (review M2): a pairing the relay refused for this computer's
    /// clock says so, also when its keys couldn't be removed; other relay
    /// failures keep the general notice.
    #[test]
    fn a_pairing_refused_for_the_clock_names_it() {
        use vettid_relay::client::RelayError;
        let skew = RelayError::ClockSkew { server_date: None };
        assert_eq!(pair_notice(&PairError::Relay(skew.clone()), None), link::pair_clock_notice(None));
        assert_eq!(pair_notice(&PairError::NotSent(skew.clone()), None), link::pair_clock_notice(None));
        assert_eq!(pair_notice(&PairError::NotCleared(Box::new(PairError::Relay(skew))), None), link::pair_clock_notice(None));
        assert_eq!(pair_notice(&PairError::Relay(RelayError::Connect), None), link::PAIR_FAILED_NOTICE);
        assert!(link::pair_clock_notice(None).starts_with("Not paired. This computer's clock"));
        assert!(link::end_clock_notice(Some(600)).starts_with("This computer's clock is off by about 10 minutes."));
        assert!(link::end_clock_notice(None).contains("may still be open"));
    }

    /// #107: while the relay refuses this computer's clock, the session
    /// info's notice says so (in place of "hasn't heard from your vault"),
    /// unless a session is live or an end is pending.
    #[test]
    fn session_info_names_a_refused_clock() {
        let now = chrono::Utc::now();
        let refused = Snapshot { link_open: true, clock_refused: Some(Some(300)), stale: true, ..Default::default() };
        assert_eq!(session_info(&refused, now).unwrap().notice, Some(link::clock_notice(Some(300))));
        let unknown = Snapshot { clock_refused: Some(None), ..refused.clone() };
        assert_eq!(session_info(&unknown, now).unwrap().notice, Some(link::clock_notice(None)));
        let ending = Snapshot { end_pending: true, ..refused.clone() };
        assert_eq!(session_info(&ending, now).unwrap().notice, None);
        let fine = Snapshot { clock_refused: None, ..refused };
        assert_ne!(session_info(&fine, now).unwrap().notice, Some(link::clock_notice(Some(300))));
    }

    /// The session info comes from the snapshot: live up to `live_until`
    /// only, and "not unlocked" without a link.
    #[test]
    fn session_info_is_live_only_until_live_until() {
        let now = chrono::Utc::now();
        assert!(session_info(&Snapshot::default(), now).is_err());
        let until = now + chrono::TimeDelta::seconds(90);
        let snap = Snapshot {
            link_open: true,
            device_id: Some("dev".into()),
            session_id: Some("s1".into()),
            expires_at: Some(until + chrono::TimeDelta::seconds(60)),
            ends_at: Some(until + chrono::TimeDelta::seconds(30)),
            live_until: Some(until),
            reachable: true,
            refused: false,
            stale: false,
            clock_refused: None,
            end_pending: false,
            end_settled: None,
            end_seen: false,
            // Confirmed a minute past the session's cap.
            vault: link::VaultView::open(until + chrono::TimeDelta::seconds(60)),
            seq: 0,
        };
        let info = session_info(&snap, now).unwrap();
        assert!(info.is_active);
        assert!(!info.end_pending);
        // #80: an end under way is passed on, with no session live.
        let ending = session_info(&snap.without_session(), now).unwrap();
        assert!(ending.end_pending && !ending.is_active);
        assert!(!ending.end_confirmed && ending.end_notice.is_none(), "nothing settled yet");
        // No end at all: nothing to say.
        assert_eq!(session_info(&snap, now).unwrap().end_notice, None);
        // Not pending, no outcome, after an end: not confirmed.
        let gone = session_info(&Snapshot { end_seen: true, ..snap.clone() }, now).unwrap();
        assert!(!gone.end_confirmed);
        assert_eq!(gone.end_notice.as_deref(), Some(link::END_UNCONFIRMED_NOTICE));
        let confirmed = Snapshot { end_settled: Some(link::EndSettled::Confirmed), ..snap.clone() };
        let info = session_info(&confirmed, now).unwrap();
        assert!(info.end_confirmed && info.end_notice.is_none());
        let not = Snapshot { end_settled: Some(link::EndSettled::NotConfirmed(link::END_UNCONFIRMED_NOTICE)), ..snap.clone() };
        let info = session_info(&not, now).unwrap();
        assert!(!info.end_confirmed);
        assert_eq!(info.end_notice.as_deref(), Some(link::END_UNCONFIRMED_NOTICE));
        // #82: the desktop's own end (ends_at, 30 s past live_until here), not live_until.
        assert_eq!(info.expires_at, (until + chrono::TimeDelta::seconds(30)).timestamp());
        assert_eq!(info.seconds_remaining, 120);
        assert_eq!(info.session_id, "s1");
        let later = session_info(&snap, until + chrono::TimeDelta::seconds(1)).unwrap();
        assert!(!later.is_active);
        assert_eq!((later.expires_at, later.seconds_remaining, later.session_id.as_str()), (0, 0, ""));
        assert_eq!(later.notice, None);
        // Read after the vault view's own confirmation ran out (the stored
        // snapshot, after a suspend): nothing live, and "not confirmed".
        let late = session_info(&snap, until + chrono::TimeDelta::seconds(61)).unwrap();
        assert!(!late.is_active);
        assert_eq!(late.notice.as_deref(), Some(link::STALE_NOTICE));
        let stale = Snapshot { live_until: None, stale: true, ..snap.clone() };
        let info = session_info(&stale, now).unwrap();
        assert!(!info.is_active);
        assert_eq!(info.notice.as_deref(), Some(link::STALE_NOTICE));
        // #77: the vault is passed on as of now, never the stored state.
        assert_eq!(session_info(&snap, now).unwrap().vault.state, link::VaultShown::Open);
        assert_eq!(session_info(&snap, until + chrono::TimeDelta::seconds(61)).unwrap().vault.state, link::VaultShown::Unknown);
        let held = Snapshot { vault: link::VaultView { state: link::VaultShown::Held, ..Default::default() }, ..snap };
        assert_eq!(session_info(&held, now).unwrap().vault.state, link::VaultShown::Held);
    }

    /// #77: a focus with no link open reads nothing, and says so.
    #[tokio::test]
    async fn check_vault_without_a_link_reads_nothing() {
        let state = AppState::new();
        assert!(!check_vault_now(&state).await);
        // While an operation holds the link, it isn't waited for.
        let held = state.link.clone();
        let _guard = held.lock().await;
        assert!(!check_vault_now(&state).await);
    }

    /// A failed pairing claims nothing: the engine's own texts for a
    /// rejection or a timeout, and plain ones otherwise.
    #[test]
    fn pairing_failures_have_plain_notices() {
        use vettid_device::store::StoreError;
        assert_eq!(pair_notice(&PairError::Rejected, None), vettid_device::display::REJECTED_ON_PHONE);
        assert_eq!(pair_notice(&PairError::TimedOut, None), vettid_device::display::NOT_CONFIRMED);
        assert_eq!(pair_notice(&PairError::Expired, None), link::PAIR_CODE_NOTICE);
        assert_eq!(pair_notice(&PairError::AlreadyPaired, None), link::PAIR_ALREADY_NOTICE);
        assert_eq!(pair_notice(&PairError::BadAnswer, None), link::PAIR_FAILED_NOTICE);
        let store = PairError::Store(StoreError::Io);
        assert_eq!(pair_notice(&store, Some(&CredentialError::NoProtector)), store::NO_PROTECTOR_NOTICE);
        let failing = CredentialError::NotProtected { by: "Windows data protection" };
        assert_eq!(pair_notice(&store, Some(&failing)), failing.to_string());
        assert!(failing.to_string().contains("Windows data protection"));
        assert_eq!(pair_notice(&store, Some(&CredentialError::LoggedOutMeanwhile)), store::LOGGED_OUT_MEANWHILE_NOTICE);
        assert_eq!(pair_notice(&store, None), link::PAIR_FAILED_NOTICE);
        assert_eq!(pair_notice(&PairError::NotCleared(Box::new(PairError::Rejected)), None), vettid_device::display::REJECTED_ON_PHONE);
    }

    /// The store step of log-out, without deleting the real keys.
    fn wipe_only(dir: Option<&std::path::Path>) -> Result<(), crate::credential::store::CredentialError> {
        match dir {
            Some(dir) => crate::credential::store::wipe(dir),
            None => Err(crate::credential::store::CredentialError::NoConfigDir),
        }
    }

    fn wipe_keeping_the_key(dir: &std::path::Path) -> bool {
        wipe_local_pairing_with(Some(dir), wipe_only)
    }

    /// With no folder, the store step still runs (it deletes the key), and
    /// the pairing isn't reported removed.
    #[test]
    fn wipe_local_pairing_with_no_folder_still_runs_the_store_step() {
        let mut ran = false;
        assert!(!wipe_local_pairing_with(None, |dir| {
            ran = true;
            wipe_only(dir)
        }));
        assert!(ran);
    }

    /// A relative path is passed on as no folder: the key is still deleted
    /// but nothing is removed.
    #[test]
    fn wipe_local_pairing_passes_a_relative_path_as_no_folder() {
        let relative = std::path::Path::new("vettid-desktop-relative-wipe-test-does-not-exist");
        let mut seen = Some(relative.to_path_buf());
        assert!(!wipe_local_pairing_with(Some(relative), |dir| {
            seen = dir.map(|d| d.to_path_buf());
            wipe_only(dir)
        }));
        assert_eq!(seen, None);
    }

    #[test]
    fn wipe_local_pairing_removes_the_directory() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join("vettid-desktop");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(config_dir.join("connection.enc"), b"{}").unwrap();
        assert!(wipe_keeping_the_key(&config_dir));
        assert!(!config_dir.exists());
    }

    /// A relative path is never removed, and is not reported as wiped.
    /// Uses a name that does not exist, so nothing in the current
    /// directory is at risk if the guard were missing.
    #[test]
    fn wipe_local_pairing_refuses_a_relative_path() {
        let relative = std::path::Path::new("vettid-desktop-relative-wipe-test-does-not-exist");
        assert!(!wipe_keeping_the_key(relative));
    }

    #[test]
    fn wipe_local_pairing_with_nothing_there_is_wiped() {
        let dir = tempfile::tempdir().unwrap();
        assert!(wipe_keeping_the_key(&dir.path().join("absent")));
    }

    /// A pairing that can't be deleted is reported, not assumed gone. On
    /// unix the directory is made read-only, so its entries can't be
    /// removed (root ignores that, and then the test has nothing to check).
    #[cfg(unix)]
    #[test]
    fn wipe_local_pairing_reports_a_pairing_that_survives() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join("vettid-desktop");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(config_dir.join("connection.enc"), b"{}").unwrap();
        std::fs::set_permissions(&config_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        let ignores_permissions = std::fs::write(config_dir.join("probe"), b"").is_ok();
        let wiped = wipe_keeping_the_key(&config_dir);
        std::fs::set_permissions(&config_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        if ignores_permissions {
            return;
        }
        assert!(!wiped, "a pairing still on disk must not be reported as wiped");
        assert!(config_dir.join("connection.enc").exists());
    }

    /// The same on Windows: the file is held open without delete sharing,
    /// so it can't be removed while the wipe runs.
    #[cfg(windows)]
    #[test]
    fn wipe_local_pairing_reports_a_pairing_that_survives() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join("vettid-desktop");
        std::fs::create_dir_all(&config_dir).unwrap();
        let path = config_dir.join("connection.enc");
        std::fs::write(&path, b"{}").unwrap();
        let held = std::fs::OpenOptions::new().read(true).share_mode(0).open(&path).unwrap();
        let wiped = wipe_keeping_the_key(&config_dir);
        drop(held);
        assert!(!wiped, "a pairing still on disk must not be reported as wiped");
        assert!(path.exists());
    }
}
