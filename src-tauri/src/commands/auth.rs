use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use tauri::{AppHandle, Emitter, State};

use crate::credential::device_store::{self, DeviceStore};
use crate::credential::keystore::BindingMode;
use crate::credential::store::{self, CredentialError, WipeEpoch};
use crate::link::{self, Link, Snapshot};
use crate::state::AppState;
use vettid_device::access::EndOutcome;
use vettid_device::pairing::{PairError, SystemClock};
use vettid_device::transport::Http;

#[derive(Debug, Serialize)]
pub struct AuthStatus {
    pub is_registered: bool,
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
    /// Which key protects the saved pairing, from the file's header:
    /// "keyring", "none" (no pairing saved) or "unknown" (a file that
    /// can't be read). Shown in Settings (#11).
    pub key_protection: String,
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
    /// Unix seconds: when this desktop stops treating the session as live
    /// (a margin before the vault's `expires_at`).
    pub expires_at: Option<i64>,
    /// On success, the key the saved pairing is sealed under: "keyring".
    pub key_protection: Option<String>,
    /// Not a success, but the pairing is saved: there is no access session
    /// (yet). The pairing screen shows `error` and continues to Start New
    /// Session instead of offering to pair again.
    pub paired_without_session: bool,
}

impl RegisterResponse {
    fn failed(error: impl Into<String>) -> Self {
        RegisterResponse {
            success: false,
            error: Some(error.into()),
            connection_id: None,
            session_id: None,
            expires_at: None,
            key_protection: None,
            paired_without_session: false,
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
            expires_at: snap.live_until.map(|t| t.timestamp()),
            key_protection: Some(BindingMode::Keyring.as_str().to_string()),
            paired_without_session: false,
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

/// What a failed pairing tells the person. The SAS mismatch and the
/// timeout keep the engine's own texts (`vettid_device::display`).
fn pair_notice(e: &PairError, store: Option<&CredentialError>) -> String {
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
/// stored without the keyring.
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
    let config_dir = store::default_config_dir().map_err(|e| e.to_string())?;
    // Checked before pairing starts, so a folder another account can open,
    // a computer without the machine id the pairing is bound to (#14), or a
    // keyring that can't be reached is refused before the vault ever lists
    // this desktop.
    store::ensure_config_dir_since(&config_dir, since).map_err(|e| e.to_string())?;
    store::check_machine_binding().map_err(|e| e.to_string())?;
    device_store::keyring_ready().map_err(|e| e.to_string())?;

    // The code is read as it is (it holds base64): only surrounding
    // whitespace from a paste is dropped.
    let code = request.invite_code.trim();
    if code.is_empty() {
        return Ok(RegisterResponse::failed(link::PAIR_CODE_NOTICE));
    }
    let name = collect_device_fingerprint().hostname;

    let mut store = DeviceStore::new(&config_dir, since);
    let pairing = match vettid_device::pairing::start(code, &name, Http::new, &mut store, SystemClock).await {
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
    match install(&state, link, since, mark).await {
        Some(snap) if snap.active_at(chrono::Utc::now()) => Ok(RegisterResponse::live(&snap)),
        Some(_) => Ok(RegisterResponse::paired_without_session(link::PAIRED_NO_ACCESS_NOTICE)),
        None if store::wipe_epoch() != since => {
            // A log-out ran meanwhile (and, if it ran after the save,
            // removed it): nothing is paired.
            *state.is_registered.write().await = false;
            Ok(RegisterResponse::failed(store::LOGGED_OUT_MEANWHILE_NOTICE))
        }
        // A lock or End session meanwhile: the pairing is saved, the
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
        log::warn!("a log-out, lock or End session overlapped this; staying locked");
        return None;
    }
    let now = chrono::Utc::now();
    let snap = link.snapshot(now);
    let keep = link.keep_refreshing(now);
    // An end an earlier run left unanswered is settled at once, in the
    // background (§6.8: after vault.status).
    let end_pending = link.session.access_end().is_some();
    *slot = Some(link);
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
/// state (not the folder or the keyring key), and say what happened.
async fn erase_unlinked(state: &AppState, link: Link) -> String {
    state.publish(Snapshot::default());
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
/// any reason other than [`crate::credential::store::UNREADABLE_NOTICE`]'s (a missing keyring
/// entry, for example). The detail goes to the log only.
const UNLOCK_FAILED_NOTICE: &str = "This desktop couldn't open its saved pairing. If this keeps happening, remove this desktop on your phone and pair again.";

/// Open the saved pairing: the device state, sealed under the master key
/// in the OS keyring (no user input: the keyring is unlocked by the
/// user's OS login session). Then read `vault.status`, and settle an end
/// left unanswered by an earlier run (§6.8). A session counts as live only
/// once this run's own `vault.status` names it.
///
/// A pairing saved by an earlier build (the NATS-era `connection.enc`)
/// can't be used by this one: it is removed, with the plain "can't be
/// opened" notice. Nothing is sent for it (#39's revoke went to a server
/// that no longer exists).
///
/// A saved pairing that can't be opened is not an error here: the response
/// carries a plain notice for the person, and the detail goes to the log.
#[tauri::command]
pub async fn unlock(state: State<'_, AppState>) -> Result<UnlockResponse, String> {
    // #30: first. A log-out from here on means nothing stays unlocked.
    let since = store::wipe_epoch();
    // #43: likewise a lock or End session, including one under way now.
    let mark = reset_mark(&state);

    let config_dir = match store::default_config_dir() {
        Ok(dir) => dir,
        Err(e) => return Ok(UnlockResponse { unlocked: false, notice: Some(e.to_string()) }),
    };

    if !device_store::exists(&config_dir) {
        if !store::exists(&config_dir) {
            // Not paired: nothing to open and nothing to say.
            return Ok(UnlockResponse { unlocked: false, notice: None });
        }
        if let Err(e) = store::remove_legacy_pairing(&config_dir) {
            log::error!("unlock: an earlier build's pairing couldn't be removed: {}", e);
        }
        return Ok(UnlockResponse { unlocked: false, notice: Some(store::UNREADABLE_NOTICE.to_string()) });
    }

    let mut link = match Link::open(DeviceStore::new(&config_dir, since)) {
        Ok(Some(l)) => l,
        // A pairing interrupted before the owner approved it was removed.
        Ok(None) => return Ok(UnlockResponse { unlocked: false, notice: None }),
        Err((e, failure)) => {
            log::warn!("unlock: saved pairing could not be opened: {}", e);
            let notice = failure.as_ref().and_then(link::plain_store_notice).unwrap_or_else(|| UNLOCK_FAILED_NOTICE.to_string());
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
    if install(&state, link, since, mark).await.is_none() {
        return Ok(UnlockResponse { unlocked: false, notice: None });
    }
    *state.is_registered.write().await = true;

    // Warn (never refuse) when another account can open the saved
    // pairing's folder or file (#24).
    Ok(UnlockResponse { unlocked: true, notice: store::privacy_warning(&config_dir, BindingMode::Keyring).map(str::to_string) })
}

/// Session info the frontend uses to decide which view to render
/// (active / expiring-soon / expired).
#[derive(Debug, Serialize)]
pub struct SessionInfoResponse {
    /// The id the vault gave this device.
    pub connection_id: String,
    pub session_id: String,
    /// Unix seconds at which this desktop stops treating the session as
    /// live (a margin before the vault's `expires_at`). 0 when inactive.
    pub expires_at: i64,
    pub seconds_remaining: i64,
    pub is_active: bool,
}

/// What the frontend polls (cheap, no network) to drive the expiry UI:
/// from the last snapshot of the link.
#[tauri::command]
pub async fn get_session_info(state: State<'_, AppState>) -> Result<SessionInfoResponse, String> {
    session_info(&state.snapshot(), chrono::Utc::now())
}

fn session_info(snap: &Snapshot, now: chrono::DateTime<chrono::Utc>) -> Result<SessionInfoResponse, String> {
    if !snap.unlocked {
        return Err("not unlocked".to_string());
    }
    let active = snap.active_at(now);
    let until = snap.live_until.filter(|_| active);
    Ok(SessionInfoResponse {
        connection_id: snap.device_id.clone().unwrap_or_default(),
        session_id: snap.session_id.clone().filter(|_| active).unwrap_or_default(),
        expires_at: until.map_or(0, |t| t.timestamp()),
        seconds_remaining: until.map_or(0, |t| (t - now).num_seconds().max(0)),
        is_active: active,
    })
}

/// Start New Session: ask the owner's phone for an access session
/// (`device.session.request`, §6.8), tell the frontend the phone is asked
/// (`session:requested`), and wait for the answer until the request
/// lapses. Success only once `vault.status` shows the new session.
///
/// A lock, log-out or End session meanwhile stops the wait (checked
/// between polls).
#[tauri::command]
pub async fn extend_session(app: AppHandle, state: State<'_, AppState>) -> Result<RegisterResponse, String> {
    // #33: never overlaps End session; see AppState::session_op.
    let _session_op = state.session_op.lock().await;
    let mark = reset_mark(&state);
    let mut slot = state.link.lock().await;
    let Some(link) = slot.as_mut() else {
        return Ok(RegisterResponse::failed(UNLOCK_FAILED_NOTICE));
    };
    let requested = || {
        let _ = app.emit(ACCESS_REQUESTED_EVENT, ());
    };
    let result = link.request_access(requested, || overtaken_by_reset(&state, mark)).await;
    if link.unlinked() {
        let link = slot.take().expect("checked above");
        return Ok(RegisterResponse::failed(erase_unlinked(&state, link).await));
    }
    let now = chrono::Utc::now();
    let snap = link.snapshot(now);
    // A reset that started meanwhile has cleared what the UI shows, and
    // shows its own result.
    if !overtaken_by_reset(&state, mark) {
        state.publish(snap.clone());
        if link.keep_refreshing(now) {
            state.start_refresh(false);
        }
    }
    match result {
        Ok(()) if snap.active_at(now) => Ok(RegisterResponse::live(&snap)),
        Ok(()) => Ok(RegisterResponse::failed(link::ACCESS_NOT_CONFIRMED_NOTICE)),
        Err(f) => {
            log::info!("extend_session: no session: {:?}", f);
            let failure = link.store.take_failure();
            Ok(RegisterResponse::failed(link::request_notice(&f, failure.as_ref())))
        }
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

/// Delete the desktop's config directory and the keyring key. Returns
/// whether the saved pairing is gone afterwards: checked on disk, not
/// assumed. With no usable folder only the key is deleted, and false is
/// returned.
fn wipe_local_pairing(config_dir: Option<&std::path::Path>) -> bool {
    wipe_local_pairing_with(config_dir, crate::credential::store::wipe_for_logout)
}

/// [`wipe_local_pairing`] with the store step passed in, so tests can run
/// it without deleting this machine's real keyring key.
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
/// pairing (folder and keyring key) whatever came of that, and drop the
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
    let deadline = tokio::time::Instant::now() + bound;
    // The link, if it can be had within the bound: a refresh or a Start New
    // Session may hold it.
    let mut guard = tokio::time::timeout_at(deadline, state.link.lock()).await.ok();
    // Stopped with the link held, or (if it couldn't be had) mid-operation,
    // which leaves nothing half done that matters: the link is dropped below.
    state.stop_refresh();
    let end = match guard.as_mut() {
        None => {
            log::warn!("logout: the link was busy; access not ended at the vault");
            LogoutEnd::NotConfirmed
        }
        Some(slot) => match slot.as_mut() {
            None => LogoutEnd::NoLink,
            // Unnamed: all of this desktop's access (§6.8). An end cut short
            // by the bound is dropped with the link.
            Some(l) => logout_end(Some(tokio::time::timeout_at(deadline, l.end()).await.ok())),
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
    // Not live from here on, whatever the vault answers.
    state.publish(state.snapshot().without_session());
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
            None => Some(link::END_UNCONFIRMED_NOTICE.to_string()),
            Some(l) => {
                let result = l.end().await;
                let notice = match &result {
                    Ok(EndOutcome::Ended) => None,
                    Ok(EndOutcome::Unconfirmed) => Some(link::END_UNCONFIRMED_NOTICE.to_string()),
                    Ok(EndOutcome::Replaced) => Some(link::END_REPLACED_NOTICE.to_string()),
                    Err(vettid_device::access::AccessError::EndUnconfirmed) => Some(link::END_UNCONFIRMED_NOTICE.to_string()),
                    Err(e) => {
                        log::warn!("end_session: not confirmed: {}", e);
                        if l.session.access_end().is_some() {
                            Some(link::END_NOT_SENT_NOTICE.to_string())
                        } else {
                            let failure = l.store.take_failure();
                            Some(link::access_notice(e, failure.as_ref()))
                        }
                    }
                };
                if l.unlinked() {
                    let l = slot.take().expect("checked above");
                    Some(erase_unlinked(state, l).await)
                } else {
                    let now = chrono::Utc::now();
                    state.publish(l.snapshot(now));
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
    EndSessionResponse { notice }
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
}

/// Lock: drop the link from memory (its keys wipe themselves). The
/// pairing stays saved; the next unlock opens it again.
#[tauri::command]
pub async fn lock(state: State<'_, AppState>) -> Result<bool, String> {
    lock_memory(&state).await;
    Ok(true)
}

/// [`lock`]'s work.
async fn lock_memory(state: &AppState) {
    begin_reset(state);
    state.publish(Snapshot::default());
    // The link is dropped below: stopping its refresh mid-operation leaves
    // nothing half done in memory (what is stored is as after a crash).
    state.stop_refresh();
    drop(state.link.lock().await.take());
    state.publish(Snapshot::default());
    finish_reset(state);
}

/// Get current authentication/registration status.
#[tauri::command]
pub async fn get_status(state: State<'_, AppState>) -> Result<AuthStatus, String> {
    let snap = state.snapshot();
    let is_registered = *state.is_registered.read().await || snap.unlocked;
    let config_dir = store::default_config_dir().ok();

    // Also check on disk if not yet known: this build's pairing, or an
    // earlier build's, which unlock removes with a notice.
    let is_registered = is_registered
        || config_dir.as_deref().is_some_and(|dir| device_store::exists(dir) || store::exists(dir));

    let fp = collect_device_fingerprint();

    // With no known folder nothing can have been saved.
    let key_protection = config_dir.as_deref().map_or("none", device_store::stored_key_protection).to_string();

    Ok(AuthStatus {
        key_protection,
        is_registered,
        is_unlocked: snap.unlocked,
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
        assert_eq!(fingerprint_hex_of(Err(FingerprintError::MissingMachineId)), "");
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

    /// Every session-ending path stops the background refresh: lock,
    /// log-out and End session each end its task and empty the slot, and
    /// nothing is shown as live or unlocked afterwards.
    #[tokio::test]
    async fn lock_logout_and_end_session_stop_the_refresh() {
        use std::sync::atomic::Ordering;
        for which in ["lock", "logout", "end session"] {
            let state = AppState::new();
            let live = Snapshot {
                unlocked: true,
                session_id: Some("s".into()),
                live_until: Some(chrono::Utc::now() + chrono::TimeDelta::hours(1)),
                ..Default::default()
            };
            state.publish(live);
            let dropped = tracked_task(&state);
            match which {
                "lock" => lock_memory(&state).await,
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
        assert_eq!(state.snapshot(), Snapshot::default());
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

    /// #43: every memory reset is counted as started and finished, so an
    /// unlock that one overtook can tell.
    #[tokio::test]
    async fn every_reset_is_counted() {
        use std::sync::atomic::Ordering::SeqCst;
        let state = AppState::new();
        lock_memory(&state).await;
        log_out(&state, None, |_| false, LOGOUT_END_BOUND).await;
        end_access(&state).await;
        assert_eq!(state.resets_started.load(SeqCst), 3);
        assert_eq!(state.resets_finished.load(SeqCst), 3);
    }

    /// The session info comes from the snapshot: live up to `live_until`
    /// only, and "not unlocked" without a link.
    #[test]
    fn session_info_is_live_only_until_live_until() {
        let now = chrono::Utc::now();
        assert!(session_info(&Snapshot::default(), now).is_err());
        let until = now + chrono::TimeDelta::seconds(90);
        let snap = Snapshot {
            unlocked: true,
            device_id: Some("dev".into()),
            session_id: Some("s1".into()),
            expires_at: Some(until + chrono::TimeDelta::seconds(60)),
            live_until: Some(until),
            reachable: true,
        };
        let info = session_info(&snap, now).unwrap();
        assert!(info.is_active);
        assert_eq!(info.expires_at, until.timestamp());
        assert_eq!(info.seconds_remaining, 90);
        assert_eq!(info.session_id, "s1");
        let later = session_info(&snap, until + chrono::TimeDelta::seconds(1)).unwrap();
        assert!(!later.is_active);
        assert_eq!((later.expires_at, later.seconds_remaining, later.session_id.as_str()), (0, 0, ""));
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
        assert_eq!(pair_notice(&store, Some(&CredentialError::KeyringUnavailable)), store::KEYRING_UNAVAILABLE_NOTICE);
        assert_eq!(pair_notice(&store, Some(&CredentialError::LoggedOutMeanwhile)), store::LOGGED_OUT_MEANWHILE_NOTICE);
        assert_eq!(pair_notice(&store, None), link::PAIR_FAILED_NOTICE);
        assert_eq!(pair_notice(&PairError::NotCleared(Box::new(PairError::Rejected)), None), vettid_device::display::REJECTED_ON_PHONE);
    }

    /// The store step of log-out, without deleting the real keyring key.
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
