use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use tauri::{AppHandle, Emitter, State};

use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct AuthStatus {
    pub is_registered: bool,
    pub is_unlocked: bool,
    pub has_active_session: bool,
    // Device-identity fields surfaced in the Settings view so the
    // user can confirm which desktop they're looking at and verify
    // the binary + machine fingerprints match what the phone's
    // Authorize Desktop screen displays at pairing time. Mirrors the
    // DeviceMetadata we send to the vault in `device.request-session`.
    pub hostname: String,
    pub platform: String,
    pub os_name: String,
    pub os_version: String,
    pub binary_fingerprint: String,
    pub machine_fingerprint: String,
    pub app_version: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    /// 12-char code the user typed in from the phone app, displayed
    /// to them as `ABCD-EFGH-JKLM`. The frontend strips dashes/whitespace
    /// before sending, but we also normalize defensively below.
    pub invite_code: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub success: bool,
    pub error: Option<String>,
    pub connection_id: Option<String>,
    pub session_id: Option<String>,
    pub expires_at: Option<i64>,
}

/// Event emitted to the frontend with the QR payload the user should scan
/// with their phone. Occurs after stage-1 completes, before the phone scan.
#[derive(Debug, Clone, Serialize)]
pub struct PairingQrEvent {
    pub connection_id: String,
    pub qr_payload: String,
}

/// Pair this desktop with a vault via a 12-char invite code typed by the user.
///
/// Two-stage flow (see vettid-dev/docs/DESKTOP-CONNECTION-FLOW.md):
///   1. Resolve invite via the embedded guest NATS account → scoped creds +
///      connection_id.
///   2. Publish device.request-session, emit `pairing:qr-ready` so the UI can
///      render the QR the user scans on their phone.
///   3. Receive device.session.activated with the vault's pubkey; derive the
///      session_key via HKDF; save encrypted credentials to disk.
#[tauri::command]
pub async fn register(
    app: AppHandle,
    state: State<'_, AppState>,
    request: RegisterRequest,
) -> Result<RegisterResponse, String> {
    use crate::credential::store;
    use crate::registration::pairing;

    let config_dir = store::default_config_dir().map_err(|e| e.to_string())?;
    // Checked before pairing starts, so a folder another account can open
    // is refused before the vault ever lists this desktop.
    store::ensure_config_dir(&config_dir).map_err(|e| e.to_string())?;

    // Strip dashes/whitespace so users can paste either the grouped
    // `ABCD-EFGH-JKLM` form they see on the phone or a flat 12-char run.
    // Uppercase to match the vault's code alphabet exactly.
    let invite_code: String = request
        .invite_code
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_uppercase();
    if invite_code.len() != 12 {
        return Ok(RegisterResponse {
            success: false,
            error: Some("Invite code must be 12 characters".to_string()),
            connection_id: None,
            session_id: None,
            expires_at: None,
        });
    }

    // Stage 1 — resolve invite via guest account
    let (session, runtime) = match pairing::resolve_invite(&invite_code).await {
        Ok(v) => v,
        Err(e) => {
            return Ok(RegisterResponse {
                success: false,
                error: Some(e.to_string()),
                connection_id: None,
                session_id: None,
                expires_at: None,
            });
        }
    };

    // Emit the QR payload so the UI can render it while we await approval.
    let _ = app.emit(
        "pairing:qr-ready",
        PairingQrEvent {
            connection_id: session.connection_id.clone(),
            qr_payload: session.qr_payload.clone(),
        },
    );

    let fingerprint = collect_device_fingerprint();

    // Stage 2 — wait for activation, derive session_key, save credentials.
    let outcome = match pairing::complete_pairing(
        session,
        runtime,
        fingerprint,
        &config_dir,
    )
    .await
    {
        Ok(o) => o,
        Err(e) => {
            return Ok(RegisterResponse {
                success: false,
                error: Some(e.to_string()),
                connection_id: None,
                session_id: None,
                expires_at: None,
            });
        }
    };

    *state.is_registered.write().await = true;
    let mut listener_conn_id: Option<String> = None;
    if let Ok((creds, _)) = store::load(&config_dir) {
        if creds.connection_key.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&creds.connection_key);
            *state.connection_key.write().await = Some(key);
        }
        listener_conn_id = Some(creds.connection_id.clone());

        // Reconnect the AppState NatsClient with the freshly-saved
        // creds. complete_pairing uses its own ephemeral NatsClient
        // that gets dropped on return, so the AppState client is
        // whatever was last connected (could be the now-closed pre-
        // end_session one). Without this rebind, spawn_listener
        // below tries to subscribe on a dropped client and fails
        // with "NATS client not connected". Mirrors unlock()'s
        // reconnect dance.
        if !creds.message_space_url.is_empty() && !creds.message_space_token.is_empty() {
            if let Some((jwt, seed)) = crate::registration::pairing::parse_creds_block(&creds.message_space_token) {
                let mut nats = state.nats.lock().await;
                if let Err(e) = nats
                    .connect_with_credentials(
                        &creds.message_space_url,
                        &jwt,
                        &seed,
                        &creds.owner_guid,
                    )
                    .await
                {
                    log::warn!("Failed to reconnect AppState NATS after pairing: {}", e);
                }
            } else {
                log::warn!("Stored NATS creds malformed post-pairing — listener will fail until reconnect");
            }
        }

        *state.credentials.write().await = Some(creds);
        *state.is_unlocked.write().await = true;
    }

    // Start the response listener now that AppState.nats is bound to
    // a live connection.
    if let Some(conn_id) = listener_conn_id {
        crate::nats::listener::spawn_listener(app.clone(), conn_id).await;
    }

    Ok(RegisterResponse {
        success: true,
        error: None,
        connection_id: Some(outcome.connection_id),
        session_id: Some(outcome.session_id),
        expires_at: Some(outcome.expires_at),
    })
}

/// Cached device fingerprint. `compute_device_fingerprint` hashes the
/// whole executable with SHA-256 — several seconds on a debug build —
/// so it is computed exactly once. `warm_device_fingerprint()` kicks
/// that off at app startup (see lib.rs) so a pairing's request-session
/// never blocks on it; the value is known before the request is made.
static DEVICE_FINGERPRINT: OnceLock<crate::registration::pairing::DeviceFingerprint> =
    OnceLock::new();

/// Return the device fingerprint, computing it once and caching it.
/// Effectively instant after `warm_device_fingerprint()` has run.
pub(crate) fn collect_device_fingerprint() -> crate::registration::pairing::DeviceFingerprint {
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

fn compute_device_fingerprint() -> crate::registration::pairing::DeviceFingerprint {
    use crate::fingerprint::binary::binary_fingerprint;
    #[cfg(not(windows))]
    use crate::fingerprint::platform_linux::{collect_machine_attributes, compute_machine_fingerprint_hex};
    #[cfg(windows)]
    use crate::fingerprint::platform_windows::{
        collect_machine_attributes_windows as collect_machine_attributes,
        compute_machine_fingerprint_hex,
    };
    use crate::registration::pairing::DeviceFingerprint;

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
    let machine_fp = collect_machine_attributes()
        .ok()
        .map(|attrs| compute_machine_fingerprint_hex(&attrs))
        .unwrap_or_default();

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

/// Unlock the credential store.
///
/// Loads the encrypted connection.enc file using the master key from
/// the OS keyring (or the machine-bound fallback). No user input —
/// the keyring is unlocked by the user's OS login session and that
/// gate is the security factor at the local layer.
/// Populates AppState with credentials and connection key.
///
/// A saved pairing that can't be opened is not an error here: the response
/// carries a plain notice for the person, and the detail goes to the log.
#[tauri::command]
pub async fn unlock(app: AppHandle, state: State<'_, AppState>) -> Result<UnlockResponse, String> {
    use crate::credential::store::{self, CredentialError};

    let config_dir = match store::default_config_dir() {
        Ok(dir) => dir,
        Err(e) => {
            return Ok(UnlockResponse {
                unlocked: false,
                notice: Some(e.to_string()),
            });
        }
    };

    let (creds, _binding) = match store::load(&config_dir) {
        Ok(loaded) => loaded,
        Err(e @ CredentialError::Unreadable) => {
            return Ok(UnlockResponse {
                unlocked: false,
                notice: Some(e.to_string()),
            });
        }
        Err(CredentialError::NotFound(_)) => {
            // Not paired: nothing to open and nothing to say.
            return Ok(UnlockResponse {
                unlocked: false,
                notice: None,
            });
        }
        Err(e) => {
            log::warn!("unlock: saved pairing could not be opened: {}", e);
            return Ok(UnlockResponse {
                unlocked: false,
                notice: Some(UNLOCK_FAILED_NOTICE.to_string()),
            });
        }
    };

    // Load connection key (stored as raw bytes in ConnectionCredentials)
    if creds.connection_key.len() == 32 {
        let mut key = [0u8; 32];
        key.copy_from_slice(&creds.connection_key);
        *state.connection_key.write().await = Some(key);
    }

    // Reconnect NATS so subsequent vault ops can publish + receive
    // responses. The stored `message_space_token` is a NATS .creds
    // block (JWT + seed), not a single auth token — so we have to
    // parse it and go through connect_with_credentials, which also
    // pins TLS-first + rustls (load-bearing for the NLB listener).
    // The previous `nats.connect(.., token, ..)` call used `.token()`
    // auth, which expects an opaque bearer string and never works
    // against this account's JWT-based auth → every op hit
    // "publish failed: NATS client not connected".
    if !creds.message_space_url.is_empty() && !creds.message_space_token.is_empty() {
        match crate::registration::pairing::parse_creds_block(&creds.message_space_token) {
            Some((jwt, seed)) => {
                let mut nats = state.nats.lock().await;
                if let Err(e) = nats
                    .connect_with_credentials(
                        &creds.message_space_url,
                        &jwt,
                        &seed,
                        &creds.owner_guid,
                    )
                    .await
                {
                    log::warn!("Failed to reconnect NATS on unlock: {}", e);
                    // Don't fail unlock if NATS reconnect fails — user
                    // can retry; some op paths re-establish on demand.
                }
            }
            None => {
                log::warn!(
                    "Stored NATS creds malformed — unlock continues but vault ops will fail until re-pair"
                );
            }
        }
    }

    let connection_id = creds.connection_id.clone();
    *state.credentials.write().await = Some(creds);
    *state.is_unlocked.write().await = true;

    // Spawn the background NATS listener so device_op_response
    // envelopes get decrypted + matched to pending request_ids.
    // Without this, every vault op hits the 30-second timeout —
    // the request reaches the vault, the response is published
    // back to MessageSpace.{owner}.forOwner.device.{conn}, and
    // nobody's subscribed to it.
    crate::nats::listener::spawn_listener(app.clone(), connection_id).await;

    Ok(UnlockResponse {
        unlocked: true,
        notice: None,
    })
}

/// Session info the frontend uses to decide which view to render
/// (active / expiring-soon / expired).
#[derive(Debug, Serialize)]
pub struct SessionInfoResponse {
    pub connection_id: String,
    pub session_id: String,
    /// Unix seconds. 0 means unknown/inactive.
    pub expires_at: i64,
    pub seconds_remaining: i64,
    pub is_active: bool,
}

/// Inspect the currently-loaded credentials and return session state. The
/// frontend polls this (cheap, no network) to drive the expiry UI.
#[tauri::command]
pub async fn get_session_info(state: State<'_, AppState>) -> Result<SessionInfoResponse, String> {
    let creds_guard = state.credentials.read().await;
    let creds = creds_guard
        .as_ref()
        .ok_or_else(|| "not unlocked".to_string())?;

    let now = chrono::Utc::now().timestamp();
    let remaining = (creds.session_expires_at - now).max(0);
    Ok(SessionInfoResponse {
        connection_id: creds.connection_id.clone(),
        session_id: creds.session_id.clone(),
        expires_at: creds.session_expires_at,
        seconds_remaining: remaining,
        is_active: creds.session_expires_at > 0 && remaining > 0,
    })
}

/// Start an extension: generate fresh ephemeral keys for the existing
/// connection_id, publish device.request-session, emit a new `pairing:qr-ready`
/// with the QR the user scans on their phone, wait for device.session.activated,
/// derive a new session_key, save to disk.
///
/// The phone-side UI is identical to initial pairing — the vault's
/// HandleDeviceAuthorizeSession detects the existing DeviceSession and rotates.
#[tauri::command]
pub async fn extend_session(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<RegisterResponse, String> {
    use crate::credential::store;
    use crate::registration::pairing;

    let config_dir = match store::default_config_dir() {
        Ok(dir) => dir,
        Err(e) => {
            return Ok(RegisterResponse {
                success: false,
                error: Some(e.to_string()),
                connection_id: None,
                session_id: None,
                expires_at: None,
            });
        }
    };

    let (session, runtime) = match pairing::start_extension(&config_dir).await {
        Ok(v) => v,
        Err(e) => {
            return Ok(RegisterResponse {
                success: false,
                error: Some(e.to_string()),
                connection_id: None,
                session_id: None,
                expires_at: None,
            });
        }
    };

    let _ = app.emit(
        "pairing:qr-ready",
        PairingQrEvent {
            connection_id: session.connection_id.clone(),
            qr_payload: session.qr_payload.clone(),
        },
    );

    let fingerprint = collect_device_fingerprint();

    let outcome = match pairing::complete_pairing(
        session,
        runtime,
        fingerprint,
        &config_dir,
    )
    .await
    {
        Ok(o) => o,
        Err(e) => {
            return Ok(RegisterResponse {
                success: false,
                error: Some(e.to_string()),
                connection_id: None,
                session_id: None,
                expires_at: None,
            });
        }
    };

    // Refresh AppState with the rotated session
    let mut listener_conn_id: Option<String> = None;
    if let Ok((creds, _)) = store::load(&config_dir) {
        if creds.connection_key.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&creds.connection_key);
            *state.connection_key.write().await = Some(key);
        }

        // Reconnect the SHARED state.nats client with the rotated
        // session's scoped creds. The Stage-2 handshake in
        // complete_pairing ran on its own short-lived NatsClient, and
        // the preceding end_session left state.nats disconnected.
        // spawn_listener (below) subscribes through state.nats — so
        // without this reconnect it fails with "NATS client not
        // connected" and the desktop never receives vault op
        // responses for the new session. Mirrors unlock()'s connect.
        if !creds.message_space_url.is_empty() && !creds.message_space_token.is_empty() {
            match pairing::parse_creds_block(&creds.message_space_token) {
                Some((jwt, seed)) => {
                    let mut nats = state.nats.lock().await;
                    if let Err(e) = nats
                        .connect_with_credentials(
                            &creds.message_space_url,
                            &jwt,
                            &seed,
                            &creds.owner_guid,
                        )
                        .await
                    {
                        log::error!(
                            "extend_session: failed to connect state.nats for the new session: {}",
                            e
                        );
                    }
                }
                None => log::error!(
                    "extend_session: stored NATS creds malformed — listener will fail"
                ),
            }
        }

        listener_conn_id = Some(creds.connection_id.clone());
        *state.credentials.write().await = Some(creds);
    }

    // Restart the response listener for the rotated session keys.
    // Existing pending request channels are dropped by the previous
    // listener's exit path; new requests register against the fresh
    // listener.
    if let Some(conn_id) = listener_conn_id {
        crate::nats::listener::spawn_listener(app.clone(), conn_id).await;
    }

    Ok(RegisterResponse {
        success: true,
        error: None,
        connection_id: Some(outcome.connection_id),
        session_id: Some(outcome.session_id),
        expires_at: Some(outcome.expires_at),
    })
}

/// What the person is told when logout could not send the revoke.
const REVOKE_NOT_SENT_NOTICE: &str = "This desktop has been logged out here, but your vault was not told. Remove this desktop on your phone.";
/// ... when the saved pairing could not be deleted from this computer.
const NOT_WIPED_NOTICE: &str = "This desktop's saved pairing could not be deleted from this computer. Remove this desktop on your phone, then try logging out again.";
/// ... when neither happened.
const NOT_WIPED_NOR_SENT_NOTICE: &str = "This desktop's saved pairing could not be deleted from this computer, and your vault was not told. Remove this desktop on your phone, then try logging out again.";

/// Result of [`logout`].
#[derive(Debug, Serialize)]
pub struct LogoutResponse {
    /// The revoke was written to the message server connection. The vault
    /// does not acknowledge it, so this does not confirm the device was
    /// removed.
    pub revoke_sent: bool,
    /// The saved pairing is gone from this computer.
    pub local_wiped: bool,
    /// Plain text to show the person when either of the above is false.
    pub notice: Option<String>,
}

fn logout_notice(revoke_sent: bool, local_wiped: bool) -> Option<&'static str> {
    match (revoke_sent, local_wiped) {
        (true, true) => None,
        (false, true) => Some(REVOKE_NOT_SENT_NOTICE),
        (true, false) => Some(NOT_WIPED_NOTICE),
        (false, false) => Some(NOT_WIPED_NOR_SENT_NOTICE),
    }
}

/// Delete the desktop's config directory. Returns whether the saved
/// pairing is gone afterwards: checked on disk, not assumed.
fn wipe_local_pairing(config_dir: &std::path::Path) -> bool {
    use crate::credential::store;

    // SECURITY: never remove a relative path, which would resolve against
    // whatever the current directory is. `default_config_dir` only returns
    // absolute paths; this guards the destructive step on its own.
    if !config_dir.is_absolute() {
        log::error!("Refusing to wipe a relative config path on logout");
        return false;
    }

    if config_dir.exists() {
        if let Err(e) = std::fs::remove_dir_all(config_dir) {
            log::warn!("Failed to remove config dir on logout: {}", e);
            // Fall back to best-effort removal of the pairing itself.
            if let Err(e) = store::delete(config_dir) {
                log::error!("Failed to remove the saved pairing on logout: {}", e);
            }
        }
    }
    !store::exists(config_dir)
}

/// Log out: tell the vault to revoke this device, then wipe the on-disk
/// credential store and reset AppState. The local wipe happens even if the
/// revoke can't be sent; the response says whether it was, so the UI never
/// implies the vault was told when it wasn't.
#[tauri::command]
pub async fn logout(state: State<'_, AppState>) -> Result<LogoutResponse, String> {
    use crate::credential::keystore;
    use crate::credential::store;
    use crate::registration::pairing;
    use zeroize::Zeroize;

    // With no known folder there is nothing to revoke from or wipe, and
    // neither can be confirmed: both are reported as not done.
    let config_dir = store::default_config_dir();
    if let Err(e) = &config_dir {
        log::warn!("logout: {}", e);
    }

    // The vault may be unreachable or the creds may be unreadable: the
    // local wipe still has to happen, and the response reports it.
    let revoke_sent = match &config_dir {
        Ok(dir) => match pairing::publish_revoke(dir).await {
            Ok(()) => true,
            Err(e) => {
                log::warn!("device.revoke not sent (continuing with local wipe): {}", e);
                false
            }
        },
        Err(_) => false,
    };

    // Disconnect NATS
    state.nats.lock().await.disconnect().await;

    // Zero key material in memory
    {
        let mut key_guard = state.connection_key.write().await;
        if let Some(ref mut key) = *key_guard {
            key.zeroize();
        }
        *key_guard = None;
    }
    *state.credentials.write().await = None;
    *state.is_unlocked.write().await = false;
    *state.is_registered.write().await = false;
    state.session.write().await.revoke();

    // Wipe the config directory entirely — nothing left on disk.
    let local_wiped = match &config_dir {
        Ok(dir) => wipe_local_pairing(dir),
        Err(_) => false,
    };

    // Wipe the master key from the keyring too. A future pairing on
    // this machine will mint a fresh key — a leaked disk image from
    // an earlier install can't be decrypted under the new key.
    keystore::delete_keyring_key();

    Ok(LogoutResponse {
        revoke_sent,
        local_wiped,
        notice: logout_notice(revoke_sent, local_wiped).map(str::to_string),
    })
}

/// End the current vault session immediately, server-side AND locally.
///
/// Unlike `logout` (which wipes the on-disk credential store and ends the
/// desktop's pairing entirely), this preserves the pairing so the user can
/// start a new session under the same connection without re-pairing on the
/// phone. The flow is:
///   1. Publish device.end-session to the vault — wipes the session key
///      server-side, flips DeviceSession.Status to "expired", notifies the
///      desktop via forApp.device.{conn}.ended.
///   2. Locally expire the session: zero the connection key, clear
///      credentials from memory, flip the local session state to expired
///      so the UI routes to SessionExpired (where "Start New Session"
///      restarts the session without re-pair).
#[tauri::command]
pub async fn end_session(state: State<'_, AppState>) -> Result<bool, String> {
    use crate::credential::store;
    use zeroize::Zeroize;

    // With no known folder there is no stored pairing to end or update;
    // the in-memory reset below still happens.
    match store::default_config_dir() {
        Ok(config_dir) => end_session_on_disk(&config_dir).await,
        Err(e) => log::warn!("end_session: {}; local reset only", e),
    }

    state.nats.lock().await.disconnect().await;

    {
        let mut key_guard = state.connection_key.write().await;
        if let Some(ref mut key) = *key_guard {
            key.zeroize();
        }
        *key_guard = None;
    }
    *state.credentials.write().await = None;
    *state.is_unlocked.write().await = false;
    state.session.write().await.expire();

    Ok(true)
}

/// The stored-pairing half of [`end_session`]: tell the vault, then
/// clear the session fields in the saved pairing.
async fn end_session_on_disk(config_dir: &std::path::Path) {
    use crate::credential::store;
    use crate::registration::pairing;

    let config_dir = config_dir.to_path_buf();

    // Tell the vault to end the session. publish_end_session flushes
    // before returning, within a deadline: on a clean return the
    // end-session frame was written to the connection. That is not a
    // confirmation from the vault. On error we still reset locally.
    if let Err(e) = pairing::publish_end_session(&config_dir, "user_locked").await {
        log::warn!("device.end-session publish failed (continuing with local reset): {}", e);
    }

    // Persist the session-end to disk. The device stays PAIRED — the
    // device keypair, connection_key and NATS creds are untouched, so
    // "Start New Session" needs no re-pair — but the session fields
    // MUST be cleared here. get_session_info derives is_active purely
    // from the on-disk session_expires_at, so leaving it set meant a
    // relaunch reloaded a dead session: the desktop routed straight to
    // the vault and every op hung because the vault no longer had it.
    match store::load(&config_dir) {
        Ok((mut creds, _)) => {
            creds.session_id.clear();
            creds.session_expires_at = 0;
            creds.session_duration_seconds = 0;
            if let Err(e) = store::save(&config_dir, &creds) {
                log::error!("end_session: failed to persist cleared session state: {}", e);
            } else {
                log::info!("end_session: on-disk session fields cleared (pairing preserved)");
            }
        }
        Err(e) => log::warn!(
            "end_session: could not load creds to clear on-disk session fields: {}", e
        ),
    }
}

/// Lock the session — clear credentials from memory.
/// SECURITY: Zeroizes key material before dropping.
#[tauri::command]
pub async fn lock(state: State<'_, AppState>) -> Result<bool, String> {
    use zeroize::Zeroize;

    // SECURITY: Zeroize connection key before clearing
    {
        let mut key_guard = state.connection_key.write().await;
        if let Some(ref mut key) = *key_guard {
            key.zeroize();
        }
        *key_guard = None;
    }

    // Clear credentials (ConnectionCredentials implements Zeroize on drop)
    *state.credentials.write().await = None;
    *state.is_unlocked.write().await = false;

    // Disconnect NATS
    state.nats.lock().await.disconnect().await;

    // Reset session
    state.session.write().await.expire();

    Ok(true)
}

/// Get current authentication/registration status.
#[tauri::command]
pub async fn get_status(state: State<'_, AppState>) -> Result<AuthStatus, String> {
    let is_registered = *state.is_registered.read().await;
    let is_unlocked = *state.is_unlocked.read().await;
    let has_active_session = state.session.read().await.is_active();

    // Also check on disk if not yet known
    let is_registered = if !is_registered {
        use crate::credential::store;
        store::default_config_dir()
            .map(|dir| store::exists(&dir))
            .unwrap_or(false)
    } else {
        is_registered
    };

    let fp = collect_device_fingerprint();

    Ok(AuthStatus {
        is_registered,
        is_unlocked,
        has_active_session,
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

    #[test]
    fn wipe_local_pairing_removes_the_directory() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join("vettid-desktop");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(config_dir.join("connection.enc"), b"{}").unwrap();
        assert!(wipe_local_pairing(&config_dir));
        assert!(!config_dir.exists());
    }

    /// A relative path is never removed, and is not reported as wiped.
    /// Uses a name that does not exist, so nothing in the current
    /// directory is at risk if the guard were missing.
    #[test]
    fn wipe_local_pairing_refuses_a_relative_path() {
        let relative = std::path::Path::new("vettid-desktop-relative-wipe-test-does-not-exist");
        assert!(!wipe_local_pairing(relative));
    }

    #[test]
    fn wipe_local_pairing_with_nothing_there_is_wiped() {
        let dir = tempfile::tempdir().unwrap();
        assert!(wipe_local_pairing(&dir.path().join("absent")));
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
        let wiped = wipe_local_pairing(&config_dir);
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
        let wiped = wipe_local_pairing(&config_dir);
        drop(held);
        assert!(!wiped, "a pairing still on disk must not be reported as wiped");
        assert!(path.exists());
    }
}
