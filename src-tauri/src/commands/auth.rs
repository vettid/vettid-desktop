use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use tauri::{AppHandle, Emitter, Manager, State};

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
    /// Which key protects the saved pairing, from the file's header:
    /// "keyring", "machine", "none" (no pairing saved) or "unknown" (a
    /// file that can't be read). Shown in Settings (#11).
    pub key_protection: String,
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
    /// On success, the key the saved pairing was sealed under: "keyring"
    /// or "machine". The pairing screen warns once when it is "machine".
    pub key_protection: Option<String>,
    /// Not a success, but the pairing is saved: the new session couldn't
    /// be recorded (#33). The pairing screen shows `error` and continues to
    /// Start New Session instead of offering to pair again.
    pub paired_without_session: bool,
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

    // #30: first, before anything that waits. A log-out from here on means
    // this pairing is not saved.
    let since = store::wipe_epoch();
    let config_dir = store::default_config_dir().map_err(|e| e.to_string())?;
    // Checked before pairing starts, so a folder another account can open,
    // or a computer without the machine id the pairing is bound to (#14),
    // is refused before the vault ever lists this desktop.
    // #30: under the store's lock, and not after a log-out since `since`.
    store::ensure_config_dir_since(&config_dir, since).map_err(|e| e.to_string())?;
    store::check_machine_binding().map_err(|e| e.to_string())?;

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
            key_protection: None,
            paired_without_session: false,
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
                key_protection: None,
                paired_without_session: false,
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
        since,
    )
    .await
    {
        Ok(o) => o,
        Err(e) => {
            // #33: the pairing is saved, only the session isn't. Mark this
            // desktop registered, so the next launch goes to Start New
            // Session rather than pairing again.
            let paired = matches!(e, crate::registration::flow::RegistrationError::SessionNotRecorded);
            if paired {
                *state.is_registered.write().await = true;
                // #30: as on success, set then check: a log-out since
                // means nothing is paired.
                if store::wipe_epoch() != since {
                    clear_logged_out_memory(&state).await;
                    return Ok(RegisterResponse {
                        success: false,
                        error: Some(store::LOGGED_OUT_MEANWHILE_NOTICE.to_string()),
                        connection_id: None,
                        session_id: None,
                        expires_at: None,
                        key_protection: None,
                        paired_without_session: false,
                    });
                }
            }
            return Ok(RegisterResponse {
                success: false,
                error: Some(e.to_string()),
                connection_id: None,
                session_id: None,
                expires_at: None,
                key_protection: None,
                paired_without_session: paired,
            });
        }
    };

    *state.is_registered.write().await = true;
    let mut listener_conn_id: Option<String> = None;
    if let Ok((creds, _)) = pairing::load_saved(&config_dir).await {
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

    // #30: a log-out that ran after the save (its wipe removed it) cleared
    // memory before or after the lines above. If it may have been before,
    // what they set must go too: no connection, key or unlocked state is
    // kept for a pairing the log-out reported removed.
    if store::wipe_epoch() != since {
        clear_logged_out_memory(&state).await;
        return Ok(RegisterResponse {
            success: false,
            error: Some(store::LOGGED_OUT_MEANWHILE_NOTICE.to_string()),
            connection_id: None,
            session_id: None,
            expires_at: None,
            key_protection: None,
            paired_without_session: false,
        });
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
        key_protection: Some(outcome.binding.as_str().to_string()),
        paired_without_session: false,
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

    // #30: first. A log-out from here on means nothing stays unlocked.
    let since = store::wipe_epoch();
    // #43: likewise a lock, End session, or a session the vault ended.
    let resets_at_start = resets_now(&state);

    let config_dir = match store::default_config_dir() {
        Ok(dir) => dir,
        Err(e) => {
            return Ok(UnlockResponse {
                unlocked: false,
                notice: Some(e.to_string()),
            });
        }
    };

    // #15: an earlier build's pairing is deleted and revoked here; the
    // notice says whether the revoke was sent.
    let (creds, binding) = match crate::registration::pairing::load_saved(&config_dir).await {
        Ok(loaded) => loaded,
        Err(e @ (CredentialError::Unreadable | CredentialError::OldBuildRemoved { .. } | CredentialError::NoMachineId)) => {
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

    // #30: a log-out while this ran may have cleared memory before the
    // lines above set it; then clear it again. Logout's own response tells
    // the person what happened.
    if store::wipe_epoch() != since {
        clear_logged_out_memory(&state).await;
        return Ok(UnlockResponse {
            unlocked: false,
            notice: None,
        });
    }
    // #43: the same for a lock, End session, or a session the vault
    // ended while this ran: it stays locked, as that reset left it.
    if resets_now(&state) != resets_at_start {
        lock_memory(&state).await;
        return Ok(UnlockResponse {
            unlocked: false,
            notice: None,
        });
    }

    // Spawn the background NATS listener so device_op_response
    // envelopes get decrypted + matched to pending request_ids.
    // Without this, every vault op hits the 30-second timeout —
    // the request reaches the vault, the response is published
    // back to MessageSpace.{owner}.forOwner.device.{conn}, and
    // nobody's subscribed to it.
    crate::nats::listener::spawn_listener(app.clone(), connection_id).await;

    // Warn (never refuse) when another account can open the saved
    // pairing's folder or file (#24).
    Ok(UnlockResponse {
        unlocked: true,
        notice: store::privacy_warning(&config_dir, binding).map(str::to_string),
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
    // #30: first, before waiting for the lock. A log-out from here on
    // means the new session is not saved.
    let since = store::wipe_epoch();
    // #33: never overlaps End session; see AppState::session_op.
    let _session_op = state.session_op.lock().await;

    let config_dir = match store::default_config_dir() {
        Ok(dir) => dir,
        Err(e) => {
            return Ok(RegisterResponse {
                success: false,
                error: Some(e.to_string()),
                connection_id: None,
                session_id: None,
                expires_at: None,
                key_protection: None,
                paired_without_session: false,
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
                key_protection: None,
                paired_without_session: false,
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
        since,
    )
    .await
    {
        Ok(o) => o,
        Err(e) => {
            // #26: a refusal because the folder or file isn't private
            // points at Log out; pairing again into it wouldn't help.
            let error = match e {
                crate::registration::flow::RegistrationError::NotPrivate => {
                    store::not_private_extension_notice(&config_dir).to_string()
                }
                e => e.to_string(),
            };
            return Ok(RegisterResponse {
                success: false,
                error: Some(error),
                connection_id: None,
                session_id: None,
                expires_at: None,
                key_protection: None,
                paired_without_session: false,
            });
        }
    };

    // Refresh AppState with the rotated session. If the saved pairing
    // can't be read back, memory must not keep the old session as if it
    // were current (#33): clear it and report a failure.
    let mut listener_conn_id: Option<String> = None;
    let reloaded = match pairing::load_saved(&config_dir).await {
        Ok(loaded) => Some(loaded),
        Err(e) => {
            log::error!("extend_session: the new session was saved but couldn't be read back: {}", e);
            // #30: a log-out since (its wipe may be why it can't be read):
            // the pairing is gone, and so is anything in memory.
            if store::wipe_epoch() != since {
                clear_logged_out_memory(&state).await;
                return Ok(RegisterResponse {
                    success: false,
                    error: Some(store::LOGGED_OUT_MEANWHILE_NOTICE.to_string()),
                    connection_id: None,
                    session_id: None,
                    expires_at: None,
                    key_protection: None,
                    paired_without_session: false,
                });
            }
            // The disk must match what the person is told: the session
            // isn't treated as live at the next launch either. Not after a
            // log-out, whose marker it would no longer be (#30).
            if let Err(e) = store::end_saved_session_since(&config_dir, since) {
                log::error!("extend_session: could not remove the live marker: {}", e);
            }
            // As End session: the listener stopped, NATS disconnected, the
            // key zeroized, the credentials cleared (#40).
            clear_in_memory_session(&state).await;
            return Ok(RegisterResponse {
                success: false,
                error: Some(store::SESSION_NOT_RECORDED_NOTICE.to_string()),
                connection_id: None,
                session_id: None,
                expires_at: None,
                key_protection: None,
                paired_without_session: false,
            });
        }
    };
    if let Some((creds, _)) = reloaded {
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

    // #30: as in `register`.
    if store::wipe_epoch() != since {
        clear_logged_out_memory(&state).await;
        return Ok(RegisterResponse {
            success: false,
            error: Some(store::LOGGED_OUT_MEANWHILE_NOTICE.to_string()),
            connection_id: None,
            session_id: None,
            expires_at: None,
            key_protection: None,
            paired_without_session: false,
        });
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
        key_protection: Some(outcome.binding.as_str().to_string()),
        paired_without_session: false,
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

/// Log out: tell the vault to revoke this device, then wipe the on-disk
/// credential store and reset AppState. The local wipe happens even if the
/// revoke can't be sent; the response says whether it was, so the UI never
/// implies the vault was told when it wasn't.
#[tauri::command]
pub async fn logout(state: State<'_, AppState>) -> Result<LogoutResponse, String> {
    use crate::credential::store;
    use crate::registration::pairing;

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

    clear_logged_out_memory(&state).await;

    // Wipe the config directory entirely — nothing left on disk — and the
    // master key from the keyring too. A future pairing on this machine
    // will mint a fresh key — a leaked disk image from an earlier install
    // can't be decrypted under the new key.
    let local_wiped = wipe_local_pairing(config_dir.as_deref().ok());

    // #30: a pairing or Start New Session whose save ran just before the
    // wipe may have set memory since the clear above. Clear it again; one
    // that sets it after this sees the wipe and clears it itself.
    clear_logged_out_memory(&state).await;

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
pub async fn end_session(state: State<'_, AppState>) -> Result<EndSessionResponse, String> {
    use crate::credential::store;

    // #30: first. If a log-out wipes the pairing from here on, the saved
    // pairing isn't updated, even if a new one has been made since.
    let since = store::wipe_epoch();

    // The in-memory session ends at once, so nothing reports it as live
    // while this waits for the lock or tells the vault.
    clear_in_memory_session(&state).await;

    // #33: no Start New Session runs while this does, and one started
    // meanwhile waits until the end is done on disk and at the vault. A
    // Start New Session that was running holds the lock until it
    // finishes (up to its activation timeout), so memory is cleared again
    // once the lock is ours: anything it put back is ended too.
    let _session_op = state.session_op.lock().await;
    clear_in_memory_session(&state).await;

    // With no known folder there is no stored pairing to end or update.
    let notice = match store::default_config_dir() {
        Ok(config_dir) => end_session_on_disk(&config_dir, since).await,
        Err(e) => {
            log::warn!("end_session: {}; local reset only", e);
            None
        }
    };

    Ok(EndSessionResponse { notice })
}

/// #43: a memory reset is starting; see [`AppState::resets`]. First, before
/// anything is cleared.
fn count_reset(state: &AppState) {
    state.resets.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

/// The current reset count, for [`unlock`] to re-check.
fn resets_now(state: &AppState) -> u64 {
    state.resets.load(std::sync::atomic::Ordering::SeqCst)
}

/// #43: the vault ended this session (`session_update` expired or
/// revoked), or its time ran out: the same reset as End session, so the
/// key, the credentials, the listener and the connection go too, not only
/// the session state. `revoked` keeps the session marked revoked rather
/// than expired. Nothing on disk changes.
///
/// It stops the listener and waits for it to end, so the listener's own
/// handler must not await this: spawn it ([`end_session_from_vault_later`]).
pub(crate) async fn end_session_from_vault(state: &AppState, revoked: bool) {
    clear_in_memory_session(state).await;
    if revoked {
        state.session.write().await.revoke();
    }
}

/// [`end_session_from_vault`] on its own task, for callers that run inside
/// the listener.
pub(crate) fn end_session_from_vault_later(app: AppHandle, revoked: bool) {
    tokio::spawn(async move {
        let state = app.state::<AppState>();
        end_session_from_vault(state.inner(), revoked).await;
    });
}

/// #40: stop the background listener, then disconnect, holding the NATS
/// lock across both. A listener subscribes under that lock, so one spawned
/// meanwhile either subscribed before (and is stopped here) or subscribes
/// after, on a client that is no longer connected, and ends.
async fn stop_listener_and_disconnect(state: &AppState) {
    let mut nats = state.nats.lock().await;
    crate::nats::listener::stop_listener(state).await;
    nats.disconnect().await;
}

/// Log-out's memory reset: NATS, the connection key (zeroized), the
/// credentials, unlocked and registered, and the session (revoked).
async fn clear_logged_out_memory(state: &AppState) {
    use zeroize::Zeroize;
    count_reset(state);
    stop_listener_and_disconnect(state).await;
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
}

/// Drop the in-memory session: NATS, the connection key (zeroized), the
/// credentials and the session state.
async fn clear_in_memory_session(state: &AppState) {
    use zeroize::Zeroize;
    count_reset(state);
    stop_listener_and_disconnect(state).await;
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
}

/// What [`end_session`] tells the person. The session always ends in this
/// run; `notice` is set when that couldn't be recorded on this computer,
/// so the frontend shows it instead of "Session ended." (#26).
#[derive(Debug, Serialize)]
pub struct EndSessionResponse {
    pub notice: Option<String>,
}

/// The stored-pairing half of [`end_session`]: record on disk that the
/// session ended, tell the vault, then clear the session fields in the
/// saved pairing. Returns a notice if ending it couldn't be recorded.
async fn end_session_on_disk(
    config_dir: &std::path::Path,
    since: crate::credential::store::WipeEpoch,
) -> Option<String> {
    use crate::credential::store;
    use crate::registration::pairing;

    let config_dir = config_dir.to_path_buf();

    // #26: first, and needing no key: without the live marker the next
    // launch treats the session as ended, even if the save below is
    // refused (a folder that isn't private, an unreachable keyring).
    // #30: if a log-out has wiped the pairing since this started, the
    // pairing that ended is gone, and what is there now (if anything) was
    // made after it: leave it, and its session at the vault, alone.
    let marker_removed = match store::end_saved_session_since(&config_dir, since) {
        Ok(()) => true,
        Err(store::CredentialError::LoggedOutMeanwhile) => {
            log::warn!("end_session: logged out meanwhile; nothing more to end");
            // A pairing still there may be one the log-out failed to
            // remove, with this session's marker: then the next launch
            // could show it as open, so say so. It can't be told from a
            // new pairing, so the notice errs that way.
            return store::exists(&config_dir)
                .then(|| store::SESSION_END_NOT_RECORDED_NOTICE.to_string());
        }
        Err(e) => {
            log::error!("end_session: could not remove the live marker: {}", e);
            false
        }
    };
    let mut cleared_saved = false;

    // Tell the vault to end the session. publish_end_session flushes
    // before returning, within a deadline: on a clean return the
    // end-session frame was written to the connection. That is not a
    // confirmation from the vault. On error we still reset locally.
    // #30: checked again: a log-out (and a new pairing) may have run
    // since the marker was removed.
    if store::wipe_epoch() != since {
        log::warn!("end_session: logged out meanwhile; not telling the vault");
        return None;
    }
    // #15: if loading it found a pairing that can't be opened (an earlier
    // build's, now deleted and revoked), the person is told that, not
    // only that the session ended.
    let mut pairing_notice = None;
    if let Err(e) = pairing::publish_end_session(&config_dir, "user_locked").await {
        log::warn!("device.end-session publish failed (continuing with local reset): {}", e);
        if matches!(
            e,
            crate::registration::flow::RegistrationError::OldBuildRevoked
                | crate::registration::flow::RegistrationError::PairingUnreadable
        ) {
            pairing_notice = Some(e.to_string());
        }
    }

    // Persist the session-end to disk. The device stays PAIRED — the
    // device keypair, connection_key and NATS creds are untouched, so
    // "Start New Session" needs no re-pair — but the session fields
    // MUST be cleared here. get_session_info derives is_active purely
    // from the on-disk session_expires_at, so leaving it set meant a
    // relaunch reloaded a dead session: the desktop routed straight to
    // the vault and every op hung because the vault no longer had it.
    // #15: not if loading it above found a pairing that can't be opened:
    // there is nothing to clear, and an earlier build's file that couldn't
    // be deleted would only be revoked again.
    if pairing_notice.is_some() {
        return end_session_notice(pairing_notice, marker_removed, cleared_saved);
    }
    match pairing::load_saved(&config_dir).await {
        Ok((mut creds, _)) => {
            creds.session_id.clear();
            creds.session_expires_at = 0;
            creds.session_duration_seconds = 0;
            // Update only: if a log-out wiped the pairing since it was
            // loaded, nothing is written back (#28), and not over a new
            // pairing made after that log-out either (#30).
            if let Err(e) = store::save_existing(&config_dir, &creds, since) {
                log::error!("end_session: failed to persist cleared session state: {}", e);
            } else {
                cleared_saved = true;
                log::info!("end_session: on-disk session fields cleared (pairing preserved)");
            }
        }
        Err(e) => log::warn!(
            "end_session: could not load creds to clear on-disk session fields: {}", e
        ),
    }
    end_session_notice(pairing_notice, marker_removed, cleared_saved)
}

/// What End session tells the person: a notice about the pairing itself
/// first (#15), else whether the end was recorded (#26).
fn end_session_notice(pairing_notice: Option<String>, marker_removed: bool, cleared_saved: bool) -> Option<String> {
    if pairing_notice.is_some() {
        return pairing_notice;
    }
    // The old session comes back at the next launch only if both failed.
    if marker_removed || cleared_saved {
        None
    } else {
        Some(crate::credential::store::SESSION_END_NOT_RECORDED_NOTICE.to_string())
    }
}

/// Lock the session — clear credentials from memory.
/// SECURITY: Zeroizes key material before dropping.
#[tauri::command]
pub async fn lock(state: State<'_, AppState>) -> Result<bool, String> {
    lock_memory(&state).await;
    Ok(true)
}

/// [`lock`]'s work.
async fn lock_memory(state: &AppState) {
    use zeroize::Zeroize;
    count_reset(state);

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

    // #40: the listener, then NATS, under one lock.
    stop_listener_and_disconnect(state).await;

    // Reset session
    state.session.write().await.expire();
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

    let key_protection = {
        use crate::credential::store;
        match store::default_config_dir() {
            Ok(dir) => store::stored_key_protection(&dir),
            // With no known folder nothing can have been saved.
            Err(_) => "none",
        }
    }
    .to_string();

    Ok(AuthStatus {
        key_protection,
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

    /// #15: End session passes on a notice about the pairing; otherwise it
    /// speaks up only if the end couldn't be recorded at all.
    #[test]
    fn end_session_notice_prefers_the_pairing_notice() {
        use crate::credential::store::{OLD_BUILD_REVOKED_NOTICE, SESSION_END_NOT_RECORDED_NOTICE};
        let old = Some(OLD_BUILD_REVOKED_NOTICE.to_string());
        assert_eq!(end_session_notice(old.clone(), true, true), old);
        assert_eq!(end_session_notice(None, true, false), None);
        assert_eq!(end_session_notice(None, false, true), None);
        assert_eq!(end_session_notice(None, false, false), Some(SESSION_END_NOT_RECORDED_NOTICE.to_string()));
    }

    /// #40: logout's and End session's memory resets and lock each stop the
    /// background listener: its task ends and the slot is empty.
    #[tokio::test]
    async fn logout_end_session_and_lock_stop_the_listener() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        struct Held(Arc<AtomicBool>);
        impl Drop for Held {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        for which in ["logout", "end session", "lock"] {
            let state = AppState::new();
            let dropped = Arc::new(AtomicBool::new(false));
            let held = Held(dropped.clone());
            *state.listener_handle.lock().await = Some(tokio::spawn(async move {
                let _held = held;
                std::future::pending::<()>().await;
            }));
            match which {
                "logout" => clear_logged_out_memory(&state).await,
                "end session" => clear_in_memory_session(&state).await,
                _ => lock_memory(&state).await,
            }
            assert!(dropped.load(Ordering::SeqCst), "{which}: the listener task ended");
            assert!(state.listener_handle.lock().await.is_none(), "{which}: the slot is empty");
        }
    }

    /// #43: every memory reset is counted, so an unlock that one overtook
    /// can tell.
    #[tokio::test]
    async fn every_reset_is_counted() {
        let state = AppState::new();
        let before = resets_now(&state);
        clear_logged_out_memory(&state).await;
        clear_in_memory_session(&state).await;
        lock_memory(&state).await;
        end_session_from_vault(&state, false).await;
        assert_eq!(resets_now(&state), before + 4);
    }

    /// #43: a session the vault ended takes the key, the credentials and
    /// the listener with it; a revoked one stays marked revoked.
    #[tokio::test]
    async fn a_session_the_vault_ended_is_cleared_from_memory() {
        use crate::session::manager::SessionState;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        struct Held(Arc<AtomicBool>);
        impl Drop for Held {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        for revoked in [false, true] {
            let state = AppState::new();
            *state.connection_key.write().await = Some([9u8; 32]);
            *state.is_unlocked.write().await = true;
            let dropped = Arc::new(AtomicBool::new(false));
            let held = Held(dropped.clone());
            *state.listener_handle.lock().await = Some(tokio::spawn(async move {
                let _held = held;
                std::future::pending::<()>().await;
            }));
            end_session_from_vault(&state, revoked).await;
            assert!(state.connection_key.read().await.is_none());
            assert!(!*state.is_unlocked.read().await);
            assert!(dropped.load(Ordering::SeqCst), "the listener ended");
            let want = if revoked { SessionState::Revoked } else { SessionState::Expired };
            assert_eq!(state.session.read().await.state(), want);
        }
    }

    /// #43: the listener's handler can't await the reset (it would wait
    /// for itself). A reset spawned from inside the listener, as the
    /// handler does, stops it without hanging.
    #[tokio::test]
    async fn a_reset_spawned_from_inside_the_listener_stops_it() {
        use std::sync::Arc;
        let state = Arc::new(AppState::new());
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let state2 = state.clone();
        let slot = state.listener_handle.clone();
        let mut guard = slot.lock().await;
        *guard = Some(tokio::spawn(async move {
            let state3 = state2.clone();
            tokio::spawn(async move {
                end_session_from_vault(&state3, true).await;
                let _ = done_tx.send(());
            });
            std::future::pending::<()>().await;
        }));
        drop(guard);
        tokio::time::timeout(std::time::Duration::from_secs(5), done_rx)
            .await
            .expect("the reset finished")
            .unwrap();
        assert!(state.listener_handle.lock().await.is_none());
    }

    /// #40: a listener spawned while a reset is under way (an unlock
    /// racing lock) never subscribes on the live client. The reset holds
    /// the NATS lock from before its stop until after its disconnect, so a
    /// listener tracked meanwhile is stopped while it waits for that lock.
    /// With the stop outside the lock, the stop would find no listener and
    /// this one would subscribe before the disconnect.
    #[tokio::test]
    async fn a_listener_spawned_during_a_reset_never_subscribes() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        let state = Arc::new(AppState::new());
        let subscribed = Arc::new(AtomicBool::new(false));
        // Something else holds the NATS lock, so the reset queues for it.
        let busy = state.nats.lock().await;
        let reset = {
            let state = state.clone();
            tokio::spawn(async move { stop_listener_and_disconnect(&state).await })
        };
        tokio::task::yield_now().await;
        // A listener is spawned and tracked, and queues to subscribe.
        let (state2, subscribed2) = (state.clone(), subscribed.clone());
        *state.listener_handle.lock().await = Some(tokio::spawn(async move {
            let _nats = state2.nats.lock().await;
            subscribed2.store(true, Ordering::SeqCst);
        }));
        tokio::task::yield_now().await;
        drop(busy);
        reset.await.unwrap();
        tokio::task::yield_now().await;
        assert!(!subscribed.load(Ordering::SeqCst), "it never subscribed");
        assert!(state.listener_handle.lock().await.is_none());
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
