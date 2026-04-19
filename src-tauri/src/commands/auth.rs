use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};

use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct AuthStatus {
    pub is_registered: bool,
    pub is_unlocked: bool,
    pub has_active_session: bool,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    /// 8-char code the user typed in from the phone app.
    pub invite_code: String,
    /// Passphrase for encrypting the on-disk credential store.
    pub passphrase: String,
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

/// Pair this desktop with a vault via an 8-char invite code typed by the user.
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

    let config_dir = store::default_config_dir();
    std::fs::create_dir_all(&config_dir)
        .map_err(|e| format!("Failed to create config dir: {}", e))?;

    let invite_code = request.invite_code.trim().to_string();
    if invite_code.len() != 8 {
        return Ok(RegisterResponse {
            success: false,
            error: Some("Invite code must be 8 characters".to_string()),
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
        &request.passphrase,
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
    if let Ok((creds, _)) = store::load_with_tolerance(&config_dir, &request.passphrase) {
        if creds.connection_key.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&creds.connection_key);
            *state.connection_key.write().await = Some(key);
        }
        *state.credentials.write().await = Some(creds);
        *state.is_unlocked.write().await = true;
    }

    Ok(RegisterResponse {
        success: true,
        error: None,
        connection_id: Some(outcome.connection_id),
        session_id: Some(outcome.session_id),
        expires_at: Some(outcome.expires_at),
    })
}

fn collect_device_fingerprint() -> crate::registration::pairing::DeviceFingerprint {
    use crate::fingerprint::binary::binary_fingerprint;
    use crate::registration::pairing::DeviceFingerprint;

    let hostname = hostname::get()
        .ok()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_default();
    let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let binary_fp = binary_fingerprint().unwrap_or_default();
    // Machine fingerprint derivation is done by the platform_key module, which
    // returns a key rather than the raw fingerprint. For now we leave this
    // empty; the binary fingerprint gives the user enough to verify identity.
    let machine_fp = String::new();

    DeviceFingerprint {
        hostname,
        platform,
        os_name: std::env::consts::OS.to_string(),
        os_version: String::new(),
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        binary_fingerprint: binary_fp,
        machine_fingerprint: machine_fp,
    }
}

/// Unlock the credential store with passphrase.
///
/// Loads the encrypted connection.enc file using passphrase + platform key.
/// Uses 4-of-5 fingerprint tolerance for hardware changes.
/// Populates AppState with credentials and connection key.
#[tauri::command]
pub async fn unlock(state: State<'_, AppState>, passphrase: String) -> Result<bool, String> {
    use crate::credential::store;

    let config_dir = store::default_config_dir();

    let (creds, _re_encrypted) = store::load_with_tolerance(&config_dir, &passphrase)
        .map_err(|e| format!("Failed to unlock: {}", e))?;

    // Load connection key (stored as raw bytes in ConnectionCredentials)
    if creds.connection_key.len() == 32 {
        let mut key = [0u8; 32];
        key.copy_from_slice(&creds.connection_key);
        *state.connection_key.write().await = Some(key);
    }

    // Reconnect NATS if we have the connection info
    if !creds.message_space_url.is_empty() && !creds.message_space_token.is_empty() {
        let mut nats = state.nats.lock().await;
        if let Err(e) = nats
            .connect(
                &creds.message_space_url,
                &creds.message_space_token,
                &creds.owner_guid,
            )
            .await
        {
            log::warn!("Failed to reconnect NATS on unlock: {}", e);
            // Don't fail unlock if NATS reconnect fails — user can retry
        }
    }

    *state.credentials.write().await = Some(creds);
    *state.is_unlocked.write().await = true;

    Ok(true)
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
    passphrase: String,
) -> Result<RegisterResponse, String> {
    use crate::credential::store;
    use crate::registration::pairing;

    let config_dir = store::default_config_dir();

    let (session, runtime) = match pairing::start_extension(&config_dir, &passphrase).await {
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
        &passphrase,
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
    if let Ok((creds, _)) = store::load_with_tolerance(&config_dir, &passphrase) {
        if creds.connection_key.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&creds.connection_key);
            *state.connection_key.write().await = Some(key);
        }
        *state.credentials.write().await = Some(creds);
    }

    Ok(RegisterResponse {
        success: true,
        error: None,
        connection_id: Some(outcome.connection_id),
        session_id: Some(outcome.session_id),
        expires_at: Some(outcome.expires_at),
    })
}

/// Log out: tell the vault to revoke this device, then wipe the on-disk
/// credential store and reset AppState. Returns even if the revoke publish
/// fails — we want the local wipe to happen regardless.
#[tauri::command]
pub async fn logout(state: State<'_, AppState>, passphrase: String) -> Result<bool, String> {
    use crate::credential::store;
    use crate::registration::pairing;
    use zeroize::Zeroize;

    let config_dir = store::default_config_dir();

    // Best-effort revoke. Ignore errors: the vault may be unreachable or the
    // creds may already be invalid — local wipe still has to happen.
    if let Err(e) = pairing::publish_revoke(&config_dir, &passphrase).await {
        log::warn!("device.revoke publish failed (continuing with local wipe): {}", e);
    }

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
    if config_dir.exists() {
        if let Err(e) = std::fs::remove_dir_all(&config_dir) {
            log::warn!("Failed to remove config dir on logout: {}", e);
            // Fall back to best-effort removal of known files
            let _ = std::fs::remove_file(config_dir.join("connection.enc"));
        }
    }

    Ok(true)
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
        store::exists(&store::default_config_dir())
    } else {
        is_registered
    };

    Ok(AuthStatus {
        is_registered,
        is_unlocked,
        has_active_session,
    })
}
