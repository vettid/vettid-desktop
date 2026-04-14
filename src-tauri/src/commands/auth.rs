use serde::{Deserialize, Serialize};
use tauri::State;

use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct AuthStatus {
    pub is_registered: bool,
    pub is_unlocked: bool,
    pub has_active_session: bool,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub shortlink_code: String,
    pub passphrase: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub success: bool,
    pub error: Option<String>,
    pub device_name: Option<String>,
    pub session_id: Option<String>,
}

/// Register this desktop with a vault via invite code.
///
/// Uses the same connection pattern as peer-to-peer connections:
/// 1. Resolve invite code → get NATS credentials, connection info
/// 2. Connect to NATS with invitation JWT+seed
/// 3. Store credentials (like a peer accepting an invitation)
/// 4. Wait for key exchange and activation
/// 5. Save encrypted credentials with passphrase + platform key
#[tauri::command]
pub async fn register(
    state: State<'_, AppState>,
    request: RegisterRequest,
) -> Result<RegisterResponse, String> {
    use crate::credential::store;
    use crate::registration::flow::RegistrationFlow;

    let config_dir = store::default_config_dir();

    // Ensure config directory exists
    std::fs::create_dir_all(&config_dir)
        .map_err(|e| format!("Failed to create config dir: {}", e))?;

    let mut flow = RegistrationFlow::new(config_dir.clone());

    match flow.run(&request.shortlink_code, &request.passphrase).await {
        Ok(()) => {
            // Mark as registered
            *state.is_registered.write().await = true;

            // Load and populate credentials into shared state
            match crate::credential::store::load_with_tolerance(&config_dir, &request.passphrase) {
                Ok((creds, _)) => {
                    // Decode connection key from hex
                    if let Ok(key_bytes) = hex::decode(&creds.connection_key) {
                        if key_bytes.len() == 32 {
                            let mut key = [0u8; 32];
                            key.copy_from_slice(&key_bytes);
                            *state.connection_key.write().await = Some(key);
                        }
                    }

                    // Activate session if session_id is present
                    if !creds.session_id.is_empty() {
                        // Session will be activated when we receive session info from vault
                    }

                    let device_name = creds.owner_name.clone();
                    *state.credentials.write().await = Some(creds);
                    *state.is_unlocked.write().await = true;

                    Ok(RegisterResponse {
                        success: true,
                        error: None,
                        device_name: Some(
                            hostname::get()
                                .ok()
                                .map(|h| h.to_string_lossy().to_string())
                                .unwrap_or_else(|| device_name),
                        ),
                        session_id: None,
                    })
                }
                Err(_) => Ok(RegisterResponse {
                    success: true,
                    error: None,
                    device_name: hostname::get()
                        .ok()
                        .map(|h| h.to_string_lossy().to_string()),
                    session_id: None,
                }),
            }
        }
        Err(e) => Ok(RegisterResponse {
            success: false,
            error: Some(e.to_string()),
            device_name: None,
            session_id: None,
        }),
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
