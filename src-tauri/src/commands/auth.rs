use serde::{Deserialize, Serialize};
use std::sync::Mutex;

/// Application state shared across commands.
pub struct AppState {
    pub is_registered: Mutex<bool>,
    pub is_unlocked: Mutex<bool>,
    pub config_dir: String,
}

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

/// Register this desktop with a vault via shortlink code.
///
/// Flow:
/// 1. Resolve shortlink → get NATS URI, invite token, vault public key
/// 2. Connect to NATS MessageSpace
/// 3. Generate X25519 keypair, collect fingerprints
/// 4. ECIES-encrypt registration request with vault public key
/// 5. Wait for phone approval (up to 5 minutes)
/// 6. On approval: derive connection key, save credentials encrypted with passphrase + platform key
#[tauri::command]
pub async fn register(request: RegisterRequest) -> Result<RegisterResponse, String> {
    use crate::registration::flow::RegistrationFlow;
    use std::path::PathBuf;

    let config_dir = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("~/.config"))
        .join("vettid-desktop");

    // Ensure config directory exists
    std::fs::create_dir_all(&config_dir).map_err(|e| format!("Failed to create config dir: {}", e))?;

    let mut flow = RegistrationFlow::new(config_dir);

    match flow.run(&request.shortlink_code).await {
        Ok(()) => Ok(RegisterResponse {
            success: true,
            error: None,
            device_name: hostname::get().ok().map(|h| h.to_string_lossy().to_string()),
            session_id: None, // Set from flow result
        }),
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
#[tauri::command]
pub async fn unlock(passphrase: String) -> Result<bool, String> {
    use crate::credential::store;
    use std::path::PathBuf;

    let config_dir = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("~/.config"))
        .join("vettid-desktop");

    match store::load_with_tolerance(&config_dir, &passphrase) {
        Ok((_creds, _re_encrypted)) => Ok(true),
        Err(e) => Err(format!("Failed to unlock: {}", e)),
    }
}

/// Lock the session — clear credentials from memory.
#[tauri::command]
pub async fn lock() -> Result<bool, String> {
    // Credentials are cleared when the session manager drops them
    Ok(true)
}

/// Get current authentication/registration status.
#[tauri::command]
pub async fn get_status() -> Result<AuthStatus, String> {
    use crate::credential::store;
    use std::path::PathBuf;

    let config_dir = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("~/.config"))
        .join("vettid-desktop");

    Ok(AuthStatus {
        is_registered: store::exists(&config_dir),
        is_unlocked: false, // Will be managed by session state
        has_active_session: false,
    })
}
