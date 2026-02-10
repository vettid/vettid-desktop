use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct SessionStatus {
    pub state: String,
    pub session_id: Option<String>,
    pub expires_at: Option<i64>,
    pub seconds_remaining: Option<i64>,
    pub extended_count: Option<i32>,
    pub max_extensions: Option<i32>,
    pub phone_reachable: bool,
}

#[derive(Debug, Serialize)]
pub struct SessionTimer {
    pub seconds_remaining: i64,
    pub expires_at: i64,
    pub warn_30min: bool,
    pub warn_5min: bool,
}

/// Get current session status.
#[tauri::command]
pub async fn get_session_status() -> Result<SessionStatus, String> {
    // TODO: Read from SessionManager state
    Ok(SessionStatus {
        state: "inactive".to_string(),
        session_id: None,
        expires_at: None,
        seconds_remaining: None,
        extended_count: None,
        max_extensions: None,
        phone_reachable: false,
    })
}

/// Get session timer for countdown display.
#[tauri::command]
pub async fn get_session_timer() -> Result<SessionTimer, String> {
    // TODO: Calculate from SessionManager
    let now = chrono::Utc::now().timestamp();
    Ok(SessionTimer {
        seconds_remaining: 0,
        expires_at: now,
        warn_30min: false,
        warn_5min: false,
    })
}
