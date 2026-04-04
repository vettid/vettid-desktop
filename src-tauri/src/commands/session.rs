use serde::Serialize;
use tauri::State;

use crate::session::manager::SessionState;
use crate::state::AppState;

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

/// Get current session status from the SessionManager.
#[tauri::command]
pub async fn get_session_status(state: State<'_, AppState>) -> Result<SessionStatus, String> {
    let session_mgr = state.session.read().await;
    let current = session_mgr.state();

    match current {
        SessionState::Active { expires_at, session_id } => {
            let remaining = session_mgr.seconds_remaining().unwrap_or(0);
            let info = session_mgr.session_info();

            Ok(SessionStatus {
                state: "active".to_string(),
                session_id: Some(session_id),
                expires_at: Some(expires_at),
                seconds_remaining: Some(remaining),
                extended_count: info.map(|i| i.ttl_hours), // TODO: track extensions
                max_extensions: Some(3),
                phone_reachable: true, // TODO: track from heartbeat
            })
        }
        SessionState::Suspended => Ok(SessionStatus {
            state: "suspended".to_string(),
            session_id: None,
            expires_at: None,
            seconds_remaining: None,
            extended_count: None,
            max_extensions: None,
            phone_reachable: false,
        }),
        SessionState::Expired => Ok(SessionStatus {
            state: "expired".to_string(),
            session_id: None,
            expires_at: None,
            seconds_remaining: None,
            extended_count: None,
            max_extensions: None,
            phone_reachable: false,
        }),
        SessionState::Revoked => Ok(SessionStatus {
            state: "revoked".to_string(),
            session_id: None,
            expires_at: None,
            seconds_remaining: None,
            extended_count: None,
            max_extensions: None,
            phone_reachable: false,
        }),
        SessionState::Inactive => Ok(SessionStatus {
            state: "inactive".to_string(),
            session_id: None,
            expires_at: None,
            seconds_remaining: None,
            extended_count: None,
            max_extensions: None,
            phone_reachable: false,
        }),
    }
}

/// Get session timer for countdown display.
#[tauri::command]
pub async fn get_session_timer(state: State<'_, AppState>) -> Result<SessionTimer, String> {
    let session_mgr = state.session.read().await;
    let remaining = session_mgr.seconds_remaining().unwrap_or(0);

    let expires_at = match session_mgr.state() {
        SessionState::Active { expires_at, .. } => expires_at,
        _ => chrono::Utc::now().timestamp(),
    };

    Ok(SessionTimer {
        seconds_remaining: remaining,
        expires_at,
        warn_30min: remaining <= 1800 && remaining > 0,
        warn_5min: remaining <= 300 && remaining > 0,
    })
}
