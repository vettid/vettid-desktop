use serde::Serialize;
use std::sync::{Arc, RwLock};

use crate::nats::messages::DeviceSessionInfo;

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum SessionState {
    /// No active session.
    Inactive,
    /// Session is live and valid until `expires_at` (Unix timestamp).
    Active {
        expires_at: i64,
        session_id: String,
    },
    /// Session is temporarily suspended (phone unreachable).
    Suspended,
    /// Session TTL has elapsed.
    Expired,
    /// Session was explicitly revoked by the vault owner.
    Revoked,
}

// ---------------------------------------------------------------------------
// Session manager
// ---------------------------------------------------------------------------

pub struct SessionManager {
    state: Arc<RwLock<SessionState>>,
    session_info: Option<DeviceSessionInfo>,
}

impl SessionManager {
    /// Create a new, inactive session manager.
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(SessionState::Inactive)),
            session_info: None,
        }
    }

    /// Return a snapshot of the current session state.
    pub fn state(&self) -> SessionState {
        self.state.read().expect("session state lock poisoned").clone()
    }

    /// Activate the session using the information received during registration.
    pub fn activate(&mut self, session: DeviceSessionInfo) {
        let new_state = SessionState::Active {
            expires_at: session.expires_at,
            session_id: session.session_id.clone(),
        };
        *self.state.write().expect("session state lock poisoned") = new_state;
        self.session_info = Some(session);
        log::info!("Session activated");
    }

    /// Suspend the session (e.g., phone became unreachable).
    pub fn suspend(&mut self) {
        *self.state.write().expect("session state lock poisoned") = SessionState::Suspended;
        log::info!("Session suspended");
    }

    /// Mark the session as expired.
    pub fn expire(&mut self) {
        *self.state.write().expect("session state lock poisoned") = SessionState::Expired;
        log::info!("Session expired");
    }

    /// Mark the session as revoked.
    pub fn revoke(&mut self) {
        *self.state.write().expect("session state lock poisoned") = SessionState::Revoked;
        log::info!("Session revoked");
    }

    /// Resume a suspended session (phone is back).
    pub fn resume(&mut self) {
        let current = self.state();
        if current == SessionState::Suspended {
            if let Some(ref info) = self.session_info {
                let new_state = SessionState::Active {
                    expires_at: info.expires_at,
                    session_id: info.session_id.clone(),
                };
                *self.state.write().expect("session state lock poisoned") = new_state;
                log::info!("Session resumed");
            }
        }
    }

    /// Return `true` if the session is currently active and not expired.
    pub fn is_active(&self) -> bool {
        let state = self.state();
        match state {
            SessionState::Active { expires_at, .. } => {
                let now = chrono::Utc::now().timestamp();
                now < expires_at
            }
            _ => false,
        }
    }

    /// Return the number of seconds remaining until the session expires,
    /// or `None` if the session is not active.
    pub fn seconds_remaining(&self) -> Option<i64> {
        let state = self.state();
        match state {
            SessionState::Active { expires_at, .. } => {
                let now = chrono::Utc::now().timestamp();
                let remaining = expires_at - now;
                Some(remaining.max(0))
            }
            _ => None,
        }
    }

    /// Return a reference to the full session info, if available.
    pub fn session_info(&self) -> Option<&DeviceSessionInfo> {
        self.session_info.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session_info(expires_at: i64) -> DeviceSessionInfo {
        DeviceSessionInfo {
            session_id: "sess-001".to_string(),
            status: "active".to_string(),
            expires_at,
            ttl_hours: 24,
            capabilities: vec!["profile.view".to_string()],
            requires_phone: vec!["secrets.retrieve".to_string()],
        }
    }

    #[test]
    fn test_new_session_is_inactive() {
        let mgr = SessionManager::new();
        assert_eq!(mgr.state(), SessionState::Inactive);
        assert!(!mgr.is_active());
        assert_eq!(mgr.seconds_remaining(), None);
    }

    #[test]
    fn test_activate_session() {
        let mut mgr = SessionManager::new();
        let future = chrono::Utc::now().timestamp() + 3600;
        mgr.activate(make_session_info(future));
        assert!(mgr.is_active());
        assert!(mgr.seconds_remaining().unwrap() > 0);
    }

    #[test]
    fn test_suspend_and_resume() {
        let mut mgr = SessionManager::new();
        let future = chrono::Utc::now().timestamp() + 3600;
        mgr.activate(make_session_info(future));
        mgr.suspend();
        assert_eq!(mgr.state(), SessionState::Suspended);
        assert!(!mgr.is_active());
        mgr.resume();
        assert!(mgr.is_active());
    }

    #[test]
    fn test_expire_session() {
        let mut mgr = SessionManager::new();
        let future = chrono::Utc::now().timestamp() + 3600;
        mgr.activate(make_session_info(future));
        mgr.expire();
        assert_eq!(mgr.state(), SessionState::Expired);
        assert!(!mgr.is_active());
    }

    #[test]
    fn test_revoke_session() {
        let mut mgr = SessionManager::new();
        let future = chrono::Utc::now().timestamp() + 3600;
        mgr.activate(make_session_info(future));
        mgr.revoke();
        assert_eq!(mgr.state(), SessionState::Revoked);
        assert!(!mgr.is_active());
    }
}
