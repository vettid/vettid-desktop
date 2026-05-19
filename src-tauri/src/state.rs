use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::task::JoinHandle;

use crate::credential::store::ConnectionCredentials;
use crate::nats::client::NatsClient;
use crate::session::delegation::DelegationManager;
use crate::session::manager::SessionManager;

#[cfg(feature = "webrtc")]
use crate::webrtc::CallSession;

// ---------------------------------------------------------------------------
// Central application state — managed by Tauri
// ---------------------------------------------------------------------------

pub struct AppState {
    /// NATS client for vault communication.
    pub nats: Arc<Mutex<NatsClient>>,

    /// Session state machine.
    pub session: Arc<RwLock<SessionManager>>,

    /// Pending phone-approval tracker.
    pub delegation: Arc<Mutex<DelegationManager>>,

    /// Loaded connection credentials (after unlock).
    pub credentials: Arc<RwLock<Option<ConnectionCredentials>>>,

    /// Derived connection key for encrypting/decrypting vault messages.
    pub connection_key: Arc<RwLock<Option<[u8; 32]>>>,

    /// Whether the user is registered (credential file exists).
    pub is_registered: Arc<RwLock<bool>>,

    /// Whether credentials are currently unlocked in memory.
    pub is_unlocked: Arc<RwLock<bool>>,

    /// Pending operation response channels, keyed by request_id.
    ///
    /// Multi-shot (mpsc) rather than oneshot because phone-required ops
    /// produce TWO vault responses against the same request_id: an
    /// immediate `status: "pending_approval"` ack, then the eventual
    /// final response after the human taps approve/deny on their phone.
    /// A oneshot would close after the ack and silently drop the
    /// final result. The receiver side filters: it forwards the ack
    /// to the UI as an event and waits for the final response.
    pub pending_responses: Arc<Mutex<HashMap<String, mpsc::UnboundedSender<serde_json::Value>>>>,

    /// Handle to the currently running background NATS listener task.
    /// Held so callers that re-spawn the listener (unlock,
    /// extend_session, register) can abort the previous one first.
    /// Without this, each re-spawn stacked another subscriber on the
    /// same subjects and every response was processed N times, which
    /// poisoned multi-shot ops (the second listener's duplicate ack
    /// got mistaken for the final response).
    pub listener_handle: Arc<Mutex<Option<JoinHandle<()>>>>,

    /// Currently active WebRTC call session, if any. Only one call at a time
    /// — multi-call (call-waiting) would warrant a HashMap keyed by call_id,
    /// but the Android app is single-call and we follow that model.
    #[cfg(feature = "webrtc")]
    pub active_call: Arc<Mutex<Option<Arc<CallSession>>>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            nats: Arc::new(Mutex::new(NatsClient::new())),
            session: Arc::new(RwLock::new(SessionManager::new())),
            delegation: Arc::new(Mutex::new(DelegationManager::new())),
            credentials: Arc::new(RwLock::new(None)),
            connection_key: Arc::new(RwLock::new(None)),
            is_registered: Arc::new(RwLock::new(false)),
            is_unlocked: Arc::new(RwLock::new(false)),
            pending_responses: Arc::new(Mutex::new(HashMap::new())),
            listener_handle: Arc::new(Mutex::new(None)),
            #[cfg(feature = "webrtc")]
            active_call: Arc::new(Mutex::new(None)),
        }
    }
}
