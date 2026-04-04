use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock, oneshot};

use crate::credential::store::ConnectionCredentials;
use crate::nats::client::NatsClient;
use crate::session::delegation::DelegationManager;
use crate::session::manager::SessionManager;

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
    /// The background listener resolves these when a matching response arrives.
    pub pending_responses: Arc<Mutex<HashMap<String, oneshot::Sender<serde_json::Value>>>>,
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
        }
    }
}
