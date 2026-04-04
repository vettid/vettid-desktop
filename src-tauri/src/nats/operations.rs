use std::fmt;
use std::time::Duration;
use tokio::sync::oneshot;

use crate::crypto::encrypt;
use crate::nats::messages::{
    encode_envelope, DeviceOpRequest, DeviceOpResponse, MSG_DEVICE_OP_REQUEST,
};
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum OperationError {
    NotConnected,
    NoConnectionKey,
    EncryptionFailed(String),
    EncodingFailed(String),
    PublishFailed(String),
    Timeout,
    ResponseError(String),
}

impl fmt::Display for OperationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotConnected => write!(f, "Not connected to vault"),
            Self::NoConnectionKey => write!(f, "No connection key available"),
            Self::EncryptionFailed(e) => write!(f, "Encryption failed: {}", e),
            Self::EncodingFailed(e) => write!(f, "Encoding failed: {}", e),
            Self::PublishFailed(e) => write!(f, "Publish failed: {}", e),
            Self::Timeout => write!(f, "Operation timed out"),
            Self::ResponseError(e) => write!(f, "Response error: {}", e),
        }
    }
}

impl std::error::Error for OperationError {}

// ---------------------------------------------------------------------------
// Execute a vault operation via NATS
// ---------------------------------------------------------------------------

/// Send a `device_op_request` to the vault and await the response.
///
/// 1. Builds a DeviceOpRequest with a unique request_id
/// 2. Encrypts the payload with the connection key
/// 3. Wraps in an Envelope and publishes via NATS
/// 4. Registers a oneshot channel in AppState.pending_responses
/// 5. Awaits the response (background listener resolves it) with timeout
pub async fn execute_operation(
    state: &AppState,
    operation: &str,
    params: serde_json::Value,
    timeout_secs: u64,
) -> Result<DeviceOpResponse, OperationError> {
    // Read connection key
    let connection_key = {
        let key_guard = state.connection_key.read().await;
        key_guard.ok_or(OperationError::NoConnectionKey)?
    };

    // Read credentials for connection_id and key_id
    let (connection_id, key_id) = {
        let creds_guard = state.credentials.read().await;
        let creds = creds_guard.as_ref().ok_or(OperationError::NotConnected)?;
        (creds.connection_id.clone(), creds.key_id.clone())
    };

    // Build the request
    let request_id = hex::encode(crate::crypto::keys::generate_random_bytes(16));
    let request = DeviceOpRequest {
        request_id: request_id.clone(),
        operation: operation.to_string(),
        connection_id: connection_id.clone(),
        params,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    // Serialize the request to JSON
    let request_json = serde_json::to_vec(&request)
        .map_err(|e| OperationError::EncodingFailed(e.to_string()))?;

    // Encrypt with connection key
    let encrypted = encrypt::encrypt(&connection_key, &request_json)
        .map_err(|e| OperationError::EncryptionFailed(e.to_string()))?;

    // Wrap in envelope
    let nats_client = state.nats.lock().await;
    let sequence = nats_client.next_sequence();
    let envelope_bytes = encode_envelope(
        MSG_DEVICE_OP_REQUEST,
        &key_id,
        &encrypted,
        sequence,
    )
    .map_err(|e| OperationError::EncodingFailed(e.to_string()))?;

    // Register a pending response channel
    let (tx, rx) = oneshot::channel();
    {
        let mut pending = state.pending_responses.lock().await;
        pending.insert(request_id.clone(), tx);
    }

    // Publish
    nats_client
        .publish_message(&envelope_bytes)
        .await
        .map_err(|e| OperationError::PublishFailed(e.to_string()))?;

    drop(nats_client);

    // Await response with timeout
    let response_value = tokio::time::timeout(Duration::from_secs(timeout_secs), rx)
        .await
        .map_err(|_| {
            // Clean up the pending entry on timeout
            let pending = state.pending_responses.clone();
            let rid = request_id.clone();
            tokio::spawn(async move {
                pending.lock().await.remove(&rid);
            });
            OperationError::Timeout
        })?
        .map_err(|_| OperationError::ResponseError("Response channel closed".to_string()))?;

    // Parse as DeviceOpResponse
    let response: DeviceOpResponse = serde_json::from_value(response_value)
        .map_err(|e| OperationError::ResponseError(e.to_string()))?;

    Ok(response)
}

/// Convenience wrapper with default 30-second timeout.
pub async fn execute(
    state: &AppState,
    operation: &str,
    params: serde_json::Value,
) -> Result<DeviceOpResponse, OperationError> {
    execute_operation(state, operation, params, 30).await
}
