use futures::StreamExt;
use std::sync::Arc;
use tauri::{AppHandle, Emitter};

use crate::crypto::encrypt;
use crate::nats::messages::{decode_envelope, MSG_DEVICE_OP_RESPONSE};
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Background NATS listener
// ---------------------------------------------------------------------------

/// Spawn a background task that subscribes to the device's NATS response topic
/// and routes incoming messages:
///
/// - `device_op_response` → resolves pending operation via oneshot channel
/// - `session_update` → updates SessionManager, emits Tauri event
/// - `feed_event` → emits `vault:feed-event` Tauri event
/// - `new_message` → emits `vault:message-received` Tauri event
/// - `phone_approval_result` → resolves delegation, emits event
pub fn spawn_listener(
    app_handle: AppHandle,
    state: Arc<AppState>,
    connection_id: String,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let subscription = {
            let nats = state.nats.lock().await;
            match nats.subscribe_responses(&connection_id).await {
                Ok(sub) => sub,
                Err(e) => {
                    log::error!("Failed to subscribe for responses: {}", e);
                    return;
                }
            }
        };

        log::info!("Background listener started for connection {}", connection_id);

        let mut stream = subscription;
        while let Some(msg) = stream.next().await {
            if let Err(e) = handle_message(&app_handle, &state, &msg.payload).await {
                log::warn!("Failed to handle incoming message: {}", e);
            }
        }

        // Listener ended — drain all pending response channels so waiting
        // operations fail immediately instead of timing out one-by-one.
        {
            let mut pending = state.pending_responses.lock().await;
            let count = pending.len();
            pending.clear();
            if count > 0 {
                log::warn!("Listener ended: dropped {} pending response channels", count);
            }
        }

        let _ = app_handle.emit("vault:nats-disconnected", &serde_json::json!({
            "reason": "listener ended",
        }));

        log::info!("Background listener ended for connection {}", connection_id);
    })
}

async fn handle_message(
    app_handle: &AppHandle,
    state: &AppState,
    raw: &[u8],
) -> Result<(), String> {
    // Try to decode as envelope
    let envelope = decode_envelope(raw).map_err(|e| format!("decode: {}", e))?;

    // Decrypt the payload based on message type.
    // device_op_response MUST be encrypted; other types may be unencrypted.
    let payload_data = match envelope.msg_type.as_str() {
        MSG_DEVICE_OP_RESPONSE => {
            // Encrypted message — must decrypt
            let key_guard = state.connection_key.read().await;
            let key = key_guard.as_ref().ok_or("No connection key for encrypted message".to_string())?;
            let ciphertext = extract_bytes(&envelope.payload)?;
            let plaintext = encrypt::decrypt(key, &ciphertext)
                .map_err(|e| format!("Decryption failed for device_op_response: {}", e))?;
            serde_json::from_slice(&plaintext)
                .map_err(|e| format!("Parse decrypted payload failed: {}", e))?
        }
        _ => {
            // Unencrypted message types (session updates, etc.)
            envelope.payload.clone()
        }
    };

    match envelope.msg_type.as_str() {
        MSG_DEVICE_OP_RESPONSE => {
            // Check for vault_locked error — emit event for re-authentication
            if let Some(error_code) = payload_data.get("error_code").and_then(|v| v.as_str()) {
                if error_code == "vault_locked" {
                    let _ = app_handle.emit("vault:vault-locked", &payload_data);
                    log::warn!("Vault locked — DEK unavailable, PIN re-entry required");
                }
            }

            // Resolve pending operation by request_id
            if let Some(request_id) = payload_data.get("request_id").and_then(|v| v.as_str()) {
                let mut pending = state.pending_responses.lock().await;
                if let Some(sender) = pending.remove(request_id) {
                    let _ = sender.send(payload_data.clone());
                    log::debug!("Resolved pending operation: {}", request_id);
                } else {
                    log::debug!("No pending handler for request_id: {}", request_id);
                }
            }
        }
        "session_update" => {
            // Update session manager
            if let Some(status) = payload_data.get("status").and_then(|v| v.as_str()) {
                let mut session = state.session.write().await;
                match status {
                    "suspended" => session.suspend(),
                    "expired" => session.expire(),
                    "revoked" => session.revoke(),
                    "active" => session.resume(),
                    _ => {}
                }
            }
            let _ = app_handle.emit("vault:session-update", &payload_data);
        }
        "feed_event" | "feed.notification" => {
            let _ = app_handle.emit("vault:feed-event", &payload_data);
        }
        "new_message" | "message.received" => {
            let _ = app_handle.emit("vault:message-received", &payload_data);
        }
        "phone_approval_result" => {
            // Resolve delegation
            if let Some(request_id) = payload_data.get("request_id").and_then(|v| v.as_str()) {
                let mut delegation = state.delegation.lock().await;
                delegation.resolve(request_id);
            }
            let _ = app_handle.emit("vault:phone-approval-result", &payload_data);
        }
        other => {
            log::debug!("Unhandled message type: {}", other);
            // Forward unknown events as generic vault events
            let _ = app_handle.emit("vault:event", &serde_json::json!({
                "type": other,
                "data": payload_data,
            }));
        }
    }

    Ok(())
}

/// Extract raw bytes from an envelope payload (JSON array of numbers or base64 string).
fn extract_bytes(value: &serde_json::Value) -> Result<Vec<u8>, String> {
    match value {
        serde_json::Value::Array(arr) => {
            let mut bytes = Vec::with_capacity(arr.len());
            for v in arr {
                let b = v.as_u64().ok_or("payload byte is not a number")?;
                if b > 255 {
                    return Err("payload byte exceeds u8 range".to_string());
                }
                bytes.push(b as u8);
            }
            Ok(bytes)
        }
        serde_json::Value::String(s) => {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(s)
                .map_err(|e| format!("base64 decode failed: {}", e))
        }
        _ => Err("unexpected payload format".to_string()),
    }
}
