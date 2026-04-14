use futures::StreamExt;
use std::sync::Arc;
use tauri::{AppHandle, Emitter};

use crate::crypto::encrypt;
use crate::nats::client::NatsConnectionEvent;
use crate::nats::messages::{decode_envelope, MSG_DEVICE_OP_RESPONSE};
use crate::state::AppState;
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Background NATS listener
// ---------------------------------------------------------------------------

/// Spawn a background task that subscribes to two NATS channels in parallel:
///
/// 1. `MessageSpace.{owner}.forOwner.device.{connection_id}` — device-specific
///    response channel: device_op_response, session_update, phone_approval_result.
///    Routed by Envelope.msg_type.
///
/// 2. `OwnerSpace.{owner}.forApp.>` — broad vault push channel: new-message,
///    read-receipt, connection.*, call.*, feed.*, profile-update, etc. Routed
///    by NATS subject (mirrors Android's `OwnerSpaceClient.handleVaultResponse`).
///
/// Both streams are multiplexed via `tokio::select!` inside one task so that
/// shutdown semantics stay simple and AppState locks aren't contended across
/// independent task boundaries.
pub fn spawn_listener(
    app_handle: AppHandle,
    state: Arc<AppState>,
    connection_id: String,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (responses_sub, app_events_sub, event_rx_opt) = {
            let mut nats = state.nats.lock().await;
            let r = match nats.subscribe_responses(&connection_id).await {
                Ok(s) => s,
                Err(e) => {
                    log::error!("Failed to subscribe for responses: {}", e);
                    return;
                }
            };
            let a = match nats.subscribe_app_events().await {
                Ok(s) => s,
                Err(e) => {
                    log::error!("Failed to subscribe to forApp events: {}", e);
                    return;
                }
            };
            let evs = nats.take_event_receiver();
            (r, a, evs)
        };

        log::info!(
            "Background listener started for connection {} (responses + forApp + state-events)",
            connection_id,
        );

        let mut responses = responses_sub;
        let mut app_events = app_events_sub;
        // The connection-event receiver may be `None` if the listener is
        // restarted on the same NatsClient without a fresh connect — in that
        // case skip the state-events arm in the select.
        let mut event_rx = event_rx_opt;

        loop {
            tokio::select! {
                Some(msg) = responses.next() => {
                    if let Err(e) = handle_response_message(&app_handle, &state, &msg.payload).await {
                        log::warn!("Failed to handle response message: {}", e);
                    }
                }
                Some(msg) = app_events.next() => {
                    handle_app_event(&app_handle, &msg.subject, &msg.payload).await;
                }
                Some(ev) = recv_state_event(event_rx.as_mut()) => {
                    handle_state_event(&app_handle, ev);
                }
                else => break,
            }
        }

        // Both streams ended — drain pending response channels so waiting
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

// ---------------------------------------------------------------------------
// Response channel handler (MessageSpace device-specific)
// ---------------------------------------------------------------------------

async fn handle_response_message(
    app_handle: &AppHandle,
    state: &AppState,
    raw: &[u8],
) -> Result<(), String> {
    let envelope = decode_envelope(raw).map_err(|e| format!("decode: {}", e))?;

    // Decrypt the payload based on message type.
    // device_op_response MUST be encrypted; other types may be unencrypted.
    let payload_data = match envelope.msg_type.as_str() {
        MSG_DEVICE_OP_RESPONSE => {
            let key_guard = state.connection_key.read().await;
            let key = key_guard
                .as_ref()
                .ok_or("No connection key for encrypted message".to_string())?;
            let ciphertext = extract_bytes(&envelope.payload)?;
            let plaintext = encrypt::decrypt(key, &ciphertext)
                .map_err(|e| format!("Decryption failed for device_op_response: {}", e))?;
            serde_json::from_slice(&plaintext)
                .map_err(|e| format!("Parse decrypted payload failed: {}", e))?
        }
        _ => envelope.payload.clone(),
    };

    match envelope.msg_type.as_str() {
        MSG_DEVICE_OP_RESPONSE => {
            // Vault-locked → re-authentication required.
            if let Some(error_code) = payload_data.get("error_code").and_then(|v| v.as_str()) {
                if error_code == "vault_locked" {
                    let _ = app_handle.emit("vault:vault-locked", &payload_data);
                    log::warn!("Vault locked — DEK unavailable, PIN re-entry required");
                }
            }

            // Resolve pending operation by request_id.
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
        "phone_approval_result" => {
            if let Some(request_id) = payload_data.get("request_id").and_then(|v| v.as_str()) {
                let mut delegation = state.delegation.lock().await;
                delegation.resolve(request_id);
            }
            let _ = app_handle.emit("vault:phone-approval-result", &payload_data);
        }
        other => {
            log::debug!("Unhandled response message type: {}", other);
            let _ = app_handle.emit("vault:event", &serde_json::json!({
                "type": other,
                "data": payload_data,
            }));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// forApp push channel handler (OwnerSpace broadcast)
// ---------------------------------------------------------------------------

/// Route a vault push message to the appropriate Tauri event by NATS subject.
///
/// Subject patterns mirror Android's `OwnerSpaceClient.handleVaultResponse`. We
/// use `contains()` on the suffix so we match regardless of any `.response`
/// trailer added by JetStream when a message is replayed through a consumer.
///
/// Payloads are forwarded raw to the frontend as base64-encoded bytes inside the
/// event detail; per-feature handlers in later phases will decrypt with the
/// appropriate key (vault key, connection key, or unencrypted depending on type).
async fn handle_app_event(app_handle: &AppHandle, subject: &str, payload: &[u8]) {
    let event_payload = serde_json::json!({
        "subject": subject,
        "payload_b64": base64_encode(payload),
    });

    // Match in priority order — more specific patterns first (e.g.,
    // `connection.peer-accepted` before generic `connection.*`).
    let tauri_event = if subject.contains(".forApp.new-message") {
        "vault:message-received"
    } else if subject.contains(".forApp.read-receipt")
        && !subject.contains(".forApp.message.read-receipt")
    {
        // Push receipt from peer (request-response replies are skipped — they
        // come back on the device-specific response channel via JetStream).
        "vault:read-receipt"
    } else if subject.contains(".forApp.connection-revoked") {
        "vault:connection-revoked"
    } else if subject.contains(".forApp.connection.") {
        "vault:connection-event"
    } else if subject.contains(".forApp.profile-update")
        || subject.contains(".forApp.profile.public")
    {
        "vault:profile-update"
    } else if subject.contains(".forApp.credentials.rotate") {
        "vault:credentials-rotate"
    } else if subject.contains(".forApp.call.") {
        "vault:call-event"
    } else if subject.contains(".forApp.recovery.") {
        "vault:recovery-event"
    } else if subject.contains(".forApp.transfer.") {
        "vault:transfer-event"
    } else if subject.contains(".forApp.security.") {
        "vault:security-event"
    } else if subject.contains(".forApp.location-update") {
        "vault:location-update"
    } else if subject.contains(".forApp.feed.new") || subject.contains(".forApp.feed.updated") {
        "vault:feed-event"
    } else if subject.contains(".forApp.agent.") {
        "vault:agent-event"
    } else {
        // Unknown forApp event — forward as generic so frontend can opt-in
        // to handling it without backend changes.
        log::debug!("Unmapped forApp subject: {}", subject);
        "vault:app-event"
    };

    let _ = app_handle.emit(tauri_event, &event_payload);
}

// ---------------------------------------------------------------------------
// Connection-state events
// ---------------------------------------------------------------------------

/// Optional receiver poll. When the receiver is `None` (no event channel for
/// this listener) we return a never-resolving future so the `tokio::select!`
/// arm stays inert without crashing.
async fn recv_state_event(
    rx: Option<&mut mpsc::UnboundedReceiver<NatsConnectionEvent>>,
) -> Option<NatsConnectionEvent> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

fn handle_state_event(app_handle: &AppHandle, event: NatsConnectionEvent) {
    log::info!("NATS connection state: {:?}", event);
    let _ = app_handle.emit("vault:nats-state", &event);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    // Subject-routing logic is exercised through integration testing against a
    // running vault. The match arms above are simple enough that unit testing
    // each pattern would just duplicate the source.
}
