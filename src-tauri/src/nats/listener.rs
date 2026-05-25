use futures::StreamExt;
use tauri::{AppHandle, Emitter, Manager};

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
pub async fn spawn_listener(
    app_handle: AppHandle,
    connection_id: String,
) {
    // Abort any prior listener under the lock so we don't end up with
    // overlapping subscribers on the same subjects. Without this,
    // re-spawning across unlock / extend_session / register stacked
    // listeners and every NATS message got processed N times — the
    // duplicate ack from listener #2 poisoned the multi-shot
    // phone-approval reader ("Approval did not complete" after the
    // human approved).
    let listener_slot = {
        let state = app_handle.state::<AppState>();
        state.listener_handle.clone()
    };
    {
        let mut slot = listener_slot.lock().await;
        if let Some(prev) = slot.take() {
            prev.abort();
            log::debug!("Aborted previous background listener before respawn");
        }
    }

    let app_handle_for_task = app_handle.clone();
    let handle = tokio::spawn(async move {
        let app_handle = app_handle_for_task;
        let state = app_handle.state::<AppState>();
        let (responses_sub, event_rx_opt) = {
            let mut nats = state.nats.lock().await;
            let r = match nats.subscribe_device_channel(&connection_id).await {
                Ok(s) => s,
                Err(e) => {
                    log::error!("Failed to subscribe to device channel: {}", e);
                    return;
                }
            };
            let evs = nats.take_event_receiver();
            (r, evs)
        };

        log::info!(
            "Background listener started for connection {} (MessageSpace device channel + state events)",
            connection_id,
        );

        let mut device_channel = responses_sub;
        // The connection-event receiver may be `None` if the listener is
        // restarted on the same NatsClient without a fresh connect — in that
        // case skip the state-events arm in the select.
        let mut event_rx = event_rx_opt;

        loop {
            tokio::select! {
                Some(msg) = device_channel.next() => {
                    // The device channel carries both op responses
                    // (MessageSpace.{o}.forApp.device.{c}.response) and
                    // vault push events fanned out by PublishToApp
                    // (MessageSpace.{o}.forApp.device.{c}.{event}).
                    // Route on subject suffix so each lands on its
                    // intended handler.
                    if msg.subject.ends_with(".response") {
                        if let Err(e) = handle_response_message(&app_handle, state.inner(), &msg.payload).await {
                            log::warn!("Failed to handle response message: {}", e);
                        }
                    } else {
                        handle_app_event(&app_handle, state.inner(), &msg.subject, &msg.payload).await;
                    }
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
    });

    // Track the new task so the next respawn can abort it.
    let mut slot = listener_slot.lock().await;
    *slot = Some(handle);
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
            //
            // Phone-required ops send TWO responses against the same
            // request_id: a `status: "pending_approval"` ack, then the
            // eventual final response after the phone responds. Don't
            // remove the pending entry on the ack — only forward it on
            // the channel and keep waiting for the final result. The
            // ack is also surfaced to the UI so the user gets a
            // "Waiting for phone..." indicator rather than a frozen
            // spinner.
            if let Some(request_id) = payload_data.get("request_id").and_then(|v| v.as_str()) {
                let is_pending_ack = payload_data
                    .get("status")
                    .and_then(|v| v.as_str())
                    .map(|s| s == "pending_approval")
                    .unwrap_or(false);

                if is_pending_ack {
                    let _ = app_handle.emit("vault:operation-pending-approval", &payload_data);
                    log::debug!("Pending-approval ack for {}", request_id);
                }

                let mut pending = state.pending_responses.lock().await;
                if is_pending_ack {
                    if let Some(sender) = pending.get(request_id) {
                        let _ = sender.send(payload_data.clone());
                    }
                } else if let Some(sender) = pending.remove(request_id) {
                    let _ = sender.send(payload_data.clone());
                    log::debug!("Resolved pending operation: {}", request_id);
                } else {
                    log::debug!("No pending handler for request_id: {}", request_id);
                    // WS2: a secret.unlock-session result can land after
                    // its caller already gave up (slow enclave, or the
                    // phone approved late). The grant is still valid —
                    // surface it so the Sensitive Data chip flips to
                    // Unlocked instead of stranding the user on a stale
                    // "request timed out" error.
                    let is_late_unlock = payload_data
                        .get("operation")
                        .and_then(|v| v.as_str())
                        .map(|op| op == "secret.unlock-session")
                        .unwrap_or(false)
                        && payload_data
                            .get("unlocked_until")
                            .map(|v| !v.is_null())
                            .unwrap_or(false);
                    if is_late_unlock {
                        let _ = app_handle.emit("vault:secrets-unlocked", &payload_data);
                        log::info!("Late secret.unlock-session grant applied for {}", request_id);
                    }
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
async fn handle_app_event(app_handle: &AppHandle, state: &AppState, subject: &str, payload: &[u8]) {
    // Drop request/response reply traffic at the door. Subjects like
    // `OwnerSpace.{owner}.forApp.feed.sync.{id}.response` are phone-
    // originated request/reply pairs that land on this broad
    // forApp.> subscription as a side effect. They aren't events the
    // desktop should react to (the phone has its own subscriber for
    // its own responses), so emit nothing and skip the decode work.
    // The desktop's own op responses come back on a different prefix
    // (MessageSpace.{owner}.forApp.device.{conn}.response) handled by
    // handle_response_message.
    if subject.ends_with(".response") {
        return;
    }

    // Backend interception of `call.accepted`: bind the per-call
    // shared_secret to the active session's frame cryptor before the
    // event is forwarded to the frontend. The secret arrives at the
    // root of the CallEvent JSON (set by handleCallAccept in
    // vault-manager/calls.go); the cryptor needs 32 raw bytes. We
    // explicitly avoid round-tripping the secret through JS — once it
    // is in the platform crypto layer, no other component needs to
    // see it (matches Android's "secret stays in CallFrameCryptor"
    // property).
    let tag = event_suffix(subject);

    #[cfg(feature = "webrtc")]
    if tag == "call.accepted" {
        if let Ok(event) = serde_json::from_slice::<serde_json::Value>(payload) {
            if let Some(secret_b64) = event.get("shared_secret").and_then(|v| v.as_str()) {
                if let Err(e) = crate::commands::calls::bind_shared_secret_to_active_call(
                    state,
                    secret_b64,
                )
                .await
                {
                    log::warn!("Failed to bind shared_secret from call.accepted: {}", e);
                }
            }
        }
    }
    #[cfg(not(feature = "webrtc"))]
    let _ = state;

    let event_payload = serde_json::json!({
        "subject": subject,
        "payload_b64": base64_encode(payload),
    });

    // Match on the event suffix (the part after `.forApp.` or
    // `.forApp.device.{conn}.`). The previous `subject.contains()`
    // pattern only matched the broad `OwnerSpace.{}.forApp.{event}`
    // shape, but the desktop only subscribes to the per-device
    // `MessageSpace.{}.forApp.device.{conn}.>` channel — so every push
    // event silently fell through to `vault:app-event` and the
    // frontend never heard about it. (Symptom: live incoming messages
    // never appeared on the desktop; only the phone got the
    // notification.) Match in priority order — more specific suffixes
    // before generic namespace prefixes.
    let tauri_event = if tag == "new-message" {
        "vault:message-received"
    } else if tag == "read-receipt" {
        // Push receipt from peer. The request/response reply variant
        // arrives under tag "message.read-receipt" and is not matched
        // here — naturally distinguished by the exact-suffix compare
        // (the old contains()-with-negation was working around the
        // same ambiguity).
        "vault:read-receipt"
    } else if tag == "connection-revoked" {
        "vault:connection-revoked"
    } else if tag.starts_with("connection.") {
        "vault:connection-event"
    } else if tag == "profile-update" || tag.starts_with("profile.") {
        "vault:profile-update"
    } else if tag == "credentials.rotate" {
        "vault:credentials-rotate"
    } else if tag.starts_with("call.") {
        "vault:call-event"
    } else if tag.starts_with("recovery.") {
        "vault:recovery-event"
    } else if tag.starts_with("transfer.") {
        "vault:transfer-event"
    } else if tag.starts_with("security.") {
        "vault:security-event"
    } else if tag == "location-update" {
        "vault:location-update"
    } else if tag.starts_with("feed.") {
        "vault:feed-event"
    } else if tag == "agent.message.received" {
        // Agent→owner chat message, sealed under the AgentSession
        // key and emitted by the vault's handleAgentMessage after
        // store + audit. Conversation.svelte listens for this on
        // agent conversations and reloads via get_conversation; same
        // pattern as vault:message-received for peer messages. Must
        // come before the generic agent.* arm so the dedicated event
        // wins.
        "vault:agent-message"
    } else if tag.starts_with("agent.") {
        "vault:agent-event"
    } else {
        // Unknown forApp event — forward as generic so frontend can opt-in
        // to handling it without backend changes.
        log::debug!("Unmapped forApp subject: {} (tag: {})", subject, tag);
        "vault:app-event"
    };

    let _ = app_handle.emit(tauri_event, &event_payload);
}

/// Extract the event-name suffix from a forApp subject, normalizing
/// across the two shapes the vault publishes:
///
/// * `OwnerSpace.{owner}.forApp.{tag}` — broad fan-out (phone listens).
/// * `MessageSpace.{owner}.forApp.device.{conn}.{tag}` — per-device
///   fan-out (desktop listens).
///
/// Returning the tag directly lets matchers compare on a single
/// canonical form instead of having to enumerate both subject shapes.
fn event_suffix(subject: &str) -> &str {
    let after_for_app = match subject.find(".forApp.") {
        Some(idx) => &subject[idx + ".forApp.".len()..],
        None => return subject,
    };
    // Per-device subjects insert a `device.{conn}.` segment between
    // `.forApp.` and the event tag. Strip the prefix and skip one
    // dot-delimited token (the connection_id) to land on the tag.
    if let Some(rest) = after_for_app.strip_prefix("device.") {
        if let Some(dot) = rest.find('.') {
            return &rest[dot + 1..];
        }
        return "";
    }
    after_for_app
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
    use super::event_suffix;

    // The desktop subscribes to the per-device fan-out shape, so the
    // suffix extractor MUST normalize both subject shapes to the same
    // tag — otherwise push events fall through to the catch-all and
    // the UI never sees them (this regressed for new-message and
    // read-receipt and went unnoticed until messages stopped landing
    // in the conversation pane).
    #[test]
    fn event_suffix_handles_both_subject_shapes() {
        // OwnerSpace shape (phone subscription path).
        assert_eq!(
            event_suffix("OwnerSpace.user-1.forApp.new-message"),
            "new-message",
        );
        // MessageSpace per-device shape (desktop subscription path).
        assert_eq!(
            event_suffix("MessageSpace.user-1.forApp.device.conn-9.new-message"),
            "new-message",
        );
        // Namespaced events keep the sub-path so `starts_with("call.")`
        // etc. still routes correctly.
        assert_eq!(
            event_suffix("MessageSpace.user-1.forApp.device.conn-9.call.accepted"),
            "call.accepted",
        );
        assert_eq!(
            event_suffix("OwnerSpace.user-1.forApp.connection.peer-accepted"),
            "connection.peer-accepted",
        );
        // Read-receipt push vs request/response reply — disambiguated
        // by suffix alone instead of the old contains()+negation.
        assert_eq!(
            event_suffix("OwnerSpace.user-1.forApp.read-receipt"),
            "read-receipt",
        );
        assert_eq!(
            event_suffix("MessageSpace.user-1.forApp.device.conn-9.message.read-receipt"),
            "message.read-receipt",
        );
        // Agent chat: dedicated suffix so the cascade can route it to
        // vault:agent-message ahead of the generic agent.* arm.
        assert_eq!(
            event_suffix("MessageSpace.user-1.forApp.device.conn-9.agent.message.received"),
            "agent.message.received",
        );
        assert_eq!(
            event_suffix("OwnerSpace.user-1.forApp.agent.message.received"),
            "agent.message.received",
        );
    }
}
