//! Tauri commands for WebRTC call signaling.
//!
//! Signaling only — the actual media stack (peer connection, audio/video
//! tracks, ICE) is not yet wired. The signaling commands publish to the
//! target user's vault using the same `OwnerSpace.{guid}.forVault.{op}`
//! pattern Android uses, so once a WebRTC stack is plugged in the wire
//! protocol is already correct.
//!
//! Incoming call events flow back through the Phase 1 listener as
//! `vault:call-event` Tauri events; the frontend stores routes them into
//! incoming/outgoing/active state.

use serde::Serialize;
use tauri::State;

use crate::state::AppState;

/// Outcome of a signaling call. Mirrors `VaultOpResponse` shape so the
/// frontend's response handling stays uniform across regular vault ops and
/// signaling.
#[derive(Debug, Serialize)]
pub struct CallSignalResponse {
    pub success: bool,
    pub call_id: Option<String>,
    pub error: Option<String>,
}

impl CallSignalResponse {
    fn ok(call_id: impl Into<String>) -> Self {
        Self { success: true, call_id: Some(call_id.into()), error: None }
    }
    fn err(msg: impl Into<String>) -> Self {
        Self { success: false, call_id: None, error: Some(msg.into()) }
    }
}

/// Build the VaultMessage envelope that wraps signaling payloads.
///
/// Format matches Android's `VaultMessage`: a small JSON object with `id`,
/// `type`, `payload`, and `timestamp`. The vault validates the type and
/// relays an event to the recipient's `forApp.call.*` channel.
fn build_envelope(
    request_id: &str,
    msg_type: &str,
    payload: serde_json::Value,
) -> Result<Vec<u8>, String> {
    let envelope = serde_json::json!({
        "id": request_id,
        "type": msg_type,
        "payload": payload,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });
    serde_json::to_vec(&envelope).map_err(|e| format!("encode envelope: {}", e))
}

/// Publish a signaling message to the target user's vault.
async fn publish_signal(
    state: &AppState,
    target_guid: &str,
    operation: &str,
    payload: serde_json::Value,
) -> Result<String, String> {
    let request_id = hex::encode(crate::crypto::keys::generate_random_bytes(16));

    // Add caller_id from our own credentials so the recipient knows who's
    // ringing without trusting client-supplied claims. The vault re-checks
    // this anyway, but it short-circuits trivial spoofing.
    let payload = {
        let creds = state.credentials.read().await;
        let caller_id = creds.as_ref().map(|c| c.owner_guid.clone()).unwrap_or_default();
        let mut p = payload;
        if let serde_json::Value::Object(ref mut map) = p {
            map.entry("caller_id")
                .or_insert(serde_json::Value::String(caller_id));
        }
        p
    };

    let envelope = build_envelope(&request_id, operation, payload)?;
    let nats = state.nats.lock().await;
    nats.publish_to_target_vault(target_guid, operation, &envelope)
        .await
        .map_err(|e| e.to_string())?;
    Ok(request_id)
}

/// Initiate an outgoing call to a peer. The SDP offer is optional during
/// signaling-only mode; once the WebRTC stack lands the offer will be
/// generated from a fresh RTCPeerConnection before this command is called.
#[tauri::command]
pub async fn initiate_call(
    state: State<'_, AppState>,
    target_guid: String,
    display_name: String,
    call_type: String, // "audio" | "video"
    sdp_offer: Option<String>,
) -> Result<CallSignalResponse, String> {
    let call_id = format!("call-{}", uuid_v4());
    let mut payload = serde_json::json!({
        "call_id": call_id,
        "caller_display_name": display_name,
        "call_type": call_type,
    });
    if let Some(offer) = sdp_offer {
        payload["sdp_offer"] = serde_json::Value::String(offer);
    }

    match publish_signal(&state, &target_guid, "call.initiate", payload).await {
        Ok(_) => Ok(CallSignalResponse::ok(call_id)),
        Err(e) => Ok(CallSignalResponse::err(e)),
    }
}

#[tauri::command]
pub async fn answer_call(
    state: State<'_, AppState>,
    call_id: String,
    peer_guid: String,
    sdp_answer: Option<String>,
) -> Result<CallSignalResponse, String> {
    let mut payload = serde_json::json!({ "call_id": call_id });
    if let Some(answer) = sdp_answer {
        payload["sdp_answer"] = serde_json::Value::String(answer);
    }
    match publish_signal(&state, &peer_guid, "call.answer", payload).await {
        Ok(_) => Ok(CallSignalResponse::ok(call_id)),
        Err(e) => Ok(CallSignalResponse::err(e)),
    }
}

#[tauri::command]
pub async fn decline_call(
    state: State<'_, AppState>,
    call_id: String,
    peer_guid: String,
) -> Result<CallSignalResponse, String> {
    let payload = serde_json::json!({ "call_id": call_id, "reason": "declined" });
    match publish_signal(&state, &peer_guid, "call.decline", payload).await {
        Ok(_) => Ok(CallSignalResponse::ok(call_id)),
        Err(e) => Ok(CallSignalResponse::err(e)),
    }
}

#[tauri::command]
pub async fn end_call(
    state: State<'_, AppState>,
    call_id: String,
    peer_guid: String,
) -> Result<CallSignalResponse, String> {
    let payload = serde_json::json!({ "call_id": call_id });
    match publish_signal(&state, &peer_guid, "call.end", payload).await {
        Ok(_) => Ok(CallSignalResponse::ok(call_id)),
        Err(e) => Ok(CallSignalResponse::err(e)),
    }
}

#[tauri::command]
pub async fn send_ice_candidate(
    state: State<'_, AppState>,
    call_id: String,
    peer_guid: String,
    candidate: serde_json::Value,
) -> Result<CallSignalResponse, String> {
    let payload = serde_json::json!({ "call_id": call_id, "candidate": candidate });
    match publish_signal(&state, &peer_guid, "call.candidate", payload).await {
        Ok(_) => Ok(CallSignalResponse::ok(call_id)),
        Err(e) => Ok(CallSignalResponse::err(e)),
    }
}

/// Quick UUID v4 generator without pulling in another dep — random 128 bits
/// formatted to the 8-4-4-4-12 layout. Good enough for client-generated call
/// ids; the vault doesn't trust these for anything beyond correlation.
fn uuid_v4() -> String {
    let bytes = crate::crypto::keys::generate_random_bytes(16);
    let mut b = [0u8; 16];
    b.copy_from_slice(&bytes);
    // Set version (4) and variant (RFC 4122) bits.
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
    )
}
