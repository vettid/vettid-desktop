//! Tauri commands for WebRTC call signaling and (when the `webrtc` feature
//! is enabled) media negotiation.
//!
//! The signaling layer publishes to the target user's vault using the same
//! `OwnerSpace.{guid}.forVault.{op}` pattern Android uses. When `webrtc` is
//! on, every call also drives a `webrtc::CallSession` that produces SDP +
//! ICE candidates and forwards them via the same signaling path; without
//! the feature, the commands act as bare signal forwarders so the call UX
//! still works for end-to-end testing.
//!
//! Incoming call events flow back through the Phase 1 listener as
//! `vault:call-event` Tauri events. The frontend stores route them into
//! incoming/outgoing/active state and call into the apply_remote_*
//! commands below to feed remote SDP/ICE into the active session.

use serde::Serialize;
use tauri::{AppHandle, State};

use crate::state::AppState;

#[cfg(feature = "webrtc")]
use std::sync::Arc;
#[cfg(feature = "webrtc")]
use tauri::Emitter;
#[cfg(feature = "webrtc")]
use tokio::sync::mpsc;
#[cfg(feature = "webrtc")]
use crate::webrtc::session::{CallSession, SessionEvent};

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

/// Initiate an outgoing call to a peer.
///
/// With `--features webrtc`: creates a CallSession, generates an SDP offer,
/// and includes it in the published signal — the caller-supplied
/// `sdp_offer` arg is ignored since we own the negotiation. Without the
/// feature: sends `sdp_offer` through unchanged, useful for testing the
/// signaling path without media.
#[tauri::command]
#[cfg_attr(feature = "webrtc", allow(unused_variables))]
pub async fn initiate_call(
    state: State<'_, AppState>,
    app_handle: AppHandle,
    target_guid: String,
    display_name: String,
    call_type: String, // "audio" | "video"
    sdp_offer: Option<String>,
) -> Result<CallSignalResponse, String> {
    let call_id = format!("call-{}", uuid_v4());

    // When WebRTC is compiled in, ignore the caller-supplied SDP and
    // generate one from a fresh CallSession instead.
    #[cfg(feature = "webrtc")]
    let sdp_offer = match start_call_session(&state, &app_handle, &call_id, &target_guid, true).await {
        Ok(sdp) => Some(sdp),
        Err(e) => return Ok(CallSignalResponse::err(e)),
    };
    #[cfg(not(feature = "webrtc"))]
    let _ = &app_handle; // suppress unused warning

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

/// Accept an incoming call.
///
/// With `--features webrtc`: requires the remote SDP offer (the frontend
/// pulled it out of the `vault:call-event` payload), creates a CallSession,
/// applies the offer, generates an answer, and ships the answer back —
/// `sdp_answer` is ignored. With the feature off: publishes call.answer with
/// whatever `sdp_answer` the caller passes through.
#[tauri::command]
#[cfg_attr(feature = "webrtc", allow(unused_variables))]
pub async fn answer_call(
    state: State<'_, AppState>,
    app_handle: AppHandle,
    call_id: String,
    peer_guid: String,
    sdp_offer: Option<String>,
    sdp_answer: Option<String>,
) -> Result<CallSignalResponse, String> {
    #[cfg(feature = "webrtc")]
    let sdp_answer = match sdp_offer {
        Some(offer) => match accept_call_session(&state, &app_handle, &call_id, &peer_guid, &offer).await {
            Ok(answer) => Some(answer),
            Err(e) => return Ok(CallSignalResponse::err(e)),
        },
        None => return Ok(CallSignalResponse::err("WebRTC enabled but no SDP offer in payload")),
    };
    #[cfg(not(feature = "webrtc"))]
    {
        let _ = (&app_handle, &sdp_offer);
    }

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
    // Tear down the local session before we lose the chance — once the
    // peer publishes call.ended back at us, we'll be racing the listener.
    #[cfg(feature = "webrtc")]
    {
        let mut slot = state.active_call.lock().await;
        if let Some(session) = slot.take() {
            session.close().await;
        }
    }

    let payload = serde_json::json!({ "call_id": call_id });
    match publish_signal(&state, &peer_guid, "call.end", payload).await {
        Ok(_) => Ok(CallSignalResponse::ok(call_id)),
        Err(e) => Ok(CallSignalResponse::err(e)),
    }
}

/// Apply a remote SDP answer received via `call.answered`.
///
/// Caller-side only: the callee never receives an answer (it's the side
/// generating one). No-op when the webrtc feature is disabled.
#[tauri::command]
pub async fn apply_remote_answer(
    state: State<'_, AppState>,
    sdp: String,
) -> Result<CallSignalResponse, String> {
    #[cfg(feature = "webrtc")]
    {
        let slot = state.active_call.lock().await;
        match slot.as_ref() {
            Some(session) => match session.set_remote_answer(&sdp).await {
                Ok(()) => Ok(CallSignalResponse::ok(&session.call_id)),
                Err(e) => Ok(CallSignalResponse::err(e.to_string())),
            },
            None => Ok(CallSignalResponse::err("no active call")),
        }
    }
    #[cfg(not(feature = "webrtc"))]
    {
        let _ = (state, sdp);
        Ok(CallSignalResponse::ok(""))
    }
}

/// Apply a remote ICE candidate received via `call.candidate`.
#[tauri::command]
pub async fn apply_remote_ice(
    state: State<'_, AppState>,
    candidate: serde_json::Value,
) -> Result<CallSignalResponse, String> {
    #[cfg(feature = "webrtc")]
    {
        let slot = state.active_call.lock().await;
        match slot.as_ref() {
            Some(session) => match session.add_remote_ice(candidate).await {
                Ok(()) => Ok(CallSignalResponse::ok(&session.call_id)),
                Err(e) => Ok(CallSignalResponse::err(e.to_string())),
            },
            None => Ok(CallSignalResponse::err("no active call")),
        }
    }
    #[cfg(not(feature = "webrtc"))]
    {
        let _ = (state, candidate);
        Ok(CallSignalResponse::ok(""))
    }
}

// ---------------------------------------------------------------------------
// WebRTC session helpers (feature-gated)
// ---------------------------------------------------------------------------

/// Spawn a CallSession for the caller side and return the SDP offer.
#[cfg(feature = "webrtc")]
async fn start_call_session(
    state: &AppState,
    app_handle: &AppHandle,
    call_id: &str,
    peer_guid: &str,
    is_caller: bool,
) -> Result<String, String> {
    let _ = is_caller; // currently informational; will matter for stats/logs
    let (tx, rx) = mpsc::unbounded_channel();
    let session = CallSession::new(call_id.to_string(), peer_guid.to_string(), tx)
        .await
        .map_err(|e| e.to_string())?;
    let offer = session.create_offer().await.map_err(|e| e.to_string())?;

    let session = Arc::new(session);
    *state.active_call.lock().await = Some(session.clone());

    spawn_session_event_loop(app_handle.clone(), session, rx);
    Ok(offer)
}

/// Spawn a CallSession for the callee side, applying the caller's offer and
/// returning our SDP answer.
#[cfg(feature = "webrtc")]
async fn accept_call_session(
    state: &AppState,
    app_handle: &AppHandle,
    call_id: &str,
    peer_guid: &str,
    remote_offer_sdp: &str,
) -> Result<String, String> {
    let (tx, rx) = mpsc::unbounded_channel();
    let session = CallSession::new(call_id.to_string(), peer_guid.to_string(), tx)
        .await
        .map_err(|e| e.to_string())?;
    let answer = session
        .create_answer(remote_offer_sdp)
        .await
        .map_err(|e| e.to_string())?;

    let session = Arc::new(session);
    *state.active_call.lock().await = Some(session.clone());

    spawn_session_event_loop(app_handle.clone(), session, rx);
    Ok(answer)
}

/// Drain the SessionEvent channel forever (until the channel closes when
/// the session drops). For each event:
///
/// - `LocalIceCandidate` → publish `call.candidate` to the peer's vault.
/// - `ConnectionState` → emit `vault:call-state` to the UI.
#[cfg(feature = "webrtc")]
fn spawn_session_event_loop(
    app_handle: AppHandle,
    session: Arc<CallSession>,
    mut rx: mpsc::UnboundedReceiver<SessionEvent>,
) {
    tokio::spawn(async move {
        // We need state again inside the loop to publish ICE candidates;
        // pull it from the AppHandle each iteration to avoid holding a
        // long-lived reference (Tauri's State<'_, T> is request-scoped).
        while let Some(event) = rx.recv().await {
            match event {
                SessionEvent::LocalIceCandidate(candidate) => {
                    use tauri::Manager;
                    let state: tauri::State<'_, AppState> = app_handle.state();
                    let payload = serde_json::json!({
                        "call_id": session.call_id,
                        "candidate": candidate,
                    });
                    if let Err(e) = publish_signal(
                        &state,
                        &session.peer_guid,
                        "call.candidate",
                        payload,
                    )
                    .await
                    {
                        log::warn!("Failed to publish ICE candidate: {}", e);
                    }
                }
                SessionEvent::ConnectionState(label) => {
                    let _ = app_handle.emit(
                        "vault:call-state",
                        &serde_json::json!({
                            "call_id": session.call_id,
                            "state": label,
                        }),
                    );
                }
            }
        }
        log::debug!("Call session event loop ended for {}", session.call_id);
    });
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
