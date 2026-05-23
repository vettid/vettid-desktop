//! Tauri commands for WebRTC call signaling and (when the `webrtc` feature
//! is enabled) media negotiation.
//!
//! ## Wire shape (post-2026-05-23 vault-routed rewrite)
//!
//! Every call op funnels through the same encrypted device-op envelope
//! the rest of the desktop uses: `execute("call.start", payload)` →
//! `MessageSpace.{own}.forOwner.device` (encrypted with conn key) →
//! vault's `handleDeviceOpRequest` sees `call.*` as an independent
//! capability and rebuilds a synthetic `forVault.call.*` subject →
//! `handleCallOperation` → `HandleInitiateCall` (etc.) → response wraps
//! under `data:` and lands on `MessageSpace.{own}.forApp.device.{conn}
//! .response`, where `listener.rs::handle_response_message` resolves it
//! by `request_id`.
//!
//! The vault generates the X25519 keypair, holds the per-call shared
//! secret, encrypts peer signaling on the wire, and tracks active-call
//! state — so the desktop only needs to (a) feed call control through
//! `execute()` and (b) wire the WebRTC SDP/ICE exchange through
//! `call.signal`. No more direct-to-peer `publish_to_target_vault`.
//!
//! Incoming peer events arrive as `vault:call-event` Tauri emits driven
//! by the same listener: `call.incoming`, `call.offer`, `call.answer`,
//! `call.candidate`, `call.accepted`, `call.cancelled`, `call.ended`.
//! The listener also intercepts `call.accepted` to bind the per-call
//! `shared_secret` into the active session's `CryptorConfig` without
//! the secret crossing the JS boundary (see Phase C).

use serde::Serialize;
use serde_json::json;
use tauri::{AppHandle, State};

use crate::nats::messages::DeviceOpResponse;
use crate::nats::operations;
use crate::state::AppState;

#[cfg(feature = "webrtc")]
use std::sync::Arc;
#[cfg(feature = "webrtc")]
use tauri::Emitter;
#[cfg(feature = "webrtc")]
use tokio::sync::mpsc;
#[cfg(feature = "webrtc")]
use crate::webrtc::session::{CallSession, SessionEvent};
#[cfg(feature = "webrtc")]
use crate::webrtc::turn;

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

/// Pull the vault-issued call_id out of a `call.start` response.
///
/// Vault returns `InitiateCallResponse{call_id, status, local_key_pub,
/// initiated_at}` under the device-op envelope's `data:` wrapper.
fn extract_call_id(resp: &DeviceOpResponse) -> Result<String, String> {
    let data = resp
        .data
        .as_ref()
        .ok_or_else(|| "vault response missing data".to_string())?;
    data.get("call_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "vault response missing call_id".to_string())
}

/// Bind a base64-encoded 32-byte per-call shared secret into the active
/// session's frame cryptor. Used by both:
///
/// - The callee side, right after `execute("call.accept", ...)` returns
///   with `AcceptCallResponse.shared_secret`.
/// - The caller side, when the listener intercepts the `call.accepted`
///   push event (which carries `shared_secret` at the root of the
///   forwarded CallEvent).
///
/// Empty input is a no-op (peer hadn't sent its key yet — the other
/// arrival path will deliver it). The secret never enters the JS layer.
#[cfg(feature = "webrtc")]
pub(crate) async fn bind_shared_secret_to_active_call(
    state: &AppState,
    secret_b64: &str,
) -> Result<(), String> {
    if secret_b64.is_empty() {
        return Ok(());
    }
    let secret_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        secret_b64,
    )
    .map_err(|e| format!("shared_secret base64: {}", e))?;
    let secret: [u8; 32] = secret_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "shared_secret must be 32 bytes".to_string())?;

    let slot = state.active_call.lock().await;
    if let Some(session) = slot.as_ref() {
        if let Some(cryptor) = session.cryptor() {
            cryptor.set_key_from_secret(&secret).await;
            log::debug!("Bound per-call shared_secret to cryptor for {}", session.call_id);
        }
    }
    Ok(())
}

/// Initiate an outgoing call to a connection.
///
/// Flow:
/// 1. `execute("call.start", {connection_id, metadata})` — vault returns
///    the call_id (vault-issued, not desktop-minted) and publishes the
///    encrypted `call.initiate` event to the peer.
/// 2. With `--features webrtc`: start a `CallSession` with that call_id,
///    generate an SDP offer, and ship it via
///    `execute("call.signal", {call_id, signal_type:"offer", payload:
///    {sdp}})`. Vault encrypts and forwards to peer as `call.offer`.
#[tauri::command]
#[cfg_attr(not(feature = "webrtc"), allow(unused_variables))]
pub async fn initiate_call(
    state: State<'_, AppState>,
    app_handle: AppHandle,
    connection_id: String,
    peer_guid: String,
    display_name: String,
    call_type: String, // "audio" | "video"
) -> Result<CallSignalResponse, String> {
    // Step 1 — vault-issue the call_id.
    let metadata = json!({
        "call_type": call_type,
        "caller_display_name": display_name,
    });
    let resp = match operations::execute(
        &state,
        "call.start",
        json!({
            "connection_id": connection_id,
            "metadata": metadata,
        }),
    )
    .await
    {
        Ok(r) if r.success => r,
        Ok(r) => return Ok(CallSignalResponse::err(
            r.error.unwrap_or_else(|| "call.start failed".to_string()),
        )),
        Err(e) => return Ok(CallSignalResponse::err(e.to_string())),
    };
    let call_id = match extract_call_id(&resp) {
        Ok(id) => id,
        Err(e) => return Ok(CallSignalResponse::err(e)),
    };

    // Step 2 — start WebRTC session and ship the SDP offer.
    #[cfg(feature = "webrtc")]
    {
        let offer = match start_call_session(&state, &app_handle, &call_id, &peer_guid).await {
            Ok(o) => o,
            Err(e) => return Ok(CallSignalResponse::err(e)),
        };
        if let Err(e) = send_signal(&state, &call_id, "offer", json!({ "sdp": offer })).await {
            return Ok(CallSignalResponse::err(e));
        }
    }
    #[cfg(not(feature = "webrtc"))]
    {
        let _ = &app_handle;
        let _ = &peer_guid;
    }

    Ok(CallSignalResponse::ok(call_id))
}

/// Accept an incoming call.
///
/// `sdp_offer` is the SDP the listener buffered from the most recent
/// `call.offer` push (frontend's `pendingRemoteOffer`). Backend creates
/// the WebRTC session, applies the offer, generates an answer, and
/// publishes `call.accept` carrying that answer. The vault's accept
/// response includes the per-call `shared_secret` — bind it to the
/// active session's cryptor on the spot.
#[tauri::command]
#[cfg_attr(not(feature = "webrtc"), allow(unused_variables))]
pub async fn answer_call(
    state: State<'_, AppState>,
    app_handle: AppHandle,
    call_id: String,
    peer_guid: String,
    sdp_offer: Option<String>,
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
    let sdp_answer: Option<String> = {
        let _ = (&app_handle, &peer_guid, &sdp_offer);
        None
    };

    let mut payload = json!({ "call_id": call_id });
    if let Some(answer) = sdp_answer {
        payload["sdp_answer"] = serde_json::Value::String(answer);
    }
    let resp = match operations::execute(&state, "call.accept", payload).await {
        Ok(r) if r.success => r,
        Ok(r) => return Ok(CallSignalResponse::err(
            r.error.unwrap_or_else(|| "call.accept failed".to_string()),
        )),
        Err(e) => return Ok(CallSignalResponse::err(e.to_string())),
    };

    // Bind the per-call shared_secret to the cryptor on the callee side.
    // If absent (peer didn't include its key yet) the caller-side
    // `call.accepted` push will deliver it via listener interception.
    #[cfg(feature = "webrtc")]
    if let Some(secret_b64) = resp
        .data
        .as_ref()
        .and_then(|d| d.get("shared_secret"))
        .and_then(|v| v.as_str())
    {
        if let Err(e) = bind_shared_secret_to_active_call(&state, secret_b64).await {
            log::warn!("Failed to bind shared_secret on accept: {}", e);
        }
    }

    Ok(CallSignalResponse::ok(call_id))
}

#[tauri::command]
pub async fn decline_call(
    state: State<'_, AppState>,
    call_id: String,
    reason: Option<String>,
) -> Result<CallSignalResponse, String> {
    let mut payload = json!({ "call_id": call_id });
    if let Some(r) = reason {
        payload["reason"] = serde_json::Value::String(r);
    }
    match operations::execute(&state, "call.reject", payload).await {
        Ok(r) if r.success => Ok(CallSignalResponse::ok(call_id)),
        Ok(r) => Ok(CallSignalResponse::err(
            r.error.unwrap_or_else(|| "call.reject failed".to_string()),
        )),
        Err(e) => Ok(CallSignalResponse::err(e.to_string())),
    }
}

#[tauri::command]
pub async fn end_call(
    state: State<'_, AppState>,
    call_id: String,
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

    match operations::execute(&state, "call.end", json!({ "call_id": call_id })).await {
        Ok(r) if r.success => Ok(CallSignalResponse::ok(call_id)),
        Ok(r) => Ok(CallSignalResponse::err(
            r.error.unwrap_or_else(|| "call.end failed".to_string()),
        )),
        Err(e) => Ok(CallSignalResponse::err(e.to_string())),
    }
}

/// Apply a remote SDP answer received via `call.accepted`.
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
// Internal helpers
// ---------------------------------------------------------------------------

/// Ship one WebRTC signaling message through the vault's `call.signal` op.
/// `signal_type` ∈ {"offer", "answer", "candidate"}. The `payload`
/// shape is app-pair convention — see the table in `sframe-cryptor.md`
/// for the contract Android and desktop share.
async fn send_signal(
    state: &AppState,
    call_id: &str,
    signal_type: &str,
    payload: serde_json::Value,
) -> Result<(), String> {
    let resp = operations::execute(
        state,
        "call.signal",
        json!({
            "call_id": call_id,
            "signal_type": signal_type,
            "payload": payload,
        }),
    )
    .await
    .map_err(|e| e.to_string())?;
    if !resp.success {
        return Err(resp.error.unwrap_or_else(|| format!("call.signal {} failed", signal_type)));
    }
    Ok(())
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
) -> Result<String, String> {
    // Fetch fresh TURN credentials before we build the peer connection.
    // Empty vec falls back to STUN-only inside CallSession::new.
    let ice = turn::fetch_ice_servers(state).await;
    let (tx, rx) = mpsc::unbounded_channel();
    let session = CallSession::new(
        call_id.to_string(),
        peer_guid.to_string(),
        tx,
        ice,
        // Deferred-key cryptor: the per-call shared_secret arrives later
        // via the `call.accepted` push (caller) or the `call.accept`
        // response (callee). Until set, the interceptor drops outbound
        // frames and surfaces empty inbound payloads — matches Android's
        // `discardFrameWhenCryptorNotReady = true`.
        Some(crate::webrtc::cryptor::CryptorConfig::new()),
    )
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
    let ice = turn::fetch_ice_servers(state).await;
    let (tx, rx) = mpsc::unbounded_channel();
    let session = CallSession::new(
        call_id.to_string(),
        peer_guid.to_string(),
        tx,
        ice,
        Some(crate::webrtc::cryptor::CryptorConfig::new()),
    )
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
/// - `LocalIceCandidate` → publish via `call.signal` (signal_type=
///   "candidate") to OWN vault, which encrypts and forwards to peer.
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
                    if let Err(e) = send_signal(
                        &state,
                        &session.call_id,
                        "candidate",
                        candidate,
                    )
                    .await
                    {
                        log::warn!("Failed to publish ICE candidate: {}", e);
                    }
                }
                SessionEvent::ConnectionState(label) => {
                    let _ = app_handle.emit(
                        "vault:call-state",
                        &json!({
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

/// Frontend-callable shim used by the older direct-publish path. Kept for
/// the case where the WebRTC session has already negotiated ICE elsewhere
/// and just wants to push a candidate; new code should use the
/// `LocalIceCandidate` event loop above.
#[tauri::command]
pub async fn send_ice_candidate(
    state: State<'_, AppState>,
    call_id: String,
    candidate: serde_json::Value,
) -> Result<CallSignalResponse, String> {
    match send_signal(&state, &call_id, "candidate", candidate).await {
        Ok(()) => Ok(CallSignalResponse::ok(call_id)),
        Err(e) => Ok(CallSignalResponse::err(e)),
    }
}
