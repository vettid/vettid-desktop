//! A single WebRTC peer-connection wrapping the lifecycle of one call.

use std::sync::Arc;
use tokio::sync::mpsc;

use webrtc::api::media_engine::MediaEngine;
use webrtc::api::APIBuilder;
use webrtc::ice_transport::ice_candidate::RTCIceCandidate;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

/// Outbound event from a call session — published to the peer's vault by the
/// signaling layer.
#[derive(Debug, Clone)]
pub enum SessionEvent {
    /// A locally-gathered ICE candidate, ready to forward to the peer.
    LocalIceCandidate(serde_json::Value),
    /// Connection state change for UI display ("connecting" → "active" → "ended").
    ConnectionState(String),
}

/// Errors surfaced by session operations. Strings (rather than the full
/// webrtc crate hierarchy) so the public surface of this module doesn't leak
/// the webrtc-rs version.
#[derive(Debug)]
pub enum SessionError {
    Webrtc(String),
    InvalidSdp(String),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::Webrtc(s) => write!(f, "webrtc: {}", s),
            SessionError::InvalidSdp(s) => write!(f, "invalid SDP: {}", s),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<webrtc::error::Error> for SessionError {
    fn from(e: webrtc::error::Error) -> Self {
        SessionError::Webrtc(e.to_string())
    }
}

/// Default STUN servers — Google's free public ones. For production we'd
/// want to add VettID-operated TURN servers so calls survive symmetric NATs,
/// but STUN is enough to validate the path in dev.
fn default_ice_servers() -> Vec<RTCIceServer> {
    vec![RTCIceServer {
        urls: vec![
            "stun:stun.l.google.com:19302".to_string(),
            "stun:stun1.l.google.com:19302".to_string(),
        ],
        ..Default::default()
    }]
}

pub struct CallSession {
    pc: Arc<RTCPeerConnection>,
    pub call_id: String,
    pub peer_guid: String,
}

impl CallSession {
    /// Create a new peer connection and wire the ICE / state callbacks to
    /// the supplied event channel.
    pub async fn new(
        call_id: String,
        peer_guid: String,
        events_tx: mpsc::UnboundedSender<SessionEvent>,
    ) -> Result<Self, SessionError> {
        let mut media_engine = MediaEngine::default();
        // Audio codecs (Opus) are registered by `register_default_codecs`
        // — that's also where video codecs would land when we add them.
        media_engine.register_default_codecs()?;

        let api = APIBuilder::new().with_media_engine(media_engine).build();

        let config = RTCConfiguration {
            ice_servers: default_ice_servers(),
            ..Default::default()
        };
        let pc = Arc::new(api.new_peer_connection(config).await?);

        // Forward locally-gathered ICE candidates to the signaling layer.
        let tx = events_tx.clone();
        pc.on_ice_candidate(Box::new(move |candidate: Option<RTCIceCandidate>| {
            let tx = tx.clone();
            Box::pin(async move {
                if let Some(c) = candidate {
                    if let Ok(json) = c.to_json() {
                        let value = serde_json::to_value(&json).unwrap_or(serde_json::Value::Null);
                        let _ = tx.send(SessionEvent::LocalIceCandidate(value));
                    }
                }
            })
        }));

        // Surface peer connection state to the UI so we can transition
        // "connecting" → "active" → "ended" without polling.
        let tx = events_tx.clone();
        pc.on_peer_connection_state_change(Box::new(move |state: RTCPeerConnectionState| {
            let tx = tx.clone();
            Box::pin(async move {
                let label = match state {
                    RTCPeerConnectionState::New => "new",
                    RTCPeerConnectionState::Connecting => "connecting",
                    RTCPeerConnectionState::Connected => "active",
                    RTCPeerConnectionState::Disconnected => "disconnected",
                    RTCPeerConnectionState::Failed => "failed",
                    RTCPeerConnectionState::Closed => "ended",
                    RTCPeerConnectionState::Unspecified => "unknown",
                };
                let _ = tx.send(SessionEvent::ConnectionState(label.to_string()));
            })
        }));

        // TODO: add audio track (cpal capture → TrackLocalStaticSample).
        // TODO: install RTP frame cryptor for E2EE matching Android's
        //       `CallFrameCryptor` (X25519-derived shared secret + AES-128-GCM).

        Ok(Self { pc, call_id, peer_guid })
    }

    /// Generate an SDP offer to send to the callee.
    pub async fn create_offer(&self) -> Result<String, SessionError> {
        let offer = self.pc.create_offer(None).await?;
        self.pc.set_local_description(offer.clone()).await?;
        Ok(offer.sdp)
    }

    /// Apply a remote offer (callee path) and produce the matching answer.
    pub async fn create_answer(&self, remote_offer_sdp: &str) -> Result<String, SessionError> {
        let offer = RTCSessionDescription::offer(remote_offer_sdp.to_string())
            .map_err(|e| SessionError::InvalidSdp(e.to_string()))?;
        self.pc.set_remote_description(offer).await?;
        let answer = self.pc.create_answer(None).await?;
        self.pc.set_local_description(answer.clone()).await?;
        Ok(answer.sdp)
    }

    /// Apply the remote answer (caller path) once the callee responds.
    pub async fn set_remote_answer(&self, sdp: &str) -> Result<(), SessionError> {
        let answer = RTCSessionDescription::answer(sdp.to_string())
            .map_err(|e| SessionError::InvalidSdp(e.to_string()))?;
        self.pc.set_remote_description(answer).await?;
        Ok(())
    }

    /// Add a remote ICE candidate received via signaling.
    pub async fn add_remote_ice(&self, candidate: serde_json::Value) -> Result<(), SessionError> {
        // The candidate JSON shape from the peer is `{ candidate, sdpMid, sdpMLineIndex, ... }`
        // — webrtc-rs's `RTCIceCandidateInit` deserializes that directly.
        let init: webrtc::ice_transport::ice_candidate::RTCIceCandidateInit =
            serde_json::from_value(candidate)
                .map_err(|e| SessionError::InvalidSdp(format!("ice json: {}", e)))?;
        self.pc.add_ice_candidate(init).await?;
        Ok(())
    }

    /// Tear down the peer connection cleanly.
    pub async fn close(&self) {
        let _ = self.pc.close().await;
    }
}
