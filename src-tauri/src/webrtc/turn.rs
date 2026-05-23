//! TURN credential fetch.
//!
//! Calls the `call.turn-credentials` vault op once per call setup;
//! parses the response into webrtc-rs `RTCIceServer` rows. The vault
//! proxies to the AWS Lambda that mints HMAC-SHA1 short-lived
//! Cloudflare TURN creds tied to the user's identity.
//!
//! Response shape (matches `getTurnCredentials.ts` Lambda):
//! ```json
//! {
//!   "ice_servers": [
//!     { "urls": ["stun:..."] },
//!     { "urls": ["turn:...", "turns:..."], "username": "...", "credential": "..." }
//!   ],
//!   "expires_at": "ISO-8601"
//! }
//! ```

#![cfg(feature = "webrtc")]

use webrtc::ice_transport::ice_server::RTCIceServer;

use crate::nats::operations;
use crate::state::AppState;

/// Fetch TURN credentials from the vault, parse into a list of ICE
/// servers ready to drop into `RTCConfiguration`. Returns an empty
/// vec on any error so the caller can fall back to its STUN-only
/// defaults — a degraded call is better than a refused one.
pub async fn fetch_ice_servers(state: &AppState) -> Vec<RTCIceServer> {
    let result = operations::execute(state, "call.turn-credentials", serde_json::json!({})).await;
    let resp = match result {
        Ok(r) => r,
        Err(e) => {
            log::warn!("call.turn-credentials failed: {} — falling back to STUN", e);
            return Vec::new();
        }
    };

    // `execute` returns the unwrapped DeviceOpResponse — look for the
    // top-level `data` then `ice_servers`. The vault's HandleGetTurnCredentials
    // forwards the Lambda body unmodified, so the shape is the same.
    let data = match resp.data {
        Some(d) => d,
        None => {
            log::warn!("call.turn-credentials returned no data — falling back to STUN");
            return Vec::new();
        }
    };

    let arr = match data.get("ice_servers").and_then(|v| v.as_array()) {
        Some(a) => a.clone(),
        None => {
            log::warn!("call.turn-credentials missing ice_servers — falling back to STUN");
            return Vec::new();
        }
    };

    let mut out = Vec::with_capacity(arr.len());
    for entry in arr {
        let urls = entry
            .get("urls")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|u| u.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if urls.is_empty() {
            continue;
        }
        out.push(RTCIceServer {
            urls,
            username: entry
                .get("username")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            credential: entry
                .get("credential")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            ..Default::default()
        });
    }

    if out.is_empty() {
        log::warn!("call.turn-credentials returned no parseable rows — falling back to STUN");
    } else {
        log::info!("Loaded {} ICE server entries from vault", out.len());
    }
    out
}
