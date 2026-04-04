use std::sync::Arc;
use tauri::{AppHandle, Emitter};
use tokio::time::{interval, Duration};

use crate::nats::operations;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Heartbeat task
// ---------------------------------------------------------------------------

/// Heartbeat interval: 2 minutes (matches mobile DeviceConstants).
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(120);

/// Number of consecutive heartbeat failures before suspending session.
const MAX_FAILURES: u32 = 3;

/// Spawn a background heartbeat task that:
/// - Sends `device.heartbeat` to the vault every 2 minutes
/// - Checks session TTL and emits warnings at 30min and 5min
/// - Suspends the session after 3 consecutive heartbeat failures
/// - Expires the session when TTL reaches 0
pub fn spawn_heartbeat(
    app_handle: AppHandle,
    state: Arc<AppState>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = interval(HEARTBEAT_INTERVAL);
        let mut consecutive_failures: u32 = 0;
        let mut warned_30min = false;
        let mut warned_5min = false;

        loop {
            tick.tick().await;

            // Check session state with a single lock acquisition
            let (session_active, remaining) = {
                let session = state.session.read().await;
                (session.is_active(), session.seconds_remaining().unwrap_or(0))
            };

            if !session_active {
                log::debug!("Heartbeat: session not active, skipping");
                warned_30min = false;
                warned_5min = false;
                continue;
            }

            if remaining <= 0 {
                state.session.write().await.expire();
                let _ = app_handle.emit("vault:session-update", &serde_json::json!({
                    "status": "expired",
                    "reason": "session TTL elapsed",
                }));
                log::info!("Heartbeat: session expired");
                continue;
            }

            if remaining <= 300 && !warned_5min {
                warned_5min = true;
                let _ = app_handle.emit("vault:session-warning", &serde_json::json!({
                    "level": "critical",
                    "seconds_remaining": remaining,
                    "message": "Session expires in less than 5 minutes",
                }));
            } else if remaining <= 1800 && !warned_30min {
                warned_30min = true;
                let _ = app_handle.emit("vault:session-warning", &serde_json::json!({
                    "level": "warning",
                    "seconds_remaining": remaining,
                    "message": "Session expires in less than 30 minutes",
                }));
            }

            // Send heartbeat
            match operations::execute(
                &state,
                "device.heartbeat",
                serde_json::json!({}),
            )
            .await
            {
                Ok(resp) if resp.success => {
                    consecutive_failures = 0;
                    log::debug!("Heartbeat: success, {} seconds remaining", remaining);
                }
                Ok(resp) => {
                    consecutive_failures += 1;
                    log::warn!(
                        "Heartbeat: vault returned error ({}/{}): {:?}",
                        consecutive_failures,
                        MAX_FAILURES,
                        resp.error,
                    );
                }
                Err(e) => {
                    consecutive_failures += 1;
                    log::warn!(
                        "Heartbeat: failed ({}/{}): {}",
                        consecutive_failures,
                        MAX_FAILURES,
                        e,
                    );
                }
            }

            // Suspend after too many failures
            if consecutive_failures >= MAX_FAILURES {
                state.session.write().await.suspend();
                let _ = app_handle.emit("vault:session-update", &serde_json::json!({
                    "status": "suspended",
                    "reason": "heartbeat failures exceeded threshold",
                }));
                log::warn!("Heartbeat: session suspended after {} consecutive failures", MAX_FAILURES);
                consecutive_failures = 0;
            }
        }
    })
}
