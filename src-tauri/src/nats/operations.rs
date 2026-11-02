use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

use crate::crypto::encrypt;
use crate::nats::messages::{
    encode_envelope, DeviceOpRequest, DeviceOpResponse, MSG_DEVICE_OP_REQUEST,
};
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Dev watchdog — runaway vault-op detector
// ---------------------------------------------------------------------------
//
// Every vault op funnels through execute_operation, so it is the one
// place to measure op rate. A frontend reactive loop (a Svelte $effect
// that re-fires its own load) sprays vault ops in a tight loop. On a
// slow vault that crawled and went unnoticed; once the vsock multiplex
// made ops fast it flooded — 8k ops in 6 minutes — and the symptom was
// a frozen UI with no clue what caused it (2026-05-20).
//
// This watchdog is always on and silent in normal use. When the op
// rate goes pathological it logs one loud line naming the dominant
// operation — so the *next* loop announces its own culprit instead of
// presenting as a mystery freeze. The log fires on the Rust thread, so
// it still reaches the console even when the WebView/JS thread is
// pinned by the loop.

const OP_WATCH_WINDOW: Duration = Duration::from_secs(10);
/// >40 ops in 10s is far above any legitimate burst (a screen load is
/// a handful); a reactive loop does hundreds.
const OP_WATCH_THRESHOLD: usize = 40;
/// Warn at most this often while a flood persists — one loud line, not
/// a second flood in the log.
const OP_WATCH_WARN_COOLDOWN: Duration = Duration::from_secs(5);

struct OpRateWatch {
    recent: Vec<(Instant, String)>,
    last_warned: Option<Instant>,
}

static OP_RATE_WATCH: Mutex<OpRateWatch> = Mutex::new(OpRateWatch {
    recent: Vec::new(),
    last_warned: None,
});

/// Record one vault op and, if the recent rate is pathological, log a
/// single loud line naming the operations that dominate the window.
fn record_op_and_check(operation: &str) {
    let now = Instant::now();
    let mut w = match OP_RATE_WATCH.lock() {
        Ok(w) => w,
        Err(_) => return, // poisoned — a watchdog must never break the app
    };
    w.recent.push((now, operation.to_string()));
    let cutoff = now.checked_sub(OP_WATCH_WINDOW).unwrap_or(now);
    w.recent.retain(|(t, _)| *t >= cutoff);

    if w.recent.len() <= OP_WATCH_THRESHOLD {
        return;
    }
    if let Some(last) = w.last_warned {
        if now.duration_since(last) < OP_WATCH_WARN_COOLDOWN {
            return;
        }
    }
    w.last_warned = Some(now);

    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for (_, op) in &w.recent {
        *counts.entry(op.as_str()).or_insert(0) += 1;
    }
    let mut top: Vec<(&str, usize)> = counts.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1));
    let breakdown = top
        .iter()
        .take(3)
        .map(|(op, n)| format!("{}×{}", op, n))
        .collect::<Vec<_>>()
        .join(", ");

    log::error!(
        "DEV-WATCHDOG: runaway vault-op rate — {} ops in {}s (top: {}). \
         A frontend reactive loop is almost certainly re-firing a load — \
         check $effect blocks that read state their own load() writes; \
         load-once belongs in onMount.",
        w.recent.len(),
        OP_WATCH_WINDOW.as_secs(),
        breakdown,
    );
}

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
    /// Timed out waiting for the vault to acknowledge the request at all.
    /// Suggests network/vault issue, not a slow human.
    AckTimeout,
    /// Vault acknowledged, but no final response within the longer
    /// phone-approval window. Almost always means the human didn't
    /// approve in time (or denied without producing a response).
    ApprovalTimeout,
    /// The desktop stopped waiting: the person chose Stop waiting, or the
    /// listener ended (lock, End session, log-out, a dropped connection).
    /// The vault wasn't told, and can't be (#42), so the request may still
    /// be approved on the phone and carried out. Displays
    /// [`STOPPED_WAITING_NOTICE`]; never "cancelled".
    StoppedWaiting,
    ResponseError(String),
}

/// Shown when the desktop stopped waiting for a request's answer (#42).
/// The send sheet and the secrets chip show their own texts for it; they
/// match on [`OperationError::code`] (`"stopped_waiting"`), and on this
/// text's "stopped waiting" only for an error thrown over IPC.
pub const STOPPED_WAITING_NOTICE: &str =
    "This desktop stopped waiting for an answer. If your phone still shows the request, approving it there will still carry it out.";

impl fmt::Display for OperationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotConnected => write!(f, "Not connected to vault"),
            Self::NoConnectionKey => write!(f, "No connection key available"),
            Self::EncryptionFailed(e) => write!(f, "Encryption failed: {}", e),
            Self::EncodingFailed(e) => write!(f, "Encoding failed: {}", e),
            Self::PublishFailed(e) => write!(f, "Publish failed: {}", e),
            Self::AckTimeout => write!(f, "Vault did not acknowledge the request"),
            Self::ApprovalTimeout => write!(f, "Phone approval timed out"),
            Self::StoppedWaiting => f.write_str(STOPPED_WAITING_NOTICE),
            Self::ResponseError(e) => write!(f, "Response error: {}", e),
        }
    }
}

impl std::error::Error for OperationError {}

impl OperationError {
    /// A stable code for errors the frontend words for itself (#42).
    pub fn code(&self) -> Option<&'static str> {
        match self {
            Self::StoppedWaiting => Some("stopped_waiting"),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Execute a vault operation via NATS
// ---------------------------------------------------------------------------

/// Send a `device_op_request` to the vault and await the response.
///
/// Two-stage timeout model. Phone-required ops produce two responses:
/// an immediate `status: "pending_approval"` ack from the vault, then
/// a final response once the human taps approve/deny. The split
/// timeouts preserve the diagnostic value of a failure:
///
///   * `ack_timeout_secs`: short (~5s). If the vault never sends *any*
///     response in this window, something is wrong with the vault or
///     NATS path — not the human. Surfaces as `AckTimeout`.
///   * `final_timeout_secs`: longer (~120s for phone-required ops).
///     Starts ticking either from the original publish (for ops the
///     vault answers directly) or after the ack arrives. The ack
///     "extends" the deadline because it confirms the request is now
///     in the human's hands.
///
/// Ops that don't require phone approval return their final response
/// directly without an intermediate ack — those still resolve within
/// the ack window, which is the common path.
pub async fn execute_operation(
    state: &AppState,
    operation: &str,
    params: serde_json::Value,
    ack_timeout_secs: u64,
    final_timeout_secs: u64,
) -> Result<DeviceOpResponse, OperationError> {
    // DEV-WATCHDOG: sample the op rate through this single chokepoint
    // so a runaway frontend loop is named in the log instead of
    // silently freezing the UI.
    record_op_and_check(operation);

    // Read connection key
    let connection_key = {
        let key_guard = state.connection_key.read().await;
        key_guard.ok_or(OperationError::NoConnectionKey)?
    };

    // Read credentials for the connection ID. The envelope's KeyID
    // field is what the vault uses to look up `connections/{KeyID}` in
    // storage, so it has to be the connection_id — not the session_id.
    let connection_id = {
        let creds_guard = state.credentials.read().await;
        let creds = creds_guard.as_ref().ok_or(OperationError::NotConnected)?;
        creds.connection_id.clone()
    };
    let key_id = connection_id.clone();

    // Build the request
    let request_id = hex::encode(crate::crypto::keys::generate_random_bytes(16));
    let request = DeviceOpRequest {
        request_id: request_id.clone(),
        operation: operation.to_string(),
        connection_id: connection_id.clone(),
        params,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    let request_json = serde_json::to_vec(&request)
        .map_err(|e| OperationError::EncodingFailed(e.to_string()))?;

    let encrypted = encrypt::encrypt(&connection_key, &request_json)
        .map_err(|e| OperationError::EncryptionFailed(e.to_string()))?;

    let nats_client = state.nats.lock().await;
    let sequence = nats_client.next_sequence();
    let envelope_bytes = encode_envelope(
        MSG_DEVICE_OP_REQUEST,
        &key_id,
        &encrypted,
        sequence,
    )
    .map_err(|e| OperationError::EncodingFailed(e.to_string()))?;

    // Register a pending mpsc — listener.rs forwards every response
    // for this request_id here, but only removes the entry on a
    // non-ack response. We loop-drain.
    let (tx, mut rx) = mpsc::unbounded_channel();
    {
        let mut pending = state.pending_responses.lock().await;
        pending.insert(request_id.clone(), tx);
    }

    nats_client
        .publish_message(&envelope_bytes)
        .await
        .map_err(|e| {
            // Couldn't publish — drop our pending entry before bubbling.
            let pending = state.pending_responses.clone();
            let rid = request_id.clone();
            tokio::spawn(async move { pending.lock().await.remove(&rid); });
            OperationError::PublishFailed(e.to_string())
        })?;

    drop(nats_client);

    let final_value = match await_response(&mut rx, ack_timeout_secs, final_timeout_secs, &request_id).await {
        Ok(v) => v,
        Err(e) => {
            // Timed out: drop our pending entry. Stopped waiting: it's
            // already gone (that's how we were told).
            if matches!(e, OperationError::AckTimeout | OperationError::ApprovalTimeout) {
                let pending = state.pending_responses.clone();
                let rid = request_id.clone();
                tokio::spawn(async move { pending.lock().await.remove(&rid); });
            }
            return Err(e);
        }
    };

    // Parse as DeviceOpResponse
    let mut response: DeviceOpResponse = serde_json::from_value(final_value)
        .map_err(|e| OperationError::ResponseError(e.to_string()))?;

    // Some ops (e.g. secret.unlock-session) return op-specific fields
    // at the top level rather than nested under `data`. Fold those
    // captured extras into `data` so the frontend has one place to
    // look. Don't overwrite `data` if the vault already populated it.
    if response.data.is_none() && !response.extra.is_empty() {
        // Drop the structural fields we already mapped, keep only
        // the op-specific extras.
        let mut data_map = serde_json::Map::new();
        for (k, v) in response.extra.iter() {
            // `status` is purely a flow signal; keep the data clean
            // unless the op surfaces a meaningful status (denied is
            // already surfaced via error/success, executed is the
            // happy path so the UI doesn't need it).
            data_map.insert(k.clone(), v.clone());
        }
        if !data_map.is_empty() {
            response.data = Some(serde_json::Value::Object(data_map));
        }
    }

    Ok(response)
}

/// Whether a response is a `pending_approval` ack (no payload, just "the
/// vault saw your request and is waiting on the human").
fn is_pending_ack(v: &serde_json::Value) -> bool {
    v.get("status")
        .and_then(|s| s.as_str())
        .map(|s| s == "pending_approval")
        .unwrap_or(false)
}

/// Wait for a request's final response on `rx`.
///
/// First read: a short window. The vault should answer almost at once,
/// with the final response (no phone needed) or a `pending_approval` ack
/// (phone-required). After an ack, keep reading until a non-ack message:
/// that's the real final response. Duplicate acks can arrive (listener
/// fan-out, NATS replay, intermediate status updates) and must not poison
/// the result, or the caller would see `pending_approval` as the final
/// payload and report "Approval did not complete" right after the human
/// approved.
///
/// A channel that closes means the desktop stopped waiting (#42):
/// [`OperationError::StoppedWaiting`], never "cancelled", since the vault
/// still has the request.
async fn await_response(
    rx: &mut mpsc::UnboundedReceiver<serde_json::Value>,
    ack_timeout_secs: u64,
    final_timeout_secs: u64,
    request_id: &str,
) -> Result<serde_json::Value, OperationError> {
    let first_value = match tokio::time::timeout(Duration::from_secs(ack_timeout_secs), rx.recv()).await {
        Err(_) => return Err(OperationError::AckTimeout),
        Ok(None) => return Err(OperationError::StoppedWaiting),
        Ok(Some(v)) => v,
    };
    if !is_pending_ack(&first_value) {
        return Ok(first_value);
    }
    loop {
        match tokio::time::timeout(Duration::from_secs(final_timeout_secs), rx.recv()).await {
            Err(_) => return Err(OperationError::ApprovalTimeout),
            Ok(None) => return Err(OperationError::StoppedWaiting),
            Ok(Some(v)) if is_pending_ack(&v) => {
                log::debug!("Ignoring duplicate pending_approval ack for {}", request_id);
            }
            Ok(Some(v)) => return Ok(v),
        }
    }
}

/// Default for ops that don't require phone approval. Short ack and
/// final windows — these ops answer immediately or not at all.
pub async fn execute(
    state: &AppState,
    operation: &str,
    params: serde_json::Value,
) -> Result<DeviceOpResponse, OperationError> {
    execute_operation(state, operation, params, 30, 30).await
}

/// For ops that may route through phone approval. Same short ack
/// window so a dead vault still fails fast, but a long final window
/// for the human to tap Approve.
pub async fn execute_phone_required(
    state: &AppState,
    operation: &str,
    params: serde_json::Value,
) -> Result<DeviceOpResponse, OperationError> {
    execute_operation(state, operation, params, 5, 120).await
}

/// Stop waiting for a pending operation (the person's Stop waiting).
/// Removes the channel from `pending_responses` so the awaiter wakes with
/// [`OperationError::StoppedWaiting`]. The vault is not notified, and the
/// legacy vault has no way to cancel a pending request (#42): the prompt
/// stays on the phone, and approving it there still carries it out.
pub async fn cancel(state: &AppState, request_id: &str) -> bool {
    let mut pending = state.pending_responses.lock().await;
    pending.remove(request_id).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// #42: a waiter whose channel closes, before or after the vault's
    /// ack, stopped waiting: never "cancelled", and the text says the
    /// phone may still carry it out.
    #[tokio::test]
    async fn a_dropped_request_says_the_desktop_stopped_waiting() {
        // Before any answer.
        let (tx, mut rx) = mpsc::unbounded_channel::<serde_json::Value>();
        drop(tx);
        let err = await_response(&mut rx, 5, 5, "r1").await.unwrap_err();
        assert!(matches!(err, OperationError::StoppedWaiting));
        // After the pending_approval ack, while the phone shows it.
        let (tx, mut rx) = mpsc::unbounded_channel();
        tx.send(json!({"status": "pending_approval"})).unwrap();
        drop(tx);
        let err = await_response(&mut rx, 5, 5, "r2").await.unwrap_err();
        assert!(matches!(err, OperationError::StoppedWaiting));
        let text = err.to_string();
        assert_eq!(text, STOPPED_WAITING_NOTICE);
        assert!(!text.to_lowercase().contains("cancel"), "{text}");
    }

    /// The answer still comes through: directly, or after acks
    /// (duplicates ignored).
    #[tokio::test]
    async fn the_final_response_comes_through_after_acks() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        tx.send(json!({"status": "executed", "n": 1})).unwrap();
        assert_eq!(await_response(&mut rx, 5, 5, "r3").await.unwrap()["n"], 1);
        tx.send(json!({"status": "pending_approval"})).unwrap();
        tx.send(json!({"status": "pending_approval"})).unwrap();
        tx.send(json!({"status": "executed", "n": 2})).unwrap();
        assert_eq!(await_response(&mut rx, 5, 5, "r4").await.unwrap()["n"], 2);
    }

    /// #42: the person's Stop waiting (`cancel`) wakes the waiter with
    /// StoppedWaiting, coded for the frontend.
    #[tokio::test]
    async fn stop_waiting_wakes_the_waiter() {
        let state = crate::state::AppState::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        state.pending_responses.lock().await.insert("r7".into(), tx);
        assert!(cancel(&state, "r7").await);
        let err = await_response(&mut rx, 5, 5, "r7").await.unwrap_err();
        assert!(matches!(err, OperationError::StoppedWaiting));
        assert_eq!(err.code(), Some("stopped_waiting"));
        assert!(!cancel(&state, "r7").await, "already gone");
    }

    /// Timeouts are told apart from stopping: no answer at all, and an
    /// ack with no final answer.
    #[tokio::test]
    async fn timeouts_are_not_stopped_waiting() {
        let (_tx, mut rx) = mpsc::unbounded_channel::<serde_json::Value>();
        assert!(matches!(await_response(&mut rx, 0, 0, "r5").await, Err(OperationError::AckTimeout)));
        let (tx, mut rx) = mpsc::unbounded_channel();
        tx.send(json!({"status": "pending_approval"})).unwrap();
        assert!(matches!(await_response(&mut rx, 1, 0, "r6").await, Err(OperationError::ApprovalTimeout)));
    }
}
