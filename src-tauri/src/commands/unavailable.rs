//! The vault operations this build can't carry out. They went over NATS;
//! the device engine (`crates/vettid-device`) doesn't carry them yet. The
//! commands keep their Tauri signatures and their callers stay as they
//! are, but [`execute`] sends nothing and answers every one with the same
//! plain error, [`NOT_AVAILABLE`]. Nothing about the operation is claimed:
//! no "sent", "saved" or "removed".

use crate::state::AppState;

/// What every vault operation answers in this build.
///
/// NEW TEXT: needs the owner's approval before a release.
pub const NOT_AVAILABLE: &str = "Not available yet in this build: the desktop is moving to a new connection to your vault.";

/// A vault operation's answer, in the shape the commands read. This build
/// never makes one: [`execute`] always fails.
#[derive(Debug, Clone)]
pub struct OpResponse {
    pub success: bool,
    pub data: Option<serde_json::Value>,
    pub error: Option<String>,
    pub pending_phone_approval: bool,
}

/// Why a vault operation failed: it isn't available in this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationError {
    NotAvailable,
}

impl OperationError {
    /// No code: the frontend shows the text as it is.
    pub fn code(&self) -> Option<&'static str> {
        None
    }
}

impl std::fmt::Display for OperationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(NOT_AVAILABLE)
    }
}

impl std::error::Error for OperationError {}

/// Send nothing; answer [`OperationError::NotAvailable`].
pub async fn execute(_state: &AppState, _operation: &str, _params: serde_json::Value) -> Result<OpResponse, OperationError> {
    Err(OperationError::NotAvailable)
}

/// The same for an operation that needs the phone's approval: nothing is
/// sent, so the phone is never asked.
pub async fn execute_phone_required(_state: &AppState, _operation: &str, _params: serde_json::Value) -> Result<OpResponse, OperationError> {
    Err(OperationError::NotAvailable)
}

/// Nothing waits for an answer, so there is nothing to stop waiting for.
pub async fn cancel(_state: &AppState, _request_id: &str) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn every_operation_answers_the_same_plain_error() {
        let state = AppState::new();
        for op in ["connection.list", "message.send", "secret.add", "call.start", "call.turn-credentials"] {
            let e = execute(&state, op, serde_json::json!({})).await.unwrap_err();
            assert_eq!(e.to_string(), NOT_AVAILABLE);
            assert_eq!(e.code(), None);
            let e = execute_phone_required(&state, op, serde_json::json!({})).await.unwrap_err();
            assert_eq!(e.to_string(), NOT_AVAILABLE);
        }
        assert!(!cancel(&state, "r").await);
    }
}
