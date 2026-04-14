use serde::Serialize;
use tauri::State;

use crate::nats::operations;
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct VaultOpResponse {
    pub success: bool,
    pub data: Option<serde_json::Value>,
    pub error: Option<String>,
    pub pending_approval: bool,
}

impl VaultOpResponse {
    fn from_op(result: Result<crate::nats::messages::DeviceOpResponse, operations::OperationError>) -> Self {
        match result {
            Ok(resp) => Self {
                success: resp.success,
                data: resp.data,
                error: resp.error,
                pending_approval: resp.pending_phone_approval,
            },
            Err(e) => Self {
                success: false,
                data: None,
                error: Some(e.to_string()),
                pending_approval: false,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Independent operations (no phone approval)
// ---------------------------------------------------------------------------

/// List connections.
#[tauri::command]
pub async fn list_connections(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute(&state, "connection.list", serde_json::json!({})).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Get a specific connection.
#[tauri::command]
pub async fn get_connection(state: State<'_, AppState>, connection_id: String) -> Result<VaultOpResponse, String> {
    let result = operations::execute(
        &state,
        "connection.get",
        serde_json::json!({ "connection_id": connection_id }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// List feed events.
#[tauri::command]
pub async fn list_feed(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute(&state, "feed.list", serde_json::json!({})).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Query audit log.
#[tauri::command]
pub async fn query_audit(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute(&state, "audit.query", serde_json::json!({})).await;
    Ok(VaultOpResponse::from_op(result))
}

/// List messages.
#[tauri::command]
pub async fn list_messages(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute(&state, "message.list", serde_json::json!({})).await;
    Ok(VaultOpResponse::from_op(result))
}

/// List secrets catalog (metadata only, no secret values).
#[tauri::command]
pub async fn list_secrets_catalog(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute(&state, "secrets.catalog", serde_json::json!({})).await;
    Ok(VaultOpResponse::from_op(result))
}

// ---------------------------------------------------------------------------
// Phone-approval-required operations
// ---------------------------------------------------------------------------

/// Request a secret value. Returns pending_approval: true.
#[tauri::command]
pub async fn request_secret(state: State<'_, AppState>, secret_id: String) -> Result<VaultOpResponse, String> {
    let result = operations::execute(
        &state,
        "secrets.retrieve",
        serde_json::json!({ "secret_id": secret_id }),
    ).await;

    // Track pending delegation if awaiting phone approval
    if let Ok(ref resp) = result {
        if resp.pending_phone_approval {
            let mut delegation = state.delegation.lock().await;
            delegation.add_pending(resp.request_id.clone(), "secrets.retrieve".to_string());
        }
    }

    Ok(VaultOpResponse::from_op(result))
}

// ---------------------------------------------------------------------------
// New feature operations
// ---------------------------------------------------------------------------

/// List proposals (independent).
#[tauri::command]
pub async fn list_proposals(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute(&state, "proposal.list", serde_json::json!({})).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Cast a vote (phone-required).
#[tauri::command]
pub async fn cast_vote(state: State<'_, AppState>, proposal_id: String, choice: String) -> Result<VaultOpResponse, String> {
    let result = operations::execute(
        &state,
        "vote.cast",
        serde_json::json!({ "proposal_id": proposal_id, "choice": choice }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// List personal data (independent).
#[tauri::command]
pub async fn list_personal_data(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute(&state, "personal-data.list", serde_json::json!({})).await;
    Ok(VaultOpResponse::from_op(result))
}

/// List wallets (independent).
#[tauri::command]
pub async fn list_wallets(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute(&state, "wallet.list", serde_json::json!({})).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Get wallet balance (independent).
#[tauri::command]
pub async fn get_wallet_balance(state: State<'_, AppState>, wallet_id: String) -> Result<VaultOpResponse, String> {
    let result = operations::execute(
        &state,
        "wallet.get-balance",
        serde_json::json!({ "wallet_id": wallet_id }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Get transaction history (independent).
#[tauri::command]
pub async fn get_transaction_history(state: State<'_, AppState>, wallet_id: String) -> Result<VaultOpResponse, String> {
    let result = operations::execute(
        &state,
        "wallet.get-history",
        serde_json::json!({ "wallet_id": wallet_id, "limit": 50 }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Send BTC (phone-required, 60s timeout for signing).
#[tauri::command]
pub async fn send_btc(
    state: State<'_, AppState>,
    wallet_id: String,
    to_address: String,
    amount_sats: i64,
    fee_rate: Option<i32>,
) -> Result<VaultOpResponse, String> {
    let mut params = serde_json::json!({
        "wallet_id": wallet_id,
        "to_address": to_address,
        "amount_sats": amount_sats,
    });
    if let Some(rate) = fee_rate {
        params["fee_rate"] = serde_json::json!(rate);
    }
    let result = operations::execute_operation(&state, "wallet.send", params, 60).await;
    Ok(VaultOpResponse::from_op(result))
}

/// List connected devices (independent).
#[tauri::command]
pub async fn list_devices(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute(&state, "device.list", serde_json::json!({})).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Get own profile (independent).
#[tauri::command]
pub async fn get_profile(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute(&state, "profile.view", serde_json::json!({})).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Update fields in the user's published profile (phone-required).
///
/// `fields` is a JSON object whose keys are field IDs and whose values are
/// `{ display_name, value, visibility }` triples — same shape Android sends to
/// `profile.update`. The vault validates the schema and the phone confirms.
#[tauri::command]
pub async fn update_profile(
    state: State<'_, AppState>,
    fields: serde_json::Value,
) -> Result<VaultOpResponse, String> {
    let result = operations::execute(
        &state,
        "profile.update",
        serde_json::json!({ "fields": fields }),
    )
    .await;
    Ok(VaultOpResponse::from_op(result))
}

/// Update a personal-data section (phone-required).
///
/// `section` identifies the category (e.g., `"medical"`, `"financial"`) and
/// `entries` is an array of `{ field_id, value, visibility }` items.
#[tauri::command]
pub async fn update_personal_data(
    state: State<'_, AppState>,
    section: String,
    entries: serde_json::Value,
) -> Result<VaultOpResponse, String> {
    let result = operations::execute(
        &state,
        "personal-data.update",
        serde_json::json!({ "section": section, "entries": entries }),
    )
    .await;
    Ok(VaultOpResponse::from_op(result))
}

/// Revoke a connection (phone-required — irreversible).
#[tauri::command]
pub async fn revoke_connection(
    state: State<'_, AppState>,
    connection_id: String,
) -> Result<VaultOpResponse, String> {
    let result = operations::execute(
        &state,
        "connection.revoke",
        serde_json::json!({ "connection_id": connection_id }),
    )
    .await;
    Ok(VaultOpResponse::from_op(result))
}

/// Send a read receipt for a single message (independent — no phone needed).
#[tauri::command]
pub async fn mark_message_read(
    state: State<'_, AppState>,
    connection_id: String,
    message_id: String,
) -> Result<VaultOpResponse, String> {
    let result = operations::execute(
        &state,
        "message.read-receipt",
        serde_json::json!({
            "connection_id": connection_id,
            "message_id": message_id,
        }),
    )
    .await;
    Ok(VaultOpResponse::from_op(result))
}

/// Send a message.
#[tauri::command]
pub async fn send_message(
    state: State<'_, AppState>,
    peer_connection_id: String,
    content: String,
) -> Result<VaultOpResponse, String> {
    let result = operations::execute(
        &state,
        "message.send",
        serde_json::json!({
            "connection_id": peer_connection_id,
            "content": content,
            "content_type": "text",
        }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Get conversation messages for a connection.
#[tauri::command]
pub async fn get_conversation(state: State<'_, AppState>, peer_connection_id: String) -> Result<VaultOpResponse, String> {
    let result = operations::execute(
        &state,
        "message.list",
        serde_json::json!({ "connection_id": peer_connection_id }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// List call history (independent).
#[tauri::command]
pub async fn list_call_history(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute(&state, "call.history", serde_json::json!({})).await;
    Ok(VaultOpResponse::from_op(result))
}

// ---------------------------------------------------------------------------
// Missing wallet commands (parity with iOS WalletClient)
// ---------------------------------------------------------------------------

/// Create a new wallet (phone-required — key generation in enclave).
#[tauri::command]
pub async fn create_wallet(state: State<'_, AppState>, label: String, network: String) -> Result<VaultOpResponse, String> {
    let result = operations::execute(
        &state,
        "wallet.create",
        serde_json::json!({ "label": label, "network": network }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Get receive address for a wallet.
#[tauri::command]
pub async fn get_wallet_address(state: State<'_, AppState>, wallet_id: String) -> Result<VaultOpResponse, String> {
    let result = operations::execute(
        &state,
        "wallet.get-address",
        serde_json::json!({ "wallet_id": wallet_id }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Get fee estimates from mempool.
#[tauri::command]
pub async fn get_fee_estimates(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute(&state, "wallet.get-fees", serde_json::json!({})).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Delete a wallet (phone-required).
#[tauri::command]
pub async fn delete_wallet(state: State<'_, AppState>, wallet_id: String) -> Result<VaultOpResponse, String> {
    let result = operations::execute(
        &state,
        "wallet.delete",
        serde_json::json!({ "wallet_id": wallet_id }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Set wallet visibility (phone-required — making public is irreversible).
#[tauri::command]
pub async fn set_wallet_visibility(state: State<'_, AppState>, wallet_id: String, is_public: bool) -> Result<VaultOpResponse, String> {
    let result = operations::execute(
        &state,
        "wallet.set-visibility",
        serde_json::json!({ "wallet_id": wallet_id, "is_public": is_public }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Request payment from a connection.
#[tauri::command]
pub async fn request_payment(
    state: State<'_, AppState>,
    connection_id: String,
    wallet_id: String,
    amount_sats: i64,
    memo: Option<String>,
) -> Result<VaultOpResponse, String> {
    let mut params = serde_json::json!({
        "connection_id": connection_id,
        "wallet_id": wallet_id,
        "amount_sats": amount_sats,
    });
    if let Some(m) = memo {
        params["memo"] = serde_json::json!(m);
    }
    let result = operations::execute(&state, "wallet.request-payment", params).await;
    Ok(VaultOpResponse::from_op(result))
}
