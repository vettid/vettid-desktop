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

/// List the user's secrets (metadata only — names, types, categories,
/// discoverability). Values stay on the phone. Calls `secret.list`
/// (singular form is the modern dispatch in the vault; the older
/// `secrets.catalog` referenced an op that never existed).
#[tauri::command]
pub async fn list_secrets_catalog(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute(&state, "secret.list", serde_json::json!({})).await;
    Ok(VaultOpResponse::from_op(result))
}

// ---------------------------------------------------------------------------
// Phone-approval-required operations
// ---------------------------------------------------------------------------

/// Request a secret value (phone-required).
#[tauri::command]
pub async fn request_secret(state: State<'_, AppState>, secret_id: String) -> Result<VaultOpResponse, String> {
    let result = operations::execute_phone_required(
        &state,
        "secrets.retrieve",
        serde_json::json!({ "secret_id": secret_id }),
    ).await;
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
    let result = operations::execute_phone_required(
        &state,
        "vote.cast",
        serde_json::json!({ "proposal_id": proposal_id, "choice": choice }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// List personal data (independent). The vault exposes this as
/// `personal-data.get` with an empty `namespaces` payload — passing
/// no filter returns every field in the user's data index.
#[tauri::command]
pub async fn list_personal_data(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute(&state, "personal-data.get", serde_json::json!({})).await;
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

/// Send BTC (phone-required — signing in enclave gated on phone approval).
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
    let result = operations::execute_phone_required(&state, "wallet.send", params).await;
    Ok(VaultOpResponse::from_op(result))
}

/// List connected devices (independent).
#[tauri::command]
pub async fn list_devices(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute(&state, "device.list", serde_json::json!({})).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Get own profile (independent). Vault routes this as `profile.get`
/// (the older `.view` name doesn't resolve in the current handler).
#[tauri::command]
pub async fn get_profile(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute(&state, "profile.get", serde_json::json!({})).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Get the user's profile photo (base64). Independent op — kept
/// separate from `profile.get` server-side because photos can be
/// hundreds of KB and most callers don't need them on every read.
#[tauri::command]
pub async fn get_profile_photo(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute(&state, "profile.photo.get", serde_json::json!({})).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Retrieve a specific secret value. Phone-required by default;
/// becomes independent once this session has been unlocked via
/// `request_secrets_unlock` (and until the grant expires).
#[tauri::command]
pub async fn get_secret(state: State<'_, AppState>, id: String) -> Result<VaultOpResponse, String> {
    // Phone-required if the session hasn't been unlocked yet —
    // independent once SecretsUnlockedUntil is set. Use the
    // phone-required helper so a non-unlocked call doesn't trip the
    // short ack window mid-approval.
    let result = operations::execute_phone_required(&state, "secret.get", serde_json::json!({ "id": id })).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Request a once-per-session unlock for viewing secret values.
/// Routes through the phone-required approval flow; on phone
/// approval, the vault sets DeviceSession.SecretsUnlockedUntil so
/// subsequent `get_secret` calls within the session don't re-prompt.
#[tauri::command]
pub async fn request_secrets_unlock(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute_phone_required(&state, "secret.unlock-session", serde_json::json!({})).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Cancel a pending phone-approval operation by request_id. The
/// awaiter wakes with a Cancelled error and the UI returns to the
/// pre-request state. Vault-side orphan cleanup (dismissing the
/// approval prompt on the phone) is a future enhancement; right
/// now the orphan on the phone times out on its own.
#[tauri::command]
pub async fn cancel_pending_operation(state: State<'_, AppState>, request_id: String) -> Result<bool, String> {
    Ok(operations::cancel(&state, &request_id).await)
}

/// Get a wallet's transaction history. Independent op — same data
/// the Android wallet detail screen pulls. Sibling to the existing
/// get_wallet_balance + get_wallet_address commands below.
#[tauri::command]
pub async fn get_wallet_transactions(state: State<'_, AppState>, wallet_id: String) -> Result<VaultOpResponse, String> {
    let result = operations::execute(
        &state,
        "wallet.get-history",
        serde_json::json!({ "wallet_id": wallet_id, "limit": 50 }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// One-round-trip screen-load: profile + photo + personal-data
/// bundled into a single vault op. Eliminates 3 separate vsock
/// round-trips on the Vault home; per-op overhead (queue
/// serialization, ChaCha20, JSON encode/decode, response routing)
/// dominates the work for tiny read ops, so bundling cuts the
/// wall-clock load time substantially.
#[tauri::command]
pub async fn get_vault_snapshot(state: State<'_, AppState>) -> Result<VaultOpResponse, String> {
    let result = operations::execute(&state, "vault.snapshot", serde_json::json!({})).await;
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
    let result = operations::execute_phone_required(
        &state,
        "profile.update",
        serde_json::json!({ "fields": fields }),
    )
    .await;
    Ok(VaultOpResponse::from_op(result))
}

/// Upsert one or more personal-data fields (phone-required).
///
/// `fields` is a `{namespace: value}` map and `aliases` is an optional
/// `{namespace: alias}` map for grouping related entries in the catalog.
/// Matches the vault's PersonalDataUpdateRequest shape exactly — the
/// earlier `{section, entries}` shape was a frontend invention and never
/// reached the handler intact.
#[tauri::command]
pub async fn update_personal_data(
    state: State<'_, AppState>,
    fields: serde_json::Value,
    aliases: Option<serde_json::Value>,
) -> Result<VaultOpResponse, String> {
    let mut payload = serde_json::json!({ "fields": fields });
    if let Some(a) = aliases {
        payload["aliases"] = a;
    }
    let result = operations::execute_phone_required(
        &state,
        "personal-data.update",
        payload,
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Add a minor (catalog-visible) secret. Phone-required.
/// Matches the vault's SecretAddRequest shape. `discoverability`
/// defaults to "cataloged" — same default the Android client uses.
#[tauri::command]
pub async fn add_secret(
    state: State<'_, AppState>,
    name: String,
    value: String,
    category: String,
    alias: Option<String>,
    description: Option<String>,
) -> Result<VaultOpResponse, String> {
    let mut payload = serde_json::json!({
        "name": name,
        "value": value,
        "category": category,
        "discoverability": "cataloged",
    });
    if let Some(a) = alias.filter(|s| !s.trim().is_empty()) {
        payload["alias"] = serde_json::Value::String(a);
    }
    if let Some(d) = description.filter(|s| !s.trim().is_empty()) {
        payload["description"] = serde_json::Value::String(d);
    }
    let result = operations::execute_phone_required(&state, "secret.add", payload).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Revoke a connection (phone-required — irreversible).
#[tauri::command]
pub async fn revoke_connection(
    state: State<'_, AppState>,
    connection_id: String,
) -> Result<VaultOpResponse, String> {
    let result = operations::execute_phone_required(
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
    let result = operations::execute_phone_required(
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
    let result = operations::execute_phone_required(
        &state,
        "wallet.delete",
        serde_json::json!({ "wallet_id": wallet_id }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Set wallet visibility (phone-required — making public is irreversible).
#[tauri::command]
pub async fn set_wallet_visibility(state: State<'_, AppState>, wallet_id: String, is_public: bool) -> Result<VaultOpResponse, String> {
    let result = operations::execute_phone_required(
        &state,
        "wallet.set-visibility",
        serde_json::json!({ "wallet_id": wallet_id, "is_public": is_public }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Update a minor secret in place (phone-required). Any field passed
/// as Some(...) replaces the existing value; None leaves it alone.
#[tauri::command]
pub async fn update_secret(
    state: State<'_, AppState>,
    id: String,
    name: Option<String>,
    value: Option<String>,
    category: Option<String>,
    alias: Option<String>,
    description: Option<String>,
) -> Result<VaultOpResponse, String> {
    let mut payload = serde_json::json!({ "id": id });
    if let Some(n) = name { payload["name"] = serde_json::Value::String(n); }
    if let Some(v) = value { payload["value"] = serde_json::Value::String(v); }
    if let Some(c) = category { payload["category"] = serde_json::Value::String(c); }
    if let Some(a) = alias { payload["alias"] = serde_json::Value::String(a); }
    if let Some(d) = description { payload["description"] = serde_json::Value::String(d); }
    let result = operations::execute_phone_required(&state, "secret.update", payload).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Delete a minor secret (phone-required).
#[tauri::command]
pub async fn delete_secret(state: State<'_, AppState>, id: String) -> Result<VaultOpResponse, String> {
    let result = operations::execute_phone_required(
        &state,
        "secret.delete",
        serde_json::json!({ "id": id }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Rotate the E2E keys for a connection. Phone-required.
#[tauri::command]
pub async fn rotate_connection_keys(
    state: State<'_, AppState>,
    connection_id: String,
) -> Result<VaultOpResponse, String> {
    let result = operations::execute_phone_required(
        &state,
        "connection.rotate",
        serde_json::json!({ "connection_id": connection_id }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Challenge a peer's identity (proves they still hold the private key
/// that bound the connection). Phone-required to authorize the
/// challenge — the verification result arrives asynchronously via the
/// vault's verify-state push and is read with `connection.list`.
#[tauri::command]
pub async fn authenticate_connection(
    state: State<'_, AppState>,
    connection_id: String,
) -> Result<VaultOpResponse, String> {
    let result = operations::execute_phone_required(
        &state,
        "connection.authenticate",
        serde_json::json!({ "connection_id": connection_id }),
    ).await;
    Ok(VaultOpResponse::from_op(result))
}

/// Delete personal-data fields by namespace (phone-required). The vault
/// keys storage as `personal-data/<namespace>`, so for aliased fields
/// the composite key (e.g. `contact.phone.mobile::Wife`) is passed
/// verbatim to delete just that variant.
#[tauri::command]
pub async fn delete_personal_data_fields(
    state: State<'_, AppState>,
    namespaces: Vec<String>,
) -> Result<VaultOpResponse, String> {
    let result = operations::execute_phone_required(
        &state,
        "personal-data.delete",
        serde_json::json!({ "namespaces": namespaces }),
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
