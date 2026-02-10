use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct VaultOpResponse {
    pub success: bool,
    pub data: Option<serde_json::Value>,
    pub error: Option<String>,
    pub pending_approval: bool,
}

/// List connections (independent operation — no phone approval needed).
#[tauri::command]
pub async fn list_connections() -> Result<VaultOpResponse, String> {
    // TODO: Send device_op_request with operation "connection.list" via NATS
    Ok(VaultOpResponse {
        success: true,
        data: Some(serde_json::json!({ "connections": [], "count": 0 })),
        error: None,
        pending_approval: false,
    })
}

/// Get a specific connection (independent operation).
#[tauri::command]
pub async fn get_connection(_connection_id: String) -> Result<VaultOpResponse, String> {
    // TODO: Send device_op_request with operation "connection.get"
    Ok(VaultOpResponse {
        success: true,
        data: None,
        error: Some("Not yet implemented".to_string()),
        pending_approval: false,
    })
}

/// List feed events (independent operation).
#[tauri::command]
pub async fn list_feed() -> Result<VaultOpResponse, String> {
    // TODO: Send device_op_request with operation "feed.list"
    Ok(VaultOpResponse {
        success: true,
        data: Some(serde_json::json!({ "events": [], "total": 0 })),
        error: None,
        pending_approval: false,
    })
}

/// Query audit log (independent operation).
#[tauri::command]
pub async fn query_audit() -> Result<VaultOpResponse, String> {
    // TODO: Send device_op_request with operation "audit.query"
    Ok(VaultOpResponse {
        success: true,
        data: Some(serde_json::json!({ "events": [], "total": 0 })),
        error: None,
        pending_approval: false,
    })
}

/// List messages (independent operation).
#[tauri::command]
pub async fn list_messages() -> Result<VaultOpResponse, String> {
    // TODO: Send device_op_request with operation "message.list"
    Ok(VaultOpResponse {
        success: true,
        data: Some(serde_json::json!({ "messages": [], "count": 0 })),
        error: None,
        pending_approval: false,
    })
}

/// List secrets catalog (independent operation — metadata only, not secret values).
#[tauri::command]
pub async fn list_secrets_catalog() -> Result<VaultOpResponse, String> {
    // TODO: Send device_op_request with operation "secrets.catalog"
    Ok(VaultOpResponse {
        success: true,
        data: Some(serde_json::json!({ "secrets": [], "count": 0 })),
        error: None,
        pending_approval: false,
    })
}

/// Request a secret value (phone-approval-required operation).
/// Returns pending_approval: true — the frontend shows "Approve on phone" UI.
#[tauri::command]
pub async fn request_secret(_secret_id: String) -> Result<VaultOpResponse, String> {
    // TODO: Send device_op_request with operation "secrets.retrieve"
    // This will trigger phone approval flow
    Ok(VaultOpResponse {
        success: true,
        data: None,
        error: None,
        pending_approval: true,
    })
}
