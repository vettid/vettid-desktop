use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Message type constants
// ---------------------------------------------------------------------------

pub const MSG_DEVICE_CONNECTION_REQUEST: &str = "device_connection_request";
pub const MSG_DEVICE_CONNECTION_APPROVED: &str = "device_connection_approved";
pub const MSG_DEVICE_CONNECTION_DENIED: &str = "device_connection_denied";
pub const MSG_DEVICE_OP_REQUEST: &str = "device_op_request";
pub const MSG_DEVICE_OP_RESPONSE: &str = "device_op_response";

// ---------------------------------------------------------------------------
// Envelope -- the wire format for all NATS messages
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Logical message type (one of the MSG_* constants).
    #[serde(rename = "type")]
    pub msg_type: String,

    /// Key identifier used for encryption/decryption of the payload.
    pub key_id: String,

    /// Encrypted payload serialized as a JSON value (typically a base64 string
    /// or a JSON array of bytes, depending on the transport convention).
    pub payload: serde_json::Value,

    /// ISO 8601 timestamp of when the message was created.
    pub timestamp: String,

    /// Monotonically increasing sequence number scoped to this sender.
    pub sequence: u64,
}

// ---------------------------------------------------------------------------
// Connection request (desktop -> vault-manager)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionRequest {
    pub invitation_id: String,
    pub device_public_key: Vec<u8>,
    pub registration: DeviceRegistration,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceRegistration {
    pub device_type: String,
    pub ip_address: String,
    pub hostname: String,
    pub platform: String,
    pub binary_fingerprint: String,
    pub machine_fingerprint: String,
    pub app_version: String,
    pub os_version: String,
}

// ---------------------------------------------------------------------------
// Connection approval (vault-manager -> desktop)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct ConnectionApproval {
    pub connection_id: String,
    pub key_id: String,
    pub session: DeviceSessionInfo,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeviceSessionInfo {
    pub session_id: String,
    pub status: String,
    pub expires_at: i64,
    pub ttl_hours: i32,
    pub capabilities: Vec<String>,
    pub requires_phone: Vec<String>,
}

// ---------------------------------------------------------------------------
// Connection denial (vault-manager -> desktop)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct ConnectionDenial {
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Encode / decode helpers
// ---------------------------------------------------------------------------

/// Serialize an [`Envelope`] to JSON bytes suitable for NATS publish.
pub fn encode_envelope(
    msg_type: &str,
    key_id: &str,
    payload: &[u8],
    sequence: u64,
) -> Result<Vec<u8>, serde_json::Error> {
    let envelope = Envelope {
        msg_type: msg_type.to_string(),
        key_id: key_id.to_string(),
        payload: serde_json::Value::Array(
            payload.iter().map(|b| serde_json::Value::Number((*b).into())).collect(),
        ),
        timestamp: chrono::Utc::now().to_rfc3339(),
        sequence,
    };
    serde_json::to_vec(&envelope)
}

/// Deserialize an [`Envelope`] from raw JSON bytes received over NATS.
pub fn decode_envelope(data: &[u8]) -> Result<Envelope, serde_json::Error> {
    serde_json::from_slice(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_roundtrip() {
        let payload = b"encrypted-bytes";
        let encoded = encode_envelope(
            MSG_DEVICE_CONNECTION_REQUEST,
            "key-001",
            payload,
            1,
        )
        .expect("encoding should succeed");

        let decoded = decode_envelope(&encoded).expect("decoding should succeed");
        assert_eq!(decoded.msg_type, MSG_DEVICE_CONNECTION_REQUEST);
        assert_eq!(decoded.key_id, "key-001");
        assert_eq!(decoded.sequence, 1);
    }
}
