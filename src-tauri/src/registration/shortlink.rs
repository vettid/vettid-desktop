use serde::Deserialize;

use crate::registration::flow::RegistrationError;

// ---------------------------------------------------------------------------
// Invitation payload — matches mobile peer connection invitation format
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct InvitationPayload {
    /// NATS server URI
    pub nats_endpoint: String,

    /// NATS JWT for authentication (from invitation credentials)
    pub jwt: String,

    /// NATS seed for signing (from invitation credentials)
    pub seed: String,

    /// Connection ID assigned by the vault
    pub connection_id: String,

    /// Vault owner's OwnerSpace identifier
    pub owner_space: String,

    /// Vault owner's MessageSpace topic
    pub message_space: String,

    /// When the invitation expires (ISO 8601)
    pub expires_at: String,

    /// Display label (inviter's name)
    #[serde(default)]
    pub label: String,

    /// Inviter's profile data
    #[serde(default)]
    pub inviter_profile: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Resolve an invite code to an invitation payload
// ---------------------------------------------------------------------------

/// Resolve a VettID invite code to an [`InvitationPayload`].
///
/// The invite code is resolved via the same broker/shortlink service used by
/// mobile peer connections. Returns NATS credentials (JWT+seed), connection_id,
/// and space identifiers needed to connect and accept the invitation.
pub async fn resolve_invite_code(code: &str) -> Result<InvitationPayload, RegistrationError> {
    let url = format!("https://vett.id/{}", code);
    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| RegistrationError::ShortlinkFailed(format!("HTTP request failed: {}", e)))?;

    match response.status().as_u16() {
        200 => {}
        404 => {
            return Err(RegistrationError::ShortlinkFailed(
                "invite code expired or already used".to_string(),
            ));
        }
        429 => {
            return Err(RegistrationError::ShortlinkFailed(
                "rate limited — try again shortly".to_string(),
            ));
        }
        status => {
            return Err(RegistrationError::ShortlinkFailed(format!(
                "unexpected HTTP status: {}",
                status,
            )));
        }
    }

    let payload: InvitationPayload = response
        .json()
        .await
        .map_err(|e| RegistrationError::ShortlinkFailed(format!("failed to parse invitation: {}", e)))?;

    validate_invitation(&payload)?;
    check_expiry(&payload)?;

    Ok(payload)
}

fn check_expiry(payload: &InvitationPayload) -> Result<(), RegistrationError> {
    if payload.expires_at.is_empty() {
        return Ok(()); // No expiry set
    }
    if let Ok(expires) = chrono::DateTime::parse_from_rfc3339(&payload.expires_at) {
        if expires < chrono::Utc::now() {
            return Err(RegistrationError::ShortlinkFailed(
                "invitation has expired".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_invitation(payload: &InvitationPayload) -> Result<(), RegistrationError> {
    let checks: &[(&str, &str)] = &[
        ("nats_endpoint", &payload.nats_endpoint),
        ("jwt", &payload.jwt),
        ("seed", &payload.seed),
        ("connection_id", &payload.connection_id),
        ("owner_space", &payload.owner_space),
        ("message_space", &payload.message_space),
    ];

    for (name, value) in checks {
        if value.trim().is_empty() {
            return Err(RegistrationError::ShortlinkFailed(format!(
                "invitation field '{}' is empty",
                name,
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_payload() -> InvitationPayload {
        InvitationPayload {
            nats_endpoint: "tls://nats.vettid.dev:443".to_string(),
            jwt: "eyJ...".to_string(),
            seed: "SUAB...".to_string(),
            connection_id: "conn-abc123".to_string(),
            owner_space: "OwnerSpace.user-guid".to_string(),
            message_space: "MessageSpace.user-guid.forOwner.>".to_string(),
            expires_at: "2026-04-04T00:00:00Z".to_string(),
            label: "John Doe".to_string(),
            inviter_profile: serde_json::json!({}),
        }
    }

    #[test]
    fn test_validate_success() {
        assert!(validate_invitation(&test_payload()).is_ok());
    }

    #[test]
    fn test_validate_empty_jwt_fails() {
        let mut p = test_payload();
        p.jwt = String::new();
        assert!(validate_invitation(&p).is_err());
    }
}
