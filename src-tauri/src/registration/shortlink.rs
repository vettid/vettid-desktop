use serde::Deserialize;

use crate::registration::flow::RegistrationError;

// ---------------------------------------------------------------------------
// Shortlink payload returned by the VettID API
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct ShortlinkPayload {
    pub messagespace_uri: String,
    pub invite_token: String,
    pub invitation_id: String,
    pub vault_public_key: String,
    pub owner_guid: String,
    pub connection_type: Option<String>,
}

// ---------------------------------------------------------------------------
// Shortlink resolution
// ---------------------------------------------------------------------------

/// Resolve a VettID shortlink URL to a [`ShortlinkPayload`].
///
/// Performs an HTTP GET with `Accept: application/json` and parses the
/// response body. Handles common error status codes with human-readable
/// error messages.
pub async fn resolve_shortlink(url: &str) -> Result<ShortlinkPayload, RegistrationError> {
    let client = reqwest::Client::new();
    let response = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| RegistrationError::ShortlinkFailed(format!("HTTP request failed: {}", e)))?;

    match response.status().as_u16() {
        200 => {}
        404 => {
            return Err(RegistrationError::ShortlinkFailed(
                "shortlink expired or already used".to_string(),
            ));
        }
        429 => {
            return Err(RegistrationError::ShortlinkFailed(
                "rate limited".to_string(),
            ));
        }
        status => {
            return Err(RegistrationError::ShortlinkFailed(format!(
                "unexpected HTTP status: {}",
                status,
            )));
        }
    }

    let payload: ShortlinkPayload = response
        .json()
        .await
        .map_err(|e| RegistrationError::ShortlinkFailed(format!("failed to parse JSON: {}", e)))?;

    // Validate that all required fields are non-empty.
    validate_non_empty(&payload)?;

    Ok(payload)
}

fn validate_non_empty(payload: &ShortlinkPayload) -> Result<(), RegistrationError> {
    let checks: &[(&str, &str)] = &[
        ("messagespace_uri", &payload.messagespace_uri),
        ("invite_token", &payload.invite_token),
        ("invitation_id", &payload.invitation_id),
        ("vault_public_key", &payload.vault_public_key),
        ("owner_guid", &payload.owner_guid),
    ];

    for (name, value) in checks {
        if value.trim().is_empty() {
            return Err(RegistrationError::ShortlinkFailed(format!(
                "shortlink payload field '{}' is empty",
                name,
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_non_empty_success() {
        let payload = ShortlinkPayload {
            messagespace_uri: "nats://example.com".to_string(),
            invite_token: "tok-123".to_string(),
            invitation_id: "inv-456".to_string(),
            vault_public_key: "abcdef".to_string(),
            owner_guid: "owner-789".to_string(),
            connection_type: None,
        };
        assert!(validate_non_empty(&payload).is_ok());
    }

    #[test]
    fn test_validate_non_empty_failure() {
        let payload = ShortlinkPayload {
            messagespace_uri: "nats://example.com".to_string(),
            invite_token: "".to_string(),
            invitation_id: "inv-456".to_string(),
            vault_public_key: "abcdef".to_string(),
            owner_guid: "owner-789".to_string(),
            connection_type: None,
        };
        assert!(validate_non_empty(&payload).is_err());
    }
}
