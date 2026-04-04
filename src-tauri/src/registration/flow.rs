use futures::StreamExt;
use serde::Serialize;
use std::fmt;
use std::path::PathBuf;
use tokio::time::{timeout, Duration};
use zeroize::Zeroize;

use crate::crypto::keys::{compute_shared_secret, generate_x25519_keypair, generate_random_bytes};
use crate::crypto::CryptoError;
use crate::nats::client::{NatsClient, NatsError};
use crate::registration::shortlink::resolve_invite_code;

// ---------------------------------------------------------------------------
// Registration errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum RegistrationError {
    /// The invite code could not be resolved.
    ShortlinkFailed(String),
    /// Failed to connect to NATS.
    NatsConnectionFailed(String),
    /// A NATS publish or subscribe operation failed.
    NatsOperationFailed(String),
    /// Cryptographic operation failed.
    CryptoFailed(String),
    /// The connection request was denied by the vault owner.
    Denied(String),
    /// Timed out waiting for approval.
    Timeout,
    /// An unexpected error occurred.
    Internal(String),
}

impl fmt::Display for RegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShortlinkFailed(msg) => write!(f, "invite resolution failed: {}", msg),
            Self::NatsConnectionFailed(msg) => write!(f, "NATS connection failed: {}", msg),
            Self::NatsOperationFailed(msg) => write!(f, "NATS operation failed: {}", msg),
            Self::CryptoFailed(msg) => write!(f, "cryptographic operation failed: {}", msg),
            Self::Denied(reason) => write!(f, "connection denied: {}", reason),
            Self::Timeout => write!(f, "timed out waiting for approval"),
            Self::Internal(msg) => write!(f, "internal error: {}", msg),
        }
    }
}

impl std::error::Error for RegistrationError {}

impl From<NatsError> for RegistrationError {
    fn from(err: NatsError) -> Self {
        match err {
            NatsError::ConnectionFailed(msg) => Self::NatsConnectionFailed(msg),
            other => Self::NatsOperationFailed(other.to_string()),
        }
    }
}

impl From<CryptoError> for RegistrationError {
    fn from(err: CryptoError) -> Self {
        Self::CryptoFailed(err.to_string())
    }
}

// ---------------------------------------------------------------------------
// Registration state machine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub enum RegistrationState {
    Idle,
    ResolvingInvite,
    ConnectingNats,
    StoringCredentials,
    WaitingApproval,
    KeyExchange,
    Approved,
    Denied(String),
    Failed(String),
}

// ---------------------------------------------------------------------------
// Registration flow — uses P2P connection pattern
// ---------------------------------------------------------------------------

/// Maximum time to wait for approval + key exchange (5 minutes).
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(300);

/// HKDF domain for connection key derivation (matches peer connections).
const CONNECTION_DOMAIN: &str = "vettid-connection-v1";

pub struct RegistrationFlow {
    state: RegistrationState,
    config_dir: PathBuf,
    nats_client: NatsClient,
}

impl RegistrationFlow {
    pub fn new(config_dir: PathBuf) -> Self {
        Self {
            state: RegistrationState::Idle,
            config_dir,
            nats_client: NatsClient::new(),
        }
    }

    pub fn state(&self) -> &RegistrationState {
        &self.state
    }

    /// Execute the full registration flow using the same pattern as peer-to-peer
    /// connections in the mobile apps.
    ///
    /// # Phases
    ///
    /// 1. Resolve invite code → get NATS credentials (JWT+seed), connection_id,
    ///    owner_space, message_space (same format as mobile invitations)
    /// 2. Connect to NATS using JWT+seed credentials (same as a peer accepting
    ///    an invitation)
    /// 3. Generate X25519 keypair, publish `connection.store-credentials` to the
    ///    vault via OwnerSpace (same handler mobile apps use)
    /// 4. Wait for vault to forward approval request to phone, phone user approves
    /// 5. Receive key exchange message with vault's X25519 public key
    /// 6. Compute shared secret, derive connection key, save encrypted credentials
    pub async fn run(&mut self, invite_code: &str, passphrase: &str) -> Result<(), RegistrationError> {
        // -- Phase 1: Resolve invite code -------------------------------------
        self.set_state(RegistrationState::ResolvingInvite);
        let invitation = resolve_invite_code(invite_code).await?;
        log::info!(
            "Invite resolved: connection_id={}, owner_space={}",
            invitation.connection_id,
            invitation.owner_space,
        );

        // -- Phase 2: Connect to NATS with invitation credentials -------------
        self.set_state(RegistrationState::ConnectingNats);
        self.nats_client
            .connect_with_credentials(
                &invitation.nats_endpoint,
                &invitation.jwt,
                &invitation.seed,
                &invitation.owner_space,
            )
            .await?;
        log::info!("NATS connected with invitation credentials");

        // -- Phase 3: Store credentials (accept the invitation) ---------------
        self.set_state(RegistrationState::StoringCredentials);

        // Generate X25519 keypair for this device connection.
        let (device_secret, device_public) = generate_x25519_keypair();

        // Collect device metadata to send as peer_profile.
        let device_profile = collect_device_profile();

        // Build store-credentials request (same format as mobile apps).
        let store_request = serde_json::json!({
            "connection_id": invitation.connection_id,
            "peer_guid": format!("desktop-{}", hex::encode(generate_random_bytes(8))),
            "label": hostname().unwrap_or_else(|| "Desktop".to_string()),
            "nats_credentials": format!(
                "-----BEGIN NATS USER JWT-----\n{}\n------END NATS USER JWT------\n\n-----BEGIN USER NKEY SEED-----\n{}\n------END USER NKEY SEED------",
                invitation.jwt, invitation.seed,
            ),
            "peer_owner_space_id": invitation.owner_space,
            "peer_message_space_id": invitation.message_space,
            "peer_profile": device_profile,
            "e2e_public_key": hex::encode(device_public.as_bytes()),
            "connection_type": "device",
        });

        // Build a vault event message matching the mobile OwnerSpaceClient pattern.
        let request_id = hex::encode(generate_random_bytes(16));
        let vault_message = serde_json::json!({
            "id": request_id,
            "type": "connection.store-credentials",
            "payload": store_request,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        let message_bytes = serde_json::to_vec(&vault_message)
            .map_err(|e| RegistrationError::Internal(format!("serialize request: {}", e)))?;

        // Publish to vault's MessageSpace (desktop devices use MessageSpace, not OwnerSpace).
        let vault_topic = format!(
            "MessageSpace.{}.forOwner.connection.store-credentials",
            invitation.owner_space,
        );
        self.nats_client
            .publish_to(&vault_topic, &message_bytes)
            .await?;
        log::info!("Store-credentials request published to vault");

        // -- Phase 4: Wait for approval + key exchange ------------------------
        self.set_state(RegistrationState::WaitingApproval);

        // Subscribe to device-specific response topics on MessageSpace.
        let response_subject = format!(
            "MessageSpace.{}.forOwner.device.>",
            invitation.owner_space,
        );
        let mut subscription = self.nats_client.subscribe_to(&response_subject).await?;

        // Also subscribe to the store-credentials response on MessageSpace.
        let store_response_subject = format!(
            "MessageSpace.{}.forOwner.connection.store-credentials.response",
            invitation.owner_space,
        );
        let mut store_sub = self.nats_client.subscribe_to(&store_response_subject).await?;

        // Wait for store-credentials response first.
        let store_response = timeout(Duration::from_secs(30), store_sub.next())
            .await
            .map_err(|_| RegistrationError::Timeout)?
            .ok_or_else(|| RegistrationError::Internal("store-credentials subscription closed".to_string()))?;

        let store_result: serde_json::Value = serde_json::from_slice(&store_response.payload)
            .map_err(|e| RegistrationError::Internal(format!("parse store response: {}", e)))?;

        let success = store_result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
        if !success {
            let error = store_result.get("error").and_then(|v| v.as_str()).unwrap_or("unknown error");
            return Err(RegistrationError::Denied(error.to_string()));
        }

        log::info!("Store-credentials accepted, waiting for key exchange...");
        self.set_state(RegistrationState::KeyExchange);

        // Wait for key exchange message from vault (vault sends its public key).
        let key_exchange_msg = timeout(APPROVAL_TIMEOUT, async {
            while let Some(msg) = subscription.next().await {
                if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&msg.payload) {
                    // Look for key-exchange or activated message
                    if parsed.get("e2e_public_key").and_then(|v| v.as_str()).is_some() {
                        return Ok(parsed.clone());
                    }
                }
            }
            Err(RegistrationError::Internal("subscription ended without key exchange".to_string()))
        })
        .await
        .map_err(|_| RegistrationError::Timeout)??;

        // -- Phase 5: Compute shared secret + save credentials ----------------
        let vault_public_hex = key_exchange_msg
            .get("e2e_public_key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RegistrationError::CryptoFailed("no e2e_public_key in key exchange".to_string()))?;

        let vault_pk_bytes = hex::decode(vault_public_hex)
            .map_err(|e| RegistrationError::CryptoFailed(format!("invalid vault public key hex: {}", e)))?;

        if vault_pk_bytes.len() != 32 {
            return Err(RegistrationError::CryptoFailed("vault public key is not 32 bytes".to_string()));
        }

        let vault_public = x25519_dalek::PublicKey::from(
            <[u8; 32]>::try_from(vault_pk_bytes.as_slice()).unwrap(),
        );

        // Compute shared secret via X25519 ECDH (same as peer connections).
        let mut shared_secret = compute_shared_secret(&device_secret, &vault_public);

        // Derive connection key via HKDF-SHA256 with connection_id as salt.
        let mut connection_key = derive_connection_key(
            &shared_secret,
            invitation.connection_id.as_bytes(),
            CONNECTION_DOMAIN.as_bytes(),
        )?;
        shared_secret.zeroize();

        // Save encrypted credentials via the credential store.
        save_credentials(
            &self.config_dir,
            passphrase,
            &invitation.connection_id,
            &hex::encode(device_public.as_bytes()),
            &connection_key,
            device_public.as_bytes(),
            &vault_pk_bytes,
            &invitation.owner_space,
            &invitation.nats_endpoint,
            &invitation.jwt,
            &invitation.seed,
            &invitation.label,
        )?;

        // SECURITY: Zeroize connection key after saving
        connection_key.zeroize();

        self.nats_client.set_connection_id(invitation.connection_id.clone());
        self.set_state(RegistrationState::Approved);
        log::info!("Registration complete via P2P connection pattern");
        Ok(())
    }

    fn set_state(&mut self, state: RegistrationState) {
        log::info!("Registration state -> {:?}", state);
        self.state = state;
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Collect device metadata as a profile object (sent as peer_profile in
/// store-credentials, matching how mobile apps send peer profiles).
fn collect_device_profile() -> serde_json::Value {
    serde_json::json!({
        "_system_first_name": hostname().unwrap_or_else(|| "Desktop".to_string()),
        "_system_last_name": "Device",
        "device_type": "desktop",
        "hostname": hostname().unwrap_or_default(),
        "platform": format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
        "app_version": env!("CARGO_PKG_VERSION"),
        "os_version": format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
    })
}

fn hostname() -> Option<String> {
    hostname::get().ok().map(|h| h.to_string_lossy().to_string())
}

/// Derive a 32-byte symmetric key from a shared secret using HKDF-SHA256.
/// Uses connection_id as salt for binding to this specific connection.
fn derive_connection_key(
    shared_secret: &[u8; 32],
    salt: &[u8],
    info: &[u8],
) -> Result<[u8; 32], RegistrationError> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|e| RegistrationError::CryptoFailed(format!("HKDF expand failed: {}", e)))?;
    Ok(okm)
}

/// Persist connection credentials using the encrypted credential store.
/// Uses Argon2id + XChaCha20-Poly1305 with passphrase + platform key binding.
fn save_credentials(
    config_dir: &PathBuf,
    passphrase: &str,
    connection_id: &str,
    key_id: &str,
    connection_key: &[u8; 32],
    device_public_key: &[u8],
    vault_public_key: &[u8],
    owner_guid: &str,
    nats_endpoint: &str,
    jwt: &str,
    seed: &str,
    owner_name: &str,
) -> Result<(), RegistrationError> {
    use crate::credential::store::{self, ConnectionCredentials};
    use crate::fingerprint::platform_key;

    std::fs::create_dir_all(config_dir).map_err(|e| {
        RegistrationError::Internal(format!("create config dir: {}", e))
    })?;

    let nats_creds_string = format!(
        "-----BEGIN NATS USER JWT-----\n{}\n------END NATS USER JWT------\n\n-----BEGIN USER NKEY SEED-----\n{}\n------END USER NKEY SEED------",
        jwt, seed,
    );

    let creds = ConnectionCredentials {
        connection_id: connection_id.to_string(),
        connection_key: connection_key.to_vec(),
        key_id: key_id.to_string(),
        device_private_key: Vec::new(), // Private key not stored — ephemeral
        device_public_key: device_public_key.to_vec(),
        vault_public_key: vault_public_key.to_vec(),
        message_space_token: nats_creds_string,
        message_space_url: nats_endpoint.to_string(),
        owner_guid: owner_guid.to_string(),
        owner_name: owner_name.to_string(),
        session_id: String::new(),
    };

    // Derive platform key for machine binding
    let platform_key = platform_key::derive_platform_key()
        .map_err(|e| RegistrationError::Internal(format!("platform key: {}", e)))?;

    // Save via encrypted credential store (Argon2id + XChaCha20-Poly1305, mode 0600)
    store::save(config_dir, &creds, passphrase.as_bytes(), &platform_key)
        .map_err(|e| RegistrationError::Internal(format!("save credentials: {}", e)))?;

    // Clean up any leftover plaintext credentials from previous versions
    let plaintext_path = config_dir.join("credentials.json");
    if plaintext_path.exists() {
        let _ = std::fs::remove_file(&plaintext_path);
    }

    log::info!("Credentials saved (encrypted) to {:?}", config_dir);
    Ok(())
}
