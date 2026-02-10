use futures::StreamExt;
use serde::Serialize;
use std::fmt;
use std::path::PathBuf;
use tokio::time::{timeout, Duration};
use zeroize::Zeroize;

use crate::crypto::keys::{compute_shared_secret, generate_x25519_keypair};
use crate::crypto::encrypt;
use crate::crypto::CryptoError;
use crate::nats::client::{NatsClient, NatsError};
use crate::nats::messages::{
    self, ConnectionApproval, ConnectionDenial, ConnectionRequest, DeviceRegistration,
    DeviceSessionInfo, MSG_DEVICE_CONNECTION_APPROVED, MSG_DEVICE_CONNECTION_DENIED,
    MSG_DEVICE_CONNECTION_REQUEST,
};
use crate::registration::shortlink::resolve_shortlink;

// ---------------------------------------------------------------------------
// Registration errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum RegistrationError {
    /// The shortlink could not be resolved.
    ShortlinkFailed(String),
    /// Failed to connect to NATS.
    NatsConnectionFailed(String),
    /// A NATS publish or subscribe operation failed.
    NatsOperationFailed(String),
    /// Cryptographic operation failed.
    CryptoFailed(String),
    /// The registration request was denied by the vault owner.
    Denied(String),
    /// Timed out waiting for approval.
    Timeout,
    /// An unexpected error occurred.
    Internal(String),
}

impl fmt::Display for RegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistrationError::ShortlinkFailed(msg) => {
                write!(f, "shortlink resolution failed: {}", msg)
            }
            RegistrationError::NatsConnectionFailed(msg) => {
                write!(f, "NATS connection failed: {}", msg)
            }
            RegistrationError::NatsOperationFailed(msg) => {
                write!(f, "NATS operation failed: {}", msg)
            }
            RegistrationError::CryptoFailed(msg) => {
                write!(f, "cryptographic operation failed: {}", msg)
            }
            RegistrationError::Denied(reason) => {
                write!(f, "registration denied: {}", reason)
            }
            RegistrationError::Timeout => {
                write!(f, "timed out waiting for approval")
            }
            RegistrationError::Internal(msg) => {
                write!(f, "internal error: {}", msg)
            }
        }
    }
}

impl std::error::Error for RegistrationError {}

impl From<NatsError> for RegistrationError {
    fn from(err: NatsError) -> Self {
        match err {
            NatsError::ConnectionFailed(msg) => RegistrationError::NatsConnectionFailed(msg),
            other => RegistrationError::NatsOperationFailed(other.to_string()),
        }
    }
}

impl From<CryptoError> for RegistrationError {
    fn from(err: CryptoError) -> Self {
        RegistrationError::CryptoFailed(err.to_string())
    }
}

// ---------------------------------------------------------------------------
// Registration state machine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub enum RegistrationState {
    Idle,
    ResolvingShortlink,
    ConnectingNats,
    SendingRequest,
    WaitingApproval,
    Approved,
    Denied(String),
    Failed(String),
}

// ---------------------------------------------------------------------------
// Registration flow
// ---------------------------------------------------------------------------

/// Maximum time to wait for an approval/denial response (5 minutes).
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(300);

/// The ECIES domain separator used during device registration.
const ECIES_DOMAIN: &str = "vettid-device-v1";

pub struct RegistrationFlow {
    state: RegistrationState,
    config_dir: PathBuf,
    nats_client: NatsClient,
}

impl RegistrationFlow {
    /// Create a new registration flow that will persist credentials under
    /// `config_dir`.
    pub fn new(config_dir: PathBuf) -> Self {
        Self {
            state: RegistrationState::Idle,
            config_dir,
            nats_client: NatsClient::new(),
        }
    }

    /// Return a reference to the current state.
    pub fn state(&self) -> &RegistrationState {
        &self.state
    }

    /// Execute the full registration flow end-to-end.
    ///
    /// # Phases
    ///
    /// 1. Resolve the shortlink to obtain NATS URI, invite token, etc.
    /// 2. Connect to NATS using the invite token.
    /// 3. Generate an X25519 keypair, collect device fingerprint, build the
    ///    [`ConnectionRequest`], ECIES-encrypt it with the vault public key
    ///    using the domain `"vettid-device-v1"`, and publish.
    /// 4. Subscribe to the invitation topic and wait up to 5 minutes for a
    ///    response.
    /// 5. On approval, derive the connection key from the shared secret,
    ///    decrypt the approval payload, and save credentials to disk.
    pub async fn run(&mut self, shortlink_code: &str) -> Result<(), RegistrationError> {
        // -- Phase 1: Resolve shortlink ------------------------------------
        self.set_state(RegistrationState::ResolvingShortlink);
        let shortlink_url = format!("https://vett.id/{}", shortlink_code);
        let payload = resolve_shortlink(&shortlink_url).await?;
        log::info!(
            "Shortlink resolved: invitation_id={}, owner_guid={}",
            payload.invitation_id,
            payload.owner_guid,
        );

        // -- Phase 2: Connect to NATS --------------------------------------
        self.set_state(RegistrationState::ConnectingNats);
        self.nats_client
            .connect(
                &payload.messagespace_uri,
                &payload.invite_token,
                &payload.owner_guid,
            )
            .await?;
        log::info!("NATS connected");

        // -- Phase 3: Build & publish registration request -----------------
        self.set_state(RegistrationState::SendingRequest);

        // Generate ephemeral X25519 keypair.
        let (device_secret, device_public) = generate_x25519_keypair();

        // Collect device registration metadata.
        let registration = collect_device_registration();

        let request = ConnectionRequest {
            invitation_id: payload.invitation_id.clone(),
            device_public_key: device_public.as_bytes().to_vec(),
            registration,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let request_json = serde_json::to_vec(&request)
            .map_err(|e| RegistrationError::Internal(format!("serialize request: {}", e)))?;

        // Decode vault public key from hex.
        let vault_pk_bytes = hex::decode(&payload.vault_public_key).map_err(|e| {
            RegistrationError::CryptoFailed(format!("invalid vault public key hex: {}", e))
        })?;

        // ECIES-encrypt the request payload with the vault's public key.
        // We derive a one-time shared secret and use HKDF with the domain
        // separator to produce the symmetric key.
        let encrypted = ecies_encrypt_for_vault(
            &vault_pk_bytes,
            &device_secret,
            &device_public,
            &request_json,
        )?;

        // Wrap in an envelope and publish.
        let seq = self.nats_client.next_sequence();
        let envelope_bytes = messages::encode_envelope(
            MSG_DEVICE_CONNECTION_REQUEST,
            "ephemeral",
            &encrypted,
            seq,
        )
        .map_err(|e| RegistrationError::Internal(format!("encode envelope: {}", e)))?;

        self.nats_client
            .publish_registration(&envelope_bytes)
            .await?;
        log::info!("Registration request published");

        // -- Phase 4: Wait for approval ------------------------------------
        self.set_state(RegistrationState::WaitingApproval);

        let mut subscription = self
            .nats_client
            .subscribe_invitation(&payload.invitation_id)
            .await?;

        let response_msg = timeout(APPROVAL_TIMEOUT, subscription.next())
            .await
            .map_err(|_| RegistrationError::Timeout)?
            .ok_or_else(|| {
                RegistrationError::Internal("subscription closed unexpectedly".to_string())
            })?;

        let envelope = messages::decode_envelope(&response_msg.payload).map_err(|e| {
            RegistrationError::Internal(format!("decode response envelope: {}", e))
        })?;

        match envelope.msg_type.as_str() {
            MSG_DEVICE_CONNECTION_APPROVED => {
                // -- Phase 5: Decrypt approval, persist credentials --------
                let vault_public =
                    x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(vault_pk_bytes.as_slice())
                        .map_err(|_| {
                            RegistrationError::CryptoFailed(
                                "vault public key is not 32 bytes".to_string(),
                            )
                        })?);
                let mut shared_secret = compute_shared_secret(&device_secret, &vault_public);

                // Derive connection key via HKDF.
                let connection_key =
                    derive_connection_key(&shared_secret, ECIES_DOMAIN.as_bytes())?;
                shared_secret.zeroize();

                // Extract ciphertext from the envelope payload.
                let ciphertext = extract_payload_bytes(&envelope.payload)?;

                // Decrypt the approval payload.
                let approval_json = encrypt::decrypt(&connection_key, &ciphertext)?;

                let approval: ConnectionApproval = serde_json::from_slice(&approval_json)
                    .map_err(|e| {
                        RegistrationError::Internal(format!("parse approval: {}", e))
                    })?;

                log::info!(
                    "Registration approved: connection_id={}, session_id={}",
                    approval.connection_id,
                    approval.session.session_id,
                );

                // Persist credentials.
                save_credentials(
                    &self.config_dir,
                    &approval.connection_id,
                    &approval.key_id,
                    &connection_key,
                    &approval.session,
                )?;

                self.nats_client
                    .set_connection_id(approval.connection_id.clone());

                self.set_state(RegistrationState::Approved);
                Ok(())
            }
            MSG_DEVICE_CONNECTION_DENIED => {
                let denial: ConnectionDenial =
                    serde_json::from_value(envelope.payload).map_err(|e| {
                        RegistrationError::Internal(format!("parse denial: {}", e))
                    })?;
                self.set_state(RegistrationState::Denied(denial.reason.clone()));
                Err(RegistrationError::Denied(denial.reason))
            }
            other => {
                let msg = format!("unexpected message type during registration: {}", other);
                self.set_state(RegistrationState::Failed(msg.clone()));
                Err(RegistrationError::Internal(msg))
            }
        }
    }

    /// Update state and emit a log line.
    fn set_state(&mut self, state: RegistrationState) {
        log::info!("Registration state -> {:?}", state);
        self.state = state;
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Collect device metadata for the registration request.
fn collect_device_registration() -> DeviceRegistration {
    DeviceRegistration {
        device_type: "desktop".to_string(),
        ip_address: String::new(), // filled by server
        hostname: hostname().unwrap_or_default(),
        platform: std::env::consts::OS.to_string(),
        binary_fingerprint: String::new(), // TODO: compute from binary hash
        machine_fingerprint: String::new(), // TODO: use fingerprint module
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        os_version: os_version(),
    }
}

fn hostname() -> Option<String> {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .ok()
}

fn os_version() -> String {
    format!("{} {}", std::env::consts::OS, std::env::consts::ARCH)
}

/// ECIES encrypt: compute ECDH shared secret between the device's ephemeral
/// private key and the vault's public key, derive a symmetric key via HKDF
/// with the domain separator, and XChaCha20-Poly1305 encrypt the plaintext.
///
/// The output is: `device_public_key (32 bytes) || ciphertext`.
fn ecies_encrypt_for_vault(
    vault_pk_bytes: &[u8],
    device_secret: &x25519_dalek::StaticSecret,
    device_public: &x25519_dalek::PublicKey,
    plaintext: &[u8],
) -> Result<Vec<u8>, RegistrationError> {
    if vault_pk_bytes.len() != 32 {
        return Err(RegistrationError::CryptoFailed(
            "vault public key is not 32 bytes".to_string(),
        ));
    }

    let vault_public = x25519_dalek::PublicKey::from(
        <[u8; 32]>::try_from(vault_pk_bytes).unwrap(),
    );

    let mut shared_secret = compute_shared_secret(device_secret, &vault_public);
    let sym_key = derive_connection_key(&shared_secret, ECIES_DOMAIN.as_bytes())?;
    shared_secret.zeroize();

    let ciphertext = encrypt::encrypt(&sym_key, plaintext)?;

    // Prepend the ephemeral device public key so the vault can recompute the
    // shared secret.
    let mut result = Vec::with_capacity(32 + ciphertext.len());
    result.extend_from_slice(device_public.as_bytes());
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Derive a 32-byte symmetric key from a shared secret using HKDF-SHA256.
fn derive_connection_key(
    shared_secret: &[u8; 32],
    info: &[u8],
) -> Result<[u8; 32], RegistrationError> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|e| RegistrationError::CryptoFailed(format!("HKDF expand failed: {}", e)))?;
    Ok(okm)
}

/// Extract raw bytes from an envelope payload (JSON array of numbers).
fn extract_payload_bytes(value: &serde_json::Value) -> Result<Vec<u8>, RegistrationError> {
    match value {
        serde_json::Value::Array(arr) => {
            let mut bytes = Vec::with_capacity(arr.len());
            for v in arr {
                let b = v
                    .as_u64()
                    .ok_or_else(|| {
                        RegistrationError::Internal("payload byte is not a number".to_string())
                    })?;
                if b > 255 {
                    return Err(RegistrationError::Internal(
                        "payload byte exceeds u8 range".to_string(),
                    ));
                }
                bytes.push(b as u8);
            }
            Ok(bytes)
        }
        serde_json::Value::String(s) => {
            // Also support base64-encoded payloads.
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(s)
                .map_err(|e| {
                    RegistrationError::Internal(format!("base64 decode failed: {}", e))
                })
        }
        _ => Err(RegistrationError::Internal(
            "unexpected payload format".to_string(),
        )),
    }
}

/// Persist connection credentials to the config directory.
fn save_credentials(
    config_dir: &PathBuf,
    connection_id: &str,
    key_id: &str,
    connection_key: &[u8; 32],
    session: &DeviceSessionInfo,
) -> Result<(), RegistrationError> {
    std::fs::create_dir_all(config_dir).map_err(|e| {
        RegistrationError::Internal(format!("create config dir: {}", e))
    })?;

    let creds = serde_json::json!({
        "connection_id": connection_id,
        "key_id": key_id,
        "connection_key": hex::encode(connection_key),
        "session": {
            "session_id": session.session_id,
            "status": session.status,
            "expires_at": session.expires_at,
            "ttl_hours": session.ttl_hours,
            "capabilities": session.capabilities,
            "requires_phone": session.requires_phone,
        }
    });

    let creds_path = config_dir.join("credentials.json");
    let json_bytes = serde_json::to_vec_pretty(&creds).map_err(|e| {
        RegistrationError::Internal(format!("serialize credentials: {}", e))
    })?;

    std::fs::write(&creds_path, &json_bytes).map_err(|e| {
        RegistrationError::Internal(format!("write credentials file: {}", e))
    })?;

    log::info!("Credentials saved to {:?}", creds_path);
    Ok(())
}
