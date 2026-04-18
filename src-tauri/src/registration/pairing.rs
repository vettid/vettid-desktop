//! Two-stage desktop pairing flow.
//!
//! Protocol reference: `vettid-dev/docs/DESKTOP-CONNECTION-FLOW.md`.
//!
//! Stage 1 — invite resolution via guest NATS account:
//!   1. User types an 8-char invite code displayed by the phone app.
//!   2. We connect to NATS using embedded guest creds (no user auth yet).
//!   3. We fetch `invite.<code>` from the `INVITATIONS` JetStream.
//!   4. The payload gives us scoped NATS creds bound to a new connection_id.
//!
//! Stage 2 — session authorization:
//!   1. Reconnect as that scoped user.
//!   2. Generate ephemeral X25519 keypair + 32-byte approval token.
//!   3. Publish `device.request-session` with our pubkey + device fingerprint.
//!   4. Display a QR (`{"t":<token>,"c":<connection_id>}`) to the user.
//!   5. User scans the QR on their phone and approves with a duration.
//!   6. Vault responds on `forApp.device.<conn-id>.activated` with its pubkey
//!      and session metadata.
//!   7. Derive session_key via HKDF(X25519(desktop_priv, vault_pub),
//!      salt=connection_id, info="vettid-device-session-v1|<session_id>").
//!   8. Save encrypted credentials to disk.

use async_nats::jetstream;
use futures::StreamExt;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::PathBuf;
use tokio::time::{timeout, Duration};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::Zeroize;

use crate::crypto::keys::{compute_shared_secret, generate_random_bytes, generate_x25519_keypair};
use crate::nats::client::NatsClient;
use crate::registration::flow::RegistrationError;

/// HKDF info string — MUST match vault-manager/device_pairing.go `DomainDeviceSession`.
const DOMAIN_DEVICE_SESSION: &str = "vettid-device-session-v1";

/// Where to reach the bootstrap endpoint that mints per-pair NATS creds.
/// Override at runtime via the `VETTID_BOOTSTRAP_URL` env var for testing.
const DEFAULT_BOOTSTRAP_URL: &str = "https://api.vettid.dev/pair/device/bootstrap";

/// How long we wait for the user to scan the QR on their phone.
const ACTIVATION_TIMEOUT_SECS: u64 = 300;

/// Response from POST /pair/device/bootstrap.
#[derive(Debug, Deserialize)]
struct BootstrapResponse {
    nats_endpoint: String,
    jwt: String,
    seed: String,
    #[serde(default)]
    _expires_in: i64,
}

/// Call the bootstrap endpoint to obtain short-lived NATS creds scoped to
/// this specific invite code. No long-lived credential is stored in the
/// desktop binary — every pairing mints a fresh keypair server-side.
async fn fetch_bootstrap_creds(code: &str) -> Result<BootstrapResponse, RegistrationError> {
    let url = std::env::var("VETTID_BOOTSTRAP_URL")
        .unwrap_or_else(|_| DEFAULT_BOOTSTRAP_URL.to_string());

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| RegistrationError::InviteResolutionFailed(format!("http client: {}", e)))?;

    let response = client
        .post(&url)
        .json(&serde_json::json!({ "code": code }))
        .send()
        .await
        .map_err(|e| RegistrationError::InviteResolutionFailed(format!("bootstrap request: {}", e)))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(RegistrationError::InviteResolutionFailed(format!(
            "bootstrap endpoint returned {}: {}",
            status, body
        )));
    }

    response
        .json::<BootstrapResponse>()
        .await
        .map_err(|e| RegistrationError::InviteResolutionFailed(format!("parse bootstrap response: {}", e)))
}

// ---------------------------------------------------------------------------
// Wire formats
// ---------------------------------------------------------------------------

/// The invite payload published by the vault to `invite.<code>` on JetStream.
/// Must match vault-manager/connections.go HandleCreateDeviceInvite.
#[derive(Debug, Clone, Deserialize)]
struct InvitePayload {
    #[serde(default, rename = "type")]
    _payload_type: String,
    connection_id: String,
    jwt: String,
    seed: String,
    owner_space: String,
    #[serde(default)]
    _message_space: String,
    #[serde(default)]
    _expires_at: String,
    #[serde(default)]
    _label: String,
}

/// Device fingerprint sent to the vault in device.request-session.
/// Field names match DeviceMetadata in vault-manager/connections.go.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceFingerprint {
    pub hostname: String,
    pub platform: String,
    pub os_name: String,
    pub os_version: String,
    pub app_version: String,
    pub binary_fingerprint: String,
    pub machine_fingerprint: String,
}

/// Payload of `device.session.activated` from vault.
#[derive(Debug, Clone, Deserialize)]
struct SessionActivatedPayload {
    connection_id: String,
    session_id: String,
    #[serde(default)]
    _session_key_id: String,
    vault_pubkey: String,
    expires_at: i64,
    duration_s: i64,
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Stage 1: resolve an invite code.
///
/// Mints short-lived NATS creds via the bootstrap endpoint, connects as that
/// user, reads `invite.<code>` from JetStream, then tears down the guest
/// connection. Returns the scoped peer credentials the vault attached to the
/// invitation, plus the ephemeral crypto state for stage 2.
pub async fn resolve_invite(
    invite_code: &str,
) -> Result<(InviteSession, PairingRuntime), RegistrationError> {
    let guest = fetch_bootstrap_creds(invite_code).await?;

    log::info!(
        "Resolving invite code on {} with fresh per-pair guest creds",
        guest.nats_endpoint
    );

    // Ephemeral guest connection purely for JetStream read.
    let guest_client = async_nats::ConnectOptions::with_credentials(&format!(
        "-----BEGIN NATS USER JWT-----\n{}\n------END NATS USER JWT------\n\n-----BEGIN USER NKEY SEED-----\n{}\n------END USER NKEY SEED------",
        guest.jwt, guest.seed,
    ))
    .map_err(|e| RegistrationError::InviteResolutionFailed(format!("guest creds: {}", e)))?
    .connect(&guest.nats_endpoint)
    .await
    .map_err(|e| RegistrationError::NatsConnectionFailed(format!("guest connect: {}", e)))?;

    let js = jetstream::new(guest_client.clone());

    // Ephemeral pull consumer filtered to invite.<code>
    let subject = format!("invite.{}", invite_code.to_uppercase());
    let stream = js
        .get_stream("INVITATIONS")
        .await
        .map_err(|e| RegistrationError::InviteResolutionFailed(format!("stream: {}", e)))?;

    let consumer = stream
        .create_consumer(jetstream::consumer::pull::Config {
            filter_subject: subject.clone(),
            deliver_policy: jetstream::consumer::DeliverPolicy::LastPerSubject,
            ..Default::default()
        })
        .await
        .map_err(|e| RegistrationError::InviteResolutionFailed(format!("consumer: {}", e)))?;

    let mut batch = consumer
        .fetch()
        .max_messages(1)
        .expires(Duration::from_secs(5))
        .messages()
        .await
        .map_err(|e| RegistrationError::InviteResolutionFailed(format!("fetch: {}", e)))?;

    let invite_msg = batch
        .next()
        .await
        .ok_or_else(|| RegistrationError::InviteResolutionFailed(
            "invite not found — code expired or invalid".to_string(),
        ))?
        .map_err(|e| RegistrationError::InviteResolutionFailed(format!("read: {}", e)))?;

    let payload: InvitePayload = serde_json::from_slice(&invite_msg.payload).map_err(|e| {
        RegistrationError::InviteResolutionFailed(format!("parse invite payload: {}", e))
    })?;

    invite_msg.ack().await.ok();
    // async-nats disconnects when the client is dropped; no explicit drain needed.
    drop(guest_client);

    log::info!(
        "Invite resolved — connection_id={}, owner_space={}",
        payload.connection_id,
        payload.owner_space,
    );

    // Generate ephemeral keys + approval token now so the QR can be shown
    // as soon as the frontend asks.
    let (device_secret, device_public) = generate_x25519_keypair();
    let approval_token_bytes = generate_random_bytes(32);
    let approval_token = hex::encode(&approval_token_bytes);

    let session = InviteSession {
        connection_id: payload.connection_id,
        owner_space: payload.owner_space,
        nats_url: guest.nats_endpoint,
        scoped_jwt: payload.jwt,
        scoped_seed: payload.seed,
        approval_token,
        qr_payload: String::new(), // set below
    };

    let runtime = PairingRuntime {
        device_secret,
        device_public,
        approval_token_hex: session.approval_token.clone(),
        connection_id: session.connection_id.clone(),
    };

    // Build QR payload — matches what the Android scanner expects.
    let qr = serde_json::json!({
        "t": session.approval_token,
        "c": session.connection_id,
    })
    .to_string();

    Ok((InviteSession { qr_payload: qr, ..session }, runtime))
}

/// Stage 2: connect with the scoped creds and publish device.request-session,
/// then wait for device.session.activated and derive the session key.
/// On success, writes the encrypted credentials to disk and returns.
pub async fn complete_pairing(
    session: InviteSession,
    runtime: PairingRuntime,
    fingerprint: DeviceFingerprint,
    config_dir: &PathBuf,
    passphrase: &str,
) -> Result<PairingOutcome, RegistrationError> {
    let mut client = NatsClient::new();
    client
        .connect_with_credentials(
            &session.nats_url,
            &session.scoped_jwt,
            &session.scoped_seed,
            &session.owner_space,
        )
        .await?;

    // Subscribe BEFORE publishing so we don't miss the activation event.
    let activated_subject = format!(
        "MessageSpace.{}.forApp.device.{}.activated",
        session.owner_space, session.connection_id,
    );
    let mut activated = client.subscribe_to(&activated_subject).await?;
    let revoked_subject = format!(
        "MessageSpace.{}.forApp.device.{}.revoked",
        session.owner_space, session.connection_id,
    );
    let mut revoked = client.subscribe_to(&revoked_subject).await?;

    // Publish request-session
    let request_subject = format!(
        "MessageSpace.{}.forOwner.device.{}.request-session",
        session.owner_space, session.connection_id,
    );
    let request_id = hex::encode(generate_random_bytes(16));
    let payload = serde_json::json!({
        "id": request_id,
        "type": "device.request-session",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "payload": {
            "connection_id": session.connection_id,
            "approval_token": runtime.approval_token_hex,
            "device_pubkey": hex::encode(runtime.device_public.as_bytes()),
            "device_metadata": fingerprint,
        },
    });
    client
        .publish_to(&request_subject, payload.to_string().as_bytes())
        .await?;
    log::info!("Stage-2 request-session published; awaiting user approval");

    // Wait for activation OR revocation OR timeout.
    let activation_result = timeout(Duration::from_secs(ACTIVATION_TIMEOUT_SECS), async {
        loop {
            tokio::select! {
                maybe_msg = activated.next() => {
                    if let Some(msg) = maybe_msg {
                        match serde_json::from_slice::<SessionActivatedPayload>(&msg.payload) {
                            Ok(p) if p.connection_id == session.connection_id => return Ok(p),
                            Ok(_) => continue,
                            Err(e) => log::warn!("Malformed activation payload: {}", e),
                        }
                    } else {
                        return Err(RegistrationError::Internal("activation subscription closed".into()));
                    }
                }
                maybe_msg = revoked.next() => {
                    if maybe_msg.is_some() {
                        return Err(RegistrationError::Denied("user denied authorization".into()));
                    }
                }
            }
        }
    })
    .await
    .map_err(|_| RegistrationError::Timeout)??;

    // Key exchange: X25519(desktop_priv, vault_pub) → HKDF-SHA256
    let vault_pub_bytes = hex::decode(&activation_result.vault_pubkey).map_err(|e| {
        RegistrationError::CryptoFailed(format!("vault pubkey hex: {}", e))
    })?;
    if vault_pub_bytes.len() != 32 {
        return Err(RegistrationError::CryptoFailed(
            "vault pubkey must be 32 bytes".into(),
        ));
    }
    let mut vault_pub_arr = [0u8; 32];
    vault_pub_arr.copy_from_slice(&vault_pub_bytes);
    let vault_public = X25519Public::from(vault_pub_arr);

    let mut shared_secret = compute_shared_secret(&runtime.device_secret, &vault_public);
    let mut session_key = derive_session_key(
        &shared_secret,
        &session.connection_id,
        &activation_result.session_id,
    )?;
    shared_secret.zeroize();

    // Save encrypted credentials
    use crate::credential::store::{self, ConnectionCredentials};
    use crate::fingerprint::platform_key::derive_platform_key;

    std::fs::create_dir_all(config_dir)
        .map_err(|e| RegistrationError::Internal(format!("create config dir: {}", e)))?;

    let nats_creds = format!(
        "-----BEGIN NATS USER JWT-----\n{}\n------END NATS USER JWT------\n\n-----BEGIN USER NKEY SEED-----\n{}\n------END USER NKEY SEED------",
        session.scoped_jwt, session.scoped_seed,
    );

    let creds = ConnectionCredentials {
        connection_id: session.connection_id.clone(),
        connection_key: session_key.to_vec(),
        key_id: activation_result.session_id.clone(),
        device_private_key: runtime.device_secret.to_bytes().to_vec(),
        device_public_key: runtime.device_public.as_bytes().to_vec(),
        vault_public_key: vault_pub_bytes,
        message_space_token: nats_creds,
        message_space_url: session.nats_url.clone(),
        owner_guid: session.owner_space.clone(),
        owner_name: String::new(),
        session_id: activation_result.session_id.clone(),
        session_expires_at: activation_result.expires_at,
        session_duration_seconds: activation_result.duration_s,
    };

    let platform_key = derive_platform_key()
        .map_err(|e| RegistrationError::Internal(format!("platform key: {}", e)))?;

    store::save(config_dir, &creds, passphrase.as_bytes(), &platform_key)
        .map_err(|e| RegistrationError::Internal(format!("save credentials: {}", e)))?;

    session_key.zeroize();

    Ok(PairingOutcome {
        connection_id: session.connection_id,
        session_id: activation_result.session_id,
        expires_at: activation_result.expires_at,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn derive_session_key(
    shared_secret: &[u8; 32],
    connection_id: &str,
    session_id: &str,
) -> Result<[u8; 32], RegistrationError> {
    let info = format!("{}|{}", DOMAIN_DEVICE_SESSION, session_id);
    let hk = Hkdf::<Sha256>::new(Some(connection_id.as_bytes()), shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(info.as_bytes(), &mut okm)
        .map_err(|e| RegistrationError::CryptoFailed(format!("HKDF expand: {}", e)))?;
    Ok(okm)
}

// ---------------------------------------------------------------------------
// Public data types (shared with commands layer)
// ---------------------------------------------------------------------------

/// Returned after stage 1 — the frontend uses `qr_payload` to render the QR.
/// Treat `scoped_jwt` / `scoped_seed` as secret.
pub struct InviteSession {
    pub connection_id: String,
    pub owner_space: String,
    pub nats_url: String,
    pub scoped_jwt: String,
    pub scoped_seed: String,
    pub approval_token: String,
    pub qr_payload: String,
}

/// Ephemeral crypto state held between stage 1 and stage 2.
pub struct PairingRuntime {
    pub device_secret: StaticSecret,
    pub device_public: X25519Public,
    pub approval_token_hex: String,
    pub connection_id: String,
}

pub struct PairingOutcome {
    pub connection_id: String,
    pub session_id: String,
    pub expires_at: i64,
}
