use async_nats::{Client, Subscriber};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;

/// High-level connection-state events surfaced to the UI.
///
/// We translate `async_nats::Event` into this smaller enum so consumers don't
/// need a direct dependency on the async-nats crate.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NatsConnectionEvent {
    Connected,
    Disconnected,
    LameDuckMode,
    SlowConsumer { dropped: u64 },
    ServerError { message: String },
    ClientError { message: String },
}

use serde::Serialize;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum NatsError {
    /// Failed to establish a connection to the NATS server.
    ConnectionFailed(String),
    /// A publish operation failed.
    PublishFailed(String),
    /// A subscribe operation failed.
    SubscribeFailed(String),
    /// The client has not been connected yet.
    NotConnected,
}

impl fmt::Display for NatsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NatsError::ConnectionFailed(msg) => write!(f, "NATS connection failed: {}", msg),
            NatsError::PublishFailed(msg) => write!(f, "NATS publish failed: {}", msg),
            NatsError::SubscribeFailed(msg) => write!(f, "NATS subscribe failed: {}", msg),
            NatsError::NotConnected => write!(f, "NATS client not connected"),
        }
    }
}

impl std::error::Error for NatsError {}

// ---------------------------------------------------------------------------
// NATS client wrapper
// ---------------------------------------------------------------------------

pub struct NatsClient {
    client: Option<Client>,
    owner_guid: String,
    connection_id: Option<String>,
    sequence: AtomicU64,
    /// Receiver for connection-state events. The listener consumes this once
    /// via [`Self::take_event_receiver`] when it spins up. Subsequent calls
    /// return `None` so the listener owns events for the lifetime of the
    /// connection.
    event_rx: Option<mpsc::UnboundedReceiver<NatsConnectionEvent>>,
}

impl NatsClient {
    /// Create a new, disconnected [`NatsClient`].
    pub fn new() -> Self {
        Self {
            client: None,
            owner_guid: String::new(),
            connection_id: None,
            sequence: AtomicU64::new(0),
            event_rx: None,
        }
    }

    /// Take ownership of the connection-event receiver. Returns `None` if it
    /// has already been taken or no connection has been established yet.
    pub fn take_event_receiver(
        &mut self,
    ) -> Option<mpsc::UnboundedReceiver<NatsConnectionEvent>> {
        self.event_rx.take()
    }

    /// Connect to the NATS server at `url` using the supplied bearer `token`.
    ///
    /// The `owner_guid` is stored for constructing topic names. Reconnection is
    /// enabled with unlimited retries — async-nats handles backoff and resumes
    /// existing subscriptions automatically.
    pub async fn connect(
        &mut self,
        url: &str,
        token: &str,
        owner_guid: &str,
    ) -> Result<(), NatsError> {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let client = with_resilience(async_nats::ConnectOptions::new(), event_tx)
            .token(token.to_string())
            .connect(url)
            .await
            .map_err(|e| NatsError::ConnectionFailed(e.to_string()))?;

        self.client = Some(client);
        self.owner_guid = owner_guid.to_string();
        self.event_rx = Some(event_rx);
        log::info!("Connected to NATS at {}", url);
        Ok(())
    }

    /// Connect to NATS using JWT + seed credentials (same format as mobile
    /// peer connection invitations). Reconnection is enabled with unlimited
    /// retries.
    pub async fn connect_with_credentials(
        &mut self,
        url: &str,
        jwt: &str,
        seed: &str,
        owner_guid: &str,
    ) -> Result<(), NatsError> {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let creds = format!(
            "-----BEGIN NATS USER JWT-----\n{}\n------END NATS USER JWT------\n\n-----BEGIN USER NKEY SEED-----\n{}\n------END USER NKEY SEED------",
            jwt, seed,
        );

        let opts = async_nats::ConnectOptions::with_credentials(&creds)
            .map_err(|e| NatsError::ConnectionFailed(format!("invalid credentials: {}", e)))?;

        let client = with_resilience(opts, event_tx)
            .connect(url)
            .await
            .map_err(|e| NatsError::ConnectionFailed(e.to_string()))?;

        self.client = Some(client);
        self.owner_guid = owner_guid.to_string();
        self.event_rx = Some(event_rx);
        log::info!("Connected to NATS at {} with JWT credentials", url);
        Ok(())
    }

    /// Publish a message to a specific subject.
    pub async fn publish_to(&self, subject: &str, payload: &[u8]) -> Result<(), NatsError> {
        let client = self.client.as_ref().ok_or(NatsError::NotConnected)?;
        client
            .publish(subject.to_string(), payload.to_vec().into())
            .await
            .map_err(|e| NatsError::PublishFailed(e.to_string()))?;
        Ok(())
    }

    /// Subscribe to a specific subject.
    pub async fn subscribe_to(&self, subject: &str) -> Result<Subscriber, NatsError> {
        let client = self.client.as_ref().ok_or(NatsError::NotConnected)?;
        client
            .subscribe(subject.to_string())
            .await
            .map_err(|e| NatsError::SubscribeFailed(e.to_string()))
    }

    /// Get the owner GUID.
    pub fn owner_guid(&self) -> &str {
        &self.owner_guid
    }

    /// Publish a registration payload to the owner's device topic.
    ///
    /// Topic: `MessageSpace.{owner_guid}.forOwner.device`
    pub async fn publish_registration(&self, payload: &[u8]) -> Result<(), NatsError> {
        let client = self.client.as_ref().ok_or(NatsError::NotConnected)?;
        let subject = format!(
            "MessageSpace.{}.forOwner.device",
            self.owner_guid,
        );
        client
            .publish(subject, payload.to_vec().into())
            .await
            .map_err(|e| NatsError::PublishFailed(e.to_string()))?;
        Ok(())
    }

    /// Subscribe to the invitation-specific topic to receive the connection
    /// approval or denial.
    ///
    /// Topic: `MessageSpace.{owner_guid}.forOwner.device.invitation.{invitation_id}`
    pub async fn subscribe_invitation(
        &self,
        invitation_id: &str,
    ) -> Result<Subscriber, NatsError> {
        let client = self.client.as_ref().ok_or(NatsError::NotConnected)?;
        let subject = format!(
            "MessageSpace.{}.forOwner.device.invitation.{}",
            self.owner_guid, invitation_id,
        );
        client
            .subscribe(subject)
            .await
            .map_err(|e| NatsError::SubscribeFailed(e.to_string()))
    }

    /// Subscribe to the connection-specific topic for operational messages
    /// after registration is complete.
    ///
    /// Topic: `MessageSpace.{owner_guid}.forOwner.device.{connection_id}`
    pub async fn subscribe_responses(
        &self,
        connection_id: &str,
    ) -> Result<Subscriber, NatsError> {
        let client = self.client.as_ref().ok_or(NatsError::NotConnected)?;
        let subject = format!(
            "MessageSpace.{}.forOwner.device.{}",
            self.owner_guid, connection_id,
        );
        client
            .subscribe(subject)
            .await
            .map_err(|e| NatsError::SubscribeFailed(e.to_string()))
    }

    /// Subscribe to the broad vault push-event channel.
    ///
    /// Topic: `OwnerSpace.{owner_guid}.forApp.>` — this is the channel the vault
    /// uses to push events to the user's apps (messages received, read receipts,
    /// connection lifecycle, calls, feed events, etc.). Mirrors Android's
    /// `OwnerSpaceClient.subscribeToVaultEvents()`.
    pub async fn subscribe_app_events(&self) -> Result<Subscriber, NatsError> {
        let client = self.client.as_ref().ok_or(NatsError::NotConnected)?;
        let subject = format!("OwnerSpace.{}.forApp.>", self.owner_guid);
        client
            .subscribe(subject)
            .await
            .map_err(|e| NatsError::SubscribeFailed(e.to_string()))
    }

    /// Publish an already-encoded envelope to the owner's device topic.
    pub async fn publish_message(&self, envelope_bytes: &[u8]) -> Result<(), NatsError> {
        let client = self.client.as_ref().ok_or(NatsError::NotConnected)?;
        let subject = format!(
            "MessageSpace.{}.forOwner.device",
            self.owner_guid,
        );
        client
            .publish(subject, envelope_bytes.to_vec().into())
            .await
            .map_err(|e| NatsError::PublishFailed(e.to_string()))?;
        Ok(())
    }

    /// Return the next monotonically-increasing sequence number.
    pub fn next_sequence(&self) -> u64 {
        self.sequence.fetch_add(1, Ordering::SeqCst)
    }

    /// Set the connection ID after successful registration.
    pub fn set_connection_id(&mut self, id: String) {
        self.connection_id = Some(id);
    }

    /// Get the current connection ID, if any.
    pub fn connection_id(&self) -> Option<&str> {
        self.connection_id.as_deref()
    }

    /// Get the underlying async-nats client connection state. `None` if
    /// `connect` has never succeeded.
    pub fn connection_state(&self) -> Option<async_nats::connection::State> {
        self.client.as_ref().map(|c| c.connection_state())
    }

    /// Gracefully disconnect from the NATS server.
    pub async fn disconnect(&mut self) {
        if let Some(client) = self.client.take() {
            if let Err(e) = client.flush().await {
                log::warn!("Error flushing NATS client on disconnect: {}", e);
            }
            // Dropping the client closes the underlying connection.
            drop(client);
            log::info!("Disconnected from NATS");
        }
        self.owner_guid.clear();
        self.connection_id = None;
        self.event_rx = None;
        // Use a random starting sequence on reconnect to avoid replay confusion
        let random_start = rand::random::<u32>() as u64;
        self.sequence.store(random_start, Ordering::SeqCst);
    }
}

/// Apply standard resilience options: retry initial connect, unlimited
/// reconnect attempts, and forward connection-state events to the listener.
fn with_resilience(
    opts: async_nats::ConnectOptions,
    event_tx: mpsc::UnboundedSender<NatsConnectionEvent>,
) -> async_nats::ConnectOptions {
    opts.retry_on_initial_connect()
        .max_reconnects(None) // unlimited
        .event_callback(move |event| {
            let tx = event_tx.clone();
            async move {
                let mapped = match event {
                    async_nats::Event::Connected => NatsConnectionEvent::Connected,
                    async_nats::Event::Disconnected => NatsConnectionEvent::Disconnected,
                    async_nats::Event::LameDuckMode => NatsConnectionEvent::LameDuckMode,
                    async_nats::Event::SlowConsumer(n) => {
                        NatsConnectionEvent::SlowConsumer { dropped: n }
                    }
                    async_nats::Event::ServerError(e) => {
                        NatsConnectionEvent::ServerError { message: e.to_string() }
                    }
                    async_nats::Event::ClientError(e) => {
                        NatsConnectionEvent::ClientError { message: e.to_string() }
                    }
                };
                let _ = tx.send(mapped);
            }
        })
}
