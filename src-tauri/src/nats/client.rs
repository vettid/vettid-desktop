use async_nats::{Client, Subscriber};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

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
}

impl NatsClient {
    /// Create a new, disconnected [`NatsClient`].
    pub fn new() -> Self {
        Self {
            client: None,
            owner_guid: String::new(),
            connection_id: None,
            sequence: AtomicU64::new(0),
        }
    }

    /// Connect to the NATS server at `url` using the supplied bearer `token`.
    ///
    /// The `owner_guid` is stored for constructing topic names.
    pub async fn connect(
        &mut self,
        url: &str,
        token: &str,
        owner_guid: &str,
    ) -> Result<(), NatsError> {
        let client = async_nats::ConnectOptions::new()
            .token(token.to_string())
            .connect(url)
            .await
            .map_err(|e| NatsError::ConnectionFailed(e.to_string()))?;

        self.client = Some(client);
        self.owner_guid = owner_guid.to_string();
        log::info!("Connected to NATS at {}", url);
        Ok(())
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
        self.sequence.store(0, Ordering::SeqCst);
    }
}
