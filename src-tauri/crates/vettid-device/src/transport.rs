//! The relay operations pairing needs, as a trait so the engine can be
//! tested against an in-memory relay. [`Http`] is the real one: PR D's
//! `RelayClient`, one per relay base URL, signing as this device's relay
//! key.

use std::future::Future;

use ed25519_dalek::SigningKey;
use vettid_relay::client::{DepositError, Message, Registration, RelayClient, RelayError};
use vettid_relay::token::Token;

/// What the engine asks of the relay. Every call signs as this device's
/// relay key; `base` is the relay base URL it goes to.
pub trait Transport {
    /// `POST /v1/register` for this device's mailbox at `base`.
    fn register(&self, base: &str) -> impl Future<Output = Result<Registration, RelayError>> + Send;
    /// Deposit into `mailbox` at `base` with `token`.
    fn deposit(&self, base: &str, mailbox: &str, token: &Token, payload: &[u8]) -> impl Future<Output = Result<String, DepositError>> + Send;
    /// Long-poll this device's mailbox at `base`.
    fn collect(&self, base: &str, wait_secs: u64, max: u32) -> impl Future<Output = Result<Vec<Message>, RelayError>> + Send;
    /// Ack a message of this device's mailbox at `base`.
    fn ack(&self, base: &str, msg_id: &str) -> impl Future<Output = Result<(), RelayError>> + Send;
    /// Fetch (and so spend) a claim at `base`.
    fn get_claim(&self, base: &str, claim_id: &str) -> impl Future<Output = Result<Vec<u8>, RelayError>> + Send;
}

/// The real relay, over HTTPS.
pub struct Http {
    key: SigningKey,
    /// The dev stack's relay instead (development builds only).
    #[cfg(feature = "dev-relay")]
    dev: Option<vettid_relay::dev::DevRelay>,
}

impl std::fmt::Debug for Http {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Http(..)")
    }
}

impl Http {
    /// A transport signing as `key`, this device's relay key.
    pub fn new(key: SigningKey) -> Self {
        Http {
            key,
            #[cfg(feature = "dev-relay")]
            dev: None,
        }
    }

    /// **DEVELOPMENT ONLY** (`dev-relay`): a transport that reaches only
    /// the dev stack's relay (`https://relay.vettid.test`, see
    /// `vettid_relay::dev`); any other base URL is refused.
    #[cfg(feature = "dev-relay")]
    pub fn dev(key: SigningKey, dev: vettid_relay::dev::DevRelay) -> Self {
        Http { key, dev: Some(dev) }
    }

    fn client(&self, base: &str) -> Result<RelayClient, RelayError> {
        #[cfg(feature = "dev-relay")]
        if let Some(d) = &self.dev {
            return RelayClient::new_dev(base, self.key.clone(), d);
        }
        RelayClient::new(base, self.key.clone())
    }
}

impl Transport for Http {
    async fn register(&self, base: &str) -> Result<Registration, RelayError> {
        self.client(base)?.register().await
    }
    async fn deposit(&self, base: &str, mailbox: &str, token: &Token, payload: &[u8]) -> Result<String, DepositError> {
        let c = self.client(base).map_err(|error| DepositError { error, possibly_delivered: false })?;
        c.deposit(mailbox, token, payload).await
    }
    async fn collect(&self, base: &str, wait_secs: u64, max: u32) -> Result<Vec<Message>, RelayError> {
        self.client(base)?.collect(wait_secs, max).await
    }
    async fn ack(&self, base: &str, msg_id: &str) -> Result<(), RelayError> {
        self.client(base)?.ack(msg_id).await
    }
    async fn get_claim(&self, base: &str, claim_id: &str) -> Result<Vec<u8>, RelayError> {
        self.client(base)?.get_claim(claim_id).await
    }
}
