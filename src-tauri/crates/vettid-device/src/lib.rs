//! The VettID device engine, desktop side. This first part pairs a
//! desktop with its vault (VAULT-MESSAGING §6.7) end to end over the
//! relay: the pairing code, the claim bundle, the handshake, the SAS the
//! member compares on their phone, and the owner's approval
//! (`device.paired`) or rejection (`device.pair.rejected`).
//!
//! [`session`] runs a paired desktop's session: sending through an outbox,
//! collecting with both dedupe layers, storing before acking, and keeping
//! tokens fresh. The responder side (the vault's rekeys) follows.
//!
//! - [`transport`]: the relay operations the engine needs, over
//!   `vettid-relay`'s client.
//! - [`token`]: the standing token this device mints for its vault, and
//!   the check of the tokens the vault hands it.
//! - [`store`]: what the device keeps, and the [`store::Persist`] trait a
//!   key store implements. A plain-file store exists for development
//!   only, behind the `dev-file-store` feature, which a release build
//!   refuses to compile.
//! - [`pairing`]: the flow itself.
//! - [`display`]: what the desktop may show of what the vault's side
//!   wrote.
//!
//! Nothing here logs. Secrets print nothing in `Debug`.

#[cfg(all(feature = "dev-file-store", not(debug_assertions)))]
compile_error!("the dev-file-store feature writes keys to a plain file: it is for development builds only");

pub mod display;
pub mod pairing;
pub mod session;
pub mod store;
pub mod token;
pub mod transport;

#[cfg(feature = "dev-file-store")]
pub mod dev_store;

#[cfg(test)]
mod testutil;
