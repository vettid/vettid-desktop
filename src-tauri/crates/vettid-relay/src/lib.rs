//! VettID relay client (RELAY-PROTOCOL).
//!
//! This crate holds the relay's authentication primitives as a client needs
//! them:
//! - [`auth`]: mailbox ids (§3.2) and signed requests (§4.1);
//! - [`token`]: PASETO v4.public deposit tokens (§5).
//!
//! - [`client`]: the transport: register, deposit, collect, ack and the
//!   claim fetch (§6, §7).
//!
//! Nothing here logs, and no error carries key, signature, token or payload
//! material.

pub mod auth;
pub mod client;
pub mod token;
