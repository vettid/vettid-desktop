//! VettID relay client (RELAY-PROTOCOL).
//!
//! This crate holds the relay's authentication primitives as a client needs
//! them:
//! - [`auth`]: mailbox ids (§3.2) and signed requests (§4.1);
//! - [`token`]: PASETO v4.public deposit tokens (§5).
//!
//! The transport (register, deposit, collect, ack) follows in its own module.
//!
//! Nothing here logs, and no error carries key, signature, token or payload
//! material.

pub mod auth;
pub mod token;
