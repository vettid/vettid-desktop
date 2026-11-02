//! VettID messaging, suite 2 (VAULT-MESSAGING §3.2, §4).
//!
//! [`suite`] holds the primitives: the MLKEM768X25519 (X-Wing) KEM,
//! single-shot HPKE base mode, the session AEAD, kids and labelled
//! signatures. [`envelope`] is the v2 envelope (§5): its byte layout,
//! padding and the inner plaintext, read with [`strict_json`].
//! [`handshake`] is the session handshake's initiator side (§6.1–§6.3).
//! [`invite`] reads invitations and pairing codes (§6.4). The device
//! engine follows in its own module.
//!
//! Nothing here logs. Secret types print nothing in `Debug` and are wiped
//! when dropped.

pub mod envelope;
pub mod handshake;
pub mod invite;
pub mod strict_json;
pub mod suite;
