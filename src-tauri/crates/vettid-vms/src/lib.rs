//! VettID messaging, suite 2 (VAULT-MESSAGING §3.2, §4).
//!
//! [`suite`] holds the primitives: the MLKEM768X25519 (X-Wing) KEM,
//! single-shot HPKE base mode, the session AEAD, kids and labelled
//! signatures. [`envelope`] is the v2 envelope (§5): its byte layout,
//! padding and the inner plaintext, read with [`strict_json`]. The
//! handshake and the device engine follow in their own modules.
//!
//! Nothing here logs. Secret types print nothing in `Debug` and are wiped
//! when dropped.

pub mod envelope;
pub mod strict_json;
pub mod suite;
