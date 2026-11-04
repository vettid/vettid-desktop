# VettID Desktop

Desktop companion app for VettID, built with Tauri v2, Rust, and Svelte.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

## Overview

VettID Desktop extends your VettID vault to desktop environments. Sessions are time-limited and capability-scoped — your phone stays in control. The desktop can browse connections, read feeds, and view audit logs independently, but any sensitive operation (retrieving secrets, updating credentials, approving agents) requires real-time phone approval. The desktop reaches its vault through the vault's relay; in this build only pairing and sessions do, and other vault operations answer "not available yet".

## Features

- **Device Pairing** — QR / short-link registration flow with machine fingerprinting
- **Session Management** — Time-bounded sessions with automatic expiry, suspend, and resume
- **Phone Approval** — Sensitive operations require delegated approval from the paired phone
- **Encrypted Credential Store** — ECIES (X25519 + XChaCha20-Poly1305) with domain separation
- **Machine Fingerprinting** — Binary hash + platform key binding for device identity
- **Capability Tiers** — Independent operations vs. phone-required operations

## Requirements

- Rust 1.75+ (2021 edition)
- Node.js 18+
- Tauri v2 system dependencies ([see Tauri prerequisites](https://v2.tauri.app/start/prerequisites/))

### Pairing (no creds shipped in the binary)

The member's phone shows a desktop pairing code. The desktop reads it and pairs with the vault through the relay (VAULT-MESSAGING §6.7, `src-tauri/crates/vettid-device`): a handshake, a six-digit code the member compares on the phone, and the owner's approval there. The keys are made on the desktop and kept sealed under a key in the OS keyring; without a keyring the desktop doesn't pair.

## Project Structure

```
src-tauri/src/
├── lib.rs                  # Tauri app builder, IPC handler registration
├── main.rs                 # Entry point
├── commands/
│   ├── auth.rs             # register, unlock, lock, get_status
│   ├── session.rs          # get_session_status, get_session_timer
│   └── vault.rs            # list_connections, get_connection, list_feed,
│                           #   query_audit, list_messages, list_secrets_catalog,
│                           #   request_secret
├── crypto/
│   ├── argon2.rs           # Argon2id key derivation (passphrase + platform key)
│   ├── ecies.rs            # ECIES encrypt/decrypt with domain separation
│   ├── encrypt.rs          # CryptoError, symmetric helpers
│   ├── hkdf.rs             # HKDF-SHA256 key derivation
│   └── keys.rs             # X25519 keypair generation
├── credential/
│   ├── device_store.rs     # The device engine's state, sealed (keyring only)
│   └── store.rs            # On-disk encrypted storage (shared parts)
├── fingerprint/
│   ├── binary.rs           # Binary self-hash
│   ├── platform_key.rs     # Platform key abstraction
│   └── platform_linux.rs   # Linux-specific platform key
├── link.rs                 # Session and access session with the vault (relay)
└── session/
    ├── capabilities.rs     # Independent vs. phone-required capability lists
    └── delegation.rs       # Phone-delegated operation requests

src/
├── App.svelte              # Root component, view router
├── main.ts                 # Svelte mount
└── lib/
    ├── components/
    │   ├── PendingApproval.svelte
    │   ├── SessionTimer.svelte
    │   └── StatusBar.svelte
    ├── stores/
    │   └── session.ts      # Session state
    └── views/
        ├── Pairing.svelte  # Device registration flow
        ├── Session.svelte  # Active session dashboard
        ├── Settings.svelte # App settings
        └── Vault.svelte    # Vault browser
```

## Build

```bash
# Install frontend dependencies
npm install

# Development (hot-reload frontend + Rust backend)
npm run dev            # frontend only
cargo tauri dev        # full Tauri app

# Production build
cargo tauri build

# Run Rust tests
cargo test --manifest-path src-tauri/Cargo.toml

# Type-check frontend
npm run check
```

## Security

### Crypto Stack
- **X25519** — Elliptic curve Diffie-Hellman for key exchange
- **XChaCha20-Poly1305** — AEAD symmetric encryption
- **HKDF-SHA256** — Key derivation with domain separation (`vettid-device-v1`, `vettid-connection-v1`)
- **Argon2id** — Password hashing (t=3, m=64MB, p=4) matching OWASP recommendations

### Credential Binding
Derived keys are bound to both the user's passphrase and the device's platform key material, preventing credential extraction to a different machine.

### Zeroization
All intermediate key material (shared secrets, derived keys, concatenated inputs) is zeroized immediately after use via the `zeroize` crate.

## Architecture

```
Phone App → Vault (Nitro Enclave) ← relay (E2E encrypted) ← Desktop Client
```

The desktop never holds the vault master key. After phone-approved pairing it holds its own device keys, and asks the vault for time-limited access sessions, which the owner's phone approves (VAULT-MESSAGING §6.8).

## Related Repositories

- [vettid-dev](https://github.com/vettid/vettid-dev) — Backend infrastructure
- [vettid-android](https://github.com/vettid/vettid-android) — Android app
- [vettid-ios](https://github.com/vettid/vettid-ios) — iOS app
- [vettid-agent](https://github.com/vettid/vettid-agent) — Agent connector (Go sidecar)
- [vettid-service-vault](https://github.com/vettid/vettid-service-vault) — Service integration layer
- [vettid.org](https://github.com/vettid/vettid.org) — Website

## License

AGPL-3.0-or-later — See [LICENSE](LICENSE) for details.

## Links

- Website: [vettid.org](https://vettid.org)
- Documentation: [docs.vettid.dev](https://docs.vettid.dev)
