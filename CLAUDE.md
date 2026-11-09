# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
# Rust backend
cargo check --manifest-path src-tauri/Cargo.toml     # Type-check
cargo build --manifest-path src-tauri/Cargo.toml      # Debug build
cargo test --manifest-path src-tauri/Cargo.toml       # Run tests
cargo test --manifest-path src-tauri/Cargo.toml --release  # Release-mode tests

# Frontend
npm install          # Install dependencies
npm run dev          # Vite dev server (hot-reload)
npm run build        # Production build
npm run check        # svelte-check type checking

# Full Tauri app
cargo tauri dev      # Dev mode (frontend + backend)
cargo tauri build    # Production binary

# With WebRTC calls (audio in/out via libopus + cpal)
brew install opus pkg-config cmake     # one-time system deps
cargo tauri build --features webrtc    # adds ~5min on first compile

# Local install (drag-to-Applications + ad-hoc sign + quarantine strip)
./scripts/install-local.sh             # release, signaling-only
./scripts/install-local.sh --calls     # release, with WebRTC media
./scripts/install-local.sh --debug     # debug build (faster compile)
```

## Testing

All Rust tests live alongside source files in `#[cfg(test)] mod tests` blocks:
```bash
cargo test --manifest-path src-tauri/Cargo.toml                   # All tests
cargo test --manifest-path src-tauri/Cargo.toml -- crypto         # Crypto module tests
cargo test --manifest-path src-tauri/Cargo.toml -- session        # Session module tests
cargo test --manifest-path src-tauri/Cargo.toml -- fingerprint    # Fingerprint tests
```

## Architecture

### IPC Flow
```
Svelte Frontend → Tauri IPC (invoke) → commands/*.rs → link.rs → crates/vettid-device → relay → Vault
```

The frontend calls Tauri commands via `@tauri-apps/api`. Commands in `src-tauri/src/commands/` delegate to the core Rust modules. The desktop reaches its vault through the relay, with the device engine in `src-tauri/crates/vettid-device` (pairing, sessions and access sessions, VAULT-MESSAGING §6–§8). Other vault operations are not carried over yet: they answer one plain "not available" error (`commands/unavailable.rs`).

### Module Map

| Module | Purpose |
|--------|---------|
| `crypto/` | X25519 keypairs, ECIES encrypt/decrypt, HKDF-SHA256, zeroization |
| `fingerprint/` | Binary self-hash, the displayed machine fingerprint (not a key) |
| `credential/` | On-disk encrypted stores: `device_store.rs` (the device engine's state, `device.enc` v2: a random data key wrapped by a protector), `protector.rs` (the protectors: DPAPI on Windows in `dpapi.rs`; on Linux the TPM in `tpm.rs`, then the Secret Service in `secret_service.rs`; the keyring on macOS for now), `store.rs` (shared parts; wipes; the earlier builds' pairing) |
| `link.rs` | The paired device's session and access session with its vault, and the background refresh |
| `session/` | Capability tiers, phone delegation |
| `commands/` | Tauri IPC command handlers (auth, vault, session) |

### Frontend Structure

| Path | Purpose |
|------|---------|
| `src/lib/views/` | Page-level Svelte components (Pairing, Session, Settings, Vault) |
| `src/lib/stores/` | Svelte stores for session and vault state |
| `src/lib/components/` | Reusable UI (PendingApproval, SessionTimer, StatusBar) |

## Security Patterns

### ECIES Domain Separation
Two domain constants prevent key confusion between encryption contexts:
- `vettid-device-v1` — Device-level encryption
- `vettid-connection-v1` — Connection-level encryption

HKDF uses the domain string as the salt, producing different derived keys from the same shared secret.

### Zeroization
All intermediate key material (`zeroize` crate) is wiped after use. Look for `// SECURITY:` comments marking critical zeroization points.

### At-rest key
The device file is sealed under a random data key wrapped by a platform protector, with no passphrase and no machine id in the key or the associated data (DESKTOP-REWORK-PLAN §4 "At-rest protectors"). With no protector, the desktop doesn't pair.

### Capability Tiers
- **Independent** (`capabilities.rs`): `profile.view`, `connection.list`, `feed.list`, `audit.query`, `message.list`, `secrets.catalog`, etc.
- **Phone-required** (`capabilities.rs`): `secrets.retrieve`, `secrets.add`, `connection.create`, `credential.get`, `agent.approve`, etc.

### Session State
A session is live only while the vault's access session is (VAULT-MESSAGING §6.8): `link.rs` follows `Access::active_at` after this run's own `vault.status`, and the UI reads a snapshot of it. An end the vault hasn't confirmed is never shown as ended.

## Naming Conventions

- **Rust**: `snake_case` for functions, modules, variables
- **TypeScript/Svelte**: `camelCase` for variables/functions, `PascalCase` for components
- **Tauri commands**: `snake_case` in Rust, invoked as `camelCase` from frontend

## Wire Format

The device engine's messages are VAULT-MESSAGING's envelopes (`crates/vettid-vms`), sent through the relay (`crates/vettid-relay`). The specifications in `vettid/vettid.org` `docs/` decide.
