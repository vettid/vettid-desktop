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
Svelte Frontend → Tauri IPC (invoke) → commands/*.rs → Rust modules → NATS → Vault Manager
```

The frontend calls Tauri commands via `@tauri-apps/api`. Commands in `src-tauri/src/commands/` delegate to the core Rust modules. External communication goes through NATS to the vault-manager running inside a Nitro Enclave.

### Module Map

| Module | Purpose |
|--------|---------|
| `crypto/` | X25519 keypairs, ECIES encrypt/decrypt, HKDF-SHA256, Argon2id, zeroization |
| `fingerprint/` | Binary self-hash, platform key (Linux-specific), machine identity |
| `credential/` | On-disk encrypted credential store |
| `nats/` | async-nats client, Envelope wire format, message types |
| `registration/` | Pairing flow orchestration, short-link code handling |
| `session/` | SessionManager state machine, capability tiers, phone delegation |
| `commands/` | Tauri IPC command handlers (auth, vault, session) |

### Frontend Structure

| Path | Purpose |
|------|---------|
| `src/lib/views/` | Page-level Svelte components (Pairing, Session, Settings, Vault) |
| `src/lib/stores/` | Svelte stores for NATS and session state |
| `src/lib/components/` | Reusable UI (PendingApproval, SessionTimer, StatusBar) |

## Security Patterns

### ECIES Domain Separation
Two domain constants prevent key confusion between encryption contexts:
- `vettid-device-v1` — Device-level encryption
- `vettid-connection-v1` — Connection-level encryption

HKDF uses the domain string as the salt, producing different derived keys from the same shared secret.

### Zeroization
All intermediate key material (`zeroize` crate) is wiped after use. Look for `// SECURITY:` comments marking critical zeroization points.

### Argon2id Parameters
- Time: 3 iterations
- Memory: 64 MB (65536 KB)
- Parallelism: 4 threads
- Output: 32 bytes

Input is `passphrase || platform_key`, binding derived keys to both user knowledge and device identity.

### Capability Tiers
- **Independent** (`capabilities.rs`): `profile.view`, `connection.list`, `feed.list`, `audit.query`, `message.list`, `secrets.catalog`, etc.
- **Phone-required** (`capabilities.rs`): `secrets.retrieve`, `secrets.add`, `connection.create`, `credential.get`, `agent.approve`, etc.

### Session State Machine
`SessionManager` tracks: `Inactive → Active → Suspended/Expired/Revoked`. Suspended sessions can resume when the phone reconnects.

## Naming Conventions

- **Rust**: `snake_case` for functions, modules, variables
- **TypeScript/Svelte**: `camelCase` for variables/functions, `PascalCase` for components
- **NATS message types**: `snake_case` constants (`device_connection_request`, `device_op_request`)
- **NATS topics**: `Control.enclave.{id}.*`, `MessageSpace.{ownerSpace}.*`
- **Tauri commands**: `snake_case` in Rust, invoked as `camelCase` from frontend

## Wire Format

All NATS messages use a JSON `Envelope`:
```json
{
  "type": "device_connection_request",
  "key_id": "...",
  "payload": [...],
  "timestamp": "ISO 8601",
  "sequence": 1
}
```
