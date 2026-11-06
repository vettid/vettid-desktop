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

The member's phone shows a desktop pairing code. The desktop reads it and pairs with the vault through the relay (VAULT-MESSAGING §6.7, `src-tauri/crates/vettid-device`): a handshake, a six-digit code the member compares on the phone, and the owner's approval there. The keys are made on the desktop and kept sealed under a data key that a platform protector wraps (see Credential Binding); with no protector available the desktop doesn't pair.

## Project Structure

```
src-tauri/src/
├── lib.rs                  # Tauri app builder, IPC handler registration
├── main.rs                 # Entry point
├── commands/
│   ├── auth.rs             # register, unlock, get_status
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
│   ├── device_store.rs     # The device engine's state, sealed (device.enc v2)
│   ├── protector.rs        # What wraps its data key: DPAPI (Windows), TPM or Secret Service (Linux), keyring (macOS, for now)
│   ├── tpm.rs              # Linux: the TPM 2.0 protector (/dev/tpmrm0)
│   ├── secret_service.rs   # Linux: the Secret Service protector, ranked after the TPM
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
The paired device's state (`device.enc`) is sealed under a random data key made at pairing, and that key is wrapped by a platform protector (DESKTOP-REWORK-PLAN §4 "At-rest protectors"). On Windows it is DPAPI for the user's account: a copy of the file alone doesn't open elsewhere, but a copy of the whole profile with the user's password does, and an administrator can unwrap it while the user is logged on. Another Windows account on the same computer can't open a copy of the file, even one it owns; that was tested with a second account standing in for another computer (`docs/WINDOWS-TESTING.md`, #13). On Linux it is the TPM 2.0 through `/dev/tpmrm0`: the data key is sealed under the storage root key, with no PCR policy and no auth value, so it opens only on this TPM, but root, or any user who can read the file and use the TPM (any process of this user included), can unseal it, and clearing the TPM loses the pairing. Many distributions give `/dev/tpmrm0` to `root:tss` only, and a Flatpak has none; without a TPM this user can use, the key is kept in the Secret Service (GNOME Keyring, KWallet), one item per pairing, which is not bound to the computer: a copy of the keyring file opens elsewhere with the login password. With neither, the desktop doesn't pair. The TPM protector links `libtss2` (esys, tctildr, mu, and the device TCTI at run time). On macOS, for now, the key is kept in the OS keyring, which is not bound to the computer. An old copy of the file recovered from a backup or the disk still opens for the same user on the same computer.

Uninstalling on Windows deletes the saved pairing, silent `/S` included. An update (`/UPDATE`), or an upgrade, downgrade or reinstall by hand (the installer runs the old uninstaller in place), keeps it. The uninstaller runs `vettid-desktop.exe --uninstall-wipe`, the same confirmed wipe as log-out, without contacting the vault, and checks the files again once the program is removed before it says anything. It uninstalls only when run by the account that installed the app; run as another account (say, "Run as administrator" with another password), it removes nothing, so that account's pairing is untouched and the user can still log out or uninstall, and it reports a failure. A failure gives exit code 2, silent or not, and nearly always a Warning in the Windows Application event log (an uninstall that stops before removing anything writes none, #74); a script that needs the exit code runs `uninstall.exe /S /WIPEPAIRING _?=<install folder>`, because a plain `uninstall.exe /S` returns 0 at once. The vault still lists the desktop until it is removed on the phone; the uninstaller doesn't tell the phone. For Intune, ConfigMgr or a script, deploy in user context (install and uninstall as the person, not as SYSTEM), and uninstall with `scripts/windows/uninstall-vettid.ps1`: `uninstall.exe /S _?=<folder>` without `/WIPEPAIRING` keeps the pairing and still exits 0. Exit codes, the commands for managed installs and what is still left behind: `docs/WINDOWS-TESTING.md`.

The machine fingerprint shown in Settings is not a key, and is not unique: a cloned disk image or VM shows the same one.

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
