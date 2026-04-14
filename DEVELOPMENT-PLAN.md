# VettID Desktop — Development Plan

## Current State Assessment (2026-04-13)

The desktop client is a **functional prototype** built with Tauri v2 (Rust backend + Svelte 5 frontend). The core architecture is sound and aligned with the Android app's NATS-based vault communication model.

### What's Working
- **Crypto stack**: X25519, XChaCha20-Poly1305, HKDF-SHA256, Argon2id, Ed25519 — same as Android
- **NATS client**: async-nats v0.37, pub/sub, encrypted operations
- **Device registration**: P2P pairing via 6-character shortlink codes
- **Credential storage**: Encrypted with passphrase + platform key binding (4-of-5 hardware fingerprint tolerance)
- **Session management**: State machine with time-bounded tokens, phone delegation
- **Operation mapping**: 30+ vault operations mapped (independent + phone-required)
- **Background listener**: Incoming message routing (device_op_response, session_update, feed_event, new_message)
- **Cross-platform fingerprint scaffolding**: `platform_linux.rs` (production) + `platform_macos.rs` (scaffolded — IOPlatformUUID, sysctl CPU brand, diskutil, ifconfig MAC). `platform_key.rs` already cfg-dispatches by target OS.

### What's Scaffolded (Empty UI)
- ConnectionsList, MessagingView, FeedView, WalletView, VotingView, SecretsView, DevicesView
- These Svelte views exist as containers but lack logic and data binding

### Target Platforms
- **Linux** (primary dev target — x86_64 and aarch64; AppImage + .deb)
- **macOS** (parallel target — Apple Silicon `aarch64` only; .app + .dmg, Developer ID signed and notarized. Intel Macs are out of scope: Apple stopped selling them in 2023, and a 2026 launch with no existing Intel users doesn't justify the build/bundle overhead. Adding `x86_64` later is a one-line CI change if needed.)
- Windows is out of scope for this plan

### Architecture Model
The desktop operates as a **"device connection"** — it does NOT own a vault. It delegates operations through the user's phone/vault:
- **Independent operations** (no phone approval): profile.view, connection.list, feed.list, message.list, wallet.list, etc.
- **Phone-required operations** (needs delegation): secrets.retrieve, connection.create, profile.update, send.btc, send.message, etc.

---

## Reference: Android App Current Features

The Android app (vettid-android) is the reference implementation. Key features to match:

| Feature | Android Status | Desktop Priority |
|---------|---------------|-----------------|
| Feed (connection-centric) | Done | Phase 2 |
| Messaging (E2E encrypted) | Done | Phase 3 |
| Connection management | Done | Phase 2 |
| Profile view/edit | Done | Phase 4 |
| BTC Wallet | Done | Phase 5 |
| Voice/Video calls (WebRTC + E2EE) | Done | Phase 6 |
| Push notifications (NATS real-time) | Done | Phase 1 |
| Read receipts | Done | Phase 3 |
| Clickable links in messages | Done | Phase 3 |
| Notification deep-linking | Done | Phase 7 |
| Foreground service (background) | Done | Phase 7 (system tray) |

---

## Cross-Platform Strategy

The desktop is built once with Tauri v2 and deployed to both Linux and macOS. The vast majority of code is platform-agnostic; platform-specific concerns are isolated to a handful of modules.

### Where the OSes diverge

| Concern | Linux approach | macOS approach |
|---|---|---|
| Machine fingerprint (5 attrs) | `/etc/machine-id`, `/proc/cpuinfo`, `lsblk`, `/sys/class/net` | `ioreg` IOPlatformUUID, `sysctl machdep.cpu.brand_string`, `diskutil info disk0`, `ifconfig` |
| HMAC domain label | `vettid-desktop-platform-v1` (shared — same label across OSes; fingerprints are inherently OS-bound through their inputs) | same |
| Credential store path | `$XDG_DATA_HOME/vettid` or `~/.local/share/vettid` (via `dirs::data_dir()`) | `~/Library/Application Support/com.vettid.desktop` (via `dirs::data_dir()`) |
| System tray icon | Standard PNG | Template icon (black + alpha) so macOS recolors it for light/dark menu bar |
| Notifications | `notify-rust` / freedesktop spec, no permission prompt | Requires `NSUserNotificationUsageDescription` in Info.plist; first send triggers permission prompt |
| Window chrome | Standard decorations | Native traffic-light buttons; consider `titleBarStyle: "overlay"` for unified look |
| Single-instance | `tauri-plugin-single-instance` | same plugin; macOS also reactivates on Dock click via `RunEvent::Reopen` |
| Camera/mic permissions (Phase 6) | None at OS level | Requires `NSCameraUsageDescription`, `NSMicrophoneUsageDescription` in Info.plist + first-use prompt |
| Screen sharing (Phase 6) | PipeWire (Wayland) / X11 | Requires `NSScreenCaptureUsageDescription`; user must grant in System Settings → Privacy & Security → Screen Recording |
| Auto-launch on login | `.desktop` file in `~/.config/autostart` | `LaunchAgents` plist or `tauri-plugin-autostart` |
| Distribution format | AppImage (portable) + .deb (Debian/Ubuntu) | .dmg with .app inside, signed + notarized |

### Code organization principle

- **Default-to-shared**: place logic in cross-platform modules; only branch on `cfg(target_os = …)` when behavior actually differs.
- **Platform modules stay thin**: each `platform_<os>.rs` exposes the same shared types (`MachineAttributes`, `FingerprintError`) and a `collect_*` function. Higher-level code (`platform_key.rs`) dispatches via `cfg`.
- **No conditional imports in business logic**: views, stores, and command handlers must compile identically on both platforms.

### CI matrix

CI should build and test on:
- `ubuntu-latest` (Linux x86_64)
- `macos-latest` (Apple Silicon aarch64 — single-arch build, no `lipo` step)

Run `cargo test`, `npm run check`, and `cargo tauri build` on each runner. Bundle artifacts get attached to GitHub Releases.

---

## Implementation Phases

### Phase 1: Core Communication & Real-time Updates
**Goal**: Desktop receives real-time events like the Android app.

**Why first**: Everything else depends on reliable real-time communication.

#### 1.1 NATS Push Subscription
- Subscribe to `OwnerSpace.{ownerGuid}.forApp.>` for real-time push events
- Currently the listener only subscribes to device response topics
- Reference: Android's `OwnerSpaceClient.subscribeToVaultEvents()`

#### 1.2 Event Routing
- Mirror Android's `handleVaultResponse()` pattern in `nats/listener.rs`
- Route by subject using `contains()` matching (handles `.response` suffix from JetStream):
  - `.forApp.new-message` → message received handler
  - `.forApp.read-receipt` → read receipt handler
  - `.forApp.call.*` → call signaling handler
  - `.forApp.feed.new` / `.forApp.feed.updated` → feed notification handler
  - `.forApp.connection.*` → connection lifecycle handler
  - `.forApp.profile-update` → profile update handler
  - `.forApp.credentials.rotate` → credential rotation handler
- Reference: `OwnerSpaceClient.kt:handleVaultResponse()` (lines 1398-1477)

#### 1.3 JetStream Consumer
- Add JetStream support for request-response patterns
- Android uses `JetStreamRequestHelper` with ephemeral consumers for reliable request-response
- Consider whether desktop needs JetStream or if basic NATS pub/sub with timeouts is sufficient for the delegation model

#### 1.4 Reconnection Handling
- Implement clean reconnection logic (Android had a bug with dual reader threads after reconnect)
- On disconnect: attempt reconnect with exponential backoff
- On reconnect: re-subscribe to all push topics, sync missed events via `feed.sync`
- Emit connection state changes to frontend (StatusBar component)

**Key files to modify:**
- `src-tauri/src/nats/listener.rs` — Add push subscription and event routing
- `src-tauri/src/nats/client.rs` — Add reconnection logic
- `src-tauri/src/state.rs` — Add push event flows

---

### Phase 2: Feed & Connections UI
**Goal**: Working feed and connection management matching Android's connection-centric design.

#### 2.1 Connection List
- Wire `connection.list` vault operation to ConnectionsList view
- Display connection cards by status: active, pending, revoked, rejected
- Show: peer name, avatar (base64), last message preview, unread count, last activity time
- Reference: Android's `FeedViewModel.buildConnectionCards()` and `ConnectionRecord` model

#### 2.2 Connection Detail
- Full peer profile display (name, email, phone, public keys, wallet addresses)
- Sections: Profile, Shared Info, Security, Manage
- Manage section: revoke connection (phone-required operation)
- Reference: Android's `ConnectionDetailScreen`

#### 2.3 Feed View
- Two sections: Connections first, then Activity items (matching Android's refactored feed)
- Connection cards sorted by last activity timestamp
- Activity items for standalone events (guides, security alerts, etc.)
- Pull-to-refresh equivalent (manual refresh button)
- Reference: Android's `FeedScreen.kt` sectioned layout

#### 2.4 Connection Actions
- Accept/decline for pending inbound connections
- Create new connection: generate shortlink code for phone to scan (or share invite link)
- Connection review screen for pending connections
- Reference: Android's `ConnectionReviewScreen`

#### 2.5 Real-time Feed Updates
- Wire `feed.new` / `feed.updated` push events to update UI
- Update unread counts when messages arrive
- Badge count on connections with unread messages

**Key files to modify:**
- `src/lib/views/VaultView.svelte` — Wire connection list
- `src/lib/views/` — New ConnectionDetail view
- `src/lib/stores/vault.ts` — Connection state management
- `src-tauri/src/commands/vault.rs` — Connection list command handler

---

### Phase 3: Messaging
**Goal**: Full conversation experience.

#### 3.1 Conversation View
- Message list with bubble UI
- Color scheme: gold (#ffc125) on black for sent, black on gold for received (matching Android)
- Reverse chronological with scroll-to-bottom
- Infinite scroll for loading older messages

#### 3.2 Send Messages
- Wire `message.send` through vault (phone-required operation — needs delegation)
- Text input with send button
- Show sending state and delivery confirmation

#### 3.3 Read Receipts
- Send `message.read-receipt` when conversation is opened
- Display single check (delivered) and double check (read) on sent messages
- Real-time receipt updates via `read-receipt` push events
- Reference: Android's `ConversationViewModel.observeReadReceipts()`

#### 3.4 Clickable Links
- Detect URLs in message text using regex
- Make them clickable — open in system default browser via `shell.open()`
- URL pattern: `https?://[^\s]+` and `www.[^\s]+`
- Reference: Android's `LinkifiedText` composable

#### 3.5 Rich Message Types
- BTC payment request/receipt rendering (parse JSON content)
- BTC address sharing with copy button
- Reference: Android's `MessageContentType` enum and specialized content renderers

#### 3.6 Desktop Notifications
- Show OS notification for incoming messages when app is not focused
- Use the `tauri-plugin-notification` v2 plugin (replaces the v1 `tauri::api::notification` path)
- Include sender name and message preview
- Click notification → focus app and navigate to conversation
- **macOS**: first call triggers permission prompt; check + request via plugin API on app start. Add `NSUserNotificationUsageDescription` (or rely on the bundle identifier — modern macOS uses identifier-bound permission). Confirm notifications work both when app is in Dock and when only in menu bar.
- **Linux**: uses freedesktop notification spec via `notify-rust` under the hood; no permission prompt. Verify on both GNOME and KDE.

**Key files to modify:**
- `src/lib/views/` — New ConversationView component
- `src/lib/stores/` — Message state store
- `src-tauri/src/commands/vault.rs` — Message send/list commands
- `src-tauri/src/nats/listener.rs` — Message received handler

---

### Phase 4: Profile & Personal Data
**Goal**: View and manage identity.

#### 4.1 Profile View
- Display published profile: name, email, phone, wallet addresses, public keys
- Fetch via `profile.get-published` (independent operation)
- Profile photo display (base64 from vault)

#### 4.2 Profile Editing
- Edit fields with phone approval (delegated operation via `profile.update`)
- Show pending approval state while waiting for phone

#### 4.3 Personal Data
- View personal data sections (Medical, Financial, Legal, etc.)
- Section visibility toggles
- Add/edit with phone approval

#### 4.4 Profile Photo
- Display peer and own profile photos
- Upload requires phone approval
- Cache photos locally for performance

**Key files to modify:**
- `src/lib/views/` — ProfileView component
- `src-tauri/src/commands/vault.rs` — Profile commands

---

### Phase 5: Wallet
**Goal**: Bitcoin wallet management from desktop.

#### 5.1 Wallet List
- Display wallets with balances (independent operation)
- Wallet cards with name, balance, address preview

#### 5.2 Receive
- Show receive address with QR code (generate QR in frontend)
- Copy address to clipboard
- Share payment request link

#### 5.3 Send BTC
- Send flow with amount input, address, fee selection
- Fee estimation via `wallet.get-fees` (independent)
- Actual send via `wallet.send` (phone-required)
- Confirmation dialog with transaction details

#### 5.4 Transaction History
- Display transaction list via `wallet.get-history`
- Transaction detail view with txid, amount, confirmations

#### 5.5 Payment Requests
- Send/receive BTC payment requests in conversations
- Inline payment UI in message bubbles

**Key files to modify:**
- `src/lib/views/` — WalletView (already scaffolded)
- `src-tauri/src/commands/vault.rs` — Wallet operation commands

---

### Phase 6: Voice/Video Calling
**Goal**: WebRTC calls from desktop.

This is the largest phase and may require a Rust WebRTC library or Tauri plugin.

#### 6.1 WebRTC Integration
- Evaluate options:
  - `webrtc-rs` (pure Rust WebRTC): most aligned with architecture
  - Browser-based WebRTC in Tauri WebView: simpler but less control
  - Tauri plugin: check ecosystem for existing solutions
- Need: peer connection, audio/video tracks, ICE handling

#### 6.2 Call Signaling
- Same vault-routed signaling as Android
- Publish to target's vault: `call.initiate` with SDP offer
- Receive from own vault: `call.incoming`, `call.answer`, `call.candidate`
- Reference: Android's `CallSignalingClient.kt`

#### 6.3 Call UI
- Incoming call screen: Answer/Decline buttons, caller name, call type
- Outgoing call screen: Pulsing avatar, ring-back tone, Cancel/Mute/Speaker
- Active call screen: Duration timer, Mute/Speaker/Video/CameraSwitch/EndCall
- Reference: Android's `IncomingCallScreen.kt`, `OutgoingCallScreen.kt`, `ActiveCallScreen.kt`

#### 6.4 E2EE Frame Encryption
- Encrypt media frames with vault-derived shared secret (AES-128-GCM)
- Same pattern as Android's `CallFrameCryptor`
- Shared secret from vault's X25519 ECDH + HKDF

#### 6.5 Screen Sharing (Desktop-Specific)
- Desktop advantage: share screen/window during video calls
- Use WebRTC's `getDisplayMedia` equivalent
- Add share button to active call controls
- **macOS**: requires explicit Screen Recording permission (System Settings → Privacy & Security → Screen Recording). First attempt fails silently if the user hasn't granted; show an in-app guide that opens the relevant pane via `x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture`. Prefer ScreenCaptureKit (macOS 12.3+) over deprecated CGDisplayStream when the chosen WebRTC stack supports it.
- **Linux**: differs by display server. Wayland requires PipeWire + xdg-desktop-portal screen-cast; X11 uses `XCompositeNameWindowPixmap`. Detect at runtime via `XDG_SESSION_TYPE`.

#### 6.6 Camera & Microphone Permissions
- **macOS**: bundle Info.plist must declare `NSCameraUsageDescription` and `NSMicrophoneUsageDescription` (set via `tauri.conf.json` bundle config). First access triggers OS prompt; denial requires the user to flip the toggle in System Settings.
- **Linux**: PulseAudio/PipeWire handles mic with no OS prompt. Camera access via `/dev/video*` is governed by group membership (`video` group) — handle the `EACCES` case with a clear error message.
- Add a pre-call permission check that surfaces missing permissions before initiating the call rather than mid-handshake.

**Key files to create:**
- `src-tauri/src/webrtc/` — WebRTC client module
- `src/lib/views/` — Call screen components
- `src-tauri/src/nats/` — Call signaling handler

---

### Phase 7: Notifications & Background
**Goal**: Reliable notifications even when app window isn't focused.

#### 7.1 System Tray / Menu Bar
- Run in system tray (Linux) / menu bar (macOS) when window is closed
- Maintain NATS connection in background
- Tray icon with context menu: Open, Status, Quit
- Reference: Tauri v2 `TrayIconBuilder` API
- **macOS specifics**:
  - Use a *template image* (black + transparency, no color) so macOS auto-tints for light/dark menu bar
  - Hide the Dock icon when only running from menu bar by setting `LSUIElement = true` in Info.plist (or making it a runtime toggle in Settings)
  - Handle `RunEvent::Reopen` (Dock click after window close) to restore the window
  - `Cmd+W` should close the window without quitting the app; `Cmd+Q` quits
- **Linux specifics**:
  - On GNOME, `StatusNotifierItem` requires the AppIndicator extension; document the requirement or fall back to legacy XEmbed
  - On KDE / Wayland, native support is fine

#### 7.2 Desktop Notifications
- OS-native notifications via Tauri notification API
- Notification types: messages, calls, connection requests, security alerts
- Respect per-event-type notification policy (matching Android's `NotifyPolicy`)

#### 7.3 Notification Click
- Click notification → focus app window → navigate to relevant screen
- Pass event metadata (connection_id, event_type) to frontend for routing

#### 7.4 Badge Count
- Show unread count on system tray icon
- Clear on app focus or when user reads messages
- **macOS**: also set the Dock badge via `app.set_dock_badge()` (or the `tauri::AppHandle` equivalent) — this is the canonical Mac UX for unread counts and is more visible than the menu bar icon
- **Linux**: tray icon overlay only (Dock badges aren't a universal concept)

**Key files to modify:**
- `src-tauri/src/lib.rs` — System tray setup
- `src-tauri/src/nats/listener.rs` — Notification emission
- `src/App.svelte` — Notification click handling

---

### Phase 8: Settings & Security
**Goal**: Full settings management.

#### 8.1 Theme
- Light/dark/auto theme switching
- Persist preference locally

#### 8.2 Security
- Change passphrase (re-encrypt credentials)
- View session info (token TTL, capabilities)
- View device fingerprint info
- Lock/unlock controls

#### 8.3 Devices
- View connected devices list
- Revoke device access (phone-required)

#### 8.4 About
- App version, vault status
- Enclave info (PCR0, attestation status)
- Connection quality indicators

**Key files to modify:**
- `src/lib/views/SettingsView.svelte` — Settings UI
- `src-tauri/src/commands/` — Settings commands

---

### Phase 9: macOS Build, Packaging & Distribution
**Goal**: Ship a signed, notarized, Apple Silicon `.dmg` that installs cleanly on Macs running macOS 12+ (`aarch64` only — see Target Platforms above for the Intel decision).

This phase runs *in parallel* with the feature phases, not at the end. Get a basic dev build running on macOS as soon as Phase 1 is in flight; come back to signing/notarization once the app is feature-complete enough to share with testers.

#### 9.1 Bring-up: dev build on macOS
- Verify `cargo tauri dev` runs end-to-end on Apple Silicon
- Validate the `platform_macos.rs` fingerprint produces ≥3 attributes on a real Mac (fix the `disk_serial` collector — currently parses "Media Name" instead of the actual serial; should match on `"Volume UUID"` or `"Disk / Partition UUID"` line from `diskutil info disk0`)
- Validate the credential store path under `~/Library/Application Support/com.vettid.desktop/`
- Confirm NATS connection survives Sleep/Wake transitions (Power Nap wake delivers a different network state than Linux suspend/resume)

#### 9.2 Bundle configuration
Update `tauri.conf.json` `bundle` section:
- `targets`: `["app", "dmg"]` for macOS, `["appimage", "deb"]` for Linux
- `macOS.minimumSystemVersion`: `"12.0"` (covers ScreenCaptureKit + reasonable adoption)
- `macOS.frameworks`: any required system frameworks (likely none for Phases 1–5; AVFoundation for Phase 6)
- `macOS.entitlements`: path to `entitlements.plist` (see 9.4)
- `macOS.signingIdentity`: `"Developer ID Application: <Team Name> (<Team ID>)"` — read from CI secret, not committed
- `icon`: include `.icns` alongside the existing `.png`/`.ico` set; generate from a 1024×1024 master via `iconutil`
- Bundle identifier already correct: `com.vettid.desktop`

#### 9.3 Info.plist additions
Tauri generates the Info.plist at build time. Required keys (declared via `bundle.macOS.infoPlist`):
- `NSCameraUsageDescription` — "VettID uses your camera for video calls."
- `NSMicrophoneUsageDescription` — "VettID uses your microphone for voice and video calls."
- `NSScreenCaptureUsageDescription` — "VettID uses screen recording for sharing your screen during calls."
- `LSMinimumSystemVersion` — `"12.0"`
- `LSUIElement` — `false` for v1; consider `true` toggle in Settings for "menu-bar-only mode"
- `NSAppTransportSecurity` — only relax if absolutely required; default is fine since vault traffic is over WSS

#### 9.4 Entitlements
Create `src-tauri/entitlements.plist`:
- `com.apple.security.app-sandbox`: `false` initially (sandboxing will require careful work around the credential store, IOKit access for fingerprinting, and screen-capture). Plan to enable in a follow-up phase.
- Hardened Runtime entitlements (required for notarization):
  - `com.apple.security.cs.allow-jit`: `true` (WebKit JIT)
  - `com.apple.security.cs.allow-unsigned-executable-memory`: `true` (Tauri webview)
  - `com.apple.security.device.audio-input`: `true`
  - `com.apple.security.device.camera`: `true`
  - `com.apple.security.network.client`: `true`

#### 9.5 Single-arch build (Apple Silicon)
- Build for `aarch64-apple-darwin` only: `cargo tauri build --target aarch64-apple-darwin`
- No `lipo` step, no x86_64 toolchain needed in CI
- If Intel demand emerges, switch the target to `universal-apple-darwin` (Tauri handles `lipo` internally) and re-cut the release

#### 9.6 Code signing
- Apple Developer Program enrollment required (~$99/yr) — out of scope for this plan but a prerequisite for distribution
- Developer ID Application certificate installed in CI keychain (or use Keychain Access locally)
- Sign with `--options runtime` for Hardened Runtime
- Tauri does this automatically when `signingIdentity` is set in config

#### 9.7 Notarization
- Submit signed `.dmg` to Apple's notary service via `notarytool` (replaces deprecated `altool`)
- Requires App Store Connect API key (separate from Developer ID cert)
- Staple ticket back to the .dmg with `xcrun stapler staple`
- Verify with `spctl -a -t open --context context:primary-signature -v <path>`
- CI: store API key, key ID, and issuer ID as encrypted secrets

#### 9.8 Auto-update (optional, defer to v1.1)
- `tauri-plugin-updater` with signed update artifacts
- Hosting: GitHub Releases or self-hosted endpoint
- macOS signature verification is mandatory per Apple's requirements

#### 9.9 Distribution
- v0: GitHub Releases — direct .dmg download, users manually re-download for updates
- v1: signed updater feed pointing at GitHub Releases
- v2 (deferred): Mac App Store (requires sandboxing — major rework around fingerprinting and credential storage)

**Key files to create/modify:**
- `src-tauri/tauri.conf.json` — bundle.macOS section, target list, icon list
- `src-tauri/entitlements.plist` (new)
- `src-tauri/icons/icon.icns` (new — generate from existing icon set)
- `.github/workflows/release.yml` (new) — matrix build for Linux + macOS, signing, notarization
- `src-tauri/src/fingerprint/platform_macos.rs` — fix `collect_disk_serial`

---

## Priority & Ship Order

**Recommended order**: Phase 1 → 2 → 3 → 7 → 4 → 5 → 6 → 8

Phases 1-3 + 7 produce a **useful daily-driver**: real-time events, connections, messaging with notifications — covering 80% of daily use cases. Wallet and calling can follow.

**Phase 9 (macOS packaging) runs in parallel.** Sub-phase 9.1 (dev bring-up + fingerprint fix) should happen alongside Phase 1 — there's no value in writing the rest of the app if it doesn't run on macOS at all. Sub-phases 9.2–9.7 (signing/notarization) can wait until just before the first external release.

## Key Reference Files (Android)

| Android File | Desktop Equivalent | Purpose |
|---|---|---|
| `core/nats/OwnerSpaceClient.kt` | `src-tauri/src/nats/listener.rs` | NATS event routing |
| `features/feed/FeedViewModel.kt` | `src/lib/stores/vault.ts` | Feed state management |
| `features/feed/FeedScreen.kt` | `src/lib/views/VaultView.svelte` | Feed UI |
| `features/messaging/ConversationViewModel.kt` | New store needed | Message state |
| `features/messaging/ConversationScreen.kt` | New view needed | Conversation UI |
| `features/calling/CallManager.kt` | `src-tauri/src/webrtc/` (new) | Call lifecycle |
| `core/nats/CallSignalingClient.kt` | Extension to nats module | Call signaling |
| `features/feed/FeedNotificationService.kt` | `src-tauri/src/nats/listener.rs` | Notification routing |

## NATS Architecture Notes

- The vault publishes push notifications via **both** core NATS and JetStream
- Push notification subjects use `.forApp.{eventType}` pattern
- The desktop should subscribe to `OwnerSpace.{ownerGuid}.forApp.>` for all push events
- Use `contains()` matching for subjects (handles `.response` suffix from JetStream)
- Request-response uses JetStream ephemeral consumers on Android, but desktop's current basic pub/sub with timeouts may be sufficient for delegated operations
- Call signaling goes through target user's vault (publish to `OwnerSpace.{targetGuid}.forVault.call.initiate`)

## Testing Strategy

1. **Phase 1**: Verify real-time message delivery by sending from Android → desktop receives
2. **Phase 2**: Verify connection list matches what Android shows
3. **Phase 3**: Send messages bidirectionally (Android ↔ Desktop), verify read receipts
4. **Phase 7**: Verify desktop notifications when app is in system tray
5. **Phase 6**: Make a call from Android → Desktop answers

## Security Considerations

- Desktop NEVER holds the vault master key — all sensitive operations delegated through phone
- Connection key (derived via X25519 ECDH) encrypts all NATS messages
- Credential storage uses Argon2id + platform key binding
- Phone approval required for all write operations
- Frame encryption for calls uses vault-derived shared secrets
