# VettID Desktop — Rework Plan

Supersedes the relevant sections of `DEVELOPMENT-PLAN.md` (which is
oriented around the old 8-character pairing flow and a feature-parity
checklist). The post-Stage-2 pairing flow is solid; this plan focuses
on the information architecture, simplifying the credential model, and
sequencing the build-out of the Vault + Connections surfaces.

## Goals

1. **Simpler mental model.** The desktop has four user-facing concerns
   — session lifecycle, vault data, peer connections, and settings.
   Each gets one obvious home; the nav doesn't expose internal plumbing.
2. **No on-device data hoarding.** Nothing sensitive on disk between
   sessions. The vault remains the single source of truth.
3. **Passwordless onboarding** (recommended, see §4). The phone is
   already the security factor; a separate passphrase is friction
   without a load-bearing protection benefit.
4. **Feature reach matching the Android app** for the surfaces a
   keyboard-and-screen user actually wants: vault management +
   peer connections + messaging/calls.
5. **One user per install.** The desktop binds to one vault; switching
   accounts means "remove this desktop, pair fresh."

## Non-goals (this plan)

- Multi-account / account switcher. Out of scope.
- Mobile-style biometric unlock. Defer until we know the OS APIs we
  need (TouchID on macOS, fprintd on Linux); not on the critical path.
- WebRTC calls in the first pass. Listed in §6 as a later phase — the
  signalling/TURN work was already done for the Android app but
  porting the audio/video pipeline is its own slice.
- Windows. macOS + Linux only (mirrors current scope).

---

## 1. Information architecture

```
┌──────────────────────────────────────────────────────────────────┐
│ ◆ VettID    Session: active 4h 23m · Phone reachable     ⚙       │
├────────┬─────────────────────────────────────────────────────────┤
│        │                                                          │
│ Vault  │  (main content)                                          │
│ Conn-  │                                                          │
│ ections│                                                          │
│        │                                                          │
│        │                                                          │
└────────┴─────────────────────────────────────────────────────────┘
```

- **Top bar**: brand on the left; session status pill in the middle
  ("Inactive" / "Active 4h 23m" / "Expired — start new session" /
  "Phone unreachable" with a color-coded dot); settings gear on the
  right.
- **Left nav** (rail, not labeled buttons): two destinations — Vault
  and Connections. Only enabled when a session is active.
- **Modal/overlay**: pairing + new-session flow appears as a full-
  screen takeover, not a nav destination. This matches the user's
  intuition: starting a session is a one-shot action, not a place
  you live.
- **Settings**: opens from the gear icon as a routed page (back arrow
  to return), not a sidebar. Contains device details, theme picker,
  about, and an Advanced section (raw NATS state, etc.).

### Why a session pill in the top bar rather than a dedicated nav item

The current nav exposes Pair Device, Vault, Session, Settings as four
sibling buttons. Pair + Session are really the same concern
("am I connected and how?") and the user shouldn't have to navigate
to a dedicated screen to see status — it's a constant ambient signal.
A pill in the top bar keeps it visible from any view; the takeover
flows handle the "do something about it" cases.

### Session pill states + actions

| State | Pill text | Click action |
|---|---|---|
| Not paired | `Pair a device` | Open Pairing takeover |
| Locked (paired, no active session) | `Start a new session` | Open Start-Session takeover (passphrase or biometric if §4 lands) |
| Active | `Active · 4h 23m` | Open Session menu: Extend, End now, View detail |
| Expiring soon (< 5min) | `Expiring · 4m 12s` | Same as Active, but pill turns amber |
| Expired | `Session expired — start new session` | Open Start-Session takeover |
| Phone unreachable | overlay on the active pill: `Phone offline` | Open Session menu + phone-status detail |

---

## 2. Vault section

Mirror the Android Vault home: a single screen with profile preview
on top + tiles/sections underneath for the four data domains.

```
┌──────────────────────────────────────────────────────────────────┐
│ [photo] Al Liebl                                                  │
│         al@liebl.me                                               │
│         Linux desktop · paired since 2026-05-17                   │
├──────────────────────────────────────────────────────────────────┤
│ Personal data  >    │  Secrets  >        │  Wallets  >           │
│ Name, contact,      │  PIN, critical     │  BTC: 0.0012          │
│ family, address...  │  credentials...    │  Testnet              │
└──────────────────────────────────────────────────────────────────┘
```

Each tile expands into a detail view (existing scaffolds —
`PersonalDataView`, `SecretsView`, `WalletView` — get wired to live
data). The detail views follow the Android patterns: list + add/edit
+ catalog visibility toggles for personal data; reveal-with-password
+ visibility toggles for secrets; balance + send/request + history
for wallet.

**Phone-required operations** (secret retrieval, BTC sign, profile
publish, etc.) trigger a "Approve on phone" overlay — the desktop
publishes the op, the phone gets a notification, user approves, the
desktop unblocks. Matches the current pattern; we just need to wire
it consistently across all phone-required ops.

---

## 3. Connections section

Mirror the Android Feed/Connections list:

```
┌────────────────────────────────────────────────────────┐
│ [Search…]                                  [+ Invite]  │
├────────────────────────────────────────────────────────┤
│ [photo] Mesmer                                          │
│         Last activity · 2h ago                          │
│         [Message] [Call] [Video]                        │
├────────────────────────────────────────────────────────┤
│ [photo] Bob                                             │
│         You: thanks!                                    │
│         [Message] [Call] [Video]                        │
└────────────────────────────────────────────────────────┘
```

Tap a row → connection detail (peer profile + interaction history +
shared-data grants).
Tap Message → conversation view (`Conversation.svelte` already
scaffolded; wire it to `messages.list` / `connection.send-message`).
Tap Call/Video → WebRTC bridge (phase later; show a "coming soon"
toast in the first cut).

Notably: connection cards on desktop don't need the same status
variants as Android (no `pending_review` UX because invitations on
desktop are minimal). Pending invitations and review can live on a
secondary tab inside Connections.

---

## 4. Credential model — passwordless

**Current:** at pairing time the user picks a passphrase. The
on-disk credential blob (`connection.enc`) is encrypted with
Argon2id(passphrase + platform_key). Every launch requires the
passphrase to unlock.

**Proposed:** drop the passphrase entirely. Bind the on-disk blob to
a key held in the OS keyring (Linux: Secret Service via
`secret-service` crate; macOS: Keychain via `security-framework`),
which is itself unlocked by the user's OS login session.

### Why this is safe

The desktop has never been a primary security boundary in VettID's
threat model — the phone is. Every privileged vault operation
already requires phone authorization. The passphrase only protects
the on-disk credential blob, and the credential blob doesn't grant
access to user data on its own: it grants the ability to publish
`device.request-session` on this desktop's scoped NATS subjects.
That request still has to be authorized by the phone (QR scan) to
become a working session.

Threat model summary:

| Attacker capability | With passphrase | Passwordless via OS keyring |
|---|---|---|
| Steals disk image, can't run as user | Can't decrypt blob (Argon2id) | Can't decrypt blob (keyring key never reaches disk in plaintext) |
| Steals disk + user account password | Could brute-force passphrase offline | Can decrypt (had OS access anyway) |
| Has shell as the user, session unlocked | Reads in-memory session key | Same |
| Has shell as the user, vault locked | Can read encrypted blob, can't decrypt without passphrase | Can read keyring entries (user-level access) |
| Has phone access | Can authorize as user (regardless of desktop state) | Same |

The only attack the passphrase materially defends against is "I
stole the laptop AND I have the user's login password." That's a
narrow window — and if the attacker has both, they almost certainly
have access to other things (browser saved passwords, email
sessions, SSH keys). The phone-authorization gate still protects
the vault itself.

### What we still persist

Minimum needed to make extend-session work on the next launch:
- `connection_id` (low-sensitivity identifier)
- Scoped NATS JWT + seed (long-lived, but scoped to this desktop's
  MessageSpace; useless without phone authorizing a session)
- Owner GUID (so we know which MessageSpace to subscribe on)

Nothing else. No session key (ephemeral), no user data cache, no
profile cache (refetched from vault on session start).

### What this changes in the flow

- **Pair Desktop**: user enters 12-char code → desktop resolves
  invite → phone QR appears → user scans + approves → done. No
  passphrase prompt.
- **Launch (locked)**: desktop reads connection_id + scoped creds
  from disk (decrypted with keyring-held key, auto via OS auth) →
  publishes request-session → phone notification → user
  approves on phone → desktop derives session key in memory →
  Vault view.
- **End session**: desktop publishes end-session, locally wipes
  session key. Persisted creds untouched.
- **Remove desktop**: desktop publishes revoke, locally wipes both
  session key AND persisted creds.

### Open decision: fallback for systems without keyring

Some Linux desktops (e.g., kiosk-mode setups, fresh GNOME installs
without a keyring daemon) won't have Secret Service available. Two
options:
1. **Refuse to install/pair if no keyring** — keeps the security
   model uniform, but excludes some users.
2. **Fall back to a machine-bound key** — derive an encryption key
   from the machine fingerprint (same approach as the current
   `platform_key`) without a user passphrase. Slightly weaker
   (attacker who can read the disk image of a running system can
   re-derive), but matches the current `platform_key`-only mode
   that already exists in the codebase.

Recommend option 2 as the fallback, with a one-time prompt at
pairing that says "we couldn't reach your keyring; we'll bind to
this machine instead." That's the same posture macOS Keychain
takes when it can't unlock.

---

## 5. On-device storage policy

Stronger version of the existing CLAUDE.md `no user data on device`
principle, applied to the desktop:

**Persisted to disk (encrypted with keyring/machine-bound key)**:
- `connection.enc` — the credential blob (connection_id, scoped
  NATS creds, owner_guid, fingerprint binding)
- Theme preference (`localStorage` is fine; non-sensitive)

**Never persisted to disk**:
- Session keys
- User profile data (refetched on session start)
- Connection peer profiles (refetched)
- Personal data values
- Secret values
- Wallet balances / transaction history (refetched)
- Message content

**In-memory only, zeroized on lock/exit**:
- Session key
- Decrypted connection key
- Cached vault responses (kept until session ends or app closes)

**Webview caches**: explicitly disabled. The Tauri webview defaults
to caching network responses; we'll override with a strict CSP and
`Cache-Control: no-store` on every vault response so the WebKit
cache layer doesn't accidentally retain anything.

The vault can hold a per-desktop encryption key if we ever need
something stronger than keyring (it would require a small chicken-
and-egg fix on bootstrapping — fetch the key on the first request-
session after pairing). Not needed for the first pass.

---

## 6. Phased delivery

Each phase ends with a shippable build. Phase 1 is the credential
model (lowest risk, biggest UX win); Phase 2 is the chrome (top bar
+ settings); Phase 3+ wire the data sections.

### Phase 1 — Passwordless onboarding + storage cleanup (~1 week)

- Add `keyring`-based encryption-key store
  (`secret-service` / `security-framework`); fallback to machine-
  bound key when keyring unavailable
- Drop passphrase from the pairing UI + unlock flow
- Remove `passphrase` param from `register`, `unlock`, `end_session`,
  `extend_session`, `logout` Tauri commands; replace internal
  Argon2id-with-passphrase derivation with keyring-fetched key
- Verify nothing else lands on disk: audit `store::default_config_dir`
  and the WebKit cache directory
- Migration: existing installs prompt once for passphrase, decrypt
  with old method, re-encrypt with keyring, never prompt again

**Acceptance:** fresh install pairs without a passphrase prompt;
relaunch goes straight to the Start-New-Session takeover (which is
just "tap Start, phone shows QR" with no passphrase field).

### Phase 2 — Top bar + settings restructure (~3 days)

- Replace the left nav's Pair Device + Session entries with a top-
  bar session pill (states per §1 table)
- Move Settings to a gear icon at the top right; convert the
  Settings page to sub-pages (Device, Theme, Network/Advanced,
  About)
- Active session enables Vault + Connections rail items; inactive
  session disables them
- Pairing + Start-New-Session become full-screen takeovers triggered
  by the pill, not nav destinations

**Acceptance:** chrome matches §1 mockup; session status is visible
from every view; nav is uncluttered.

### Phase 3 — Vault home + Personal Data (~1 week)

- Wire `Vault.svelte` to show profile header (photo, name, email,
  paired-on date)
- Wire `PersonalDataView` (already scaffolded) against the existing
  `personal_data.list` / `.add` / `.update` ops; mirror the Android
  catalog + alias + category UX
- Phone-approval overlay component (reusable for any phone-gated op)

**Acceptance:** user can view + edit their personal data from the
desktop, with phone approval where the Android app already requires it.

### Phase 4 — Secrets + Wallet (~1 week)

- Wire `SecretsView` against `credential.secret.list`, with the same
  visibility-segmented control as Android
- Critical-secret reveal flow (password gate matching Android's
  `CriticalSecretsScreen`)
- Wire `WalletView` against `wallet.list` / balance / send / receive;
  reuse the BTC send/receive sheets the Android app shipped
- Hide both sections from the rail if the vault doesn't advertise
  them (graceful degradation)

**Acceptance:** parity with Android's vault management for secrets +
wallet, minus mobile-specific affordances (biometric reveal, etc.).

### Phase 5 — Connections + Messaging (~1.5 weeks)

- Connection list with the same status variants as Android
  (Active / Pending / Outstanding invitation)
- Connection detail screen (peer profile + interaction history +
  grants)
- Conversation view wired against `messages.list` /
  `connection.send-message` (E2E encryption via the existing
  session-key derivation)
- Invitation flow: create QR + copy link (no scan-from-desktop — let
  the phone scan)

**Acceptance:** can chat with a peer end-to-end from desktop, with
read receipts and delivery state matching Android.

### Phase 6 — Voice + Video calls (~1.5 weeks, optional first pass)

- WebRTC peer-connection bridge; reuse the signalling subjects from
  Android
- TURN integration (already deployed); local audio via cpal,
  encoding via libopus (the `webrtc` Cargo feature already
  scaffolded)
- Incoming call overlay (rings, accept/decline)

**Acceptance:** can make and receive 1:1 audio + video calls.

### Phase 7 — Polish (~3 days)

- Notification handling (system tray + desktop notifications)
- Background mode (system tray icon stays alive after window close)
- Keyboard shortcuts for common actions (Cmd+, for settings,
  Cmd+1/2 for Vault/Connections, etc.)
- Final accessibility pass (focus rings, screen-reader labels)

---

## 7. Decisions (locked 2026-05-18)

1. **Keyring fallback** → option 2. When the OS keyring is
   unavailable, fall back to a machine-bound key derived from
   `platform_key` (no user passphrase). One-time inline warning at
   pairing: "Couldn't reach your keyring — binding to this machine
   instead. Disk-only theft is still safe; user-account compromise
   would be enough to decrypt."
2. **Migration** → skip. No real users yet. On first launch with
   the new build the existing `connection.enc` is wiped and the
   user re-pairs. Transitional code stays out of the codebase.
3. **Tray on window-close** → keep current behavior (window hides,
   tray icon stays alive). The new credential model still benefits
   from a long-running process so the user doesn't have to re-
   authorize every time they tab away.
4. **Single-user enforcement** → prompt + require explicit removal.
   If a pairing attempt comes in while creds already exist on disk,
   show "This desktop is already paired with [owner_guid]. Remove
   the existing pairing first?" with Remove + Cancel buttons. No
   silent overwrite.
5. **Distros without a keyring daemon** → same as #1. Resolved by
   the machine-bound fallback. Minimal Linux setups (kiosks,
   GrapheneOS-style) work without extra packaging.

---

## 8. Things this plan explicitly inherits as-is

The post-Stage-2 pairing flow we just shipped works well — these
parts of the existing stack stay:

- Two-stage pairing protocol (12-char code → bootstrap → Stage-2
  request-session → phone authorize)
- TLS-first NATS connect against the NLB
- Soft `device.end-session` (server-side session-key wipe without
  revoking the pairing)
- `device.revoke` for full retirement
- Existing async-nats client + resilience options
- Existing crypto stack (X25519 / XChaCha20-Poly1305 / HKDF /
  Argon2id — the latter only on the vault side now that desktop
  goes passphraseless)
- Settings → Network raw NATS state for debugging
- Light/dark/auto theme support

What the rework *replaces*:
- Passphrase-based credential store → keyring-bound
- Pair Device + Session as nav siblings → top-bar pill + takeover
- Settings in nav → gear icon
- Vault placeholder screen → real Vault home with sub-pages
