# VettID Desktop — Rework Plan

> **Note (2026-11-03):** NATS is retired in this desktop. It reaches its vault through the
> relay with `src-tauri/crates/vettid-device` (vettid-desktop#64). The NATS details below are
> history; this plan has not been rewritten.

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
│ [photo] <owner name>                                              │
│         <owner email>                                             │
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
│ [Search…]                                              │
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

Notably: the desktop never *creates* an invitation — that flow stays
on the phone (§7 decision #6). The connection list still surfaces an
"Outstanding invitation" status for invitations the user sent from
their phone, since that state is read straight from vault data; the
desktop just renders it. No "+ Invite" affordance, no QR generation.

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

> **Superseded (2026-11-04, #13).** The machine-bound fallback is
> retired (owner decision, desktop V6 plan): see "At-rest protectors"
> below. Kept above as history.

### At-rest protectors (AG3, #13; proposed 2026-11-04, needs the owner's approval)

The desktop follows the agent's AG3 design (AGENT-PLAN §4.2), with the
deviations marked below.

**Format.**
- **The file:** one state file, `device.enc`, holding the device engine's `DeviceState`: its seeds, the vault record, tokens and the session keyring.
- **Encryption:** it is sealed with XChaCha20-Poly1305 under a **random 256-bit data key**. The data key is **wrapped by a platform protector** and kept, wrapped, in the file's header.
- **The header:** `{v, protector, wrapped_key, nonce, created_at}`. The passphrase protector adds the Argon2id salt and parameters, so the parameters can be raised later.
- **Associated data:** the header bytes plus the label `vettid-desktop-device-v1`.
- **When a key is made:** a new data key at each pairing.
- **The file itself:** written to a temporary file, synced and renamed. It keeps the owner-only permissions checked at load: the DACL on Windows, 0700 for the folder and 0600 for the file elsewhere.

**Dropped:**
- the machine-attribute key (`platform_key`, the "machine-bound" mode), because it is an HMAC of values any local process can read, so it adds obscurity, not a secret;
- the #14 storage binding (a machine-id HMAC) from the associated data, so a machine without a readable machine id can pair.

**Why move off the keyring.**
- **macOS:** today the data key is the OS keyring's master key. The `keyring` crate uses the file-based login keychain, which doesn't support `ThisDeviceOnly`, and its items travel with Time Machine and Migration Assistant.
- **Linux:** a Secret Service collection opens on another machine given the keyring file and its login password.
- **Wiping:** the keyring entry lives apart from the file, so a wipe has two parts to get right.

**Protectors, best first:**

| Platform | Protector | What it binds to, and who can still open it |
|---|---|---|
| Windows | **DPAPI, user scope**: `CryptProtectData` with `CRYPTPROTECT_UI_FORBIDDEN` and an app-specific entropy label. `CRYPTPROTECT_LOCAL_MACHINE` is **not** set. It replaces today's Credential Manager entry (`wincred.rs`), which is DPAPI underneath but a second object to wipe. | A copy of the state file alone doesn't open elsewhere. A copy of the whole profile (the DPAPI master keys are under `%APPDATA%\Microsoft\Protect`) **plus the user's password** does. Any process running as this user can unwrap; the entropy label is domain separation, not a secret. An administrator can unwrap by running code as the user, or from LSASS, while the user is logged on. That is out of scope, and the README says so. A **domain account** or **roaming profile** gets a notice, not a refusal (AGENT-PLAN §4.2, 2026-10-18). A check that fails gives no notice, so no notice is not a guarantee. (`device.enc` is in `%LOCALAPPDATA%`, which doesn't roam.) |
| macOS | **Data protection keychain** item, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, not synchronizable. It needs a `keychain-access-groups` entitlement, so only the **signed app bundle** (the owner's App ID and provisioning profile) can use it. | This device only. Without the entitlement (an unsigned or ad-hoc build), the keychain is *absent* and the next protector is used, with the reason shown. |
| Linux | **TPM 2.0** through `/dev/tpmrm0`: the data key sealed under a primary key in the storage hierarchy, with **no PCR policy** (so firmware and kernel updates don't lock the person out) and no authValue. Built on `tss-esapi`, which needs `libtss2` as a package dependency. | This TPM only. Root, or any user who can read the file and use the TPM, can unseal. Clearing the TPM loses the state: a load failure, so re-pair. Many distributions give `/dev/tpmrm0` to `root:tss` only, so an ordinary user often has no TPM. |
| Linux, no TPM | **Secret Service** (GNOME Keyring or KWallet). **A deviation from AG3**, which has no such step; owner's choice (b) below. | It opens on another machine given the keyring file and its login password. It doesn't meet LEASH §3.4's "copying … MUST render them undecryptable". Settings says "not bound to this computer". |
| Any, none of the above | **Passphrase**: Argon2id at least at VAULT-MESSAGING §4.1's password parameters, with §1's strength rules applied at pairing. Asked at each launch. Owner's choice (c) below. | It opens anywhere with the passphrase. It doesn't meet LEASH §3.4, and Settings says "not bound to this computer". The passphrase is zeroized in Rust and never logged (it crosses IPC as a webview string that can't be zeroized). Wrong entries get a growing delay. A forgotten passphrase means re-pairing; there is no recovery. |

**Rules:**
- **Absent and failing are different.** At pairing the desktop moves to the next protector only when the better one is *absent*: no device, no entitlement, no service. That is detected, never inferred from an error. A protector that is present but fails (DPAPI error, TPM busy, keychain locked) **stops the pairing with the reason**.
- **No silent downgrade.** At load, a file whose protector ranks below the best one available here opens only after a notice saying so, and Settings keeps showing it. A file is never re-sealed to a weaker protector. A protector that fails at load keeps the file, says why, and offers a re-pair; it never falls back on its own.
- **Migration: none** (decision #2 stands).
  - **What is deleted:** a `device.enc` in today's keyring-sealed format is deleted unread, and so is the old `master-key-v1` keyring or Credential Manager entry.
  - **Re-pairing:** the person re-pairs, with a notice.
  - **Reporting:** a deletion is reported only once it is confirmed.
  - **The legacy file:** `connection.enc` stays removed unread, as today.
- **Wipe** (log out, `device.unlinked`):
  - **What goes:** the file and its temporary copies, plus the protector's key where it keeps one (the keychain item) and any legacy `master-key-v1` entry. DPAPI and the TPM keep nothing outside the file.
  - **No overwrite:** AG3's "overwrite" step is dropped, since overwriting is not reliable on SSDs or journalled file systems.
  - **Confirmed, or "not removed":** each part is confirmed gone (`confirm_gone`). A part that can't be confirmed is reported as "not removed" and retried, never reported as done on a guess.
  - **Old copies:** as in AGENT-PLAN §4.2, an old copy of the file recovered from a backup or the raw disk can still be opened on the same computer by the same user (DPAPI, TPM). That is accepted for v1, and the README says so.
- **Status:** Settings shows the protector in use and whether the state is bound to this computer.
- **No weaker test modes in member builds.**
  - **Test protectors** (fixed keys, the `swtpm` wiring) are `#[cfg(test)]` only. No build flag or environment variable selects a weaker protector in a build a member could run.
  - **Logging:** a protector's error is logged by its code, never with key bytes or the passphrase.

**Owner's choices:**
- **(b) Secret Service on Linux without a TPM.**
  - *Keep (recommended):* most Linux desktops have a keyring but no TPM the user can reach. Without this step, they would go straight to a passphrase at every launch.
  - *Drop:* restores AG3 exactly.
- **(c) When no protector binds to this computer.**
  - *Passphrase (recommended):* as AG3.
  - *Refuse to pair:* keeps the desktop passwordless (§4). But then no macOS desktop can pair until the signed build exists, and, with (b) dropped, no Linux desktop without TPM access can either.

**Done** (task 01M6EFHHANEEVAMCKH3WT7JM71):
- **Round trips:** DPAPI (on the Windows test machine), TPM (against `swtpm` in CI, if CI has it; otherwise on a Linux machine) and the passphrase.
- **Copy refusal:**
  - DPAPI: tested as a second Windows user, and on a second VM if one is available. The second user stands in for "another machine"; the README says so.
  - TPM: tested with a second `swtpm` instance.
- **Removed:** the machine-bound code and the #14 binding.
- **Not done in this task; follow-up tasks, listed as open:**
  - the macOS keychain round trip, which needs the owner's signed build (until then macOS uses the next protector);
  - the Secret Service check, if (b) is kept.

Built in that order: Windows first (it can be tested here), then Linux, then macOS.

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

Section-visibility gating was dropped — see §7 decision #7. Every
user vault carries all three sections; the empty states handle
"nothing here yet" gracefully on their own.

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

Connection *creation* (sending an invitation) is intentionally
phone-only — see §7 decision #6. The desktop manages and converses
with connections; it does not originate them.

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
   *Superseded (2026-11-04, #13): the machine-bound key is retired;
   see §4 "At-rest protectors".*
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
   *Superseded (2026-11-04, #13): see §4 "At-rest protectors".*
6. **Outbound invitations** (added 2026-05-22) → cut from the
   desktop. Creating a connection (generate invite code → QR →
   share) stays phone-only; the desktop manages and converses with
   connections but never originates them. This drops the former
   Phase 5 "Invitation flow" item entirely — no "+ Invite" button,
   no QR generation, no `connection.create` wiring on the desktop.
7. **Section-visibility gating** (added 2026-05-22) → dropped from
   Phase 4. The plan assumed the vault "advertises" which sections
   it supports, but `vault.snapshot` carries no capability signal
   and every user vault has the Personal-data / Secrets / Wallets
   subsystems built in — there is no vault that lacks one. The
   per-section empty states ("No wallets yet — create one from the
   VettID app on your phone") already provide graceful degradation;
   hiding a tab on a zero count would only remove that guidance.

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
