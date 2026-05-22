# Desktop Connections Rework Plan

Bring the vettid-desktop Connections surface in line with the Android app's
Connections experience. Created 2026-05-22 after a screen-by-screen audit of
both clients.

## Decisions locked

- **Layout:** two-pane master-detail — connections list always visible on the
  left, the selected connection's workspace on the right.
- **Scope (this plan):** Phases **A, B, D**. Phases C and E are deferred to a
  follow-up plan.
- **Out of scope:** functional voice/video media (tracked separately as
  Phase 6 — TURN + SFrame cryptor); connection creation / invitations
  (phone-only — desktop-rework item 20 was cut); sharing the desktop's *own*
  location (no GPS on desktop).

## Why this is mostly display work

`connection.list` (vault `ConnectionInfo`, `enclave/vault-manager/connections.go`)
already returns `unread_count`, `last_message_preview`, `last_activity_*`,
`peer_profile`, `connection_type`, `peer_verifications`, `is_favorite`, etc.
The Rust `list_connections` command passes the payload through verbatim — the
desktop simply discards most of it. Phase A is therefore pure frontend.

> Caution: the desktop `Connection` type drifted badly from `ConnectionInfo`
> (a missing-field `TypeError` was the cause of the Connections-tab freeze
> fixed in this same session). Extend the type carefully and field-by-field
> against `ConnectionInfo` in `connections.go`.

## Architecture — two-pane shell

`Connections.svelte` becomes a two-pane layout:

- **Left pane** (fixed ~320px): `ConnectionsList` — always mounted, so opening
  a connection no longer remounts/refetches the list.
- **Right pane** (flex): `ConnectionWorkspace` when a connection is selected,
  otherwise an empty state ("Select a connection").

`ConnectionWorkspace.svelte` (new): a persistent header (avatar, name, status
chip, verified badge, quick actions: Message / Voice / Video) plus a body with
a **Messages | Profile** segmented toggle. Default body = Messages.
`selectedConnectionStore` remains the single source of truth for selection.

---

## Phase A — List redesign (pure frontend)

Files: `src/lib/types.ts`, `src/lib/views/vault/ConnectionsList.svelte`
(rewrite), new `src/lib/components/Avatar.svelte`, new
`src/lib/components/StatusChip.svelte`, `src/lib/stores/vault.ts`.

- **A1.** Extend the `Connection` type with the fields `connection.list` already
  returns: `unread_count`, `last_message_preview`, `last_message_at`,
  `last_message_direction`, `last_activity_at`, `last_activity_title`,
  `last_activity_type`, `connection_type`, `peer_verifications`,
  `needs_attention`, `is_favorite`, `is_archived`.
- **A2.** `Avatar.svelte` — base64 photo or initials on a deterministic color;
  sizes for list (40px) / hero (72px) / header (36px). Reused by detail.
- **A3.** `StatusChip.svelte` — icon + color per status (active/pending/
  revoked/expired). Reused by detail.
- **A4.** Connection card: avatar + name + subtitle (last-message preview, else
  last-activity relative time, else "Connected {date}") + unread badge (red
  pill, 99+ cap) + status chip + connection-type icon (peer/agent/device).
- **A5.** Search input — client-side filter on display name.
- **A6.** Sort control — Recent activity / Alphabetical / Connection date;
  default Recent, with unread connections floated to the top (matches Android).
- **A7.** Empty state — icon + "No connections yet" + hint that connections are
  created from the phone.
- **A8.** Selected-card highlight (drives the two-pane selection in Phase B).
- **A9.** Wire `initVaultListeners` (currently defined but never called) so
  connection/message push events refresh the list live — fixes a known latent
  bug where new messages don't bump unread counts.

No backend changes. Verify: rich cards render; list updates live on a new
message; search + sort work.

---

## Phase B — Detail screen + two-pane shell

Files: `Connections.svelte` (two-pane rewrite), new `ConnectionWorkspace.svelte`,
`ConnectionDetail.svelte` (redesign), `src-tauri/src/commands/vault.rs` +
`src-tauri/src/lib.rs` (new commands).

- **B1.** Two-pane layout in `Connections.svelte`; left = `ConnectionsList`,
  right = `ConnectionWorkspace` / empty state.
- **B2.** `ConnectionWorkspace.svelte` — header + Messages/Profile body toggle.
- **B3.** `ConnectionDetail` redesign:
  - Hero: avatar (72px), name, status chip, verified badge, presence dot,
    profile-content badge counts (handlers / secrets / data) if available.
  - Them/You tab scaffold:
    - **Them:** peer profile fields. (Their-catalog row left as a Phase C slot.)
    - **You:** connection metadata (id, type, created, e2e key) + Manage.
- **B4.** Manage actions: Revoke (exists), **Rotate keys** (new), **Verify
  identity** (new) — with in-flight / verified / failed result states.
- **B5.** New Rust commands in `commands/vault.rs`, registered in `lib.rs`:
  - `rotate_connection_keys` → vault `connection.rotate`
  - `authenticate_connection` → vault `connection.authenticate`
  Both are phone-required; reuse the existing `pending_approval` response
  pattern (see `revoke_connection`).
- **B6.** Verify-identity state read — the vault exposes per-connection verify
  state (`connection_verify_state.go`); surface last-result + a re-challenge
  refresh action.
- **B7.** Workspace header quick actions: Message (→ Conversation), Voice,
  Video. Calls initiate via the existing `placeCall`; media remains stubbed
  until Phase 6 — buttons are wired now, the user just won't get audio/video.

Verify: open a connection → rich detail in the right pane; rotate-keys and
verify-identity round-trip through phone approval.

---

## Phase D — Messaging richness

Files: `Conversation.svelte`, `RequestPaymentSheet.svelte` (already exists —
wire it in).

- **D1.** BTC payment message bubbles — render `payment_request`,
  `btc_payment_receipt`, `btc_address`, and payment-decline as custom bubbles
  (the `Message` type already declares these `content_type`s).
- **D2.** Pay / Decline actions on an incoming `payment_request` bubble.
- **D3.** Wire `RequestPaymentSheet` as a conversation action (compose-bar
  attach/➕ menu).
- **D4.** Pagination — load older messages on scroll-up via `list_messages`
  offset/limit.
- **D5.** Scroll-to-bottom button when scrolled away from the latest message.
- **D6.** (Optional) display received image/file messages.

Verify: a BTC payment request from the phone renders as an actionable bubble;
older history pages in on scroll.

---

## Deferred — follow-up plan

- **Phase C — data-sharing:** PeerCatalog (request access to a peer's published
  items), "Data they've shared" / "Data you've shared" grants, "My sharing"
  (share policies, presence override), and surfacing verify-identity in the
  Them/You tabs. Heaviest phase — needs new `capability.request` /
  `grant.approve|deny|revoke` command wiring.
- **Phase E — history:** archived-connections view + call history
  (`list_call_history` is already wired in the Rust layer, unused).

## Risks / notes

- `connection.list` is ~51KB for 24 connections — fine. `ListConnectionsRequest`
  already supports `limit`/`offset` if server-side paging is ever needed.
- Two-pane keeps `ConnectionsList` mounted — eliminates the per-open refetch.
- Call media stays stubbed (Phase 6); call buttons initiate but won't connect
  audio/video until the SFrame cryptor + TURN config land.
