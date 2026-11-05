# Desktop: locking the vault, and the vault's lock and hold (design note, #77)

*Draft, 2026-11-05, for the owner's approval before code. Read against
VAULT-MESSAGING 0.85.0 (vettid.org master) §3.6.3, §3.6.5, §8 ("`vault.lock`
is never retried from a durable outbox"), §10.2 ("Locks", `vault.status`,
`vault.held`, `vault.locking`) and VAULT-LOCK; this desktop at `main`
`67b2ea0`; vettid-vault `main` `0ee0078`. This is a security path: the code
gets the lead's independent review.*

## 1. What the specification asks of a desktop

| # | Rule | Where |
|---|---|---|
| R1 | A desktop may lock the vault: `vault.lock {unlock_id}`, with the `unlock_id` from `vault.status` (release L). To a vault that announces none, `vault.lock {}` once. | §10.2 table, "Locks" ("Other owner devices") |
| R2 | `vault.lock` never goes in a durable outbox; its `exp` is at most 60 s. With an `unlock_id` it may be sent again while unconfirmed, each time a new request with a new `exp`. | §8, "`vault.lock` is never retried…" |
| R3 | The lock is confirmed only by the vault: its `{}` to the request, or a `vault.locking` naming the device's current `unlock_id`. `stale_lock` ends the lock without confirming it (the vault is open under a newer unlock), and the device does not repeat it on its own. | "Locks", "What ends a device's lock" |
| R4 | A `vault.locking` whose `unlock_id` is not the device's current one is ignored. A device that holds no current `unlock_id` uses the time rule of §11.4. | "Locks" |
| R5 | `vault.held` (durable) goes to desktops with an unexpired access session: the hold's start, then the counts. A desktop SHOULD show the hold, the counts and "open your app to continue", and SHOULD hide its cached content. `vault.status`'s `owner_check` carries the state, `hold`, the deadline, the counts and `idle_lock_at`. | §3.6.3, §3.6.5, §10.2 |
| R6 | While held, a desktop's access session is suspended: still current, but requests other than `vault.status`, `vault.lock`, `device.session.end` (and two call types) are answered `owner_check_required`. With the hold off, desktops' sessions continue. | §3.6.3 (the table of what is allowed while held), §3.6.7 |
| R7 | A locked vault collects nothing: requests wait at the relay and get no answer. After an unlock the session resumes if it has not expired. | §12.1, VAULT-LOCK §5 (the table: "sessions resume after an unlock and a check") |
| R8 | The vault sends `vault.locking` best effort, deposited directly, and skips a device with deposits still queued (vettid-vault `vault/outbox.go`). A desktop must not depend on receiving it. | as built |

## 2. What the desktop does today (`main` `67b2ea0`)

- **It never sends `vault.lock`.** The engine can send it correctly:
  `Session::send_once` refuses a durable outbox for it and an `exp`
  over 60 s (`crates/vettid-device/src/session.rs`, `VAULT_LOCK_MAX_EXP`).
  But no command or UI uses it. "Lock" (`commands/auth.rs` `lock`) drops
  the link from memory: it locks this desktop only (#76).
- **It reads nothing of the lock or the hold.** `parse_status` reads only
  `session` (`crates/vettid-device/src/access.rs`), not `unlock_id` or
  `owner_check`. `parse_event` knows only `device.session.granted` and
  `device.session.ended`, so `Link::drain_held` drops `vault.locking`
  and `vault.held` unread.
- **After a lock made on the phone**, the desktop finds out only when
  `vault.status` stops answering. It keeps showing the session as live
  until `STALE_AFTER` (120 s past the last confirmation, `link.rs`), then
  shows `STALE_NOTICE` ("hasn't heard from your vault…"). It never says
  the vault is locked.
- **While the vault is held**, `vault.status` still answers and names
  the (suspended) session, so the desktop **shows the session as
  active** while every request is refused `owner_check_required`. That
  shows a session as usable when it is not. It is the gap closest to
  "never show … on a guess": fail secure, the opposite way round.

## 3. Design

### 3.1 The engine (`crates/vettid-device`)

- `vault.status`: also parse `unlock_id` (32 lowercase hex, else
  treated as absent) and `owner_check` (`state`, `hold`, `deadline`,
  `waiting`, `idle_lock_at`). Unknown members stay ignored, as today.
- New events in `Access::observe`:
  - **`vault.locking`**:
    - With an `unlock_id` equal to the current one: the vault is locked
      (confirmed). The current session is no longer live.
    - With another `unlock_id`: ignored (R4).
    - With no current `unlock_id` held (no status read yet, or a vault
      before L): *(chosen; not in the spec)* the notice is not trusted
      as confirmation, because a desktop has no unlock result for the
      §11.4 time rule. But the session is not shown as live, and a
      `vault.status` is read at once. Fail secure: the notice can't
      make the desktop show more, only less.
  - **`vault.held`**: newest by `ts` (R5). It marks the vault held, with
    its counts, until a `vault.status` says otherwise. While held, with
    the hold on, the session is **suspended**, not live (R6).
- **The access state** that the UI reads (in `Snapshot`) gains
  `vault: Open | Held{deadline, waiting} | Locked | Unknown`.
  - `Locked` comes only from the vault's word (R3).
  - `Unknown` comes when a status read fails after a `vault.locking`
    without a match, or after a lock the vault didn't confirm.
  - Only `Open` with a current session shows the session as live.
  - `STALE_AFTER` stays as the cap on top.

### 3.2 Locking from the desktop

- A **"Lock vault"** action (question 1), asking first. Then:
  1. If the `unlock_id` held is from a status more than 60 s old, read
     `vault.status` first. If that read fails, send no lock: say the
     vault can't be reached.
  2. `send_once("vault.lock", {unlock_id}, exp = now + 60 s)`, and wait
     for the answer until `exp`.
  3. Outcomes:
     - `{}`, or a matching `vault.locking`: **locked**, confirmed.
     - `stale_lock`: not locked by this request; read `vault.status`.
       If it answers, the vault is open under a newer unlock: say so and
       don't repeat. If it doesn't answer, the state is unknown: say so.
     - No answer by `exp`: **not confirmed**. While the person keeps the
       screen open, send it again, at most 3 times in all, each a new
       request with a new `exp` (R2). Then say plainly that the lock
       isn't confirmed and the vault may still be open.
  4. To a vault with no `unlock_id` in its status (before release L):
     `vault.lock {}` once, and no resend (R2).
- **After a confirmed lock** the desktop keeps its link, so it notices
  the unlock. The background refresh goes on, and its `vault.status`
  waits unanswered while the vault is locked. When a status answers
  with a new `unlock_id`, the vault is open again. The session shows as
  live only if that status names it (R7).
- **"Lock this desktop"** (today's Lock, #76) stays as it is.

### 3.3 The hold

- `vault.held`, or a status with `owner_check.state` `held` and
  `hold: true`, shows the hold screen in place of the session: the
  text, the counts and the deadline. Nothing of the vault is shown
  behind it. This desktop caches no vault content yet (the vault
  operations are "not available", `commands/unavailable.rs`), so
  hiding is only the screen for now.
- A request answered `owner_check_required` shows the same screen
  (today it surfaces as a generic error).
- The hold ends when a `vault.status` says `ok`, or `due` with the
  session named, after a check on the phone (the
  `sync.event{owner_check}` is not read yet; the refresh catches it
  within 60 s).
- `idle_lock_at` is shown on the hold screen: "Your vault locks itself
  at <time> unless you do your daily check." (question 2).

### 3.4 Texts (all NEW, for the owner's approval)

- **Lock vault** (button), and the confirmation: "Lock your vault? It
  stays locked until you unlock it on your phone."
- **Locking**: "Locking your vault…"
- **Locked** (confirmed): "Your vault is locked. Unlock it on your phone
  to continue."
- **Locked from elsewhere** (a matching `vault.locking`): "Your vault was
  locked. Unlock it on your phone to continue."
- **Not confirmed**: "Your vault hasn't confirmed the lock. It may still
  be open. This desktop tried 3 times; try again, or lock it on your
  phone."
- **Opened again** (`stale_lock`, then an answering status): "Your vault
  was unlocked again since this desktop last checked, so this lock did
  nothing. Lock again if you want it locked."
- **Unknown**: "This desktop can't tell whether your vault is locked.
  It keeps checking."
- **Can't reach** (no fresh status before locking): "Your vault can't be
  reached, so this desktop can't lock it. Lock it on your phone."
- **Held**: "Your vault is waiting for your daily check. Open VettID on
  your phone to continue." with "Waiting: <n> messages, <n> requests,
  <n> missed calls, <n> other." and the idle-lock line of §3.3.

## 4. Tests

- **Engine, with the fake vault:**
  - each lock outcome (`{}`, `stale_lock` then answered or unanswered
    status, no answer, resend at most 3, a vault before L sent once);
  - `vault.locking` matching, not matching, and with none held;
  - `vault.held` newest by `ts`;
  - a held status with the hold on (not live) and off (live);
  - `owner_check_required` mapped to the hold;
  - `vault.lock` never in the outbox (the engine's existing test).
- **UI:** the routing and state tests (`npm test`) for each state.
- **Staging, on Windows here, with the phone:**
  - lock from the desktop, confirmed;
  - a lock from the phone;
  - a hold (STAGING-TIME-SCALE's shortened interval, if staging has it);
  - an unlock afterwards;
  - the relay cut during a lock (not confirmed, resend, the plain text).

## 5. Questions for the owner

1. **The Lock actions.**
   - a (recommended): two actions, "Lock this desktop" (today) and "Lock
     vault" (new, asks first).
   - b: one "Lock" that locks the vault and this desktop.
2. **The idle-lock time on the hold screen.**
   - a (recommended): show it.
   - b: leave it out for now.
3. **The resend.**
   - a (recommended): at most 3 sends of an unconfirmed lock, each with a
     new 60 s `exp`, while the screen stays open.
   - b: once only, then the plain text.

## 6. Order

This note, then one PR for the engine (§3.1, with its tests), then one
for the commands and UI (§3.2–§3.4). Both get the lead's independent
review (a security path). Staging needs a vault release with release L.
`unlock_id` and `vault.locking {unlock_id}` are in vettid-vault `main`;
whether the current staging release has them is checked before the
staging step.
