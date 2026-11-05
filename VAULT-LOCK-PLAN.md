# Desktop: locking the vault, and the vault's lock and hold (design note, #77)

*Draft, 2026-11-05, for the owner's approval before code. Read against:*
- *VAULT-MESSAGING 0.85.0 (vettid.org master): §3.6.3, §3.6.5, §3.6.7, §8 ("`vault.lock` is never retried from a durable outbox"), §8.4, §10.2 ("Locks", `vault.status`, `vault.held`, `vault.locking`), §11.4, §12.1;*
- *VAULT-LOCK §4.5;*
- *this desktop at `main` `67b2ea0`;*
- *vettid-vault `main` `0ee0078`.*

*This is a security path: the code gets the lead's independent review.*

## 1. What the specification asks of a desktop

| # | Rule | Where |
|---|---|---|
| R1 | A desktop may lock the vault: `vault.lock {unlock_id}`, with the `unlock_id` from `vault.status` (release L). To a vault that announces none, `vault.lock {}` once. | §10.2 table, "Locks" ("Other owner devices") |
| R2 | `vault.lock` never goes in a durable outbox; its `exp` is at most 60 s. With an `unlock_id` it may be sent again while unconfirmed, each time a new request with a new `exp`. | §8, "`vault.lock` is never retried…" |
| R3 | The lock is confirmed only by the vault: its `{}` to the request, or a `vault.locking` naming the device's current `unlock_id`. `stale_lock` ends the lock without confirming it (the vault is open under a newer unlock), and the device does not repeat it on its own. The device then reads the status (MEMBER-API `GET /api/vault/status`) and says the vault is locked only if that status was read and is not `unlocked`. | "Locks", "What ends a device's lock" |
| R4 | A `vault.locking` whose `unlock_id` is not the device's current one is ignored. A device that holds no current `unlock_id` handles it by the time rule of §11.4: its `ts` later than that of its latest successful unlock result. | "Locks" |
| R5 | `vault.held` (durable) goes to desktops with an unexpired access session: the hold's start, then the counts. A desktop SHOULD show the hold, the counts and "open your app to continue", and SHOULD hide its cached content. `vault.status`'s `owner_check` carries `state`, `hold`, `deadline`, the counts (`waiting`, only while `due` or `held`) and `idle_lock_at`. A device with neither a notice nor a status answer does not know the counts. | §3.6.3, §3.6.5, §10.2 |
| R6 | While held (with the hold on), a desktop's access session is suspended: still current, but anything other than `vault.status`, `vault.lock`, `device.session.end{}`, `call.end`, `call.ice` of an answered call and `location.share.stop` is answered `owner_check_required`. Entering the hold drops pending session requests. With the hold off, desktops' sessions continue. | §3.6.3 (what is allowed while held), §3.6.7 |
| R7 | A locked vault collects nothing: requests wait at the relay and get no answer. Sessions resume after an unlock **and a check**: an idle-locked vault comes back held. | §12.1, VAULT-LOCK §4.5 |
| R8 | Messages arrive in no order. A status answered before a lock can arrive after the lock's confirmation. | §8.4 |
| R9 | As built, the vault sends `vault.locking` best effort, deposited directly. It skips a device with deposits still queued, and the notice's `exp` is `ts` + 60 s, so a device that collects later drops it as expired. A desktop must not depend on receiving it. | vettid-vault `vault/outbox.go` |

## 2. What the desktop does today (`main` `67b2ea0`)

- **It never sends `vault.lock`.** The engine has the transport half.
  `Session::send_once` refuses a durable outbox for `vault.lock`, and an
  `exp` over 60 s (`crates/vettid-device/src/session.rs`,
  `VAULT_LOCK_MAX_EXP`). But it does not **arm** the request (it never
  calls `Session::arm`), so the vault's answer, `{}` or `stale_lock`, is
  dropped as a response to no pending request. `Access::observe` has no
  case for it either. No command or UI uses it. "Lock"
  (`commands/auth.rs` `lock`) drops the link from memory: it locks this
  desktop only (#76).
- **It reads nothing of the lock or the hold.** `parse_status` reads only
  `session` (`crates/vettid-device/src/access.rs`), not `unlock_id` or
  `owner_check`. `parse_event` knows only `device.session.granted` and
  `device.session.ended`, so `Link::drain_held` drops `vault.locking`
  and `vault.held` unread.
- **It collects only while it reads or waits.** The background refresh
  reads `vault.status` every 60 s (`REFRESH_EVERY`), and only while the
  session is live, an end is stored, or no status has been read
  (`Link::keep_refreshing`). So a `vault.locking` (60 s `exp`) is
  usually dropped as expired before it is collected. Once the session is
  not live, the refresh stops.
- **After a lock made on the phone**, the desktop finds out only when
  `vault.status` stops answering. It keeps showing the session as live
  until `STALE_AFTER` (120 s past the last confirmation, `link.rs`), then
  shows `STALE_NOTICE` ("hasn't heard from your vault…"). It never says
  the vault is locked.
- **While the vault is held**, `vault.status` still answers and names the
  (suspended) session, so the desktop **shows the session as active**
  while every request is refused `owner_check_required`. It shows a
  session as usable when it is not.

## 3. Design

### 3.1 The vault state, in the engine (`crates/vettid-device`)

- **The state.** `Access` keeps a vault state beside the session:
  - `Unknown`: at start, after a restart, after sleep or resume, and
    whenever nothing below has said otherwise;
  - `Open { unlock_id? }`;
  - `Held { deadline, waiting? }`;
  - `Locked { since, by_this_desktop }`.

  Only `Open`, or `Held` with the hold off, with a current session,
  shows the session as live. `STALE_AFTER` stays as the cap on top.
  `Snapshot` gains this state, as `vault`. Its field `unlocked` (the
  link in memory) is renamed `link_open`, so it can't be confused with
  the vault's lock.
- **What sets it, ordered by the vault's `ts`** (R8), as `Access::learn`
  already orders session statements. An older statement never replaces
  a newer one.
  - A `vault.status` answer sets `Open` (with its `unlock_id`) or, by its
    `owner_check`, `Held`.
    - It never sets `Open` with an `unlock_id` that a confirmed lock has
      ended.
    - A malformed `unlock_id` makes the state `Unknown`. It is never
      read as "none", which would downgrade a lock to `vault.lock {}`.
  - The vault's `{}` to this desktop's `vault.lock` sets `Locked`. So does
    a `vault.locking` naming the current `unlock_id`.
  - A `vault.locking` with another `unlock_id` changes nothing (R4), but
    it shows the `unlock_id` held is out of date, so a `vault.status`
    is read at once.
  - A `vault.locking` when no `unlock_id` is held (no status read yet, or
    a vault before L): the desktop has no unlock result for the §11.4
    time rule (question 4). Proposed: the state becomes `Unknown` (the
    session not live) and a status is read at once. The notice never
    makes the desktop show "locked", only less.
  - `vault.held` (newest by `ts`) sets `Held` with its counts.
  - `device.session.granted` and `.ended` never change the vault state
    (§3.6.3).
- **The lock request is armed.** `send_once` gains the arming that
  `send` has, with the request's `exp`, so the vault's answer is
  matched, and `Access::observe` routes it. A `{}` that arrives after the
  desktop said "not confirmed" still moves the state to `Locked`.
- **The refresh keeps going** (`keep_refreshing`) while the state is
  `Held`, `Locked` or `Unknown`, not only while a session is live. That
  way the desktop notices an unlock, a check, or a lock.
  - Its pace stays 60 s. A locked vault leaves each status unanswered
    (it waits at the relay), and that is not read as reachability.
  - **`Locked` doesn't go stale silently.** `Locked` stays only while
    each refresh reaches the relay (the collect answers) and the status
    gets no answer. If the relay can't be reached, the state shows
    "locked as of <time>": the last time it was confirmed, and that
    this desktop can't check now (question 5).
- **Pending requests and ends.**
  - A pending `device.session.request` is dropped when the state becomes
    `Held` (the vault drops it, R6) or `Locked`. Its waiting screen
    gives way to the hold or locked screen.
  - A stored `device.session.end` keeps retrying through a lock, since
    sessions resume after an unlock (R7, #80).

### 3.2 Locking from the desktop

- A **"Lock vault"** action, offered in every state (a desktop may send
  `vault.lock` while held, R6). It asks first (question 1). Then:
  1. Send `vault.lock {unlock_id}` at once with the `unlock_id` held,
     armed, `exp` = now + 60 s (`send_once`). A stale `unlock_id` is
     harmless: the vault answers `stale_lock`. There is no status read
     first, since that would block a lock most often when the vault
     can't be reached.
  2. Outcomes:
     - `{}`, or a matching `vault.locking`: **locked**, confirmed.
     - `stale_lock`: read `vault.status`. The spec names the member API's
       status for this (R3). This desktop has no member-API access, so
       it reads the vault's status instead (a deviation, question 3). If
       the status answers, the vault is open under a newer unlock: say
       so, and don't repeat. If it doesn't answer, the state is
       `Unknown`: say so.
     - No answer by `exp`: **not confirmed**. While the person keeps the
       screen open, send again, at most 3 sends in all, each a new
       request with a new 60 s `exp` (R2, question 2). Then say plainly
       that the lock isn't confirmed and the vault may still be open.
  3. No `unlock_id` held, because the last status had none (a vault
     before release L): `vault.lock {}` once, never resent (R2). With
     **no status read at all**, or `Unknown`, it still sends
     `vault.lock {}` once, and says the result can't be confirmed
     beyond the vault's answer.
- **After a confirmed lock** the desktop keeps its link, so it notices
  the unlock (above). When a status answers with a new `unlock_id`, the
  vault is open again. The session shows as live only if that status
  names it and the vault is not held (R7).
- **"Lock this desktop"** (today's Lock, #76) stays as it is.

### 3.3 The hold

- `Held` (from `vault.held`, or a status with `owner_check.state` `held`
  and `hold: true`) shows the hold screen in place of the session.
  - The screen holds the text, the counts and the deadline, with nothing
    of the vault behind it. This desktop caches no vault content yet
    (the vault operations are "not available", `commands/unavailable.rs`),
    so hiding is only the screen for now.
  - **No counts known** (R5): the screen says something may be waiting,
    never zeros.
- A request answered `owner_check_required` sets `Held` and shows the
  same screen; today it surfaces as a generic error.
- `due` (before the deadline) changes nothing on the desktop. With the
  hold off, `held` shows the session as live, and the screen shows a
  line that the hold is off.
- The hold ends when a `vault.status` says `ok` (newer than the hold
  statement). A `vault.held` delivered late shows the hold until that
  status, which the continued refresh reads within 60 s.
- `idle_lock_at` is shown on the hold screen (question 2b). A
  `vault.locking` with `reason: "idle"` uses the "locked by inactivity"
  text.

### 3.4 Texts (all NEW, for the owner's approval, question 6)

- **Lock vault** (the button), and its confirmation: "Lock your vault? It
  stays locked until you unlock it on your phone."
- **Locking**: "Locking your vault…"
- **Locked** (confirmed): "Your vault is locked. Unlock it on your phone
  to continue."
- **Locked from elsewhere** (a matching `vault.locking` for a lock this
  desktop didn't send): "Your vault was locked. Unlock it
  on your phone to continue."
- **Locked by inactivity** (`reason: "idle"`): "Your vault locked itself
  because your daily check wasn't done. Unlock it on your phone."
- **Locked, can't check now**: "Your vault was locked at <time>. This
  desktop can't reach it now to check."
- **Not confirmed**: "Your vault hasn't confirmed the lock. It may still
  be open. This desktop tried 3 times; try again, or lock it on your
  phone."
- **Unlocked since** (`stale_lock`, then an answering status): "Your
  vault has been unlocked since this desktop last checked. It is open
  now. Lock again if you want it locked."
- **Unknown**: "This desktop can't tell whether your vault is locked.
  It keeps checking."
- **Held**: "Your vault is waiting for your daily check. Open VettID on
  your phone to continue."
  - With counts: "Waiting: <n> messages, <n> requests, <n> missed calls,
    <n> other."
  - Without counts: "Something may be waiting for you."
  - The line "Your vault locks itself at <time> unless you do your daily
    check."
- **Hold off** (a line on the session): "Your daily check is overdue.
  Your vault's hold is off, so this desktop keeps working."

## 4. Tests

- **Engine, with the fake vault:**
  - each lock outcome: `{}`, `stale_lock` then an answered or
    unanswered status, no answer, the resend capped at 3, a vault before
    L sent `{}` once, and a late `{}` after "not confirmed";
  - the lock request armed, with its answer matched;
  - `vault.locking` matching, not matching (a status read follows), with
    no `unlock_id` held, and expired;
  - a malformed `unlock_id` gives `Unknown`;
  - ordering by `ts`: a status from before the lock arriving after the
    `{}` doesn't reopen it, and one from before the deadline doesn't end
    the hold;
  - `vault.held` newest by `ts`, with and without counts;
  - a held status with the hold on (not live) and off (live);
  - `owner_check_required` sets `Held`;
  - the refresh continues in `Held`, `Locked` and `Unknown`;
  - `Locked` with the relay unreachable becomes "as of";
  - a pending session request dropped on `Held` and on `Locked`;
  - a stored end that keeps retrying through a lock;
  - `vault.lock` never in the outbox (the engine's existing test).
- **UI:** the routing and state tests (`npm test`) for each state.
- **Staging, on Windows here, with the phone:**
  - a lock from the desktop, confirmed;
  - a lock from the phone, then the desktop's refresh;
  - a hold (STAGING-TIME-SCALE's shortened interval, if staging has it);
  - an unlock afterwards;
  - the relay cut during a lock (not confirmed, the resend, the plain
    text);
  - sleep and resume while locked.

## 5. Questions for the owner

1. **The Lock actions.**
   - a (recommended): two actions, "Lock this desktop" (today) and
     "Lock vault" (new, asks first).
   - b: one "Lock" that locks the vault and this desktop.
2. **Resend and idle lock.**
   - a (recommended): at most 3 sends of an unconfirmed lock, each with
     a new 60 s `exp`, and the idle-lock time on the hold screen.
   - b: one send only, no idle-lock time.
3. **After `stale_lock`.**
   - a (recommended): read the vault's own `vault.status`, a deviation
     from §10.2's member-API status, which a desktop doesn't use.
   - b: give the desktop member-API access for this (a larger change).
4. **A `vault.locking` with no `unlock_id` held.** §10.2 and §11.4 give
   the time rule, against an unlock result, which a desktop never has.
   - a (recommended): treat it as `Unknown`. The session is not live, a
     status is read, and "locked" is never shown on it.
   - b: a spec erratum that defines the rule for desktops (for example,
     `ts` later than its latest status answer).
5. **Locked when the vault can't be checked** (offline, after resume).
   - a (recommended): "locked as of <time>", with "can't check now".
   - b: `Unknown`.
6. **The texts of §3.4.** Approve them as written, or change them.

## 6. Order

1. This note.
2. One PR for the engine (§3.1, the arming, with its tests).
3. One PR for the commands and the UI (§3.2–§3.4).

Both PRs get the lead's independent review (a security path). The staging
step needs a vault release with release L: `unlock_id` and
`vault.locking {unlock_id}` are in vettid-vault `main`. Before that step,
I'll check whether the current staging release has them.
