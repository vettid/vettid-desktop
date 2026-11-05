# Desktop: the vault's lock and hold (design note, #77)

*2026-11-05. Approved by the owner (§5); the code follows it.*

*Read against:*
- *VAULT-MESSAGING 0.85.0 (vettid.org master): §3.6.3, §3.6.5, §3.6.7, §8.4, §10.2 ("Locks", `vault.status`, `vault.held`, `vault.locking`), §11.4, §12.1;*
- *VAULT-LOCK §4.5;*
- *this desktop at `main` `67b2ea0`;*
- *vettid-vault `main` `0ee0078`.*

*This is a security path: the code gets the lead's independent review.*

**Owner decision of 2026-11-05** (thread 01M6PHX9DKPAXGKRPNQ6HX7V8V):
**the desktop never locks the vault.** Locking is available only from the
phone. The desktop's "Lock" stays this desktop's own lock (#76), and the
desktop never sends `vault.lock`. VAULT-MESSAGING §3.6.5 and §10.2 say a
desktop may lock; the lead writes the erratum ("desktops don't lock the
vault, owner decision 2026-11-05").

What this note covers is the other half: what the vault tells a desktop
about its lock and hold, and how the desktop shows it honestly.

## 1. What the specification asks of a desktop

| # | Rule | Where |
|---|---|---|
| R1 | `vault.locking {unlock_id}` names the unlock a lock ends, for a lock from any cause. A device MUST ignore one whose `unlock_id` is not its current one. A device that holds no current `unlock_id` handles it by the time rule of §11.4: its `ts` later than that of its latest successful unlock result. A desktop reads the `unlock_id` in `vault.status`. | §10.2 "Locks", the `vault.locking` row |
| R2 | `vault.held` (durable) goes to desktops with an unexpired access session: the hold's start, then the counts. A desktop SHOULD show the hold, the counts and "open your app to continue", and SHOULD hide its cached content. `vault.status`'s `owner_check` carries `state`, `hold`, `deadline`, the counts (`waiting`, only while `due` or `held`) and `idle_lock_at`. A device with neither a notice nor a status answer does not know the counts. | §3.6.3, §3.6.5, §10.2 |
| R3 | `owner_check.state` is `ok` before the deadline, `due` past it with the hold off, `held` past it with the hold on. While held, a desktop's access session is suspended: still current, but anything other than `vault.status`, `vault.lock`, `device.session.end{}`, `call.end`, `call.ice` of an answered call and `location.share.stop` is answered `owner_check_required`. Entering the hold drops pending session requests. With the hold off (`due`), desktops' sessions continue. | §3.6.3, §3.6.7, §10.2 |
| R4 | A locked vault collects nothing: requests wait at the relay and get no answer. Sessions resume after an unlock **and a check**; an idle-locked vault comes back held. | §12.1, VAULT-LOCK §4.5 |
| R5 | Messages arrive in no order. A status answered before a lock can arrive after the lock's notice. | §8.4 |
| R6 | As built, the vault sends `vault.locking` best effort, deposited directly. It skips a device with deposits still queued (`outboxPending`), and the notice's `exp` is `ts` + 60 s (`Exp: now.Add(time.Minute)`), so a device that collects later drops it as expired. A desktop must not depend on receiving it. | vettid-vault `main` `0ee0078`, `vault/outbox.go` (read) |

## 2. What the desktop does today (`main` `67b2ea0`)

- **It reads nothing of the lock or the hold.** `parse_status` reads only
  `session` (`crates/vettid-device/src/access.rs`), not `unlock_id` or
  `owner_check`. `parse_event` knows only `device.session.granted` and
  `device.session.ended`, so `Link::drain_held` drops `vault.locking`
  and `vault.held` unread.
- **It collects only while it reads or waits.** The background refresh
  reads `vault.status` every 60 s (`REFRESH_EVERY`), but only while the
  session is live, an end is stored, or no status has been read
  (`Link::keep_refreshing`). So a `vault.locking` (60 s `exp`) is usually
  dropped as expired before it is collected. Once the session is not
  live, the refresh stops.
- **After a lock made on the phone**, the desktop finds out only when
  `vault.status` stops answering. It keeps showing the session as live
  until `STALE_AFTER` (120 s past the last confirmation, `link.rs`), then
  shows `STALE_NOTICE` ("hasn't heard from your vault…"). It never says
  the vault is locked.
- **While the vault is held**, `vault.status` still answers and names the
  (suspended) session, so the desktop **shows the session as active**
  while every request is refused `owner_check_required`: a session shown
  as usable when it is not.
- "Lock" (`commands/auth.rs` `lock`) drops the link from memory. It locks
  this desktop only (#76), and stays so.

## 3. Design

### 3.1 The vault state, in the engine (`crates/vettid-device`)

- **The state.** `Access` keeps a vault state beside the session:
  - `Unknown`: at start, after a restart, and whenever nothing below
    has said otherwise. `Open` also becomes `Unknown` after sleep or
    resume, and when a status goes unanswered or `STALE_AFTER` passes
    without a confirmation. So a lock whose notice the desktop missed
    never leaves "open" on the screen. `Locked` after resume becomes
    "locked as of <time>" (below) until a status answers;
  - `Open { unlock_id?, due }`: `due` means `owner_check.state` `due`,
    past the deadline with the hold off, and the session continues;
  - `Held { deadline, waiting? }`: `owner_check.state` `held`;
  - `Locked { since, reason? }`.

  Only `Open` with a current session shows the session as live.
  `STALE_AFTER` stays as the cap on top. `Snapshot` gains this state as
  `vault`. Its field `unlocked` (the link in memory) is renamed
  `link_open`, so it can't be confused with the vault's lock.
- **What sets it, ordered by the vault's `ts`** (R5), as `Access::learn`
  already orders session statements. An older statement never replaces
  a newer one.
  - A `vault.status` answer sets `Open` (with its `unlock_id` and `due`)
    or, by its `owner_check`, `Held`.
    - It never sets `Open` with an `unlock_id` that a lock notice has
      ended.
    - A malformed `unlock_id` makes the state `Unknown`.
  - A `vault.locking` naming the current `unlock_id` sets `Locked`, with
    its `reason`.
  - A `vault.locking` with another `unlock_id` changes nothing (R1). But
    it shows the `unlock_id` held is out of date, so a `vault.status` is
    read at once.
  - A `vault.locking` when no `unlock_id` is held (no status read yet,
    or a vault before release L): the desktop has no unlock result for
    the §11.4 time rule (owner decision 1, §5): the state becomes
    `Unknown`, the session not live, and a status is read at once. The
    notice never makes the desktop show "locked", only less.
  - `vault.held` (newest by `ts`) sets `Held` with its counts.
  - An answer `owner_check_required` to any request sets `Held`.
  - `device.session.granted` and `.ended` never change the vault state
    (§3.6.3).
- **The refresh keeps going** (`keep_refreshing`) while the state is
  `Held`, `Locked` or `Unknown`, not only while a session is live. That
  way the desktop notices an unlock, a check, or a lock.
  - Its pace stays 60 s, and it also reads `vault.status` on wake and
    when the window gains focus.
  - A locked vault leaves each status unanswered (it waits at the
    relay); that is not read as reachability.
  - **`Locked` doesn't go stale silently.** `Locked` stays only while
    each refresh reaches the relay (the collect answers) and the status
    gets no answer. If the relay can't be reached, the state shows
    "locked as of <time>": the last time it was confirmed, and that
    this desktop can't check now (owner decision 2). It turns back to `Locked`
    once the relay answers again and the status still doesn't.
- **Pending requests and ends.**
  - A pending `device.session.request` is dropped when the state becomes
    `Held` (the vault drops it, R3) or `Locked`. Its waiting screen
    gives way to the hold or locked screen.
  - A locked vault does not drop the request, and may grant it after an
    unlock. Such a grant is a fresh session, shown as live only after a
    `vault.status` names it and the state is `Open`.
  - A stored `device.session.end` keeps retrying through a lock, since
    sessions resume after an unlock (R4, #80).
- **Accepted, said plainly:** after a lock made on the phone, with the
  `vault.locking` missed (R6), a desktop can show the session as live
  for up to about 2 minutes (`STALE_AFTER`), less when the wake and focus
  status reads catch it first.

### 3.2 Session actions through a lock or hold

- **End session** stays offered in every state: Open, Held, Locked and
  Unknown. `device.session.end` is allowed while held (R3), and a stored
  end keeps retrying (§3.1).
- The pending-end notice (#80, #85) and `endState.js`'s `readIsStale`
  survive a change of the vault state; a screen swap does not clear
  them.
- An open End confirmation isn't lost or re-pointed when the screen
  swaps. It stays on the action the person opened it for, and the person
  answers or cancels it.
- **Start New Session** is hidden while Held, Locked or Unknown. The
  vault would refuse it or not answer, and the desktop asks only for
  what can be used now.
- "Lock" stays as it is: it locks this desktop.

### 3.3 The hold

- `Held` shows the hold screen in place of the session: the text, the
  counts and the deadline, with nothing of the vault behind it.
  - This desktop caches no vault content yet (the vault operations are
    "not available", `commands/unavailable.rs`), so hiding is only the
    screen for now.
  - **No counts known** (R2): the screen says something may be waiting,
    never zeros.
- `due` (past the deadline with the hold off) keeps the session live,
  with the "hold off" line of §3.4. `ok` changes nothing.
- The hold ends when a `vault.status` says `ok` or `due` (newer than the
  hold statement). A `vault.held` delivered late shows the hold until
  that status, which the continued refresh reads within 60 s.
- `idle_lock_at` is shown on the hold screen (owner decision 4).

### 3.4 Texts (each NEW; approved by the owner, decision 3)

- **Locked** (NEW; a matching `vault.locking`, no reason): "Your vault
  was locked. Unlock it on your phone to continue."
- **Locked by inactivity** (NEW; `reason: "idle"`): "Your vault locked
  itself because your daily check wasn't done. Unlock it on your phone."
- **Locked after failed checks** (NEW; `reason: "owner_check"`, ten
  failed checks, §3.6.4): "Your vault locked itself after too many failed
  daily checks. Unlock it on your phone."
- **Locked by a recovery** (NEW; `reason: "recovery"`): "Your vault was
  locked because a recovery started. Use your phone to continue."
- **Locked, can't check now** (NEW): "Your vault was locked at <time>.
  This desktop can't reach it now to check."
- **Unknown** (NEW): "This desktop can't tell whether your vault is
  open. It keeps checking."
- **Held** (NEW): "Your vault is waiting for your daily check. Open
  VettID on your phone to continue."
  - With counts: "Waiting: <n> messages, <n> requests, <n> missed calls,
    <n> other." Each count of 1 takes its singular ("1 message", "1
    request", "1 missed call"), and a count of 0 is left out.
  - Without counts: "Something may be waiting for you."
  - The line "Your vault locks itself at <time> unless you do your daily
    check."
- **Hold off** (NEW; a line on the session, `due`): "Your daily check is
  overdue. Your vault's hold is off, so this desktop keeps working."

## 4. Tests

- **Engine, with the fake vault:**
  - `vault.locking` matching (with each `reason`), not matching (a
    status read follows), with no `unlock_id` held, and expired;
  - a malformed `unlock_id` gives `Unknown`;
  - ordering by `ts`: a status from before a lock notice, arriving after
    it, doesn't reopen; one from before the deadline doesn't end the
    hold;
  - `vault.held` newest by `ts`, with and without counts;
  - `due` to `held` to `ok`; a held status not live, a `due` one live;
  - `owner_check_required` sets `Held`;
  - the refresh continues in `Held`, `Locked` and `Unknown`;
  - `Open` to `Unknown` on an unanswered status, on `STALE_AFTER` and
    on resume;
  - `Locked` with the relay unreachable becomes "as of", and back to
    `Locked` once the relay returns;
  - a pending session request dropped on `Held` and on `Locked`, and a
    later grant shown only after a status;
  - a stored end that keeps retrying through a lock;
  - the desktop never sends `vault.lock` (no code path reaches it).
- **UI:** the routing and state tests (`npm test`) for each state:
  - End offered in every state, and Start New Session hidden in Held,
    Locked and Unknown;
  - a pending end, with its confirmation open, through a swap to Held
    and to Locked;
  - the plurals.
- **Staging, on Windows here, with the phone:**
  - a lock from the phone, then the desktop's refresh, wake and focus
    reads;
  - a hold (STAGING-TIME-SCALE's shortened interval, if staging has it);
  - an unlock afterwards;
  - the relay cut while locked ("as of");
  - sleep and resume while locked.

## 5. Owner decisions (2026-11-05)

The owner chose the recommended answer to each question (thread
01M6PJ5AMK6YXG58NYA4PGTW2T, "rec"):

1. **A `vault.locking` with no `unlock_id` held** shows `Unknown` and
   re-reads the status; "locked" is never shown on it alone. This is the
   owner's decision for desktops, in place of the §11.4 time rule. The
   spec erratum is the lead's.
2. **Locked when the vault can't be checked** (offline, after resume):
   "locked as of <time>", with "can't check now".
3. **The texts of §3.4** are approved as written.
4. **The hold screen** shows the idle-lock time.

## 6. Order

1. This note.
2. One PR for the engine (§3.1, with its tests).
3. One PR for the commands and the UI (§3.2–§3.4).

Both PRs get the lead's independent review (a security path). The staging
step needs a vault release with release L (`unlock_id` and
`vault.locking {unlock_id}` are in vettid-vault `main`); whether the
current staging release has them is checked before the staging step.
