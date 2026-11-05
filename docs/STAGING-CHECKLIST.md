# Staging checklist: the desktop on the relay (VAULT-PLAN V6 exit)

A scripted run of the desktop against a **staging** vault, through the relay. It is the V6 exit: the desktop
pairs, opens a session, reads `vault.status`, ends the session and locks. The owner runs it with a phone on
staging; the Windows test machine's session prepares it and records what the machine shows.

**Staging only.** The desktop has no built-in service address: it reaches whatever relay the invite names.
So the invite must come from a phone on **staging**, and nothing in this run touches production. Never put
the invite code, the check code, a PIN, a key or an email address in a log, an issue or a message.

## Before the run

- **Vault:** staging release 27 or later (it carries vault #183, `session_id` on End session).
- **Phone:** the VettID app on staging, signed in, with the vault unlocked.
- **Desktop build:** a debug NSIS installer built from `main` on this machine (`cargo tauri build --debug
  --bundles nsis`). Record the commit. Unsigned: SmartScreen may warn.
- **This Windows account** has never paired, or logged out: `%LOCALAPPDATA%\vettid-desktop` doesn't exist.
- **Install:** `"VettID Desktop_<version>_x64-setup.exe" /S`.
- **Start it with a log:** a debug build has a console, and the log goes to it. From PowerShell:
  ```powershell
  $env:RUST_LOG = 'info'
  & "$env:LOCALAPPDATA\VettID Desktop\vettid-desktop.exe" 2> "$env:TEMP\vettid-staging.log"
  ```
  The log holds no codes or keys; read it before attaching any of it anywhere.

## The run

Record each step's result (pass, fail, and what was shown) in the table below. For each step, the
fail-secure check says what must **not** happen.

1. **Pair.**
   1. On the phone: add a desktop, and copy its pairing code to this machine.
   2. On the desktop: paste it, and choose Connect.
   3. The desktop shows a check code. Compare it with the phone's, then approve on the phone.
   4. Expected: the desktop shows "Desktop paired! Session active."; Continue opens the Session view.
      `%LOCALAPPDATA%\vettid-desktop\device.enc` now exists. `icacls` on that folder shows only this account,
      SYSTEM and Administrators.
   5. Fail-secure: if the codes differ, deny on the phone. The desktop must then say it isn't paired, and
      leave no `device.enc`.
2. **Session and `vault.status`.**
   - Expected: the Session view shows a live session with its timer, and the phone lists this desktop as
     active. The desktop shows a session as live only after its own `vault.status` this run.
   - Fail-secure: with the network off (Wi-Fi off, or the cable out) when the app starts, the session must
     not be shown as live.
3. **End session.**
   - Choose End session and confirm. Expected: the desktop shows the session ended only after the vault
     confirms it, and the phone no longer lists it as active.
   - Fail-secure, a second session: choose Start New Session and approve it on the phone. Turn the network
     off, then End session. The desktop must say it couldn't reach the vault and that the session may still
     be open ("This desktop couldn't reach your vault to end the session…"), not that it ended. Turn the
     network back on: the end is sent. Check on the phone.
4. **Lock.**
   1. **The desktop's Lock now:** in a live session, choose Lock now. Expected: the session is no longer
      shown; the next launch unlocks the pairing and asks for a new session.
   2. **The vault locked from the phone:** in a live session, lock the vault on the phone. Expected: the
      desktop stops showing a live session, and nothing shows the vault's contents. Unlock on the phone:
      the desktop needs a new session (Start New Session), approved on the phone.
5. **Log out.**
   - In Settings, Log out. Expected: `%LOCALAPPDATA%\vettid-desktop` is gone, and the desktop shows the
     pairing screen.
   - Then remove the desktop on the phone. Log out doesn't tell the phone.
6. **Uninstall.** `uninstall.exe /S /WIPEPAIRING _?=<install folder>` gives exit code 0, with nothing paired
   left (see `docs/WINDOWS-TESTING.md`).

## Results

| Step | Result | What was shown (no codes, keys or email) |
|---|---|---|
| Build: commit, Windows version, release | | |
| 1. Pair | | |
| 1. Codes differ, denied | | |
| 2. Session and `vault.status` | | |
| 2. Network off at start | | |
| 3. End session | | |
| 3. End session, network off | | |
| 4.1 Lock now | | |
| 4.2 Vault locked on the phone | | |
| 5. Log out | | |
| 6. Uninstall | | |

Report the filled table on the V6 task, linking this file's commit. A failure is reported as it was seen;
the run isn't redone until it passes.
