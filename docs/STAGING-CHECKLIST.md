# Staging checklist: the desktop on the relay (VAULT-PLAN V6 exit)

A scripted run of the desktop against a **staging** vault, through the relay: the desktop pairs, opens a
session, reads `vault.status`, ends the session, and is locked. The owner runs it with a phone on staging. The
Windows test machine's session prepares it and records what the machine shows. Where this build's behaviour is
uncertain, the step says **record** rather than asserting a result.

**What "staging" means here.** The desktop has no built-in service address: it reaches whatever relay the
invite names. Staging vaults use the shared relay, `relay.vettid.org`, which production also uses (owner
decision D11 in vettid.org `STAGING-DEVELOPMENT-PLAN.md`). An invite's relay looks the same on staging and on
production. So the staging check is the **phone**: a staging build of the app, signed in to a staging vault.
Use the relay lightly: no load and no repeated loops.

**No secrets anywhere.** Never put the invite code, the check code, a PIN, a key or an email address in a log,
a screenshot, an issue or a message.

**What this build doesn't do yet.** It doesn't lock the **vault** itself (VAULT-MESSAGING §10.2 `vault.lock`
isn't sent by the app), and it doesn't handle `vault.locking` or `vault.held`. Step 4 tests the desktop's own
lock, and a lock made on the phone. Every vault operation other than the session answers "not available".

## Before the run

- **Vault:** a staging release with vault #183 (`session_id` on End session): release 27 or later.
- **Phone:** a staging build of the app that can make a desktop pairing code and approve a desktop's session
  requests, signed in, with the vault unlocked. Record its version.
- **Desktop build:** a debug NSIS installer built from `main` on this machine with no `--features`
  (`cargo tauri build --debug --bundles nsis`; the installer is in `src-tauri\target\debug\bundle\nsis\`).
  Record the commit. Unsigned, so SmartScreen may warn.
- **This Windows account** has never paired, or has logged out: `%LOCALAPPDATA%\vettid-desktop` doesn't exist.
- **Install:** `Start-Process -Wait -FilePath "<path>\VettID Desktop_<version>_x64-setup.exe" -ArgumentList '/S'`.
- **Start it with a log**, in its own PowerShell window. A debug build is a console program, and its log goes to
  standard error:
  ```powershell
  Start-Process -NoNewWindow -FilePath "$env:LOCALAPPDATA\VettID Desktop\vettid-desktop.exe" `
    -RedirectStandardError "$env:TEMP\vettid-staging.log"
  ```
  Leave `RUST_LOG` unset (the built-in level is `info`, with this app at `debug` and `reqwest` at `warn`). Never
  set it to `debug` or `trace` for other crates. Run the checks below from a second window.
  The app's own log lines hold no codes, keys or email addresses. A file-system error can include a path with
  the Windows user name, so read the log before quoting it, and delete it after the run.
- **Closing vs quitting.** Closing the window only hides the app. "Relaunch" below means Quit from the tray
  icon, then start it again as above. A second start while it runs only shows the running app.

## The run

Record each step in the table below: pass or fail, the time where asked, and what was shown.

1. **Pair.**
   1. On the phone: make a desktop pairing code (record the phone's label for it), and bring it to this
      machine.
   2. On the desktop: paste it, and choose **Connect**.
   3. The desktop shows a check code. Compare it with the phone's, then approve on the phone.
   4. Expected: "Desktop paired! Session active.", then **Continue**, which reloads into the app (Connections).
      The Session view opens from the session pill in the top bar.
      `%LOCALAPPDATA%\vettid-desktop\device.enc` exists. `icacls` on the folder and on `device.enc` shows only
      this account and SYSTEM.
   5. **Fail-secure, the codes differ** (a separate pass, before the real one): deny on the phone. Expected:
      "Rejected on your phone" and Try Again. `device.enc` is gone; the empty `vettid-desktop` folder may stay.
2. **Session and `vault.status`.**
   - Expected: the Session view shows a live session with its timer, and the phone lists this desktop as
     active. The desktop shows a session as live only after its own `vault.status` this run.
   - **Fail-secure, no network at start:** turn the network off, relaunch. Expected: "Start a new session",
     with no session shown live. Turn the network on: within about a minute, the session may be shown live
     again with no approval, because the vault still names it. Record what happens.
3. **End session.**
   1. In the Session view, choose End session and confirm. Expected: "Ending your session…" until the vault
      answers, then "Start a new session" with no notice. Any notice there means the end was **not**
      confirmed. The phone no longer lists the desktop as active.
   2. **Fail-secure, no network:** choose Start New Session and approve it on the phone. Turn the network off,
      and **within a minute** choose End session (after that the desktop stops showing the session as live,
      and End session is disabled). Expected: "This desktop couldn't reach your vault to end the session, so it
      may still be open. This desktop keeps trying while it runs; …". It may take up to about 90 s. It must
      never say the session ended. Turn the network on and keep the app running (don't Quit): within about a
      minute, the phone no longer lists the session as active. The notice stays on the desktop; the phone is
      the check.
4. **Lock.**
   1. **The desktop's own lock:** in a live session, choose Lock now, and confirm with **Lock**.
      - Expected: "Locked. The next launch auto-unlocks." The session isn't shown, and the app shows "Start a
        new session".
      - This lock is the desktop's alone: it sends nothing to the vault. Record what the phone shows; it is
        expected to still list the desktop as active.
      - Don't choose Start New Session now, and don't follow a notice that points to Log out. Record any notice
        you see.
      - Relaunch. Expected: if the session hasn't expired, it is shown live again with no approval, after the
        desktop's `vault.status`. Record it.
   2. **The vault locked on the phone:** in a live session, lock the vault on the phone, and note the time.
      - Expected: within about 3 minutes, the desktop stops showing the session as live, and shows "Start a new
        session" with "This desktop hasn't heard from your vault for a few minutes…". Record how long it took.
      - Unlock on the phone, and record what the desktop does: whether the old session comes back by itself,
        or Start New Session (approved on the phone) is needed.
5. **Log out.** Settings → Danger zone → Log out, then confirm.
   - Expected: a notice and OK. If the end was confirmed, the notice says the desktop was logged out and its
     access to the vault was ended. If it says the vault was not told, record it. OK shows the pairing screen.
   - `%LOCALAPPDATA%\vettid-desktop` is gone. No Credential Manager entry `vettid-desktop/master-key-v1/local`
     is left (`cmdkey /list:vettid-desktop/master-key-v1/local` shows `* NONE *`).
   - Then remove the desktop on the phone. Log out doesn't tell the phone.
6. **Uninstall with a pairing** (pair again first, steps 1.1–1.4):
   `(Start-Process -Wait -PassThru -FilePath "$env:LOCALAPPDATA\VettID Desktop\uninstall.exe" -ArgumentList
   "/S /WIPEPAIRING _?=$env:LOCALAPPDATA\VettID Desktop").ExitCode`.
   - Expected: 0. `%LOCALAPPDATA%\vettid-desktop` is gone, the Credential Manager entry is absent, and there is
     no new "VettID Desktop" event in the Application log.
   - Left behind, as expected: `uninstall.exe` and its folder (run in place), and
     `%LOCALAPPDATA%\com.vettid.desktop\EBWebView` (see `docs/WINDOWS-TESTING.md`).
   - Then remove the desktop on the phone.

**Optional, if there is time** (CLAUDE-windows.md): with a live session, sleep the machine, or lock the
workstation, for more than 3 minutes. On waking, the session must not be shown live until the desktop's
`vault.status` answers. Record it.

## Results

| Step | Result | Time, and what was shown (no codes, keys or email) |
|---|---|---|
| Build: commit, Windows version, vault release, phone app version | | |
| 1. Pair | | |
| 1.5 Codes differ, denied | | |
| 2. Session and `vault.status` | | |
| 2. No network at start; network back | | |
| 3.1 End session | | |
| 3.2 End session, no network; network back (seen on the phone) | | |
| 4.1 Lock now: the phone's list; any notice; after relaunch | | |
| 4.2 Vault locked on the phone: time until not shown live; after the unlock | | |
| 5. Log out | | |
| 6. Uninstall with a pairing | | |
| Optional: sleep or locked workstation | | |

Report the filled table on the V6 task, linking this file's commit. A failure is reported as it was seen.
