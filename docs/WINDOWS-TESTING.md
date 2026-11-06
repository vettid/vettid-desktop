# Windows testing

Hands-on results from the Windows test machine: building, installing, starting and uninstalling the desktop
app. They cover what CI can't check. Each run says what was done and what was only read in the code. Issue #9
has the first run in full.

## Runs

| | Run 1 (#9) | Run 2 |
|---|---|---|
| Date | 2026-10-12 | 2026-11-04 |
| Code | `main` with PRs #7 and #8 applied locally (not merged then) | `main` at `6bbf653` (same code as `9da6840`, #66) |
| Windows | 11 Pro 10.0.26300 x64 | same |
| rustc | 1.99.0 (MSVC) | 1.99.0 (MSVC) |
| tauri-cli / tauri-bundler | 2.12.2 / 2.10.2 | same |
| Node | 24.20.0 | 24.20.0 |
| WebView2 runtime | 154.0.4258.62 | 156.0.4314.58 |
| Smart App Control | **on**, enforcement | **off** (turned off on this machine since 2026-10-13) |
| Account | member of Administrators, not elevated | same |
| Signing | none | none |

## Build

`cargo tauri build --bundles nsis`. The bundle target is given on the command line because `tauri.conf.json`
lists only `app`, `dmg`, `appimage` and `deb`.

- Run 2 used `CARGO_BUILD_JOBS=2`, because a build with the default job count was stopped for low memory on
  this laptop. With two jobs the release compile took 15m09s, about as long as run 1's 15m34s with all jobs.
- Outputs: `vettid-desktop.exe` (19.0 MB) and `VettID Desktop_0.1.0_x64-setup.exe` (4.5 MB).
- One compiler warning, in both runs: `unquote` in `commands/auth.rs` is unused on Windows, because only the
  Linux branch of `resolve_os_details` calls it.
- On its first run Tauri downloads NSIS 3.11 and checks its hashes.
- **The Visual C++ runtime is linked in** (#112): `src-tauri/build.rs` and `.cargo/config.toml` set
  `STATIC_VCRUNTIME`, so the program starts on a PC without the runtime. The UCRT, part of Windows 10 and 11,
  stays a DLL. After a release build, check it:
  `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/windows/check-no-vcruntime.ps1 src-tauri/target/release/vettid-desktop.exe`
  must exit 0. CI checks the debug build the same way.
- **Servicing:** Windows Update doesn't patch a VC runtime linked into the program. A fix to it reaches members
  only with a rebuild, so build releases with a current MSVC toolset (an up-to-date Visual Studio Build Tools).

## Smart App Control

**Run 1 (SAC on):**

| What was run | Result |
|---|---|
| `target\release\vettid-desktop.exe`, from the build folder | **blocked**, 4 attempts out of 4: "An Application Control policy has blocked this file" |
| The unsigned installer, `/S` | ran |
| The installed copy, `%LOCALAPPDATA%\VettID Desktop\vettid-desktop.exe` | **started** |
| The debug test binary from `cargo test` | ran on three builds, then was blocked on the next, 3 attempts out of 3 |

**Why the two copies were treated differently (found in run 2):** they aren't the same file. Before packing the
installer, the bundler writes a 3-byte bundle-type marker (`NSS`, for NSIS) into the exe it packs. Then it puts
the build-folder exe back as it was (`UNK`) (tauri-bundler 2.10.2, `bundle.rs`). Otherwise the two are byte for byte the same (`cmp`: 3 bytes differ, at one
offset). So they have different hashes, and SAC judges each hash on its own.

**What this means for members:** an unsigned build may or may not run, and when SAC blocks it there is no "run
anyway". Signing is the owner's decision (#9).

**Run 2 (SAC off):** both copies ran. Defender reported no detections.

## Install, run and uninstall (run 2; silent, current user)

**Started from the build folder:** the window opens on "Connect Desktop", the pairing screen, with "No
session" in the status bar.

**Install with `/S`:**
- It takes 3 s, needs no elevation, and exits with 0.
- Files: `%LOCALAPPDATA%\VettID Desktop\` holds `vettid-desktop.exe`, `uninstall.exe` and `icons\`.
- Registry: an uninstall entry under `HKCU\...\Uninstall\VettID Desktop` (no `QuietUninstallString`), and
  `HKCU\Software\vettid\VettID Desktop`, which holds the install path.
- The app isn't signed (`Get-AuthenticodeSignature`: `NotSigned`).

**The installed copy:** it starts and shows the same screen.

**A second launch while it's running:** the second process exits with 0 and leaves the first one running
(the single-instance plugin).

**Closing the window:** the app hides, and the process keeps running, by design (`lib.rs`: the tray keeps the
app running). Only the tray's Quit ends it.

**Reinstall over a running install** (same version, `/S`): the installer ends the running app and exits
with 0. The app starts normally afterwards. An upgrade to a newer version wasn't tested (only one version
exists).

**Uninstall with `/S`:** it exits with 0, and removes the install folder, the Start Menu shortcut
(`%APPDATA%\Microsoft\Windows\Start Menu\Programs\VettID Desktop.lnk`, made at install; no desktop
shortcut) and the uninstall entry.

**Left behind after uninstall, in both runs:**
- `%LOCALAPPDATA%\com.vettid.desktop\EBWebView\` (WebView2 profile data, 7.9 MB after short runs);
- `HKCU\Software\vettid\VettID Desktop`.

**Why they're left (read in the bundler's `installer.nsi`, not run):**
- The uninstaller removes both only when the person ticks "Delete the application data", which a silent
  uninstall can't do.
- The interactive uninstaller wasn't run here; that's left for the owner.

I removed the leftovers by hand after each run.

## Paired state after uninstall, before AG3 and the uninstall hook (read in the code, not run)

Nothing was paired on this machine: pairing needs a phone and a vault on staging. So no state file and no
Credential Manager entry were created in either run (checked: neither exists).

From the code, a paired desktop keeps:
- the device state at `%LOCALAPPDATA%\vettid-desktop\device.enc` (`credential/store.rs`, `CONFIG_SUBDIR`);
- the Credential Manager entry `vettid-desktop/master-key-v1/local` (`credential/wincred.rs`).

**The uninstaller removes neither,** even with "Delete the application data" ticked. That option deletes
`%APPDATA%\com.vettid.desktop` and `%LOCALAPPDATA%\com.vettid.desktop`, and the state is in neither folder.

**The consequences:**
- The desktop stays linked at the vault until the person unlinks it from the phone.
- A reinstall finds the old pairing.
- Logging out first:
  - asks the vault to end its access (`device.session.end`, waiting up to 10 s), and says so only if the vault
    confirms;
  - wipes either way. `store::wipe_for_logout` deletes the state folder and checks on disk that it's gone, then
    tries to delete the Credential Manager entry. **That second step isn't confirmed:** a failure is only logged
    (`keystore::delete_keyring_key`), so the entry can outlive a logout reported as done. Nothing is sealed under
    it once the file is gone. AG3 (#13) removes the entry and confirms each part of a wipe.
  - doesn't unlink the desktop: a desktop can't unlink itself (VAULT-MESSAGING §7.4), only the phone can.

That was before AG3. With AG3 (#13) the data key is DPAPI-wrapped inside `device.enc`, so nothing else is kept
outside the file; the earlier format's Credential Manager entry is only ever deleted.

## Uninstall: the saved pairing (owner decision "a")

What was run:
- the wipe mode's unit tests;
- the hook compiled by `makensis` 3.11 into a mock uninstaller (the template's order, a stand-in for
  `CheckIfAppIsRunning` without the Tauri plugin, and a stand-in wipe program that exits with a chosen code);
- a real debug installer, end to end (results below).

The rest was read in the bundler's template (tauri-bundler 2.10.2, `installer.nsi`).

**Build with tauri-cli 2.12.2 or later** (tested with 2.12.2). The hook passes `CheckIfAppIsRunning` the
program's path, the 2.12 template's form. Earlier templates take a process name there, and the hook's app
check would then silently do nothing, leaving the post-uninstall check (step 3 below) as the only safeguard.
The CLI is installed with cargo (`cargo install tauri-cli`), so the repository can't pin it.

**What the uninstaller removes now:** the saved pairing, on every real uninstall, silent `/S` included. Not
on an update (`/UPDATE`), and not when an installer runs the old uninstaller (an upgrade, downgrade or
reinstall by hand): those keep the pairing. Its hook (`src-tauri/windows/installer-hooks.nsh`) runs
`vettid-desktop.exe --uninstall-wipe` (`src-tauri/src/uninstall.rs`), which is log-out's local wipe
(`store::wipe_for_logout`), each part confirmed on disk:
- `%LOCALAPPDATA%\vettid-desktop\`, with `device.enc` and any temporary copy of it, and an earlier build's
  `connection.enc`;
- the protectors' external keys (none on Windows: DPAPI keeps nothing outside the file);
- the earlier format's Credential Manager entry `vettid-desktop/master-key-v1/local`.

**What it doesn't do:** it doesn't contact the vault, and doesn't tell the phone. A desktop can't unlink
itself (VAULT-MESSAGING §7.4), and an uninstall shouldn't wait on the network. The vault lists the desktop
until it is removed on the phone.

**The wipe's exit codes:**

| Code | Meaning |
|---|---|
| 10 | A pairing was saved here, and every part is confirmed gone. |
| 11 | Nothing was paired here (no pairing file before the wipe). |
| 20 | Something couldn't be removed, or its removal couldn't be confirmed. Also: no user folder, or a panic. |

Anything else is a failure, **0 included**: a program that ignores the switch (an older build, which would
also open its window) exits 0.

**The order:**
1. `NSIS_HOOK_PREUNINSTALL`, before the template removes anything:
   - Skipped on `/UPDATE`; when `$INSTDIR` is empty (a missing install-location entry); and when the
     uninstaller runs in place, from the install folder (`$EXEDIR` = `$INSTDIR`, compared in short form,
     ignoring case and a trailing backslash; owner decision "a", 2026-11-04). An installer runs the old
     uninstaller in place (`uninstall.exe _?=$INSTDIR`), without `/UPDATE`. An uninstall from Windows' Apps
     list, or `uninstall.exe /S`, first copies the uninstaller to a temporary folder and runs it from there
     (the NSIS manual, 3.2: `_?=` "stops the uninstaller from copying itself to the temporary directory and
     running from there"; seen in the mock, case 9 below), so it wipes. `/WIPEPAIRING` (see Scripts) makes
     an in-place uninstall wipe; `/UPDATE` skips it even then.
   - **Refused when this account didn't install the app:** the uninstall goes on only if the account the
     uninstaller runs as has `$INSTDIR` recorded in its own `HKCU`, as the product key's default value or the
     uninstall entry's `InstallLocation` (the template deletes both only later). Otherwise (an uninstall "Run
     as administrator" with another account's password, a SYSTEM or management-tool uninstall, or the keys
     gone), the wipe would delete that account's pairing and keep the user's. So nothing is removed: the
     uninstall stops there with exit code 2, a Warning (event ID 1002) and, if someone is watching, "VettID
     Desktop wasn't uninstalled. This Windows account isn't the one that installed it, and uninstalling it
     from here would leave that account's saved pairing on this computer. Sign in as the account that
     installed VettID Desktop, and uninstall it there." (for the owner's approval). The app, its uninstaller
     and the user's Apps-list entry stay, so the user can still log out or uninstall. Any other install mode
     (per-machine or "both", not used) fails the build with an `!error`: every uninstall would be refused.
   - A running app is closed (`CheckIfAppIsRunning`). If the person cancels, or the app can't be closed, the
     uninstall stops there. **This check can also silently do nothing** (when its Restart Manager session or
     registration fails), and the app could be started again before the wipe; step 3 covers both.
   - The wipe runs; its code is kept for step 3. Nothing is shown yet.
2. The template: its own running-app check (which closes the app or stops the uninstall), then removes the
   program, shortcuts and registry entries.
3. `NSIS_HOOK_POSTUNINSTALL`, unless the wipe was skipped. It looks for `device.enc`, `connection.enc` and any
   `*.tmp-*` in the current user's local app data folder (the known folder, as the app finds it, not the
   `LOCALAPPDATA` variable), under `vettid-desktop`, and for `vettid-desktop.exe` still in the install folder
   (the app may still be running, and save again). This is an extra check, not the confirmation: NSIS's
   `FileExists` reads a folder it can't list as empty. The confirmation is the wipe's own 10 or 11.
   - Code 10 and nothing there: "This desktop was paired. Remove it on your phone too."
   - Code 11 and nothing there: nothing is shown.
   - The program still there: the uninstaller's exit code is 2, a Warning (event ID 1003) goes to the
     Windows Application event log (below), and the message (owner approval needed): "VettID Desktop couldn't
     be fully removed from this computer: its program is still in `<install folder>`, and may still be
     running. Close VettID Desktop, then delete that folder. Also delete `<local app data>`\vettid-desktop if
     it's there, and any vettid-desktop entry in Windows Credential Manager. Remove this desktop on your phone
     too."
   - Anything else (code 20, 0, any other code, the program not starting, or a pairing file there): exit
     code 2, event 1001, and the message (owner approval needed): "VettID Desktop was uninstalled, but this
     desktop's saved pairing couldn't be removed from this computer, or its removal couldn't be confirmed. If
     the folder `<local app data>`\vettid-desktop is still there, delete it, and delete any vettid-desktop
     entry in Windows Credential Manager. Remove this desktop on your phone too."
   - The texts wait for the owner's approval. The uninstall has finished in every case that reaches step 3.
   - Messages are shown only when a person is watching: not under `/S`, and not under `/P` (passive), where a
     box would wait for a click. The exit code is set either way.

**Edge cases:**
- The "paired" message can show when the folder couldn't be read before the wipe (counted as "may be
  paired"), but the wipe then removed it cleanly. That errs on the safe side: the person is told to check the
  phone.
- If the template's own app check (step 2) is canceled or fails (the app was started again after the
  wipe), the uninstall stops there and step 3 doesn't run. The wipe has already run, but the person sees
  neither message, only the template's "is running" one; the exit code is 2. Since #74 it writes event 1004
  with the wipe's result, saying the pairing's removal isn't confirmed and to remove the desktop on the phone
  too (case G below).
- If NSIS ever ran a real uninstall in place (say, if it couldn't copy itself to `%TEMP%`), the hook would
  keep the pairing and say nothing. Not found: the manual doesn't say what NSIS does then, and the NSIS
  download here has no source for the uninstaller's start-up.

**Scripts:**
- `uninstall.exe /S` deletes the pairing, but returns 0 at once, before its temporary copy has run, so a
  failure can't be seen in its exit code, and silent mode shows no box.
- To wait and see the result, run it in place with the switch:
  `uninstall.exe /S /WIPEPAIRING _?=<install folder>`. It wipes, and exits 0 or, if the pairing couldn't be
  removed or confirmed, 2. Run in place, the uninstaller can't delete itself: remove `uninstall.exe` and the
  folder afterwards.
- `uninstall.exe /S _?=<install folder>` without the switch **keeps the pairing**, as for an installer.
  No installer passes `/WIPEPAIRING`.
- **The event log:** every failure the hooks detect, silent or not, writes a Warning, source "VettID Desktop", to the Application
  log: event ID 1001 when the pairing couldn't be removed or confirmed, 1002 when the uninstall was refused
  because another account ran it, 1003 when the program itself couldn't be deleted, and (#74) 1004 when the
  uninstall stopped before it finished: an `Abort` from the app check (`CheckIfAppIsRunning`), when the app is
  running and can't be closed or the person cancels its box (exit 2). Under `/P`, an aborted uninstall's
  progress page stays open, and 1004 is written only once that window is closed: don't use `/P` unattended
  (the script uses `/S`). When an installer runs the old uninstaller in place for an upgrade, an app-check
  abort there writes 1004 too, although that uninstall keeps the pairing by design; the installer then says
  it couldn't uninstall the old version. The source isn't registered (that needs an administrator), so Event Viewer says the
  description isn't found and shows the text as the event's data. Find it with
  `Get-WinEvent -LogName Application -FilterXPath "*[System[Provider[@Name='VettID Desktop']]]"`. Its text (for
  the owner's approval) names no person, folder or account; 1001's and 1003's give the wipe's result code.
  The 1001 text:
  "VettID Desktop was uninstalled, but this desktop's saved pairing couldn't be removed from this computer, or
  its removal couldn't be confirmed (result `<code>`). If %LOCALAPPDATA%\vettid-desktop is still there for the
  account that installed it, delete it, and delete any vettid-desktop entry in that account's Windows
  Credential Manager. Remove this desktop on the phone too." The 1002 text: "VettID Desktop wasn't
  uninstalled: the uninstaller ran as a Windows account that didn't install it, and uninstalling it would
  leave the installing account's saved pairing on this computer. Sign in as the account that installed VettID
  Desktop, and uninstall it there." The 1003 text: "VettID Desktop couldn't be fully removed from this
  computer: its program was still in its folder after the uninstall, and may still be running (result
  `<code>`). Close VettID Desktop, then delete its program folder; for the account that installed it, also
  delete %LOCALAPPDATA%\vettid-desktop if it's there, and any vettid-desktop entry in that account's Windows
  Credential Manager. Remove this desktop on the phone too." The 1004 texts: before the wipe ran (or when it
  is skipped), "VettID Desktop's uninstall stopped before it finished, and nothing was removed: the program
  and this desktop's saved pairing are still on this computer. This usually means VettID Desktop was running
  and couldn't be closed, or the uninstall was canceled. Close VettID Desktop, then try again." After the wipe ran: "VettID Desktop's uninstall stopped before it finished (result `<code>`).
  Removing this desktop's saved pairing was tried, but the program may still be on this computer and may
  still be running, so the pairing's removal isn't confirmed. Close VettID Desktop, then uninstall it again.
  If this desktop was paired, also remove it on the phone."

**Who can run `--uninstall-wipe`:** anyone who can run a program as this Windows user, who can already delete
these files and entries. It opens no window, prints nothing and isn't passed to a running app.

**The mock (makensis 3.11; the uninstaller copied out of the install folder and run with `/S _?=`, as NSIS's
temporary copy runs, so its exit code is seen):**

| Case | Uninstaller exit code | Wipe ran |
|---|---|---|
| 1. wipe code 10, nothing left | 0 | yes |
| 2. wipe code 11 | 0 | yes |
| 3. wipe code 0 (a program that ignores the switch) | 2 | yes |
| 4. wipe code 20 | 2 | yes |
| 5. no program | 2 | no |
| 6. code 10, but `device.enc` there afterwards (as if a running app saved it again) | 2 | yes |
| 6b. code 10, but a `device.enc.tmp-*` there afterwards | 2 | yes |
| 7. in place (`_?=` from the install folder), code 20 | 0 | no |
| 8. `/UPDATE`, code 20 | 0 | no |
| 8b. `/P`, code 20 (no box) | 2 | yes |
| 9. plain `uninstall.exe /S` from the install folder | 0 (the launcher's) | yes (from the temporary copy) |
| 10. another account: neither key records the folder, code 11 (refused: program kept, one event 1002) | 2 | no |
| 10b. only `InstallLocation` records it, code 11 | 0 | yes |
| 10c. only the product key records it, code 11 | 0 | yes |
| 10d. neither key there, code 11 (refused: program kept, one event 1002) | 2 | no |
| 10e. another account under `/P` and under `/S` (refused at once: no progress page left open) | 2 | no |
| 13. the program held open, so it can't be started or deleted (event 1003) | 2 | no (result -1) |
| `installMode` per-machine | the build fails (`!error`) | |
| 11. in place with `/WIPEPAIRING`, code 11 | 0 | yes |
| 11b. in place with `/WIPEPAIRING`, code 10 | 0 | yes |
| 11c. in place with `/WIPEPAIRING`, code 20 (one event logged) | 2 | yes |
| 12. in place with `/WIPEPAIRING /UPDATE`, code 20 | 0 | no |

Every failing case wrote one Warning (level 3) with its text: ID 1001 for 3 to 6b, 8b and 11c, with the
result code, ID 1002 for 10 and 10d, and ID 1003 for 13.

**An uninstall that stops part way (#74, event 1004).** First a test uninstaller (makensis 3.11), under `/S`:
an `Abort` in `Section Uninstall` exits 2 and NSIS calls `un.onUninstFailed`; `SetErrorLevel 2` then `Quit`
(the 1002 path) exits 2 and doesn't call it; a finished uninstall exits 0 and doesn't call it. Then the mock
above, with this branch's hooks, the template's passive auto-close at the end of the uninstall, and a
stand-in app check that aborts on request, before the wipe or only after it:

| Case | Uninstaller exit code | Wipe ran | Events |
|---|---|---|---|
| A. `/S`, the hooks' app check aborts (before the wipe) | 2 | no (program kept) | one 1004, the "nothing was removed" text |
| G. `/S`, the template's app check aborts (after the wipe, code 10) | 2 | yes (program kept) | one 1004, the "result 10 … also remove it on the phone" text |
| B. `/S`, finished, code 11 | 2 | yes | one 1001 (a real pairing was on this machine, so the post-check found `device.enc`, as designed) |
| C. `/S`, finished, code 20 | 2 | yes | one 1001 |
| D. `/S`, another account (the 1002 refusal, `Quit`) | 2 | no | one 1002, no 1004 |
| E. `/S /UPDATE`, the app check aborts | 2 | no | one 1004 |
| F. `/P`, the app check aborts | 2, once the window was closed | no | none while the progress page stayed open (8 s); one 1004 after it was closed |

The real pairing on this machine was only read, never changed: its hash was the same before and after.

**End to end, with a real installer** (`cargo tauri build --debug --bundles nsis`, tauri-cli 2.12.2, a
per-user install; Windows 11 Pro 10.0.26300). The pairing is a fixture: 64 bytes as `device.enc`. No
`vettid-desktop` Credential Manager entry existed, and the unrelated entries were untouched. Exit codes are
the uninstaller's own: from a temporary copy run with `/S _?=<install folder>` and waited for, as NSIS's
launcher does, or from `/S /WIPEPAIRING _?=`. Each uninstall started at least 10 s after the install (see the
last row).

| Case | Exit code | Afterwards |
|---|---|---|
| Fixture there (8 of 8 runs, and at the hook's final head) | 0 | fixture, folder and program gone |
| Fixture held open with share mode 0 (3 of 3, and at the final head) | 2 | fixture kept, program gone |
| Nothing paired | 0 | everything gone |
| The app running (4 of 4 at the final head) | 0 | app closed, fixture and program gone |
| A stand-in writing `device.enc` back as soon as it's gone, for 20 s | 2 | fixture there |
| Another account, simulated: this account's two keys changed to another folder | 2, one event 1002 | refused: fixture, program, `uninstall.exe` and the Apps-list entry kept |
| `/S /WIPEPAIRING _?=`, fixture there | 0 | fixture and program gone |
| `/S /WIPEPAIRING _?=`, fixture held open | 2, one event | fixture kept |
| In place, `/S _?=` | 0 | fixture kept |
| Reinstall over an install: `/S`, `/S /UPDATE`, `/P`, `/P /UPDATE` | 0 | fixture kept |
| Uninstall within about a second of the install | 2 in 2 of 7 runs | once the fixture gone but the program left; once both kept |

The last row and two plain `uninstall.exe /S` runs that took over 60 s (the first uninstall after a build; one
app-running run, not seen again in 4 more) fit Defender scanning the new, unsigned files, but that isn't
confirmed. Each failed safe: nothing was reported removed that wasn't.

Not covered by the mock: the real `CheckIfAppIsRunning` and its plugin, the message boxes, and the real app.

**Reinstall, upgrade and downgrade (read in `installer.nsi`; the same-version silent and passive reinstalls
were run, above):**
- A silent install (`/S`) over an existing install shows no pages, so it never runs the old uninstaller: the
  pairing is kept.
- With `/UPDATE` (with or without `/P`), the installer never runs the old uninstaller.
- Interactive, same version: the default is "Add/Reinstall components", which doesn't uninstall. Choosing
  "Uninstall VettID Desktop" runs the old uninstaller in place, without `/UPDATE`: the pairing is kept.
- Interactive, upgrade or downgrade: the default is "Uninstall before installing", which runs the old
  uninstaller in place, without `/UPDATE`: the pairing is kept, and no message is shown. "Do not uninstall"
  keeps it too. (Downgrades are allowed by default.)
- Passive (`/P`) without `/UPDATE`: the reinstall page's choice is read from a control that isn't there. From
  the code, a same-version reinstall then runs the old uninstaller in place (pairing kept), and an upgrade or
  downgrade doesn't run it. Run here for the same version, `/P` and `/P /UPDATE`: the fixture was kept. An
  upgrade or downgrade under `/P` wasn't run (it needs a second version).
- So the pairing is deleted only by an uninstall itself: from the Apps list, `uninstall.exe` run without
  `_?=`, or in place with `/WIPEPAIRING`.

**Still left behind after uninstall:** `%LOCALAPPDATA%\com.vettid.desktop\EBWebView\` and
`HKCU\Software\vettid\VettID Desktop`, unless "Delete the application data" is ticked (see above). Neither
holds the pairing.

**Another account's elevation** ("Run as administrator" with an administrator's password): the account check
in step 1 refuses the uninstall before anything is removed, so the administrator's own pairing is untouched,
and the app, its uninstaller and the user's Apps-list entry stay (exit 2, event 1002, and the box if someone
is watching). The user can then log out of the desktop, or uninstall as themselves. Tested only by changing
the registry entries in the mock and in a real install; not with a second account.

**IT-managed installs (Intune, SCCM/ConfigMgr, an admin's script):** the installer stays per-user (owner
decision "a" on #72, 2026-11-04). Deploy it in **user context**, so it runs as the person who will use the app:
in Intune, a Win32 app with "Install behavior: User"; in ConfigMgr, a deployment type with "Installation
behavior: Install for user" and "Logon requirement: Only when a user is logged on". The install and the
uninstall then run as that person, without administrator rights, and the uninstall's confirmed wipe of the
saved pairing works as above.
- **Install:** `<setup>.exe /S`. It installs for that user and exits 0. The folder is
  `%LOCALAPPDATA%\VettID Desktop`, unless this user installed it elsewhere before (`/D=`, or by hand): the
  installer reuses the folder in `HKCU\Software\vettid\VettID Desktop`, which an uninstall keeps. So don't
  assume the default folder; the two scripts below read that key, and the Apps-list entry's `InstallLocation`.
- **Uninstall:** `powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File uninstall-vettid.ps1`
  (`scripts/windows/uninstall-vettid.ps1`). It finds the folder and runs
  `uninstall.exe /S /WIPEPAIRING _?=<folder>`, the one form that waits and wipes. It exits 0 only when the
  saved pairing is confirmed gone, and 2 otherwise. A 0 from the uninstaller isn't taken on trust: the script
  then checks that the program, the pairing folder and the Credential Manager entry are gone, so an older
  build or a regression that exits 0 without wiping gives 2. It also exits 2:
  - when the program is there but its `uninstall.exe` is missing or won't run;
  - when the product key and the Apps-list entry name different folders;
  - when it runs as SYSTEM, LocalService or NetworkService (see "Not system context");
  - on any error of its own (fail secure).

  If the program is already gone, nothing can run the wipe. The script then exits 2, without a new event,
  while anything is left in `%LOCALAPPDATA%\vettid-desktop` (hidden files and subfolders included; a folder
  it can't read counts as left) or the earlier format's Credential Manager entry
  (`vettid-desktop/master-key-v1/local`, checked with `cmdkey`) is still there. It exits 0 when neither is.
  `cmdkey`'s output counts as "absent" only in its absent shape (no line but the header naming the target,
  and a `* … *` marker line); anything else counts as present. Only English output was seen here.
  It deletes only the leftover `uninstall.exe`, and only if its version information says VettID Desktop
  (another program's is left as it is), then the folder if that is empty: the install folder can be shared
  with other files (`/D=`). It refuses a
  folder that isn't a full path below a drive or a share. A management tool must count 2 as a failure, which
  Intune's default return codes do.
- **A 2 without an event.** The script's own 2s (listed above) write no event, and some come after the
  uninstaller removed things (its 0 with the pairing left, or the program gone with the pairing left). A 2
  from the uninstaller itself with no event most likely came from a build before #74, where an uninstall that
  stopped part way wrote none (it may have run the wipe already): retry it. Since #74, such a stop writes event
  1004, and the uninstaller's other 2s come with event 1001, 1002 or 1003 (see Scripts). An event can still be
  missing if it couldn't be written, or if the uninstaller was ended (for example a `/P` run whose open
  progress page a tool killed). An uninstall started within a
  second or two of the install returned 2 in 4 of 5 runs here, removed nothing and wrote no event, and the
  next run gave 0 (the row "Uninstall within about a second of the install" above). Every path in the hooks that sets 2 also
  writes an event, so this one comes from elsewhere. The likely cause (a hypothesis) is NSIS's own "aborted"
  code from the template's app-running check (`CheckIfAppIsRunning`, run before the wipe): something holding
  `vettid-desktop.exe` couldn't be closed. Polling the Restart Manager every 250 ms for 8 s after an install
  showed nothing holding the file, though. Every run started 10 s or more after the install gave the expected
  result. Since #74 such a stop writes event 1004, so the next occurrence shows whether it is an abort.
- **Script signing.** The scripts aren't signed. With Intune's "Enforce script signature check: Yes", a
  detection script that can't run counts as **not installed**, and the failure would drop off the dashboard.
  Set it to No, or sign the scripts with your own certificate. An uninstall script that can't run (that
  setting, an execution policy set by Group Policy, Constrained Language Mode, AppLocker or WDAC) gives a
  non-zero exit code, never a false 0.
- **Don't build the command yourself.** A plain `uninstall.exe /S` (Windows' `UninstallString`) returns 0 at
  once, before the wipe has run. `uninstall.exe /S _?=<folder>` without `/WIPEPAIRING` waits but **keeps the
  pairing**, and exits 0 with no event: it is the form an installer uses to update.
- **Detection:** `scripts/windows/detect-vettid.ps1`, as a script detection rule run as the user. It always
  exits 0, and prints a line when detected (Intune's rule for a detection script, from its documentation, not
  checked against a live tenant). It reports the app while the program is there, **or anything of a saved
  pairing is left** (the same checks as the uninstall script), when it can't check, and when it runs as a
  service account. It looks for the program in the default folder, the product key's and `InstallLocation`.
  - A failed wipe can still have removed the program (see the table below). A rule on `vettid-desktop.exe`
    alone would then show "not installed" while the pairing is still on the disk, and the failure would drop
    off the dashboard.
  - With this rule, an uninstall assignment keeps retrying and keeps reporting 2 until the person, or IT,
    deletes `%LOCALAPPDATA%\vettid-desktop` and the Credential Manager entry, as event 1001 says.
  - The other side: while a pairing is left without the program, a required install assignment counts the
    app as installed and doesn't reinstall it.
- **After the uninstall:** run in place, the uninstaller can't delete itself, so `uninstall.exe` and its
  folder stay. The Apps-list entry and the program are gone. The script's next run removes `uninstall.exe`,
  and the folder if it is then empty.
- **Not system context.** Nothing here reaches a person's install when run as SYSTEM:
  - the installer run as SYSTEM installs into SYSTEM's own profile;
  - the scripts refuse to run as SYSTEM, LocalService or NetworkService: the uninstall script exits 2 and
    the detection script reports "installed". Run that way, they would see only that account's own profile
    (`%LOCALAPPDATA%` and `HKCU`), and would say "uninstalled" while every person's pairing stays;
  - `uninstall.exe` run by SYSTEM, or by any account but the installing one, on the person's folder is
    refused (exit 2, event 1002), as above.
- **The person must be signed in** for either to run. An IT department that needs system-context deployment
  isn't supported yet (#72 lists what that would take).
- **The phone:** as with every uninstall, the vault still lists the desktop until it is removed on the phone.

Not tested here: Intune and ConfigMgr themselves (neither is on this machine), so not how they run a `.ps1`
or handle a detection script. The scripts were run as below.

**Run from a standard account** (2026-11-04, Windows 11 Pro 10.0.26300, the #71 debug installer). This was a
temporary local account in Users only, not Administrators, with its own profile. The installer, the
uninstaller and both scripts were run as that account through secondary logon (`Start-Process -Credential
-LoadUserProfile`), and a fixture `device.enc` stood in for a pairing. Each uninstall started 10 s or more
after the install:

| Case | Exit code | Afterwards |
|---|---|---|
| `setup.exe /S` | 0 | installed in that account's `%LOCALAPPDATA%\VettID Desktop`; its `HKCU` product key written |
| `uninstall.exe /S /WIPEPAIRING _?=…` | 0, no event | fixture, program and Apps-list entry gone; the folder left with `uninstall.exe` only; the product key kept |
| The same, with the fixture held open | 2, event 1001 | fixture kept; the program and the Apps-list entry removed |
| Run again after that | 2, event 1001 | fixture kept: the program is gone, so nothing can run the wipe. The person deletes `%LOCALAPPDATA%\vettid-desktop` by hand, as 1001 says |
| `setup.exe /S /D=<a folder holding another app's file>`, then the detection script | 0; detected | detected with no pairing, and with one |
| `uninstall-vettid.ps1` | 0, no event | fixture gone; not detected |
| `uninstall-vettid.ps1` again, nothing installed | 0 | the leftover `uninstall.exe` removed |
| `setup.exe /S` again, without `/D=` | 0 | installed in the earlier folder, not the default one |
| `uninstall-vettid.ps1`, fixture held open | 2, event 1001 | fixture kept; program gone; still detected (pairing left) |
| `uninstall-vettid.ps1` again | 2, no new event | still detected |
| The pairing folder deleted by hand, then `uninstall-vettid.ps1` | 0 | not detected; `uninstall.exe` removed; the other app's file kept |
| A fixture Credential Manager entry `vettid-desktop/master-key-v1/local`, program gone | 2 | detected (legacy entry); after deleting it, 0 and not detected |
| The pairing folder unreadable (a deny-read ACE, then a deny-full-control ACE on the folder) | 2, 2 | detected ("couldn't check") both times |
| The product key set to `C:\`, `C:`, `C:foo`, `\foo`, `relative` (program gone) | 2 each | nothing deleted |
| Only a hidden file in a subfolder of the pairing folder | 2 | detected |
| Program there, `uninstall.exe` not a program | 2 | program kept |
| Program there, `uninstall.exe` missing | 2 | program kept |
| `uninstall.exe` put back, fixture, `uninstall-vettid.ps1`, then again | 0, 0 | fixture gone, not detected; only the other app's file left in the folder |
| `uninstall.exe` replaced by a stand-in that exits 0 and wipes nothing (an older build, a regression) | 2 | fixture kept, still detected; with the real one back, 0 |
| The product key and `InstallLocation` name different folders | 2 | fixture and program kept, detected; once they agree (other case, trailing `\`), 0 |
| Program gone, a leftover `uninstall.exe` that isn't VettID's (a copy of `whoami.exe`) | 0 | kept, and its folder; a leftover VettID `uninstall.exe` is removed (0), and the empty folder |
| Both scripts run as SYSTEM (a one-off scheduled task, run by an administrator) | 2 | detection printed "running as a service account … counted as installed" |
| `windo`'s own profile | – | no install folder before or after |

The events go to the machine's Application log, so a management tool or an administrator can read them. A
non-elevated process can start one as another account but can't wait on it, so the test waited for a result file.

**Run in Windows Sandbox, without a console** (2026-11-06, #72, owner decision "a"). This was a clean Windows 11
Pro 10.0.26300 Sandbox with networking off, so nothing reached the relay or a vault. It had no other apps, and
no Visual C++ runtime (not checked directly; the `0xC0000135` exit below is the evidence). A temporary standard
account (Users only, given "Log on as a batch job") ran every case as a one-off scheduled task: no console and
no signed-in session. A management agent's user-context run instead uses the signed-in person's own token, in
their session, so this was a harsher case, not the same one. It doesn't change "The person must be signed in"
above. The SYSTEM cases were scheduled tasks as SYSTEM. The scripts ran with
`-NoProfile -NonInteractive -ExecutionPolicy Bypass -File`, under the 32-bit host
(`SysWOW64\WindowsPowerShell`, as Intune's agent uses) or the 64-bit one. A dummy `device.enc` (64 fixed bytes,
no keys) stood in for a pairing. Each uninstall started 15 s or more after the install. The debug installer was
built from `dfc539a`; "after #113" means built with `STATIC_VCRUNTIME=true`, which main now sets
(`.cargo/config.toml` and `src-tauri/build.rs`; see "Build"):

| Case | Before #113 | After #113 |
|---|---|---|
| `setup.exe /S` (user) | 0; product key in the user's hive | the same |
| Detection, 64- and 32-bit host (user) | "program True, pairing files True" | the same |
| Detection as SYSTEM | "running as a service account … counted as installed" | the same |
| `uninstall-vettid.ps1` as SYSTEM, 64- and 32-bit host | 2, 2; nothing removed | the same |
| `uninstall.exe /S /WIPEPAIRING _?=<the user's folder>` as SYSTEM | 2, event 1002; nothing removed | the same |
| `uninstall-vettid.ps1`, 32-bit host (user) | **2, event 1001**; program gone, pairing kept, still detected | **0**; program and pairing gone, not detected |
| `uninstall-vettid.ps1` again (user) | 2, no new event | 0; the leftover `uninstall.exe` and the empty folder removed |
| Program gone, dummy pairing left: the script (32-bit), then detection | 2, no event; detected | the same |
| Fresh install, nothing paired, `uninstall-vettid.ps1` (64-bit) | **2, event 1001**; not detected | **0**; not detected |

**Before #113 the uninstall never succeeded on such a PC (#112).** `vettid-desktop.exe` imported
`VCRUNTIME140.dll` and `VCRUNTIME140_1.dll`. Without the Visual C++ runtime it exited `0xC0000135` (DLL not
found) before doing anything, so the wipe didn't run and the uninstaller reported 1001, even with nothing
paired. That is fail-secure (the pairing is kept and nothing says it's gone), but it never got to 0. The app
couldn't open its window either, for the same reason (inferred: the Sandbox runs were non-interactive). Tempe
has the runtime through Visual Studio, which is why the 2026-11-04 run didn't show this.

**Scheduled task versus secondary logon:** to rule out the batch logon as the cause of those 1001s, the same
`CredDeleteW` call the wipe makes, on the absent legacy entry, was run in both. It gave `ERROR_NOT_FOUND` (1168)
in both, so deleting an absent entry, which is what an unpaired wipe does, works the same in a batch logon.
Reading or writing a stored entry in a batch logon wasn't tested.

Still not tested: Intune and ConfigMgr themselves, and an interactive session of the standard account.

## At-rest protection: a second Windows user can't open the pairing (DPAPI, #13)

DESKTOP-REWORK-PLAN §4 "At-rest protectors", "Done": "DPAPI: tested as a second Windows user". Run on 2026-11-06
in Windows Sandbox (Windows 11 Pro 10.0.26300, networking off), with the **real** DPAPI protector and store code:
the ignored test `credential::device_store::tests::dpapi_copy_refusal_step` (debug test binary from `3a4eca5`,
statically linked), run by two temporary standard accounts, A and B (Users only), each as a scheduled task. The
state was a fixed fixture, not a pairing; no vault or relay was involved. The harness is described below the
table.

| Step | Account | Result |
|---|---|---|
| Seal a fixture `device.enc` in A's own folder | A | sealed, protector `dpapi` |
| Open it | A | opened, the same state |
| Read A's file directly | B | denied (access denied) |
| Open A's folder as a store | B | refused before DPAPI: reading the file is denied (os error 5) |
| Seal B's own fixture (a proper store folder), then overwrite B's file with A's bytes | B, an administrator | the copy is B's file, in B's folder |
| Open that copy | B | **refused by DPAPI**: "couldn't open with Windows data protection" (`NotOpened`); the state is not read |
| Open A's own file again | A | opened, the same state |

So a copy of `device.enc` doesn't open for another account on the same computer, even when that account owns the
copy: the data key is wrapped to A's DPAPI master key. The second account stands in for "another machine", as §4
says; a second machine (or VM) wasn't used.

Seen on the way:
- **The administrator couldn't list the ACL** of A's folder or file with `icacls` (access denied): the owner-only
  DACL doesn't include Administrators. The copy was taken with backup rights (`robocopy /B`). An administrator can
  still run code as A, or read A's DPAPI master key while A is logged on; §4 puts that out of scope.
- **What B would be told:** the copied file gives `NotOpened` ("couldn't open its saved pairing with Windows data
  protection just now ... Sign out of your computer and back in to try again. If it keeps happening, remove this
  desktop ... and pair again"). For a copy, signing in again won't help; the re-pair advice that follows is the
  right one. A copied file on another account isn't a real case for the app, which only reads the account's own
  folder.

The harness: in the Sandbox, as its administrator, two accounts were made with random passwords (never written
anywhere) and "Log on as a batch job". Each step ran as a one-off scheduled task as A or B with
`VETTID_COPY_TEST=seal|open` and `VETTID_COPY_TEST_DIR=%LOCALAPPDATA%\vt13`. The administrator copied A's file out
with `robocopy /B` and granted B read on the copy; B wrote it over its own `device.enc`.

## Not tested yet

- Interactive install and uninstall, and what SmartScreen and Defender show a person (left for the owner).
- An upgrade from an older version.
- The uninstall hook's message boxes, an uninstall from Windows' Apps list, and an elevated uninstall as a
  second account.
- A standard (non-administrator) account signed in interactively, and two Windows users using the app on one
  machine. Silent install and uninstall from a standard account were run (see IT-managed installs).
- A deployment from Intune or ConfigMgr itself.
- Anything that needs pairing: the state file and its ACL on disk, sessions, sleep and resume, fast user
  switching, a wrong clock.
- `cargo tauri dev`, and the `webrtc` feature.
- A path with spaces or non-ASCII characters, and WebView2 missing or out of date.
