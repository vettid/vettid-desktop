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

**Not run in a real installer yet.** The debug installer build was stopped for low memory before NSIS ran.
What was run: the wipe mode's unit tests, and the hook compiled by `makensis` 3.11 into a mock uninstaller
(the template's order, a stand-in for `CheckIfAppIsRunning` without the Tauri plugin, and a stand-in wipe
program that exits with a chosen code); results below. The rest was read in the bundler's template
(tauri-bundler 2.10.2, `installer.nsi`).

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
     running from there"; seen in the mock, case 9 below), so it wipes.
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
   - Anything else (code 20, 0, any other code, the program not starting, or a file there): the uninstaller's
     exit code is 2, and the message that the saved pairing couldn't be removed, with the folder, the
     Credential Manager entry and the phone step.
   - Both texts wait for the owner's approval. The uninstall has finished in every case.
   - Messages are shown only when a person is watching: not under `/S`, and not under `/P` (passive), where a
     box would wait for a click. The exit code is set either way.

**Edge cases:**
- The "paired" message can show when the folder couldn't be read before the wipe (counted as "may be
  paired"), but the wipe then removed it cleanly. That errs on the safe side: the person is told to check the
  phone.
- If the template's own app check (step 2) is cancelled or fails (the app was started again after the
  wipe), the uninstall stops there and step 3 doesn't run. The wipe has already run, but the person sees
  neither message, only the template's "is running" one; the exit code is non-zero.
- If NSIS ever ran a real uninstall in place (say, if it couldn't copy itself to `%TEMP%`), the hook would
  keep the pairing and say nothing. Not found: the manual doesn't say what NSIS does then, and the NSIS
  download here has no source for the uninstaller's start-up.

**Scripts:** `uninstall.exe /S` deletes the pairing, but returns before the temporary copy has finished, so the
exit code 2 can't be seen that way: check that `%LOCALAPPDATA%\vettid-desktop` is gone instead. Running it in
place, `uninstall.exe /S _?=<install folder>`, waits and gives the exit code, but **keeps the pairing**, as for
an installer.

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

Not covered by the mock: the real `CheckIfAppIsRunning` and its plugin, the message boxes, and the real app.

**Reinstall, upgrade and downgrade (read in `installer.nsi`, not run):**
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
  downgrade doesn't run it. To be checked on this machine.
- So the pairing is deleted only by an uninstall itself: from the Apps list, or `uninstall.exe` run without
  `_?=`.

**Still left behind after uninstall:** `%LOCALAPPDATA%\com.vettid.desktop\EBWebView\` and
`HKCU\Software\vettid\VettID Desktop`, unless "Delete the application data" is ticked (see above). Neither
holds the pairing.

**Not covered: another account's elevation.**
- A per-machine install (`installMode: perMachine`, not used) runs its uninstaller elevated. An
  administrator's elevation as another account would wipe that account's folder, not the user's.
- The same applies to this per-user install if its uninstaller is run elevated as another account (say,
  "Run as administrator" with an administrator's password). The wipe then removes that account's pairing, if
  it has one. It reports "nothing paired" (code 11, no message), and the user's own pairing stays.

## Not tested yet

- Interactive install and uninstall, and what SmartScreen and Defender show a person (left for the owner).
- An upgrade from an older version.
- The uninstall hook in a real installer: a fixture `device.enc` removed by `uninstall.exe /S`; a held file
  kept (the exit code isn't observable without `_?=`); a clean uninstall; `/S _?=` in place keeping the
  fixture; a reinstall (`/S`, `/S /UPDATE`, `/P`) keeping it; the app running during the uninstall; the
  message boxes.
- A standard (non-administrator) account, and a second Windows user.
- Anything that needs pairing: the state file and its ACL on disk, sessions, sleep and resume, fast user
  switching, a wrong clock.
- `cargo tauri dev`, and the `webrtc` feature.
- A path with spaces or non-ASCII characters, and WebView2 missing or out of date.
