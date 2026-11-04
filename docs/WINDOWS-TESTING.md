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

**Not run on this machine yet.** The debug installer build was stopped for low memory before NSIS ran, so the
hook below hasn't been compiled by `makensis` or tried. The wipe mode's unit tests pass. What follows is the
design and what was read in the bundler's template (tauri-bundler 2.10.2, `installer.nsi`).

**What the uninstaller removes now:** the saved pairing, always, silent `/S` included, but not on an update
(`/UPDATE`). Its hook (`src-tauri/windows/installer-hooks.nsh`, `NSIS_HOOK_PREUNINSTALL`) runs
`vettid-desktop.exe --uninstall-wipe` (`src-tauri/src/uninstall.rs`), which is log-out's local wipe
(`store::wipe_for_logout`), each part confirmed on disk:
- `%LOCALAPPDATA%\vettid-desktop\`, with `device.enc` and any temporary copy of it, and an earlier build's
  `connection.enc`;
- the protectors' external keys (none on Windows: DPAPI keeps nothing outside the file);
- the earlier format's Credential Manager entry `vettid-desktop/master-key-v1/local`.

**What it doesn't do:** it doesn't contact the vault, and doesn't tell the phone. A desktop can't unlink
itself (VAULT-MESSAGING §7.4), and an uninstall shouldn't wait on the network. The vault lists the desktop
until it is removed on the phone.

**The order in the hook:**
1. On `/UPDATE`, nothing: an update keeps the pairing.
2. The running app is closed first (`CheckIfAppIsRunning`; the template checks only after the hook). Otherwise
   it could save the pairing again after the wipe. If it can't be closed, or the person cancels, the uninstall
   stops before anything is removed.
3. The wipe. Its exit code:

| Code | Meaning |
|---|---|
| 0 | Nothing was paired here (no pairing file before the wipe). |
| 10 | A pairing was saved here, and every part is confirmed gone. |
| 20 | Something couldn't be removed, or its removal couldn't be confirmed. Also: no user folder, or a panic. |

4. Interactive: on 10, "This desktop was paired. Remove it on your phone too." On 20, any other code, or if the
   program couldn't be started, a message that the saved pairing couldn't be removed, with the folder, and the
   phone step. Both texts wait for the owner's approval. The uninstall goes on in every case.
5. On 20 or a failure the uninstaller's exit code is 2, silent included, so a script can tell.

A scripted uninstall that needs the exit code has to run the uninstaller in place:
`uninstall.exe /S _?=<install folder>` (NSIS otherwise copies the uninstaller to `%TEMP%` and returns at once; NSIS's documented behaviour, not checked here).

**Who can run `--uninstall-wipe`:** anyone who can run a program as this Windows user, who can already delete
these files and entries. It opens no window, prints nothing and isn't passed to a running app.

**Reinstall, upgrade and downgrade (read in `installer.nsi`, not run):**
- A silent install (`/S`) over an existing install shows no pages, so it never runs the old uninstaller: the
  pairing is kept.
- With `/UPDATE` (with or without `/P`), the installer never runs the old uninstaller.
- Interactive, same version: the default is "Add/Reinstall components", which keeps the pairing. Choosing
  "Uninstall VettID Desktop" runs the old uninstaller without `/UPDATE`, so the pairing is deleted.
- Interactive, upgrade or downgrade: **the default is "Uninstall before installing"**, which runs the old
  uninstaller without `/UPDATE`, so the pairing is deleted, and the person sees the message. "Do not
  uninstall" keeps it. (Downgrades are allowed by default.)
- Passive (`/P`) without `/UPDATE`: the reinstall page's choice is read from a control that isn't there. From
  the code, a same-version reinstall then uninstalls first (pairing deleted), and an upgrade or downgrade
  doesn't. To be checked on this machine.

**Still left behind after uninstall:** `%LOCALAPPDATA%\com.vettid.desktop\EBWebView\` and
`HKCU\Software\vettid\VettID Desktop`, unless "Delete the application data" is ticked (see above). Neither
holds the pairing.

**Not covered:** a per-machine install (`installMode: perMachine`, not used): the uninstaller runs elevated,
and an administrator's elevation as another account would wipe that account's folder, not the user's.

## Not tested yet

- Interactive install and uninstall, and what SmartScreen and Defender show a person (left for the owner).
- An upgrade from an older version.
- The uninstall hook end to end: a fixture `device.enc` removed by `/S`; a held file reported (exit code 2) and
  kept; a clean uninstall; a reinstall (`/S`, `/S /UPDATE`, `/P`) keeping the fixture.
- A standard (non-administrator) account, and a second Windows user.
- Anything that needs pairing: the state file and its ACL on disk, sessions, sleep and resume, fast user
  switching, a wrong clock.
- `cargo tauri dev`, and the `webrtc` feature.
- A path with spaces or non-ASCII characters, and WebView2 missing or out of date.
