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

**Why the two copies were treated differently (found in run 2):** they aren't the same file. After it builds the
bundle, Tauri writes a 3-byte bundle-type marker into the executable. The installed copy says `NSS` (NSIS) and
the build-folder copy says `UNK`. Otherwise the two are byte for byte the same (`cmp`: 3 bytes differ, at one
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

## Paired state after uninstall (read in the code, not run)

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
- Logging out first wipes both parts (`device_store` wipe, each part confirmed) and ends the session at the
  vault (`device.session.end`). It doesn't unlink the desktop: a desktop can't unlink itself
  (VAULT-MESSAGING §7.4), only the phone can.

AG3 (#13) replaces the Credential Manager entry with a DPAPI-wrapped key kept inside `device.enc`. That leaves
one part to remove. Whether the uninstaller should remove it, or tell the person to log out or unlink first,
is for the owner to decide.

## Not tested yet

- Interactive install and uninstall, and what SmartScreen and Defender show a person (left for the owner).
- An upgrade from an older version.
- A standard (non-administrator) account, and a second Windows user.
- Anything that needs pairing: the state file and its ACL on disk, sessions, sleep and resume, fast user
  switching, a wrong clock.
- `cargo tauri dev`, and the `webrtc` feature.
- A path with spaces or non-ASCII characters, and WebView2 missing or out of date.
