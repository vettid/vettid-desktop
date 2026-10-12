# Windows machine: setup checklist for VettID work

Do the steps in order. Version numbers are minimums from the repositories as they stand today
(`vettid-desktop`: Tauri 2, Rust 1.75+, Node 18+; `vettid-agent`: Go 1.24). Check each repository's README
when you start, in case they have moved.

## 1. Windows itself

- [ ] Windows 11 (or 10 22H2), fully updated. Note the exact version and build: test reports need it.
- [ ] A standard (non-administrator) account for daily work, and know the administrator password for
      installs. Many Windows problems only show without administrator rights.
- [ ] BitLocker on for the system drive (the machine will hold source code and staging test data).
- [ ] Turn on long paths: in an administrator PowerShell,
      `New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem -Name LongPathsEnabled -Value 1 -PropertyType DWORD -Force`
- [ ] Pick a short working folder without spaces, for example `C:\dev\vettid`.

## 2. Git

- [ ] Install Git for Windows (it also gives Claude Code its Bash).
- [ ] Line endings: `git config --global core.autocrlf false` and `git config --global core.eol lf`.
      (Shell scripts in the repositories break with CRLF.)
- [ ] `git config --global core.longpaths true`
- [ ] Your name and email for commits, and commit signing if you sign on the other machine. Use a key made
      for THIS machine; do not copy the Linux machine's signing key here.
- [ ] GitHub access: install the GitHub CLI (`winget install GitHub.cli`), then `gh auth login`. Prefer a
      token scoped to the repositories this machine needs (`vettid-desktop`, `vettid-agent`; read access to
      `vettid.org` for the specs).

## 3. Toolchains

- [ ] Visual Studio Build Tools 2022 with the "Desktop development with C++" workload (MSVC and the Windows
      SDK). Rust and Tauri need it.
- [ ] Rust: install `rustup` from rustup.rs, default toolchain `stable-x86_64-pc-windows-msvc`. Then
      `cargo install tauri-cli --version "^2"`.
- [ ] Node.js LTS (22): `winget install OpenJS.NodeJS.LTS`.
- [ ] WebView2 Runtime: present on Windows 11; on Windows 10 install the Evergreen runtime from Microsoft.
- [ ] Go 1.24 or newer: `winget install GoLang.Go`.
- [ ] `make` for the agent's Makefile: Git Bash does not include it. Either `winget install GnuWin32.Make`
      (and add it to PATH) or run the Makefile's commands directly (`go build ./...`, `go test ./...`).
- [ ] Optional: WSL, for the odd Linux tool. Do NOT run the VettID Claude Code sessions inside WSL: it would
      build and test Linux binaries.

## 4. Windows Defender

- [ ] Add exclusions for the build folders (administrator PowerShell):
      `Add-MpPreference -ExclusionPath C:\dev\vettid, $env:USERPROFILE\.cargo, $env:USERPROFILE\.rustup, $env:USERPROFILE\go`
      Without this, Rust builds are several times slower.
- [ ] Do NOT turn Defender or SmartScreen off. How they treat an unsigned VettID build is one of the things
      to test.

## 5. Claude Code (native Windows)

- [ ] Install Claude Code for Windows (the native installer or `npm install -g @anthropic-ai/claude-code`),
      and run it from PowerShell or Windows Terminal, not from WSL.
- [ ] Sign in with your account.
- [ ] Permissions: start with the default (ask before running commands). Do not grant blanket permission
      for `git push`, `gh pr merge` or anything that publishes.

## 6. The repositories

- [ ] In `C:\dev\vettid`: `gh repo clone vettid/vettid-desktop`, `gh repo clone vettid/vettid-agent`, and
      `gh repo clone vettid/vettid.org` (read-only use: the specifications in `docs/`).
- [ ] Copy the instructions file that sits beside this checklist to the folder above the checkouts, before
      starting a Claude Code session there:
      `copy C:\dev\vettid\vettid-desktop\docs\windows\CLAUDE-windows.md C:\dev\vettid\CLAUDE.md`.
      Copy it again when it changes in the repository.
- [ ] Check nothing shows as modified straight after cloning (`git status` in each). If files do, the
      line-ending settings of step 2 are not in effect.

## 7. First tasks (in this order; each ends with a short written result)

- [ ] `vettid-agent`: `go build ./...`, `go vet ./...`, `go test ./...`. Record what fails on Windows and
      why (paths, file permissions, signals, sockets). Open one issue with the list.
- [ ] `vettid-desktop`: `npm ci`, `npm run build`, `cargo test` in `src-tauri`, then `cargo tauri dev` and
      `cargo tauri build`. Record build time, what fails, and whether the unsigned installer installs and
      starts for a standard user. One issue with the list.
- [ ] Propose (as an issue, not a change) Windows jobs for each repository's CI on GitHub's Windows runners,
      so routine build-and-test does not depend on this machine being on.

## 8. Not on this machine

- [ ] No production AWS credentials. No AWS credentials at all until a test needs staging access; then a
      staging-only profile.
- [ ] No VettID signing keys (Android, release tags, anything). Test certificates only, clearly named.
- [ ] No copy of the Linux machine's notes, memory or `local/` folder. The repositories are the only link
      between the two machines.

## 9. Later, when there is something to test against staging

- [ ] A staging test member for this machine (the other session creates it and sends the setup details
      through you, not through a repository).
- [ ] A phone with that member's vault for pairing tests (the desktop client pairs through the phone; the
      phone stays in control).
- [ ] Decide with the owner how Windows release builds will be signed before any build leaves this machine.
