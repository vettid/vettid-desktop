# Instructions for Claude Code on the Windows machine

This file lives in `vettid-desktop` at `docs/windows/CLAUDE-windows.md`; the setup checklist is beside it.
Put a copy where the Windows session will read it at start: as `CLAUDE.md` in the folder that holds the
VettID checkouts on that machine (for example `C:\dev\vettid\CLAUDE.md`), so it applies to every repository
under it. Each repository's own `CLAUDE.md` still applies; where the two disagree, this file wins for work done
on this machine.

## What this machine is for

This is the Windows test and build machine for VettID. The main development line (specifications, vault,
relay, member API, Android, releases, deploys) runs on the owner's Linux machine in another Claude Code
session. That session and this one share nothing except the GitHub repositories.

Work that belongs here:
1. Building and running `vettid-desktop` (Tauri 2, Rust, Svelte 5, Vite) and `vettid-agent` (Go) on Windows.
2. Fixing what is specific to Windows, as ordinary pull requests.
3. Hands-on tests that CI cannot do: install, upgrade, uninstall, first run, sleep and resume, a second
   Windows user, antivirus and SmartScreen behaviour, where keys and files end up.

Work that does not belong here: anything in `vettid.org` (specs, stacks, sites), `vettid-vault`,
`vettid-relay`, `vettid-push`, `vettid-android`; releases; deploys. If a Windows finding needs a change
there, open an issue in that repository that says what was seen and stop.

## State of the two projects (October 2026)

Neither is released, and both pre-date the current vault design.
- `vettid-agent` (the Agent Connector) is being rebuilt for the current vault and relay and does not work
  with them yet.
- `vettid-desktop` is not released; its rework plans are in the repository (`DESKTOP-REWORK-PLAN.md`,
  `CONNECTIONS-REWORK-PLAN.md`).

So the first job on this machine is modest: make both build and pass their tests on Windows, and write down
what breaks. Do not start the rework here.

The specifications are in `github.com/vettid/vettid.org` under `docs/`. They decide; the code follows.
Read, do not edit: `VAULT-MESSAGING.md` (devices, pairing, sessions, LEASH grants), `RELAY-PROTOCOL.md`,
`MEMBER-API.md`, `VAULT-LOCK.md`.

## Standing rules (the owner's; they apply to every session)

- **Staging only.** Never point a build at production services, never deploy, never publish a release, never
  tag. Production changes are made by the owner or on their explicit go-ahead, in the other session.
- **No secrets on this machine beyond what a test needs.** No production AWS credentials. No signing keys.
  If a task seems to need either, stop and ask the owner. Never print a secret, a token, a PIN or a key to
  the terminal, a log, a commit, an issue or a pull request.
- **Signing.** Builds made here are unsigned or signed with a throwaway test certificate that is clearly
  named as such. VettID's real signing keys stay with the owner. A Windows release build is a decision for
  the owner, not something to set up on the way.
- **Fail secure.** When something cannot be confirmed (a lock, a deletion, a revocation, a pairing), the app
  must behave as if the safe outcome has NOT happened, keep trying, and say so plainly to the person. Never
  show "locked", "removed" or "sent" on a guess.
- **Security paths get a second pair of eyes.** A change to locking, unlocking, pairing, key handling, key
  storage, attestation, session set-up or anything a member relies on for safety is reviewed independently
  before it merges, even when CI is green. Say what a failure looks like, before and after the change.
- **Specifications and plans need the owner's approval.** App, fix and test pull requests may merge on green
  unless they touch a security path.
- **Email addresses** are never shared with connections or agents, and never written to logs.
- **A vault has no export.** History export is the only exception. Do not add ways to copy vault content
  out, including for debugging.
- **Agents (LEASH)**: an agent acts only within grants the owner signed; when the vault is locked or held,
  agents pause. Do not add a bypass, a cache of secrets, or a "test mode" that weakens this in a build a
  member could run.
- **Report faithfully.** Say what was run and what was only read. If a test failed or was skipped, say so
  with the output. Do not describe something as working because it compiled.

## How to work on this machine

- **Pull requests, small ones.** Branch from the default branch; never push to it. One concern per PR. The
  PR body says what was tested on this machine and how (Windows version, toolchain versions, commands,
  result).
- **Windows-specific code stays behind the platform boundary** (`#[cfg(windows)]`, `_windows.go` files, the
  Tauri platform configuration). Do not change shared behaviour to suit Windows without saying so in the PR.
- **Do not reformat files or change line endings.** If Git shows whole-file changes, stop: the line-ending
  setting is wrong (see the setup checklist).
- **Record findings in the repository,** as issues or in the PR, not in files on this machine. The other
  session cannot see this disk.
- **Things worth checking on Windows, and reporting even when they work:**
  - where the app keeps keys and state (DPAPI? the Credential Manager? a file under `%APPDATA%`? with which
    ACL), and what another Windows user or an administrator on the same machine can read;
  - what is left behind after uninstall;
  - behaviour across sleep, hibernate, fast user switching and a locked workstation (sessions with the
    vault are time-limited: the app must not treat a stale session as live);
  - the system clock being wrong by a few minutes (the relay refuses stale timestamps);
  - WebView2 missing or out of date; a path with spaces or non-ASCII characters; a roaming profile;
  - Defender or SmartScreen blocking or quarantining a build, and what the user sees;
  - the agent as a Windows service versus a console program: start, stop, crash, restart, log location.
- **Memory and disk.** Rust and Vite builds are heavy. Run one build at a time. Stop background compilers
  when done.

## When unsure

Stop and ask the owner. A wrong guess on this machine is cheap; a wrong guess merged into a security path is
not.
