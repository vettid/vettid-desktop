#!/usr/bin/env bash
# Puts a signed, notarized macOS DMG on GitHub as a DRAFT release, for the owner
# to read and publish on GitHub (docs/MACOS-RELEASE.md, "Publishing"). It never
# publishes: a draft is visible only to the repository's maintainers.
#
#   VETTID_TEAM_ID=<team> scripts/macos-publish.sh [<dmg>]
#
# The DMG defaults to the one scripts/macos-release.sh made (CARGO_TARGET_DIR,
# else src-tauri/target); the tag goes on the commit it was built from. The full check (scripts/macos-verify.sh, the team
# included) must pass first. The tag follows the repository's earlier releases:
# v<UTC yyyymmdd-HHMMSS>-macos. Needs the GitHub CLI (gh), signed in.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"
REPO=vettid/vettid-desktop
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/src-tauri/target}"
HEAD_VERSION="$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' src-tauri/tauri.conf.json | head -1)"
DMG="${1:-$TARGET_DIR/aarch64-apple-darwin/release/bundle/dmg/VettID Desktop_${HEAD_VERSION}_aarch64.dmg}"

[[ -f "$DMG" ]] || { echo "ERROR: no DMG at $DMG" >&2; exit 1; }
[[ -n "${VETTID_TEAM_ID:-}" ]] || { echo "ERROR: VETTID_TEAM_ID is not set (the team the DMG must be signed by)." >&2; exit 1; }
command -v gh >/dev/null || { echo "ERROR: the GitHub CLI (gh) is not installed." >&2; exit 1; }

# The record macos-release.sh wrote beside the DMG: the commit it was built
# from, whether that tree was clean, the calls flag and the DMG's sha256.
[[ -f "$DMG.commit" ]] || { echo "ERROR: no $DMG.commit: build the DMG with scripts/macos-release.sh." >&2; exit 1; }
field() { sed -n "s/^$1=//p" "$DMG.commit" | head -1; }
COMMIT="$(field commit)"; CLEAN="$(field clean)"; CALLS="$(field calls)"; SHA="$(field sha256)"
[[ -n "$COMMIT" && -n "$SHA" ]] || { echo "ERROR: $DMG.commit is incomplete." >&2; exit 1; }
[[ "$CLEAN" == "yes" ]] || { echo "ERROR: the DMG was built from a tree with local changes." >&2; exit 1; }
git fetch -q origin main
git merge-base --is-ancestor "$COMMIT" origin/main || { echo "ERROR: $COMMIT is not on origin/main." >&2; exit 1; }
VERSION="$(git show "$COMMIT:src-tauri/tauri.conf.json" | sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' | head -1)"

# Everything below works on one copy: the file verified, hashed and uploaded is
# the same, and it must be the one recorded at build time.
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
NAME="VettID-Desktop-${VERSION}-macos-arm64.dmg"
ditto "$DMG" "$WORK/$NAME"
(cd "$WORK" && shasum -a 256 "$NAME" > SHA256SUMS.txt)
[[ "$(cut -d' ' -f1 "$WORK/SHA256SUMS.txt")" == "$SHA" ]] || { echo "ERROR: the DMG isn't the one recorded at build time." >&2; exit 1; }

echo "==> Checking the DMG (commit $COMMIT$([[ "$CALLS" == 1 ]] && echo ", calls build"))"
scripts/macos-verify.sh "$WORK/$NAME"

TAG="v$(date -u +%Y%m%d-%H%M%S)-macos"
cat > "$WORK/notes.md" <<NOTES
VettID Desktop ${VERSION} for macOS (Apple silicon), signed with VettID's Developer ID and notarized by Apple.

To check the download before opening it, keep both files' names as downloaded, put them in one folder, and run \`shasum -a 256 -c SHA256SUMS.txt\` there.
NOTES

echo "==> Creating the draft release $TAG"
gh release create "$TAG" -R "$REPO" --draft --target "$COMMIT" \
    --title "macOS Build $TAG" --notes-file "$WORK/notes.md" \
    "$WORK/$NAME" "$WORK/SHA256SUMS.txt"
echo "Draft created. Read it on GitHub (Releases), then publish it there."
