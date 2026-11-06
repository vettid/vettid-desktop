#!/usr/bin/env bash
# Puts a signed, notarized macOS DMG on GitHub as a DRAFT release, for the owner
# to read and publish on GitHub (docs/MACOS-RELEASE.md, "Publishing"). It never
# publishes: a draft is visible only to the repository's maintainers.
#
#   VETTID_TEAM_ID=<team> scripts/macos-publish.sh [<dmg>]
#
# The DMG defaults to the one scripts/macos-release.sh made (CARGO_TARGET_DIR,
# else src-tauri/target). The full check (scripts/macos-verify.sh, the team
# included) must pass first. The tag follows the repository's earlier releases:
# v<UTC yyyymmdd-HHMMSS>-macos. Needs the GitHub CLI (gh), signed in.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/src-tauri/target}"
VERSION="$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' src-tauri/tauri.conf.json | head -1)"
DMG="${1:-$TARGET_DIR/aarch64-apple-darwin/release/bundle/dmg/VettID Desktop_${VERSION}_aarch64.dmg}"

[[ -f "$DMG" ]] || { echo "ERROR: no DMG at $DMG" >&2; exit 1; }
[[ -n "${VETTID_TEAM_ID:-}" ]] || { echo "ERROR: VETTID_TEAM_ID is not set (the team the DMG must be signed by)." >&2; exit 1; }
command -v gh >/dev/null || { echo "ERROR: the GitHub CLI (gh) is not installed." >&2; exit 1; }

echo "==> Checking the DMG"
scripts/macos-verify.sh "$DMG"

TAG="v$(date -u +%Y%m%d-%H%M%S)-macos"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
NAME="VettID-Desktop-${VERSION}-macos-arm64.dmg"
ditto "$DMG" "$WORK/$NAME"
(cd "$WORK" && shasum -a 256 "$NAME" > SHA256SUMS.txt)
cat > "$WORK/notes.md" <<NOTES
VettID Desktop ${VERSION} for macOS (Apple silicon), signed with VettID's Developer ID and notarized by Apple.

Check the download before opening it: \`shasum -a 256 -c SHA256SUMS.txt\`.
NOTES

echo "==> Creating the draft release $TAG"
gh release create "$TAG" --draft --target "$(git rev-parse HEAD)" \
    --title "macOS Build $TAG" --notes-file "$WORK/notes.md" \
    "$WORK/$NAME" "$WORK/SHA256SUMS.txt"
echo "Draft created. Read it on GitHub (Releases), then publish it there."
