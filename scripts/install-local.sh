#!/usr/bin/env bash
# Install the locally-built VettID Desktop .app to /Applications.
#
# Builds an unsigned release bundle (or reuses an existing one), strips the
# macOS quarantine attribute so Gatekeeper doesn't block it, and copies it
# into /Applications. After running this you can launch VettID from
# Spotlight or Launchpad like any installed app.
#
# Usage:
#   ./scripts/install-local.sh           # build if missing, then install
#   ./scripts/install-local.sh --rebuild # always rebuild before installing
#   ./scripts/install-local.sh --debug   # install the debug build instead
#   ./scripts/install-local.sh --calls   # build with --features webrtc
#                                         (real audio calls; ~5min first build)
#
# The --calls flag requires libopus + cmake on the system:
#   brew install opus pkg-config cmake
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROFILE="release"
REBUILD=0
WITH_CALLS=0

for arg in "$@"; do
    case "$arg" in
        --rebuild) REBUILD=1 ;;
        --debug)   PROFILE="debug" ;;
        --calls)   WITH_CALLS=1 ;;
        --help|-h)
            grep '^#' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
    esac
done

if [[ "$WITH_CALLS" -eq 1 ]]; then
    # Quick sanity check on the C deps; better to fail fast than after a
    # multi-minute compile when audiopus_sys can't find libopus.
    if ! command -v pkg-config >/dev/null; then
        echo "ERROR: --calls requires pkg-config. Install with: brew install pkg-config" >&2
        exit 1
    fi
    if ! pkg-config --exists opus 2>/dev/null; then
        echo "ERROR: --calls requires libopus. Install with: brew install opus" >&2
        exit 1
    fi
fi

APP_DIR="$REPO_ROOT/src-tauri/target/aarch64-apple-darwin/$PROFILE/bundle/macos/VettID Desktop.app"
DEST="/Applications/VettID Desktop.app"

cd "$REPO_ROOT"

build_args=()
if [[ "$PROFILE" == "debug" ]]; then
    build_args+=(--debug)
fi
build_args+=(--target aarch64-apple-darwin --bundles app)
if [[ "$WITH_CALLS" -eq 1 ]]; then
    build_args+=(--features webrtc)
fi

if [[ "$REBUILD" -eq 1 || ! -d "$APP_DIR" ]]; then
    echo "==> Building $PROFILE bundle (this takes a few minutes the first time)"
    if [[ "$WITH_CALLS" -eq 1 ]]; then
        echo "    (with --features webrtc; first compile of webrtc-rs is slow)"
    fi
    cargo tauri build "${build_args[@]}"
fi

if [[ ! -d "$APP_DIR" ]]; then
    echo "ERROR: bundle not found at $APP_DIR" >&2
    exit 1
fi

echo "==> Installing to $DEST"
if [[ -d "$DEST" ]]; then
    rm -rf "$DEST"
fi
cp -R "$APP_DIR" "$DEST"

echo "==> Stripping quarantine attribute (so Gatekeeper allows the unsigned binary)"
xattr -dr com.apple.quarantine "$DEST" 2>/dev/null || true

echo "==> Re-signing with an ad-hoc identity (lets the Hardened Runtime entitlements stick locally)"
codesign --force --deep --sign - --entitlements src-tauri/entitlements.plist "$DEST" 2>&1 | tail -5

echo
echo "Installed. Launch with:"
echo "  open '$DEST'"
echo
echo "Or just type 'VettID Desktop' in Spotlight."
