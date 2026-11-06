#!/usr/bin/env bash
# Build, sign (Developer ID), notarize and staple the macOS DMG.
#
# Usage:
#   APPLE_SIGNING_IDENTITY="Developer ID Application: <name> (<team>)" \
#     ./scripts/macos-release.sh [--calls] [--sign-only] [--dry-run]
#
#   --calls      build with --features webrtc (needs: brew install opus pkg-config cmake)
#   --sign-only  build, sign and make the DMG, but do not notarize or staple.
#                Needs no notary credentials. "-" (ad-hoc) is accepted as the
#                identity only here and under --dry-run.
#   --dry-run    print the steps and check the inputs; build nothing
#
# Environment:
#   APPLE_SIGNING_IDENTITY    required; the Developer ID Application identity
#   VETTID_NOTARY_PROFILE     notarytool keychain profile (default: vettid-notary)
#   VETTID_PROVISION_PROFILE  optional path to a provisioning profile; embedded
#                             as Contents/embedded.provisionprofile before
#                             signing (needed once the entitlements include
#                             keychain-access-groups)
#
# Output: <target dir>/aarch64-apple-darwin/release/bundle/dmg/ (CARGO_TARGET_DIR, else src-tauri/target)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET=aarch64-apple-darwin
ENTITLEMENTS="$REPO_ROOT/src-tauri/entitlements.plist"
# Cargo's target directory: CARGO_TARGET_DIR when set (a CI cache, another disk), else src-tauri/target.
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/src-tauri/target}"
BUNDLE_DIR="$TARGET_DIR/$TARGET/release/bundle"
CALLS=0 SIGN_ONLY=0 DRY=0

for arg in "$@"; do
    case "$arg" in
        --calls) CALLS=1 ;;
        --sign-only) SIGN_ONLY=1 ;;
        --dry-run) DRY=1 ;;
        --help|-h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

IDENTITY="${APPLE_SIGNING_IDENTITY:-}"
PROFILE="${VETTID_NOTARY_PROFILE:-vettid-notary}"
PROVISION="${VETTID_PROVISION_PROFILE:-}"

if [[ -z "$IDENTITY" ]]; then
    echo "ERROR: APPLE_SIGNING_IDENTITY is not set (\"Developer ID Application: <name> (<team>)\")." >&2
    exit 1
fi
if [[ "$IDENTITY" == "-" && "$SIGN_ONLY" -eq 0 && "$DRY" -eq 0 ]]; then
    echo "ERROR: an ad-hoc identity cannot be notarized; use --sign-only." >&2
    exit 1
fi
if [[ "$IDENTITY" != "-" && "$IDENTITY" != Developer\ ID\ Application:* ]]; then
    echo "ERROR: APPLE_SIGNING_IDENTITY must be a \"Developer ID Application: ...\" identity." >&2
    exit 1
fi
if [[ -n "$PROVISION" && ! -f "$PROVISION" ]]; then
    echo "ERROR: VETTID_PROVISION_PROFILE does not name a file." >&2
    exit 1
fi

run() {
    echo "+ $*"
    if [[ "$DRY" -eq 0 ]]; then "$@"; fi
}

cd "$REPO_ROOT"

# 1. The app bundle. Tauri is told no identity (the variable is not passed on),
#    so it signs ad-hoc; the real signature is made below, after the optional
#    provisioning profile is in the bundle.
build=(cargo tauri build --target "$TARGET" --bundles app)
[[ "$CALLS" -eq 1 ]] && build+=(--features webrtc)
echo "==> Building the app"
if [[ "$DRY" -eq 0 ]]; then
    env -u APPLE_SIGNING_IDENTITY -u APPLE_CERTIFICATE -u APPLE_CERTIFICATE_PASSWORD "${build[@]}"
else
    echo "+ ${build[*]}"
fi

APP="$BUNDLE_DIR/macos/VettID Desktop.app"
DMG_DIR="$BUNDLE_DIR/dmg"
VERSION="$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' src-tauri/tauri.conf.json | head -1)"
DMG="$DMG_DIR/VettID Desktop_${VERSION}_aarch64.dmg"

# 2. Provisioning profile, if one is given.
if [[ -n "$PROVISION" ]]; then
    echo "==> Embedding the provisioning profile"
    run cp "$PROVISION" "$APP/Contents/embedded.provisionprofile"
fi

# 3. Sign: nested code first, the app last. Hardened runtime and a secure
#    timestamp (an ad-hoc signature has no timestamp).
sign_opts=(--force --sign "$IDENTITY" --options runtime)
if [[ "$IDENTITY" == "-" ]]; then sign_opts+=(--timestamp=none); else sign_opts+=(--timestamp); fi

echo "==> Signing the app"
if [[ "$DRY" -eq 0 ]]; then
    while IFS= read -r -d '' f; do
        if file "$f" | grep -q 'Mach-O' && [[ "$f" != "$APP/Contents/MacOS/"* ]]; then
            codesign "${sign_opts[@]}" "$f"
        fi
    done < <(find "$APP/Contents" -type f -print0)
fi
run codesign "${sign_opts[@]}" --entitlements "$ENTITLEMENTS" "$APP"

# 4. The DMG: the app and a link to /Applications, signed.
echo "==> Making the DMG"
if [[ "$DRY" -eq 0 ]]; then
    mkdir -p "$DMG_DIR"
    rm -f "$DMG"
    stage="$(mktemp -d)"
    trap 'rm -rf "$stage"' EXIT
    cp -R "$APP" "$stage/"
    ln -s /Applications "$stage/Applications"
    hdiutil create -quiet -volname "VettID Desktop" -srcfolder "$stage" -format UDZO -fs HFS+ "$DMG"
else
    echo "+ hdiutil create ... \"$DMG\""
fi
run codesign "${sign_opts[@]}" "$DMG"

# 5. Notarize and staple.
if [[ "$SIGN_ONLY" -eq 1 ]]; then
    echo "==> --sign-only: not notarized"
    run "$REPO_ROOT/scripts/macos-verify.sh" --adhoc "$DMG"
    echo "DMG: $DMG"
    exit 0
fi
echo "==> Notarizing (profile: $PROFILE)"
run xcrun notarytool submit "$DMG" --keychain-profile "$PROFILE" --wait
run xcrun stapler staple "$DMG"

# 6. Verify.
echo "==> Verifying"
run "$REPO_ROOT/scripts/macos-verify.sh" "$DMG"
echo "DMG: $DMG"
