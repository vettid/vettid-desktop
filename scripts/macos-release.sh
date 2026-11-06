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
#   APPLE_SIGNING_IDENTITY    required; the Developer ID Application identity,
#                             by name or by the 40-hex SHA-1 of the certificate
#                             (use the SHA-1 when a renewed certificate sits
#                             beside the old one: `security find-identity -v -p codesigning`)
#   VETTID_TEAM_ID            the team the signature must carry (checked by the
#                             verification). Derived from the "(TEAMID)" of a
#                             name identity; required with a SHA-1 identity
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
if [[ "$IDENTITY" != "-" && "$IDENTITY" != Developer\ ID\ Application:* && ! "$IDENTITY" =~ ^[0-9A-Fa-f]{40}$ ]]; then
    echo "ERROR: APPLE_SIGNING_IDENTITY must be a \"Developer ID Application: ...\" name or a 40-hex SHA-1." >&2
    exit 1
fi
# The team the signature must carry: VETTID_TEAM_ID, else the "(TEAMID)" of a
# Developer ID name. A SHA-1 identity names no team.
TEAM="${VETTID_TEAM_ID:-}"
if [[ -z "$TEAM" && "$IDENTITY" =~ \(([A-Z0-9]{10})\)$ ]]; then TEAM="${BASH_REMATCH[1]}"; fi
if [[ "$IDENTITY" != "-" && -z "$TEAM" ]]; then
    echo "ERROR: with a SHA-1 identity, VETTID_TEAM_ID (the 10-character team) is required." >&2
    exit 1
fi
export VETTID_TEAM_ID="$TEAM"
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
if [[ "$CALLS" -eq 1 ]]; then
    build+=(--features webrtc)
    export LIBOPUS_STATIC=1   # link libopus statically (audiopus_sys), no Homebrew dylib in the app
fi
echo "==> Building the app"
if [[ "$DRY" -eq 0 ]]; then
    if ! env -u APPLE_SIGNING_IDENTITY -u APPLE_CERTIFICATE -u APPLE_CERTIFICATE_PASSWORD "${build[@]}"; then
        echo "ERROR: the build failed. If rustc said \"can't find crate for\" a *_derive or macro crate, a" >&2
        echo "       proc-macro was linked with a mis-aligned string table: check that .cargo/config.toml's" >&2
        echo "       aarch64-apple-darwin linker (scripts/macos-cc) is in use, and remove the target" >&2
        echo "       directory's release/ folder before trying again (docs/MACOS-RELEASE.md)." >&2
        exit 1
    fi
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
    # Frameworks, nested apps and several executables need bundle signing,
    # deepest first. The app has none today; refuse rather than sign them wrongly.
    nested="$(find "$APP/Contents" \( -name '*.framework' -o -name '*.app' -o -name '*.xpc' \) -prune -print -quit)"
    nmain="$(find "$APP/Contents/MacOS" -type f | wc -l | tr -d ' ')"
    if [[ -n "$nested" || "$nmain" -ne 1 ]]; then
        echo "ERROR: the bundle has a framework, nested app, XPC service or more than one executable in Contents/MacOS;" >&2
        echo "       they must be signed deepest first, which this script does not do yet:" >&2
        echo "$nested" >&2
        exit 1
    fi
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
    ditto "$APP" "$stage/$(basename "$APP")"
    ln -s /Applications "$stage/Applications"
    hdiutil create -quiet -volname "VettID Desktop" -srcfolder "$stage" -format UDZO -fs HFS+ "$DMG"
    # The commit the DMG was built from, and whether the tree had changes then
    # (scripts/macos-publish.sh tags that commit and refuses a dirty build).
    { git rev-parse HEAD; git diff --quiet HEAD && echo clean || echo dirty; } > "$DMG.commit"
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
if [[ "$DRY" -eq 0 ]]; then
    # An Invalid result or a network error exits non-zero: carry on to the status check, which says what to do.
    result="$(xcrun notarytool submit "$DMG" --keychain-profile "$PROFILE" --wait --output-format json)" || true
    field() { printf '%s' "$result" | python3 -I -c 'import json,sys
try: print(json.load(sys.stdin).get(sys.argv[1], ""))
except Exception: print("")' "$1"; }
    status="$(field status)"
    subid="$(field id)"
    echo "notarization: $status (submission $subid)"
    if [[ "$status" != "Accepted" ]]; then
        if [[ -z "$subid" ]]; then
            echo "ERROR: no submission was made (see the notarytool output above)." >&2
        else
            echo "ERROR: not accepted. See why with:" >&2
            echo "  xcrun notarytool log $subid --keychain-profile \"$PROFILE\"" >&2
        fi
        exit 1
    fi
else
    echo "+ xcrun notarytool submit \"$DMG\" --keychain-profile \"$PROFILE\" --wait --output-format json"
fi
run xcrun stapler staple "$DMG"

# 6. Verify.
echo "==> Verifying"
run "$REPO_ROOT/scripts/macos-verify.sh" "$DMG"
echo "DMG: $DMG"
