#!/usr/bin/env bash
# Check a built VettID Desktop .app or .dmg.
#
# Usage: scripts/macos-verify.sh [--adhoc] <VettID Desktop.app | .dmg>
#
#   (default) full release check: valid signature, hardened runtime, a
#             Developer ID authority, entitlements equal to
#             src-tauri/entitlements.plist (no extra, none missing),
#             no get-task-allow, arm64 only, Gatekeeper (spctl), and the
#             stapled notarization ticket.
#
#   For a DMG, the DMG itself is checked for its staple (`stapler staple`
#   stamps only the DMG); the app inside is not, and `spctl --type execute`
#   on it finds its ticket online. A bare .app is checked for its own staple.
#
#   --adhoc   for an ad-hoc signed build (CI): skips the Developer ID,
#             Gatekeeper and staple checks; all the others still run.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXPECTED="$REPO_ROOT/src-tauri/entitlements.plist"
ADHOC=0
TARGET=""
for arg in "$@"; do
    case "$arg" in
        --adhoc) ADHOC=1 ;;
        --help|-h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) TARGET="$arg" ;;
    esac
done
[[ -n "$TARGET" && -e "$TARGET" ]] || { echo "usage: $0 [--adhoc] <app or dmg>" >&2; exit 2; }

fail=0
ok()  { echo "ok    $*"; }
bad() { echo "FAIL  $*"; fail=1; }
check() { local what="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$what"; else bad "$what"; fi; }

mnt=""; actual=""; ISDMG=0
cleanup() {
    if [[ -n "$mnt" ]]; then hdiutil detach -quiet "$mnt" 2>/dev/null || true; rmdir "$mnt" 2>/dev/null || true; fi
    if [[ -n "$actual" ]]; then rm -f "$actual"; fi
}
trap cleanup EXIT

APP="$TARGET"
if [[ "$TARGET" == *.dmg ]]; then
    ISDMG=1
    check "dmg signature" codesign --verify --strict "$TARGET"
    if [[ "$ADHOC" -eq 0 ]]; then
        check "dmg Gatekeeper (spctl --type open)" spctl --assess --type open --context context:primary-signature "$TARGET"
        check "dmg stapled" xcrun stapler validate "$TARGET"
    fi
    mnt="$(mktemp -d)"
    hdiutil attach -quiet -nobrowse -readonly -mountpoint "$mnt" "$TARGET"
    APP="$(find "$mnt" -maxdepth 1 -name '*.app' | head -1)"
    [[ -n "$APP" ]] || { echo "FAIL  no .app in the dmg"; exit 1; }
fi

check "app signature (codesign --verify --deep --strict)" codesign --verify --deep --strict "$APP"

info="$(codesign -dvv "$APP" 2>&1 || true)"
if grep -E '^CodeDirectory .*flags=.*\(.*runtime' <<< "$info" >/dev/null; then ok "hardened runtime"; else bad "hardened runtime flag missing"; fi

if [[ "$ADHOC" -eq 0 ]]; then
    if grep -q '^Authority=Developer ID Application:' <<< "$info"; then ok "Developer ID authority"; else bad "no Developer ID Application authority"; fi
    check "app Gatekeeper (spctl --type execute)" spctl --assess --type execute "$APP"
    if [[ "$ISDMG" -eq 0 ]]; then check "app stapled" xcrun stapler validate "$APP"; fi
fi

# Entitlements: the signed set must equal the expected file, key and value.
actual="$(mktemp)"
codesign -d --entitlements - --xml "$APP" > "$actual" 2>/dev/null || true
cmp_out="$(python3 -I - "$EXPECTED" "$actual" <<'PY'
import plistlib, sys
def load(p):
    data = open(p, 'rb').read()
    i = data.find(b'<?xml')
    return plistlib.loads(data[i:]) if i >= 0 else {}
want, got = load(sys.argv[1]), load(sys.argv[2])
for k in sorted(set(want) | set(got)):
    if k not in got: print(f"missing: {k}")
    elif k not in want: print(f"EXTRA: {k}")
    elif want[k] != got[k]: print(f"differs: {k}")
PY
)"
if [[ -z "$cmp_out" ]]; then ok "entitlements equal the expected set"; else bad "entitlements differ from src-tauri/entitlements.plist"; sed 's/^/        /' <<< "$cmp_out"; fi
if grep -q 'get-task-allow' "$actual"; then bad "get-task-allow is set"; else ok "no get-task-allow"; fi

# Architecture: arm64 only, every Mach-O in the bundle.
arch_bad=0
while IFS= read -r -d '' f; do
    if file "$f" | grep -q 'Mach-O'; then
        archs="$(lipo -archs "$f" 2>/dev/null || echo unknown)"
        [[ "$archs" == "arm64" ]] || { echo "        $f: $archs"; arch_bad=1; }
    fi
done < <(find "$APP/Contents" -type f -print0)
if [[ "$arch_bad" -eq 0 ]]; then ok "arm64 only"; else bad "not arm64 only"; fi

# Linked libraries of every Mach-O: system paths, or inside the bundle. An
# @rpath entry must resolve through an LC_RPATH inside the bundle to a library
# that exists under Contents/Frameworks.
dyl_bad=0
while IFS= read -r -d '' f; do
    file "$f" | grep -q 'Mach-O' || continue
    rpaths="$(otool -l "$f" | awk '/cmd LC_RPATH/{getline; getline; print $2}')"
    while IFS= read -r rp; do
        [[ -z "$rp" ]] && continue
        case "$rp" in
            @executable_path/*|@loader_path/*) ;;
            *) echo "        $f: rpath outside the bundle: $rp"; dyl_bad=1 ;;
        esac
    done <<< "$rpaths"
    while IFS= read -r lib; do
        case "$lib" in
            /usr/lib/*|/System/*|@executable_path/*|@loader_path/*) ;;
            @rpath/*)
                if [[ ! -e "$APP/Contents/Frameworks/${lib#@rpath/}" ]]; then
                    echo "        $f: $lib is not under Contents/Frameworks"; dyl_bad=1
                fi ;;
            *) echo "        $f: links $lib"; dyl_bad=1 ;;
        esac
    done < <(otool -L "$f" | tail -n +2 | awk '{print $1}')
done < <(find "$APP/Contents" -type f -print0)
if [[ "$dyl_bad" -eq 0 ]]; then ok "no library from outside the system or the bundle"; else bad "libraries outside the system or the bundle"; fi

exit "$fail"
