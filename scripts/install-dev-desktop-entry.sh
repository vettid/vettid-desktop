#!/usr/bin/env bash
# Install a user-level .desktop entry so `cargo tauri dev` shows the
# VettID logo in the GNOME panel / dock instead of a generic "w"
# fallback icon (Linux only).
#
# WHY THIS IS NEEDED
#   A dev build runs the raw target/debug/vettid-desktop binary. On
#   Wayland the shell picks a window's panel icon by matching the
#   window's app_id to an installed .desktop file. A dev binary has no
#   installed .desktop, so GNOME falls back to a generic icon.
#
#   End users are NOT affected: the production install is the
#   Tauri-bundled .deb / .dmg, and Tauri's bundler ships its own
#   .desktop file + hicolor icons (see bundle.icon in tauri.conf.json).
#   This script only patches the *developer's* local dev experience.
#
# USAGE
#   ./scripts/install-dev-desktop-entry.sh           # install
#   ./scripts/install-dev-desktop-entry.sh --remove  # uninstall
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APPS_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
# The basename must equal the app's Wayland app_id (Tauri 2 sets the
# GTK application id from `identifier` in tauri.conf.json) for GNOME to
# associate the running dev window with this entry.
DESKTOP_FILE="$APPS_DIR/com.vettid.desktop.desktop"
ICON="$REPO/src-tauri/icons/256x256.png"
BIN="$REPO/src-tauri/target/debug/vettid-desktop"

if [[ "${1:-}" == "--remove" ]]; then
    rm -f "$DESKTOP_FILE"
    update-desktop-database "$APPS_DIR" 2>/dev/null || true
    echo "Removed $DESKTOP_FILE"
    exit 0
fi

if [[ ! -f "$ICON" ]]; then
    echo "ERROR: icon not found at $ICON" >&2
    exit 1
fi

mkdir -p "$APPS_DIR"
cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Type=Application
Name=VettID Desktop
Comment=VettID desktop client (local dev build)
Icon=$ICON
Exec=$BIN
StartupWMClass=com.vettid.desktop
Categories=Network;
Terminal=false
EOF

update-desktop-database "$APPS_DIR" 2>/dev/null || true
echo "Installed $DESKTOP_FILE"
echo "Icon: $ICON"
echo "Restart the desktop app (fully quit + relaunch cargo tauri dev) so"
echo "the panel re-associates the window with the new entry."
