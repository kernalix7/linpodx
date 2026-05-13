#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# linpodx uninstaller
#
# Usage:
#   ./uninstall.sh              # Interactive: asks before destructive steps
#   ./uninstall.sh --confirm    # Auto: removes installed files, keeps data
#   ./uninstall.sh --purge      # Full: removes installed files + local data/config
#
# One-liner:
#   curl -fsSL https://raw.githubusercontent.com/kernalix7/linpodx/main/uninstall.sh | bash -s -- --confirm
#   curl -fsSL https://raw.githubusercontent.com/kernalix7/linpodx/main/uninstall.sh | bash -s -- --purge
#
# Podman containers, images, volumes, and system packages are never removed.
###############################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
log() { echo -e "${GREEN}[linpodx]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }
err() { echo -e "${RED}[error]${NC} $*" >&2; }

INSTALL_DIR="${LINPODX_INSTALL_DIR:-$HOME/.local/bin/linpodx-app}"
BIN_DIR="${LINPODX_BIN_DIR:-$HOME/.local/bin}"
AUTO=false
PURGE=false

usage() {
    sed -n '4,18p' "${BASH_SOURCE[0]:-/dev/null}" 2>/dev/null || cat <<'USAGE_EOF'
Usage: uninstall.sh [--confirm] [--purge]
USAGE_EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --confirm)
            AUTO=true
            shift
            ;;
        --purge)
            PURGE=true
            AUTO=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            err "Unknown argument: $1"
            usage >&2
            exit 1
            ;;
    esac
done

if [ "$AUTO" != true ] && [ ! -r /dev/tty ]; then
    err "Interactive uninstall needs a terminal."
    err "Use --confirm to remove installed files or --purge to remove files plus data."
    exit 1
fi

ask() {
    if [ "$AUTO" = true ]; then
        return 0
    fi
    local answer=""
    printf "  %s (y/N): " "$1" >/dev/tty
    read -r answer </dev/tty || answer=""
    [[ "$answer" =~ ^[Yy] ]]
}

remove_file() {
    local path="$1"
    if [ -e "$path" ] || [ -L "$path" ]; then
        rm -f "$path"
        log "Removed $path"
        REMOVED=$((REMOVED + 1))
    fi
}

remove_dir() {
    local path="$1"
    local prompt="$2"
    if [ -d "$path" ]; then
        if ask "$prompt ($path)?"; then
            rm -rf "$path"
            log "Removed $path"
            REMOVED=$((REMOVED + 1))
        fi
    fi
}

echo ""
echo "=========================================="
echo " linpodx uninstaller"
echo "=========================================="
if [ "$PURGE" = true ]; then
    echo " Mode: FULL PURGE (installed files + local data/config)"
else
    echo " Mode: installed files only (data/config kept)"
fi
echo ""

REMOVED=0

if pgrep -u "$(id -u)" -x linpodx-daemon >/dev/null 2>&1; then
    warn "linpodx-daemon is still running. Stop it before reinstalling or purging runtime state."
fi

DESKTOP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
DESKTOP_FILE="$DESKTOP_DIR/linpodx.desktop"
remove_file "$DESKTOP_FILE"
update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
kbuildsycoca6 --noincremental 2>/dev/null || kbuildsycoca5 --noincremental 2>/dev/null || true

for bin in linpodx linpodx-daemon linpodx-gui linpodx-netfilter-helper; do
    remove_file "$BIN_DIR/$bin"
done

remove_dir "$INSTALL_DIR" "Remove linpodx installation"

if [ "$PURGE" = true ]; then
    DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/linpodx"
    CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/linpodx"
    RUNTIME_SOCKET="${XDG_RUNTIME_DIR:-}/linpodx.sock"
    TMP_SOCKET="/tmp/linpodx-$(id -u).sock"

    remove_dir "$DATA_DIR" "Remove data"
    remove_dir "$CONFIG_DIR" "Remove config"
    if [ -n "${XDG_RUNTIME_DIR:-}" ]; then
        remove_file "$RUNTIME_SOCKET"
    fi
    remove_file "$TMP_SOCKET"

    if [ -e /run/linpodx/netfilter.sock ]; then
        rm -f /run/linpodx/netfilter.sock 2>/dev/null || \
            warn "Could not remove /run/linpodx/netfilter.sock; remove it with sudo if needed."
    fi
fi

echo ""
echo " NOT removed: Podman containers, images, volumes, Rust, Podman, or build tools."
if [ "$PURGE" != true ]; then
    echo " To remove local data/config too: ./uninstall.sh --purge"
fi
echo ""
log "Uninstall complete ($REMOVED items removed)"
