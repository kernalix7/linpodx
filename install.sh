#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# linpodx installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/kernalix7/linpodx/main/install.sh | bash
#   or: ./install.sh [--main] [--ref TAG] [--source PATH] [--skip-deps]
#                    [--no-gui] [--no-helper] [--setcap-helper] [--help]
#
# Installs release binaries to ~/.local/bin and keeps a source/build checkout at
# ~/.local/bin/linpodx-app. No root is required unless dependency installation
# or --setcap-helper is requested.
#
# Version selection (default: latest GitHub release):
#   --main             Install from git main HEAD.
#   --ref TAG          Install a specific tag/branch/commit.
#
# Local-path options:
#   --source PATH      Copy and build linpodx from PATH instead of git clone.
#   --skip-deps        Skip distro dependency installation and fail if required
#                      tools are missing.
###############################################################################

REQUIRED_RUST="1.85"
INSTALL_DIR="${LINPODX_INSTALL_DIR:-$HOME/.local/bin/linpodx-app}"
BIN_DIR="${LINPODX_BIN_DIR:-$HOME/.local/bin}"
REPO_URL="https://github.com/kernalix7/linpodx.git"
REPO_API="https://api.github.com/repos/kernalix7/linpodx"

LINPODX_SOURCE="${LINPODX_SOURCE:-}"
LINPODX_REF="${LINPODX_REF:-}"
LINPODX_SKIP_DEPS="${LINPODX_SKIP_DEPS:-}"
LINPODX_NO_GUI="${LINPODX_NO_GUI:-}"
LINPODX_NO_HELPER="${LINPODX_NO_HELPER:-}"
LINPODX_SETCAP_HELPER="${LINPODX_SETCAP_HELPER:-}"
LINPODX_NO_DESKTOP="${LINPODX_NO_DESKTOP:-}"
LINPODX_ASSUME_YES="${LINPODX_ASSUME_YES:-}"
CARGO_TOOLCHAIN=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
log() { echo -e "${GREEN}[linpodx]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }
err() { echo -e "${RED}[error]${NC} $*" >&2; }

usage() {
    sed -n '4,24p' "${BASH_SOURCE[0]:-/dev/null}" 2>/dev/null || cat <<'USAGE_EOF'
linpodx installer - see install.sh header for full usage.

Flags:
  --main              Install from git main HEAD
  --ref TAG           Install a specific tag/branch/commit
  --source PATH       Copy from local repo instead of git clone
  --skip-deps         Skip distro dependency installation
  --no-gui            Do not build/install linpodx-gui or desktop entry
  --no-helper         Do not build/install linpodx-netfilter-helper
  --setcap-helper     Grant helper CAP_NET_ADMIN + CAP_SYS_ADMIN via sudo setcap
  --install-dir DIR   Source/build checkout directory
  --bin-dir DIR       Binary installation directory
  -h, --help          Print this help and exit
USAGE_EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --main|--dev)
            LINPODX_REF="main"
            shift
            ;;
        --ref)
            LINPODX_REF="${2:-}"
            shift 2
            ;;
        --source)
            LINPODX_SOURCE="${2:-}"
            shift 2
            ;;
        --skip-deps)
            LINPODX_SKIP_DEPS=1
            shift
            ;;
        --no-gui)
            LINPODX_NO_GUI=1
            shift
            ;;
        --no-helper)
            LINPODX_NO_HELPER=1
            shift
            ;;
        --setcap-helper)
            LINPODX_SETCAP_HELPER=1
            shift
            ;;
        --no-desktop)
            LINPODX_NO_DESKTOP=1
            shift
            ;;
        --install-dir)
            INSTALL_DIR="${2:-}"
            shift 2
            ;;
        --bin-dir)
            BIN_DIR="${2:-}"
            shift 2
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

detect_distro() {
    if [ -f /etc/os-release ]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        echo "$ID"
    else
        echo "unknown"
    fi
}

pkg_name() {
    local dep="$1"
    case "$DISTRO" in
        ubuntu|debian|linuxmint|pop)
            case "$dep" in
                pkg-config) echo "pkg-config" ;;
                libcap) echo "libcap2-bin" ;;
                nsenter|util-linux) echo "util-linux" ;;
                nft|nftables) echo "nftables" ;;
                *) echo "$dep" ;;
            esac
            ;;
        fedora|rhel|centos|rocky|alma)
            case "$dep" in
                pkg-config) echo "pkgconf-pkg-config" ;;
                libcap) echo "libcap" ;;
                nsenter|util-linux) echo "util-linux" ;;
                nft|nftables) echo "nftables" ;;
                *) echo "$dep" ;;
            esac
            ;;
        arch|manjaro|endeavouros)
            case "$dep" in
                gcc|make) echo "base-devel" ;;
                pkg-config) echo "pkgconf" ;;
                libcap) echo "libcap" ;;
                nsenter|util-linux) echo "util-linux" ;;
                nft|nftables) echo "nftables" ;;
                *) echo "$dep" ;;
            esac
            ;;
        opensuse*|sles)
            case "$dep" in
                pkg-config) echo "pkg-config" ;;
                libcap) echo "libcap-progs" ;;
                nsenter|util-linux) echo "util-linux" ;;
                nft|nftables) echo "nftables" ;;
                *) echo "$dep" ;;
            esac
            ;;
        *)
            echo "$dep"
            ;;
    esac
}

package_manager() {
    if command -v zypper >/dev/null 2>&1; then
        echo "zypper"
    elif command -v dnf >/dev/null 2>&1; then
        echo "dnf"
    elif command -v apt-get >/dev/null 2>&1; then
        echo "apt-get"
    elif command -v pacman >/dev/null 2>&1; then
        echo "pacman"
    else
        return 1
    fi
}

install_pkg() {
    local dep="$1"
    local actual
    actual="$(pkg_name "$dep")"
    log "Installing $actual..."

    case "$(package_manager 2>/dev/null || true)" in
        zypper) sudo zypper install -y "$actual" ;;
        dnf) sudo dnf install -y "$actual" ;;
        apt-get) sudo apt-get install -y "$actual" ;;
        pacman) sudo pacman -S --noconfirm "$actual" ;;
        *)
            err "No supported package manager found. Install '$actual' manually."
            return 1
            ;;
    esac
}

add_missing() {
    local dep="$1"
    local item
    for item in "${MISSING[@]:-}"; do
        [ "$item" = "$dep" ] && return
    done
    MISSING+=("$dep")
}

version_ge() {
    [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]
}

detect_local_source() {
    if [ -n "$LINPODX_SOURCE" ]; then
        return
    fi
    local src="${BASH_SOURCE[0]:-}"
    local dir
    if [ -n "$src" ] && [ -f "$src" ]; then
        dir="$(cd "$(dirname "$src")" && pwd)"
        if [ -f "$dir/Cargo.toml" ] && [ -d "$dir/crates/linpodx-cli" ]; then
            LINPODX_SOURCE="$dir"
        fi
    fi
}

validate_source() {
    if [ -n "$LINPODX_SOURCE" ]; then
        if [ ! -d "$LINPODX_SOURCE" ]; then
            err "--source path does not exist or is not a directory: $LINPODX_SOURCE"
            exit 1
        fi
        if [ ! -f "$LINPODX_SOURCE/Cargo.toml" ] || [ ! -d "$LINPODX_SOURCE/crates/linpodx-cli" ]; then
            err "--source path does not look like a linpodx repo: $LINPODX_SOURCE"
            exit 1
        fi
        log "Using local source: $LINPODX_SOURCE"
    fi
}

collect_missing_deps() {
    MISSING=()

    command -v podman >/dev/null 2>&1 || add_missing "podman"
    command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 || add_missing "gcc"
    command -v make >/dev/null 2>&1 || add_missing "make"
    command -v pkg-config >/dev/null 2>&1 || command -v pkgconf >/dev/null 2>&1 || add_missing "pkg-config"

    if ! command -v rustup >/dev/null 2>&1 && ! command -v cargo >/dev/null 2>&1; then
        add_missing "rustup"
    fi
    if [ -z "$LINPODX_SOURCE" ]; then
        command -v git >/dev/null 2>&1 || add_missing "git"
        command -v curl >/dev/null 2>&1 || add_missing "curl"
    fi
    if [ -n "$LINPODX_SETCAP_HELPER" ] && [ -z "$LINPODX_NO_HELPER" ]; then
        command -v nft >/dev/null 2>&1 || add_missing "nftables"
        command -v nsenter >/dev/null 2>&1 || add_missing "util-linux"
        command -v setcap >/dev/null 2>&1 || add_missing "libcap"
    fi
}

install_missing_deps() {
    collect_missing_deps
    if [ "${#MISSING[@]}" -eq 0 ]; then
        log "All dependencies OK"
        return
    fi

    if [ -n "$LINPODX_SKIP_DEPS" ]; then
        err "--skip-deps is set but required tools are missing: ${MISSING[*]}"
        exit 1
    fi

    local pm
    pm="$(package_manager 2>/dev/null || true)"
    if [ -z "$pm" ]; then
        err "Missing dependencies: ${MISSING[*]}"
        err "No supported package manager found; install them manually and re-run."
        exit 1
    fi

    log "Missing: ${MISSING[*]}"
    echo ""
    echo "  The following packages will be installed via $pm:"
    local dep
    for dep in "${MISSING[@]}"; do
        echo "    - $(pkg_name "$dep")"
    done
    echo ""

    local answer=""
    if [ -n "$LINPODX_ASSUME_YES" ]; then
        answer="Y"
    elif [ -r /dev/tty ]; then
        printf "  Proceed with installation? (Y/n): " >/dev/tty
        read -r answer </dev/tty || answer=""
    else
        err "Missing dependencies: ${MISSING[*]}"
        err "No terminal is available for confirmation. Install them manually, re-run with --skip-deps, or set LINPODX_ASSUME_YES=1."
        exit 1
    fi
    if [[ "$answer" =~ ^[Nn] ]]; then
        err "Aborted. Install dependencies manually and try again."
        exit 1
    fi

    local fail=0
    for dep in "${MISSING[@]}"; do
        if ! install_pkg "$dep"; then
            warn "Failed to install: $(pkg_name "$dep")"
            fail=$((fail + 1))
        fi
    done
    if [ "$fail" -gt 0 ]; then
        err "$fail package(s) failed to install. Fix manually and re-run."
        exit 1
    fi
}

ensure_rust() {
    if command -v rustup >/dev/null 2>&1; then
        log "Installing Rust toolchain $REQUIRED_RUST via rustup..."
        rustup toolchain install "$REQUIRED_RUST"
        CARGO_TOOLCHAIN="+$REQUIRED_RUST"
        return
    fi

    if command -v cargo >/dev/null 2>&1; then
        local version
        version="$(cargo --version | sed -n 's/^cargo \([0-9][0-9.]*\).*/\1/p')"
        if [ -n "$version" ] && version_ge "$version" "$REQUIRED_RUST"; then
            log "Using cargo $version"
            CARGO_TOOLCHAIN=""
            return
        fi
        err "Rust/Cargo >= $REQUIRED_RUST is required (found ${version:-unknown})."
        err "Install rustup from https://rustup.rs and re-run."
        exit 1
    fi

    err "Rust/Cargo not found. Install rustup from https://rustup.rs and re-run."
    exit 1
}

cargo_cmd() {
    if [ -n "$CARGO_TOOLCHAIN" ]; then
        cargo "$CARGO_TOOLCHAIN" "$@"
    else
        cargo "$@"
    fi
}

copy_from_local() {
    local src="$1"
    local src_real
    local install_parent
    src_real="$(cd "$src" && pwd -P)"
    install_parent="$(dirname "$INSTALL_DIR")"
    mkdir -p "$install_parent"

    if [ -d "$INSTALL_DIR" ] && [ "$(cd "$INSTALL_DIR" && pwd -P)" = "$src_real" ]; then
        log "Building from existing installation checkout"
        return
    fi

    rm -rf "$INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"

    if git -C "$src" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        (
            cd "$src"
            git ls-files -z --cached --others --exclude-standard
        ) | while IFS= read -r -d '' path; do
            mkdir -p "$INSTALL_DIR/$(dirname "$path")"
            cp -P "$src/$path" "$INSTALL_DIR/$path"
        done
    else
        local item
        for item in Cargo.toml Cargo.lock rust-toolchain.toml crates tests bench-tools \
            bench-results examples docs README.md LICENSE SECURITY.md CHANGELOG.md \
            CODE_OF_CONDUCT.md CONTRIBUTING.md deny.toml install.sh uninstall.sh; do
            if [ -e "$src/$item" ]; then
                cp -R "$src/$item" "$INSTALL_DIR/"
            fi
        done
    fi
}

resolve_ref() {
    if [ -n "$LINPODX_REF" ]; then
        echo "$LINPODX_REF"
        return
    fi
    if ! command -v curl >/dev/null 2>&1; then
        echo "main"
        return
    fi
    local latest
    latest="$(curl -fsSL "$REPO_API/releases/latest" 2>/dev/null \
        | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        | head -n1 || true)"
    if [ -n "$latest" ]; then
        echo "$latest"
    else
        echo "main"
    fi
}

checkout_source() {
    mkdir -p "$(dirname "$INSTALL_DIR")"

    if [ -n "$LINPODX_SOURCE" ]; then
        log "Copying linpodx from --source: $LINPODX_SOURCE"
        copy_from_local "$LINPODX_SOURCE"
        return
    fi

    local ref
    ref="$(resolve_ref)"
    if [ "$ref" = "main" ]; then
        log "Installing from git main"
    else
        log "Installing release/ref: $ref"
    fi

    if [ -d "$INSTALL_DIR/.git" ]; then
        log "Updating existing checkout..."
        git -C "$INSTALL_DIR" fetch --quiet --tags --prune origin
        git -C "$INSTALL_DIR" checkout --quiet --detach "$ref" \
            || git -C "$INSTALL_DIR" checkout --quiet "$ref"
        if [ "$ref" = "main" ]; then
            git -C "$INSTALL_DIR" reset --hard --quiet "origin/$ref"
        fi
    else
        rm -rf "$INSTALL_DIR"
        log "Cloning from GitHub..."
        git clone --quiet "$REPO_URL" "$INSTALL_DIR"
        git -C "$INSTALL_DIR" fetch --quiet --tags --prune origin
        git -C "$INSTALL_DIR" checkout --quiet --detach "$ref" \
            || git -C "$INSTALL_DIR" checkout --quiet "$ref"
        if [ "$ref" = "main" ]; then
            git -C "$INSTALL_DIR" reset --hard --quiet "origin/$ref"
        fi
    fi
}

build_and_install() {
    local build_args=(build --release -p linpodx-cli -p linpodx-daemon)
    if [ -z "$LINPODX_NO_GUI" ]; then
        build_args+=(-p linpodx-gui)
    fi
    if [ -z "$LINPODX_NO_HELPER" ]; then
        build_args+=(-p linpodx-netfilter)
    fi

    log "Building release binaries..."
    (
        cd "$INSTALL_DIR"
        cargo_cmd "${build_args[@]}"
    )

    install -d "$BIN_DIR"
    install -m 0755 "$INSTALL_DIR/target/release/linpodx" "$BIN_DIR/linpodx"
    install -m 0755 "$INSTALL_DIR/target/release/linpodx-daemon" "$BIN_DIR/linpodx-daemon"
    if [ -z "$LINPODX_NO_GUI" ]; then
        install -m 0755 "$INSTALL_DIR/target/release/linpodx-gui" "$BIN_DIR/linpodx-gui"
    fi
    if [ -z "$LINPODX_NO_HELPER" ]; then
        install -m 0755 "$INSTALL_DIR/target/release/linpodx-netfilter-helper" \
            "$BIN_DIR/linpodx-netfilter-helper"
    fi
}

install_desktop_entry() {
    if [ -n "$LINPODX_NO_GUI" ] || [ -n "$LINPODX_NO_DESKTOP" ]; then
        return
    fi

    local desktop_dir="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
    local desktop_file="$desktop_dir/linpodx.desktop"
    mkdir -p "$desktop_dir"
    cat >"$desktop_file" <<DESKTOP_EOF
[Desktop Entry]
Type=Application
Name=linpodx
GenericName=Container Manager
Comment=Linux-native container management
Exec=$BIN_DIR/linpodx-gui
Icon=utilities-terminal
Terminal=false
Categories=System;Utility;
StartupNotify=true
DESKTOP_EOF

    update-desktop-database "$desktop_dir" 2>/dev/null || true
    kbuildsycoca6 --noincremental 2>/dev/null || kbuildsycoca5 --noincremental 2>/dev/null || true
    log "Installed desktop launcher: $desktop_file"
}

configure_helper_caps() {
    if [ -z "$LINPODX_SETCAP_HELPER" ] || [ -n "$LINPODX_NO_HELPER" ]; then
        return
    fi
    log "Granting netfilter helper capabilities via sudo..."
    sudo setcap cap_net_admin,cap_sys_admin+ep "$BIN_DIR/linpodx-netfilter-helper"
    sudo install -d -m 0755 /run/linpodx
}

print_summary() {
    if ! echo "$PATH" | grep -q "$BIN_DIR"; then
        warn "$BIN_DIR is not in PATH"
        warn "Add this to your shell rc file:"
        warn "  export PATH=\"$BIN_DIR:\$PATH\""
    fi

    echo ""
    echo " Location: $INSTALL_DIR"
    echo " Binaries: $BIN_DIR"
    echo ""
    echo " Usage:"
    echo "   linpodx-daemon                 # start local daemon"
    echo "   linpodx ps --all               # query containers"
    if [ -z "$LINPODX_NO_GUI" ]; then
        echo "   linpodx-gui                    # open desktop GUI"
    fi
    if [ -z "$LINPODX_NO_HELPER" ]; then
        echo "   linpodx-netfilter-helper --daemon-uid \"\$(id -u)\""
    fi
    echo ""
    log "Installation complete!"
}

DISTRO="$(detect_distro)"
ARCH="$(uname -m)"
log "Detected distro: $DISTRO"
log "Detected arch: $ARCH"

detect_local_source
validate_source
install_missing_deps
ensure_rust
checkout_source
build_and_install
install_desktop_entry
configure_helper_caps
print_summary
