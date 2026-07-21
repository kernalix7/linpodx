# Installation

[Back to README](../README.md)

linpodx installs from source today. The default installer path pulls the latest
published release; `main` and arbitrary refs are explicit choices.

## Quick install

```bash
curl -fsSL https://raw.githubusercontent.com/kernalix7/linpodx/main/install.sh | bash
```

The script builds release binaries and installs them into `~/.local/bin` by
default:

- `linpodx`
- `linpodx-daemon`
- `linpodx-gui` when GUI dependencies are available
- `linpodx-netfilter-helper` unless disabled

It also writes a desktop entry for the GUI when possible.

## Choose a version

```bash
# Latest stable release
curl -fsSL https://raw.githubusercontent.com/kernalix7/linpodx/main/install.sh | bash

# Latest main HEAD
curl -fsSL https://raw.githubusercontent.com/kernalix7/linpodx/main/install.sh | bash -s -- --main

# Specific public version tag, branch, or commit
curl -fsSL https://raw.githubusercontent.com/kernalix7/linpodx/main/install.sh | bash -s -- --ref v0.1.0
```

Environment-variable equivalents are useful with `curl | bash`:

```bash
LINPODX_REF=main   curl -fsSL https://raw.githubusercontent.com/kernalix7/linpodx/main/install.sh | bash
LINPODX_REF=v0.1.0 curl -fsSL https://raw.githubusercontent.com/kernalix7/linpodx/main/install.sh | bash
```

## Local or offline install

```bash
# Install from an existing checkout
./install.sh --source .

# Install from copied media
./install.sh --source /media/usb/linpodx

# Skip package-manager dependency installation
./install.sh --source . --skip-deps

# Build CLI and daemon only
./install.sh --source . --no-gui

# Skip the privileged L4 egress helper
./install.sh --source . --no-helper
```

Supported environment variables:

| Variable | Meaning |
|----------|---------|
| `LINPODX_SOURCE` | local source tree to copy/build |
| `LINPODX_REF` | tag, branch, or commit to clone |
| `LINPODX_SKIP_DEPS=1` | skip distro package installation |
| `LINPODX_NO_GUI=1` | skip `linpodx-gui` |
| `LINPODX_NO_HELPER=1` | skip `linpodx-netfilter-helper` |
| `LINPODX_INSTALL_DIR` | source/build directory, default `~/.local/bin/linpodx-app` |
| `LINPODX_BIN_DIR` | binary install directory, default `~/.local/bin` |

## Prerequisites

- Linux x86_64 or aarch64.
- Podman 4.6.0 or newer, rootless preferred.
- Rust 1.85+ for source builds.
- `rustfmt` and `clippy` for development checks.
- Optional GUI dependencies for iced/wgpu.
- Optional `nftables`, `nsenter`, and `setcap` for the L4 egress helper.

The installer can install common build dependencies on Debian/Ubuntu, Fedora,
Arch, openSUSE, and Alpine hosts. Use `--skip-deps` when preparing dependencies
through another provisioning system.

## Helper capabilities

The network helper is installed without elevated capabilities unless you opt in:

```bash
./install.sh --source . --setcap-helper
```

That path asks `sudo setcap` to grant `CAP_NET_ADMIN` and `CAP_SYS_ADMIN` to the
helper binary. Without the helper, DNS allowlist filtering still works and L4
egress enforcement reports that the helper was not applied.

## Uninstall

```bash
curl -fsSL https://raw.githubusercontent.com/kernalix7/linpodx/main/uninstall.sh | bash -s -- --confirm
```

Remove local linpodx data and config as well:

```bash
./uninstall.sh --confirm --purge
```

Uninstalling does not remove Podman, Rust, system packages, Podman containers,
images, or volumes.
