<div align="center">

# linpodx

### Containers, AI sandboxes, GUI apps. Native on Linux.

<p>Linux-native container management with a Rust CLI, desktop GUI,<br>
AI-agent sandboxing, and lightweight multi-distro environments.</p>

<pre><code># Latest stable release (default)
curl -fsSL https://raw.githubusercontent.com/kernalix7/linpodx/main/install.sh | bash

# Latest main HEAD (development; may be unstable)
curl -fsSL https://raw.githubusercontent.com/kernalix7/linpodx/main/install.sh | bash -s -- --main

# Uninstall (keeps local linpodx data; pass --purge to wipe data/config)
curl -fsSL https://raw.githubusercontent.com/kernalix7/linpodx/main/uninstall.sh | bash -s -- --confirm</code></pre>

[![Pre-alpha](https://img.shields.io/badge/status-pre--alpha-orange?style=for-the-badge)](#status-pre-alpha)
[![Latest](https://img.shields.io/github/v/release/kernalix7/linpodx?include_prereleases&style=for-the-badge&label=latest&color=2962FF)](https://github.com/kernalix7/linpodx/releases)

[![license](https://img.shields.io/github/license/kernalix7/linpodx?style=flat-square&color=blue)](LICENSE)
[![rust](https://img.shields.io/badge/rust-1.85%2B-b7410e?style=flat-square&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![tests](https://img.shields.io/badge/tests-829%20%2B%2054%20ignored-2EA44F?style=flat-square)](#testing)
[![CI](https://img.shields.io/github/actions/workflow/status/kernalix7/linpodx/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/kernalix7/linpodx/actions/workflows/ci.yml)

###### Works on

[![openSUSE](https://img.shields.io/badge/openSUSE-73BA25?style=flat-square&logo=opensuse&logoColor=white)](https://www.opensuse.org/)
[![Fedora](https://img.shields.io/badge/Fedora-294172?style=flat-square&logo=fedora&logoColor=white)](https://fedoraproject.org/)
[![Debian](https://img.shields.io/badge/Debian-A81D33?style=flat-square&logo=debian&logoColor=white)](https://www.debian.org/)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?style=flat-square&logo=ubuntu&logoColor=white)](https://ubuntu.com/)
[![RHEL family](https://img.shields.io/badge/RHEL%20%2F%20Alma%20%2F%20Rocky-EE0000?style=flat-square&logo=redhat&logoColor=white)](https://www.redhat.com/)
[![Arch](https://img.shields.io/badge/Arch-1793D1?style=flat-square&logo=archlinux&logoColor=white)](https://archlinux.org/)

<sub>**English** &nbsp;·&nbsp; [한국어](docs/README.ko.md) &nbsp;·&nbsp; [Changelog](CHANGELOG.md) &nbsp;·&nbsp; [Architecture](docs/architecture.md) &nbsp;·&nbsp; [Contributing](CONTRIBUTING.md) &nbsp;·&nbsp; [Security](SECURITY.md)</sub>

</div>

---

> ### Status: Pre-alpha
> linpodx is preparing its first `v0.1.0` release. Phase 0..17 implementation is in-tree: local daemon, CLI, iced GUI, AI-agent sandbox, audit log, snapshots, host-stdio bridge, GUI passthrough, multi-distro templates, remote daemon, plugin hooks, cluster scaffolding, and snapshot encryption hardening. The current release gate is conservative: 829 unit tests pass, 54 host/runtime-dependent integration tests are ignored by default, and the project still expects sharp edges outside development workstations.

**No Docker Desktop VM.** linpodx talks to rootless Podman on Linux, keeps the daemon local by default, and exposes the same container state through CLI, GUI, and event subscriptions.

## Why linpodx

| Tool | Gap linpodx targets |
|------|---------------------|
| Docker Desktop | Heavy Linux story, license friction, weak desktop passthrough, no AI-agent sandbox model |
| Rancher Desktop | Kubernetes-first; too much machinery for daily local container work |
| Podman Desktop | Strong general container UI, but not built around sandbox approvals, snapshots, or multi-distro shells |
| distrobox / toolbx | Great lightweight environments, but CLI-first and light on policy/audit controls |
| Full VMs | Strong isolation, but slower boot and heavier CPU/RAM/storage footprint |

linpodx bundles a desktop container manager, a safe AI-agent execution sandbox, and GUI-integrated Linux environments into one Linux-native toolchain.

## Use cases

1. **Desktop container management** — daily container, image, volume, and network work through a CLI and GUI backed by the same daemon.
2. **AI-agent sandbox execution** — run risky agentic shell workflows in containers with approval gates, audit trails, resource limits, snapshots, and rollback.
3. **Lightweight distro shells** — keep Ubuntu, Fedora, Arch, Debian, Alpine, and NixOS environments side-by-side without full VMs.
4. **GUI-integrated containers** — forward Wayland/X11, audio, GPU, clipboard, DBus, theme, and HiDPI state into selected containers.
5. **Local-first remote access** — stay Unix-socket local by default, then opt into WebSocket, bearer tokens, mTLS, and cert pinning when needed.

## Quick install

One-liner, any supported Linux distro:

```bash
curl -fsSL https://raw.githubusercontent.com/kernalix7/linpodx/main/install.sh | bash
```

Install from a local checkout or offline source tree:

```bash
git clone https://github.com/kernalix7/linpodx.git
cd linpodx
./install.sh --source .
```

Optional L4 egress helper capabilities:

```bash
./install.sh --source . --setcap-helper
```

Uninstall:

```bash
curl -fsSL https://raw.githubusercontent.com/kernalix7/linpodx/main/uninstall.sh | bash -s -- --confirm
```

Use `--purge` to remove local linpodx data/config as well. Podman containers, images, volumes, Rust, Podman, and system packages are left alone.

## Choose a version

The installer follows the linpodx release posture: default to the latest published release, make `main` and arbitrary refs explicit.

```bash
# Latest stable release (default)
curl -fsSL https://raw.githubusercontent.com/kernalix7/linpodx/main/install.sh | bash

# Latest main HEAD
curl -fsSL https://raw.githubusercontent.com/kernalix7/linpodx/main/install.sh | bash -s -- --main

# Specific tag, branch, or commit
curl -fsSL https://raw.githubusercontent.com/kernalix7/linpodx/main/install.sh | bash -s -- --ref v0.1.0

# Env-var equivalents, useful under curl | bash
LINPODX_REF=main   curl -fsSL https://raw.githubusercontent.com/kernalix7/linpodx/main/install.sh | bash
LINPODX_REF=v0.1.0 curl -fsSL https://raw.githubusercontent.com/kernalix7/linpodx/main/install.sh | bash
```

## Offline / source install

```bash
# Copy from a local clone instead of git clone
./install.sh --source /media/usb/linpodx

# Skip distro dependency installation; fail early if tools are missing
./install.sh --skip-deps

# Build CLI + daemon only
./install.sh --source . --no-gui

# Skip the privileged L4 egress helper
./install.sh --source . --no-helper
```

Environment variables mirror the flags: `LINPODX_SOURCE`, `LINPODX_REF`, `LINPODX_SKIP_DEPS`, `LINPODX_NO_GUI`, `LINPODX_NO_HELPER`, `LINPODX_INSTALL_DIR`, and `LINPODX_BIN_DIR`.

## Prerequisites

- Linux x86_64 or aarch64, with Wayland or X11 for the desktop GUI.
- Podman 4.6.0 or newer, rootless preferred.
- Rust 1.85+ for source builds. `rust-toolchain.toml` pins the workspace baseline.
- `rustfmt` and `clippy` for development.
- Runtime libraries for the iced GUI (most distros ship these by default — see
  [Troubleshooting](#troubleshooting) if `linpodx-gui` fails to start):
  - `libwayland-client0` and `libxkbcommon0` on Wayland sessions
  - `libx11-6` and `libxcb1` on X11 sessions
  - `libegl1` and `libgl1` for wgpu rendering
- Optional: `nftables`, `util-linux` / `nsenter`, and `setcap` for the privileged L4 egress helper.

The helper is intentionally opt-in because it needs `CAP_NET_ADMIN` and `CAP_SYS_ADMIN`:

```bash
sudo setcap cap_net_admin,cap_sys_admin+ep ~/.local/bin/linpodx-netfilter-helper
sudo install -d -m 0755 /run/linpodx
linpodx-netfilter-helper --daemon-uid "$(id -u)" &
```

Without the helper, DNS allowlist filtering still works and `network egress apply` reports `helper_applied: false`.

## Launch

```bash
linpodx-daemon                 # Start the local Unix-socket daemon
linpodx ps --all               # Query containers from the CLI
linpodx-gui                    # Open the desktop dashboard
```

The daemon binds `$XDG_RUNTIME_DIR/linpodx.sock` by default, falling back to `/tmp/linpodx-$UID.sock`.

## Key features

<table>
<tr><td width="50%">

**Desktop container manager**
- Container lifecycle: create, start, stop, restart, pause, remove
- Image, volume, and network management through one CLI/API surface
- Live event stream for daemon state changes
- iced desktop GUI with containers, images, volumes, networks, audit, snapshots, sessions, plugins, and cluster views
- JSON/table output for shell-friendly workflows

</td><td width="50%">

**AI-agent sandbox**
- YAML sandbox profiles with capability drops, read-only rootfs, mount allowlists, and network modes
- Approval gates for sensitive actions such as host mounts, capability adds, and bridge tool calls
- Tamper-evident audit log with hash chaining
- Session timeline that merges container lifetime, audit events, and bridge events
- Snapshot before/after workflows for rollback-friendly experiments

</td></tr>
<tr><td width="50%">

**GUI passthrough**
- Wayland and X11 socket forwarding
- PipeWire / PulseAudio audio passthrough
- GPU access through DRI-oriented device grants
- DBus session bus, clipboard, HiDPI, and theme environment propagation
- Per-profile and per-container passthrough configuration

</td><td width="50%">

**Multi-distro environments**
- Ubuntu, Fedora, Arch, Debian, Alpine, and NixOS templates
- Optional `systemd` inside supported container profiles
- VM mode with persistent home volume, auto-restart, and host UID/GID mapping
- Template inspection, build, create, enter, and remove commands
- Lighter than a full VM for day-to-day Linux environment testing

</td></tr>
<tr><td width="50%">

**Snapshots & storage**
- Podman commit snapshots with list, rollback, remove, prune, and async job APIs
- Branch and diff helpers for comparing snapshot state
- Overlayfs and BTRFS backend scaffolding
- Snapshot encryption and key-rotation plumbing
- Metrics and audit hooks for long-running jobs

</td><td width="50%">

**Remote, plugins, and cluster**
- Local Unix socket by default, optional WebSocket remote daemon
- mTLS, token auth, and client certificate pinning for remote access
- Wasmtime plugin registry with signed-plugin verification
- Cluster gossip, membership, and Raft state-machine scaffolding
- Kubernetes read/write adapter surface for workstation automation

</td></tr>
</table>

See [CHANGELOG.md](CHANGELOG.md) for the full v0.1.0 feature list.

## Common workflows

Container lifecycle:

```bash
linpodx-daemon &
linpodx run --name demo docker.io/library/alpine:latest sleep 30
linpodx ps --all
linpodx logs demo
linpodx rm -f demo
```

Sandbox profile:

```bash
mkdir -p ~/.config/linpodx/profiles
cp examples/profiles/read-only-net-disabled.yaml ~/.config/linpodx/profiles/
linpodx sandbox reload
linpodx run --sandbox read-only-net-disabled --name probe alpine sleep 5
linpodx sandbox audit --profile read-only-net-disabled
```

Snapshots:

```bash
linpodx run --name work alpine sleep 600
linpodx snapshot create --label before-experiment work
linpodx snapshot list
linpodx snapshot rollback --new-name work-restored 1
```

Multi-distro shell:

```bash
linpodx distro list
linpodx distro build --kind ubuntu --include git,curl,python3
linpodx distro create --kind ubuntu --vm-mode my-ubuntu
linpodx distro enter my-ubuntu
```

Remote daemon:

```bash
linpodx-daemon --socket /tmp/lp.sock --remote-listen 127.0.0.1:8443 --remote-token dev
linpodx --remote ws://127.0.0.1:8443/ipc --token dev ps --all
```

## Remote daemon

Run a daemon with a WebSocket listener when another process or host needs access to the same JSON-RPC surface:

```bash
linpodx-daemon \
  --socket /tmp/lp.sock \
  --remote-listen 127.0.0.1:8443 \
  --remote-token hunter2

linpodx --remote ws://127.0.0.1:8443/ipc --token hunter2 version
linpodx --remote 127.0.0.1:8443 --token hunter2 ps
```

Environment variables work too:

```bash
export LINPODX_REMOTE=ws://daemon.internal:8443/ipc
export LINPODX_REMOTE_TOKEN=hunter2
linpodx ps
```

Keep plain `ws://` behind loopback, a firewall, or an SSH tunnel. For untrusted networks, use TLS and client certificates.

## mTLS and client pinning

Generate local test certificates:

```bash
linpodx daemon cert generate --out ./certs
```

Start a remote daemon with TLS and client-certificate verification:

```bash
linpodx-daemon \
  --socket /tmp/lp.sock \
  --remote-listen 127.0.0.1:8443 \
  --remote-token hunter2 \
  --tls-cert ./certs/server.pem \
  --tls-key ./certs/server-key.pem \
  --client-ca ./certs/ca.pem \
  --pin-clients
```

Then connect with the client certificate:

```bash
linpodx \
  --remote wss://127.0.0.1:8443/ipc \
  --token hunter2 \
  --client-cert ./certs/client.pem \
  --client-key ./certs/client-key.pem \
  --client-ca ./certs/ca.pem \
  ps --all
```

Pinned clients are managed through `linpodx daemon pin-client {add,list,remove,tofu}`. TOFU enrollment can be enabled for controlled first-contact windows, then disabled once the expected clients are pinned.

## Web UI

The daemon can serve a browser UI on the same listener as the remote `/ipc` endpoint:

```bash
linpodx-daemon \
  --socket /tmp/lp.sock \
  --remote-listen 127.0.0.1:8443 \
  --remote-token hunter2
```

Open `http://127.0.0.1:8443/ui/` and provide the bearer token. The Web UI shares the remote listener's security posture, so use mTLS for untrusted networks.

The Leptos/WASM UI is opt-in at build time:

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli
LINPODX_WASM=1 cargo build -p linpodx-daemon --release
```

Without `LINPODX_WASM=1`, the daemon serves the lightweight built-in fallback UI. For air-gapped terminal modals, vendor xterm.js assets at build time:

```bash
LINPODX_VENDOR_XTERM=1 cargo build --release -p linpodx-daemon
```

## Security profiles

Compile a sandbox profile's seccomp and AppArmor artifacts:

```bash
linpodx sandbox profile compile read-only-net-disabled --secprofile-out /tmp/secprofiles
```

When the profile has `syscall_allowlist` or `apparmor_extra`, the daemon applies the generated files through Podman's `--security-opt` flags. Hosts without `apparmor_parser` keep the seccomp half and skip AppArmor.

SELinux profile synthesis is available on hosts with `checkmodule`, `semodule_package`, `semodule`, and SELinux in enforcing/permissive mode. Set `selinux_type: <type_name>` in a sandbox profile to synthesize, package, install, and apply a per-profile label. Hosts without SELinux tooling fall back gracefully.

## Interactive exec

Interactive PTY mode is available over the WebSocket remote listener:

```bash
linpodx --remote 127.0.0.1:8443 --token hunter2 \
  exec -it <container_id> -- bash
```

The daemon allocates a PTY pair, the CLI switches the local terminal into raw mode, and `/pty/<bridge_id>` carries the interactive stream. Each bridge is single-use and closes when the process exits or the WebSocket disconnects.

## Kubernetes adapter

linpodx can call the standard Kubernetes discovery chain (`KUBECONFIG`, `~/.kube/config`, or in-cluster service account) through the daemon:

```bash
linpodx k8s pod create ./pod.yaml -n my-ns
cat pod.yaml | linpodx k8s pod create - -n my-ns
linpodx k8s pod delete hello -n my-ns
linpodx k8s ns create my-ns
linpodx k8s scale web --replicas 3 -n prod
```

Cluster-mutating operations are recorded in the local audit log.

## Benchmarks

Criterion benches live under the relevant crates and have a baseline in `bench-results/`:

```bash
cargo bench -p linpodx-runtime --bench snapshot --bench container --bench cgroup \
  -p linpodx-mcp --bench policy \
  -p linpodx-plugin --bench invoke -- --quick
```

The bench workflow compares quick-mode means against the checked-in baseline and flags large regressions without failing the build.

## Roadmap

| Version | Focus |
|---------|-------|
| `v0.1.x` | Stabilize the local daemon, installer, GUI dashboard, and core sandbox flows |
| `v0.2.x` | Packaging, systemd user units, Web UI polish, and remote daemon hardening |
| `v0.3.x` | More distro workflows, richer GUI actions, and plugin author ergonomics |
| `v0.4.x` | Multi-host/cluster usability and stronger operational recovery |

## Non-goals

- Replacing Kubernetes, Rancher, k3s, or k0s.
- First-class Windows/macOS hosts; linpodx is Linux-native.
- Hiding Podman. The runtime remains visible, debuggable, and compatible with normal Podman workflows.
- Removing user judgment from sensitive operations. Approval gates and audit logs are part of the product, not a temporary limitation.

## Architecture

```text
linpodx CLI / GUI / Web UI
          |
          | JSON-RPC 2.0 over Unix socket or WebSocket
          v
linpodx-daemon
  |-- Podman runtime adapter
  |-- sandbox policy manager
  |-- audit/event/session/snapshot managers
  |-- plugin registry
  |-- remote daemon transport
  `-- cluster / distro / passthrough adapters
          |
          v
Rootless Podman + Linux desktop integrations
```

| Crate | Purpose |
|-------|---------|
| `linpodx-cli` | `linpodx` command-line client |
| `linpodx-daemon` | Unix-socket API server, dispatcher, event bus, remote transport |
| `linpodx-gui` | iced desktop dashboard |
| `linpodx-runtime` | Podman wrapper, images, volumes, networks, snapshots, passthrough |
| `linpodx-sandbox` | profiles, approvals, audit, sessions, snapshot triggers |
| `linpodx-common` | shared IPC, state, errors, database migrations |
| `linpodx-distro` | distro templates and VM-mode helpers |
| `linpodx-plugin` | Wasmtime plugin loading, manifests, signing, registry |
| `linpodx-cluster` | gossip, Raft, Kubernetes adapter |
| `linpodx-webui` | browser UI bundle for the remote daemon |

## Documentation

| Document | What's inside |
|----------|---------------|
| [CHANGELOG.md](CHANGELOG.md) | v0.1.0 release notes and pre-release phase history |
| [docs/README.ko.md](docs/README.ko.md) | Korean overview |
| [docs/INSTALL.md](docs/INSTALL.md) | Installer, uninstall, offline/source install, prerequisites |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | First-run snags and recovery steps |
| [docs/RELEASE.md](docs/RELEASE.md) | Versioning, tag discipline, release checklist |
| [docs/architecture.md](docs/architecture.md) | System architecture, data flow, trust boundaries |
| [docs/scenarios/ai-agent-sandbox.md](docs/scenarios/ai-agent-sandbox.md) | Sandbox workflow |
| [docs/scenarios/gui-app.md](docs/scenarios/gui-app.md) | GUI passthrough scenario |
| [docs/scenarios/multi-distro-shell.md](docs/scenarios/multi-distro-shell.md) | Multi-distro shell scenario |
| [docs/scenarios/plugin-author.md](docs/scenarios/plugin-author.md) | Plugin author workflow |
| [docs/scenarios/remote-daemon.md](docs/scenarios/remote-daemon.md) | Remote daemon workflow |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup and workflow |
| [SECURITY.md](SECURITY.md) | Security disclosure process |

## Supported distros

| Distro | Package manager | Status |
|--------|-----------------|--------|
| openSUSE Tumbleweed / Leap / Slowroll | zypper | Supported |
| Fedora / RHEL family / AlmaLinux / Rocky | dnf | Supported |
| Debian / Ubuntu / Linux Mint / Pop!_OS | apt | Supported |
| Arch / Manjaro / EndeavourOS | pacman | Supported |

Podman 4.6.0 or newer is required. Rust 1.85+ is required for source builds.

## Testing

```bash
cargo +1.85 fmt --all -- --check
cargo +1.85 clippy --workspace --all-targets --all-features -- -D warnings
cargo +1.85 build --workspace
cargo +1.85 test --workspace
cargo +1.85 doc --workspace --no-deps
```

Ignored integration tests touch host runtimes, networking helpers, Podman lifecycle, or external services:

```bash
cargo +1.85 test --workspace -- --ignored --test-threads=1
```

## Development

```bash
git clone https://github.com/kernalix7/linpodx.git
cd linpodx
rustup toolchain install 1.85 --component clippy --component rustfmt
cargo +1.85 build --workspace
```

Run from a checkout without installing:

```bash
cargo +1.85 run -p linpodx-daemon
cargo +1.85 run -p linpodx-cli -- ps --all
cargo +1.85 run -p linpodx-gui
```

## Snapshot encryption

Snapshots can be stored encrypted at rest with AES-256-GCM. Encryption is opt-in
through environment variables read by the daemon at startup:

| Variable | Meaning |
|----------|---------|
| `LINPODX_SNAPSHOT_ENCRYPT_PASSPHRASE` | Derive the encryption key from this passphrase. Required for the passphrase path. |
| `LINPODX_SNAPSHOT_KEY` | Use this raw base64-encoded 32-byte key directly. Mutually exclusive with the passphrase. |
| `LINPODX_SNAPSHOT_KDF` | `argon2id` (default; OWASP 2023 baseline `m=19456, t=2, p=1`) or `sha256-rounds-1k` for backward compatibility. |

When neither variable is set, snapshots are written unencrypted (the original
v0.1.0 behaviour). Existing snapshots written under one KDF keep their original
KDF tag; use `linpodx snapshot key-rotate` and `linpodx snapshot re-encrypt-all`
to migrate the on-disk corpus. Inspect a single snapshot with:

```bash
linpodx snapshot encryption-status <snapshot_id>
```

## Troubleshooting

Common first-run snags:

- **`daemon: connection refused`** — start the daemon (`linpodx-daemon &`).
- **`podman: command not found` / version too old** — install Podman 4.6.0+
  for your distro.
- **`linpodx-gui` panics with `wgpu` / `wayland` / `EGL`** — install the
  runtime libraries listed under [Prerequisites](#prerequisites).
- **`snapshot decryption failed`** — match the same
  `LINPODX_SNAPSHOT_ENCRYPT_PASSPHRASE` / `LINPODX_SNAPSHOT_KEY` /
  `LINPODX_SNAPSHOT_KDF` the snapshot was created with.
- **`plugin signature rejected`** — install the publisher's public key under
  `~/.config/linpodx/plugins/keys/`, or set `LINPODX_ALLOW_UNSIGNED_PLUGINS=1`
  for local development.
- **Container starts but has no network egress** — the active sandbox profile
  is in `network: kind: allowlist`; widen it or run without `--sandbox`.

See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for the full list
(daemon connectivity, podman runtime, GUI startup, snapshot encryption +
key-rotation, plugin signatures + revocation, remote daemon mTLS + pinning,
cluster leader routing, sandbox approvals).

## Security

linpodx defaults to rootless Podman and local Unix-socket IPC. Optional features such as the netfilter helper, remote daemon listener, mTLS, certificate pinning, host mounts, and plugin loading expand the trust boundary; enable them deliberately and review [SECURITY.md](SECURITY.md) for reporting guidance.

## License

[MIT](LICENSE) - Kim DaeHyun (kernalix7@kodenet.io)
