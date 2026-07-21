# Troubleshooting

[Back to README](../README.md) | [한국어 (TODO)](#)

If a command misbehaves, work through this list before filing an issue.
Items flagged "planned (Phase 18)" describe commands that the next release is
adding — until they ship, the workaround listed alongside them is the supported
path.

## Daemon connectivity

### `daemon: connection refused`

The daemon is not running on the expected socket. Start it in the foreground:

```bash
linpodx-daemon &
```

Then confirm:

```bash
linpodx version
```

A `daemon start` / `daemon stop` / `daemon status` subcommand group is planned
(Phase 18). Until it lands, run `linpodx-daemon` directly and stop it with
`fg` + `Ctrl-C` (or `kill` against the PID).

### `error: socket path not writable: …`

`$XDG_RUNTIME_DIR` is unset or read-only on this host. Either export it to a
writable directory or pass `--socket /tmp/linpodx-$UID.sock` to both the
daemon and the CLI.

### `linpodx events` prints nothing

Confirm the daemon is up, then check the topic filter. `linpodx events --topic
container --topic image` narrows the stream; `linpodx events --json` shows the
raw envelopes. Approval prompts are delivered through `linpodx approvals`, not
`linpodx events` — they are separate subscription surfaces.

## Podman runtime

### `podman: command not found`

Install Podman 4.6.0 or newer for your distro:

| Distro family | Install command |
|---------------|-----------------|
| Debian / Ubuntu / Linux Mint / Pop!_OS | `sudo apt install podman` |
| Fedora / RHEL family / AlmaLinux / Rocky | `sudo dnf install podman` |
| openSUSE Tumbleweed / Leap / Slowroll | `sudo zypper install podman` |
| Arch / Manjaro / EndeavourOS | `sudo pacman -S podman` |
| Alpine | `apk add podman` |

Confirm with `podman --version`.

### `podman: version 4.5 is too old, need >= 4.6.0`

Upgrade your distro's Podman, or use the upstream RPM/DEB from
[podman.io](https://podman.io). linpodx will not run against a Podman that
predates the rootless network parity work in 4.6.

An environment-check command (`linpodx doctor`) is planned (Phase 18) to flag
this exact condition with a fix hint up front.

### Container starts but has no network egress

The active sandbox profile is in `network: kind: allowlist` mode and the
destination host is not on the list. Either widen the allowlist or run without
`--sandbox`:

```bash
linpodx sandbox show <profile>          # inspect the YAML
linpodx passthrough status <profile>    # passthrough toggles
linpodx network egress status <profile> # current egress rule set
# edit profile YAML, then reload
linpodx sandbox reload
```

The privileged L4 helper (`linpodx-netfilter-helper`) is optional; without it,
DNS-only filtering is applied. `network egress apply` reports
`helper_applied: false` when the helper has not been installed with
`CAP_NET_ADMIN`.

## Desktop GUI

### `linpodx-gui` panics on startup with `wgpu` / `wayland` / `EGL` in the message

The iced renderer is failing to find a runtime library. Install the basics:

| Distro family | Install command |
|---------------|-----------------|
| Debian / Ubuntu | `sudo apt install libwayland-client0 libxkbcommon0 libegl1 libgl1 libxcb1` |
| Fedora / RHEL | `sudo dnf install libwayland-client libxkbcommon mesa-libEGL mesa-libGL libxcb` |
| openSUSE | `sudo zypper install libwayland-client0 libxkbcommon0 libEGL1 libGL1 libxcb1` |
| Arch | `sudo pacman -S wayland libxkbcommon mesa libxcb` |

A graceful-error path that explains the missing library is planned (Phase 18).

### GUI dashboard stays empty

Confirm the daemon is the one the GUI connected to. If the daemon is running on
a non-default socket, start the GUI with the same `--socket` argument
(`linpodx-gui --socket /tmp/linpodx-$UID.sock`).

## Snapshots & encryption

### `snapshot decryption failed`

The daemon was started with a different
`LINPODX_SNAPSHOT_ENCRYPT_PASSPHRASE` / `LINPODX_SNAPSHOT_KEY` /
`LINPODX_SNAPSHOT_KDF` than the snapshot was created with. Match the variables
that were set when the snapshot was written, or inspect the recorded KDF:

```bash
linpodx snapshot encryption-status <snapshot_id>
```

If you have access to both the old and the new key material, migrate the
on-disk corpus with:

```bash
linpodx snapshot key-rotate <snapshot_id>
linpodx snapshot re-encrypt-all
```

### Snapshots take longer than expected

`Argon2id` is the default KDF for encrypted snapshots, with OWASP 2023
parameters (`m = 19 456 KiB, t = 2, p = 1`). On older hardware this can add
~15–20 ms per snapshot create. Switch to the legacy KDF for development
machines:

```bash
LINPODX_SNAPSHOT_KDF=sha256-rounds-1k linpodx-daemon
```

Production hosts should stay on `argon2id`.

## Plugins

### `plugin signature rejected`

The plugin manifest carries an Ed25519 signature that does not match any
public key in the registry. Install the publisher's key:

```bash
mkdir -p ~/.config/linpodx/plugins/keys
cp /path/to/<publisher>.pub ~/.config/linpodx/plugins/keys/
```

Alternative locations (resolved in order): `$XDG_CONFIG_HOME/linpodx/plugins/keys/`,
`/etc/linpodx/plugins/keys/`. For local development, set
`LINPODX_ALLOW_UNSIGNED_PLUGINS=1` and restart the daemon.

### `plugin key revoked` after a cluster propagation

A cluster leader has revoked this publisher's key. Inspect the active keys and
their state:

```bash
linpodx plugin key list
```

To restore a key locally (after revoking the revocation upstream), remove the
`<publisher>.revoked` marker from the same directory the public key lives in.

## Remote daemon

### `error: mTLS handshake failed: unknown CA`

The daemon's `--client-ca` does not include the CA that signed the client
certificate. Regenerate the dev bundle and use the matching `ca.pem` on both
sides:

```bash
linpodx daemon cert generate --out ./certs
```

### `error: client certificate not pinned`

`--pin-clients` is active and this fingerprint is not in the allow list. Pin
the certificate explicitly:

```bash
linpodx daemon pin-client add ./certs/client.pem --label dev
linpodx daemon pin-client list
```

For a controlled first-contact window, open TOFU enrollment:

```bash
linpodx daemon pin-client tofu --enable --expires-in 300
```

The window auto-closes after 300 seconds and the first matching client is
auto-pinned.

### Web UI loads but stays empty

The bearer token entered in the browser does not match `--remote-token`.
Re-enter the token. The Web UI shares the remote listener's security posture,
so for untrusted networks pair it with mTLS.

### Build fails with `failed to find tool 'wasm-bindgen'`

The Leptos Web UI is opt-in. Install the prerequisites once:

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli
```

Then rebuild with `LINPODX_WASM=1 cargo build -p linpodx-daemon --release`.
Without `LINPODX_WASM=1` the daemon serves the lightweight fallback UI and
`wasm-bindgen` is not needed.

## Cluster

### `not_leader` when proposing a state change

Cluster state proposals only succeed on the Raft leader. Identify it and retry
against that node:

```bash
linpodx cluster leader
linpodx cluster role
```

The `linpodx cluster state propose` and `plugin key revoke --cluster-wide`
commands return `not_leader` from followers; rerun the same command against
the leader node's daemon (over the remote transport if needed).

## Sandbox & approvals

### Approval prompt never appears

Make sure `linpodx approvals` is running. The CLI listener resolves prompts
within a 30-second window before the call is denied by default. The window can
be overridden per profile via `approval_timeout_secs`.

### `error: profile not found`

Run `linpodx sandbox reload` after dropping a new YAML into the profiles
directory. The daemon does not auto-discover profiles created while it is
running.

## Filing a bug

If the workaround did not help, please include in the issue:

- linpodx version (`linpodx version`)
- Podman version (`podman --version`)
- Distro + kernel (`cat /etc/os-release; uname -r`)
- The full command line that triggered the problem
- Daemon logs from around the failure window (`linpodx-daemon` writes to
  stderr by default)
