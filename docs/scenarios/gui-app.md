# Scenario — Run a GUI application inside a container with Wayland passthrough

> **Status — illustrative end-to-end walkthrough.** The runnable surface today
> is profile-driven: edit a sandbox profile's `passthrough:` block with
> `linpodx passthrough {grant, revoke, status}` and apply it with
> `linpodx run --sandbox <profile>`. The inline `linpodx run --passthrough …`
> form shown below is the target ergonomics and is planned for a later
> release; the underlying behaviour (Wayland / audio / clipboard / GPU
> surfaces) is already wired through `linpodx-runtime::passthrough` today.

linpodx wires the host Wayland socket, audio, clipboard, and (optionally) GPU
into the container so a containerized app windows on your host like any other
native app.

## What gets passed through

| Surface       | Default | Knob |
|---------------|---------|------|
| Wayland       | on      | `--passthrough wayland=off` |
| X11 fallback  | on if no Wayland | `--passthrough x11=off` |
| PulseAudio / PipeWire | on | `--passthrough audio=off` |
| Clipboard     | on      | `--passthrough clipboard=off` |
| GPU (DRM)     | off     | `--passthrough gpu=on` |

## 1. Firefox in a sandbox

```console
$ linpodx run \
    --image docker.io/library/firefox:latest \
    --passthrough wayland,audio,clipboard \
    --name firefox-sandbox \
    --rm
[wayland] socket: /run/user/1000/wayland-0 -> /run/host/wayland-0
[audio]   pulse:  /run/user/1000/pulse -> /run/host/pulse
container_id: 4d11abef
state:        running
```

Firefox opens on your desktop; clipboard works; YouTube has audio. When you close the
window the container stops and (because of `--rm`) is removed.

## 2. VS Code with GPU acceleration for the editor

```console
$ linpodx run \
    --image docker.io/library/code:latest \
    --passthrough wayland,clipboard,gpu \
    --mount type=bind,src=$HOME/projects/demo,dst=/work \
    --name vscode \
    --workdir /work
[gpu] /dev/dri/card0 -> /dev/dri/card0 (rw)
[gpu] /dev/dri/renderD128 -> /dev/dri/renderD128 (rw)
container_id: 9f2c8a1c
```

GPU passthrough requires the host kernel's render node to be readable by the user
running linpodx (typically the `render` group).

## 3. Inspect what the container actually sees

```console
$ linpodx exec firefox-sandbox -- env | grep -E 'WAYLAND|XDG'
WAYLAND_DISPLAY=wayland-0
XDG_RUNTIME_DIR=/run/host
$ linpodx exec firefox-sandbox -- ls -la /run/host
srwxr-xr-x 1 1000 1000 0 May 10 09:14 wayland-0
drwxr-xr-x 2 1000 1000 0 May 10 09:14 pulse
```

## 4. HiDPI and fractional scaling

linpodx forwards `GDK_SCALE` and `WAYLAND_DISPLAY` from the host. For apps that read
`QT_SCALE_FACTOR` instead, set it explicitly:

```console
$ linpodx run --image my/qtapp --passthrough wayland --env QT_SCALE_FACTOR=1.5 ...
```

## 5. Diagnose a black or empty window

```console
$ linpodx events --filter passthrough
[2026-05-10T09:14:02Z] firefox-sandbox passthrough wayland: ok
[2026-05-10T09:14:02Z] firefox-sandbox passthrough audio:   socket missing on host (skipped)
```

If `audio: socket missing` shows up, your host is using PipeWire but the
`pipewire-pulse` shim isn't running. Start it (`systemctl --user start pipewire-pulse`)
and relaunch.

## 6. Lock the app down with a sandbox profile

Pair `--passthrough` with `--profile`:

```console
$ linpodx run \
    --image docker.io/library/firefox:latest \
    --passthrough wayland,audio,clipboard \
    --profile firefox-no-egress \
    --rm
```

A profile can revoke even passthrough surfaces — useful for "GUI app, but no
clipboard read access" cases (`clipboard: read_only_paste`).

## Caveats

- Native menus rendered by `xdg-portal` may need `--passthrough xdg-portal=on`
  (planned Phase 9.5).
- NVIDIA proprietary drivers need extra `--device /dev/nvidia*` flags; planned to be
  wrapped in `--passthrough gpu=nvidia`.
- Some sandboxed apps refuse to launch under a different uid; pair with `--user
  $(id -u):$(id -g)`.
