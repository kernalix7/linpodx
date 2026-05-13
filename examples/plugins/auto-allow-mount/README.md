# auto-allow-mount

Sample linpodx approval-rule plugin. Auto-allows any approval request whose
serialized payload contains the substring `"mount"`. Defers otherwise.

This plugin is meant as a starting template for writing your own linpodx plugins
in Rust.

## Build

```sh
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown
```

The compiled artifact lands at:

```
target/wasm32-unknown-unknown/release/auto_allow_mount.wasm
```

`linpodx-plugin.toml` references it as `auto_allow_mount.wasm`. Copy the wasm
file next to the manifest before installing:

```sh
cp target/wasm32-unknown-unknown/release/auto_allow_mount.wasm \
   examples/plugins/auto-allow-mount/auto_allow_mount.wasm
```

## Install into the running daemon

```sh
linpodx plugin install examples/plugins/auto-allow-mount
linpodx plugin list
linpodx plugin disable auto-allow-mount      # toggle off without uninstalling
linpodx plugin enable  auto-allow-mount
linpodx plugin remove  auto-allow-mount --force   # delete on-disk dir too
```

## Host ABI

Plugins import three functions from the `linpodx_host` namespace:

- `host_log(level, ptr, len)` — emit a tracing event in the host.
- `host_get_payload(ptr, max) -> i32` — copy the request payload bytes into
  wasm memory; returns the required length when `max` is too small so the
  guest can re-allocate.
- `host_return_decision(decision, reason_ptr, reason_len)` —
  `decision`: 0 = Defer, 1 = Allow, 2 = Deny.

Plugins must export an `evaluate_approval()` function (no args, no result).
The host calls it for every pending approval request.
