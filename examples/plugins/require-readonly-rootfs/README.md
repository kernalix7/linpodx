# require-readonly-rootfs

Sample linpodx `profile_validator` plugin. Rejects every sandbox profile whose YAML body
does not contain `read_only_rootfs: true`. Use this as a starting template for your own
policy validators (e.g. "every profile must drop CAP_SYS_ADMIN", "no profile may bind
host:/etc").

## Behavior

| Profile YAML contains | Decision |
|--|--|
| `read_only_rootfs: true` (uncommented) | Pass |
| `read_only_rootfs: false` | Reject |
| `# read_only_rootfs: true` (commented out) | Reject |
| Directive missing entirely | Reject |
| Non-UTF-8 bytes | Reject |

When the validator rejects, the sandbox manager skips that profile (other profiles in
the directory still load) and writes one `ProfileValidatorRejected` audit row per
offending plugin so operators can trace which rule caught it.

## Build

```sh
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown
```

The compiled artifact lands at:

```
target/wasm32-unknown-unknown/release/require_readonly_rootfs.wasm
```

`linpodx-plugin.toml` references it as `require_readonly_rootfs.wasm`. Copy the wasm
file next to the manifest before installing:

```sh
cp target/wasm32-unknown-unknown/release/require_readonly_rootfs.wasm \
   examples/plugins/require-readonly-rootfs/require_readonly_rootfs.wasm
```

## Install into the running daemon

```sh
linpodx plugin install examples/plugins/require-readonly-rootfs
linpodx plugin list
linpodx plugin disable require-readonly-rootfs      # toggle off without uninstalling
linpodx plugin enable  require-readonly-rootfs
linpodx plugin remove  require-readonly-rootfs --force   # delete on-disk dir too
```

## Host ABI used

This plugin needs three imported functions from the `linpodx_host` namespace:

- `host_log(level, ptr, len)`
- `host_get_payload(ptr, max) -> i32` — payload bytes are the raw YAML body of the
  profile being validated.
- `host_return_validator_decision(decision, reason_ptr, reason_len)` —
  `decision`: 0 = Pass, 1 = Reject. Reason text on Reject is recorded in the audit log.

The export the host calls is `evaluate_profile_validator()` (no args, no result). It is
invoked once per profile per `SandboxManager::reload`.
