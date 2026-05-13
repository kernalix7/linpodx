# audit-redact-secrets

Sample linpodx `audit_filter` plugin. Walks every audit payload looking for keys whose
name contains `password`, `token`, `secret`, `api_key`, or `key`, and rewrites the
matching string value to `"***"` before the entry hits the hash-chained audit log.

This plugin is meant as a starting template for writing your own `audit_filter` plugins
in Rust.

## Behavior

| Input payload | Output |
|--|--|
| `{"user":"alice","password":"hunter2"}` | `{"user":"alice","password":"***"}` |
| `{"hostname":"node-7","port":443}` | unchanged → Forward |
| `{"password":42}` (non-string) | unchanged → Forward |

The plugin returns:
* `Transform` (decision code 2) when at least one key was redacted.
* `Forward`   (decision code 0) when no key matched, the payload is non-UTF-8, or every
  match had a non-string value.

`Drop` (decision code 1) is intentionally never returned — silently suppressing audit
entries should be an opt-in, not an accidental side effect of redaction.

## Build

```sh
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown
```

The compiled artifact lands at:

```
target/wasm32-unknown-unknown/release/audit_redact_secrets.wasm
```

`linpodx-plugin.toml` references it as `audit_redact_secrets.wasm`. Copy the wasm file
next to the manifest before installing:

```sh
cp target/wasm32-unknown-unknown/release/audit_redact_secrets.wasm \
   examples/plugins/audit-redact-secrets/audit_redact_secrets.wasm
```

## Install into the running daemon

```sh
linpodx plugin install examples/plugins/audit-redact-secrets
linpodx plugin list
linpodx plugin disable audit-redact-secrets      # toggle off without uninstalling
linpodx plugin enable  audit-redact-secrets
linpodx plugin remove  audit-redact-secrets --force   # delete on-disk dir too
```

## Host ABI used

This plugin needs four imported functions from the `linpodx_host` namespace:

- `host_log(level, ptr, len)`
- `host_get_payload(ptr, max) -> i32`
- `host_return_payload(ptr, len)` — write the rewritten bytes (only used on Transform)
- `host_return_filter_decision(decision, reason_ptr, reason_len)` —
  `decision`: 0 = Forward, 1 = Drop, 2 = Transform.

The export the host calls is `evaluate_audit_filter()` (no args, no result). When the
`audit_filter` chain runs, every plugin sees the payload produced by the previous plugin
in registry order — the first `Drop` short-circuits the chain.
