# audit-egress

Sample linpodx `network_trace` plugin. Receives every network event the runtime sees
(`dns_query`, `tcp_connect`, `udp_send`) and unconditionally returns `AuditOnly` so
the runtime keeps doing whatever it would have done — this plugin only observes, it
never blocks.

The interesting line lands in the daemon log via `host_log`:

```
audit-egress: dns_query api.openai.com
audit-egress: tcp_connect 1.1.1.1:443
```

The decision-side audit entry (`PluginNetworkTraceCalled`) lands in the hash-chained
audit log per call.

## Behavior

| Event payload | Returned decision |
|--|--|
| any well-formed `NetworkTraceEvent` | `AuditOnly` |
| non-UTF-8 payload | `AuditOnly` (with a warning log line) |

`Allow` and `Deny` are intentionally never returned — for a deny-on-policy plugin you
want a separate template that wires in your allowlist / blocklist.

## Build

```sh
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown
```

The compiled artifact lands at:

```
target/wasm32-unknown-unknown/release/audit_egress.wasm
```

`linpodx-plugin.toml` references it as `audit_egress.wasm`. Copy the wasm file next to
the manifest before installing:

```sh
cp target/wasm32-unknown-unknown/release/audit_egress.wasm \
   examples/plugins/audit-egress/audit_egress.wasm
```

## Install into the running daemon

```sh
linpodx plugin install examples/plugins/audit-egress
linpodx plugin list
linpodx plugin disable audit-egress      # toggle off without uninstalling
linpodx plugin enable  audit-egress
linpodx plugin remove  audit-egress --force   # delete on-disk dir too
```

## Host ABI used

This plugin needs three imported functions from the `linpodx_host` namespace:

- `host_log(level, ptr, len)`
- `host_get_payload(ptr, max) -> i32`
- `host_return_network_decision(decision, reason_ptr, reason_len)` —
  `decision`: 0 = Allow, 1 = Deny, 2 = AuditOnly.

The export the host calls is `evaluate_network_trace()` (no args, no result). The
runtime resolves chain decisions as: `Deny` wins; otherwise `AuditOnly` if any plugin
returned that; otherwise `Allow`.
