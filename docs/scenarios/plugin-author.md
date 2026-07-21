# Scenario — Write a linpodx WASM plugin

> **Status — illustrative end-to-end walkthrough.** Today the runnable
> surface for plugin lifecycle is `linpodx plugin {install, list, enable,
> disable, remove, key {list, revoke}}`. Five hook kinds are wired in the
> host (`approval`, `audit_filter`, `profile_validator`, `network_trace`,
> `runtime_injector`); the three listed below are a subset. Ed25519
> signatures are required by default — set
> `LINPODX_ALLOW_UNSIGNED_PLUGINS=1` for local development.

linpodx plugins are WASM modules. They can hook three extension points:

- **`approval`** — run alongside the built-in approval gate; vote `Allow`,
  `Defer`, or `Deny` with a reason.
- **`audit_filter`** — transform or drop audit events before they hit the SQLite
  log (e.g. redact secrets).
- **`profile_validator`** — cross-check a sandbox YAML profile and reject it if it
  violates a policy your team encodes in code.

Authors can use any language that targets `wasm32-unknown-unknown`. We'll use Rust.

## 1. Scaffold a plugin crate

```console
$ cargo new --lib --name geo-fence-approval geo-fence-approval
$ cd geo-fence-approval
```

`Cargo.toml`:

```toml
[package]
name    = "geo-fence-approval"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
serde      = { version = "1", features = ["derive"] }
serde_json = "1"
```

## 2. Write the hook

`src/lib.rs`:

```rust
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct ApprovalPayload {
    method: String,
    tool_name: Option<String>,
    arguments: serde_json::Value,
}

#[derive(Serialize)]
struct ApprovalDecision {
    decision: &'static str,
    reason: String,
}

#[no_mangle]
pub extern "C" fn approval(ptr: *const u8, len: usize) -> u64 {
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    let payload: ApprovalPayload = serde_json::from_slice(bytes).unwrap();

    // Block any tool call whose arguments mention `prod`.
    let s = payload.arguments.to_string();
    let decision = if s.contains("prod") {
        ApprovalDecision { decision: "deny",  reason: "geo-fence: prod tag denied".into() }
    } else {
        ApprovalDecision { decision: "allow", reason: "geo-fence: ok".into() }
    };

    let out = serde_json::to_vec(&decision).unwrap();
    let leaked = Box::leak(out.into_boxed_slice());
    let p = leaked.as_ptr() as u64;
    let l = leaked.len() as u64;
    (p << 32) | l
}
```

## 3. Build for wasm32

```console
$ rustup target add wasm32-unknown-unknown
$ cargo build --release --target wasm32-unknown-unknown
$ ls target/wasm32-unknown-unknown/release/*.wasm
target/wasm32-unknown-unknown/release/geo_fence_approval.wasm
```

## 4. Author a manifest

`plugin.toml`:

```toml
name        = "geo-fence-approval"
version     = "0.1.0"
description = "Deny any approval whose payload mentions prod"
hooks       = ["approval"]
sdk_version = "1"
```

## 5. Install it

```console
$ linpodx plugin install \
    --manifest plugin.toml \
    --wasm target/wasm32-unknown-unknown/release/geo_fence_approval.wasm
plugin: geo-fence-approval@0.1.0
status: installed (disabled)
```

Plugins are inert until activated.

## 6. Activate

```console
$ linpodx plugin activate geo-fence-approval
plugin: geo-fence-approval@0.1.0
status: active
hooks:  approval
```

## 7. Watch it fire

```console
$ linpodx events --filter plugin
[2026-05-10T09:15:00Z] geo-fence-approval approval ALLOW  reason="geo-fence: ok"
[2026-05-10T09:15:14Z] geo-fence-approval approval DENY   reason="geo-fence: prod tag denied"
```

A plugin's `Deny` is veto-strength; `Defer` (the default if your code traps) leaves
the decision to the next plugin in the chain or the built-in gate.

## 8. Inspect / disable / remove

```console
$ linpodx plugin list
NAME                  VERSION  HOOKS      STATE
geo-fence-approval    0.1.0    approval   active

$ linpodx plugin disable geo-fence-approval
$ linpodx plugin remove  geo-fence-approval
```

## Tips

- Keep plugins small. wasmtime cold-load is ~1µs per registry construction; per-call
  invocation is sub-millisecond for trivial logic. Larger plugins blow that budget.
- A plugin trap surfaces as `Defer` with the trap message in the reason field — the
  host never errors out of `evaluate_approval` because of a misbehaving plugin.
- Audit-filter plugins should be deterministic. The chain runs the plugins in
  registration order and a non-deterministic filter makes the chain hard to reason
  about.
