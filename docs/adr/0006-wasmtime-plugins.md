# ADR 0006 — wasmtime as the plugin runtime

- **Status**: Accepted (2026-05, Phase 6)
- **Deciders**: kernalix7

## Context

Plugins extend the daemon with three kinds of hooks: approval gates, audit-event
filters, and sandbox-profile validators. The plugin substrate must be:

- Language-neutral (we don't want to dictate Rust to plugin authors).
- Sandbox-able by default — a misbehaving plugin must not be able to read host files
  or open sockets.
- Embeddable in a single-binary daemon with no system runtime dependency.
- Audit-friendly — we need to see what the plugin returned and why.

Candidates: native dynamic libraries (rejected — no sandboxing), Lua/Rhai (rejected
— ties authors to one scripting language), JavaScript via QuickJS (rejected — heavy
runtime), WASM via wasmtime, WASM via wasmer.

## Decision

WASM via **wasmtime 26**, with `default-features = false` and only `runtime` +
`cranelift` enabled. The plugin SDK exposes three hook signatures (`approval`,
`audit_filter`, `profile_validator`) and the host calls them with serialized payloads.

A plugin trap surfaces as a `Defer` decision in approval/filter chains — never an
error from the host call.

## Consequences

**Positive:**
- Authors can use any wasm-targeting language (Rust, AssemblyScript, Tinygo, etc.).
- WASM is sandboxed by default — no syscalls except the explicit imports we wire in.
- Cranelift JIT is fast enough that per-invocation latency is sub-millisecond for the
  trivial plugins we ship.

**Negative:**
- Plugins cannot share host pointers; every call serializes payloads. This is
  acceptable given hook frequency.
- wasmtime drags in Cranelift, which is a non-trivial dependency. Mitigated by feature
  pruning (`default-features = false`).
- The plugin ABI is informal — we may need a wit-bindgen-based formalization later
  once external authors pile on.
