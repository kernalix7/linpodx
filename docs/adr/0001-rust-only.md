# ADR 0001 — Single-language workspace (Rust 2021)

- **Status**: Accepted (2026-04, Phase 0)
- **Deciders**: kernalix7

## Context

linpodx spans a daemon, a CLI, a desktop GUI (iced), a future Web UI (Leptos →
WebAssembly), policy engines, a WASM host runtime, and a snapshot/runtime adapter.
Many comparable container managers (Docker Desktop, Rancher Desktop, k3d) use a Go
backend with a Node/TypeScript frontend, which means two language toolchains, two
package managers, two test runners, and an IPC marshalling layer that crosses a
language boundary.

A monoglot workspace removes that boundary. Rust 2021 is a credible candidate because:

- iced (GUI), Leptos (Web UI → wasm32), wasmtime (plugin host), axum (HTTP/WS),
  rustls, sqlx, hickory-dns, and tokio all live in one ecosystem.
- The IPC schema in `linpodx-common` can be authored once and reused verbatim by every
  client crate — no `.proto`/codegen step.
- Forbid-unsafe is a workspace-wide default we can mechanically enforce.
- MSRV pinning via `rust-toolchain.toml` gives reproducible builds for every
  contributor without per-tool configuration.

## Decision

The entire workspace is Rust 2021. MSRV = 1.83. `rustfmt` defaults are mandatory.
`clippy --all-targets --all-features -- -D warnings` is enforced in CI.

The only languages tolerated outside Rust source are: TOML (Cargo manifests, deny.toml,
plugin manifests), YAML (sandbox profiles, GitHub Actions), SQL (migrations), and
Markdown (docs). No Python/JS build steps in the toolchain.

## Consequences

**Positive:**
- One toolchain, one cache, one CI matrix.
- Type-checked end-to-end — IPC payloads share a single `serde` schema.
- Forbid-unsafe is enforceable via `#![forbid(unsafe_code)]` per crate.

**Negative:**
- iced and Leptos are both younger than the GTK/React mainstream alternatives.
  Mitigated by isolating GUI in `linpodx-gui` and Web UI in `linpodx-webui` so a swap
  later is a crate replacement, not a rewrite.
- Cold compile time is meaningful (~2 min for the iced crate). Mitigated by
  Swatinem/rust-cache in CI and `lto = "thin"` in release.
