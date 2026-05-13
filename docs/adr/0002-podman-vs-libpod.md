# ADR 0002 — Drive Podman as a subprocess, not via libpod FFI

- **Status**: Accepted (2026-04, Phase 0)
- **Deciders**: kernalix7

## Context

The runtime crate must orchestrate containers. Two binding strategies exist:

1. Spawn the `podman` CLI binary and parse its `--format=json` output.
2. Link `libpod` as a CGO/FFI dependency.

`libpod` is written in Go. Linking from Rust would require either CGO with a C shim or
a hand-rolled JSON-RPC bridge — both of which add a Go toolchain to the build.

## Decision

Drive Podman as a subprocess via `tokio::process::Command`. Parse `--format=json`
output with `serde_json` into the types declared in `linpodx-common::state`.

Minimum supported Podman version: **4.6.0** (Phase 1A). Some integration tests
(`*-snapshot*`) require Podman ≥ 5.0 features and are gated with `#[ignore]`.

## Consequences

**Positive:**
- No Go toolchain in the build pipeline.
- Each podman call is a process boundary — failures cannot corrupt the daemon's heap.
- Trivial to record/replay against canned JSON fixtures (`crates/linpodx-runtime/src/parse.rs`
  is exercised by ~20 unit tests this way).
- Rootless Podman just works — we inherit the user's session.

**Negative:**
- Per-call fork+exec overhead. Measured at ~5ms on a typical desktop; acceptable for
  CRUD operations, prohibitive for hot inner loops. Where it matters (metrics
  collection) we read `cgroup v2` directly from `/sys/fs/cgroup` — see
  `runtime::metrics::cgroup_sample`.
- We are coupled to Podman's JSON output schema; minor variations between 4.x and 5.x
  are absorbed by lossy parsers in `parse.rs`.
- No streaming attach API — `podman attach` only works as a child stdio pipe.
