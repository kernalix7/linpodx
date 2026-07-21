//! Phase 18 — per-command module scaffold.
//!
//! New CLI command groups land as files in this directory rather than being
//! bolted onto `main.rs`. Each stream owns its own submodule and re-exports
//! the public entry points (`Cmd` sub-enums + `handle_*` functions) consumed
//! by `main.rs`.
//!
//! **File ownership (Phase 18 streams):**
//! - `doctor.rs` — Stream C (sandbox-team).
//! - `daemon_mgmt.rs` — Stream D (runtime-team), houses `linpodx daemon
//!   start|stop|status` and the `--fork` / `--pid-file` plumbing.
//! - `completion.rs` — Stream B (runtime-team), shell completion + `docker`
//!   alias surface.
//! - `container.rs` / `image.rs` / `volume.rs` / `network.rs` — Stream B
//!   (runtime-team), as the per-noun split lands incrementally.
//!
//! Until a stream lands its module the corresponding `pub mod` line is
//! intentionally omitted so the crate still compiles cleanly. Adding a new
//! command group is a *single* file-create + a one-line `pub mod` here.

// Stream-owned modules are added here as they land.
pub mod doctor;

// Stream D (runtime) — `linpodx daemon {start,stop,status,logs}`.
pub mod daemon_mgmt;

// Stream B (runtime) — docker-compat alias surface + shell completion.
pub(crate) mod completion;
pub(crate) mod container;
// Sibling files (`image.rs`, `volume.rs`, `network.rs`) hold the rationale
// for the singular/plural alias mappings on the matching `Cmd` variants in
// `main.rs`; they re-export nothing today, but they are wired in so
// `cargo build` keeps their docs honest.
mod image;
mod network;
mod volume;
