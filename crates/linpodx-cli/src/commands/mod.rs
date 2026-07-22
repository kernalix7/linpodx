//! Per-command module tree.
//!
//! Every CLI command group lives in its own file here rather than being
//! bolted onto `main.rs`. Each module owns its `clap::Subcommand` enum(s)
//! plus the `async fn handle_*` that turns a parsed value into IPC calls.
//! `main.rs` keeps only the top-level `Cli` / `Cmd` definitions, `main()`
//! itself, and the dispatch `match` that routes each `Cmd` variant to its
//! module's handler.

pub mod doctor;

// `linpodx daemon {start,stop,status,logs,cert,pin-client}`.
pub mod daemon_mgmt;
pub(crate) mod daemon_pin;

// docker-compat alias surface + shell completion.
pub(crate) mod completion;
pub(crate) mod container;
// Sibling files (`image.rs`, `volume.rs`, `network.rs`) hold the rationale
// for the singular/plural alias mappings on the matching `Cmd` variants in
// `main.rs`.
pub(crate) mod image;
pub(crate) mod network;
pub(crate) mod pod;
pub(crate) mod volume;

// Shared helpers reused by more than one domain module.
pub(crate) mod util;

pub(crate) mod cluster;
pub(crate) mod distro;
pub(crate) mod events;
pub(crate) mod exec;
pub(crate) mod k8s;
pub(crate) mod mcp;
pub(crate) mod passthrough;
pub(crate) mod plugin;
pub(crate) mod sandbox;
pub(crate) mod session;
pub(crate) mod snapshot;
