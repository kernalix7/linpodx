//! Phase 24 — linpodx GUI core (Qt-agnostic).
//!
//! Holds the parts of the desktop GUI that have no Qt dependency: the
//! application state model + reducer (`state`), the message enum (`messages`),
//! the daemon IPC client (`connection`, `daemon_client`), and the process-wide
//! event/log rings (`rings`). Keeping these in their own crate means they are
//! unit-tested without linking Qt — which sidesteps the cxx-qt initializer
//! linkage that otherwise breaks `cargo test` on the Qt binary crate.
//!
//! `linpodx-common` remains the single source of truth for IPC payloads.

pub mod connection;
pub mod daemon_client;
pub mod messages;
pub mod rings;
pub mod state;
