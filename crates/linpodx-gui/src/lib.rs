#![forbid(unsafe_code)]

//! linpodx desktop GUI — live read-only dashboard for containers / images / volumes / networks.
//!
//! Phase 1B introduces this as a read-only viewer: the daemon is the source of truth and pushes
//! events on subscribe, the GUI re-renders. User actions still go through the CLI for now;
//! action buttons land in a follow-up.

pub mod connection;
pub mod daemon_client;
pub mod messages;
pub mod state;
pub mod views;
