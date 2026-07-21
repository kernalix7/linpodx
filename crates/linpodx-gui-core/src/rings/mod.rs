//! Process-wide, Qt-agnostic data rings fed by the state reducer + IPC task.
//!
//! `events` is the 1000-entry event history; `daemon` is the 200-line daemon
//! log tail. The Qt Events/Daemon tabs (in the `linpodx-gui` crate) read these
//! through their `snapshot` / `log_snapshot` accessors.

pub mod daemon;
pub mod events;
