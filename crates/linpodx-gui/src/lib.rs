//! Phase 24 (Tauri pivot) — thin Tauri 2 desktop shell for linpodx.
//!
//! The cxx-qt + Qt 6 direction was cancelled (licensing + velocity). This crate
//! is now a minimal Tauri window whose webview displays the **daemon-served**
//! leptos Web UI (`/ui/*` over a loopback plaintext listener the daemon opens
//! on demand via `WebUiEnsure`). All the container-management surface lives in
//! that web UI; the shell's only job is to reach the daemon and point the
//! webview at it.
//!
//! The Qt-free connection/state model still lives in the sibling
//! `linpodx-gui-core` crate (re-exported here as `core`); the shell-specific
//! glue (socket probing, daemon auto-spawn, URL building) lives in [`shell`].

pub mod shell;

/// Re-export the Qt-agnostic core so callers can refer to
/// `linpodx_gui::core::...` without a second `use` path.
pub use linpodx_gui_core as core;
