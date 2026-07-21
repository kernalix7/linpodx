//! Phase 24 — cxx-qt + Qt 6 desktop GUI for linpodx.
//!
//! This crate holds the Qt-linked surface: the `ffi` bridge to the C++
//! `MainWindow` shell (`src/cpp/mainwindow.*`) and, from Stage 2, the
//! QWidget-backed per-tab views + modal dialogs.
//!
//! The Qt-agnostic state model, IPC client, and event rings live in the
//! sibling `linpodx-gui-core` crate (re-exported here as `core`) so they are
//! unit-tested without linking Qt.

pub mod ffi;

/// Re-export the Qt-agnostic core so view code can refer to
/// `linpodx_gui::core::state::App` etc. without a second `use` path.
pub use linpodx_gui_core as core;
