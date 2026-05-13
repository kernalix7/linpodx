//! Phase 17 — re-export surface for the GUI's `Message` enum.
//!
//! Historically every GUI message lived in `state::Message`. Phase 17 split the
//! Phase 17 variants out for owned-path bookkeeping but kept the enum in
//! `state.rs` (a single source of truth so the reducer stays exhaustive). This
//! module exists so `use linpodx_gui::messages::Message` continues to work for
//! external callers; the in-tree code keeps importing from `state` directly.

pub use crate::state::{
    DiffSlot, Message, PluginKeyRevokeForm, PluginRevokePropagation, SnapshotEncryptionBadge,
    SnapshotKeyRotateForm, SnapshotReEncryptForm,
};
