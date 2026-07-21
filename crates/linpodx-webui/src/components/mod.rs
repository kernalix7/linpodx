//! Tab panels — one component per tab. Each panel:
//!   1. reads the bearer token from the [`AuthToken`] context,
//!   2. fires a one-shot REST `GET /api/v1/<resource>` for an initial seed,
//!   3. opens `/ipc` and Subscribes to its event topic, refetching the seed
//!      whenever a relevant notification arrives.
//!
//! Rendering is delegated to a single `ListTable` helper that walks an array of
//! JSON objects and emits one row per element. Cells are emitted as strings via
//! leptos `view!`, which escapes interpolated values — there is no `set_html`
//! anywhere in this crate.
//!
//! Phase 12 Stream B added per-row action modals (Exec / Logs / Push / snapshot
//! Branch+Rollback+Remove / Session Timeline). Each modal is its own component
//! and is mounted from the owning panel; visibility is controlled by a shared
//! `RwSignal<Option<...>>` whose `Some` payload is the row's id.

mod audit;
mod cluster;
mod containers;
mod exec_modal;
mod exec_pty_modal;
mod icons;
mod images;
mod list_table;
mod logs_modal;
mod networks;
mod pin_clients;
mod plugins;
mod push_modal;
mod sandbox;
mod sessions;
mod snapshots;
mod volumes;
mod xterm;

pub use audit::AuditFeed;
pub use cluster::ClusterView;
pub use containers::ContainerList;
pub use icons::Icon;
pub use images::ImageList;
pub use networks::NetworkList;
pub use pin_clients::PinnedClientsView;
pub use plugins::PluginsView;
pub use sandbox::SandboxList;
pub use sessions::SessionTimeline;
pub use snapshots::SnapshotTree;
pub use volumes::VolumeList;

// Modal components are mounted from their owning panels (containers / images
// / snapshots / sessions) — they don't need to surface in the parent app's
// `use components::*` line.
