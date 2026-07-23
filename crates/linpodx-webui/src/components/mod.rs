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
mod charts;
mod cluster;
mod command_palette;
mod container_detail;
mod containers;
mod context_menu;
mod create_modal;
mod dashboard;
mod disk_usage;
mod exec_modal;
mod exec_pty_modal;
mod icons;
mod illustrations;
mod images;
mod list_table;
mod live_events;
mod logs_modal;
mod networks;
mod pin_clients;
mod plugins;
mod pods;
mod push_modal;
mod sandbox;
mod secrets;
mod sessions;
mod settings;
mod snapshots;
mod stacks;
mod volumes;
mod xterm;

// Compose/stack grouping (Stacks tab) groups the container list by compose
// project label — see `stacks.rs`. The sibling `pods.rs` (Pods tab) landed, so
// both `PodsView` and `StacksView` are re-exported and mounted from `app.rs`.

pub use audit::AuditFeed;
// AreaChart / LineChart / TwoSeriesChart are consumed by the container-drawer
// Stats tab (built by a parallel agent against this same crate); re-exported
// here so that component can pull them from `crate::components::*`. Sparkline is
// used now by the status footer.
#[allow(unused_imports)]
pub use charts::{AreaChart, LineChart, Sparkline, TwoSeriesChart};
pub use cluster::ClusterView;
pub use command_palette::CommandPalette;
// `ContainerDetail` is the slide-over drawer body mounted by `AppRoot` inside
// `.drawer-body` (replacing the `loading-inline` placeholder); it consumes the
// `DrawerState` + `AuthToken` contexts. Allow the re-export to sit unused until
// that mount point is wired (mirrors the `Settings` re-export below).
pub use container_detail::ContainerDetail;
pub use containers::ContainerList;
pub use dashboard::{ContainerLiveSample, Dashboard, DashboardShared};
pub use disk_usage::DiskUsageView;
pub use icons::Icon;
pub use images::ImageList;
// `LiveEvents` is the dashboard's real-time daemon event feed (subscribes to
// the container-lifecycle topics over one `/ipc` socket). Consumed by
// `dashboard.rs` via `super::live_events::LiveEvents`; re-exported here for
// symmetry with the other panels.
#[allow(unused_imports)]
pub use live_events::LiveEvents;
pub use networks::NetworkList;
pub use pin_clients::PinnedClientsView;
pub use plugins::PluginsView;
pub use pods::PodsView;
pub use sandbox::SandboxList;
pub use secrets::SecretsView;
pub use sessions::SessionTimeline;
// `Settings` replaces app.rs's local `SettingsPlaceholder` for `Tab::Settings`
// once the app-shell mount point is wired up (owned by another agent); allow
// the re-export to sit unused until then.
pub use settings::Settings;
pub use snapshots::SnapshotTree;
pub use stacks::StacksView;
pub use volumes::VolumeList;

// Modal components are mounted from their owning panels (containers / images
// / snapshots / sessions) — they don't need to surface in the parent app's
// `use components::*` line.
