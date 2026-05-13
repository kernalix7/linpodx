//! linpodx-distro — pre-baked multi-distro templates and VM-mode lifecycle.
//!
//! Phase 4 entry crate. Stage 2-B fills in:
//! * `templates/` — six static distro descriptors (ubuntu, fedora, arch, debian, alpine,
//!   nixos), each exposing a [`templates::TemplateMeta`].
//! * `registry` — stateless `Registry` over the bundled templates.
//! * `build` — Dockerfile generator + `podman build` driver for custom images.
//! * `instance` — `InstanceManager`: `DistroCreate` / `DistroEnter` / `DistroRemove`
//!   wired to SQLite (`distro_instances`) + the cross-crate `AuditSink` /
//!   `EventPublisher` plumbing.
//! * `menu` — host application-menu integration (`.desktop` files).
//! * `dispatch` — `handle()` entry point used by the daemon's RPC dispatch layer.

#![forbid(unsafe_code)]

use thiserror::Error;

pub mod build;
pub mod dispatch;
pub mod instance;
pub mod menu;
pub mod registry;
pub mod templates;

pub use build::BuildSpec;
pub use instance::InstanceManager;
pub use registry::Registry;
pub use templates::{InitKind, TemplateMeta};

#[derive(Debug, Error)]
pub enum DistroError {
    #[error("not yet implemented (Stage 2-B): {0}")]
    NotImplemented(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("runtime error: {0}")]
    Runtime(String),
    #[error("instance '{0}' already exists")]
    NameTaken(String),
    #[error("instance '{0}' not found")]
    NotFound(String),
    #[error("db error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, DistroError>;
