#![forbid(unsafe_code)]

//! AI agent sandbox subsystem for linpodx.
//!
//! Phase 1C delivers v0.1: YAML profile schema + policy enforcement (mounts whitelist,
//! capability drops, network=none, read-only rootfs, cpu/memory caps) + tamper-evident
//! audit log (SHA-256 hash chain) over SQLite.

pub mod audit;
pub mod cluster_store;
pub mod manager;
pub mod mcp_audit;
pub mod mcp_policy;
pub mod plugin_store;
pub mod policy;
pub mod profile;
pub mod schema;
pub mod secprofile;
pub mod session;
pub mod snapshot;
pub mod snapshot_trigger;

pub use cluster_store::{record_view_served as record_cluster_view_served, ClusterStore};
pub use manager::SandboxManager;
pub use mcp_audit::{record_mcp_event, SandboxAuditSink};
pub use mcp_policy::{apply_set as apply_mcp_policy_set, McpPolicyStore};
pub use plugin_store::PluginStore;
pub use policy::{apply, AppliedPolicy, PolicyDecision};
pub use schema::{Capabilities, Limits, MountRule, NetworkPolicy, SandboxProfile, SourcePattern};
pub use secprofile::{
    is_apparmor_available, is_selinux_available, CompiledProfile, SecProfileCompiler,
};
pub use session::SessionManager;
pub use snapshot::SnapshotManager;
pub use snapshot_trigger::{
    AutoEncryptHook, AutoEncryptStatus, KeySource as SnapshotKeySource, SandboxError,
    SnapshotEncryptor, TriggerResult,
};
