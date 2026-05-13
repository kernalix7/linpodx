//! linpodx-plugin — WASM plugin SDK + host runtime.
//!
//! Phase 6 entry crate. Stage 2-A wires manifest parsing, the wasmtime loader, the
//! host ABI shims, and an in-memory registry. Plugins are discovered through the
//! sandbox's `plugin_store` (SQLite-backed) and invoked at approval time.

#![forbid(unsafe_code)]

pub mod host_api;
pub mod key_registry;
pub mod loader;
pub mod manifest;
pub mod registry;
pub mod signing;

pub use key_registry::{KeyEntry, KeyRegistry, KeyRegistryError};
pub use loader::{
    evaluate, evaluate_audit_filter, evaluate_network_trace, evaluate_profile_validator,
    evaluate_runtime_injector, load, LoadedPlugin,
};
pub use manifest::{
    install_to_user_dir, parse_from_dir, remove_user_dir, user_plugin_root, PluginManifest,
};
pub use registry::{PluginRegistry, PluginSpec};
pub use signing::{verify_plugin_signature, SigningError};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PluginError {
    #[error("not yet implemented (Stage 2-A): {0}")]
    NotImplemented(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("manifest parse error: {0}")]
    Manifest(String),
    #[error("wasm load error: {0}")]
    WasmLoad(String),
    #[error("host call rejected: {0}")]
    HostRejected(String),
    #[error("plugin '{0}' not found")]
    NotFound(String),
    #[error("plugin '{0}' already installed")]
    Duplicate(String),
}

pub type Result<T> = std::result::Result<T, PluginError>;

/// Outcome a single approval-rule plugin returns to the host. Combined across all
/// enabled plugins via `Deny > Allow > Defer`. `Defer` means "no opinion — let the
/// human/listener decide".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginDecision {
    Allow,
    Deny,
    Defer,
}

impl PluginDecision {
    pub fn as_u8(&self) -> u8 {
        match self {
            Self::Allow => 1,
            Self::Deny => 2,
            Self::Defer => 0,
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Allow,
            2 => Self::Deny,
            _ => Self::Defer,
        }
    }
}

/// Outcome of a single `audit_filter` plugin run. The registry chains plugins together —
/// the first `Drop` short-circuits the chain and suppresses the audit entry; `Transform`
/// rewrites the payload that subsequent plugins (and ultimately the audit log) see;
/// `Forward` is the no-op default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterDecision {
    Forward,
    Transform { payload: Vec<u8> },
    Drop,
}

/// Outcome of a single `profile_validator` plugin run. Returned per-plugin so the caller
/// can collect every reject reason rather than only the first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidatorDecision {
    Pass,
    Reject { reason: String },
}

/// Outcome of a single `network_trace` plugin run. The runtime egress filter chains
/// these — `Deny` wins regardless of position, otherwise the result is the lowest of
/// `AuditOnly` / `Allow` (we treat `AuditOnly` as "let it through but log").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkDecision {
    Allow,
    Deny,
    AuditOnly,
}

impl NetworkDecision {
    pub fn from_i32(v: i32) -> Self {
        match v {
            1 => Self::Deny,
            2 => Self::AuditOnly,
            _ => Self::Allow,
        }
    }
}

/// One observed network event handed to `network_trace` plugins. Plugins decide whether
/// the runtime should allow, deny, or merely audit the call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTraceEvent {
    /// "dns_query" | "tcp_connect" | "udp_send" — open-ended for forward-compat.
    pub kind: String,
    pub host: String,
    #[serde(default)]
    pub port: Option<u16>,
}

/// Payload returned by a single `runtime_injector` plugin. The registry merges payloads
/// across the chain by concatenating each `Vec` field.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InjectorPayload {
    #[serde(default)]
    pub env_add: Vec<(String, String)>,
    #[serde(default)]
    pub args_append: Vec<String>,
    #[serde(default)]
    pub security_opts_add: Vec<String>,
}

impl InjectorPayload {
    /// Merge `other` into `self` by appending every vector. Used by
    /// [`registry::PluginRegistry::evaluate_runtime_injector`] when chaining plugins.
    pub fn extend_from(&mut self, other: InjectorPayload) {
        self.env_add.extend(other.env_add);
        self.args_append.extend(other.args_append);
        self.security_opts_add.extend(other.security_opts_add);
    }

    pub fn is_empty(&self) -> bool {
        self.env_add.is_empty() && self.args_append.is_empty() && self.security_opts_add.is_empty()
    }
}
