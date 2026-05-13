//! Bridge between the cross-crate `AuditSink` trait (linpodx-common) and the
//! sandbox-internal hash-chained audit log. Subsystems that need to write audit entries
//! without depending on `linpodx-sandbox` (notably `linpodx-mcp`) take an
//! `Arc<dyn AuditSink>` and let this adapter map `AuditSinkKind` → `AuditKind`.
//!
//! Also exposes [`record_mcp_event`], the helper bridges call to insert into
//! `mcp_events` (raw stdio messages, JSON-RPC method extracts, allow/deny decisions).

use crate::audit::{self, AuditKind};
use linpodx_common::audit_sink::{AuditSink, AuditSinkKind};
use linpodx_common::db::Database;
use linpodx_common::error::{Error, Result};
use linpodx_plugin::{FilterDecision, PluginRegistry};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::warn;

pub struct SandboxAuditSink {
    db: Arc<Database>,
    /// Optional plugin chain. When `None` the sink behaves exactly like Phase 6 — every
    /// `record` call goes straight to `audit::append`. When `Some`, every entry is fed
    /// through `evaluate_audit_filter` first; `Drop` suppresses the original entry and
    /// records `AuditFiltered` instead, while `Transform` writes the rewritten payload.
    /// Skipped for the two filter-meta kinds (`AuditFiltered`, `ProfileValidatorRejected`)
    /// to avoid recursion: a plugin that drops the meta-entry would silently hide its own
    /// activity.
    plugin_registry: Option<Arc<RwLock<PluginRegistry>>>,
}

impl SandboxAuditSink {
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            db,
            plugin_registry: None,
        }
    }

    pub fn new_with_plugins(
        db: Arc<Database>,
        plugin_registry: Arc<RwLock<PluginRegistry>>,
    ) -> Self {
        Self {
            db,
            plugin_registry: Some(plugin_registry),
        }
    }
}

impl AuditSink for SandboxAuditSink {
    fn record(
        &self,
        kind: AuditSinkKind,
        profile_name: Option<String>,
        container_id: Option<String>,
        payload: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        let mapped = map_kind(kind);
        let registry = self.plugin_registry.clone();
        Box::pin(async move {
            // Skip the chain for filter-meta entries so a plugin can't silently hide its
            // own activity (and we never recurse into another plugin chain).
            let bypass_chain = matches!(
                kind,
                AuditSinkKind::AuditFiltered | AuditSinkKind::ProfileValidatorRejected
            );
            let (effective_kind, effective_payload) =
                run_audit_filter_chain(registry, kind, mapped, payload, bypass_chain).await;
            if let Err(e) = audit::append(
                &self.db,
                effective_kind,
                profile_name,
                container_id,
                effective_payload,
            )
            .await
            {
                warn!(error = %e, kind = effective_kind.as_str(), "audit sink write failed");
            }
        })
    }
}

/// Run the audit-filter plugin chain for one entry. Always returns the (kind, payload)
/// that should actually land in the audit log. Wasmtime stores aren't `Send`, so the
/// chain runs inside `spawn_blocking`; the surrounding async boundary stays clean.
async fn run_audit_filter_chain(
    registry: Option<Arc<RwLock<PluginRegistry>>>,
    kind: AuditSinkKind,
    mapped: AuditKind,
    payload: serde_json::Value,
    bypass: bool,
) -> (AuditKind, serde_json::Value) {
    if bypass {
        return (mapped, payload);
    }
    let Some(reg) = registry else {
        return (mapped, payload);
    };
    let payload_bytes = match serde_json::to_vec(&payload) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "audit payload serialize failed; bypassing plugin chain");
            return (mapped, payload);
        }
    };
    // Acquire the registry lock here (async), then move ownership of the guard into
    // a spawn_blocking is impossible — instead clone the Arc and lock inside the
    // blocking task with `blocking_write`. That keeps the wasmtime store off the async
    // executor entirely.
    let res = match tokio::task::spawn_blocking(move || {
        let mut guard = reg.blocking_write();
        guard.evaluate_audit_filter(&payload_bytes)
    })
    .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "audit_filter task join failed; bypassing chain");
            return (mapped, payload);
        }
    };
    match res.outcome {
        FilterDecision::Drop => {
            let preview = serde_json::json!({
                "filtered_kind": kind.as_str(),
                "original_payload_preview": payload_preview(&payload),
                "steps": res
                    .steps
                    .iter()
                    .map(|(name, _)| name.clone())
                    .collect::<Vec<_>>(),
            });
            (AuditKind::AuditFiltered, preview)
        }
        FilterDecision::Transform { .. } | FilterDecision::Forward => {
            let new_payload = match serde_json::from_slice::<serde_json::Value>(&res.payload) {
                Ok(v) => v,
                Err(e) => {
                    warn!(error = %e, "audit_filter transform produced invalid JSON; dropping transform");
                    payload
                }
            };
            (mapped, new_payload)
        }
    }
}

/// Truncate the original payload to a 256-char preview before recording the
/// `AuditFiltered` meta-entry. Audit-log size is capped via WAL checkpointing, but the
/// preview keeps even pathological payloads bounded.
fn payload_preview(v: &serde_json::Value) -> serde_json::Value {
    let s = v.to_string();
    if s.len() <= 256 {
        v.clone()
    } else {
        serde_json::Value::String(format!("{}…(truncated)", &s[..256]))
    }
}

fn map_kind(k: AuditSinkKind) -> AuditKind {
    match k {
        AuditSinkKind::SnapshotCreated => AuditKind::SnapshotCreated,
        AuditSinkKind::SnapshotRolledBack => AuditKind::SnapshotRolledBack,
        AuditSinkKind::SnapshotRemoved => AuditKind::SnapshotRemoved,
        AuditSinkKind::SessionStarted => AuditKind::SessionStarted,
        AuditSinkKind::SessionEnded => AuditKind::SessionEnded,
        AuditSinkKind::McpBridgeStarted => AuditKind::McpBridgeStarted,
        AuditSinkKind::McpBridgeStopped => AuditKind::McpBridgeStopped,
        AuditSinkKind::McpToolCalled => AuditKind::McpToolCalled,
        AuditSinkKind::McpToolDenied => AuditKind::McpToolDenied,
        AuditSinkKind::DistroCreated => AuditKind::DistroCreated,
        AuditSinkKind::DistroBuilt => AuditKind::DistroBuilt,
        AuditSinkKind::DistroEntered => AuditKind::DistroEntered,
        AuditSinkKind::DistroRemoved => AuditKind::DistroRemoved,
        AuditSinkKind::PassthroughGranted => AuditKind::PassthroughGranted,
        AuditSinkKind::SnapshotJobStarted => AuditKind::SnapshotJobStarted,
        AuditSinkKind::SnapshotJobFinished => AuditKind::SnapshotJobFinished,
        AuditSinkKind::McpPolicyChanged => AuditKind::McpPolicyChanged,
        AuditSinkKind::NetworkEgressApplied => AuditKind::NetworkEgressApplied,
        AuditSinkKind::NetworkEgressFailed => AuditKind::NetworkEgressFailed,
        AuditSinkKind::McpResourceSubscribed => AuditKind::McpResourceSubscribed,
        AuditSinkKind::McpResourceUnsubscribed => AuditKind::McpResourceUnsubscribed,
        AuditSinkKind::McpResourceUpdated => AuditKind::McpResourceUpdated,
        AuditSinkKind::McpListChanged => AuditKind::McpListChanged,
        AuditSinkKind::SnapshotBranched => AuditKind::SnapshotBranched,
        AuditSinkKind::PluginInstalled => AuditKind::PluginInstalled,
        AuditSinkKind::PluginEnabled => AuditKind::PluginEnabled,
        AuditSinkKind::PluginDisabled => AuditKind::PluginDisabled,
        AuditSinkKind::PluginRemoved => AuditKind::PluginRemoved,
        AuditSinkKind::PluginInvoked => AuditKind::PluginInvoked,
        AuditSinkKind::MetricsCollectorStarted => AuditKind::MetricsCollectorStarted,
        AuditSinkKind::MetricsCollectorStopped => AuditKind::MetricsCollectorStopped,
        AuditSinkKind::SnapshotBackendUsed => AuditKind::SnapshotBackendUsed,
        AuditSinkKind::RemoteSessionStarted => AuditKind::RemoteSessionStarted,
        AuditSinkKind::RemoteAuthFailed => AuditKind::RemoteAuthFailed,
        AuditSinkKind::AuditFiltered => AuditKind::AuditFiltered,
        AuditSinkKind::ProfileValidatorRejected => AuditKind::ProfileValidatorRejected,
        AuditSinkKind::WebUiSessionStarted => AuditKind::WebUiSessionStarted,
        AuditSinkKind::WebUiAccessDenied => AuditKind::WebUiAccessDenied,
        AuditSinkKind::RemoteMtlsAccepted => AuditKind::RemoteMtlsAccepted,
        AuditSinkKind::RemoteMtlsRejected => AuditKind::RemoteMtlsRejected,
        AuditSinkKind::ClusterPeerJoined => AuditKind::ClusterPeerJoined,
        AuditSinkKind::ClusterPeerLeft => AuditKind::ClusterPeerLeft,
        AuditSinkKind::ClusterViewServed => AuditKind::ClusterViewServed,
        AuditSinkKind::SnapshotMounted => AuditKind::SnapshotMounted,
        AuditSinkKind::SnapshotUnmounted => AuditKind::SnapshotUnmounted,
        AuditSinkKind::K8sQueryServed => AuditKind::K8sQueryServed,
        AuditSinkKind::SeccompCompiled => AuditKind::SeccompCompiled,
        AuditSinkKind::ApparmorCompiled => AuditKind::ApparmorCompiled,
        AuditSinkKind::SeccompApplied => AuditKind::SeccompApplied,
        AuditSinkKind::ApparmorApplied => AuditKind::ApparmorApplied,
        AuditSinkKind::ContainerExecCalled => AuditKind::ContainerExecCalled,
        AuditSinkKind::ContainerLogsStreamed => AuditKind::ContainerLogsStreamed,
        AuditSinkKind::ImagePullStarted => AuditKind::ImagePullStarted,
        AuditSinkKind::ImagePushed => AuditKind::ImagePushed,
        AuditSinkKind::ImageManifestCreated => AuditKind::ImageManifestCreated,
        AuditSinkKind::SelinuxCompiled => AuditKind::SelinuxCompiled,
        AuditSinkKind::SelinuxApplied => AuditKind::SelinuxApplied,
        AuditSinkKind::ContainerExecPtyOpened => AuditKind::ContainerExecPtyOpened,
        AuditSinkKind::ContainerExecPtyClosed => AuditKind::ContainerExecPtyClosed,
        AuditSinkKind::K8sPodCreated => AuditKind::K8sPodCreated,
        AuditSinkKind::K8sPodDeleted => AuditKind::K8sPodDeleted,
        AuditSinkKind::K8sNamespaceCreated => AuditKind::K8sNamespaceCreated,
        AuditSinkKind::K8sDeploymentScaled => AuditKind::K8sDeploymentScaled,
        AuditSinkKind::PluginNetworkTraceCalled => AuditKind::PluginNetworkTraceCalled,
        AuditSinkKind::PluginRuntimeInjectorCalled => AuditKind::PluginRuntimeInjectorCalled,
        AuditSinkKind::EgressDenyEnforced => AuditKind::EgressDenyEnforced,
        AuditSinkKind::SelinuxStaticLabelApplied => AuditKind::SelinuxStaticLabelApplied,
        AuditSinkKind::WsAuthSubprotocol => AuditKind::WsAuthSubprotocol,
        AuditSinkKind::ImagePushTls => AuditKind::ImagePushTls,
        AuditSinkKind::ClusterLeaderElected => AuditKind::ClusterLeaderElected,
        AuditSinkKind::ClusterLeaderLost => AuditKind::ClusterLeaderLost,
        AuditSinkKind::ClusterRaftPromoted => AuditKind::ClusterRaftPromoted,
        AuditSinkKind::ClusterRaftDemoted => AuditKind::ClusterRaftDemoted,
        AuditSinkKind::PluginSignatureVerified => AuditKind::PluginSignatureVerified,
        AuditSinkKind::PluginSignatureRejected => AuditKind::PluginSignatureRejected,
        AuditSinkKind::WsClientCertPinned => AuditKind::WsClientCertPinned,
        AuditSinkKind::SelinuxLabelRuntimeFallback => AuditKind::SelinuxLabelRuntimeFallback,
        AuditSinkKind::ClusterStateApplied => AuditKind::ClusterStateApplied,
        AuditSinkKind::ClusterStateProposeFailed => AuditKind::ClusterStateProposeFailed,
        AuditSinkKind::SnapshotEncrypted => AuditKind::SnapshotEncrypted,
        AuditSinkKind::SnapshotDecryptFailed => AuditKind::SnapshotDecryptFailed,
        AuditSinkKind::PluginKeyRevoked => AuditKind::PluginKeyRevoked,
        AuditSinkKind::WsClientCertTofuEnrolled => AuditKind::WsClientCertTofuEnrolled,
        AuditSinkKind::SnapshotKeyRotated => AuditKind::SnapshotKeyRotated,
        AuditSinkKind::SnapshotReEncryptCompleted => AuditKind::SnapshotReEncryptCompleted,
        AuditSinkKind::SandboxSnapshotAutoTriggered => AuditKind::SandboxSnapshotAutoTriggered,
        AuditSinkKind::TofuExpired => AuditKind::TofuExpired,
        AuditSinkKind::PluginKeyRevokePropagated => AuditKind::PluginKeyRevokePropagated,
    }
}

/// Insert one row into `mcp_events`. Used by the bridge for each stdio message it
/// observes. `payload` is stored as-is (the bridge truncates to 8 KiB before calling).
pub async fn record_mcp_event(
    db: &Database,
    session_id: i64,
    direction: &str,
    tool_name: Option<&str>,
    payload: &str,
    decision: Option<&str>,
) -> Result<i64> {
    let row: (i64,) = sqlx::query_as(
        "INSERT INTO mcp_events (session_id, direction, tool_name, payload, decision) \
         VALUES (?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(session_id)
    .bind(direction)
    .bind(tool_name)
    .bind(payload)
    .bind(decision)
    .fetch_one(db.pool())
    .await
    .map_err(Error::Sqlx)?;
    Ok(row.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use linpodx_common::audit_sink::AuditSink;

    async fn fresh_db() -> Database {
        let dir = Box::leak(Box::new(tempfile::tempdir().expect("tempdir")));
        let path = dir.path().join("mcp-audit-test.db");
        let db = Database::open(&path).await.expect("open");
        db.migrate().await.expect("migrate");
        db
    }

    #[tokio::test]
    async fn sink_writes_mapped_audit_kind() {
        let db = Arc::new(fresh_db().await);
        let sink = SandboxAuditSink::new(Arc::clone(&db));
        sink.record(
            AuditSinkKind::McpBridgeStarted,
            None,
            Some("c1".into()),
            serde_json::json!({"bridge_id": "b1"}),
        )
        .await;

        let row: (String,) = sqlx::query_as("SELECT kind FROM audit_log WHERE container_id = 'c1'")
            .fetch_one(db.pool())
            .await
            .expect("audit row");
        assert_eq!(row.0, "mcp_bridge_started");
    }

    #[tokio::test]
    async fn record_mcp_event_inserts_row() {
        let db = Arc::new(fresh_db().await);
        // Need a session row so the FK passes.
        sqlx::query(
            "INSERT INTO mcp_sessions (container_id, container_name) VALUES ('c1', 'name-c1')",
        )
        .execute(db.pool())
        .await
        .unwrap();
        let id = record_mcp_event(
            &db,
            1,
            "host_to_container",
            Some("list_dirs"),
            "{\"method\":\"list_dirs\"}",
            Some("allowed"),
        )
        .await
        .expect("insert");
        assert!(id >= 1);

        let row: (String, Option<String>, Option<String>) =
            sqlx::query_as("SELECT direction, tool_name, decision FROM mcp_events WHERE id = ?")
                .bind(id)
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(row.0, "host_to_container");
        assert_eq!(row.1.as_deref(), Some("list_dirs"));
        assert_eq!(row.2.as_deref(), Some("allowed"));
    }

    #[tokio::test]
    async fn map_kind_covers_all_variants() {
        // Compile-time enumerated; just sanity-check a few mappings.
        assert_eq!(
            map_kind(AuditSinkKind::SnapshotCreated).as_str(),
            "snapshot_created"
        );
        assert_eq!(
            map_kind(AuditSinkKind::McpToolDenied).as_str(),
            "mcp_tool_denied"
        );
        assert_eq!(
            map_kind(AuditSinkKind::SessionEnded).as_str(),
            "session_ended"
        );
    }

    // ---------- Phase 7 plugin v2: audit_filter chain integration ----------

    const DROP_WAT: &str = r#"
        (module
          (import "linpodx_host" "host_return_filter_decision" (func $ret (param i32 i32 i32)))
          (memory (export "memory") 1)
          (func (export "evaluate_audit_filter")
            (call $ret (i32.const 1) (i32.const 0) (i32.const 0))))
    "#;

    const TRANSFORM_WAT: &str = r#"
        (module
          (import "linpodx_host" "host_return_payload" (func $rp (param i32 i32)))
          (import "linpodx_host" "host_return_filter_decision" (func $rfd (param i32 i32 i32)))
          (memory (export "memory") 1)
          (data (i32.const 1024) "{\"k\":\"masked\"}")
          (func (export "evaluate_audit_filter")
            (call $rp (i32.const 1024) (i32.const 14))
            (call $rfd (i32.const 2) (i32.const 0) (i32.const 0))))
    "#;

    fn install_plugin(
        name: &str,
        hook: &str,
        wat: &str,
    ) -> (
        tempfile::TempDir,
        linpodx_plugin::PluginManifest,
        std::path::PathBuf,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let wasm_filename = format!("{}.wasm", name.replace('-', "_"));
        let wasm_bytes = wat::parse_str(wat).expect("compile wat");
        std::fs::write(dir.path().join(&wasm_filename), wasm_bytes).expect("write wasm");
        let manifest_body = format!(
            "name = \"{name}\"\nversion = \"0.1.0\"\nhooks = [\"{hook}\"]\nwasm = \"{wasm_filename}\"\n",
        );
        std::fs::write(dir.path().join("linpodx-plugin.toml"), manifest_body).expect("write toml");
        let (manifest, wasm_abs) =
            linpodx_plugin::parse_from_dir(dir.path()).expect("parse_from_dir");
        (dir, manifest, wasm_abs)
    }

    #[tokio::test]
    async fn sink_with_drop_plugin_records_audit_filtered_instead_of_original() {
        let db = Arc::new(fresh_db().await);
        let mut reg = linpodx_plugin::PluginRegistry::new().expect("registry");
        let (_d, m, w) = install_plugin("drop-all", "audit_filter", DROP_WAT);
        reg.load_one(&m, &w).expect("load");
        let registry = Arc::new(tokio::sync::RwLock::new(reg));
        let sink = SandboxAuditSink::new_with_plugins(Arc::clone(&db), registry);

        sink.record(
            AuditSinkKind::McpBridgeStarted,
            None,
            Some("c1".into()),
            serde_json::json!({"bridge_id": "b1", "secret": "should-not-leak"}),
        )
        .await;

        // The original kind must NOT have been written; the meta-entry must be present.
        let original: Option<(String,)> = sqlx::query_as(
            "SELECT kind FROM audit_log WHERE container_id = 'c1' AND kind = 'mcp_bridge_started'",
        )
        .fetch_optional(db.pool())
        .await
        .expect("query");
        assert!(
            original.is_none(),
            "Drop must suppress the original audit row"
        );

        let meta: (String, String) = sqlx::query_as(
            "SELECT kind, payload FROM audit_log WHERE container_id = 'c1' AND kind = 'audit_filtered'",
        )
        .fetch_one(db.pool())
        .await
        .expect("audit_filtered row");
        assert_eq!(meta.0, "audit_filtered");
        assert!(
            meta.1.contains("mcp_bridge_started"),
            "preview should record the suppressed kind"
        );
    }

    #[tokio::test]
    async fn sink_with_transform_plugin_writes_rewritten_payload() {
        let db = Arc::new(fresh_db().await);
        let mut reg = linpodx_plugin::PluginRegistry::new().expect("registry");
        let (_d, m, w) = install_plugin("xform", "audit_filter", TRANSFORM_WAT);
        reg.load_one(&m, &w).expect("load");
        let registry = Arc::new(tokio::sync::RwLock::new(reg));
        let sink = SandboxAuditSink::new_with_plugins(Arc::clone(&db), registry);

        sink.record(
            AuditSinkKind::McpBridgeStarted,
            None,
            Some("c2".into()),
            serde_json::json!({"orig": true}),
        )
        .await;

        let row: (String, String) =
            sqlx::query_as("SELECT kind, payload FROM audit_log WHERE container_id = 'c2'")
                .fetch_one(db.pool())
                .await
                .expect("audit row");
        // The transform plugin replaces the payload with `{"k":"masked"}`. The kind is
        // still the original (mcp_bridge_started) because Transform doesn't change the
        // kind, only the payload.
        assert_eq!(row.0, "mcp_bridge_started");
        let parsed: serde_json::Value = serde_json::from_str(&row.1).expect("payload json");
        assert_eq!(parsed, serde_json::json!({"k": "masked"}));
    }

    #[tokio::test]
    async fn sink_without_plugins_writes_original_payload() {
        let db = Arc::new(fresh_db().await);
        let sink = SandboxAuditSink::new(Arc::clone(&db));
        sink.record(
            AuditSinkKind::McpBridgeStarted,
            None,
            Some("c3".into()),
            serde_json::json!({"orig": true}),
        )
        .await;
        let row: (String, String) =
            sqlx::query_as("SELECT kind, payload FROM audit_log WHERE container_id = 'c3'")
                .fetch_one(db.pool())
                .await
                .expect("audit row");
        assert_eq!(row.0, "mcp_bridge_started");
        let parsed: serde_json::Value = serde_json::from_str(&row.1).expect("payload json");
        assert_eq!(parsed, serde_json::json!({"orig": true}));
    }

    #[tokio::test]
    async fn audit_filtered_meta_entry_bypasses_chain() {
        // Even if a plugin would Drop everything, AuditFiltered itself must still land in
        // the log — otherwise we'd silently lose the trace of suppression.
        let db = Arc::new(fresh_db().await);
        let mut reg = linpodx_plugin::PluginRegistry::new().expect("registry");
        let (_d, m, w) = install_plugin("drop-all-2", "audit_filter", DROP_WAT);
        reg.load_one(&m, &w).expect("load");
        let registry = Arc::new(tokio::sync::RwLock::new(reg));
        let sink = SandboxAuditSink::new_with_plugins(Arc::clone(&db), registry);

        sink.record(
            AuditSinkKind::AuditFiltered,
            None,
            Some("c4".into()),
            serde_json::json!({"meta": "yes"}),
        )
        .await;

        let row: (String,) = sqlx::query_as(
            "SELECT kind FROM audit_log WHERE container_id = 'c4' AND kind = 'audit_filtered'",
        )
        .fetch_one(db.pool())
        .await
        .expect("audit_filtered preserved");
        assert_eq!(row.0, "audit_filtered");
    }
}
