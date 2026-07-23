use chrono::{DateTime, Utc};
use linpodx_common::db::Database;
use linpodx_common::error::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditKind {
    /// Profile loaded from disk.
    ProfileLoaded,
    /// Profile applied to a container at create time.
    ProfileApplied,
    /// Profile rejected the request (mount violation, etc.).
    ProfileDenied,
    /// `sandbox reload` reloaded all profiles from the directory.
    ProfilesReloaded,
    /// `sandbox verify` ran chain verification.
    ChainVerified,
    // ----- Phase 2A: approval gates -----
    /// An approval gate fired and the listener was prompted.
    ApprovalRequested,
    /// Listener responded with allow.
    ApprovalGranted,
    /// Listener responded with deny.
    ApprovalDenied,
    /// No listener responded within the timeout.
    ApprovalTimedOut,
    /// No listener was registered when the request fired.
    ApprovalNoListener,
    // ----- Phase 2B: snapshot ops -----
    SnapshotCreated,
    SnapshotRolledBack,
    SnapshotRemoved,
    // ----- Phase 2C: session ops -----
    SessionStarted,
    SessionEnded,
    // ----- Phase 2D: MCP bridge ops -----
    McpBridgeStarted,
    McpBridgeStopped,
    McpToolCalled,
    McpToolDenied,
    // ----- Phase 4: distro lifecycle -----
    DistroCreated,
    DistroBuilt,
    DistroEntered,
    DistroRemoved,
    // ----- Phase 3: passthrough audit -----
    PassthroughGranted,
    // ----- Phase 2E: async snapshot job -----
    SnapshotJobStarted,
    SnapshotJobFinished,
    // ----- Phase 2E: MCP per-method policy admin -----
    McpPolicyChanged,
    // ----- Phase 5: L4 egress firewall -----
    NetworkEgressApplied,
    NetworkEgressFailed,
    // ----- Phase 5: MCP Phase 2F notifications -----
    McpResourceSubscribed,
    McpResourceUnsubscribed,
    McpResourceUpdated,
    McpListChanged,
    // ----- Phase 5: snapshot branching -----
    SnapshotBranched,
    // ----- Phase 6: plugin lifecycle + invocation -----
    PluginInstalled,
    PluginEnabled,
    PluginDisabled,
    PluginRemoved,
    PluginInvoked,
    // ----- Phase 6: metrics collector lifecycle -----
    MetricsCollectorStarted,
    MetricsCollectorStopped,
    // ----- Phase 7: pluggable snapshot backend -----
    SnapshotBackendUsed,
    // ----- Phase 7: remote daemon -----
    RemoteSessionStarted,
    RemoteAuthFailed,
    // ----- Phase 7: plugin v2 hooks -----
    AuditFiltered,
    ProfileValidatorRejected,
    // ----- Phase 8: Web UI -----
    WebUiSessionStarted,
    WebUiAccessDenied,
    // ----- Phase 8: mTLS for remote daemon -----
    RemoteMtlsAccepted,
    RemoteMtlsRejected,
    // ----- Phase 9: cluster gossip -----
    ClusterPeerJoined,
    ClusterPeerLeft,
    ClusterViewServed,
    // ----- Phase 9: overlayfs real mount -----
    SnapshotMounted,
    SnapshotUnmounted,
    // ----- Phase 10: K8s read-only adapter -----
    K8sQueryServed,
    // ----- Phase 11: seccomp / AppArmor profile generation -----
    SeccompCompiled,
    ApparmorCompiled,
    SeccompApplied,
    ApparmorApplied,
    // ----- Phase 11: container exec + log stream + pull progress -----
    ContainerExecCalled,
    ContainerLogsStreamed,
    ImagePullStarted,
    // ----- Phase 11: image registry push -----
    ImagePushed,
    ImageManifestCreated,
    // ----- Phase 12: SELinux profile generation + interactive PTY proxy -----
    SelinuxCompiled,
    SelinuxApplied,
    ContainerExecPtyOpened,
    ContainerExecPtyClosed,
    // ----- Phase 13: K8s write-side + plugin v3 hooks -----
    K8sPodCreated,
    K8sPodDeleted,
    K8sNamespaceCreated,
    K8sDeploymentScaled,
    PluginNetworkTraceCalled,
    PluginRuntimeInjectorCalled,
    // ----- Phase 14: security-finalize + push mTLS + cluster Raft -----
    EgressDenyEnforced,
    SelinuxStaticLabelApplied,
    WsAuthSubprotocol,
    ImagePushTls,
    ClusterLeaderElected,
    ClusterLeaderLost,
    // ----- Phase 15: cluster multi-node + plugin signing + polish -----
    ClusterRaftPromoted,
    ClusterRaftDemoted,
    PluginSignatureVerified,
    PluginSignatureRejected,
    WsClientCertPinned,
    SelinuxLabelRuntimeFallback,
    // ----- Phase 16: cluster state replication + snapshot encryption + supply chain polish -----
    ClusterStateApplied,
    ClusterStateProposeFailed,
    SnapshotEncrypted,
    SnapshotDecryptFailed,
    PluginKeyRevoked,
    WsClientCertTofuEnrolled,
    // ----- Phase 17: crypto hardening + supply-chain finalisation -----
    SnapshotKeyRotated,
    SnapshotReEncryptCompleted,
    SandboxSnapshotAutoTriggered,
    TofuExpired,
    PluginKeyRevokePropagated,
    // ----- Phase 26: secrets management -----
    SecretCreated,
    SecretRemoved,
    // ----- Phase 27: container live resource update -----
    ContainerUpdated,
}

impl AuditKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ProfileLoaded => "profile_loaded",
            Self::ProfileApplied => "profile_applied",
            Self::ProfileDenied => "profile_denied",
            Self::ProfilesReloaded => "profiles_reloaded",
            Self::ChainVerified => "chain_verified",
            Self::ApprovalRequested => "approval_requested",
            Self::ApprovalGranted => "approval_granted",
            Self::ApprovalDenied => "approval_denied",
            Self::ApprovalTimedOut => "approval_timed_out",
            Self::ApprovalNoListener => "approval_no_listener",
            Self::SnapshotCreated => "snapshot_created",
            Self::SnapshotRolledBack => "snapshot_rolled_back",
            Self::SnapshotRemoved => "snapshot_removed",
            Self::SessionStarted => "session_started",
            Self::SessionEnded => "session_ended",
            Self::McpBridgeStarted => "mcp_bridge_started",
            Self::McpBridgeStopped => "mcp_bridge_stopped",
            Self::McpToolCalled => "mcp_tool_called",
            Self::McpToolDenied => "mcp_tool_denied",
            Self::DistroCreated => "distro_created",
            Self::DistroBuilt => "distro_built",
            Self::DistroEntered => "distro_entered",
            Self::DistroRemoved => "distro_removed",
            Self::PassthroughGranted => "passthrough_granted",
            Self::SnapshotJobStarted => "snapshot_job_started",
            Self::SnapshotJobFinished => "snapshot_job_finished",
            Self::McpPolicyChanged => "mcp_policy_changed",
            Self::NetworkEgressApplied => "network_egress_applied",
            Self::NetworkEgressFailed => "network_egress_failed",
            Self::McpResourceSubscribed => "mcp_resource_subscribed",
            Self::McpResourceUnsubscribed => "mcp_resource_unsubscribed",
            Self::McpResourceUpdated => "mcp_resource_updated",
            Self::McpListChanged => "mcp_list_changed",
            Self::SnapshotBranched => "snapshot_branched",
            Self::PluginInstalled => "plugin_installed",
            Self::PluginEnabled => "plugin_enabled",
            Self::PluginDisabled => "plugin_disabled",
            Self::PluginRemoved => "plugin_removed",
            Self::PluginInvoked => "plugin_invoked",
            Self::MetricsCollectorStarted => "metrics_collector_started",
            Self::MetricsCollectorStopped => "metrics_collector_stopped",
            Self::SnapshotBackendUsed => "snapshot_backend_used",
            Self::RemoteSessionStarted => "remote_session_started",
            Self::RemoteAuthFailed => "remote_auth_failed",
            Self::AuditFiltered => "audit_filtered",
            Self::ProfileValidatorRejected => "profile_validator_rejected",
            Self::WebUiSessionStarted => "web_ui_session_started",
            Self::WebUiAccessDenied => "web_ui_access_denied",
            Self::RemoteMtlsAccepted => "remote_mtls_accepted",
            Self::RemoteMtlsRejected => "remote_mtls_rejected",
            Self::ClusterPeerJoined => "cluster_peer_joined",
            Self::ClusterPeerLeft => "cluster_peer_left",
            Self::ClusterViewServed => "cluster_view_served",
            Self::SnapshotMounted => "snapshot_mounted",
            Self::SnapshotUnmounted => "snapshot_unmounted",
            Self::K8sQueryServed => "k8s_query_served",
            Self::SeccompCompiled => "seccomp_compiled",
            Self::ApparmorCompiled => "apparmor_compiled",
            Self::SeccompApplied => "seccomp_applied",
            Self::ApparmorApplied => "apparmor_applied",
            Self::ContainerExecCalled => "container_exec_called",
            Self::ContainerLogsStreamed => "container_logs_streamed",
            Self::ImagePullStarted => "image_pull_started",
            Self::ImagePushed => "image_pushed",
            Self::ImageManifestCreated => "image_manifest_created",
            Self::SelinuxCompiled => "selinux_compiled",
            Self::SelinuxApplied => "selinux_applied",
            Self::ContainerExecPtyOpened => "container_exec_pty_opened",
            Self::ContainerExecPtyClosed => "container_exec_pty_closed",
            Self::K8sPodCreated => "k8s_pod_created",
            Self::K8sPodDeleted => "k8s_pod_deleted",
            Self::K8sNamespaceCreated => "k8s_namespace_created",
            Self::K8sDeploymentScaled => "k8s_deployment_scaled",
            Self::PluginNetworkTraceCalled => "plugin_network_trace_called",
            Self::PluginRuntimeInjectorCalled => "plugin_runtime_injector_called",
            Self::EgressDenyEnforced => "egress_deny_enforced",
            Self::SelinuxStaticLabelApplied => "selinux_static_label_applied",
            Self::WsAuthSubprotocol => "ws_auth_subprotocol",
            Self::ImagePushTls => "image_push_tls",
            Self::ClusterLeaderElected => "cluster_leader_elected",
            Self::ClusterLeaderLost => "cluster_leader_lost",
            Self::ClusterRaftPromoted => "cluster_raft_promoted",
            Self::ClusterRaftDemoted => "cluster_raft_demoted",
            Self::PluginSignatureVerified => "plugin_signature_verified",
            Self::PluginSignatureRejected => "plugin_signature_rejected",
            Self::WsClientCertPinned => "ws_client_cert_pinned",
            Self::SelinuxLabelRuntimeFallback => "selinux_label_runtime_fallback",
            Self::ClusterStateApplied => "cluster_state_applied",
            Self::ClusterStateProposeFailed => "cluster_state_propose_failed",
            Self::SnapshotEncrypted => "snapshot_encrypted",
            Self::SnapshotDecryptFailed => "snapshot_decrypt_failed",
            Self::PluginKeyRevoked => "plugin_key_revoked",
            Self::WsClientCertTofuEnrolled => "ws_client_cert_tofu_enrolled",
            Self::SnapshotKeyRotated => "snapshot_key_rotated",
            Self::SnapshotReEncryptCompleted => "snapshot_re_encrypt_completed",
            Self::SandboxSnapshotAutoTriggered => "sandbox_snapshot_auto_triggered",
            Self::TofuExpired => "tofu_expired",
            Self::PluginKeyRevokePropagated => "plugin_key_revoke_propagated",
            Self::SecretCreated => "secret_created",
            Self::SecretRemoved => "secret_removed",
            Self::ContainerUpdated => "container_updated",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub seq: i64,
    pub ts: DateTime<Utc>,
    pub kind: String,
    pub profile_name: Option<String>,
    pub container_id: Option<String>,
    pub payload: serde_json::Value,
    pub prev_hash: String,
    pub this_hash: String,
}

#[derive(Debug, Default, Clone)]
pub struct AuditFilters {
    pub profile_name: Option<String>,
    pub kind: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyReport {
    pub total: i64,
    pub last_seq: Option<i64>,
    pub broken_at: Option<i64>,
}

/// Chain hash version written by [`append`] and understood by [`verify_chain`].
/// v1 rows (migration 0003) hashed only `prev_hash || payload`; v2 hashes every
/// row field so `kind`, `ts`, `profile_name` and `container_id` are also
/// tamper-evident.
const HASH_VERSION_V2: i64 = 2;

/// v1 chain hash — `sha256(prev_hash_hex || payload_json)` as 64-char hex.
///
/// Retained for verifying rows written before the v2 upgrade. It authenticates
/// only `prev_hash` + `payload`, so the `kind` / `ts` / `profile_name` /
/// `container_id` columns of a v1 row are NOT covered. New rows use
/// [`hash_link_v2`].
pub fn hash_link(prev_hash_hex: &str, payload_json: &str) -> String {
    let mut h = Sha256::new();
    h.update(prev_hash_hex.as_bytes());
    h.update(payload_json.as_bytes());
    hex_encode(&h.finalize())
}

/// v2 chain hash — authenticates the full row: `prev_hash`, `kind`, `ts`,
/// `profile_name`, `container_id` and `payload`.
///
/// Fields are fed through an unambiguous, domain-separated, length-prefixed
/// encoding (each field prefixed by its byte length; `Option` fields tagged
/// present/absent) so no combination of field values can collide with a
/// different combination. Altering ANY covered column changes the hash, so a
/// direct DB edit of `kind`, `ts`, `profile_name` or `container_id` now breaks
/// verification just like a `payload` edit already did.
pub fn hash_link_v2(
    prev_hash_hex: &str,
    kind: &str,
    ts: &str,
    profile_name: Option<&str>,
    container_id: Option<&str>,
    payload_json: &str,
) -> String {
    fn feed(h: &mut Sha256, bytes: &[u8]) {
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(bytes);
    }
    fn feed_opt(h: &mut Sha256, v: Option<&str>) {
        match v {
            Some(s) => {
                h.update([1u8]);
                feed(h, s.as_bytes());
            }
            None => h.update([0u8]),
        }
    }

    let mut h = Sha256::new();
    h.update(b"linpodx.audit.v2");
    feed(&mut h, prev_hash_hex.as_bytes());
    feed(&mut h, kind.as_bytes());
    feed(&mut h, ts.as_bytes());
    feed_opt(&mut h, profile_name);
    feed_opt(&mut h, container_id);
    feed(&mut h, payload_json.as_bytes());
    hex_encode(&h.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Append a new audit entry inside a single transaction so concurrent appends serialize.
pub async fn append(
    db: &Database,
    kind: AuditKind,
    profile_name: Option<String>,
    container_id: Option<String>,
    payload: serde_json::Value,
) -> Result<AuditEntry> {
    let payload_json = serde_json::to_string(&payload).map_err(Error::Json)?;
    let ts = Utc::now();
    let ts_str = ts.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let kind_str = kind.as_str().to_string();

    let mut tx = db.pool().begin().await.map_err(Error::Sqlx)?;

    let prev_hash: String = sqlx::query_scalar::<_, String>(
        "SELECT this_hash FROM audit_log ORDER BY seq DESC LIMIT 1",
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(Error::Sqlx)?
    .unwrap_or_else(|| ZERO_HASH.to_string());

    let this_hash = hash_link_v2(
        &prev_hash,
        &kind_str,
        &ts_str,
        profile_name.as_deref(),
        container_id.as_deref(),
        &payload_json,
    );

    let row: (i64,) = sqlx::query_as(
        "INSERT INTO audit_log (ts, kind, profile_name, container_id, payload, prev_hash, this_hash, hash_version)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING seq",
    )
    .bind(&ts_str)
    .bind(&kind_str)
    .bind(&profile_name)
    .bind(&container_id)
    .bind(&payload_json)
    .bind(&prev_hash)
    .bind(&this_hash)
    .bind(HASH_VERSION_V2)
    .fetch_one(&mut *tx)
    .await
    .map_err(Error::Sqlx)?;

    tx.commit().await.map_err(Error::Sqlx)?;

    Ok(AuditEntry {
        seq: row.0,
        ts,
        kind: kind_str,
        profile_name,
        container_id,
        payload,
        prev_hash,
        this_hash,
    })
}

/// Query audit entries, ordered by `seq DESC`. Newest first.
pub async fn query(db: &Database, filters: AuditFilters) -> Result<Vec<AuditEntry>> {
    let mut q = String::from(
        "SELECT seq, ts, kind, profile_name, container_id, payload, prev_hash, this_hash \
         FROM audit_log WHERE 1=1",
    );
    let mut args: Vec<String> = Vec::new();
    if let Some(p) = &filters.profile_name {
        q.push_str(" AND profile_name = ?");
        args.push(p.clone());
    }
    if let Some(k) = &filters.kind {
        q.push_str(" AND kind = ?");
        args.push(k.clone());
    }
    if let Some(since) = &filters.since {
        q.push_str(" AND ts >= ?");
        args.push(since.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string());
    }
    if let Some(until) = &filters.until {
        q.push_str(" AND ts < ?");
        args.push(until.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string());
    }
    q.push_str(" ORDER BY seq DESC");
    if let Some(limit) = filters.limit {
        q.push_str(&format!(" LIMIT {}", limit));
    }

    let mut stmt = sqlx::query(&q);
    for a in &args {
        stmt = stmt.bind(a);
    }
    let rows = stmt.fetch_all(db.pool()).await.map_err(Error::Sqlx)?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        use sqlx::Row;
        let payload_str: String = row.try_get("payload").map_err(Error::Sqlx)?;
        let ts_str: String = row.try_get("ts").map_err(Error::Sqlx)?;
        let ts = parse_ts(&ts_str)?;
        let payload: serde_json::Value = serde_json::from_str(&payload_str).map_err(Error::Json)?;
        out.push(AuditEntry {
            seq: row.try_get("seq").map_err(Error::Sqlx)?,
            ts,
            kind: row.try_get("kind").map_err(Error::Sqlx)?,
            profile_name: row.try_get("profile_name").map_err(Error::Sqlx)?,
            container_id: row.try_get("container_id").map_err(Error::Sqlx)?,
            payload,
            prev_hash: row.try_get("prev_hash").map_err(Error::Sqlx)?,
            this_hash: row.try_get("this_hash").map_err(Error::Sqlx)?,
        });
    }
    Ok(out)
}

/// Re-compute the hash chain from `since_seq` (or seq=1 if None) onward, returning
/// the first broken seq if any.
pub async fn verify_chain(db: &Database, since_seq: Option<i64>) -> Result<VerifyReport> {
    let start = since_seq.unwrap_or(1);

    // Get the prev_hash that the start row should chain from. If start == 1, prev = ZERO_HASH;
    // else prev = this_hash of (start - 1).
    let mut prev_hash = if start <= 1 {
        ZERO_HASH.to_string()
    } else {
        sqlx::query_scalar::<_, String>("SELECT this_hash FROM audit_log WHERE seq = ?")
            .bind(start - 1)
            .fetch_optional(db.pool())
            .await
            .map_err(Error::Sqlx)?
            .unwrap_or_else(|| ZERO_HASH.to_string())
    };

    let rows = sqlx::query(
        "SELECT seq, ts, kind, profile_name, container_id, payload, prev_hash, this_hash, hash_version \
         FROM audit_log WHERE seq >= ? ORDER BY seq ASC",
    )
    .bind(start)
    .fetch_all(db.pool())
    .await
    .map_err(Error::Sqlx)?;

    let mut last_seq: Option<i64> = None;
    let mut broken_at: Option<i64> = None;
    let total = rows.len() as i64;

    for row in rows {
        use sqlx::Row;
        let seq: i64 = row.try_get("seq").map_err(Error::Sqlx)?;
        let ts: String = row.try_get("ts").map_err(Error::Sqlx)?;
        let kind: String = row.try_get("kind").map_err(Error::Sqlx)?;
        let profile_name: Option<String> = row.try_get("profile_name").map_err(Error::Sqlx)?;
        let container_id: Option<String> = row.try_get("container_id").map_err(Error::Sqlx)?;
        let payload: String = row.try_get("payload").map_err(Error::Sqlx)?;
        let stored_prev: String = row.try_get("prev_hash").map_err(Error::Sqlx)?;
        let stored_this: String = row.try_get("this_hash").map_err(Error::Sqlx)?;
        // Older DBs (or defensive reads) default to v1 when the column is absent.
        let version: i64 = row.try_get("hash_version").unwrap_or(1);

        if stored_prev != prev_hash {
            broken_at = Some(seq);
            break;
        }
        let recomputed = if version >= HASH_VERSION_V2 {
            hash_link_v2(
                &prev_hash,
                &kind,
                &ts,
                profile_name.as_deref(),
                container_id.as_deref(),
                &payload,
            )
        } else {
            hash_link(&prev_hash, &payload)
        };
        if recomputed != stored_this {
            broken_at = Some(seq);
            break;
        }
        prev_hash = stored_this;
        last_seq = Some(seq);
    }

    Ok(VerifyReport {
        total,
        last_seq,
        broken_at,
    })
}

fn parse_ts(raw: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| Error::Runtime {
            message: format!("invalid audit ts '{raw}': {e}"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn fresh_db() -> Database {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let path = dir.path().join("audit-test.db");
        let db = Database::open(&path).await.expect("open");
        db.migrate().await.expect("migrate");
        db
    }

    #[test]
    fn hash_link_is_deterministic() {
        let a = hash_link(ZERO_HASH, "{\"x\":1}");
        let b = hash_link(ZERO_HASH, "{\"x\":1}");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn hash_link_changes_on_input_change() {
        let a = hash_link(ZERO_HASH, "{\"x\":1}");
        let b = hash_link(ZERO_HASH, "{\"x\":2}");
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn first_entry_has_zero_prev_hash() {
        let db = fresh_db().await;
        let entry = append(
            &db,
            AuditKind::ProfileLoaded,
            Some("p1".into()),
            None,
            serde_json::json!({"src": "test"}),
        )
        .await
        .unwrap();
        assert_eq!(entry.prev_hash, ZERO_HASH);
        assert_eq!(entry.seq, 1);
    }

    #[tokio::test]
    async fn second_entry_chains_from_first() {
        let db = fresh_db().await;
        let e1 = append(
            &db,
            AuditKind::ProfileLoaded,
            Some("p1".into()),
            None,
            serde_json::json!({"x": 1}),
        )
        .await
        .unwrap();
        let e2 = append(
            &db,
            AuditKind::ProfileApplied,
            Some("p1".into()),
            Some("c1".into()),
            serde_json::json!({"y": 2}),
        )
        .await
        .unwrap();
        assert_eq!(e2.prev_hash, e1.this_hash);
        assert_eq!(e2.seq, 2);
    }

    #[tokio::test]
    async fn verify_chain_passes_on_valid_log() {
        let db = fresh_db().await;
        for i in 0..5 {
            append(
                &db,
                AuditKind::ProfileLoaded,
                Some(format!("p{i}")),
                None,
                serde_json::json!({"i": i}),
            )
            .await
            .unwrap();
        }
        let report = verify_chain(&db, None).await.unwrap();
        assert_eq!(report.total, 5);
        assert_eq!(report.last_seq, Some(5));
        assert!(report.broken_at.is_none());
    }

    #[tokio::test]
    async fn verify_chain_detects_tamper() {
        let db = fresh_db().await;
        for i in 0..3 {
            append(
                &db,
                AuditKind::ProfileLoaded,
                Some(format!("p{i}")),
                None,
                serde_json::json!({"i": i}),
            )
            .await
            .unwrap();
        }
        // Tamper with row seq=2's payload directly via SQL.
        sqlx::query("UPDATE audit_log SET payload = ? WHERE seq = 2")
            .bind("{\"tampered\":true}")
            .execute(db.pool())
            .await
            .unwrap();
        let report = verify_chain(&db, None).await.unwrap();
        assert_eq!(report.broken_at, Some(2));
    }

    // ---- Fix #1: chain v2 covers all row fields ----

    /// Insert a legacy v1 row (hash_version=1, hash over payload only) chained
    /// from `prev`. Returns the row's `this_hash`.
    async fn insert_v1_row(db: &Database, payload: &str, prev: &str) -> String {
        let this = hash_link(prev, payload);
        sqlx::query(
            "INSERT INTO audit_log (ts, kind, profile_name, container_id, payload, prev_hash, this_hash, hash_version) \
             VALUES (?, 'profile_loaded', NULL, NULL, ?, ?, ?, 1)",
        )
        .bind("2026-01-01T00:00:00.000Z")
        .bind(payload)
        .bind(prev)
        .bind(&this)
        .execute(db.pool())
        .await
        .unwrap();
        this
    }

    async fn db_with_three_v2_rows() -> Database {
        let db = fresh_db().await;
        for i in 0..3 {
            append(
                &db,
                AuditKind::ProfileApplied,
                Some(format!("p{i}")),
                Some(format!("c{i}")),
                serde_json::json!({"i": i}),
            )
            .await
            .unwrap();
        }
        db
    }

    #[test]
    fn hash_link_v2_changes_when_any_field_changes() {
        let base = hash_link_v2(ZERO_HASH, "k", "t", Some("p"), Some("c"), "{}");
        assert_eq!(base.len(), 64);
        assert_ne!(
            base,
            hash_link_v2(ZERO_HASH, "K", "t", Some("p"), Some("c"), "{}")
        );
        assert_ne!(
            base,
            hash_link_v2(ZERO_HASH, "k", "T", Some("p"), Some("c"), "{}")
        );
        assert_ne!(
            base,
            hash_link_v2(ZERO_HASH, "k", "t", Some("P"), Some("c"), "{}")
        );
        assert_ne!(
            base,
            hash_link_v2(ZERO_HASH, "k", "t", Some("p"), Some("C"), "{}")
        );
        assert_ne!(
            base,
            hash_link_v2(ZERO_HASH, "k", "t", Some("p"), Some("c"), "{ }")
        );
        // None vs Some("") must not collide (length-prefix + present/absent tag).
        assert_ne!(
            hash_link_v2(ZERO_HASH, "k", "t", None, Some("c"), "{}"),
            hash_link_v2(ZERO_HASH, "k", "t", Some(""), Some("c"), "{}")
        );
    }

    #[tokio::test]
    async fn verify_chain_accepts_legacy_v1_rows() {
        let db = fresh_db().await;
        let mut prev = ZERO_HASH.to_string();
        for i in 0..2 {
            prev = insert_v1_row(&db, &format!("{{\"i\":{i}}}"), &prev).await;
        }
        let report = verify_chain(&db, None).await.unwrap();
        assert_eq!(report.total, 2);
        assert!(report.broken_at.is_none());
        assert_eq!(report.last_seq, Some(2));
    }

    #[tokio::test]
    async fn verify_v2_detects_kind_tamper() {
        let db = db_with_three_v2_rows().await;
        sqlx::query("UPDATE audit_log SET kind = 'profile_denied' WHERE seq = 2")
            .execute(db.pool())
            .await
            .unwrap();
        assert_eq!(verify_chain(&db, None).await.unwrap().broken_at, Some(2));
    }

    #[tokio::test]
    async fn verify_v2_detects_ts_tamper() {
        let db = db_with_three_v2_rows().await;
        sqlx::query("UPDATE audit_log SET ts = '1999-01-01T00:00:00.000Z' WHERE seq = 2")
            .execute(db.pool())
            .await
            .unwrap();
        assert_eq!(verify_chain(&db, None).await.unwrap().broken_at, Some(2));
    }

    #[tokio::test]
    async fn verify_v2_detects_profile_name_tamper() {
        let db = db_with_three_v2_rows().await;
        sqlx::query("UPDATE audit_log SET profile_name = 'evil' WHERE seq = 2")
            .execute(db.pool())
            .await
            .unwrap();
        assert_eq!(verify_chain(&db, None).await.unwrap().broken_at, Some(2));
    }

    #[tokio::test]
    async fn verify_v2_detects_container_id_tamper() {
        let db = db_with_three_v2_rows().await;
        sqlx::query("UPDATE audit_log SET container_id = 'deadbeef' WHERE seq = 2")
            .execute(db.pool())
            .await
            .unwrap();
        assert_eq!(verify_chain(&db, None).await.unwrap().broken_at, Some(2));
    }

    #[tokio::test]
    async fn verify_v2_detects_payload_tamper() {
        let db = db_with_three_v2_rows().await;
        sqlx::query("UPDATE audit_log SET payload = '{\"tampered\":true}' WHERE seq = 2")
            .execute(db.pool())
            .await
            .unwrap();
        assert_eq!(verify_chain(&db, None).await.unwrap().broken_at, Some(2));
    }

    #[tokio::test]
    async fn verify_mixed_v1_and_v2_chain_passes() {
        let db = fresh_db().await;
        // seq=1 is a legacy v1 row; the v2 appends chain on top of it.
        let prev = insert_v1_row(&db, "{\"legacy\":true}", ZERO_HASH).await;
        assert_ne!(prev, ZERO_HASH);
        append(
            &db,
            AuditKind::ProfileApplied,
            Some("p".into()),
            None,
            serde_json::json!({"x": 1}),
        )
        .await
        .unwrap();
        append(
            &db,
            AuditKind::ProfileApplied,
            None,
            Some("c".into()),
            serde_json::json!({"y": 2}),
        )
        .await
        .unwrap();
        let report = verify_chain(&db, None).await.unwrap();
        assert_eq!(report.total, 3);
        assert!(
            report.broken_at.is_none(),
            "a mixed v1+v2 chain must verify end to end"
        );
        assert_eq!(report.last_seq, Some(3));
    }

    #[tokio::test]
    async fn verify_mixed_chain_detects_v1_field_tamper_via_payload() {
        // Even in a mixed chain, tampering the v2 segment is caught.
        let db = fresh_db().await;
        let _ = insert_v1_row(&db, "{\"legacy\":true}", ZERO_HASH).await;
        append(
            &db,
            AuditKind::ProfileApplied,
            Some("p".into()),
            None,
            serde_json::json!({"x": 1}),
        )
        .await
        .unwrap();
        sqlx::query("UPDATE audit_log SET profile_name = 'evil' WHERE seq = 2")
            .execute(db.pool())
            .await
            .unwrap();
        assert_eq!(verify_chain(&db, None).await.unwrap().broken_at, Some(2));
    }
}
