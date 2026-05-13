use serde::Serialize;
use std::future::Future;
use std::pin::Pin;

/// Object-safe trait for sub-systems (linpodx-mcp, future helpers) that need to write
/// audit entries without depending on the daemon-internal sandbox audit module.
///
/// The sandbox crate provides an adapter that wraps `audit::append`. Tests can use a
/// noop impl that drops every call. This mirrors the `EventPublisher` and
/// `ApprovalGateway` patterns from earlier phases.
pub trait AuditSink: Send + Sync {
    fn record(
        &self,
        kind: AuditSinkKind,
        profile_name: Option<String>,
        container_id: Option<String>,
        payload: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

/// Subset of `AuditKind` that subsystems plugged through `AuditSink` are allowed to write.
/// Sandbox-internal kinds (Profile* / Approval*) stay inside the sandbox crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSinkKind {
    SnapshotCreated,
    SnapshotRolledBack,
    SnapshotRemoved,
    SessionStarted,
    SessionEnded,
    McpBridgeStarted,
    McpBridgeStopped,
    McpToolCalled,
    McpToolDenied,
    // Phase 4 — distro lifecycle
    DistroCreated,
    DistroBuilt,
    DistroEntered,
    DistroRemoved,
    // Phase 3 — passthrough grant audit
    PassthroughGranted,
    // Phase 2E — async snapshot job lifecycle
    SnapshotJobStarted,
    SnapshotJobFinished,
    // Phase 2E — MCP policy admin
    McpPolicyChanged,
    // Phase 5 — L4 egress firewall
    NetworkEgressApplied,
    NetworkEgressFailed,
    // Phase 5 — MCP Phase 2F notifications
    McpResourceSubscribed,
    McpResourceUnsubscribed,
    McpResourceUpdated,
    McpListChanged,
    // Phase 5 — snapshot branching
    SnapshotBranched,
    // Phase 6 — plugin lifecycle + invocation
    PluginInstalled,
    PluginEnabled,
    PluginDisabled,
    PluginRemoved,
    PluginInvoked,
    // Phase 6 — metrics collector lifecycle
    MetricsCollectorStarted,
    MetricsCollectorStopped,
    // Phase 7 — pluggable snapshot backend
    SnapshotBackendUsed,
    // Phase 7 — remote daemon (WebSocket transport)
    RemoteSessionStarted,
    RemoteAuthFailed,
    // Phase 7 — plugin v2 hooks
    AuditFiltered,
    ProfileValidatorRejected,
    // Phase 8 — Web UI
    WebUiSessionStarted,
    WebUiAccessDenied,
    // Phase 8 — mTLS for remote daemon
    RemoteMtlsAccepted,
    RemoteMtlsRejected,
    // Phase 9 — cluster gossip
    ClusterPeerJoined,
    ClusterPeerLeft,
    ClusterViewServed,
    // Phase 9 — overlayfs real mount
    SnapshotMounted,
    SnapshotUnmounted,
    // Phase 10 — K8s read-only adapter
    K8sQueryServed,
    // Phase 11 — seccomp / AppArmor profile generation
    SeccompCompiled,
    ApparmorCompiled,
    SeccompApplied,
    ApparmorApplied,
    // Phase 11 — container exec + log stream + pull progress
    ContainerExecCalled,
    ContainerLogsStreamed,
    ImagePullStarted,
    // Phase 11 — image registry push
    ImagePushed,
    ImageManifestCreated,
    // Phase 12 — SELinux profile generation + interactive PTY proxy
    SelinuxCompiled,
    SelinuxApplied,
    ContainerExecPtyOpened,
    ContainerExecPtyClosed,
    // Phase 13 — K8s write-side + plugin v3 hooks
    K8sPodCreated,
    K8sPodDeleted,
    K8sNamespaceCreated,
    K8sDeploymentScaled,
    PluginNetworkTraceCalled,
    PluginRuntimeInjectorCalled,
    // Phase 14 — security-finalize + push mTLS + cluster Raft
    EgressDenyEnforced,
    SelinuxStaticLabelApplied,
    WsAuthSubprotocol,
    ImagePushTls,
    ClusterLeaderElected,
    ClusterLeaderLost,
    // Phase 15 — cluster multi-node + plugin signing + polish
    ClusterRaftPromoted,
    ClusterRaftDemoted,
    PluginSignatureVerified,
    PluginSignatureRejected,
    WsClientCertPinned,
    SelinuxLabelRuntimeFallback,
    // Phase 16 — cluster state replication + snapshot encryption + supply chain polish
    ClusterStateApplied,
    ClusterStateProposeFailed,
    SnapshotEncrypted,
    SnapshotDecryptFailed,
    PluginKeyRevoked,
    WsClientCertTofuEnrolled,
    // Phase 17 — crypto hardening + supply-chain finalisation
    /// Stream A — a snapshot's at-rest encryption key was rotated.
    SnapshotKeyRotated,
    /// Stream A — a `re-encrypt-all` sweep finished (success or partial).
    SnapshotReEncryptCompleted,
    /// Stream B — sandbox auto-trigger encrypted a freshly-committed snapshot.
    SandboxSnapshotAutoTriggered,
    /// Stream C — TOFU was auto-disabled because `max_age_secs` elapsed.
    TofuExpired,
    /// Stream C — a plugin-key revocation was propagated through Raft.
    PluginKeyRevokePropagated,
}

impl AuditSinkKind {
    pub fn as_str(&self) -> &'static str {
        match self {
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
        }
    }
}

/// No-op sink for unit tests that want to ignore audit traffic.
#[derive(Debug, Default)]
pub struct NoopAuditSink;

impl AuditSink for NoopAuditSink {
    fn record(
        &self,
        _kind: AuditSinkKind,
        _profile_name: Option<String>,
        _container_id: Option<String>,
        _payload: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {})
    }
}
