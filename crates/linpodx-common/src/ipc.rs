//! JSON-RPC 2.0 IPC envelope and method definitions.
//!
//! Wire format: NDJSON (one JSON object per line) over a Unix socket.

use crate::passthrough::{DistroKind, PassthroughSpec, SnapshotBackendKind};
use crate::state::{
    ContainerInspect, ContainerSummary, ImageInspect, ImageSummary, NetworkInspect, NetworkSummary,
    PortMapping, VolumeInspect, VolumeMount, VolumeSummary,
};
use crate::types::{ContainerId, ImageId, NetworkId, VolumeId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// JSON-RPC 2.0 request envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: JsonRpcVersion,
    /// Optional request id; absent ≡ notification (no response expected).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<RequestId>,
    #[serde(flatten)]
    pub method: Method,
}

impl RpcRequest {
    pub fn new(id: impl Into<RequestId>, method: Method) -> Self {
        Self {
            jsonrpc: JsonRpcVersion::V2,
            id: Some(id.into()),
            method,
        }
    }
}

/// JSON-RPC 2.0 response envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponse {
    pub jsonrpc: JsonRpcVersion,
    pub id: Option<RequestId>,
    #[serde(flatten)]
    pub payload: ResponsePayload,
}

impl RpcResponse {
    pub fn success(id: Option<RequestId>, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: JsonRpcVersion::V2,
            id,
            payload: ResponsePayload::Success { result },
        }
    }

    pub fn error(id: Option<RequestId>, error: RpcError) -> Self {
        Self {
            jsonrpc: JsonRpcVersion::V2,
            id,
            payload: ResponsePayload::Error { error },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResponsePayload {
    Success { result: serde_json::Value },
    Error { error: RpcError },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JsonRpcVersion {
    #[serde(rename = "2.0")]
    V2,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum RequestId {
    Number(i64),
    String(String),
}

impl From<i64> for RequestId {
    fn from(n: i64) -> Self {
        Self::Number(n)
    }
}

impl From<u32> for RequestId {
    fn from(n: u32) -> Self {
        Self::Number(n as i64)
    }
}

impl From<String> for RequestId {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

impl From<&str> for RequestId {
    fn from(s: &str) -> Self {
        Self::String(s.to_string())
    }
}

/// IPC method enum — type-safe routing.
///
/// `clippy::large_enum_variant` is silenced — `CreateOptions` is the dominant variant
/// (~352 bytes) and boxing it would force every CLI/dispatch call site to deref. The
/// enum is short-lived (constructed per RPC, dropped after dispatch) so the size cost
/// is acceptable.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum Method {
    Version,
    // Container ops (Phase 0)
    ContainerList(ContainerListParams),
    ContainerCreate(CreateOptions),
    ContainerStart(ContainerIdParams),
    ContainerStop(ContainerStopParams),
    ContainerRemove(ContainerRemoveParams),
    ContainerInspect(ContainerIdParams),
    ContainerLogs(ContainerLogsParams),
    // Image ops (Phase 1A)
    ImageList(ImageListParams),
    ImagePull(ImagePullParams),
    ImageRemove(ImageRemoveParams),
    ImageInspect(ImageIdParams),
    ImageTag(ImageTagParams),
    // Volume ops (Phase 1A)
    VolumeList,
    VolumeCreate(VolumeCreateParams),
    VolumeRemove(VolumeRemoveParams),
    VolumeInspect(VolumeNameParams),
    VolumePrune,
    // Network ops (Phase 1A)
    NetworkList,
    NetworkCreate(NetworkCreateParams),
    NetworkRemove(NetworkRemoveParams),
    NetworkInspect(NetworkNameParams),
    NetworkPrune,
    // Event subscription (Phase 1B)
    Subscribe(SubscribeParams),
    // Sandbox / audit ops (Phase 1C)
    SandboxProfileList,
    SandboxProfileGet(SandboxProfileNameParams),
    SandboxProfileReload,
    AuditLogQuery(AuditQueryParams),
    AuditLogVerify(AuditVerifyParams),
    // Approval gates (Phase 2A)
    ApprovalDecision(ApprovalDecisionParams),
    // Snapshot ops (Phase 2B)
    SnapshotCreate(SnapshotCreateParams),
    SnapshotList(SnapshotListParams),
    SnapshotInspect(SnapshotIdParams),
    SnapshotRollback(SnapshotRollbackParams),
    SnapshotRemove(SnapshotRemoveParams),
    SnapshotPrune(SnapshotPruneParams),
    // Session ops (Phase 2C)
    SessionList(SessionListParams),
    SessionInspect(SessionIdParams),
    SessionTimeline(SessionTimelineParams),
    // MCP bridge ops (Phase 2D)
    McpBridgeStart(McpBridgeStartParams),
    McpBridgeStop(McpBridgeStopParams),
    McpBridgeStatus(McpBridgeStatusParams),
    // Async snapshot job (Phase 2E)
    SnapshotJobCreate(SnapshotJobCreateParams),
    SnapshotJobStatus(SnapshotJobStatusParams),
    // MCP per-method approval policy (Phase 2E)
    McpPolicyList,
    McpPolicySet(McpPolicySetParams),
    // Approvals subscription — server-handled like `Subscribe` (Phase 3)
    ApprovalsSubscribe,
    // Multi-distro provisioning (Phase 4)
    DistroTemplateList,
    DistroTemplateInspect(DistroTemplateInspectParams),
    DistroCreate(DistroCreateParams),
    DistroBuild(DistroBuildParams),
    DistroEnter(DistroEnterParams),
    DistroRemove(DistroRemoveParams),
    // L4 egress firewall (Phase 5)
    NetworkEgressApply(NetworkEgressApplyParams),
    // MCP Phase 2F notifications + capabilities (Phase 5)
    McpBridgeCapabilities(McpBridgeCapabilitiesParams),
    McpBridgeSubscriptions(McpBridgeSubscriptionsParams),
    // Snapshot tree / diff (Phase 5)
    SnapshotDiff(SnapshotDiffParams),
    SnapshotBranch(SnapshotBranchParams),
    // WASM plugin SDK (Phase 6)
    PluginList,
    PluginInstall(PluginInstallParams),
    PluginEnable(PluginNameParams),
    PluginDisable(PluginNameParams),
    PluginRemove(PluginRemoveParams),
    // Live container metrics (Phase 6)
    MetricsLatest(MetricsLatestParams),
    MetricsHistory(MetricsHistoryParams),
    // Cluster gossip (Phase 9)
    ClusterJoin(ClusterJoinParams),
    ClusterLeave(ClusterLeaveParams),
    ClusterPeers,
    ClusterContainerView,
    // Cluster Raft leader-elect (Phase 14)
    ClusterLeaderGet,
    ClusterRoleGet,
    // Cluster Raft multi-node (Phase 15)
    ClusterRaftStatus,
    ClusterRaftPromote(ClusterRaftPromoteParams),
    // Cluster state replication (Phase 16)
    ClusterStateGet,
    ClusterStateProposeContainer(ClusterStateProposeContainerParams),
    // Snapshot at-rest encryption (Phase 16)
    SnapshotEncryptionStatus(SnapshotIdParams),
    // Snapshot key rotation / re-encryption (Phase 17 Stream A)
    SnapshotKeyRotate(SnapshotKeyRotateParams),
    SnapshotReEncryptAll(SnapshotReEncryptAllParams),
    // Plugin key rotation / revocation (Phase 16)
    PluginKeyList,
    PluginKeyRevoke(PluginKeyRevokeParams),
    // Plugin key revocation Raft propagation (Phase 17 Stream C)
    PluginKeyRevokePropagate(PluginKeyRevokePropagateParams),
    // Sandbox snapshot auto-trigger (Phase 17 Stream B)
    SandboxSnapshotAutoTriggerStatus,
    SandboxSnapshotAutoTriggerEnable(SandboxSnapshotAutoTriggerEnableParams),
    // Pin store TOFU auto-enroll (Phase 16)
    DaemonPinClientTofuEnable(DaemonPinClientTofuEnableParams),
    // Pin store TOFU time-based expiry (Phase 17 Stream C)
    DaemonPinClientTofuExpiryStatus,
    DaemonPinClientTofuExpirySet(DaemonPinClientTofuExpirySetParams),
    // K8s read-only adapter (Phase 10)
    K8sPodList(K8sNamespaceParams),
    K8sServiceList(K8sNamespaceParams),
    // K8s write-side (Phase 13)
    K8sPodCreate(K8sPodCreateParams),
    K8sPodDelete(K8sPodDeleteParams),
    K8sNamespaceCreate(K8sNamespaceCreateParams),
    K8sDeploymentScale(K8sDeploymentScaleParams),
    // Container exec / log streaming / image pull progress (Phase 11)
    ContainerExec(ContainerExecParams),
    ContainerLogsStream(ContainerLogsStreamParams),
    ImagePullJob(ImagePullJobParams),
    // Interactive PTY proxy (Phase 12)
    ContainerExecPty(ContainerExecPtyParams),
    // Image registry push + multi-arch manifest (Phase 11)
    ImagePush(ImagePushParams),
    ImageManifestCreate(ImageManifestCreateParams),
    ImageManifestPush(ImageManifestPushParams),
    // OCI layer-level diff + pluggable snapshot backend (Phase 7)
    SnapshotDiffV2(SnapshotDiffV2Params),
    SnapshotBackendList,
    // Remote daemon (WebSocket transport) (Phase 7)
    RemoteAuth(RemoteAuthParams),
    RemoteListenStart(RemoteListenStartParams),
    RemoteListenStop,
    RemoteListenStatus,
    // WS client cert pinning (Phase 15)
    DaemonPinClientAdd(DaemonPinClientAddParams),
    DaemonPinClientList,
    DaemonPinClientRemove(DaemonPinClientRemoveParams),
    // Phase 18 — first-run reliability (Stream C / Stream D fill the dispatch bodies).
    DoctorRun(DoctorRunParams),
    DaemonMgmtStart(DaemonMgmtStartParams),
    DaemonMgmtStop,
    DaemonMgmtStatus,
    // Phase 24 — ensure the daemon's loopback plaintext Web UI listener is up
    // and return its URL + bearer token. Used by the Tauri desktop shell to
    // point its webview at the daemon-served leptos UI. Independent of the
    // `--remote-listen` listener (which may be TLS/mTLS).
    WebUiEnsure(WebUiEnsureParams),
    // Phase 25 — system disk-usage aggregate for the Web UI dashboard. Backs
    // `GET /api/v1/system/df`. Unit-like (no params) — the daemon owns the
    // podman invocation + list fallback. Appended, never renumbered.
    SystemDf,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContainerListParams {
    #[serde(default)]
    pub all: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerIdParams {
    pub id: ContainerId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerStopParams {
    pub id: ContainerId,
    #[serde(default)]
    pub timeout_secs: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerRemoveParams {
    pub id: ContainerId,
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerLogsParams {
    pub id: ContainerId,
    /// RFC3339 timestamp.
    #[serde(default)]
    pub since: Option<String>,
    // Note: `follow` is intentionally absent in Phase 0.
    // Streaming logs land in Phase 1B with the event-bus subscription model.
}

// ----- Image params -----

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImageListParams {
    #[serde(default)]
    pub all: bool,
    #[serde(default)]
    pub dangling: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImagePullParams {
    pub reference: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageRemoveParams {
    pub id: ImageId,
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageIdParams {
    pub id: ImageId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageTagParams {
    pub source: ImageId,
    pub target: String,
}

// ----- Volume params -----

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VolumeCreateParams {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub driver: Option<String>,
    #[serde(default)]
    pub labels: Vec<(String, String)>,
    #[serde(default)]
    pub options: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeRemoveParams {
    pub name: VolumeId,
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeNameParams {
    pub name: VolumeId,
}

// ----- Network params -----

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkCreateParams {
    pub name: String,
    #[serde(default)]
    pub driver: Option<String>,
    #[serde(default)]
    pub subnet: Option<String>,
    #[serde(default)]
    pub gateway: Option<String>,
    #[serde(default)]
    pub internal: bool,
    #[serde(default = "default_true_bool")]
    pub dns_enabled: bool,
    #[serde(default)]
    pub labels: Vec<(String, String)>,
}

fn default_true_bool() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRemoveParams {
    pub name: NetworkId,
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkNameParams {
    pub name: NetworkId,
}

// ----- Sandbox / Audit params (Phase 1C) -----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxProfileNameParams {
    pub name: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditQueryParams {
    #[serde(default)]
    pub profile_name: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    /// RFC3339 lower bound on `ts` (inclusive).
    #[serde(default)]
    pub since: Option<String>,
    /// RFC3339 upper bound on `ts` (exclusive).
    #[serde(default)]
    pub until: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditVerifyParams {
    /// If set, only verify entries with `seq >= since_seq`.
    #[serde(default)]
    pub since_seq: Option<i64>,
}

// ----- Snapshot params (Phase 2B) -----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotCreateParams {
    pub container_id: String,
    /// Optional human-readable label. If absent, daemon generates `snap-<seq>`.
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SnapshotListParams {
    /// If set, filter to snapshots of a single container.
    #[serde(default)]
    pub container_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotIdParams {
    pub id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotRollbackParams {
    pub id: i64,
    /// Name for the new container produced from the snapshot. If absent, daemon names it
    /// `<original>-restored-<seq>`.
    #[serde(default)]
    pub new_name: Option<String>,
    /// Keep the original container instead of removing it.
    #[serde(default)]
    pub keep_original: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotRemoveParams {
    pub id: i64,
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SnapshotPruneParams {
    #[serde(default)]
    pub container_id: Option<String>,
    /// Keep this many newest snapshots (per container if `container_id` is set, else
    /// globally). Default: 0 (delete all that match the filter).
    #[serde(default)]
    pub keep_recent: Option<u32>,
}

// ----- Session params (Phase 2C) -----

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionListParams {
    #[serde(default)]
    pub container_id: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionIdParams {
    pub id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTimelineParams {
    pub id: i64,
    /// Filter to specific event kinds (`audit_log.kind` or `mcp_events` direction).
    /// Empty = all.
    #[serde(default)]
    pub kinds: Vec<String>,
}

// ----- MCP bridge params (Phase 2D) -----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpBridgeStartParams {
    pub container_id: String,
    /// Host-side command (e.g. `/usr/bin/cat` or path to an MCP server binary).
    pub host_command: String,
    #[serde(default)]
    pub host_args: Vec<String>,
    /// Optional allowlist of MCP method names. When set, methods outside the list go
    /// through the `ApprovalCategory::McpTool` approval gate. Empty = audit-only, no gate.
    #[serde(default)]
    pub allowlist: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpBridgeStopParams {
    pub bridge_id: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct McpBridgeStatusParams {
    /// If set, return only the bridge with this id (or empty list if absent).
    #[serde(default)]
    pub bridge_id: Option<String>,
}

// ----- Async snapshot job params (Phase 2E) -----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotJobCreateParams {
    pub container_id: String,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotJobStatusParams {
    pub job_id: String,
}

// ----- MCP policy params (Phase 2E) -----

/// One row in the MCP per-method policy table.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpPolicyRule {
    /// JSON-RPC method name, e.g. "tools/call".
    pub method: String,
    /// Optional further qualification (only meaningful for "tools/call").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    pub decision: McpPolicyDecision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpPolicyDecision {
    AutoAllow,
    Prompt,
    Deny,
    AuditOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpPolicySetParams {
    /// Replace existing rules whose `(method, tool_name)` matches; insert new ones.
    pub rules: Vec<McpPolicyRule>,
    /// If true, delete every existing rule before inserting these.
    #[serde(default)]
    pub replace_all: bool,
}

// ----- Distro params (Phase 4) -----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistroTemplateInspectParams {
    pub kind: DistroKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistroCreateParams {
    pub kind: DistroKind,
    /// Instance name (must be unique). Container is named `linpodx-distro-<name>`.
    pub name: String,
    /// VM mode: persistent home volume + auto-restart.
    #[serde(default)]
    pub vm_mode: bool,
    /// Optional passthrough overrides on top of the template's recommended set.
    #[serde(default)]
    pub passthrough: Option<PassthroughSpec>,
    /// Optional pre-built image to use instead of the template's default.
    #[serde(default)]
    pub custom_image: Option<String>,
    /// Optional sandbox profile name to apply.
    #[serde(default)]
    pub sandbox_profile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistroBuildParams {
    pub kind: DistroKind,
    /// Override the template's default base tag (e.g. "24.04" for ubuntu).
    #[serde(default)]
    pub base_tag: Option<String>,
    /// Comma-able list of additional packages to install.
    #[serde(default)]
    pub include: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistroEnterParams {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistroRemoveParams {
    pub name: String,
    /// If true, the persistent home volume is preserved for a future re-create.
    #[serde(default)]
    pub keep_volume: bool,
}

// ----- L4 egress firewall (Phase 5) -----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEgressApplyParams {
    pub container_id: String,
}

// ----- MCP Phase 2F (Phase 5) -----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpBridgeCapabilitiesParams {
    pub bridge_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpBridgeSubscriptionsParams {
    pub bridge_id: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpCapabilities {
    #[serde(default)]
    pub tools: bool,
    #[serde(default)]
    pub resources: bool,
    #[serde(default)]
    pub prompts: bool,
    #[serde(default)]
    pub logging: bool,
    #[serde(default)]
    pub experimental: serde_json::Value,
}

// ----- Snapshot tree (Phase 5) -----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotDiffParams {
    pub id_a: i64,
    pub id_b: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotBranchParams {
    pub parent_id: i64,
    #[serde(default)]
    pub label: Option<String>,
    /// Phase 6 — when true, run a real `podman commit` from the parent's container
    /// rather than just tagging the parent's image. The two rows then point at
    /// distinct image content (true fork-on-write). Requires the parent's
    /// container_id to still be alive.
    #[serde(default)]
    pub fork: bool,
}

// ----- Plugin SDK (Phase 6) -----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInstallParams {
    /// Path to a plugin directory containing `linpodx-plugin.toml` + the wasm binary.
    pub manifest_path: String,
    /// Optional path to a detached ed25519 signature (PKCS#8 PEM or raw 64 bytes)
    /// over the wasm binary. When `None`, install requires `LINPODX_ALLOW_UNSIGNED_PLUGINS=1`
    /// to be set on the daemon. Phase 15 — plugin signature verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_path: Option<std::path::PathBuf>,
    /// Optional path to the ed25519 public key (PEM, SubjectPublicKeyInfo) used to verify
    /// the signature. When `None`, the daemon looks the key up in its trusted-keys
    /// registry by `manifest.publisher`. Phase 15.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_path: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginNameParams {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginRemoveParams {
    pub name: String,
    /// If true, also delete the on-disk plugin directory. Otherwise the row is just
    /// removed from the DB and the wasm files are left for re-install.
    #[serde(default)]
    pub force: bool,
}

// ----- OCI layer diff + snapshot backend (Phase 7) -----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotDiffV2Params {
    pub id_a: i64,
    pub id_b: i64,
}

// ----- Remote daemon (Phase 7) -----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteAuthParams {
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteListenStartParams {
    /// Bind address, e.g. "127.0.0.1:8443" or "0.0.0.0:8443".
    pub addr: String,
    /// Token clients must present in their first WebSocket message.
    pub token: String,
}

// ----- WS client cert pinning (Phase 15) -----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonPinClientAddParams {
    /// PEM-encoded client certificate. The daemon parses it via rustls-pemfile,
    /// computes `Sha256(cert_der)` of the leaf, and stores the lowercase hex
    /// digest as the table primary key.
    pub cert_pem: String,
    /// Operator-supplied label for the pin (free-form). Surfaced in the audit
    /// payload and the `pin-client list` output. Empty string is allowed.
    #[serde(default)]
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonPinClientRemoveParams {
    /// Lowercase hex SHA-256 fingerprint to remove. Pass exactly what
    /// `pin-client list` printed in its `fingerprint` column.
    pub fingerprint: String,
}

// ----- Phase 18: first-run reliability -----

/// Parameters for `Method::DoctorRun` (Stream C — linpodx doctor).
///
/// `doctor` walks a fixed environment-readiness checklist (podman binary +
/// version, rootless setup, cgroup v2 availability, socket permissions, etc.)
/// and emits either a human-readable summary or a machine-parsable JSON
/// document. Stream C fills the dispatch body in
/// `linpodx-daemon/src/dispatch.rs`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DoctorRunParams {
    /// When `true`, the daemon returns a structured `DoctorRunResponse` JSON
    /// instead of a pre-formatted text block.
    #[serde(default)]
    pub json: bool,
}

/// Parameters for `Method::DaemonMgmtStart` (Stream D — daemon lifecycle).
///
/// Asks the running daemon (if any) to spawn or take ownership of a managed
/// daemon process. Stream D fills the dispatch body.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DaemonMgmtStartParams {
    /// Whether to fork a detached background daemon (`linpodx daemon start --fork`).
    #[serde(default)]
    pub fork: bool,
    /// Optional override of the pid-file location. `None` means use the
    /// daemon's compiled-in default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid_file: Option<std::path::PathBuf>,
}

// ----- K8s write-side (Phase 13) -----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sPodCreateParams {
    pub namespace: String,
    /// Inline pod spec YAML. The cluster adapter parses it via serde_norway into a
    /// `k8s_openapi::api::core::v1::Pod` and submits via `Api<Pod>::create`.
    pub pod_spec_yaml: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sPodDeleteParams {
    pub namespace: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sNamespaceCreateParams {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sDeploymentScaleParams {
    pub namespace: String,
    pub name: String,
    pub replicas: i32,
}

// ----- Container exec / log streaming / image pull progress (Phase 11) -----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerExecParams {
    pub container_id: String,
    pub command: Vec<String>,
    /// v0.1: interactive PTY proxy not supported — `interactive=true` is reserved for
    /// v0.2 and currently treated the same as false (no stdin attach).
    #[serde(default)]
    pub interactive: bool,
    #[serde(default)]
    pub tty: bool,
    #[serde(default)]
    pub env: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerLogsStreamParams {
    pub container_id: String,
    #[serde(default)]
    pub follow: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImagePullJobParams {
    pub reference: String,
}

// ----- Interactive PTY proxy (Phase 12) -----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerExecPtyParams {
    pub container_id: String,
    pub command: Vec<String>,
    #[serde(default)]
    pub env: Vec<(String, String)>,
    /// Initial PTY size hint (terminal columns).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cols: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<u16>,
}

// ----- Image registry push + multi-arch manifest (Phase 11) -----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImagePushParams {
    pub reference: String,
    /// Optional registry override. When `None`, podman uses the registry encoded in
    /// the reference (e.g. `docker.io/...`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
    /// Optional base64(user:pass) auth blob — when `None`, podman falls back to
    /// `~/.docker/config.json` / podman auth file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
    /// Optional path to a directory containing `cert.pem`, `key.pem`, and `ca.pem`
    /// for mTLS to a private registry. Mapped to podman's `--cert-dir <path>`.
    /// Phase 14 — image push mTLS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_dir: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageManifestCreateParams {
    /// Local manifest list name, e.g. "myapp:1.0".
    pub target: String,
    /// References to add. Each becomes a `podman manifest add <target> <ref>` call.
    pub refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageManifestPushParams {
    pub manifest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
}

// ----- K8s read-only adapter (Phase 10) -----

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct K8sNamespaceParams {
    /// `None` = use the daemon's default namespace (kubeconfig context default
    /// or `default`). Empty string = same as None.
    #[serde(default)]
    pub namespace: Option<String>,
}

// ----- Cluster gossip (Phase 9) -----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterJoinParams {
    /// Node identifier (free-form, must be unique within the cluster).
    pub node_id: String,
    /// Remote daemon address — `wss://host:port/ipc` or `ws://...`.
    pub addr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterLeaveParams {
    pub node_id: String,
}

// ----- Cluster Raft multi-node (Phase 15) -----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterRaftPromoteParams {
    /// String form of the target node id; the daemon hashes it the same way as
    /// `linpodx_cluster::node_id_from_string` to find the live u64 NodeId.
    pub node_id: String,
}

// ----- Cluster state replication (Phase 16) -----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterStateProposeContainerParams {
    /// Source node that observed the container.
    pub node_id: String,
    /// Container summary to propose into the replicated state machine.
    pub container: crate::state::ContainerSummary,
}

// ----- Plugin key rotation / revocation (Phase 16) -----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginKeyRevokeParams {
    /// Publisher whose key is being revoked. Future plugin installs that match
    /// this publisher will fail until the publisher's key is re-enrolled.
    pub publisher: String,
    /// Optional human-readable reason recorded in the audit row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// ----- Pin store TOFU auto-enroll (Phase 16) -----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonPinClientTofuEnableParams {
    /// When `true`, the next unknown client cert seen during a WebSocket upgrade
    /// is auto-enrolled into `pinned_clients` (Trust-On-First-Use). When `false`,
    /// disables TOFU mode (only explicitly enrolled fingerprints accepted).
    pub enable: bool,
    /// Optional max number of TOFU auto-enrollments before TOFU disables itself.
    /// `None` means no limit (until explicitly disabled).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_enrollments: Option<u32>,
}

// ----- Snapshot key rotation / re-encryption (Phase 17 Stream A) -----

/// New key material supplied for a key rotation. Mirrors the `KeySource` enum
/// in `linpodx-runtime::snapshot_crypto` but stays a transport-friendly subset.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SnapshotKeySource {
    /// Derive the new key from a passphrase via the configured KDF.
    Passphrase { passphrase: String },
    /// Use a base64-encoded raw 32-byte key directly.
    Explicit { key_b64: String },
    /// Read the new key from the environment (e.g. `LINPODX_SNAPSHOT_KEY`).
    Env { var: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotKeyRotateParams {
    /// Snapshot id (from the `snapshots` table) to rotate.
    pub snapshot_id: i64,
    /// New key material. The daemon resolves it through the runtime crate.
    pub new_key: SnapshotKeySource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotReEncryptAllParams {
    /// New key material applied to every encrypted snapshot side-car.
    pub new_key: SnapshotKeySource,
}

// ----- Plugin key revocation Raft propagation (Phase 17 Stream C) -----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginKeyRevokePropagateParams {
    pub publisher: String,
    /// Lowercase-hex SHA-256 fingerprint of the publisher's public key DER.
    pub fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// ----- Sandbox snapshot auto-trigger (Phase 17 Stream B) -----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxSnapshotAutoTriggerEnableParams {
    pub enabled: bool,
}

// ----- Pin TOFU time-based expiry (Phase 17 Stream C) -----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonPinClientTofuExpirySetParams {
    /// Max age in seconds before TOFU auto-disables. `None` clears the expiry
    /// (TOFU stays enabled until manually disabled or `max_enrollments` cap).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age_secs: Option<u64>,
}

// ----- Live metrics (Phase 6) -----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsLatestParams {
    pub container_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsHistoryParams {
    pub container_id: String,
    /// RFC3339 lower bound on `ts` (inclusive). When absent, returns the full ring
    /// buffer (capped at 600 samples per container).
    #[serde(default)]
    pub since: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSample {
    pub container_id: String,
    pub ts: chrono::DateTime<chrono::Utc>,
    /// CPU usage as a fraction of one core (0.5 ≡ 50% of one core, 2.0 ≡ 200%).
    pub cpu_pct: f64,
    pub mem_bytes: u64,
    pub mem_limit: Option<u64>,
    pub net_rx: u64,
    pub net_tx: u64,
    pub block_in: u64,
    pub block_out: u64,
}

// ----- Approval params (Phase 2A) -----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalDecisionParams {
    pub request_id: String,
    pub allow: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// ----- Subscribe / Event types (Phase 1B) -----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeParams {
    /// Topics to subscribe to. Empty Vec = subscribe to all known topics.
    #[serde(default)]
    pub topics: Vec<EventTopic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventTopic {
    Container,
    Image,
    Volume,
    Network,
    Sandbox,
    Audit,
    Snapshot,
    Session,
    Mcp,
    Distro,
    Metrics,
}

impl EventTopic {
    pub const ALL: [EventTopic; 11] = [
        EventTopic::Container,
        EventTopic::Image,
        EventTopic::Volume,
        EventTopic::Network,
        EventTopic::Sandbox,
        EventTopic::Audit,
        EventTopic::Snapshot,
        EventTopic::Session,
        EventTopic::Mcp,
        EventTopic::Distro,
        EventTopic::Metrics,
    ];

    pub fn parse(raw: &str) -> std::result::Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "container" | "containers" => Ok(Self::Container),
            "image" | "images" => Ok(Self::Image),
            "volume" | "volumes" => Ok(Self::Volume),
            "network" | "networks" => Ok(Self::Network),
            "sandbox" | "sandboxes" => Ok(Self::Sandbox),
            "audit" => Ok(Self::Audit),
            "snapshot" | "snapshots" => Ok(Self::Snapshot),
            "session" | "sessions" => Ok(Self::Session),
            "mcp" => Ok(Self::Mcp),
            "distro" | "distros" | "distribution" => Ok(Self::Distro),
            "metrics" | "metric" => Ok(Self::Metrics),
            other => Err(format!(
                "unknown event topic '{other}' (expected: container, image, volume, network, sandbox, audit, snapshot, session, mcp, distro, metrics)"
            )),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Container => "container",
            Self::Image => "image",
            Self::Volume => "volume",
            Self::Network => "network",
            Self::Sandbox => "sandbox",
            Self::Audit => "audit",
            Self::Snapshot => "snapshot",
            Self::Session => "session",
            Self::Mcp => "mcp",
            Self::Distro => "distro",
            Self::Metrics => "metrics",
        }
    }
}

impl std::fmt::Display for EventTopic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Created,
    Started,
    Stopped,
    Removed,
    Renamed,
    Pulled,
    Tagged,
    /// Indeterminate / fractional progress on a long-running operation. The structured
    /// payload (ratio, message) lives in `Event.details`.
    Progress,
    /// Phase 11 — one log line from a streaming `ContainerLogsStream` subscription.
    /// Payload includes `{stream: "stdout"|"stderr", line: String}` in `Event.details`.
    Log,
    /// Long-running operation finished successfully (e.g. snapshot job committed).
    Succeeded,
    /// Long-running operation failed; payload includes error message.
    Failed,
}

impl std::fmt::Display for EventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Created => "created",
            Self::Started => "started",
            Self::Stopped => "stopped",
            Self::Removed => "removed",
            Self::Renamed => "renamed",
            Self::Pulled => "pulled",
            Self::Tagged => "tagged",
            Self::Progress => "progress",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Log => "log",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub topic: EventTopic,
    pub kind: EventKind,
    pub resource_id: String,
    pub timestamp: DateTime<Utc>,
    /// Forward-compat slot for per-event metadata (image ref pulled, container name, etc.).
    #[serde(default)]
    pub details: serde_json::Value,
}

/// Container creation options.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CreateOptions {
    pub image: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub command: Vec<String>,
    #[serde(default)]
    pub env: Vec<(String, String)>,
    #[serde(default)]
    pub labels: Vec<(String, String)>,
    /// Auto-remove on exit (--rm).
    #[serde(default)]
    pub rm: bool,
    /// Detached.
    #[serde(default = "default_true")]
    pub detach: bool,
    // ----- Phase 1A additions -----
    /// `--publish HOST:CONTAINER/PROTO` mappings.
    #[serde(default)]
    pub port_mappings: Vec<PortMapping>,
    /// `--volume SRC:DST[:ro]` mounts. SRC may be a named volume or absolute host path.
    #[serde(default)]
    pub volumes: Vec<VolumeMount>,
    /// `--network NAME` networks to attach.
    #[serde(default)]
    pub networks: Vec<String>,
    // ----- Phase 1C additions -----
    /// `--cap-drop` capabilities (e.g. `["ALL"]`).
    #[serde(default)]
    pub cap_drop: Vec<String>,
    /// `--cap-add` capabilities (added back after drop).
    #[serde(default)]
    pub cap_add: Vec<String>,
    /// `--read-only` rootfs.
    #[serde(default)]
    pub read_only: bool,
    /// `--cpus` (e.g. 1.5).
    #[serde(default)]
    pub cpus: Option<f32>,
    /// `--memory <N>m`.
    #[serde(default)]
    pub memory_mb: Option<u64>,
    /// Sandbox profile name to apply (server-side). The CLI populates this from `--sandbox`,
    /// the daemon translates the named profile via `linpodx-sandbox` before passing to podman.
    #[serde(default)]
    pub sandbox_profile: Option<String>,
    // ----- Phase 3 / 4 additions -----
    /// Per-container desktop / device passthrough grants. `None` ≡ default (empty) spec.
    #[serde(default)]
    pub passthrough: Option<PassthroughSpec>,
    /// Run with `--systemd=true` (Phase 4 — systemd-in-container).
    #[serde(default)]
    pub systemd: bool,
    /// Forward to `--restart=unless-stopped` (Phase 4 — VM mode auto-restart).
    #[serde(default)]
    pub auto_restart: bool,
    /// `--userns=keep-id` to map host UID/GID into the container 1:1 (Phase 4 — VM mode).
    #[serde(default)]
    pub keep_user_id: bool,
    // ----- Phase 10: overlayfs --rootfs injection -----
    /// When set, runs `podman create --rootfs <path>` instead of using `image`.
    /// Wired by the Phase 9 OverlayfsBackend mount registry — Phase 10 dispatch
    /// promotes the audit-only hook into actual injection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rootfs: Option<String>,
    // ----- Phase 11: --security-opt entries from secprofile compiler -----
    /// Each entry becomes one `--security-opt <s>` argument on `podman create`.
    /// Populated by the sandbox `SecProfileCompiler` when a profile carries a
    /// `syscall_allowlist` or `apparmor_extra`. Empty by default; serde-skipped
    /// when empty so existing IPC consumers / golden JSON tests don't see drift.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub security_opts: Vec<String>,
}

fn default_true() -> bool {
    true
}

// ----- Local Web UI listener (Phase 24) -----

/// Params for [`Method::WebUiEnsure`]. Intentionally empty — the daemon owns the
/// bind address (ephemeral loopback) and token generation. Kept as a struct
/// (rather than a unit variant) so future knobs can be added without a wire
/// break.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WebUiEnsureParams {}

/// Successful response payload helpers (typed views over the JSON `result`).
pub mod responses {
    use super::*;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct VersionResponse {
        pub linpodx_version: String,
        pub ipc_version: u32,
        pub podman_version: String,
    }

    pub type ContainerListResponse = Vec<ContainerSummary>;
    pub type ContainerCreateResponse = ContainerId;
    pub type ContainerInspectResponse = ContainerInspect;

    // Image responses (Phase 1A)
    pub type ImageListResponse = Vec<ImageSummary>;
    pub type ImagePullResponse = ImageId;
    pub type ImageInspectResponse = ImageInspect;

    // Volume responses (Phase 1A)
    pub type VolumeListResponse = Vec<VolumeSummary>;
    pub type VolumeCreateResponse = VolumeId;
    pub type VolumeInspectResponse = VolumeInspect;
    pub type VolumePruneResponse = Vec<VolumeId>;

    // Network responses (Phase 1A)
    pub type NetworkListResponse = Vec<NetworkSummary>;
    pub type NetworkCreateResponse = NetworkId;
    pub type NetworkInspectResponse = NetworkInspect;
    pub type NetworkPruneResponse = Vec<NetworkId>;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct LogsResponse {
        pub stdout: String,
        pub stderr: String,
    }

    // Subscribe response (Phase 1B)
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SubscribeResponse {
        pub topics: Vec<EventTopic>,
        pub since: chrono::DateTime<chrono::Utc>,
    }

    // Sandbox / Audit responses (Phase 1C)
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SandboxProfileSummary {
        pub name: String,
        pub description: String,
        pub version: u32,
        pub yaml_hash: String,
        pub last_updated: chrono::DateTime<chrono::Utc>,
    }

    pub type SandboxProfileListResponse = Vec<SandboxProfileSummary>;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SandboxProfileGetResponse {
        pub name: String,
        pub yaml: String,
        pub yaml_hash: String,
        pub last_updated: chrono::DateTime<chrono::Utc>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SandboxProfileReloadResponse {
        pub loaded: usize,
        pub names: Vec<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AuditEntrySummary {
        pub seq: i64,
        pub ts: chrono::DateTime<chrono::Utc>,
        pub kind: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub profile_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub container_id: Option<String>,
        pub payload: serde_json::Value,
        pub prev_hash: String,
        pub this_hash: String,
    }

    pub type AuditLogQueryResponse = Vec<AuditEntrySummary>;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AuditVerifyResponse {
        pub total: i64,
        pub last_seq: Option<i64>,
        /// `Some(seq)` if a tampered entry was found, else `None`.
        pub broken_at: Option<i64>,
    }

    // Approval response (Phase 2A)
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ApprovalDecisionResponse {
        /// `true` if the daemon was still waiting on this request_id and accepted the
        /// decision. `false` means the request was unknown (already resolved or expired).
        pub accepted: bool,
    }

    // Snapshot responses (Phase 2B)
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SnapshotSummary {
        pub id: i64,
        pub container_id: String,
        pub label: Option<String>,
        pub image_ref: String,
        pub parent_id: Option<i64>,
        pub created_at: chrono::DateTime<chrono::Utc>,
        pub size_bytes: Option<u64>,
    }

    pub type SnapshotListResponse = Vec<SnapshotSummary>;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SnapshotCreateResponse {
        pub id: i64,
        pub image_ref: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SnapshotRollbackResponse {
        pub new_container_id: String,
        pub new_container_name: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SnapshotPruneResponse {
        pub removed: Vec<i64>,
    }

    // Session responses (Phase 2C)
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SessionSummary {
        pub id: i64,
        pub container_id: String,
        pub container_name: String,
        pub profile_name: Option<String>,
        pub started_at: chrono::DateTime<chrono::Utc>,
        pub ended_at: Option<chrono::DateTime<chrono::Utc>>,
        pub status: String,
    }

    pub type SessionListResponse = Vec<SessionSummary>;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SessionTimelineEntry {
        /// "audit" or "mcp"
        pub source: String,
        pub ts: chrono::DateTime<chrono::Utc>,
        pub kind: String,
        pub payload: serde_json::Value,
    }

    pub type SessionTimelineResponse = Vec<SessionTimelineEntry>;

    // MCP responses (Phase 2D)
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct McpBridgeStartResponse {
        pub bridge_id: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct McpBridgeStopResponse {
        pub bridge_id: String,
        pub stopped: bool,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct McpBridgeStatusEntry {
        pub bridge_id: String,
        pub container_id: String,
        pub host_command: String,
        pub started_at: chrono::DateTime<chrono::Utc>,
        pub messages_seen: u64,
    }

    pub type McpBridgeStatusResponse = Vec<McpBridgeStatusEntry>;

    // ----- Async snapshot job responses (Phase 2E) -----
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SnapshotJobCreateResponse {
        pub job_id: String,
        pub status: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SnapshotJobStatusResponse {
        pub job_id: String,
        pub container_id: String,
        pub label: Option<String>,
        pub status: String,
        pub snapshot_id: Option<i64>,
        pub image_ref: Option<String>,
        pub last_progress: Option<String>,
        pub error_message: Option<String>,
        pub started_at: chrono::DateTime<chrono::Utc>,
        pub ended_at: Option<chrono::DateTime<chrono::Utc>>,
    }

    // ----- MCP policy responses (Phase 2E) -----
    pub type McpPolicyListResponse = Vec<super::McpPolicyRule>;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct McpPolicySetResponse {
        pub upserted: usize,
        pub deleted: usize,
    }

    // ----- Approvals subscribe response (Phase 3) -----
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ApprovalsSubscribeResponse {
        pub since: chrono::DateTime<chrono::Utc>,
    }

    // ----- Distro responses (Phase 4) -----
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DistroTemplateSummary {
        pub kind: super::DistroKind,
        pub display_name: String,
        pub default_image: String,
        pub init_kind: String, // "none" | "systemd" | "openrc"
        pub default_packages: Vec<String>,
    }

    pub type DistroTemplateListResponse = Vec<DistroTemplateSummary>;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DistroTemplateInspectResponse {
        pub kind: super::DistroKind,
        pub display_name: String,
        pub default_image: String,
        pub init_kind: String,
        pub default_packages: Vec<String>,
        pub recommended_passthrough: super::PassthroughSpec,
        pub default_shell: String,
        pub notes: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DistroInstanceSummary {
        pub id: i64,
        pub name: String,
        pub kind: super::DistroKind,
        pub container_id: String,
        pub image_ref: String,
        pub vm_mode: bool,
        pub home_volume: Option<String>,
        pub auto_restart: bool,
        pub created_at: chrono::DateTime<chrono::Utc>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DistroCreateResponse {
        pub instance: DistroInstanceSummary,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DistroBuildResponse {
        pub image_ref: String,
        pub duration_ms: u64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DistroEnterResponse {
        pub container_id: String,
        pub suggested_command: Vec<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DistroRemoveResponse {
        pub name: String,
        pub kept_volume: bool,
    }

    // ----- L4 egress firewall response (Phase 5) -----
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct NetworkEgressApplyResponse {
        pub container_id: String,
        /// `true` if the privileged helper applied the rules; `false` if the helper was
        /// unavailable and only the DNS-only filter remains (graceful degradation).
        pub helper_applied: bool,
        pub rules_applied: usize,
    }

    // ----- MCP Phase 2F responses (Phase 5) -----
    pub type McpBridgeCapabilitiesResponse = super::McpCapabilities;

    pub type McpBridgeSubscriptionsResponse = Vec<String>;

    // ----- Snapshot tree responses (Phase 5) -----
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SnapshotDiffResponse {
        pub id_a: i64,
        pub id_b: i64,
        pub added: Vec<String>,
        pub modified: Vec<String>,
        pub deleted: Vec<String>,
        pub size_delta_bytes: i64,
    }

    pub type SnapshotBranchResponse = SnapshotSummary;

    // ----- Plugin SDK responses (Phase 6) -----
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PluginSummary {
        pub name: String,
        pub version: String,
        pub hooks: Vec<String>,
        pub enabled: bool,
        pub manifest_path: String,
        pub installed_at: chrono::DateTime<chrono::Utc>,
    }

    pub type PluginListResponse = Vec<PluginSummary>;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PluginInstallResponse {
        pub name: String,
        pub version: String,
        pub installed_path: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PluginToggleResponse {
        pub name: String,
        pub enabled: bool,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PluginRemoveResponse {
        pub name: String,
        pub deleted_files: bool,
    }

    // ----- Live metrics responses (Phase 6) -----
    pub type MetricsLatestResponse = Option<super::MetricsSample>;
    pub type MetricsHistoryResponse = Vec<super::MetricsSample>;

    // ----- Cluster responses (Phase 9) -----
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ClusterPeerSummary {
        pub node_id: String,
        pub addr: String,
        pub status: String, // "alive" | "stale" | "dead"
        pub last_seen: chrono::DateTime<chrono::Utc>,
    }

    pub type ClusterPeersResponse = Vec<ClusterPeerSummary>;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ClusterJoinResponse {
        pub node_id: String,
        pub joined: bool,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ClusterLeaveResponse {
        pub node_id: String,
        pub removed: bool,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ClusterContainerEntry {
        pub node_id: String,
        pub container: super::ContainerSummary,
    }

    pub type ClusterContainerViewResponse = Vec<ClusterContainerEntry>;

    // ----- Cluster Raft leader-elect responses (Phase 14) -----
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ClusterLeaderGetResponse {
        /// Current Raft leader's node id, or `None` if no leader is currently known
        /// (election in progress, single-node bootstrap not done, etc.).
        pub leader: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum ClusterRole {
        Leader,
        Follower,
        Candidate,
        Learner,
        Unknown,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ClusterRoleGetResponse {
        pub node_id: String,
        pub role: ClusterRole,
        /// When `role == Follower`, the leader the follower currently sees (best-effort).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub leader: Option<String>,
    }

    // ----- Cluster Raft multi-node responses (Phase 15) -----
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RaftMembershipNode {
        /// Hashed u64 NodeId (string form for JSON safety).
        pub node_id: String,
        /// Optional human-readable label / address.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        /// "voter" | "learner".
        pub role: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ClusterRaftStatusResponse {
        pub local_node_id: String,
        pub local_role: ClusterRole,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub leader: Option<String>,
        pub voters: Vec<RaftMembershipNode>,
        pub learners: Vec<RaftMembershipNode>,
        /// Last-known Raft term (best-effort).
        pub current_term: u64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ClusterRaftPromoteResponse {
        pub node_id: String,
        /// New role after promotion: typically "voter".
        pub new_role: String,
    }

    // ----- Cluster state replication responses (Phase 16) -----
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ClusterStateGetResponse {
        /// Last applied Raft log index on this node.
        pub last_applied: u64,
        /// All container summaries in the replicated view, grouped by node.
        pub containers: Vec<super::responses::ClusterContainerEntry>,
        /// Total bytes consumed by the state machine on disk (best-effort).
        pub state_bytes: u64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ClusterStateProposeContainerResponse {
        /// Raft log index assigned to the proposed entry.
        pub log_index: u64,
        pub committed: bool,
    }

    // ----- Snapshot encryption responses (Phase 16) -----
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SnapshotEncryptionStatusResponse {
        pub snapshot_id: i64,
        pub encrypted: bool,
        /// AEAD identifier when encrypted, e.g. "aes-256-gcm".
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub algorithm: Option<String>,
        /// Key derivation scheme: "passphrase", "env", "kms-stub".
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub key_source: Option<String>,
        /// Sha256 of the ciphertext file (lowercase hex), best-effort.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ciphertext_sha256: Option<String>,
    }

    // ----- Plugin key registry responses (Phase 16) -----
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PluginKeyEntry {
        pub publisher: String,
        /// Public key fingerprint (sha256 of DER, lowercase hex).
        pub fingerprint: String,
        /// "active" | "revoked".
        pub status: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
    }

    pub type PluginKeyListResponse = Vec<PluginKeyEntry>;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PluginKeyRevokeResponse {
        pub publisher: String,
        pub revoked: bool,
    }

    // ----- Pin TOFU response (Phase 16) -----
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DaemonPinClientTofuEnableResponse {
        pub enabled: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub max_enrollments: Option<u32>,
    }

    // ----- Snapshot key rotation / re-encryption responses (Phase 17 Stream A) -----
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SnapshotKeyRotateResponse {
        pub snapshot_id: i64,
        pub rotated: bool,
        /// New algorithm identifier (e.g. "aes-256-gcm").
        pub algorithm: String,
        /// New KDF identifier (e.g. "argon2id" / "sha256-1k").
        pub kdf: String,
        /// New ciphertext SHA-256 (lowercase hex).
        pub ciphertext_sha256: String,
    }

    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct SnapshotReEncryptAllResponse {
        pub total_seen: u32,
        pub re_encrypted: u32,
        pub skipped: u32,
        pub failed: u32,
    }

    // ----- Plugin key revoke propagate response (Phase 17 Stream C) -----
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PluginKeyRevokePropagateResponse {
        pub publisher: String,
        pub fingerprint: String,
        /// Raft log index assigned to the propagation entry, if available.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub log_index: Option<u64>,
        pub propagated: bool,
    }

    // ----- Sandbox snapshot auto-trigger responses (Phase 17 Stream B) -----
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SandboxSnapshotAutoTriggerStatusResponse {
        pub enabled: bool,
        /// Last image_ref that triggered the auto-encrypt hook, if any.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub last_image_ref: Option<String>,
        /// Lifetime trigger count since daemon start.
        pub trigger_count: u64,
    }

    // ----- Pin TOFU expiry responses (Phase 17 Stream C) -----
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DaemonPinClientTofuExpiryStatusResponse {
        pub enabled: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub max_age_secs: Option<u64>,
        /// Unix-seconds timestamp when TOFU was enabled, if at all.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled_at: Option<i64>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DaemonPinClientTofuExpirySetResponse {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub max_age_secs: Option<u64>,
    }

    // ----- K8s responses (Phase 10) -----
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct K8sPodSummary {
        pub namespace: String,
        pub name: String,
        pub phase: String,
        pub node: Option<String>,
        pub containers: Vec<String>,
        pub created_at: Option<chrono::DateTime<chrono::Utc>>,
    }

    pub type K8sPodListResponse = Vec<K8sPodSummary>;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct K8sServiceSummary {
        pub namespace: String,
        pub name: String,
        pub service_type: String,
        pub cluster_ip: Option<String>,
        pub ports: Vec<String>,
    }

    pub type K8sServiceListResponse = Vec<K8sServiceSummary>;

    // ----- K8s write-side responses (Phase 13) -----
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct K8sPodCreateResponse {
        pub namespace: String,
        pub name: String,
        pub uid: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct K8sPodDeleteResponse {
        pub namespace: String,
        pub name: String,
        pub deleted: bool,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct K8sNamespaceCreateResponse {
        pub name: String,
        pub uid: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct K8sDeploymentScaleResponse {
        pub namespace: String,
        pub name: String,
        pub replicas: i32,
    }

    // ----- Container exec / logs / pull responses (Phase 11) -----
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ContainerExecResponse {
        pub exit_code: i32,
        pub stdout: String,
        pub stderr: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ContainerLogsStreamResponse {
        /// Confirms the subscription started; subsequent log lines arrive via
        /// `EventTopic::Container` + `EventKind::Log` notifications.
        pub started: bool,
        pub container_id: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ImagePullJobResponse {
        pub job_id: String,
        pub status: String,
    }

    // ----- Interactive PTY proxy response (Phase 12) -----
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ContainerExecPtyResponse {
        /// Bridge id; client opens a separate WebSocket connection to
        /// `/pty/<bridge_id>` for bidirectional binary stream.
        pub bridge_id: String,
        /// Path to the WebSocket endpoint, e.g. "/pty/abcd1234".
        pub endpoint: String,
    }

    // ----- Image push + manifest responses (Phase 11) -----
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ImagePushResponse {
        pub reference: String,
        pub digest: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ImageManifestCreateResponse {
        pub manifest: String,
        pub added: Vec<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ImageManifestPushResponse {
        pub manifest: String,
        pub registry: Option<String>,
    }

    // ----- OCI layer diff + snapshot backend responses (Phase 7) -----
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct LayerInfo {
        pub layer_id: String,
        pub size_bytes: i64,
        /// `created_by` from the layer's history entry, if known.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub created_by: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct FileChange {
        pub kind: String, // "added" | "modified" | "deleted"
        pub path: String,
        pub layer_id: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SnapshotDiffV2Response {
        pub id_a: i64,
        pub id_b: i64,
        pub common_layer_count: usize,
        pub a_only_layers: Vec<LayerInfo>,
        pub b_only_layers: Vec<LayerInfo>,
        pub file_changes: Vec<FileChange>,
        pub size_delta_bytes: i64,
        pub used_layer_path: bool,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SnapshotBackendInfo {
        pub kind: super::SnapshotBackendKind,
        pub available: bool,
        pub note: String,
    }

    pub type SnapshotBackendListResponse = Vec<SnapshotBackendInfo>;

    // ----- Remote daemon responses (Phase 7) -----
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RemoteAuthResponse {
        pub accepted: bool,
        pub since: chrono::DateTime<chrono::Utc>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RemoteListenStartResponse {
        pub addr: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RemoteListenStatusResponse {
        pub addr: Option<String>,
        pub running: bool,
        pub sessions: u64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RemoteListenStopResponse {
        pub stopped: bool,
    }

    // ----- WS client cert pin responses (Phase 15) -----
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PinnedClientSummary {
        /// Lowercase hex SHA-256 of the cert DER. Stable across re-encodings.
        pub fingerprint: String,
        pub label: String,
        pub enrolled_at: chrono::DateTime<chrono::Utc>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DaemonPinClientAddResponse {
        pub fingerprint: String,
        /// `true` if the row was inserted; `false` if a row with the same
        /// fingerprint already existed (no-op upsert).
        pub inserted: bool,
    }

    pub type DaemonPinClientListResponse = Vec<PinnedClientSummary>;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DaemonPinClientRemoveResponse {
        pub fingerprint: String,
        pub removed: bool,
    }

    // ----- Phase 18: first-run reliability -----

    /// Outcome of a single doctor check. `Pass` = ready, `Warn` = degraded but
    /// usable, `Fail` = blocker the user must resolve before linpodx will work.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum DoctorOutcome {
        Pass,
        Warn,
        Fail,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DoctorCheck {
        /// Stable check identifier (e.g. `"podman-installed"`, `"cgroup-v2"`).
        pub id: String,
        pub label: String,
        pub outcome: DoctorOutcome,
        /// Free-form human-readable detail (e.g. detected version, suggested fix).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub detail: Option<String>,
        /// Optional documentation pointer (relative path under `docs/` or URL).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub fix_hint: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DoctorRunResponse {
        pub checks: Vec<DoctorCheck>,
        pub pass_count: u32,
        pub warn_count: u32,
        pub fail_count: u32,
    }

    /// Lifecycle of the daemon process from a managing CLI's point of view.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum DaemonMgmtState {
        Running,
        Stopped,
        Unknown,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DaemonMgmtStartResponse {
        pub state: DaemonMgmtState,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pid: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pid_file: Option<std::path::PathBuf>,
        /// Free-form message — e.g. "started", "already running", or a hint.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DaemonMgmtStopResponse {
        pub state: DaemonMgmtState,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DaemonMgmtStatusResponse {
        pub state: DaemonMgmtState,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pid: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub pid_file: Option<std::path::PathBuf>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub socket_path: Option<std::path::PathBuf>,
        /// Daemon uptime in seconds, when discoverable.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub uptime_secs: Option<u64>,
    }

    // ----- Local Web UI listener response (Phase 24) -----
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct WebUiEnsureResponse {
        /// Base URL of the loopback plaintext listener, e.g.
        /// `http://127.0.0.1:53187`. The shell navigates to
        /// `<url>/ui/?token=<token>`.
        pub url: String,
        /// Per-daemon-lifetime bearer token accepted by the `/api/v1/*` and
        /// WebSocket auth paths on this listener.
        pub token: String,
        /// `true` when this call bound + spawned the listener; `false` when a
        /// previously-started listener was reused (url/token are stable).
        pub started: bool,
    }

    // ----- System disk-usage aggregate (Phase 25) -----

    /// Container-domain slice of [`SystemDfResponse`]. `size_bytes` is `None`
    /// when podman's `system df` did not supply per-container writable-layer
    /// sizes (the list-only fallback path).
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SystemDfContainers {
        pub total: u64,
        pub running: u64,
        pub size_bytes: Option<u64>,
    }

    /// Image-domain slice of [`SystemDfResponse`]. `size_bytes` is the sum of
    /// image sizes (may double-count shared layers on the list-only path);
    /// `reclaimable_bytes` is only populated from `podman system df`.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SystemDfImages {
        pub total: u64,
        pub size_bytes: Option<u64>,
        pub reclaimable_bytes: Option<u64>,
    }

    /// Volume-domain slice of [`SystemDfResponse`]. `size_bytes` is only
    /// populated from `podman system df`.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SystemDfVolumes {
        pub total: u64,
        pub size_bytes: Option<u64>,
    }

    /// Response for `Method::SystemDf` / `GET /api/v1/system/df`. Every count
    /// is a `u64`; every `*_bytes` is `u64` when known and `null` when podman's
    /// `system df` was unavailable and only counts could be produced.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SystemDfResponse {
        pub containers: SystemDfContainers,
        pub images: SystemDfImages,
        pub volumes: SystemDfVolumes,
        pub build_cache_bytes: Option<u64>,
    }

    /// Composite response for `GET /api/v1/system/info`. Assembled in the REST
    /// layer from `Method::Version` + `Method::DaemonMgmtStatus`, plus the web
    /// listener base URL. Not backed by a dedicated IPC method.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SystemInfoResponse {
        pub linpodx_version: String,
        pub ipc_version: u32,
        pub podman_version: String,
        pub socket_path: Option<String>,
        pub web_listener_url: Option<String>,
        pub uptime_secs: Option<u64>,
    }
}

// =========================
// Server messages (Phase 1B)
// =========================

/// Anything the daemon can send to a client over the same socket connection.
/// Distinguished structurally — `Response` has an `id` and either `result` or `error`;
/// `Notification` has `method` + `params` but no `id` (per JSON-RPC 2.0).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServerMessage {
    Response(RpcResponse),
    Notification(Notification),
}

/// JSON-RPC 2.0 server-pushed notification (no `id`, with `method` + `params`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub jsonrpc: JsonRpcVersion,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

impl Notification {
    /// Construct an `event` notification with a typed Event payload.
    pub fn event(event: &Event) -> Self {
        Self {
            jsonrpc: JsonRpcVersion::V2,
            method: "event".to_string(),
            params: serde_json::to_value(event)
                .expect("Event always serializes (no non-serializable fields)"),
        }
    }
}

/// Standard JSON-RPC 2.0 error codes plus linpodx server-defined extensions.
///
/// # Server-defined code table (`-32000 ..= -32099`)
///
/// These codes are **stable wire contract** — never renumber an existing code.
/// New failure classes take the next free slot. Every [`crate::error::Error`]
/// variant maps to exactly one code via the daemon's `error_to_code`:
///
/// | Code                 | Value    | `Error` variant(s)                              | Meaning |
/// |----------------------|----------|-------------------------------------------------|---------|
/// | `RUNTIME_ERROR`      | `-32000` | `Runtime`, `Io`, `Json`                         | Unclassified runtime failure (catch-all). |
/// | `NOT_FOUND`          | `-32001` | `NotFound`                                       | Named resource does not exist. |
/// | `INVALID_ARGUMENT`   | `-32002` | `InvalidArgument`                                | Caller supplied a malformed / rejected argument. |
/// | `PODMAN_UNAVAILABLE` | `-32003` | `PodmanNotFound`, `PodmanVersionMismatch`        | Podman binary missing or too old. |
/// | `PERMISSION_DENIED`  | `-32004` | `PermissionDenied`                               | Authenticated but not authorized / missing host privilege. |
/// | `CONFLICT`           | `-32005` | `Conflict`                                       | Request conflicts with current state (duplicate, wrong lifecycle). |
/// | `TIMEOUT`            | `-32006` | `Timeout`                                        | Operation exceeded its deadline. |
/// | `UNSUPPORTED`        | `-32007` | `Unsupported`                                    | Not supported by this build/config (feature not enabled). |
/// | `UNAVAILABLE`        | `-32008` | `Unavailable`                                    | Subsystem/dependency temporarily unavailable (often retryable). |
/// | `INTERNAL`           | `-32009` | `Internal`, `Ipc`, `Sqlx`, `Migrate`             | Internal invariant violation / transport / persistence failure. |
pub mod error_codes {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;

    // -32000 .. -32099 — server-defined. Never renumber; append new slots.
    pub const RUNTIME_ERROR: i32 = -32000;
    pub const NOT_FOUND: i32 = -32001;
    pub const INVALID_ARGUMENT: i32 = -32002;
    pub const PODMAN_UNAVAILABLE: i32 = -32003;
    // Phase 24 — error-code taxonomy expansion (additive; the four above are
    // frozen for wire compatibility).
    pub const PERMISSION_DENIED: i32 = -32004;
    pub const CONFLICT: i32 = -32005;
    pub const TIMEOUT: i32 = -32006;
    pub const UNSUPPORTED: i32 = -32007;
    pub const UNAVAILABLE: i32 = -32008;
    pub const INTERNAL: i32 = -32009;

    /// Stable symbolic name for a server-defined (or standard JSON-RPC) code.
    ///
    /// Used by the CLI to render a human-legible label alongside the numeric
    /// code. Unknown codes fall back to `"ERROR"` so callers never panic on a
    /// code minted by a newer daemon.
    pub fn code_name(code: i32) -> &'static str {
        match code {
            PARSE_ERROR => "PARSE_ERROR",
            INVALID_REQUEST => "INVALID_REQUEST",
            METHOD_NOT_FOUND => "METHOD_NOT_FOUND",
            INVALID_PARAMS => "INVALID_PARAMS",
            INTERNAL_ERROR => "INTERNAL_ERROR",
            RUNTIME_ERROR => "RUNTIME_ERROR",
            NOT_FOUND => "NOT_FOUND",
            INVALID_ARGUMENT => "INVALID_ARGUMENT",
            PODMAN_UNAVAILABLE => "PODMAN_UNAVAILABLE",
            PERMISSION_DENIED => "PERMISSION_DENIED",
            CONFLICT => "CONFLICT",
            TIMEOUT => "TIMEOUT",
            UNSUPPORTED => "UNSUPPORTED",
            UNAVAILABLE => "UNAVAILABLE",
            INTERNAL => "INTERNAL",
            _ => "ERROR",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_serializes() {
        let req = RpcRequest::new(1u32, Method::Version);
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains("\"jsonrpc\":\"2.0\""));
        assert!(s.contains("\"method\":\"version\""));
    }

    #[test]
    fn request_with_params() {
        let req = RpcRequest::new(
            42i64,
            Method::ContainerList(ContainerListParams { all: true }),
        );
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains("\"method\":\"container_list\""));
        assert!(s.contains("\"all\":true"));
    }

    #[test]
    fn response_success_roundtrip() {
        let resp =
            RpcResponse::success(Some(RequestId::from(1u32)), serde_json::json!({"ok": true}));
        let s = serde_json::to_string(&resp).unwrap();
        let back: RpcResponse = serde_json::from_str(&s).unwrap();
        assert_eq!(back.id, Some(RequestId::Number(1)));
    }

    // ----- Phase 1B: ServerMessage / Notification / Event -----

    #[test]
    fn server_message_distinguishes_response_from_notification() {
        // Response — has `id` + `result`.
        let resp_json = r#"{"jsonrpc":"2.0","id":42,"result":{"ok":true}}"#;
        let parsed: ServerMessage = serde_json::from_str(resp_json).unwrap();
        match parsed {
            ServerMessage::Response(r) => assert_eq!(r.id, Some(RequestId::Number(42))),
            _ => panic!("expected Response"),
        }

        // Notification — has `method` + `params`, no `id`.
        let notif_json = r#"{"jsonrpc":"2.0","method":"event","params":{"topic":"container","kind":"started","resource_id":"abc","timestamp":"2026-05-09T00:00:00Z","details":{}}}"#;
        let parsed: ServerMessage = serde_json::from_str(notif_json).unwrap();
        match parsed {
            ServerMessage::Notification(n) => {
                assert_eq!(n.method, "event");
                assert_eq!(
                    n.params.get("topic").and_then(|v| v.as_str()),
                    Some("container")
                );
            }
            _ => panic!("expected Notification"),
        }
    }

    #[test]
    fn notification_event_round_trips_typed_event() {
        let event = Event {
            topic: EventTopic::Image,
            kind: EventKind::Pulled,
            resource_id: "sha256:abc".to_string(),
            timestamp: chrono::Utc::now(),
            details: serde_json::json!({"reference": "alpine:latest"}),
        };
        let notif = Notification::event(&event);
        assert_eq!(notif.method, "event");
        let s = serde_json::to_string(&notif).unwrap();
        let back: Notification = serde_json::from_str(&s).unwrap();
        let parsed_event: Event = serde_json::from_value(back.params).unwrap();
        assert_eq!(parsed_event.kind, EventKind::Pulled);
        assert_eq!(parsed_event.topic, EventTopic::Image);
    }

    #[test]
    fn event_topic_serializes_snake_case() {
        let s = serde_json::to_string(&EventTopic::Container).unwrap();
        assert_eq!(s, "\"container\"");
        let s = serde_json::to_string(&EventTopic::Network).unwrap();
        assert_eq!(s, "\"network\"");
        let parsed: EventTopic = serde_json::from_str("\"volume\"").unwrap();
        assert_eq!(parsed, EventTopic::Volume);
    }

    #[test]
    fn event_topic_parse_accepts_aliases() {
        assert_eq!(
            EventTopic::parse("container").unwrap(),
            EventTopic::Container
        );
        assert_eq!(
            EventTopic::parse("Containers").unwrap(),
            EventTopic::Container
        );
        assert_eq!(EventTopic::parse("IMAGE").unwrap(), EventTopic::Image);
        assert!(EventTopic::parse("unknown").is_err());
    }

    #[test]
    fn subscribe_method_serializes() {
        let req = RpcRequest::new(
            7u32,
            Method::Subscribe(SubscribeParams {
                topics: vec![EventTopic::Container, EventTopic::Image],
            }),
        );
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains("\"method\":\"subscribe\""));
        assert!(s.contains("\"container\""));
        assert!(s.contains("\"image\""));
    }

    #[test]
    fn response_error_roundtrip() {
        let resp = RpcResponse::error(
            Some(RequestId::from("abc")),
            RpcError {
                code: error_codes::NOT_FOUND,
                message: "no such container".into(),
                data: None,
            },
        );
        let s = serde_json::to_string(&resp).unwrap();
        let back: RpcResponse = serde_json::from_str(&s).unwrap();
        match back.payload {
            ResponsePayload::Error { error } => {
                assert_eq!(error.code, error_codes::NOT_FOUND);
                assert_eq!(error.message, "no such container");
            }
            _ => panic!("expected error payload"),
        }
    }

    #[test]
    fn taxonomy_codes_are_frozen_and_distinct() {
        // The original four must never move — clients pin these numeric values.
        assert_eq!(error_codes::RUNTIME_ERROR, -32000);
        assert_eq!(error_codes::NOT_FOUND, -32001);
        assert_eq!(error_codes::INVALID_ARGUMENT, -32002);
        assert_eq!(error_codes::PODMAN_UNAVAILABLE, -32003);
        // Every server-defined code is unique.
        let all = [
            error_codes::RUNTIME_ERROR,
            error_codes::NOT_FOUND,
            error_codes::INVALID_ARGUMENT,
            error_codes::PODMAN_UNAVAILABLE,
            error_codes::PERMISSION_DENIED,
            error_codes::CONFLICT,
            error_codes::TIMEOUT,
            error_codes::UNSUPPORTED,
            error_codes::UNAVAILABLE,
            error_codes::INTERNAL,
        ];
        let mut seen = std::collections::HashSet::new();
        for c in all {
            assert!(seen.insert(c), "duplicate error code {c}");
        }
    }

    #[test]
    fn code_name_covers_taxonomy_and_falls_back() {
        assert_eq!(error_codes::code_name(error_codes::NOT_FOUND), "NOT_FOUND");
        assert_eq!(
            error_codes::code_name(error_codes::UNSUPPORTED),
            "UNSUPPORTED"
        );
        assert_eq!(error_codes::code_name(error_codes::INTERNAL), "INTERNAL");
        // A code minted by a newer daemon must not panic.
        assert_eq!(error_codes::code_name(-32050), "ERROR");
    }

    #[test]
    fn rpc_error_with_new_code_round_trips() {
        let resp = RpcResponse::error(
            Some(RequestId::from(9u32)),
            RpcError {
                code: error_codes::UNSUPPORTED,
                message: "raft leader-elect not enabled".into(),
                data: Some(serde_json::json!({"hint": "--cluster-raft"})),
            },
        );
        let s = serde_json::to_string(&resp).unwrap();
        let back: RpcResponse = serde_json::from_str(&s).unwrap();
        match back.payload {
            ResponsePayload::Error { error } => {
                assert_eq!(error.code, error_codes::UNSUPPORTED);
                assert_eq!(error.message, "raft leader-elect not enabled");
                assert_eq!(
                    error.data.and_then(|d| d.get("hint").cloned()),
                    Some(serde_json::json!("--cluster-raft"))
                );
            }
            _ => panic!("expected error payload"),
        }
    }
}
