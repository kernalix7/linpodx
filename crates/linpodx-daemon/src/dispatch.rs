use crate::approval::ApprovalRegistry;
use crate::event_bus::EventBus;
use crate::pin_store::{new_tofu_handle, PinnedClientStore, TofuHandle};
use crate::remote::{self, constant_eq, RemoteHandle};
use linpodx_cluster::store::PeerStore;
use linpodx_common::approval::ApprovalOutcome;
use linpodx_common::audit_sink::{AuditSink, AuditSinkKind};
use linpodx_common::error::{Error, Result};
use linpodx_common::ipc::{
    error_codes, responses, Event, EventKind, EventTopic, Method, RpcError, RpcRequest, RpcResponse,
};
use linpodx_common::types::ContainerId;
use linpodx_common::version::{IPC_VERSION, LINPODX_VERSION};
use linpodx_distro::dispatch::{handle as distro_handle, DistroAction};
use linpodx_mcp::BridgeRegistry;
use linpodx_plugin::PluginRegistry;
use linpodx_runtime::{
    image, network, snapshot as runtime_snapshot, volume, EgressEnforcer, ExecOptions, LogOptions,
    MetricsCollector, OverlayfsBackend, Podman, PtyExecOptions, PtyHandle,
};
use linpodx_sandbox::audit::AuditFilters;
use linpodx_sandbox::{
    record_cluster_view_served, ClusterStore, PluginStore, SandboxAuditSink, SandboxManager,
    SessionManager, SnapshotManager,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tracing::{instrument, warn};

mod cluster;
mod containers;
mod daemon_mgmt;
mod distro;
mod doctor;
mod images;
mod mcp;
mod metrics;
mod networks;
mod pin_clients;
mod plugins;
mod remote_listen;
mod sandbox;
mod snapshots;
mod system;
mod volumes;

/// Holds the runtime adapter, event bus, sandbox subsystem, and approval registry.
#[derive(Clone)]
pub struct Dispatcher {
    pub podman: Podman,
    /// Plain string path to the podman binary (for MCP bridge subprocess spawning).
    pub podman_bin: String,
    pub podman_version: String,
    pub event_bus: Arc<EventBus>,
    pub sandbox: Arc<SandboxManager>,
    pub approvals: Arc<ApprovalRegistry>,
    pub snapshot: Arc<SnapshotManager>,
    pub session: Arc<SessionManager>,
    pub bridges: Arc<BridgeRegistry>,
    pub metrics: Arc<MetricsCollector>,
    /// Audit sink shared with the rest of the daemon — used by the remote listener
    /// to record auth handshakes and session opens.
    pub audit: Arc<dyn AuditSink>,
    /// Currently-running remote WebSocket listener, if any. `RemoteListenStart` /
    /// `Stop` mutate this; `RemoteListenStatus` reads it.
    pub remote: Arc<Mutex<Option<RemoteHandle>>>,
    /// Phase 12 — interactive PTY proxy. `ContainerExecPty` allocates one entry,
    /// the remote `/pty/<bridge_id>` WebSocket handler removes it on close. Shared
    /// with [`crate::remote::RemoteState`] by `Arc::clone` so both halves of the
    /// daemon (JSON-RPC dispatch + WebSocket listener) see the same map.
    pub pty_handles: Arc<Mutex<HashMap<String, PtyHandle>>>,
    /// Phase 13 — long-lived plugin registry shared with the sandbox / audit sink. The
    /// `ContainerCreate` arm uses it to run the `runtime_injector` chain after
    /// `apply_to_create` has produced its transformed `CreateOptions`. `None` until
    /// `set_plugin_registry` is called; `evaluate_runtime_injector` is a no-op then.
    pub plugin_registry: Option<Arc<RwLock<PluginRegistry>>>,
    /// Phase 14 Stream C — Raft leader-elect handle. Wired from main.rs after
    /// the daemon constructs a [`linpodx_cluster::RaftNode`]. The two cluster
    /// IPC arms (`ClusterLeaderGet` / `ClusterRoleGet`) read this; absence is
    /// surfaced as a friendly error rather than a panic so daemons built
    /// without leader-elect still respond.
    pub raft: Option<Arc<linpodx_cluster::RaftNode>>,
    /// Phase 15 Stream C — pinned WebSocket client cert store. The
    /// `DaemonPinClient*` IPC arms read/write through this; the WebSocket
    /// upgrade path under [`crate::remote`] reads it via `RemoteState` when
    /// `--pin-clients` was set at startup.
    pub pin_store: PinnedClientStore,
    /// Phase 16 Stream C — Trust-On-First-Use mode for the pin store. The
    /// `DaemonPinClientTofuEnable` arm flips this; the WebSocket handler
    /// reads + mutates the counter when an unknown cert is auto-enrolled.
    /// Shared by `Arc<Mutex<TofuMode>>` between dispatcher and remote state.
    pub tofu: TofuHandle,
    /// Phase 18 Stream D — wall-clock-ish process start instant. Used by
    /// `Method::DaemonMgmtStatus` to compute `uptime_secs`. `Instant` is
    /// monotonic so this stays sensible across NTP adjustments.
    pub start_time: std::time::Instant,
    /// Phase 24 — cached loopback plaintext Web UI listener for the desktop
    /// shell. Lazily populated by `Method::WebUiEnsure` (see
    /// [`crate::web_ui_local`]); `None` until the shell first asks for it.
    /// Independent of the `remote` field / `--remote-listen` listener.
    pub web_ui_local: Arc<Mutex<Option<crate::web_ui_local::WebUiLocalHandle>>>,
}

/// Builder for [`Dispatcher`] (CLAUDE.md §4 — builder pattern for complex
/// constructors). The twelve core subsystems are all required; the two
/// cluster-related handles (`plugin_registry`, `raft`) are optional and
/// default to absent. Set the required fields first, optionally add
/// `plugin_registry` / `raft`, then call [`DispatcherBuilder::build`].
#[derive(Default)]
pub struct DispatcherBuilder {
    podman: Option<Podman>,
    podman_bin: Option<String>,
    podman_version: Option<String>,
    event_bus: Option<Arc<EventBus>>,
    sandbox: Option<Arc<SandboxManager>>,
    approvals: Option<Arc<ApprovalRegistry>>,
    snapshot: Option<Arc<SnapshotManager>>,
    session: Option<Arc<SessionManager>>,
    bridges: Option<Arc<BridgeRegistry>>,
    metrics: Option<Arc<MetricsCollector>>,
    audit: Option<Arc<dyn AuditSink>>,
    pin_store: Option<PinnedClientStore>,
    plugin_registry: Option<Arc<RwLock<PluginRegistry>>>,
    raft: Option<Arc<linpodx_cluster::RaftNode>>,
}

impl DispatcherBuilder {
    /// Start a new builder with every field unset.
    pub fn new() -> Self {
        Self::default()
    }

    // ----- required subsystems -----
    pub fn podman(mut self, v: Podman) -> Self {
        self.podman = Some(v);
        self
    }
    pub fn podman_bin(mut self, v: String) -> Self {
        self.podman_bin = Some(v);
        self
    }
    pub fn podman_version(mut self, v: String) -> Self {
        self.podman_version = Some(v);
        self
    }
    pub fn event_bus(mut self, v: Arc<EventBus>) -> Self {
        self.event_bus = Some(v);
        self
    }
    pub fn sandbox(mut self, v: Arc<SandboxManager>) -> Self {
        self.sandbox = Some(v);
        self
    }
    pub fn approvals(mut self, v: Arc<ApprovalRegistry>) -> Self {
        self.approvals = Some(v);
        self
    }
    pub fn snapshot(mut self, v: Arc<SnapshotManager>) -> Self {
        self.snapshot = Some(v);
        self
    }
    pub fn session(mut self, v: Arc<SessionManager>) -> Self {
        self.session = Some(v);
        self
    }
    pub fn bridges(mut self, v: Arc<BridgeRegistry>) -> Self {
        self.bridges = Some(v);
        self
    }
    pub fn metrics(mut self, v: Arc<MetricsCollector>) -> Self {
        self.metrics = Some(v);
        self
    }
    pub fn audit(mut self, v: Arc<dyn AuditSink>) -> Self {
        self.audit = Some(v);
        self
    }
    pub fn pin_store(mut self, v: PinnedClientStore) -> Self {
        self.pin_store = Some(v);
        self
    }

    // ----- optional handles -----
    /// Phase 13 — wire the long-lived `PluginRegistry` so the `ContainerCreate`
    /// arm can run the `runtime_injector` chain.
    pub fn plugin_registry(mut self, v: Arc<RwLock<PluginRegistry>>) -> Self {
        self.plugin_registry = Some(v);
        self
    }
    /// Phase 14 Stream C — wire the Raft leader-elect handle.
    pub fn raft(mut self, v: Arc<linpodx_cluster::RaftNode>) -> Self {
        self.raft = Some(v);
        self
    }

    /// Consume the builder and produce a [`Dispatcher`]. Returns
    /// [`Error::InvalidArgument`] when a required subsystem was not set.
    pub fn build(self) -> Result<Dispatcher> {
        fn required<T>(v: Option<T>, name: &str) -> Result<T> {
            v.ok_or_else(|| {
                Error::InvalidArgument(format!("DispatcherBuilder: `{name}` is required"))
            })
        }
        Ok(Dispatcher {
            podman: required(self.podman, "podman")?,
            podman_bin: required(self.podman_bin, "podman_bin")?,
            podman_version: required(self.podman_version, "podman_version")?,
            event_bus: required(self.event_bus, "event_bus")?,
            sandbox: required(self.sandbox, "sandbox")?,
            approvals: required(self.approvals, "approvals")?,
            snapshot: required(self.snapshot, "snapshot")?,
            session: required(self.session, "session")?,
            bridges: required(self.bridges, "bridges")?,
            metrics: required(self.metrics, "metrics")?,
            audit: required(self.audit, "audit")?,
            pin_store: required(self.pin_store, "pin_store")?,
            remote: Arc::new(Mutex::new(None)),
            pty_handles: Arc::new(Mutex::new(HashMap::new())),
            plugin_registry: self.plugin_registry,
            raft: self.raft,
            tofu: new_tofu_handle(),
            start_time: std::time::Instant::now(),
            web_ui_local: Arc::new(Mutex::new(None)),
        })
    }
}

impl Dispatcher {
    /// Install an already-spawned remote listener (used by main.rs when
    /// `--remote-listen` was passed at startup).
    pub async fn set_remote(&self, handle: RemoteHandle) {
        let mut slot = self.remote.lock().await;
        if let Some(prev) = slot.take() {
            prev.shutdown().await;
        }
        *slot = Some(handle);
    }

    /// Bridge into `linpodx_distro::dispatch::handle`. Reuses `SnapshotManager`'s shared
    /// `Database` handle and the broadcast event bus; constructs a fresh
    /// `SandboxAuditSink` per call (cheap — wraps `Arc<Database>`).
    async fn run_distro(&self, action: DistroAction) -> Result<serde_json::Value> {
        let db = Arc::clone(self.snapshot.database());
        let publisher: Arc<dyn linpodx_common::events::EventPublisher> = self.event_bus.clone();
        let audit: Arc<dyn linpodx_common::audit_sink::AuditSink> =
            Arc::new(SandboxAuditSink::new(Arc::clone(&db)));
        distro_handle(action, &self.podman, &self.podman_bin, db, publisher, audit)
            .await
            .map_err(Into::into)
    }

    fn publish(&self, topic: EventTopic, kind: EventKind, resource_id: impl Into<String>) {
        self.event_bus.publish(Event {
            topic,
            kind,
            resource_id: resource_id.into(),
            timestamp: chrono::Utc::now(),
            details: serde_json::Value::Null,
        });
    }

    fn publish_with_details(
        &self,
        topic: EventTopic,
        kind: EventKind,
        resource_id: impl Into<String>,
        details: serde_json::Value,
    ) {
        self.event_bus.publish(Event {
            topic,
            kind,
            resource_id: resource_id.into(),
            timestamp: chrono::Utc::now(),
            details,
        });
    }

    #[instrument(skip(self, req))]
    pub async fn dispatch(&self, req: RpcRequest) -> RpcResponse {
        let id = req.id.clone();
        let result = self.handle_method(req.method).await;
        match result {
            Ok(value) => RpcResponse::success(id, value),
            Err(err) => {
                let (code, message) = error_to_code(&err);
                warn!(?err, "request failed");
                RpcResponse::error(
                    id,
                    RpcError {
                        code,
                        message,
                        data: None,
                    },
                )
            }
        }
    }

    async fn handle_method(&self, method: Method) -> Result<serde_json::Value> {
        match method {
            Method::Version => self.version().await,
            Method::ContainerList(p) => self.container_list(p).await,
            Method::ContainerCreate(opts) => self.container_create(opts).await,
            Method::ContainerStart(p) => self.container_start(p).await,
            Method::ContainerStop(p) => self.container_stop(p).await,
            Method::ContainerRemove(p) => self.container_remove(p).await,
            Method::ContainerInspect(p) => self.container_inspect(p).await,
            Method::ContainerLogs(p) => self.container_logs(p).await,
            Method::ImageList(p) => self.image_list(p).await,
            Method::ImagePull(p) => self.image_pull(p).await,
            Method::ImageRemove(p) => self.image_remove(p).await,
            Method::ImageInspect(p) => self.image_inspect(p).await,
            Method::ImageTag(p) => self.image_tag(p).await,
            Method::VolumeList => self.volume_list().await,
            Method::VolumeCreate(p) => self.volume_create(p).await,
            Method::VolumeRemove(p) => self.volume_remove(p).await,
            Method::VolumeInspect(p) => self.volume_inspect(p).await,
            Method::VolumePrune => self.volume_prune().await,
            Method::NetworkList => self.network_list().await,
            Method::NetworkCreate(p) => self.network_create(p).await,
            Method::NetworkRemove(p) => self.network_remove(p).await,
            Method::NetworkInspect(p) => self.network_inspect(p).await,
            Method::NetworkPrune => self.network_prune().await,
            Method::Subscribe(_) => self.subscribe_unsupported().await,
            Method::SandboxProfileList => self.sandbox_profile_list().await,
            Method::SandboxProfileGet(p) => self.sandbox_profile_get(p).await,
            Method::SandboxProfileReload => self.sandbox_profile_reload().await,
            Method::AuditLogQuery(p) => self.audit_log_query(p).await,
            Method::AuditLogVerify(p) => self.audit_log_verify(p).await,
            Method::ApprovalDecision(p) => self.approval_decision(p).await,
            Method::SnapshotCreate(p) => self.snapshot_create(p).await,
            Method::SnapshotList(p) => self.snapshot_list(p).await,
            Method::SnapshotInspect(p) => self.snapshot_inspect(p).await,
            Method::SnapshotRollback(p) => self.snapshot_rollback(p).await,
            Method::SnapshotRemove(p) => self.snapshot_remove(p).await,
            Method::SnapshotPrune(p) => self.snapshot_prune(p).await,
            Method::SessionList(p) => self.session_list(p).await,
            Method::SessionInspect(p) => self.session_inspect(p).await,
            Method::SessionTimeline(p) => self.session_timeline(p).await,
            Method::McpBridgeStart(p) => self.mcp_bridge_start(p).await,
            Method::McpBridgeStop(p) => self.mcp_bridge_stop(p).await,
            Method::McpBridgeStatus(p) => self.mcp_bridge_status(p).await,
            Method::SnapshotJobCreate(p) => self.snapshot_job_create(p).await,
            Method::SnapshotJobStatus(p) => self.snapshot_job_status(p).await,
            Method::McpPolicyList => self.mcp_policy_list().await,
            Method::McpPolicySet(p) => self.mcp_policy_set(p).await,
            Method::ApprovalsSubscribe => self.approvals_subscribe_unsupported().await,
            Method::DistroTemplateList => self.distro_template_list().await,
            Method::DistroTemplateInspect(p) => self.distro_template_inspect(p).await,
            Method::DistroCreate(p) => self.distro_create(p).await,
            Method::DistroBuild(p) => self.distro_build(p).await,
            Method::DistroEnter(p) => self.distro_enter(p).await,
            Method::DistroRemove(p) => self.distro_remove(p).await,
            Method::NetworkEgressApply(p) => self.network_egress_apply(p).await,
            Method::McpBridgeCapabilities(p) => self.mcp_bridge_capabilities(p).await,
            Method::McpBridgeSubscriptions(p) => self.mcp_bridge_subscriptions(p).await,
            Method::SnapshotDiff(p) => self.snapshot_diff(p).await,
            Method::SnapshotBranch(p) => self.snapshot_branch(p).await,
            Method::PluginList => self.plugin_list().await,
            Method::PluginInstall(p) => self.plugin_install(p).await,
            Method::PluginEnable(p) => self.plugin_enable(p).await,
            Method::PluginDisable(p) => self.plugin_disable(p).await,
            Method::PluginRemove(p) => self.plugin_remove(p).await,
            Method::MetricsLatest(p) => self.metrics_latest(p).await,
            Method::MetricsHistory(p) => self.metrics_history(p).await,
            Method::ClusterJoin(p) => self.cluster_join(p).await,
            Method::ClusterLeave(p) => self.cluster_leave(p).await,
            Method::ClusterPeers => self.cluster_peers().await,
            Method::ClusterContainerView => self.cluster_container_view().await,
            Method::ClusterLeaderGet => self.cluster_leader_get().await,
            Method::ClusterRoleGet => self.cluster_role_get().await,
            Method::ClusterRaftStatus => self.cluster_raft_status().await,
            Method::ClusterRaftPromote(p) => self.cluster_raft_promote(p).await,
            Method::ClusterStateGet => self.cluster_state_get().await,
            Method::ClusterStateProposeContainer(p) => {
                self.cluster_state_propose_container(p).await
            }
            Method::SnapshotEncryptionStatus(p) => self.snapshot_encryption_status(p).await,
            Method::SnapshotKeyRotate(p) => self.snapshot_key_rotate(p).await,
            Method::SnapshotReEncryptAll(p) => self.snapshot_re_encrypt_all(p).await,
            Method::PluginKeyList => self.plugin_key_list().await,
            Method::PluginKeyRevoke(p) => self.plugin_key_revoke(p).await,
            Method::PluginKeyRevokePropagate(p) => self.plugin_key_revoke_propagate(p).await,
            Method::SandboxSnapshotAutoTriggerStatus => {
                self.sandbox_snapshot_auto_trigger_status().await
            }
            Method::SandboxSnapshotAutoTriggerEnable(p) => {
                self.sandbox_snapshot_auto_trigger_enable(p).await
            }
            Method::DaemonPinClientTofuEnable(p) => self.daemon_pin_client_tofu_enable(p).await,
            Method::DaemonPinClientTofuExpiryStatus => {
                self.daemon_pin_client_tofu_expiry_status().await
            }
            Method::DaemonPinClientTofuExpirySet(p) => {
                self.daemon_pin_client_tofu_expiry_set(p).await
            }
            Method::K8sPodList(p) => self.k8s_pod_list(p).await,
            Method::K8sServiceList(p) => self.k8s_service_list(p).await,
            Method::K8sPodCreate(p) => self.k8s_pod_create(p).await,
            Method::K8sPodDelete(p) => self.k8s_pod_delete(p).await,
            Method::K8sNamespaceCreate(p) => self.k8s_namespace_create(p).await,
            Method::K8sDeploymentScale(p) => self.k8s_deployment_scale(p).await,
            Method::ContainerExec(p) => self.container_exec(p).await,
            Method::ContainerLogsStream(p) => self.container_logs_stream(p).await,
            Method::ImagePullJob(p) => self.image_pull_job(p).await,
            Method::ContainerExecPty(p) => self.container_exec_pty(p).await,
            Method::ImagePush(p) => self.image_push(p).await,
            Method::ImageManifestCreate(p) => self.image_manifest_create(p).await,
            Method::ImageManifestPush(p) => self.image_manifest_push(p).await,
            Method::SnapshotDiffV2(p) => self.snapshot_diff_v2(p).await,
            Method::SnapshotBackendList => self.snapshot_backend_list().await,
            Method::RemoteAuth(p) => self.remote_auth(p).await,
            Method::RemoteListenStart(p) => self.remote_listen_start(p).await,
            Method::RemoteListenStop => self.remote_listen_stop().await,
            Method::RemoteListenStatus => self.remote_listen_status().await,
            Method::DaemonPinClientAdd(p) => self.daemon_pin_client_add(p).await,
            Method::DaemonPinClientList => self.daemon_pin_client_list().await,
            Method::DaemonPinClientRemove(p) => self.daemon_pin_client_remove(p).await,
            Method::DoctorRun(p) => self.doctor_run(p).await,
            Method::DaemonMgmtStart(p) => self.daemon_mgmt_start(p).await,
            Method::DaemonMgmtStop => self.daemon_mgmt_stop().await,
            Method::DaemonMgmtStatus => self.daemon_mgmt_status().await,
            Method::WebUiEnsure(p) => self.web_ui_ensure(p).await,
            Method::SystemDf => self.system_df().await,
        }
    }

    /// Build a fresh [`ClusterStore`] backed by the shared sandbox DB and audit sink.
    /// Cheap — both inner handles are `Arc` clones — so we re-build per request rather
    /// than hold one in `Dispatcher` state.
    fn cluster_store(&self) -> Arc<dyn PeerStore> {
        let db = Arc::clone(self.snapshot.database());
        Arc::new(ClusterStore::new(db, Arc::clone(&self.audit)))
    }

    /// Phase 18 Stream C — walk the first-run readiness checklist and emit a
    /// machine-friendly summary. Each check is implemented as a small free
    /// helper below; the dispatcher just composes them and tallies outcomes.
    ///
    /// Checks (stable ids — the CLI text renderer and external scripts grep on
    /// them, so the names must not be renamed in a future patch):
    /// 1. `podman-installed` — `podman` binary is on `PATH`
    /// 2. `podman-version` — version is >= 4.6.0
    /// 3. `rootless-setup` — `podman info` reports rootless mode
    /// 4. `cgroup-v2-available` — `/sys/fs/cgroup/cgroup.controllers` exists
    /// 5. `socket-permissions` — daemon Unix socket is a socket + 0600-ish
    /// 6. `sandbox-profile-dir` — `${XDG_CONFIG_HOME}/linpodx/profiles` exists
    /// 7. `mcp-bridge-dir` — `${XDG_CONFIG_HOME}/linpodx/mcp` exists
    /// 8. `display-session` — Wayland or X11 is detected (warn-only)
    /// 9. `selinux-mode` — `/sys/fs/selinux/enforce` is readable (or absent)
    /// 10. `netfilter-helper` — the SUID helper binary has `cap_net_admin`
    /// 11. `system-libs` — common GUI passthrough libs reachable via `ldconfig`
    pub async fn run_doctor(&self) -> responses::DoctorRunResponse {
        // Each check is async-friendly (`tokio::process::Command` where needed)
        // but most are cheap stat / env reads so call sites stay synchronous
        // and run sequentially — the whole pass should complete in well under
        // one second on a normal machine.
        let podman_bin = self.podman_bin.clone();
        let podman_version_known = self.podman_version.clone();

        let mut checks: Vec<responses::DoctorCheck> = Vec::with_capacity(11);

        // 1+2. Podman binary + version. Split into two stable ids so external
        //      tooling can grep `podman-version` separately from `installed`.
        let (installed, version) =
            doctor::check_podman_binary_and_version(&podman_bin, &podman_version_known).await;
        checks.push(installed);
        checks.push(version);

        // 3. Rootless mode — `podman info --format '{{.Host.Security.Rootless}}'`.
        checks.push(doctor::check_rootless_setup(&podman_bin).await);

        // 4. cgroup v2 — required for podman's rootless lifecycle on modern kernels.
        checks.push(doctor::check_cgroup_v2());

        // 5. Daemon socket — exists, is a Unix socket, and permissions look sane.
        checks.push(doctor::check_socket_permissions());

        // 6. Sandbox profile dir — `${XDG_CONFIG_HOME}/linpodx/profiles`.
        checks.push(doctor::check_sandbox_profile_dir());

        // 7. MCP bridge dir — `${XDG_CONFIG_HOME}/linpodx/mcp`.
        checks.push(doctor::check_mcp_bridge_dir());

        // 8–11. GUI passthrough + L4 egress firewall pre-flight (warn-only).
        checks.push(doctor::check_display_session());
        checks.push(doctor::check_selinux());
        checks.push(doctor::check_netfilter_helper().await);
        checks.push(doctor::check_system_libs().await);

        let mut pass_count = 0u32;
        let mut warn_count = 0u32;
        let mut fail_count = 0u32;
        for c in &checks {
            match c.outcome {
                responses::DoctorOutcome::Pass => pass_count += 1,
                responses::DoctorOutcome::Warn => warn_count += 1,
                responses::DoctorOutcome::Fail => fail_count += 1,
            }
        }

        responses::DoctorRunResponse {
            checks,
            pass_count,
            warn_count,
            fail_count,
        }
    }
}

/// Phase 11: opaque short-id for an `image_pull_job`. Combines the current wall-clock
/// nanoseconds with a `DefaultHasher` digest of the image reference, then base16-encodes
/// the high bits — a stable, collision-resistant-enough handle for in-flight pulls.
fn make_job_id(reference: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    reference.hash(&mut h);
    let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;
    now.hash(&mut h);
    format!("pull-{:016x}", h.finish())
}

/// Translate a K8s adapter init failure into a user-friendly `Error::Runtime`.
/// `try_default` failure usually means "no kubeconfig and not in a pod" — the
/// hint string makes that legible at the CLI without dumping the raw kube
/// error chain twice.
fn k8s_unavailable_err(e: linpodx_cluster::ClusterError) -> Error {
    Error::Unavailable(format!(
        "K8s adapter unavailable: {e}. Hint: set KUBECONFIG, populate \
         ~/.kube/config, or run inside a cluster with a service account."
    ))
}

/// Append a `k8s_query_served` audit row. The local hash-chained sandbox
/// audit is best-effort here — we log on failure but never propagate, mirroring
/// the cluster-view path.
async fn record_k8s_query_served(
    audit: &dyn AuditSink,
    op: &str,
    namespace: Option<&str>,
    item_count: usize,
) {
    let payload = serde_json::json!({
        "op": op,
        "namespace": namespace.unwrap_or("<all>"),
        "item_count": item_count,
    });
    audit
        .record(AuditSinkKind::K8sQueryServed, None, None, payload)
        .await;
}

fn cluster_to_err(e: linpodx_cluster::ClusterError) -> Error {
    use linpodx_cluster::ClusterError::*;
    match e {
        InvalidAddr(m) => Error::InvalidArgument(format!("cluster: {m}")),
        PeerNotFound(n) => Error::NotFound(format!("cluster peer '{n}'")),
        PeerDuplicate(n) => Error::Conflict(format!("cluster peer '{n}' already joined")),
        NotImplemented(m) => Error::Unsupported(format!("cluster: {m}")),
        Storage(m) | Http(m) => Error::Runtime {
            message: format!("cluster: {m}"),
        },
        Io(io) => Error::Io(io),
    }
}

/// Resolve the **existing** snapshot encryption config from the daemon's
/// startup environment (`LINPODX_SNAPSHOT_*` vars). Phase 17 rotation uses
/// this as the "old key" side of the rotation. Returns a Runtime error when
/// no encryption is configured — there is nothing to rotate.
fn resolve_old_snapshot_cfg() -> Result<linpodx_runtime::EncryptionConfig> {
    linpodx_runtime::EncryptionConfig::from_env()
        .map_err(|e| Error::Runtime {
            message: format!("snapshot.key_rotate: resolve current key: {e}"),
        })?
        .ok_or_else(|| {
            Error::Unsupported(
                "snapshot.key_rotate: daemon was not started with LINPODX_SNAPSHOT_KEY / \
                 LINPODX_SNAPSHOT_ENCRYPT_PASSPHRASE — nothing to rotate"
                    .into(),
            )
        })
}

/// Build the **new** `EncryptionConfig` from an IPC `SnapshotKeySource`.
/// Mirrors the runtime-side `NewKeySource::into_config` but stays in the
/// daemon layer so the IPC schema (in `linpodx-common`) never has to depend
/// on the runtime crate.
fn resolve_new_snapshot_cfg(
    new_key: linpodx_common::ipc::SnapshotKeySource,
) -> Result<linpodx_runtime::EncryptionConfig> {
    use linpodx_common::ipc::SnapshotKeySource;
    let mapped = match new_key {
        SnapshotKeySource::Passphrase { passphrase } => linpodx_runtime::NewKeySource::Passphrase {
            passphrase,
            // Honour the daemon's KDF env var when set so operators can opt
            // back into the legacy KDF during a rotation if they need a
            // downgrade window.
            kdf: match std::env::var(linpodx_runtime::ENV_KDF) {
                Ok(v) => linpodx_runtime::Kdf::from_env_var(&v).map_err(|e| Error::Runtime {
                    message: format!(
                        "snapshot.key_rotate: parse {} env var: {e}",
                        linpodx_runtime::ENV_KDF
                    ),
                })?,
                Err(_) => linpodx_runtime::Kdf::default(),
            },
        },
        SnapshotKeySource::Explicit { key_b64 } => {
            linpodx_runtime::NewKeySource::Explicit { key_b64 }
        }
        SnapshotKeySource::Env { var } => linpodx_runtime::NewKeySource::Env { var },
    };
    mapped.into_config()
}

/// Map a library [`Error`] onto its stable IPC code. The mapping is 1:1 per
/// variant and documented in [`linpodx_common::ipc::error_codes`]. Keep this in
/// sync with that table — the `error_to_code_is_total` test asserts every
/// variant is covered.
fn error_to_code(err: &Error) -> (i32, String) {
    let code = match err {
        Error::PodmanNotFound(_) | Error::PodmanVersionMismatch { .. } => {
            error_codes::PODMAN_UNAVAILABLE
        }
        Error::NotFound(_) => error_codes::NOT_FOUND,
        Error::InvalidArgument(_) => error_codes::INVALID_ARGUMENT,
        Error::PermissionDenied(_) => error_codes::PERMISSION_DENIED,
        Error::Conflict(_) => error_codes::CONFLICT,
        Error::Timeout(_) => error_codes::TIMEOUT,
        Error::Unsupported(_) => error_codes::UNSUPPORTED,
        Error::Unavailable(_) => error_codes::UNAVAILABLE,
        // Internal invariant, transport, and persistence failures are all
        // "not the caller's fault" — collapse them onto INTERNAL.
        Error::Internal(_) | Error::Ipc(_) | Error::Sqlx(_) | Error::Migrate(_) => {
            error_codes::INTERNAL
        }
        // Genuinely unclassified: the stringly-typed catch-all plus raw I/O and
        // JSON failures that could originate on either side of the wire.
        Error::Runtime { .. } | Error::Io(_) | Error::Json(_) => error_codes::RUNTIME_ERROR,
    };
    (code, err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exhaustive variant -> code table. Adding a variant to `Error` without
    /// adding a row here fails to compile (the `match` below is non-exhaustive),
    /// which is the point: the taxonomy stays total.
    #[test]
    fn error_to_code_is_total() {
        fn expected(err: &Error) -> i32 {
            // A separate exhaustive match — a compile error here means a new
            // variant landed without a documented code.
            match err {
                Error::Runtime { .. } => error_codes::RUNTIME_ERROR,
                Error::PodmanNotFound(_) => error_codes::PODMAN_UNAVAILABLE,
                Error::PodmanVersionMismatch { .. } => error_codes::PODMAN_UNAVAILABLE,
                Error::Ipc(_) => error_codes::INTERNAL,
                Error::NotFound(_) => error_codes::NOT_FOUND,
                Error::InvalidArgument(_) => error_codes::INVALID_ARGUMENT,
                Error::PermissionDenied(_) => error_codes::PERMISSION_DENIED,
                Error::Conflict(_) => error_codes::CONFLICT,
                Error::Timeout(_) => error_codes::TIMEOUT,
                Error::Unsupported(_) => error_codes::UNSUPPORTED,
                Error::Unavailable(_) => error_codes::UNAVAILABLE,
                Error::Internal(_) => error_codes::INTERNAL,
                Error::Io(_) => error_codes::RUNTIME_ERROR,
                Error::Json(_) => error_codes::RUNTIME_ERROR,
                Error::Sqlx(_) => error_codes::INTERNAL,
                Error::Migrate(_) => error_codes::INTERNAL,
            }
        }

        let json_err = serde_json::from_str::<serde_json::Value>("{").unwrap_err();
        let samples = vec![
            Error::Runtime {
                message: "boom".into(),
            },
            Error::PodmanNotFound("podman".into()),
            Error::PodmanVersionMismatch {
                found: "4.0".into(),
                required: "4.6".into(),
            },
            Error::Ipc("frame".into()),
            Error::NotFound("ctr".into()),
            Error::InvalidArgument("bad".into()),
            Error::PermissionDenied("nope".into()),
            Error::Conflict("exists".into()),
            Error::Timeout("slow".into()),
            Error::Unsupported("not enabled".into()),
            Error::Unavailable("offline".into()),
            Error::Internal("poisoned".into()),
            Error::Io(std::io::Error::other("io")),
            Error::Json(json_err),
        ];
        for err in &samples {
            let (code, message) = error_to_code(err);
            assert_eq!(code, expected(err), "wrong code for {err:?}");
            assert_eq!(message, err.to_string());
        }

        // The classified variants must not collapse back onto RUNTIME_ERROR.
        assert_ne!(
            error_to_code(&Error::Unsupported("x".into())).0,
            error_codes::RUNTIME_ERROR
        );
        assert_eq!(
            error_to_code(&Error::Internal("x".into())).0,
            error_codes::INTERNAL
        );
    }

    #[test]
    fn make_job_id_is_short_and_prefixed() {
        let id = make_job_id("docker.io/library/alpine:latest");
        assert!(id.starts_with("pull-"), "got {id}");
        // "pull-" + 16 hex chars = 21 total.
        assert_eq!(id.len(), 5 + 16, "got {id}");
    }

    #[test]
    fn make_job_id_distinct_for_distinct_refs() {
        let a = make_job_id("alpine:1");
        let b = make_job_id("alpine:2");
        assert_ne!(a, b);
    }

    #[test]
    fn make_job_id_distinct_across_calls_for_same_ref() {
        // Even when the reference is identical, two consecutive calls should differ
        // because the wall-clock nanosecond counter advances.
        let a = make_job_id("alpine:1");
        std::thread::sleep(std::time::Duration::from_nanos(1));
        let b = make_job_id("alpine:1");
        // With nanosecond resolution this *can* still collide on a system whose
        // clock doesn't advance between calls; loosen to "at most one duplicate
        // in five attempts" to keep the assertion robust.
        let mut differs = a != b;
        for _ in 0..5 {
            if differs {
                break;
            }
            std::thread::sleep(std::time::Duration::from_micros(1));
            differs = make_job_id("alpine:1") != a;
        }
        assert!(differs, "job_ids never advanced across calls");
    }

    // ----- Phase 17 Stream C — TOFU expiry dispatch arm logic -----
    //
    // The full `Dispatcher` is too heavy to construct in a unit test (it
    // needs Podman + every subsystem). Instead, exercise the per-arm logic
    // through the shared `TofuHandle` directly — the dispatch.rs arms only
    // touch the handle + audit sink, so the behaviour is identical.

    use crate::pin_store::{new_tofu_handle, TofuMode};

    fn apply_enable_arm(handle: &crate::pin_store::TofuHandle, enable: bool, max: Option<u32>) {
        let mut mode = handle.lock().expect("lock");
        let was_enabled = mode.enabled;
        mode.enabled = enable;
        mode.max_enrollments = max;
        if enable {
            if !was_enabled {
                mode.enabled_at = Some(chrono::Utc::now().timestamp());
                mode.current_count = 0;
            }
        } else {
            mode.current_count = 0;
            mode.enabled_at = None;
            mode.max_age_secs = None;
        }
    }

    fn apply_expiry_set_arm(
        handle: &crate::pin_store::TofuHandle,
        max_age_secs: Option<u64>,
    ) -> Result<()> {
        let mut mode = handle
            .lock()
            .map_err(|_| Error::Internal("tofu mode lock poisoned".into()))?;
        if !mode.enabled {
            return Err(Error::InvalidArgument(
                "tofu mode is currently disabled".into(),
            ));
        }
        if mode.enabled_at.is_none() {
            mode.enabled_at = Some(chrono::Utc::now().timestamp());
        }
        mode.max_age_secs = max_age_secs;
        Ok(())
    }

    #[test]
    fn enable_arm_captures_enabled_at_on_off_to_on_edge() {
        let h = new_tofu_handle();
        // Initially: disabled, no anchor.
        {
            let g = h.lock().unwrap();
            assert!(!g.enabled);
            assert!(g.enabled_at.is_none());
        }
        apply_enable_arm(&h, true, None);
        let g = h.lock().unwrap();
        assert!(g.enabled);
        assert!(g.enabled_at.is_some());
    }

    #[test]
    fn enable_arm_does_not_reset_anchor_on_re_enable() {
        let h = new_tofu_handle();
        apply_enable_arm(&h, true, None);
        let initial_anchor = h.lock().unwrap().enabled_at;
        assert!(initial_anchor.is_some());

        // Sleep to ensure clock would have advanced if we tried to refresh.
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Re-issuing --enable while already enabled must NOT bump the anchor
        // (so an operator tweaking max-enrollments doesn't extend a window).
        apply_enable_arm(&h, true, Some(5));
        let after = h.lock().unwrap().enabled_at;
        assert_eq!(after, initial_anchor);
    }

    #[test]
    fn enable_arm_disable_clears_window_and_anchor() {
        let h = new_tofu_handle();
        apply_enable_arm(&h, true, Some(10));
        {
            let mut g = h.lock().unwrap();
            g.max_age_secs = Some(3600);
        }
        apply_enable_arm(&h, false, None);
        let g = h.lock().unwrap();
        assert!(!g.enabled);
        assert!(g.enabled_at.is_none());
        assert!(g.max_age_secs.is_none());
        assert_eq!(g.current_count, 0);
    }

    #[test]
    fn expiry_set_arm_refuses_when_disabled() {
        let h = new_tofu_handle();
        let err = apply_expiry_set_arm(&h, Some(60)).unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));
    }

    #[test]
    fn expiry_set_arm_writes_max_age_when_enabled() {
        let h = new_tofu_handle();
        apply_enable_arm(&h, true, None);
        apply_expiry_set_arm(&h, Some(3600)).expect("set");
        assert_eq!(h.lock().unwrap().max_age_secs, Some(3600));
    }

    #[test]
    fn expiry_set_arm_clearing_window_resets_to_none() {
        let h = new_tofu_handle();
        apply_enable_arm(&h, true, None);
        apply_expiry_set_arm(&h, Some(60)).expect("set");
        apply_expiry_set_arm(&h, None).expect("clear");
        assert!(h.lock().unwrap().max_age_secs.is_none());
    }

    #[test]
    fn expiry_set_arm_backfills_anchor_when_enabled_without_one() {
        // Defensive: caller pre-set enabled=true without enabled_at (only
        // possible from a hand-crafted state). The set arm must backfill so
        // the window starts immediately.
        let h = new_tofu_handle();
        {
            let mut g = h.lock().unwrap();
            *g = TofuMode {
                enabled: true,
                enabled_at: None,
                max_age_secs: None,
                ..TofuMode::disabled()
            };
        }
        apply_expiry_set_arm(&h, Some(60)).expect("set");
        let g = h.lock().unwrap();
        assert!(g.enabled_at.is_some());
        assert_eq!(g.max_age_secs, Some(60));
    }
}
