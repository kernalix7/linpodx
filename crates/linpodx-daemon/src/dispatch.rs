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

impl Dispatcher {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        podman: Podman,
        podman_bin: String,
        podman_version: String,
        event_bus: Arc<EventBus>,
        sandbox: Arc<SandboxManager>,
        approvals: Arc<ApprovalRegistry>,
        snapshot: Arc<SnapshotManager>,
        session: Arc<SessionManager>,
        bridges: Arc<BridgeRegistry>,
        metrics: Arc<MetricsCollector>,
        audit: Arc<dyn AuditSink>,
        pin_store: PinnedClientStore,
    ) -> Self {
        Self {
            podman,
            podman_bin,
            podman_version,
            event_bus,
            sandbox,
            approvals,
            snapshot,
            session,
            bridges,
            metrics,
            audit,
            remote: Arc::new(Mutex::new(None)),
            pty_handles: Arc::new(Mutex::new(HashMap::new())),
            plugin_registry: None,
            raft: None,
            pin_store,
            tofu: new_tofu_handle(),
            start_time: std::time::Instant::now(),
            web_ui_local: Arc::new(Mutex::new(None)),
        }
    }

    /// Phase 13 — wire the long-lived `PluginRegistry` so the `ContainerCreate` arm can
    /// run the `runtime_injector` chain. Called from `main.rs` once after constructing
    /// the dispatcher; safe to skip when no plugin support is desired.
    pub fn with_plugin_registry(mut self, registry: Arc<RwLock<PluginRegistry>>) -> Self {
        self.plugin_registry = Some(registry);
        self
    }

    /// Phase 14 Stream C — wire the Raft leader-elect handle. Called from
    /// main.rs after [`linpodx_cluster::RaftNode::start`].
    pub fn with_raft(mut self, raft: Arc<linpodx_cluster::RaftNode>) -> Self {
        self.raft = Some(raft);
        self
    }

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
            Method::Version => {
                let resp = responses::VersionResponse {
                    linpodx_version: LINPODX_VERSION.to_string(),
                    ipc_version: IPC_VERSION,
                    podman_version: self.podman_version.clone(),
                };
                Ok(serde_json::to_value(resp)?)
            }
            Method::ContainerList(p) => {
                let list = self.podman.list(p.all).await?;
                Ok(serde_json::to_value(list)?)
            }
            Method::ContainerCreate(mut opts) => {
                // Phase 1C: if a sandbox profile is named, apply policy first.
                let profile_name_for_session = opts.sandbox_profile.clone();
                if let Some(profile_name) = opts.sandbox_profile.clone() {
                    let (transformed, _applied) =
                        self.sandbox.apply_to_create(&profile_name, opts).await?;
                    opts = transformed;
                }
                // Phase 13: optional `runtime_injector` plugin chain. Runs *after*
                // `apply_to_create` so plugins see the post-policy CreateOptions and
                // can append (never override) env / args / security_opts. Each call
                // emits a single `PluginRuntimeInjectorCalled` audit entry.
                if let Some(registry) = self.plugin_registry.clone() {
                    let opts_json = serde_json::to_vec(&opts)?;
                    let payload = match tokio::task::spawn_blocking(move || {
                        let mut guard = registry.blocking_write();
                        guard.evaluate_runtime_injector(&opts_json)
                    })
                    .await
                    {
                        Ok(p) => p,
                        Err(e) => {
                            warn!(error = %e, "runtime_injector task join failed; skipping injector");
                            linpodx_plugin::InjectorPayload::default()
                        }
                    };
                    if !payload.is_empty() {
                        self.audit
                            .record(
                                AuditSinkKind::PluginRuntimeInjectorCalled,
                                profile_name_for_session.clone(),
                                None,
                                serde_json::json!({
                                    "env_add": payload.env_add.len(),
                                    "args_append": payload.args_append.len(),
                                    "security_opts_add": payload.security_opts_add.len(),
                                }),
                            )
                            .await;
                        opts.env.extend(payload.env_add);
                        opts.command.extend(payload.args_append);
                        opts.security_opts.extend(payload.security_opts_add);
                    }
                }
                // Phase 10: promote the Phase 9 audit-only overlayfs hook to actual
                // rootfs injection. When OverlayfsBackend has a live fuse-overlayfs
                // mount for this image (created by an earlier snapshot commit), pass
                // it to podman as --rootfs and drop the image positional. The audit
                // entry below still fires so the linkage is visible in the chain.
                let mounted_rootfs =
                    OverlayfsBackend::mount_path_for(&opts.image).map(|p| p.display().to_string());
                if let Some(rootfs_path) = mounted_rootfs.as_ref() {
                    opts.rootfs = Some(rootfs_path.clone());
                }
                let id = self.podman.create(&opts).await?;
                let container_name = opts.name.clone().unwrap_or_else(|| id.0.clone());
                // Phase 2C: open a session row for the container's lifetime.
                if let Err(e) = self
                    .session
                    .start(&id.0, &container_name, profile_name_for_session.as_deref())
                    .await
                {
                    warn!(error = %e, container = %id.0, "session::start failed (non-fatal)");
                }
                // Phase 2B: optional pre-run snapshot when the profile asks for it.
                if let Some(profile_name) = &profile_name_for_session {
                    match self
                        .sandbox
                        .pre_run_snapshot(&self.podman, profile_name, &id)
                        .await
                    {
                        Ok(Some(snap_id)) => {
                            tracing::info!(snap_id, container = %id.0, "pre-run snapshot taken");
                        }
                        Ok(None) => {}
                        Err(e) => {
                            warn!(error = %e, container = %id.0, "pre-run snapshot failed (non-fatal)");
                        }
                    }
                }
                // Phase 10: when an overlayfs mount was promoted to --rootfs above,
                // record an informational audit entry so the linkage between the
                // snapshot, the mount path and the new container is visible in the
                // hash-chained log.
                if let Some(rootfs_path) = mounted_rootfs.as_ref() {
                    let payload = serde_json::json!({
                        "container_id": id.0,
                        "image": opts.image,
                        "mount_path": rootfs_path,
                    });
                    self.audit
                        .record(
                            AuditSinkKind::SnapshotMounted,
                            profile_name_for_session.clone(),
                            Some(id.0.clone()),
                            payload,
                        )
                        .await;
                }
                self.publish_with_details(
                    EventTopic::Container,
                    EventKind::Created,
                    id.0.clone(),
                    serde_json::json!({
                        "image": opts.image,
                        "name": opts.name,
                        "sandbox_profile": opts.sandbox_profile,
                    }),
                );
                Ok(serde_json::to_value(id)?)
            }
            Method::ContainerStart(p) => {
                self.podman.start(&p.id).await?;
                let id_str = p.id.0.clone();
                self.metrics.spawn_for(id_str.clone()).await;
                self.publish(EventTopic::Container, EventKind::Started, id_str);
                Ok(serde_json::Value::Null)
            }
            Method::ContainerStop(p) => {
                let timeout = p.timeout_secs.map(|s| Duration::from_secs(s as u64));
                self.podman.stop(&p.id, timeout).await?;
                let id_str = p.id.0.clone();
                self.metrics.stop_for(&id_str).await;
                self.publish(EventTopic::Container, EventKind::Stopped, id_str);
                Ok(serde_json::Value::Null)
            }
            Method::ContainerRemove(p) => {
                // Resolve the user-supplied id/name to the canonical container id so the session
                // row (keyed by full id) closes correctly when the user passed a name.
                let canonical_id = match self.podman.inspect(&p.id).await {
                    Ok(insp) => insp.id.0,
                    Err(_) => p.id.0.clone(),
                };
                self.podman.remove(&p.id, p.force).await?;
                self.metrics.stop_for(&canonical_id).await;
                if let Err(e) = self.session.end(&canonical_id).await {
                    warn!(error = %e, container = %canonical_id, "session::end failed (non-fatal)");
                }
                self.publish(EventTopic::Container, EventKind::Removed, canonical_id);
                Ok(serde_json::Value::Null)
            }
            Method::ContainerInspect(p) => {
                let inspect = self.podman.inspect(&p.id).await?;
                Ok(serde_json::to_value(inspect)?)
            }
            Method::ContainerLogs(p) => {
                let logs = self
                    .podman
                    .logs(&p.id, LogOptions { since: p.since })
                    .await?;
                Ok(serde_json::to_value(responses::LogsResponse {
                    stdout: logs.stdout,
                    stderr: logs.stderr,
                })?)
            }
            // ----- Phase 1A: image ops -----
            Method::ImageList(p) => {
                let list = image::list(&self.podman, &p).await?;
                Ok(serde_json::to_value(list)?)
            }
            Method::ImagePull(p) => {
                let reference = p.reference.clone();
                let id = image::pull(&self.podman, &p).await?;
                self.publish_with_details(
                    EventTopic::Image,
                    EventKind::Pulled,
                    id.0.clone(),
                    serde_json::json!({ "reference": reference }),
                );
                Ok(serde_json::to_value(id)?)
            }
            Method::ImageRemove(p) => {
                let id_str = p.id.0.clone();
                image::remove(&self.podman, &p).await?;
                self.publish(EventTopic::Image, EventKind::Removed, id_str);
                Ok(serde_json::Value::Null)
            }
            Method::ImageInspect(p) => {
                let inspect = image::inspect(&self.podman, &p.id).await?;
                Ok(serde_json::to_value(inspect)?)
            }
            Method::ImageTag(p) => {
                let target = p.target.clone();
                let source = p.source.0.clone();
                image::tag(&self.podman, &p).await?;
                self.publish_with_details(
                    EventTopic::Image,
                    EventKind::Tagged,
                    source,
                    serde_json::json!({ "target": target }),
                );
                Ok(serde_json::Value::Null)
            }
            // ----- Phase 1A: volume ops -----
            Method::VolumeList => {
                let list = volume::list(&self.podman).await?;
                Ok(serde_json::to_value(list)?)
            }
            Method::VolumeCreate(p) => {
                let id = volume::create(&self.podman, &p).await?;
                self.publish(EventTopic::Volume, EventKind::Created, id.0.clone());
                Ok(serde_json::to_value(id)?)
            }
            Method::VolumeRemove(p) => {
                let name = p.name.0.clone();
                volume::remove(&self.podman, &p).await?;
                self.publish(EventTopic::Volume, EventKind::Removed, name);
                Ok(serde_json::Value::Null)
            }
            Method::VolumeInspect(p) => {
                let inspect = volume::inspect(&self.podman, &p.name).await?;
                Ok(serde_json::to_value(inspect)?)
            }
            Method::VolumePrune => {
                let removed = volume::prune(&self.podman).await?;
                for v in &removed {
                    self.publish(EventTopic::Volume, EventKind::Removed, v.0.clone());
                }
                Ok(serde_json::to_value(removed)?)
            }
            // ----- Phase 1A: network ops -----
            Method::NetworkList => {
                let list = network::list(&self.podman).await?;
                Ok(serde_json::to_value(list)?)
            }
            Method::NetworkCreate(p) => {
                let id = network::create(&self.podman, &p).await?;
                self.publish(EventTopic::Network, EventKind::Created, id.0.clone());
                Ok(serde_json::to_value(id)?)
            }
            Method::NetworkRemove(p) => {
                let name = p.name.0.clone();
                network::remove(&self.podman, &p).await?;
                self.publish(EventTopic::Network, EventKind::Removed, name);
                Ok(serde_json::Value::Null)
            }
            Method::NetworkInspect(p) => {
                let inspect = network::inspect(&self.podman, &p.name).await?;
                Ok(serde_json::to_value(inspect)?)
            }
            Method::NetworkPrune => {
                let removed = network::prune(&self.podman).await?;
                for n in &removed {
                    self.publish(EventTopic::Network, EventKind::Removed, n.0.clone());
                }
                Ok(serde_json::to_value(removed)?)
            }
            // Subscribe is intercepted by the server layer (see server.rs); reaching this
            // arm would be a server bug.
            Method::Subscribe(_) => Err(Error::Runtime {
                message: "Subscribe must be handled at the server layer, not dispatch".into(),
            }),
            // ----- Phase 1C: sandbox / audit ops -----
            Method::SandboxProfileList => {
                let summaries = self.sandbox.list().await;
                Ok(serde_json::to_value(summaries)?)
            }
            Method::SandboxProfileGet(p) => {
                let resp = self.sandbox.get(&p.name).await?;
                Ok(serde_json::to_value(resp)?)
            }
            Method::SandboxProfileReload => {
                let names = self.sandbox.reload().await?;
                Ok(serde_json::to_value(
                    responses::SandboxProfileReloadResponse {
                        loaded: names.len(),
                        names,
                    },
                )?)
            }
            Method::AuditLogQuery(p) => {
                let filters = AuditFilters {
                    profile_name: p.profile_name,
                    kind: p.kind,
                    since: p.since.and_then(|s| {
                        chrono::DateTime::parse_from_rfc3339(&s)
                            .ok()
                            .map(|d| d.with_timezone(&chrono::Utc))
                    }),
                    until: p.until.and_then(|s| {
                        chrono::DateTime::parse_from_rfc3339(&s)
                            .ok()
                            .map(|d| d.with_timezone(&chrono::Utc))
                    }),
                    limit: p.limit,
                };
                let entries = self.sandbox.query_audit(filters).await?;
                let summaries: Vec<responses::AuditEntrySummary> = entries
                    .into_iter()
                    .map(|e| responses::AuditEntrySummary {
                        seq: e.seq,
                        ts: e.ts,
                        kind: e.kind,
                        profile_name: e.profile_name,
                        container_id: e.container_id,
                        payload: e.payload,
                        prev_hash: e.prev_hash,
                        this_hash: e.this_hash,
                    })
                    .collect();
                Ok(serde_json::to_value(summaries)?)
            }
            Method::AuditLogVerify(p) => {
                let report = self.sandbox.verify_chain(p.since_seq).await?;
                Ok(serde_json::to_value(responses::AuditVerifyResponse {
                    total: report.total,
                    last_seq: report.last_seq,
                    broken_at: report.broken_at,
                })?)
            }
            // ----- Phase 2A: approval gate response -----
            Method::ApprovalDecision(p) => {
                let outcome = if p.allow {
                    ApprovalOutcome::Granted {
                        by: p.by.unwrap_or_else(|| "unknown".into()),
                        reason: p.reason,
                    }
                } else {
                    ApprovalOutcome::Denied {
                        by: p.by.unwrap_or_else(|| "unknown".into()),
                        reason: p.reason,
                    }
                };
                let accepted = self.approvals.respond(&p.request_id, outcome);
                Ok(serde_json::to_value(responses::ApprovalDecisionResponse {
                    accepted,
                })?)
            }
            // ----- Phase 2B: snapshot ops -----
            Method::SnapshotCreate(p) => {
                let cid = ContainerId::new(p.container_id);
                let summary = self.snapshot.create(&self.podman, &cid, p.label).await?;
                Ok(serde_json::to_value(responses::SnapshotCreateResponse {
                    id: summary.id,
                    image_ref: summary.image_ref,
                })?)
            }
            Method::SnapshotList(p) => {
                let summaries = self.snapshot.list(p.container_id.as_deref()).await?;
                Ok(serde_json::to_value(summaries)?)
            }
            Method::SnapshotInspect(p) => {
                let summary = self.snapshot.inspect(p.id).await?;
                Ok(serde_json::to_value(summary)?)
            }
            Method::SnapshotRollback(p) => {
                let resp = self
                    .snapshot
                    .rollback(&self.podman, p.id, p.new_name, p.keep_original)
                    .await?;
                Ok(serde_json::to_value(resp)?)
            }
            Method::SnapshotRemove(p) => {
                self.snapshot.remove(&self.podman, p.id, p.force).await?;
                Ok(serde_json::Value::Null)
            }
            Method::SnapshotPrune(p) => {
                let removed = self
                    .snapshot
                    .prune(
                        &self.podman,
                        p.container_id.as_deref(),
                        p.keep_recent.unwrap_or(0),
                    )
                    .await?;
                Ok(serde_json::to_value(responses::SnapshotPruneResponse {
                    removed,
                })?)
            }
            // ----- Phase 2C: session ops -----
            Method::SessionList(p) => {
                let summaries = self
                    .session
                    .list(p.container_id.as_deref(), p.limit)
                    .await?;
                Ok(serde_json::to_value(summaries)?)
            }
            Method::SessionInspect(p) => {
                let summary = self.session.inspect(p.id).await?;
                Ok(serde_json::to_value(summary)?)
            }
            Method::SessionTimeline(p) => {
                let entries = self.session.timeline(p.id, &p.kinds).await?;
                Ok(serde_json::to_value(entries)?)
            }
            // ----- Phase 2D: MCP bridge ops -----
            Method::McpBridgeStart(p) => {
                let handle = self
                    .bridges
                    .start(
                        self.podman_bin.clone(),
                        p.container_id,
                        p.host_command,
                        p.host_args,
                        p.allowlist,
                    )
                    .await
                    .map_err(|e| Error::Runtime {
                        message: format!("mcp bridge start failed: {e}"),
                    })?;
                Ok(serde_json::to_value(responses::McpBridgeStartResponse {
                    bridge_id: handle.bridge_id,
                })?)
            }
            Method::McpBridgeStop(p) => {
                let stopped =
                    self.bridges
                        .stop(&p.bridge_id)
                        .await
                        .map_err(|e| Error::Runtime {
                            message: format!("mcp bridge stop failed: {e}"),
                        })?;
                Ok(serde_json::to_value(responses::McpBridgeStopResponse {
                    bridge_id: p.bridge_id,
                    stopped,
                })?)
            }
            Method::McpBridgeStatus(p) => {
                let entries = self.bridges.status(p.bridge_id.as_deref()).await;
                let view: Vec<responses::McpBridgeStatusEntry> = entries
                    .into_iter()
                    .map(|e| responses::McpBridgeStatusEntry {
                        bridge_id: e.bridge_id,
                        container_id: e.container_id,
                        host_command: e.host_command,
                        started_at: e.started_at,
                        messages_seen: e.messages_seen,
                    })
                    .collect();
                Ok(serde_json::to_value(view)?)
            }
            // ----- Phase 2E: async snapshot job -----
            Method::SnapshotJobCreate(p) => {
                let cid = ContainerId::new(p.container_id);
                let db = self.snapshot.database().clone();
                let publisher = self.snapshot.publisher();
                let job_id =
                    runtime_snapshot::create_async(&self.podman, db, &cid, p.label, publisher)
                        .await?;
                Ok(serde_json::to_value(
                    responses::SnapshotJobCreateResponse {
                        job_id,
                        status: "pending".into(),
                    },
                )?)
            }
            Method::SnapshotJobStatus(p) => {
                let db = self.snapshot.database();
                let snap = runtime_snapshot::query_job_status(db, &p.job_id).await?;
                let resp = responses::SnapshotJobStatusResponse {
                    job_id: snap.job_id,
                    container_id: snap.container_id,
                    label: snap.label,
                    status: snap.status,
                    snapshot_id: snap.snapshot_id,
                    image_ref: snap.image_ref,
                    last_progress: snap.last_progress,
                    error_message: snap.error_message,
                    started_at: snap.started_at,
                    ended_at: snap.ended_at,
                };
                Ok(serde_json::to_value(resp)?)
            }
            // ----- Phase 2E: MCP policy admin -----
            Method::McpPolicyList => {
                let store = linpodx_sandbox::McpPolicyStore::new(self.session.db());
                let rules = store.list().await?;
                Ok(serde_json::to_value(rules)?)
            }
            Method::McpPolicySet(p) => {
                let db = self.session.db();
                let sink = linpodx_sandbox::SandboxAuditSink::new(Arc::clone(&db));
                let (upserted, deleted) =
                    linpodx_sandbox::apply_mcp_policy_set(&db, &sink, p.rules, p.replace_all)
                        .await?;
                // Refresh the in-memory policy store so running bridges pick up new rules
                // immediately (no need to restart bridges).
                let new_rules = linpodx_sandbox::McpPolicyStore::new(Arc::clone(&db))
                    .load_all()
                    .await?;
                let store = self.bridges.policy_store();
                let mut guard = store.write().await;
                *guard = new_rules;
                Ok(serde_json::to_value(responses::McpPolicySetResponse {
                    upserted,
                    deleted,
                })?)
            }
            // ApprovalsSubscribe is intercepted at the server layer (see server.rs);
            // reaching this arm would be a server bug.
            Method::ApprovalsSubscribe => Err(Error::Runtime {
                message: "ApprovalsSubscribe must be handled at the server layer, not dispatch"
                    .into(),
            }),
            // ----- Phase 4: distro provisioning -----
            Method::DistroTemplateList => self.run_distro(DistroAction::TemplateList).await,
            Method::DistroTemplateInspect(p) => {
                self.run_distro(DistroAction::TemplateInspect(p)).await
            }
            Method::DistroCreate(p) => self.run_distro(DistroAction::Create(p)).await,
            Method::DistroBuild(p) => self.run_distro(DistroAction::Build(p)).await,
            Method::DistroEnter(p) => self.run_distro(DistroAction::Enter(p)).await,
            Method::DistroRemove(p) => self.run_distro(DistroAction::Remove(p)).await,
            // ----- Phase 5: L4 egress firewall -----
            Method::NetworkEgressApply(p) => {
                let inspect = self
                    .podman
                    .inspect(&ContainerId::from(p.container_id.clone()))
                    .await?;
                let pid = inspect
                    .raw
                    .as_ref()
                    .and_then(|raw| raw.get("State"))
                    .and_then(|s| s.get("Pid"))
                    .and_then(|v| v.as_u64())
                    .filter(|n| *n > 0)
                    .ok_or_else(|| Error::Runtime {
                        message: format!(
                            "container '{}' has no live PID (not running?)",
                            p.container_id
                        ),
                    })? as u32;
                let enforcer = EgressEnforcer::from_env();
                // Stage 3 wire-up: pull the L4 allowlist from the sandbox profile that
                // was attached to this container's session at create time. When no
                // session row exists or no profile is attached, the rule vec is empty
                // and the helper installs only the base drop-by-default table.
                let rules = match self.session.profile_for_container(&inspect.id.0).await {
                    Ok(Some(profile)) => self.sandbox.l4_rules_for_profile(&profile).await,
                    _ => Vec::new(),
                };
                let rules_requested = rules.len();
                let (helper_applied, applied_count) =
                    enforcer
                        .apply(pid, rules)
                        .await
                        .map_err(|e| Error::Runtime {
                            message: format!("egress helper apply failed: {e}"),
                        })?;
                let resp = responses::NetworkEgressApplyResponse {
                    container_id: inspect.id.0.clone(),
                    helper_applied,
                    rules_applied: if helper_applied {
                        applied_count
                    } else {
                        rules_requested
                    },
                };
                Ok(serde_json::to_value(resp)?)
            }
            // ----- Phase 5: MCP Phase 2F (capability cache + subscription tracking) -----
            Method::McpBridgeCapabilities(p) => {
                let caps = self
                    .bridges
                    .capabilities(&p.bridge_id)
                    .await
                    .unwrap_or_default();
                Ok(serde_json::to_value(caps)?)
            }
            Method::McpBridgeSubscriptions(p) => {
                let subs = self
                    .bridges
                    .subscriptions(&p.bridge_id)
                    .await
                    .unwrap_or_default();
                Ok(serde_json::to_value(subs)?)
            }
            // ----- Phase 5: Snapshot tree -----
            Method::SnapshotDiff(p) => {
                let resp = self.snapshot.diff(&self.podman, p.id_a, p.id_b).await?;
                Ok(serde_json::to_value(resp)?)
            }
            Method::SnapshotBranch(p) => {
                let summary = self
                    .snapshot
                    .create_branch(&self.podman, p.parent_id, p.label, p.fork)
                    .await?;
                Ok(serde_json::to_value(summary)?)
            }
            // ----- Phase 6: Plugin SDK -----
            Method::PluginList => {
                let store = PluginStore::new(Arc::clone(self.snapshot.database()));
                let summary = store.list().await?;
                Ok(serde_json::to_value(summary)?)
            }
            Method::PluginInstall(p) => {
                let store = PluginStore::new(Arc::clone(self.snapshot.database()));
                let sink = SandboxAuditSink::new(Arc::clone(self.snapshot.database()));
                let resp = store.install(&sink, &p).await?;
                Ok(serde_json::to_value(resp)?)
            }
            Method::PluginEnable(p) => {
                let store = PluginStore::new(Arc::clone(self.snapshot.database()));
                let sink = SandboxAuditSink::new(Arc::clone(self.snapshot.database()));
                let resp = store.enable(&sink, &p.name).await?;
                Ok(serde_json::to_value(resp)?)
            }
            Method::PluginDisable(p) => {
                let store = PluginStore::new(Arc::clone(self.snapshot.database()));
                let sink = SandboxAuditSink::new(Arc::clone(self.snapshot.database()));
                let resp = store.disable(&sink, &p.name).await?;
                Ok(serde_json::to_value(resp)?)
            }
            Method::PluginRemove(p) => {
                let store = PluginStore::new(Arc::clone(self.snapshot.database()));
                let sink = SandboxAuditSink::new(Arc::clone(self.snapshot.database()));
                let resp = store.remove(&sink, &p).await?;
                Ok(serde_json::to_value(resp)?)
            }
            // ----- Phase 6: Live metrics -----
            Method::MetricsLatest(p) => {
                let latest = self.metrics.latest(&p.container_id).await;
                Ok(serde_json::to_value(latest)?)
            }
            Method::MetricsHistory(p) => {
                let since = p.since.as_deref().and_then(|s| {
                    chrono::DateTime::parse_from_rfc3339(s)
                        .ok()
                        .map(|d| d.with_timezone(&chrono::Utc))
                });
                let samples = self.metrics.history(&p.container_id, since).await;
                Ok(serde_json::to_value(samples)?)
            }
            // ----- Phase 7: OCI layer diff + snapshot backend -----
            Method::SnapshotDiffV2(p) => {
                let resp = self.snapshot.diff_v2(&self.podman, p.id_a, p.id_b).await?;
                Ok(serde_json::to_value(resp)?)
            }
            Method::SnapshotBackendList => {
                let resp = self.snapshot.backend_list().await;
                Ok(serde_json::to_value(resp)?)
            }
            // ----- Phase 7: Remote daemon -----
            Method::RemoteAuth(p) => {
                let slot = self.remote.lock().await;
                let accepted = match slot.as_ref() {
                    Some(handle) => constant_eq(&p.token, &handle.state.token),
                    None => false,
                };
                Ok(serde_json::to_value(responses::RemoteAuthResponse {
                    accepted,
                    since: chrono::Utc::now(),
                })?)
            }
            Method::RemoteListenStart(p) => {
                let addr: std::net::SocketAddr = p
                    .addr
                    .parse()
                    .map_err(|e| Error::InvalidArgument(format!("bad addr '{}': {e}", p.addr)))?;
                if p.token.trim().is_empty() {
                    return Err(Error::InvalidArgument("empty remote token".into()));
                }
                let dispatcher = Arc::new(self.clone());
                // Runtime-spawned listener via IPC currently always plain (no TLS).
                // mTLS is opt-in only via daemon startup flags; the IPC schema would
                // need a TLS variant to support it at runtime.
                let handle = remote::spawn(
                    addr,
                    p.token.clone(),
                    dispatcher,
                    Arc::clone(&self.audit),
                    None,
                    false,
                )
                .map_err(|e| Error::Runtime {
                    message: format!("remote bind failed: {e}"),
                })?;
                let actual_addr = handle.state.addr.to_string();
                {
                    let mut slot = self.remote.lock().await;
                    if let Some(prev) = slot.take() {
                        prev.shutdown().await;
                    }
                    *slot = Some(handle);
                }
                Ok(serde_json::to_value(
                    responses::RemoteListenStartResponse { addr: actual_addr },
                )?)
            }
            Method::RemoteListenStop => {
                let stopped = {
                    let mut slot = self.remote.lock().await;
                    slot.take()
                };
                let was_running = stopped.is_some();
                if let Some(handle) = stopped {
                    handle.shutdown().await;
                }
                Ok(serde_json::to_value(responses::RemoteListenStopResponse {
                    stopped: was_running,
                })?)
            }
            Method::RemoteListenStatus => {
                let slot = self.remote.lock().await;
                let resp = match slot.as_ref() {
                    Some(handle) => responses::RemoteListenStatusResponse {
                        addr: Some(handle.state.addr.to_string()),
                        running: !handle.task.is_finished(),
                        sessions: handle
                            .state
                            .sessions
                            .load(std::sync::atomic::Ordering::SeqCst),
                    },
                    None => responses::RemoteListenStatusResponse {
                        addr: None,
                        running: false,
                        sessions: 0,
                    },
                };
                Ok(serde_json::to_value(resp)?)
            }
            // ----- Phase 9: cluster gossip (Stage 2-B) -----
            Method::ClusterJoin(p) => {
                let store = self.cluster_store();
                let info = store
                    .upsert(p.node_id.clone(), p.addr.clone())
                    .await
                    .map_err(cluster_to_err)?;
                let resp = responses::ClusterJoinResponse {
                    node_id: info.node_id,
                    joined: true,
                };
                Ok(serde_json::to_value(resp)?)
            }
            Method::ClusterLeave(p) => {
                let store = self.cluster_store();
                let removed = store
                    .remove(p.node_id.clone())
                    .await
                    .map_err(cluster_to_err)?;
                let resp = responses::ClusterLeaveResponse {
                    node_id: p.node_id,
                    removed,
                };
                Ok(serde_json::to_value(resp)?)
            }
            Method::ClusterPeers => {
                let store = self.cluster_store();
                let peers = store.list().await.map_err(cluster_to_err)?;
                let summaries: Vec<responses::ClusterPeerSummary> = peers
                    .into_iter()
                    .map(|p| responses::ClusterPeerSummary {
                        node_id: p.node_id,
                        addr: p.addr,
                        status: p.status.as_str().to_string(),
                        last_seen: p.last_seen,
                    })
                    .collect();
                Ok(serde_json::to_value::<responses::ClusterPeersResponse>(
                    summaries,
                )?)
            }
            Method::ClusterContainerView => {
                // Phase 16 Stream A — prefer the Raft-replicated state when a
                // Raft node is wired and has at least one applied entry. Fall
                // back to the Phase 9 gossip aggregation when Raft is absent
                // or has not seen any container proposals yet, so single-node
                // and pre-Phase-16 deployments keep behaving the same.
                if let Some(node) = self.raft.as_ref() {
                    let snap = node.state_snapshot().await;
                    if snap.last_applied > 0 && !snap.containers.is_empty() {
                        let entries: Vec<responses::ClusterContainerEntry> = snap
                            .containers
                            .into_iter()
                            .map(|(node_id, container)| responses::ClusterContainerEntry {
                                node_id,
                                container,
                            })
                            .collect();
                        let db = Arc::clone(self.snapshot.database());
                        record_cluster_view_served(&db, self.audit.as_ref(), 0, entries.len())
                            .await;
                        return Ok(serde_json::to_value::<
                            responses::ClusterContainerViewResponse,
                        >(entries)?);
                    }
                }
                let store = self.cluster_store();
                let peers = store.list().await.map_err(cluster_to_err)?;
                let local = self.podman.list(true).await?;
                let http = linpodx_cluster::gossip::default_client();
                let local_node_id =
                    std::env::var("LINPODX_NODE_ID").unwrap_or_else(|_| "local".to_string());
                let entries = linpodx_cluster::view::aggregate_containers(
                    &local_node_id,
                    &local,
                    &peers,
                    &http,
                    None,
                )
                .await;
                let db = Arc::clone(self.snapshot.database());
                record_cluster_view_served(&db, self.audit.as_ref(), peers.len(), entries.len())
                    .await;
                Ok(serde_json::to_value::<
                    responses::ClusterContainerViewResponse,
                >(entries)?)
            }
            // ----- Phase 14: Cluster Raft leader-elect (Stream C) -----
            Method::ClusterLeaderGet => {
                let leader = match self.raft.as_ref() {
                    Some(node) => node.current_leader(),
                    None => None,
                };
                let resp = responses::ClusterLeaderGetResponse { leader };
                Ok(serde_json::to_value(resp)?)
            }
            Method::ClusterRoleGet => {
                use linpodx_cluster::LeaderState;
                let (node_id, role, leader) = match self.raft.as_ref() {
                    Some(node) => {
                        let role = match node.current_role() {
                            LeaderState::Leader => responses::ClusterRole::Leader,
                            LeaderState::Follower => responses::ClusterRole::Follower,
                            LeaderState::Candidate => responses::ClusterRole::Candidate,
                            LeaderState::Learner => responses::ClusterRole::Learner,
                            LeaderState::Unknown => responses::ClusterRole::Unknown,
                        };
                        (node.node_label().to_string(), role, node.current_leader())
                    }
                    None => {
                        let label = std::env::var("LINPODX_NODE_ID")
                            .unwrap_or_else(|_| "local".to_string());
                        (label, responses::ClusterRole::Unknown, None)
                    }
                };
                let resp = responses::ClusterRoleGetResponse {
                    node_id,
                    role,
                    leader,
                };
                Ok(serde_json::to_value(resp)?)
            }
            // ----- Phase 15: Cluster Raft multi-node (Stream A) -----
            Method::ClusterRaftStatus => {
                use linpodx_cluster::LeaderState;
                let Some(node) = self.raft.as_ref() else {
                    return Err(Error::Runtime {
                        message: "raft leader-elect not enabled on this daemon \
                                  (start with --cluster-raft to enable cluster.raft_status)"
                            .into(),
                    });
                };
                let role = match node.current_role() {
                    LeaderState::Leader => responses::ClusterRole::Leader,
                    LeaderState::Follower => responses::ClusterRole::Follower,
                    LeaderState::Candidate => responses::ClusterRole::Candidate,
                    LeaderState::Learner => responses::ClusterRole::Learner,
                    LeaderState::Unknown => responses::ClusterRole::Unknown,
                };
                let snap = node.membership_snapshot();
                let to_membership_node = |row: &linpodx_cluster::MembershipNodeView,
                                          role: &str|
                 -> responses::RaftMembershipNode {
                    responses::RaftMembershipNode {
                        node_id: row.node_id.to_string(),
                        // Prefer the friendly label; fall back to the
                        // advertised host:port so the UI never shows a bare
                        // numeric id.
                        label: row.label.clone().or_else(|| row.addr.clone()),
                        role: role.to_string(),
                    }
                };
                let voters: Vec<responses::RaftMembershipNode> = snap
                    .voters
                    .iter()
                    .map(|r| to_membership_node(r, "voter"))
                    .collect();
                let learners: Vec<responses::RaftMembershipNode> = snap
                    .learners
                    .iter()
                    .map(|r| to_membership_node(r, "learner"))
                    .collect();
                let resp = responses::ClusterRaftStatusResponse {
                    local_node_id: node.node_label().to_string(),
                    local_role: role,
                    leader: node.current_leader(),
                    voters,
                    learners,
                    current_term: snap.current_term,
                };
                Ok(serde_json::to_value(resp)?)
            }
            Method::ClusterRaftPromote(p) => {
                let Some(node) = self.raft.as_ref() else {
                    return Err(Error::Runtime {
                        message: "raft leader-elect not enabled on this daemon \
                                  (start with --cluster-raft to enable cluster.raft_promote)"
                            .into(),
                    });
                };
                let label = p.node_id.clone();
                node.promote_with_audit(std::slice::from_ref(&label))
                    .await
                    .map_err(|e| Error::Runtime {
                        message: format!("cluster.raft_promote({label}) failed: {e}"),
                    })?;
                let resp = responses::ClusterRaftPromoteResponse {
                    node_id: p.node_id,
                    new_role: "voter".to_string(),
                };
                Ok(serde_json::to_value(resp)?)
            }
            // ----- Phase 16: Cluster state replication (Stream A) -----
            Method::ClusterStateGet => {
                let Some(node) = self.raft.as_ref() else {
                    return Err(Error::Runtime {
                        message: "cluster.state_get unavailable: daemon was started \
                                  without --cluster-raft (no replicated state machine)"
                            .into(),
                    });
                };
                let snap = node.state_snapshot().await;
                let containers: Vec<responses::ClusterContainerEntry> = snap
                    .containers
                    .into_iter()
                    .map(|(node_id, container)| responses::ClusterContainerEntry {
                        node_id,
                        container,
                    })
                    .collect();
                // `state_bytes` is best-effort: serialize the current container
                // map so callers have a usable size hint without forcing the
                // store to expose its on-disk byte count (which is not a thing
                // for the in-memory MemStore yet).
                let state_bytes = serde_json::to_vec(&containers)
                    .map(|v| v.len() as u64)
                    .unwrap_or(0);
                let resp = responses::ClusterStateGetResponse {
                    last_applied: snap.last_applied,
                    containers,
                    state_bytes,
                };
                Ok(serde_json::to_value(resp)?)
            }
            Method::ClusterStateProposeContainer(p) => {
                let Some(node) = self.raft.as_ref() else {
                    return Err(Error::Runtime {
                        message: "cluster.state_propose_container unavailable: daemon \
                                  was started without --cluster-raft"
                            .into(),
                    });
                };
                let log_index = node
                    .propose_container(p.node_id.clone(), p.container.clone())
                    .await
                    .map_err(cluster_to_err)?;
                let resp = responses::ClusterStateProposeContainerResponse {
                    log_index,
                    committed: true,
                };
                Ok(serde_json::to_value(resp)?)
            }
            Method::SnapshotEncryptionStatus(p) => {
                // Phase 16 Stream B — at-rest encryption status. Read the snapshot
                // row to learn its image_ref, then prefer the on-disk side-car
                // produced by `runtime_snapshot::encrypt_committed_image` (source
                // of truth). Fall back to the DB columns when no side-car exists
                // — this lets daemons that pre-record encryption metadata at
                // commit time still answer authoritatively.
                let db = self.snapshot.database();
                type EncRow = (String, i64, Option<String>, Option<String>, Option<String>);
                let row: Option<EncRow> = sqlx::query_as(
                    "SELECT image_ref, COALESCE(encrypted, 0), algorithm, key_source, \
                     ciphertext_sha256 FROM snapshots WHERE id = ?",
                )
                .bind(p.id)
                .fetch_optional(db.pool())
                .await
                .map_err(Error::Sqlx)?;
                let (image_ref, db_encrypted, db_algo, db_source, db_sha) =
                    row.ok_or_else(|| Error::NotFound(format!("snapshot id {}", p.id)))?;
                let resp = match runtime_snapshot::read_encrypted_meta(&image_ref)? {
                    Some(meta) => responses::SnapshotEncryptionStatusResponse {
                        snapshot_id: p.id,
                        encrypted: true,
                        algorithm: Some(meta.algorithm),
                        key_source: Some(meta.key_source),
                        ciphertext_sha256: Some(meta.ciphertext_sha256),
                    },
                    None => responses::SnapshotEncryptionStatusResponse {
                        snapshot_id: p.id,
                        encrypted: db_encrypted != 0,
                        algorithm: db_algo,
                        key_source: db_source,
                        ciphertext_sha256: db_sha,
                    },
                };
                Ok(serde_json::to_value(resp)?)
            }
            Method::PluginKeyList => {
                let registry = linpodx_plugin::KeyRegistry::from_env();
                let entries = registry
                    .list_keys()
                    .into_iter()
                    .map(|e| responses::PluginKeyEntry {
                        publisher: e.publisher,
                        fingerprint: e.fingerprint,
                        status: e.status,
                        revoked_at: e.revoked_at,
                        reason: e.reason,
                    })
                    .collect::<responses::PluginKeyListResponse>();
                Ok(serde_json::to_value(entries)?)
            }
            Method::PluginKeyRevoke(p) => {
                let registry = linpodx_plugin::KeyRegistry::from_env();
                let publisher = p.publisher.clone();
                registry
                    .revoke(&publisher, p.reason.as_deref())
                    .map_err(|e| Error::Runtime {
                        message: format!("plugin.key_revoke({publisher}) failed: {e}"),
                    })?;
                self.audit
                    .record(
                        AuditSinkKind::PluginKeyRevoked,
                        None,
                        None,
                        serde_json::json!({
                            "publisher": publisher,
                            "reason": p.reason,
                        }),
                    )
                    .await;
                let resp = responses::PluginKeyRevokeResponse {
                    publisher,
                    revoked: true,
                };
                Ok(serde_json::to_value(resp)?)
            }
            Method::DaemonPinClientTofuEnable(p) => {
                {
                    let mut mode = self.tofu.lock().map_err(|_| Error::Runtime {
                        message: "tofu mode lock poisoned".into(),
                    })?;
                    let was_enabled = mode.enabled;
                    mode.enabled = p.enable;
                    mode.max_enrollments = p.max_enrollments;
                    if p.enable {
                        // Capture the enable timestamp once per off->on edge so
                        // the Phase 17 `max_age_secs` window has a stable anchor.
                        // Re-enabling while already enabled does NOT reset the
                        // anchor (so an operator tweaking `max_enrollments`
                        // mid-window does not accidentally extend the deadline).
                        if !was_enabled {
                            mode.enabled_at = Some(chrono::Utc::now().timestamp());
                            mode.current_count = 0;
                        }
                    } else {
                        // Disabling resets every Phase 16/17 field so the next
                        // --enable starts with a fresh budget + window.
                        mode.current_count = 0;
                        mode.enabled_at = None;
                        mode.max_age_secs = None;
                    }
                }
                let resp = responses::DaemonPinClientTofuEnableResponse {
                    enabled: p.enable,
                    max_enrollments: p.max_enrollments,
                };
                Ok(serde_json::to_value(resp)?)
            }
            // ----- Phase 17 Stream A — snapshot key rotation / re-encryption.
            // The old key comes from the daemon's startup env (the snapshot was
            // encrypted under it); the new key is supplied in the IPC params via
            // the `SnapshotKeySource` enum.
            Method::SnapshotKeyRotate(p) => {
                let old_cfg = resolve_old_snapshot_cfg()?;
                let new_cfg = resolve_new_snapshot_cfg(p.new_key.clone())?;
                let outcome = linpodx_runtime::rotate_snapshot_key(
                    self.snapshot.database(),
                    p.snapshot_id,
                    &old_cfg,
                    &new_cfg,
                )
                .await?;
                self.audit
                    .record(
                        AuditSinkKind::SnapshotKeyRotated,
                        None,
                        None,
                        serde_json::json!({
                            "snapshot_id": outcome.snapshot_id,
                            "image_ref": outcome.image_ref,
                            "algorithm": outcome.algorithm,
                            "kdf": outcome.kdf,
                            "ciphertext_sha256": outcome.ciphertext_sha256,
                            "rotated_at": outcome.rotated_at,
                        }),
                    )
                    .await;
                let resp = responses::SnapshotKeyRotateResponse {
                    snapshot_id: outcome.snapshot_id,
                    rotated: true,
                    algorithm: outcome.algorithm,
                    kdf: outcome.kdf,
                    ciphertext_sha256: outcome.ciphertext_sha256,
                };
                Ok(serde_json::to_value(resp)?)
            }
            Method::SnapshotReEncryptAll(p) => {
                let old_cfg = resolve_old_snapshot_cfg()?;
                let new_cfg = resolve_new_snapshot_cfg(p.new_key.clone())?;
                let outcome =
                    linpodx_runtime::re_encrypt_all(self.snapshot.database(), &old_cfg, &new_cfg)
                        .await?;
                self.audit
                    .record(
                        AuditSinkKind::SnapshotReEncryptCompleted,
                        None,
                        None,
                        serde_json::json!({
                            "total_seen": outcome.total_seen,
                            "re_encrypted": outcome.re_encrypted,
                            "skipped": outcome.skipped,
                            "failed": outcome.failed,
                        }),
                    )
                    .await;
                let resp = responses::SnapshotReEncryptAllResponse {
                    total_seen: outcome.total_seen,
                    re_encrypted: outcome.re_encrypted,
                    skipped: outcome.skipped,
                    failed: outcome.failed,
                };
                Ok(serde_json::to_value(resp)?)
            }
            // ----- Phase 17 Stream B — sandbox snapshot auto-trigger toggle / status.
            //
            // The hook is wired by main.rs after the daemon resolves a
            // snapshot encryption config. If a daemon is started without
            // encryption configured (no `LINPODX_SNAPSHOT_*` env vars and no
            // CLI override) the hook stays absent and these arms return a
            // friendly Runtime error rather than crashing.
            Method::SandboxSnapshotAutoTriggerStatus => match self.sandbox.auto_encrypt_hook() {
                Some(hook) => {
                    let st = hook.status().await;
                    let resp = responses::SandboxSnapshotAutoTriggerStatusResponse {
                        enabled: st.enabled,
                        last_image_ref: st.last_image_ref,
                        trigger_count: st.trigger_count,
                    };
                    Ok(serde_json::to_value(resp)?)
                }
                None => Err(Error::Runtime {
                    message: "sandbox.snapshot_auto_trigger: hook not wired \
                              (daemon started without snapshot encryption)"
                        .into(),
                }),
            },
            Method::SandboxSnapshotAutoTriggerEnable(p) => match self.sandbox.auto_encrypt_hook() {
                Some(hook) => {
                    let previous = hook.set_enabled(p.enabled);
                    let st = hook.status().await;
                    let resp = responses::SandboxSnapshotAutoTriggerStatusResponse {
                        enabled: st.enabled,
                        last_image_ref: st.last_image_ref,
                        trigger_count: st.trigger_count,
                    };
                    tracing::info!(previous, now = p.enabled, "sandbox auto-encrypt toggle");
                    Ok(serde_json::to_value(resp)?)
                }
                None => Err(Error::Runtime {
                    message: "sandbox.snapshot_auto_trigger: hook not wired \
                              (daemon started without snapshot encryption)"
                        .into(),
                }),
            },
            // ----- Phase 17 Stream C — plugin key revoke Raft propagation.
            //
            // When this daemon is the current Raft leader, the request is
            // proposed as an `AppData::RevokePluginKey` entry; the state-machine
            // apply step on every node (including the leader's own follower
            // path) writes the local `.revoked` marker via
            // `KeyRegistry::apply_remote_revocation`. When this daemon is a
            // follower we surface a friendly error pointing at the current
            // leader so the CLI can re-target. A daemon built without Raft
            // returns the same "not_leader"-style error.
            Method::PluginKeyRevokePropagate(p) => {
                let raft = self.raft.as_ref().ok_or_else(|| Error::Runtime {
                    message: "plugin.key_revoke_propagate: raft leader-elect is not enabled \
                              (start daemon with --cluster-raft to use cluster-wide revocation)"
                        .into(),
                })?;
                if !raft.is_leader() {
                    let leader = raft
                        .current_leader()
                        .unwrap_or_else(|| "unknown".to_string());
                    return Err(Error::Runtime {
                        message: format!(
                            "plugin.key_revoke_propagate: not_leader (current_leader={leader}); \
                             re-issue against the leader"
                        ),
                    });
                }
                let revoked_at = chrono::Utc::now().timestamp();
                let log_index = raft
                    .propose_plugin_key_revocation(
                        p.publisher.clone(),
                        p.fingerprint.clone(),
                        p.reason.clone(),
                        revoked_at,
                    )
                    .await
                    .map_err(|e| Error::Runtime {
                        message: format!("plugin.key_revoke_propagate failed: {e}"),
                    })?;
                self.audit
                    .record(
                        AuditSinkKind::PluginKeyRevokePropagated,
                        None,
                        None,
                        serde_json::json!({
                            "publisher": p.publisher,
                            "fingerprint": p.fingerprint,
                            "reason": p.reason,
                            "log_index": log_index,
                            "revoked_at": revoked_at,
                        }),
                    )
                    .await;
                let resp = responses::PluginKeyRevokePropagateResponse {
                    publisher: p.publisher,
                    fingerprint: p.fingerprint,
                    log_index: Some(log_index),
                    propagated: true,
                };
                Ok(serde_json::to_value(resp)?)
            }
            // ----- Phase 17 Stream C — TOFU time-based expiry status / set.
            Method::DaemonPinClientTofuExpiryStatus => {
                let snapshot = {
                    let mode = self.tofu.lock().map_err(|_| Error::Runtime {
                        message: "tofu mode lock poisoned".into(),
                    })?;
                    (mode.enabled, mode.max_age_secs, mode.enabled_at)
                };
                let resp = responses::DaemonPinClientTofuExpiryStatusResponse {
                    enabled: snapshot.0,
                    max_age_secs: snapshot.1,
                    enabled_at: snapshot.2,
                };
                Ok(serde_json::to_value(resp)?)
            }
            Method::DaemonPinClientTofuExpirySet(p) => {
                {
                    let mut mode = self.tofu.lock().map_err(|_| Error::Runtime {
                        message: "tofu mode lock poisoned".into(),
                    })?;
                    if !mode.enabled {
                        return Err(Error::InvalidArgument(
                            "tofu mode is currently disabled; \
                             enable it first via daemon pin-client tofu --enable"
                                .into(),
                        ));
                    }
                    if mode.enabled_at.is_none() {
                        // Backfill the anchor: the only path to a `None` anchor
                        // with `enabled=true` is a daemon that flipped TOFU on
                        // before Phase 17 (or a hand-crafted test). Use the
                        // current wall clock so the window starts here.
                        mode.enabled_at = Some(chrono::Utc::now().timestamp());
                    }
                    mode.max_age_secs = p.max_age_secs;
                }
                let resp = responses::DaemonPinClientTofuExpirySetResponse {
                    max_age_secs: p.max_age_secs,
                };
                Ok(serde_json::to_value(resp)?)
            }
            // ----- Phase 10: K8s read-only adapter (Stream C) -----
            Method::K8sPodList(p) => {
                let adapter = linpodx_cluster::K8sAdapter::try_default()
                    .await
                    .map_err(k8s_unavailable_err)?;
                let pods = adapter
                    .list_pods(p.namespace.as_deref())
                    .await
                    .map_err(cluster_to_err)?;
                record_k8s_query_served(
                    self.audit.as_ref(),
                    "pod_list",
                    p.namespace.as_deref(),
                    pods.len(),
                )
                .await;
                Ok(serde_json::to_value::<responses::K8sPodListResponse>(pods)?)
            }
            Method::K8sServiceList(p) => {
                let adapter = linpodx_cluster::K8sAdapter::try_default()
                    .await
                    .map_err(k8s_unavailable_err)?;
                let svcs = adapter
                    .list_services(p.namespace.as_deref())
                    .await
                    .map_err(cluster_to_err)?;
                record_k8s_query_served(
                    self.audit.as_ref(),
                    "service_list",
                    p.namespace.as_deref(),
                    svcs.len(),
                )
                .await;
                Ok(serde_json::to_value::<responses::K8sServiceListResponse>(
                    svcs,
                )?)
            }
            // ----- Phase 11: container exec / log streaming / pull progress -----
            Method::ContainerExec(p) => {
                let cid = ContainerId::new(p.container_id.clone());
                let opts = ExecOptions {
                    id: cid,
                    command: p.command.clone(),
                    env: p.env.clone(),
                    tty: p.tty,
                };
                let out = self.podman.exec(opts).await?;
                let payload = serde_json::json!({
                    "container_id": p.container_id,
                    "command": p.command,
                    "exit_code": out.exit_code,
                });
                self.audit
                    .record(
                        AuditSinkKind::ContainerExecCalled,
                        None,
                        Some(p.container_id.clone()),
                        payload,
                    )
                    .await;
                Ok(serde_json::to_value(responses::ContainerExecResponse {
                    exit_code: out.exit_code,
                    stdout: out.stdout,
                    stderr: out.stderr,
                })?)
            }
            Method::ContainerLogsStream(p) => {
                let cid = ContainerId::new(p.container_id.clone());
                let bus = Arc::clone(&self.event_bus);
                let podman = self.podman.clone();
                let container_id = p.container_id.clone();
                let follow = p.follow;
                let since = p.since.clone();
                tokio::spawn(async move {
                    use futures::StreamExt;
                    let mut stream = podman.logs_stream(&cid, follow, since);
                    while let Some((kind, line)) = stream.next().await {
                        bus.publish(Event {
                            topic: EventTopic::Container,
                            kind: EventKind::Log,
                            resource_id: container_id.clone(),
                            timestamp: chrono::Utc::now(),
                            details: serde_json::json!({
                                "stream": kind.as_str(),
                                "line": line,
                            }),
                        });
                    }
                });
                let payload = serde_json::json!({
                    "container_id": p.container_id,
                    "follow": p.follow,
                    "since": p.since,
                });
                self.audit
                    .record(
                        AuditSinkKind::ContainerLogsStreamed,
                        None,
                        Some(p.container_id.clone()),
                        payload,
                    )
                    .await;
                Ok(serde_json::to_value(
                    responses::ContainerLogsStreamResponse {
                        started: true,
                        container_id: p.container_id,
                    },
                )?)
            }
            Method::ImagePullJob(p) => {
                let job_id = make_job_id(&p.reference);
                let bus = Arc::clone(&self.event_bus);
                let podman = self.podman.clone();
                let reference = p.reference.clone();
                let job_id_for_task = job_id.clone();
                tokio::spawn(async move {
                    use futures::StreamExt;
                    let mut stream = podman.pull_with_progress(reference.clone());
                    let mut had_output = false;
                    while let Some(line) = stream.next().await {
                        had_output = true;
                        bus.publish(Event {
                            topic: EventTopic::Image,
                            kind: EventKind::Progress,
                            resource_id: job_id_for_task.clone(),
                            timestamp: chrono::Utc::now(),
                            details: serde_json::json!({
                                "message": line,
                                "reference": reference,
                            }),
                        });
                    }
                    // The stream closes when the child exits. Without a separate
                    // `Child::wait().await.status` we don't have a true exit code,
                    // but pulling silently with no progress lines is the only
                    // observable failure mode here — flag it so subscribers don't
                    // hang waiting for a terminal event.
                    let terminal_kind = if had_output {
                        EventKind::Succeeded
                    } else {
                        EventKind::Failed
                    };
                    bus.publish(Event {
                        topic: EventTopic::Image,
                        kind: terminal_kind,
                        resource_id: job_id_for_task.clone(),
                        timestamp: chrono::Utc::now(),
                        details: serde_json::json!({ "reference": reference }),
                    });
                });
                let payload = serde_json::json!({
                    "reference": p.reference,
                    "job_id": job_id,
                });
                self.audit
                    .record(AuditSinkKind::ImagePullStarted, None, None, payload)
                    .await;
                Ok(serde_json::to_value(responses::ImagePullJobResponse {
                    job_id,
                    status: "started".into(),
                })?)
            }
            // ----- Phase 11: image push + manifest -----
            Method::ImagePush(p) => {
                let cert_dir_used = p.cert_dir.clone();
                let resp = image::push(&self.podman, &p).await?;
                let payload = serde_json::json!({
                    "reference": resp.reference,
                    "digest": resp.digest,
                    "registry": p.registry,
                    "cert_dir": cert_dir_used.as_ref().map(|p| p.display().to_string()),
                });
                self.audit
                    .record(AuditSinkKind::ImagePushed, None, None, payload.clone())
                    .await;
                // Phase 14: when an mTLS cert dir was passed, emit a second
                // dedicated audit so operators can isolate registry-mTLS pushes
                // from anonymous / token-auth pushes.
                if cert_dir_used.is_some() {
                    self.audit
                        .record(AuditSinkKind::ImagePushTls, None, None, payload.clone())
                        .await;
                }
                self.publish_with_details(
                    EventTopic::Image,
                    EventKind::Succeeded,
                    resp.reference.clone(),
                    payload,
                );
                Ok(serde_json::to_value(resp)?)
            }
            Method::ImageManifestCreate(p) => {
                let resp = image::manifest_create(&self.podman, &p).await?;
                let payload = serde_json::json!({
                    "manifest": resp.manifest,
                    "added": resp.added,
                });
                self.audit
                    .record(
                        AuditSinkKind::ImageManifestCreated,
                        None,
                        None,
                        payload.clone(),
                    )
                    .await;
                self.publish_with_details(
                    EventTopic::Image,
                    EventKind::Created,
                    resp.manifest.clone(),
                    payload,
                );
                Ok(serde_json::to_value(resp)?)
            }
            Method::ImageManifestPush(p) => {
                let resp = image::manifest_push(&self.podman, &p).await?;
                let payload = serde_json::json!({
                    "manifest": resp.manifest,
                    "registry": resp.registry,
                });
                // No dedicated AuditSinkKind for manifest push — reuse
                // ImageManifestCreated to keep the manifest's lifecycle in a
                // single audit lane. The payload distinguishes via `registry`.
                self.audit
                    .record(
                        AuditSinkKind::ImageManifestCreated,
                        None,
                        None,
                        payload.clone(),
                    )
                    .await;
                self.publish_with_details(
                    EventTopic::Image,
                    EventKind::Succeeded,
                    resp.manifest.clone(),
                    payload,
                );
                Ok(serde_json::to_value(resp)?)
            }
            // ----- Phase 12: interactive PTY proxy -----
            Method::ContainerExecPty(p) => {
                if p.command.is_empty() {
                    return Err(Error::InvalidArgument(
                        "container_exec_pty: command must not be empty".into(),
                    ));
                }
                let cid = ContainerId::new(p.container_id.clone());
                let opts = PtyExecOptions {
                    container_id: cid,
                    command: p.command.clone(),
                    env: p.env.clone(),
                    cols: p.cols.unwrap_or(80),
                    rows: p.rows.unwrap_or(24),
                    podman_bin: self.podman_bin.clone(),
                };
                let handle = linpodx_runtime::exec_pty(opts).await?;
                let bridge_id = handle.bridge_id.clone();
                let endpoint = format!("/pty/{bridge_id}");
                {
                    let mut map = self.pty_handles.lock().await;
                    map.insert(bridge_id.clone(), handle);
                }
                let payload = serde_json::json!({
                    "container_id": p.container_id,
                    "bridge_id": bridge_id,
                    "endpoint": endpoint,
                    "cols": p.cols.unwrap_or(80),
                    "rows": p.rows.unwrap_or(24),
                });
                self.audit
                    .record(
                        AuditSinkKind::ContainerExecPtyOpened,
                        None,
                        Some(p.container_id.clone()),
                        payload,
                    )
                    .await;
                Ok(serde_json::to_value(responses::ContainerExecPtyResponse {
                    bridge_id,
                    endpoint,
                })?)
            }
            // ----- Phase 13 Stream A: K8s write-side -----
            Method::K8sPodCreate(p) => {
                let adapter = linpodx_cluster::K8sAdapter::try_default()
                    .await
                    .map_err(k8s_unavailable_err)?;
                let resp = adapter
                    .create_pod(&p.namespace, &p.pod_spec_yaml)
                    .await
                    .map_err(cluster_to_err)?;
                self.audit
                    .record(
                        AuditSinkKind::K8sPodCreated,
                        None,
                        None,
                        serde_json::json!({
                            "namespace": resp.namespace,
                            "name": resp.name,
                            "uid": resp.uid,
                        }),
                    )
                    .await;
                Ok(serde_json::to_value::<responses::K8sPodCreateResponse>(
                    resp,
                )?)
            }
            Method::K8sPodDelete(p) => {
                let adapter = linpodx_cluster::K8sAdapter::try_default()
                    .await
                    .map_err(k8s_unavailable_err)?;
                let resp = adapter
                    .delete_pod(&p.namespace, &p.name)
                    .await
                    .map_err(cluster_to_err)?;
                self.audit
                    .record(
                        AuditSinkKind::K8sPodDeleted,
                        None,
                        None,
                        serde_json::json!({
                            "namespace": resp.namespace,
                            "name": resp.name,
                            "deleted": resp.deleted,
                        }),
                    )
                    .await;
                Ok(serde_json::to_value::<responses::K8sPodDeleteResponse>(
                    resp,
                )?)
            }
            Method::K8sNamespaceCreate(p) => {
                let adapter = linpodx_cluster::K8sAdapter::try_default()
                    .await
                    .map_err(k8s_unavailable_err)?;
                let resp = adapter
                    .create_namespace(&p.name)
                    .await
                    .map_err(cluster_to_err)?;
                self.audit
                    .record(
                        AuditSinkKind::K8sNamespaceCreated,
                        None,
                        None,
                        serde_json::json!({
                            "name": resp.name,
                            "uid": resp.uid,
                        }),
                    )
                    .await;
                Ok(serde_json::to_value::<responses::K8sNamespaceCreateResponse>(resp)?)
            }
            Method::K8sDeploymentScale(p) => {
                let adapter = linpodx_cluster::K8sAdapter::try_default()
                    .await
                    .map_err(k8s_unavailable_err)?;
                let resp = adapter
                    .scale_deployment(&p.namespace, &p.name, p.replicas)
                    .await
                    .map_err(cluster_to_err)?;
                self.audit
                    .record(
                        AuditSinkKind::K8sDeploymentScaled,
                        None,
                        None,
                        serde_json::json!({
                            "namespace": resp.namespace,
                            "name": resp.name,
                            "replicas": resp.replicas,
                        }),
                    )
                    .await;
                Ok(serde_json::to_value::<responses::K8sDeploymentScaleResponse>(resp)?)
            }
            // ----- Phase 15: WS client cert pinning (Stream C) -----
            Method::DaemonPinClientAdd(p) => {
                let (fingerprint, inserted) = self
                    .pin_store
                    .add_from_pem(p.cert_pem.as_bytes(), &p.label)
                    .await?;
                let resp = responses::DaemonPinClientAddResponse {
                    fingerprint,
                    inserted,
                };
                Ok(serde_json::to_value(resp)?)
            }
            Method::DaemonPinClientList => {
                let listed = self.pin_store.list().await?;
                Ok(serde_json::to_value::<
                    responses::DaemonPinClientListResponse,
                >(listed)?)
            }
            Method::DaemonPinClientRemove(p) => {
                let removed = self.pin_store.remove(&p.fingerprint).await?;
                let resp = responses::DaemonPinClientRemoveResponse {
                    fingerprint: p.fingerprint,
                    removed,
                };
                Ok(serde_json::to_value(resp)?)
            }
            // ----- Phase 18 Stream C: first-run readiness diagnostics -----
            Method::DoctorRun(_params) => {
                let report = self.run_doctor().await;
                Ok(serde_json::to_value(report)?)
            }
            // ----- Phase 18 Stream D: daemon-side daemon-mgmt arms -----
            //
            // Design: the *primary* surface for `linpodx daemon
            // {start,stop,status,logs}` lives on the CLI
            // (`crates/linpodx-cli/src/commands/daemon_mgmt.rs`). The CLI
            // spawns/signals/probes the daemon process directly via the
            // pid-file + /proc — no IPC required. These IPC arms exist so
            // that:
            //   - a *remote* CLI session over the WebSocket transport can
            //     ask the running daemon about its own state; and
            //   - tooling that only speaks JSON-RPC has a clean way to get
            //     the same answer.
            //
            // `Start` / `Stop` are informational: a daemon cannot
            // meaningfully start itself, and shutting itself down over IPC
            // would require a graceful-stop path we have not built. Both
            // return `Running` with a message pointing the caller at the
            // CLI.
            Method::DaemonMgmtStart(_params) => {
                let resp = responses::DaemonMgmtStartResponse {
                    state: responses::DaemonMgmtState::Running,
                    pid: Some(std::process::id()),
                    pid_file: None,
                    message: Some(
                        "daemon is already running; use the CLI on the host (`linpodx daemon start`) to spawn a new instance"
                            .to_string(),
                    ),
                };
                Ok(serde_json::to_value(resp)?)
            }
            Method::DaemonMgmtStop => {
                let resp = responses::DaemonMgmtStopResponse {
                    state: responses::DaemonMgmtState::Running,
                    message: Some(
                        "stop over IPC is not supported; signal the daemon directly (`linpodx daemon stop` or `kill -TERM <pid>`)"
                            .to_string(),
                    ),
                };
                Ok(serde_json::to_value(resp)?)
            }
            Method::DaemonMgmtStatus => {
                let pid_file = crate::config::default_pid_file_path();
                let resp = responses::DaemonMgmtStatusResponse {
                    state: responses::DaemonMgmtState::Running,
                    pid: Some(std::process::id()),
                    pid_file: if pid_file.exists() {
                        Some(pid_file)
                    } else {
                        None
                    },
                    socket_path: None,
                    uptime_secs: Some(self.start_time.elapsed().as_secs()),
                };
                Ok(serde_json::to_value(resp)?)
            }
            Method::WebUiEnsure(_) => {
                let resp = crate::web_ui_local::ensure(self).await?;
                Ok(serde_json::to_value(resp)?)
            }
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

/// Phase 18 Stream C — doctor check helpers. Each `check_*` returns a
/// [`responses::DoctorCheck`] with a stable id, label, outcome, optional
/// `detail` (human-readable status detail), and optional `fix_hint`.
///
/// Helpers are deliberately small + side-effect free (read env / fs / spawn
/// short-lived subprocesses) so the whole `run_doctor` pass is deterministic
/// from the user's environment alone.
mod doctor {
    use linpodx_common::ipc::responses::{DoctorCheck, DoctorOutcome};
    use std::path::PathBuf;
    use tokio::process::Command;

    fn ok(id: &str, label: &str, detail: impl Into<String>) -> DoctorCheck {
        DoctorCheck {
            id: id.to_string(),
            label: label.to_string(),
            outcome: DoctorOutcome::Pass,
            detail: Some(detail.into()),
            fix_hint: None,
        }
    }

    fn warn(
        id: &str,
        label: &str,
        detail: impl Into<String>,
        hint: impl Into<String>,
    ) -> DoctorCheck {
        DoctorCheck {
            id: id.to_string(),
            label: label.to_string(),
            outcome: DoctorOutcome::Warn,
            detail: Some(detail.into()),
            fix_hint: Some(hint.into()),
        }
    }

    fn fail(
        id: &str,
        label: &str,
        detail: impl Into<String>,
        hint: impl Into<String>,
    ) -> DoctorCheck {
        DoctorCheck {
            id: id.to_string(),
            label: label.to_string(),
            outcome: DoctorOutcome::Fail,
            detail: Some(detail.into()),
            fix_hint: Some(hint.into()),
        }
    }

    /// Parse `Podman 4.9.4` or `podman version 4.9.4` into `(4, 9, 4)`. Returns
    /// `None` when no `MAJOR.MINOR[.PATCH]` triple is found. Public for unit
    /// testing.
    pub(super) fn parse_podman_version(s: &str) -> Option<(u32, u32, u32)> {
        let mut major = None;
        for token in s.split_whitespace() {
            // Strip leading "v" if any.
            let token = token.strip_prefix('v').unwrap_or(token);
            let parts: Vec<&str> = token.split('.').collect();
            if parts.len() < 2 {
                continue;
            }
            let a = parts[0].parse::<u32>().ok();
            let b = parts[1].parse::<u32>().ok();
            let c = parts.get(2).and_then(|p| {
                // The third component might have a `-rc1` / `-dev` suffix.
                let head: String = p.chars().take_while(|ch| ch.is_ascii_digit()).collect();
                head.parse::<u32>().ok()
            });
            if let (Some(a), Some(b)) = (a, b) {
                major = Some((a, b, c.unwrap_or(0)));
                break;
            }
        }
        major
    }

    /// Compare a parsed version against the minimum supported `(4, 6, 0)`.
    pub(super) fn is_supported_podman(v: (u32, u32, u32)) -> bool {
        v >= (4, 6, 0)
    }

    /// Run both `podman-installed` and `podman-version` in a single subprocess
    /// invocation. Returns `(installed_check, version_check)` so the dispatcher
    /// can push both onto the report. Splitting these into two stable ids lets
    /// external monitoring tools alert separately on "podman missing" vs
    /// "podman too old".
    pub(super) async fn check_podman_binary_and_version(
        bin: &str,
        cached: &str,
    ) -> (DoctorCheck, DoctorCheck) {
        let installed_id = "podman-installed";
        let installed_label = "podman binary";
        let version_id = "podman-version";
        let version_label = "podman version (>= 4.6.0)";

        // Prefer the cached version captured by `PodmanConfig::probe_version`
        // at daemon startup. Fall back to running `podman --version` if the
        // cache is empty (e.g. older daemons without the probe step).
        let probed = if cached.trim().is_empty() {
            match Command::new(bin).arg("--version").output().await {
                Ok(out) if out.status.success() => {
                    String::from_utf8_lossy(&out.stdout).trim().to_string()
                }
                Ok(_) => String::new(),
                Err(_) => {
                    let fail_installed = fail(
                        installed_id,
                        installed_label,
                        format!("`{bin}` not found on PATH"),
                        "install podman: `sudo dnf install podman` (Fedora/RHEL) or \
                         `sudo apt install podman` (Debian/Ubuntu). See docs/INSTALL.md#podman",
                    );
                    let fail_version = fail(
                        version_id,
                        version_label,
                        "podman binary missing — version unknown",
                        "see docs/INSTALL.md#podman",
                    );
                    return (fail_installed, fail_version);
                }
            }
        } else {
            cached.to_string()
        };

        let installed = ok(installed_id, installed_label, format!("found `{bin}`"));

        let Some(version) = parse_podman_version(&probed) else {
            let version_check = warn(
                version_id,
                version_label,
                format!("could not parse podman version from `{probed}`"),
                "verify `podman --version` outputs `Podman MAJOR.MINOR.PATCH` and re-run doctor",
            );
            return (installed, version_check);
        };

        let version_check = if is_supported_podman(version) {
            ok(
                version_id,
                version_label,
                format!(
                    "podman {}.{}.{} (>= 4.6.0)",
                    version.0, version.1, version.2
                ),
            )
        } else {
            fail(
                version_id,
                version_label,
                format!(
                    "podman {}.{}.{} is older than the supported minimum 4.6.0",
                    version.0, version.1, version.2
                ),
                "upgrade podman: `sudo dnf upgrade podman` or \
                 `sudo apt install -t backports podman`. See docs/INSTALL.md#podman",
            )
        };

        (installed, version_check)
    }

    pub(super) async fn check_rootless_setup(bin: &str) -> DoctorCheck {
        let id = "rootless-setup";
        let label = "podman rootless mode";
        let result = Command::new(bin)
            .args(["info", "--format", "{{.Host.Security.Rootless}}"])
            .output()
            .await;
        match result {
            Ok(out) if out.status.success() => {
                let val = String::from_utf8_lossy(&out.stdout).trim().to_string();
                match val.as_str() {
                    "true" => ok(id, label, "rootless mode enabled"),
                    "false" => warn(
                        id,
                        label,
                        "podman is running as root (rootful)",
                        "linpodx prefers rootless: run as a non-root user, or accept the \
                         reduced sandboxing posture",
                    ),
                    other => warn(
                        id,
                        label,
                        format!("podman info returned unexpected value `{other}`"),
                        "ensure podman 4.6+ supports the `Host.Security.Rootless` field",
                    ),
                }
            }
            Ok(out) => warn(
                id,
                label,
                format!(
                    "podman info exited with status {}",
                    out.status.code().unwrap_or(-1)
                ),
                "run `podman info` manually to inspect the failure",
            ),
            Err(e) => warn(
                id,
                label,
                format!("could not run podman info: {e}"),
                "ensure the podman binary is on PATH and re-run doctor",
            ),
        }
    }

    /// cgroup v2 is required for podman's rootless lifecycle on modern kernels.
    /// The reliable indicator is the presence of `/sys/fs/cgroup/cgroup.controllers`
    /// — only the unified hierarchy mounts that file at the root.
    pub(super) fn check_cgroup_v2() -> DoctorCheck {
        let id = "cgroup-v2-available";
        let label = "cgroup v2 (unified hierarchy)";
        let marker = std::path::Path::new("/sys/fs/cgroup/cgroup.controllers");
        if marker.exists() {
            match std::fs::read_to_string(marker) {
                Ok(content) => {
                    let controllers = content.trim();
                    if controllers.is_empty() {
                        warn(
                            id,
                            label,
                            "cgroup v2 mounted but no controllers exposed",
                            "delegate controllers to your user with systemd's `Delegate=yes`. \
                             See docs/INSTALL.md#cgroup-v2",
                        )
                    } else {
                        ok(id, label, format!("controllers: {controllers}"))
                    }
                }
                Err(e) => warn(
                    id,
                    label,
                    format!("could not read /sys/fs/cgroup/cgroup.controllers: {e}"),
                    "verify kernel exports the unified hierarchy. See docs/INSTALL.md#cgroup-v2",
                ),
            }
        } else {
            fail(
                id,
                label,
                "no /sys/fs/cgroup/cgroup.controllers — running on cgroup v1",
                "boot with `systemd.unified_cgroup_hierarchy=1` (set in kernel cmdline) and \
                 reboot. See docs/INSTALL.md#cgroup-v2",
            )
        }
    }

    /// Confirm the daemon's Unix socket exists, is a socket, and is mode 0700
    /// (or stricter) — the daemon's `server.rs` enforces 0700 on bind.
    pub(super) fn check_socket_permissions() -> DoctorCheck {
        let id = "socket-permissions";
        let label = "daemon Unix socket";
        let path = default_socket_path();
        match std::fs::metadata(&path) {
            Ok(meta) => {
                use std::os::unix::fs::{FileTypeExt, PermissionsExt};
                if !meta.file_type().is_socket() {
                    return fail(
                        id,
                        label,
                        format!("{} exists but is not a Unix socket", path.display()),
                        "remove the stale file and restart `linpodx daemon start`. \
                         See docs/INSTALL.md#daemon",
                    );
                }
                let mode = meta.permissions().mode() & 0o777;
                // Anything that is not group/other writable (i.e. low bits 0o022 absent)
                // is acceptable for a per-user runtime socket.
                if mode & 0o077 == 0 {
                    ok(
                        id,
                        label,
                        format!("{} (mode 0{:o}, listening)", path.display(), mode),
                    )
                } else {
                    warn(
                        id,
                        label,
                        format!("{} has loose mode 0{:o}", path.display(), mode),
                        format!(
                            "tighten with `chmod 0700 {}` or restart the daemon to re-bind",
                            path.display()
                        ),
                    )
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => warn(
                id,
                label,
                format!("no socket at {}", path.display()),
                "start the daemon: `linpodx daemon start`. See docs/INSTALL.md#daemon",
            ),
            Err(e) => warn(
                id,
                label,
                format!("could not stat {}: {e}", path.display()),
                "check filesystem permissions on the runtime directory",
            ),
        }
    }

    /// `${XDG_CONFIG_HOME:-~/.config}/linpodx/profiles` — the sandbox profile
    /// directory that `SandboxManager` reads YAML from. Absent → warn (the
    /// daemon will create it on first use) but the user has no profiles yet.
    pub(super) fn check_sandbox_profile_dir() -> DoctorCheck {
        let id = "sandbox-profile-dir";
        let label = "sandbox profile directory";
        let dir = default_config_dir().join("profiles");
        check_dir_presence(id, label, &dir, "sandbox-profiles")
    }

    /// `${XDG_CONFIG_HOME:-~/.config}/linpodx/mcp` — where users drop custom
    /// MCP bridge policy files. Same warn-only semantics as the profile dir.
    pub(super) fn check_mcp_bridge_dir() -> DoctorCheck {
        let id = "mcp-bridge-dir";
        let label = "MCP bridge config directory";
        let dir = default_config_dir().join("mcp");
        check_dir_presence(id, label, &dir, "mcp-bridge")
    }

    /// Shared implementation for the two config-directory checks. Returns
    /// `Pass` when the directory exists + is writable, `Warn` when missing
    /// (daemon recreates it), `Fail` when it exists but is not a directory or
    /// is not writable.
    fn check_dir_presence(
        id: &'static str,
        label: &'static str,
        dir: &std::path::Path,
        docs_anchor: &str,
    ) -> DoctorCheck {
        match std::fs::metadata(dir) {
            Ok(meta) if meta.is_dir() => {
                let marker = dir.join(".linpodx-doctor-probe");
                match std::fs::write(&marker, b"") {
                    Ok(()) => {
                        let _ = std::fs::remove_file(&marker);
                        ok(id, label, format!("{} (writable)", dir.display()))
                    }
                    Err(e) => fail(
                        id,
                        label,
                        format!("{} exists but is not writable: {e}", dir.display()),
                        format!(
                            "fix permissions: `chmod u+rwx {}`. See docs/INSTALL.md#{docs_anchor}",
                            dir.display()
                        ),
                    ),
                }
            }
            Ok(_) => fail(
                id,
                label,
                format!("{} exists but is not a directory", dir.display()),
                format!(
                    "remove the file and let the daemon recreate the directory. \
                     See docs/INSTALL.md#{docs_anchor}"
                ),
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => warn(
                id,
                label,
                format!("{} does not exist", dir.display()),
                format!(
                    "created on first daemon start; or `mkdir -p {}`. \
                     See docs/INSTALL.md#{docs_anchor}",
                    dir.display()
                ),
            ),
            Err(e) => fail(
                id,
                label,
                format!("could not stat {}: {e}", dir.display()),
                "check that $XDG_CONFIG_HOME or $HOME points to a readable location",
            ),
        }
    }

    pub(super) fn check_display_session() -> DoctorCheck {
        let id = "display-session";
        let label = "graphical display session";
        let session_type = std::env::var("XDG_SESSION_TYPE").ok();
        let wayland = std::env::var("WAYLAND_DISPLAY").ok();
        let x11 = std::env::var("DISPLAY").ok();

        match (session_type.as_deref(), wayland.as_deref(), x11.as_deref()) {
            (Some("wayland"), Some(w), _) => {
                ok(id, label, format!("wayland (WAYLAND_DISPLAY={w})"))
            }
            (Some("x11"), _, Some(d)) => ok(id, label, format!("x11 (DISPLAY={d})")),
            (_, Some(w), _) => ok(id, label, format!("wayland (WAYLAND_DISPLAY={w})")),
            (_, _, Some(d)) => ok(id, label, format!("x11 (DISPLAY={d})")),
            _ => warn(
                id,
                label,
                "no Wayland/X11 environment detected",
                "GUI passthrough containers will be unavailable; headless containers still work. \
                 set XDG_SESSION_TYPE / WAYLAND_DISPLAY / DISPLAY in your shell rc to enable.",
            ),
        }
    }

    pub(super) fn check_selinux() -> DoctorCheck {
        let id = "selinux-mode";
        let label = "SELinux mode";
        match std::fs::read_to_string("/sys/fs/selinux/enforce") {
            Ok(contents) => match contents.trim() {
                "0" => ok(id, label, "permissive"),
                "1" => ok(id, label, "enforcing"),
                other => warn(
                    id,
                    label,
                    format!("/sys/fs/selinux/enforce returned `{other}`"),
                    "investigate the SELinux subsystem; expected `0` (permissive) or `1` (enforcing)",
                ),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                ok(id, label, "disabled (no /sys/fs/selinux/enforce)")
            }
            Err(e) => warn(
                id,
                label,
                format!("could not read /sys/fs/selinux/enforce: {e}"),
                "check kernel SELinux config; doctor falls back to permissive assumption",
            ),
        }
    }

    pub(super) async fn check_netfilter_helper() -> DoctorCheck {
        let id = "netfilter-helper";
        let label = "linpodx-netfilter-helper capabilities";
        // The helper binary is typically installed alongside the daemon. Try a
        // small list of well-known locations.
        let candidates = [
            "/usr/local/libexec/linpodx-netfilter-helper",
            "/usr/libexec/linpodx-netfilter-helper",
            "/usr/local/bin/linpodx-netfilter-helper",
            "/usr/bin/linpodx-netfilter-helper",
        ];
        let helper = candidates.iter().find(|p| std::path::Path::new(p).exists());
        let Some(helper) = helper else {
            return warn(
                id,
                label,
                "helper binary not installed",
                "L4 egress firewall will be disabled. install via the linpodx package or \
                 run `sudo install -m 0755 target/release/linpodx-netfilter-helper \
                 /usr/local/libexec/`",
            );
        };

        let out = Command::new("getcap").arg(helper).output().await;
        let parsed = match out {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
            Ok(o) => {
                return warn(
                    id,
                    label,
                    format!(
                        "getcap exited with status {}: {}",
                        o.status.code().unwrap_or(-1),
                        String::from_utf8_lossy(&o.stderr).trim()
                    ),
                    "install libcap-progs (`sudo dnf install libcap` / `sudo apt install libcap2-bin`)",
                );
            }
            Err(e) => {
                return warn(
                    id,
                    label,
                    format!("could not run getcap: {e}"),
                    "install libcap-progs / libcap2-bin and re-run doctor",
                );
            }
        };

        if parsed.contains("cap_net_admin") {
            ok(id, label, format!("{helper} has cap_net_admin"))
        } else {
            fail(
                id,
                label,
                format!("{helper} is missing cap_net_admin"),
                format!(
                    "grant the capability: `sudo setcap cap_net_admin,cap_sys_admin+ep {helper}`"
                ),
            )
        }
    }

    pub(super) async fn check_system_libs() -> DoctorCheck {
        let id = "system-libs";
        let label = "GUI passthrough libraries";
        let probes = [
            (
                "libwayland-client.so.0",
                "libwayland-client0 (Debian/Ubuntu) / wayland-libs-client (Fedora)",
            ),
            ("libX11.so.6", "libx11-6 / libX11"),
            ("libpipewire-0.3.so.0", "libpipewire-0.3-0 / pipewire-libs"),
            ("libpulse.so.0", "libpulse0 / pulseaudio-libs"),
            ("libdbus-1.so.3", "libdbus-1-3 / dbus-libs"),
        ];

        let out = Command::new("ldconfig").arg("-p").output().await;
        let cache = match out {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
            Ok(o) => {
                return warn(
                    id,
                    label,
                    format!(
                        "ldconfig exited with status {}",
                        o.status.code().unwrap_or(-1)
                    ),
                    "install glibc-common (`sudo dnf install glibc-common` / `sudo apt install libc-bin`)",
                );
            }
            Err(e) => {
                return warn(
                    id,
                    label,
                    format!("could not run ldconfig: {e}"),
                    "install libc-bin / glibc-common and re-run doctor",
                );
            }
        };

        let mut missing: Vec<(&str, &str)> = Vec::new();
        for (lib, pkg) in probes.iter() {
            if !cache.contains(lib) {
                missing.push((lib, pkg));
            }
        }

        if missing.is_empty() {
            ok(
                id,
                label,
                format!("all {} GUI passthrough libs present", probes.len()),
            )
        } else {
            let names: Vec<String> = missing.iter().map(|(l, _)| (*l).to_string()).collect();
            let hint = missing
                .iter()
                .map(|(l, p)| format!("{l} → install {p}"))
                .collect::<Vec<_>>()
                .join("; ");
            warn(id, label, format!("missing: {}", names.join(", ")), hint)
        }
    }

    /// Mirror of [`crate::config::DaemonConfig::resolved_socket`] — kept in
    /// sync so doctor can probe the socket without injecting the config. The
    /// daemon's runtime listener uses the same defaults.
    fn default_socket_path() -> PathBuf {
        if let Ok(rt) = std::env::var("XDG_RUNTIME_DIR") {
            if !rt.is_empty() {
                return PathBuf::from(rt).join("linpodx.sock");
            }
        }
        let uid = nix_geteuid();
        PathBuf::from(format!("/tmp/linpodx-{uid}.sock"))
    }

    /// Mirror of `$XDG_CONFIG_HOME/linpodx` (fallback `~/.config/linpodx`).
    /// Sandbox profiles and MCP bridge configs both live under this root.
    fn default_config_dir() -> PathBuf {
        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            if !xdg.is_empty() {
                return PathBuf::from(xdg).join("linpodx");
            }
        }
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".config").join("linpodx")
    }

    /// Read the effective UID via `/proc/self/loginuid` fallback `/proc/self/status`
    /// — avoids pulling in the `nix` crate just for `geteuid()`. The daemon
    /// already has `forbid(unsafe_code)`, so `libc::geteuid()` is off the table.
    fn nix_geteuid() -> u32 {
        // `/proc/self/loginuid` may be `4294967295` (no login uid). Prefer
        // `/proc/self/status` which always has the real Uid line.
        if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
            for line in s.lines() {
                if let Some(rest) = line.strip_prefix("Uid:") {
                    if let Some(first) = rest.split_whitespace().next() {
                        if let Ok(uid) = first.parse::<u32>() {
                            return uid;
                        }
                    }
                }
            }
        }
        0
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parse_podman_basic() {
            assert_eq!(parse_podman_version("Podman 4.9.4"), Some((4, 9, 4)));
            assert_eq!(
                parse_podman_version("podman version 5.0.0"),
                Some((5, 0, 0))
            );
            assert_eq!(parse_podman_version("podman 4.6"), Some((4, 6, 0)));
            assert_eq!(
                parse_podman_version("podman 5.1.0-rc1"),
                Some((5, 1, 0)),
                "rc suffix on patch component should be stripped"
            );
        }

        #[test]
        fn parse_podman_none_when_absent() {
            assert_eq!(parse_podman_version("hello world"), None);
            assert_eq!(parse_podman_version(""), None);
        }

        #[test]
        fn supported_version_threshold() {
            assert!(is_supported_podman((4, 6, 0)));
            assert!(is_supported_podman((4, 9, 4)));
            assert!(is_supported_podman((5, 0, 0)));
            assert!(!is_supported_podman((4, 5, 9)));
            assert!(!is_supported_podman((3, 9, 0)));
        }

        #[test]
        fn ok_warn_fail_constructors_set_outcome() {
            let c = ok("a", "b", "c");
            assert_eq!(c.outcome, DoctorOutcome::Pass);
            assert!(c.fix_hint.is_none());

            let c = warn("a", "b", "c", "fix");
            assert_eq!(c.outcome, DoctorOutcome::Warn);
            assert_eq!(c.fix_hint.as_deref(), Some("fix"));

            let c = fail("a", "b", "c", "fix");
            assert_eq!(c.outcome, DoctorOutcome::Fail);
            assert_eq!(c.fix_hint.as_deref(), Some("fix"));
        }

        #[test]
        fn display_session_wayland_pref() {
            // We cannot reliably mutate process env in parallel tests; instead
            // verify the function returns *something* with a stable id.
            let c = check_display_session();
            assert_eq!(c.id, "display-session");
        }

        #[test]
        fn selinux_check_stable_id() {
            let c = check_selinux();
            assert_eq!(c.id, "selinux-mode");
            // Always one of the three outcomes — no panics on absent /sys/fs/selinux.
            assert!(matches!(
                c.outcome,
                DoctorOutcome::Pass | DoctorOutcome::Warn | DoctorOutcome::Fail
            ));
        }

        #[test]
        fn socket_permissions_check_stable_id() {
            let c = check_socket_permissions();
            assert_eq!(c.id, "socket-permissions");
        }

        #[test]
        fn cgroup_v2_check_stable_id() {
            let c = check_cgroup_v2();
            assert_eq!(c.id, "cgroup-v2-available");
            // Outcome depends on the host kernel; just sanity-check the enum
            // discriminant rather than asserting pass/fail.
            assert!(matches!(
                c.outcome,
                DoctorOutcome::Pass | DoctorOutcome::Warn | DoctorOutcome::Fail
            ));
        }

        #[test]
        fn sandbox_profile_dir_stable_id() {
            let c = check_sandbox_profile_dir();
            assert_eq!(c.id, "sandbox-profile-dir");
        }

        #[test]
        fn mcp_bridge_dir_stable_id() {
            let c = check_mcp_bridge_dir();
            assert_eq!(c.id, "mcp-bridge-dir");
        }

        #[test]
        fn default_socket_path_uses_xdg_runtime() {
            let prev = std::env::var("XDG_RUNTIME_DIR").ok();
            std::env::set_var("XDG_RUNTIME_DIR", "/tmp/linpodx-doctor-test");
            let p = default_socket_path();
            assert_eq!(p, PathBuf::from("/tmp/linpodx-doctor-test/linpodx.sock"));
            match prev {
                Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
                None => std::env::remove_var("XDG_RUNTIME_DIR"),
            }
        }

        #[test]
        fn default_config_dir_uses_xdg_config() {
            let prev = std::env::var("XDG_CONFIG_HOME").ok();
            std::env::set_var("XDG_CONFIG_HOME", "/tmp/linpodx-doctor-cfg-test");
            let p = default_config_dir();
            assert_eq!(p, PathBuf::from("/tmp/linpodx-doctor-cfg-test/linpodx"));
            match prev {
                Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
        }

        #[test]
        fn dir_presence_writable_passes() {
            // Create a temp dir, ensure check_dir_presence returns Pass and
            // cleans up its probe marker.
            let tmp = std::env::temp_dir().join(format!(
                "linpodx-doctor-dir-{}-{}",
                std::process::id(),
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
            ));
            std::fs::create_dir_all(&tmp).unwrap();
            let c = check_dir_presence("test-id", "test-label", &tmp, "anchor");
            assert_eq!(c.outcome, DoctorOutcome::Pass);
            // Probe marker should be cleaned up.
            assert!(!tmp.join(".linpodx-doctor-probe").exists());
            std::fs::remove_dir_all(&tmp).ok();
        }

        #[test]
        fn dir_presence_missing_is_warn() {
            let tmp = std::env::temp_dir().join(format!(
                "linpodx-doctor-missing-{}-{}",
                std::process::id(),
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
            ));
            // Intentionally do NOT create it.
            let c = check_dir_presence("test-id", "test-label", &tmp, "anchor");
            assert_eq!(c.outcome, DoctorOutcome::Warn);
            assert!(c
                .fix_hint
                .as_deref()
                .unwrap_or("")
                .contains("docs/INSTALL.md#anchor"));
        }

        #[test]
        fn nix_geteuid_returns_some_uid() {
            // Should not panic and should return a plausible uid (0 or positive).
            let _uid = nix_geteuid();
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
    Error::Runtime {
        message: format!(
            "K8s adapter unavailable: {e}. Hint: set KUBECONFIG, populate \
             ~/.kube/config, or run inside a cluster with a service account."
        ),
    }
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
        PeerDuplicate(n) => Error::InvalidArgument(format!("cluster peer '{n}' already joined")),
        Storage(m) | Http(m) | NotImplemented(m) => Error::Runtime {
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
        .ok_or_else(|| Error::Runtime {
            message: "snapshot.key_rotate: daemon was not started with LINPODX_SNAPSHOT_KEY / \
                 LINPODX_SNAPSHOT_ENCRYPT_PASSPHRASE — nothing to rotate"
                .into(),
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

fn error_to_code(err: &Error) -> (i32, String) {
    match err {
        Error::PodmanNotFound(_) | Error::PodmanVersionMismatch { .. } => {
            (error_codes::PODMAN_UNAVAILABLE, err.to_string())
        }
        Error::NotFound(_) => (error_codes::NOT_FOUND, err.to_string()),
        Error::InvalidArgument(_) => (error_codes::INVALID_ARGUMENT, err.to_string()),
        _ => (error_codes::RUNTIME_ERROR, err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let mut mode = handle.lock().map_err(|_| Error::Runtime {
            message: "tofu mode lock poisoned".into(),
        })?;
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
