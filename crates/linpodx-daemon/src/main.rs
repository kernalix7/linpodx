#![forbid(unsafe_code)]

mod approval;
mod config;
mod dispatch;
mod event_bus;
mod pin_store;
mod remote;
mod server;
mod snapshot_auto_encrypt;
mod web_ui;

use crate::approval::{ApprovalRegistry, PluginAwareApprovalGateway};
use crate::config::DaemonConfig;
use crate::dispatch::Dispatcher;
use crate::event_bus::EventBus;
use anyhow::{Context, Result};
use clap::Parser;
use linpodx_common::approval::ApprovalGateway;
use linpodx_common::audit_sink::AuditSink;
use linpodx_common::db::Database;
use linpodx_mcp::BridgeRegistry;
use linpodx_runtime::{MetricsCollector, Podman, PodmanConfig};
use linpodx_sandbox::{
    McpPolicyStore, PluginStore, SandboxAuditSink, SandboxManager, SessionManager, SnapshotManager,
};
use std::os::unix::fs::FileTypeExt;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UnixListener;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let cfg = DaemonConfig::parse();

    init_tracing(&cfg);

    let socket_path = cfg.resolved_socket();
    let db_path = cfg.resolved_db();

    info!(
        socket = %socket_path.display(),
        db = %db_path.display(),
        version = linpodx_common::version::LINPODX_VERSION,
        ipc_version = linpodx_common::version::IPC_VERSION,
        "linpodx-daemon starting"
    );

    let podman = Podman::with_config(PodmanConfig {
        binary: cfg.podman_bin.clone(),
        root: cfg.podman_root.clone(),
        runroot: cfg.podman_runroot.clone(),
    });
    let podman_version = podman
        .check()
        .await
        .context("podman version check failed (is podman installed and >= 4.6.0?)")?;
    info!(podman_version = %podman_version, "podman OK");

    let db = Database::open(&db_path)
        .await
        .context("opening sqlite database")?;
    db.migrate().await.context("running migrations")?;
    info!("database ready");

    // Clean up any stale socket file from a previous unclean shutdown.
    if socket_path.exists() {
        match std::fs::metadata(&socket_path) {
            Ok(m) if m.file_type().is_socket() || !m.is_dir() => {
                if let Err(e) = std::fs::remove_file(&socket_path) {
                    warn!(error = %e, "could not remove stale socket file; continuing");
                }
            }
            Ok(_) => {
                anyhow::bail!(
                    "socket path {} exists and is a directory",
                    socket_path.display()
                );
            }
            Err(e) => {
                warn!(error = %e, "stat on socket path failed; continuing");
            }
        }
    }
    if let Some(parent) = socket_path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("creating socket parent {}", parent.display()))?;
        }
    }

    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("binding {}", socket_path.display()))?;

    // Phase 18 Stream D — pid-file management. Honour `--pid-file` when
    // explicitly set; otherwise infer the default when `--fork` was passed
    // (the CLI's `linpodx daemon start --fork` path always passes both, so
    // this branch is mostly a safety net for direct `linpodx-daemon` runs).
    let pid_file_path: Option<std::path::PathBuf> = match (&cfg.pid_file, cfg.fork) {
        (Some(p), _) => Some(p.clone()),
        (None, true) => Some(crate::config::default_pid_file_path()),
        (None, false) => None,
    };
    if let Some(ref pf) = pid_file_path {
        if let Some(parent) = pf.parent() {
            if !parent.as_os_str().is_empty() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    warn!(error = %e, pid_file = %pf.display(), "could not create pid-file parent");
                }
            }
        }
        let pid_str = format!("{}\n", std::process::id());
        if let Err(e) = std::fs::write(pf, pid_str) {
            warn!(error = %e, pid_file = %pf.display(), "could not write pid-file (continuing)");
        } else {
            info!(pid_file = %pf.display(), pid = std::process::id(), "pid-file written");
        }
    }

    let event_bus = Arc::new(EventBus::new(1024));
    let publisher: Arc<dyn linpodx_common::events::EventPublisher> = event_bus.clone();
    let approval_registry = Arc::new(ApprovalRegistry::new());
    let db_arc = Arc::new(db);
    let plugin_store = Arc::new(PluginStore::new(Arc::clone(&db_arc)));
    // Phase 7: build a long-lived `PluginRegistry` from the persisted store so the
    // audit-filter and profile-validator hooks reuse the same wasmtime modules across
    // calls (vs the Phase 6 short-lived per-call registry that PluginAwareApprovalGateway
    // still uses for the approval hook).
    let plugin_registry = match build_plugin_registry(&plugin_store).await {
        Ok(r) => Arc::new(tokio::sync::RwLock::new(r)),
        Err(e) => {
            warn!(error = %e, "loading plugin registry failed; audit_filter / profile_validator hooks disabled this session");
            let empty = linpodx_plugin::PluginRegistry::new()
                .expect("wasmtime engine init must succeed (cranelift feature pinned)");
            Arc::new(tokio::sync::RwLock::new(empty))
        }
    };
    let audit_sink: Arc<dyn AuditSink> = Arc::new(SandboxAuditSink::new_with_plugins(
        Arc::clone(&db_arc),
        Arc::clone(&plugin_registry),
    ));
    let inner_gateway: Arc<dyn ApprovalGateway> = approval_registry.clone();
    let gateway: Arc<dyn ApprovalGateway> = Arc::new(PluginAwareApprovalGateway::new(
        inner_gateway,
        Arc::clone(&plugin_store),
        Arc::clone(&audit_sink),
    ));
    let profiles_dir = cfg
        .sandbox_profiles_dir
        .clone()
        .unwrap_or_else(linpodx_sandbox::profile::default_profiles_dir);
    let snapshot = Arc::new(SnapshotManager::new(
        Arc::clone(&db_arc),
        Arc::clone(&publisher),
    ));
    let session = Arc::new(SessionManager::new(
        Arc::clone(&db_arc),
        Arc::clone(&publisher),
    ));
    // Phase 2E: load persisted MCP policy from DB and hand the live store + ApprovalGateway
    // into the bridge registry so every bridge spawned afterwards picks up the rules.
    // `mcp_policy_set` mutates the same `Arc<RwLock<_>>` so running bridges hot-reload.
    let mcp_policy_store = match McpPolicyStore::new(Arc::clone(&db_arc)).load_all().await {
        Ok(rules) => {
            info!(count = rules.len(), "loaded MCP policy rules from db");
            Arc::new(RwLock::new(rules))
        }
        Err(e) => {
            warn!(error = %e, "loading MCP policy rules failed; starting with empty store");
            Arc::new(RwLock::new(Vec::new()))
        }
    };
    let approval_gw_for_bridges: Arc<dyn ApprovalGateway> = approval_registry.clone();
    let bridges = Arc::new(BridgeRegistry::with_policy_and_gateway(
        Arc::clone(&audit_sink),
        mcp_policy_store,
        Some(approval_gw_for_bridges),
    ));
    let mut sandbox_inner = SandboxManager::new_with_plugins(
        Arc::clone(&db_arc),
        profiles_dir.clone(),
        Arc::clone(&publisher),
        gateway,
        Duration::from_secs(30),
        Arc::clone(&snapshot),
        Arc::clone(&session),
        Arc::clone(&plugin_registry),
    );
    // Phase 17 Stream B — wire the auto-encrypt hook so sandbox-driven
    // commit-snapshot events route through `linpodx_runtime::snapshot::
    // encrypt_committed_image`. The encryptor implementation lives in
    // `crate::snapshot_auto_encrypt` (a thin adapter around the runtime
    // encrypt path); when the daemon was started without any
    // `LINPODX_SNAPSHOT_*` env var we still install the hook so the IPC
    // `Status`/`Enable` arms function — the inner encryptor records
    // `outcome=no_encryptor` until an `EncryptionConfig` is provided.
    let auto_encrypt_hook = Arc::new(linpodx_sandbox::AutoEncryptHook::new(
        Arc::clone(&db_arc),
        true,
    ));
    if let Some(encryptor) = crate::snapshot_auto_encrypt::make_encryptor(&podman) {
        Arc::clone(&auto_encrypt_hook)
            .with_encryptor(encryptor)
            .await;
    }
    sandbox_inner.set_auto_encrypt_hook(Arc::clone(&auto_encrypt_hook));
    let sandbox = Arc::new(sandbox_inner);
    info!(profiles_dir = %profiles_dir.display(), "sandbox manager initialized");
    if let Err(e) = sandbox.reload().await {
        warn!(error = %e, "initial sandbox reload failed (continuing — directory may be empty or absent)");
    }
    let podman_bin = cfg
        .podman_bin
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "podman".to_string());
    let metrics = Arc::new(MetricsCollector::new(
        podman_bin.clone(),
        Arc::clone(&publisher),
        Arc::clone(&audit_sink),
    ));
    // Phase 14 Stream C — optionally start the Raft leader-elect engine.
    // Off by default; enabled by `--cluster-raft` (or `LINPODX_CLUSTER_RAFT=1`).
    //
    // Phase 15 Stream A: when `--cluster-raft-advertise` is set we plug in
    // [`linpodx_cluster::RaftHttpFactory`] so multi-node replication actually
    // flows over HTTP. Without `--cluster-raft-advertise` we keep the placeholder
    // single-node `NoopNetworkFactory` — the leader/role IPC arms still answer,
    // but cross-node membership is disabled.
    let raft_node: Option<Arc<linpodx_cluster::RaftNode>> = if cfg.cluster_raft {
        let label = cfg
            .node_id
            .clone()
            .or_else(|| std::env::var("LINPODX_NODE_ID").ok())
            .unwrap_or_else(|| "local".to_string());
        let multi_node = cfg.cluster_raft_advertise.is_some();
        let advertise = cfg
            .cluster_raft_advertise
            .clone()
            .or_else(|| cfg.remote_listen.clone())
            .unwrap_or_else(|| "127.0.0.1:7878".to_string());
        let vote_sink: Arc<dyn linpodx_cluster::VoteSink> =
            Arc::new(linpodx_cluster::SqliteVoteSink::new(Arc::clone(&db_arc)));
        let raft_cfg = linpodx_cluster::RaftStartConfig {
            node_id: linpodx_cluster::node_id_from_string(&label),
            node_label: label.clone(),
            advertise_addr: advertise.clone(),
            heartbeat_ms: 250,
            election_timeout_min_ms: 1500,
            election_timeout_max_ms: 3000,
            bootstrap_single_node: true,
        };
        let result = if multi_node {
            let factory = linpodx_cluster::RaftHttpFactory::new();
            linpodx_cluster::RaftNode::start_with_network(
                raft_cfg,
                Some(vote_sink),
                Some(Arc::clone(&audit_sink)),
                factory,
            )
            .await
        } else {
            linpodx_cluster::RaftNode::start(
                raft_cfg,
                Some(vote_sink),
                Some(Arc::clone(&audit_sink)),
            )
            .await
        };
        match result {
            Ok(n) => {
                info!(
                    node_label = %label,
                    advertise = %advertise,
                    multi_node = multi_node,
                    "raft leader-elect started"
                );
                Some(Arc::new(n))
            }
            Err(e) => {
                warn!(error = %e, "raft leader-elect start failed; cluster leader/role queries will return 'unknown'");
                None
            }
        }
    } else {
        None
    };

    // Phase 17 Stream C — install the cluster->local plugin-key revocation
    // bridge. Every applied `AppData::RevokePluginKey` (proposed by the leader,
    // replicated to every node) writes a `<publisher>.revoked` marker via
    // `KeyRegistry::apply_remote_revocation`. Without this sink the Raft apply
    // path is silent — the entry still advances `last_applied_index` but local
    // future plugin installs would not see the revocation until restart.
    if let Some(ref raft) = raft_node {
        let sink: Arc<dyn linpodx_cluster::PluginRevocationSink> =
            Arc::new(KeyRegistryRevocationSink {
                audit: Arc::clone(&audit_sink),
            });
        raft.set_plugin_revocation_sink(sink);
        info!("raft plugin-key revocation sink installed");
    }

    // Phase 15 Stream C — long-lived pinned-client store. Cheap to construct
    // (just an Arc clone of the DB handle); shared between the JSON-RPC
    // dispatch arms and the WebSocket pin-check path so a `pin-client add`
    // takes effect on the next handshake without restarting the daemon.
    let pin_store = crate::pin_store::PinnedClientStore::new(Arc::clone(&db_arc));

    let dispatcher_builder = Dispatcher::new(
        podman,
        podman_bin,
        podman_version,
        Arc::clone(&event_bus),
        Arc::clone(&sandbox),
        Arc::clone(&approval_registry),
        Arc::clone(&snapshot),
        Arc::clone(&session),
        Arc::clone(&bridges),
        Arc::clone(&metrics),
        Arc::clone(&audit_sink),
        pin_store.clone(),
    )
    // Phase 13: hand the long-lived plugin registry to the dispatcher so the
    // `ContainerCreate` arm can run the `runtime_injector` chain.
    .with_plugin_registry(Arc::clone(&plugin_registry));
    let dispatcher = Arc::new(match raft_node.clone() {
        Some(n) => dispatcher_builder.with_raft(n),
        None => dispatcher_builder,
    });

    // Phase 15 Stream A — when multi-node Raft is enabled, periodically reconcile
    // gossip peer state into Raft membership: alive peers older than 5 s become
    // voters, dead peers stop voting. Best-effort; failures are logged inside
    // the loop and the daemon keeps running.
    if let Some(raft_for_sync) = raft_node.clone() {
        if cfg.cluster_raft_advertise.is_some() {
            let store =
                linpodx_sandbox::ClusterStore::new(Arc::clone(&db_arc), Arc::clone(&audit_sink));
            let store_arc: Arc<dyn linpodx_cluster::store::PeerStore> = Arc::new(store);
            let _handle =
                linpodx_cluster::gossip::run_raft_sync_loop(raft_for_sync, store_arc, 5, 5);
            info!("raft membership sync loop spawned (period=5s, promote_after=5s)");
        }
    }

    // Phase 10: optional K8s adapter probe at startup. v0.1 just logs whether
    // the kubeconfig discovery chain resolves — the dispatch arms always try
    // afresh per request, so a transient failure here does not gate the IPC.
    if cfg.k8s_enable {
        match linpodx_cluster::K8sAdapter::try_default().await {
            Ok(_) => info!(
                namespace = %cfg.k8s_namespace.as_deref().unwrap_or("<all>"),
                "K8s adapter ready"
            ),
            Err(e) => warn!(
                error = %e,
                "K8s adapter unavailable at startup (will retry per request)"
            ),
        }
    }

    // Phase 7: optional remote WebSocket listener spawned at startup.
    if let Some(addr_str) = cfg.remote_listen.clone() {
        let token = cfg
            .remote_token
            .clone()
            .ok_or_else(|| anyhow::anyhow!("--remote-listen requires --remote-token"))?;
        // Phase 8: opt-in TLS / mTLS. cert + key must come together; client_ca alone
        // is a config error.
        let tls = match (
            cfg.tls_cert.clone(),
            cfg.tls_key.clone(),
            cfg.client_ca.clone(),
        ) {
            (Some(cert), Some(key), client_ca) => Some(remote::TlsOptions {
                cert_path: cert,
                key_path: key,
                client_ca,
            }),
            (None, None, None) => None,
            (None, None, Some(_)) => {
                anyhow::bail!("--client-ca requires --remote-cert and --remote-key");
            }
            _ => {
                anyhow::bail!("--remote-cert and --remote-key must be supplied together");
            }
        };
        match addr_str.parse::<std::net::SocketAddr>() {
            Ok(addr) => {
                match remote::spawn(
                    addr,
                    token,
                    Arc::clone(&dispatcher),
                    Arc::clone(&audit_sink),
                    tls,
                    cfg.pin_clients,
                ) {
                    Ok(handle) => {
                        info!(
                            addr = %handle.state.addr,
                            tls = handle.state.tls_enabled,
                            mtls = handle.state.mtls_enabled,
                            pin_clients = handle.state.pin_clients_enabled,
                            "remote WebSocket listener started"
                        );
                        dispatcher.set_remote(handle).await;
                    }
                    Err(e) => {
                        warn!(error = %e, "could not start remote listener (continuing without it)");
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, addr = %addr_str, "invalid --remote-listen addr (skipping)");
            }
        }
    }

    let shutdown = CancellationToken::new();

    let shutdown_for_signals = shutdown.clone();
    tokio::spawn(async move {
        if let Err(e) = wait_for_shutdown_signal().await {
            error!(error = %e, "signal handler errored");
        }
        info!("shutdown signal received");
        shutdown_for_signals.cancel();
    });

    server::run(listener, dispatcher, shutdown.clone()).await;

    // Best-effort cleanup of the socket file.
    if let Err(e) = std::fs::remove_file(&socket_path) {
        warn!(error = %e, "could not remove socket file at shutdown");
    }
    // Phase 18 Stream D — pair the pid-file unlink with the socket cleanup
    // so `linpodx daemon status` after a clean stop reports `stopped`
    // rather than `stale-socket`.
    if let Some(ref pf) = pid_file_path {
        if let Err(e) = std::fs::remove_file(pf) {
            // Missing-file is fine (the user may have removed it manually);
            // log everything else.
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!(error = %e, pid_file = %pf.display(), "could not remove pid-file at shutdown");
            }
        }
    }
    if let Err(e) = db_arc.close_clone().await {
        warn!(error = %e, "db close errored");
    }

    info!("linpodx-daemon stopped");
    Ok(())
}

fn init_tracing(cfg: &DaemonConfig) {
    let filter = EnvFilter::try_new(cfg.resolved_log_filter())
        .unwrap_or_else(|_| EnvFilter::new("info,linpodx=debug"));

    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    if cfg.log_pretty {
        builder.pretty().init();
    } else {
        builder.json().init();
    }
}

/// Phase 7: bootstrap a long-lived `PluginRegistry` from the persisted plugin store.
/// Returns an empty registry on failure (logged at the call site).
async fn build_plugin_registry(
    store: &PluginStore,
) -> anyhow::Result<linpodx_plugin::PluginRegistry> {
    let specs = store
        .list_enabled_specs()
        .await
        .context("listing enabled plugins")?;
    let mut registry = linpodx_plugin::PluginRegistry::new()
        .map_err(|e| anyhow::anyhow!("plugin registry init failed: {e}"))?;
    if !specs.is_empty() {
        registry.load_all(&specs);
    }
    info!(
        loaded = registry.len(),
        "plugin registry populated for audit_filter / profile_validator hooks"
    );
    Ok(registry)
}

async fn wait_for_shutdown_signal() -> std::io::Result<()> {
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    tokio::select! {
        _ = sigterm.recv() => Ok(()),
        _ = sigint.recv() => Ok(()),
    }
}

// Helper to swallow `db.close()` ownership without consuming Database earlier.
trait DatabaseCloseExt {
    fn close_clone(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + '_>>;
}

impl DatabaseCloseExt for Database {
    fn close_clone(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + '_>> {
        let pool = self.pool().clone();
        Box::pin(async move {
            pool.close().await;
            Ok(())
        })
    }
}

/// Phase 17 Stream C — bridge between the Raft state-machine apply path and
/// the local `KeyRegistry`. Constructed once at daemon start and handed to
/// `RaftNode::set_plugin_revocation_sink`. Stateless except for the audit sink
/// reference; cheap to clone if needed.
struct KeyRegistryRevocationSink {
    audit: Arc<dyn linpodx_common::audit_sink::AuditSink>,
}

impl std::fmt::Debug for KeyRegistryRevocationSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyRegistryRevocationSink")
            .finish_non_exhaustive()
    }
}

impl linpodx_cluster::PluginRevocationSink for KeyRegistryRevocationSink {
    fn apply_remote_revocation(
        &self,
        publisher: &str,
        fingerprint: &str,
        reason: Option<&str>,
        revoked_at: i64,
    ) {
        let registry = linpodx_plugin::KeyRegistry::from_env();
        let result = registry.apply_remote_revocation(publisher, fingerprint, reason, revoked_at);
        let audit = Arc::clone(&self.audit);
        let publisher = publisher.to_string();
        let fingerprint = fingerprint.to_string();
        let reason = reason.map(|s| s.to_string());
        // Audit emission needs the async runtime; we're inside a sync trait
        // method called from Raft apply. Spawn a fire-and-forget task that
        // does not block the apply loop. Errors are logged but never
        // surfaced — the .revoked marker is already on disk regardless.
        tokio::spawn(async move {
            let kind = linpodx_common::audit_sink::AuditSinkKind::PluginKeyRevokePropagated;
            let payload = serde_json::json!({
                "publisher": publisher,
                "fingerprint": fingerprint,
                "reason": reason,
                "revoked_at": revoked_at,
                "applied": matches!(&result, Ok(true)),
                "error": result.as_ref().err().map(|e| e.to_string()),
            });
            audit.record(kind, None, None, payload).await;
        });
    }
}
