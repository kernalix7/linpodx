use clap::Parser;
use std::path::PathBuf;

/// linpodx daemon — Unix socket API server.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct DaemonConfig {
    /// Unix socket path. Default: `$XDG_RUNTIME_DIR/linpodx.sock` (or `/tmp/linpodx-$UID.sock` if unset).
    #[arg(long, env = "LINPODX_SOCKET")]
    pub socket: Option<PathBuf>,

    /// SQLite database path. Default: `$XDG_DATA_HOME/linpodx/state.db` (or `~/.local/share/linpodx/state.db`).
    #[arg(long, env = "LINPODX_DB")]
    pub db: Option<PathBuf>,

    /// Path to the `podman` binary. Default: `podman` from `$PATH`.
    #[arg(long, env = "LINPODX_PODMAN_BIN")]
    pub podman_bin: Option<PathBuf>,

    /// Override podman `--root`. Use a disposable path in tests.
    #[arg(long, env = "LINPODX_PODMAN_ROOT")]
    pub podman_root: Option<PathBuf>,

    /// Override podman `--runroot`. Use a disposable path in tests.
    #[arg(long, env = "LINPODX_PODMAN_RUNROOT")]
    pub podman_runroot: Option<PathBuf>,

    /// Sandbox profiles directory (YAML files). Default: `${XDG_CONFIG_HOME:-~/.config}/linpodx/profiles`.
    #[arg(long, env = "LINPODX_SANDBOX_PROFILES_DIR")]
    pub sandbox_profiles_dir: Option<PathBuf>,

    /// Tracing filter directive (`RUST_LOG` syntax). Default: `info,linpodx=debug`.
    #[arg(long, env = "RUST_LOG")]
    pub log: Option<String>,

    /// Use compact human-readable log output (instead of JSON).
    #[arg(long, env = "LINPODX_LOG_PRETTY")]
    pub log_pretty: bool,

    /// Bind address for the remote WebSocket listener (Phase 7), e.g. `127.0.0.1:8443`.
    /// When set, `--remote-token` is also required. Leave unset to disable remote access.
    #[arg(long, env = "LINPODX_REMOTE_LISTEN")]
    pub remote_listen: Option<String>,

    /// Static bearer token clients must present in the first WebSocket frame.
    /// Required when `--remote-listen` is set.
    #[arg(long, env = "LINPODX_REMOTE_TOKEN")]
    pub remote_token: Option<String>,

    /// PEM-encoded server certificate (chain) for the remote WebSocket listener.
    /// When both `--remote-cert` and `--remote-key` are set, the listener serves
    /// `wss://` instead of `ws://`. Pair with `--client-ca` to require mTLS.
    #[arg(long = "remote-cert", env = "LINPODX_REMOTE_CERT")]
    pub tls_cert: Option<PathBuf>,

    /// PEM-encoded server private key. Required when `--remote-cert` is set.
    #[arg(long = "remote-key", env = "LINPODX_REMOTE_KEY")]
    pub tls_key: Option<PathBuf>,

    /// PEM-encoded client CA bundle. When set (in addition to `--remote-cert` /
    /// `--remote-key`), the listener requires clients to present a certificate
    /// signed by one of these CAs (mTLS).
    #[arg(long, env = "LINPODX_CLIENT_CA")]
    pub client_ca: Option<PathBuf>,

    /// Enable the read-only Kubernetes adapter at startup (Phase 10).
    /// When set the daemon attempts `kube::Client::try_default()` once and
    /// logs the result. The `k8s_pod_list` / `k8s_service_list` IPC arms are
    /// always available — the flag only controls the startup probe.
    #[arg(long, env = "LINPODX_K8S_ENABLE")]
    pub k8s_enable: bool,

    /// Default namespace for K8s read-only queries. When unset the adapter
    /// lists across all namespaces. Per-call `K8sNamespaceParams.namespace`
    /// overrides this value.
    #[arg(long, env = "LINPODX_K8S_NAMESPACE")]
    pub k8s_namespace: Option<String>,

    /// Enable the Phase 14 Raft leader-elect engine. When set the daemon
    /// constructs a [`linpodx_cluster::RaftNode`] at startup, mounts the
    /// `/cluster/raft/{append,vote,snapshot}` HTTP endpoints onto the remote
    /// listener (when `--remote-listen` is also set), and answers
    /// `cluster.{leader,role}_get` IPC. Off by default — single-node deploys
    /// do not need it.
    #[arg(long, env = "LINPODX_CLUSTER_RAFT")]
    pub cluster_raft: bool,

    /// Friendly node id surfaced through `cluster.role_get`. Defaults to the
    /// `LINPODX_NODE_ID` env var or `local`. Hashed into the openraft NodeId
    /// at startup (see `linpodx_cluster::node_id_from_string`).
    #[arg(long, env = "LINPODX_NODE_ID")]
    pub node_id: Option<String>,

    /// `host:port` this node's Raft HTTP transport advertises to peers.
    /// Defaults to the `--remote-listen` address when set, else
    /// `127.0.0.1:7878`.
    #[arg(long, env = "LINPODX_CLUSTER_RAFT_ADVERTISE")]
    pub cluster_raft_advertise: Option<String>,

    /// Phase 15 — when set (in addition to `--remote-cert` / `--remote-key` /
    /// `--client-ca`), the WebSocket listener will only accept clients whose
    /// peer certificate's SHA-256 fingerprint is present in the
    /// `pinned_clients` SQLite table. Manage entries via
    /// `linpodx daemon pin-client {add,list,remove}`. No-op without
    /// `--client-ca` (no client cert is presented).
    #[arg(long, env = "LINPODX_PIN_CLIENTS")]
    pub pin_clients: bool,

    /// Phase 18 Stream D — accepted for compatibility with
    /// `linpodx daemon start --fork`. The actual detachment is performed by
    /// the CLI (via `setsid -f` + stdio redirection); the daemon itself
    /// stays attached to whatever stdio it was given. Setting `--fork`
    /// without `--pid-file` is allowed but discouraged.
    #[arg(long)]
    pub fork: bool,

    /// Phase 18 Stream D — when set, write the daemon's PID to this file on
    /// startup and remove it cleanly on shutdown. Default:
    /// `$XDG_RUNTIME_DIR/linpodx.pid` (or `/tmp/linpodx-$UID.pid`) when
    /// `--fork` is also set; otherwise no pid-file is written.
    #[arg(long, env = "LINPODX_PID_FILE", value_name = "PATH")]
    pub pid_file: Option<std::path::PathBuf>,
}

impl DaemonConfig {
    pub fn resolved_socket(&self) -> PathBuf {
        if let Some(p) = &self.socket {
            return p.clone();
        }
        default_socket_path()
    }

    pub fn resolved_db(&self) -> PathBuf {
        if let Some(p) = &self.db {
            return p.clone();
        }
        linpodx_common::db::Database::default_path()
    }

    pub fn resolved_log_filter(&self) -> String {
        self.log
            .clone()
            .unwrap_or_else(|| "info,linpodx=debug".to_string())
    }
}

pub fn default_socket_path() -> PathBuf {
    if let Ok(rt) = std::env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(rt).join("linpodx.sock");
    }
    let uid = current_uid();
    PathBuf::from(format!("/tmp/linpodx-{uid}.sock"))
}

/// Phase 18 Stream D — default pid-file location. Mirrors the CLI's
/// `default_pid_file()` so they always agree on where to look.
pub fn default_pid_file_path() -> PathBuf {
    if let Ok(rt) = std::env::var("XDG_RUNTIME_DIR") {
        if !rt.is_empty() {
            return PathBuf::from(rt).join("linpodx.pid");
        }
    }
    let uid = current_uid();
    PathBuf::from(format!("/tmp/linpodx-{uid}.pid"))
}

/// Resolve the current user's UID from `/proc/self/status`. Falls back to 1000.
/// This avoids pulling in `libc` just for `getuid()`.
fn current_uid() -> u32 {
    match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s
            .lines()
            .find_map(|l| {
                l.strip_prefix("Uid:")
                    .and_then(|rest| rest.split_whitespace().next())
            })
            .and_then(|n| n.parse().ok())
            .unwrap_or(1000),
        Err(_) => 1000,
    }
}
