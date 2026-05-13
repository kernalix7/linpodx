#![forbid(unsafe_code)]

mod client;
mod output;

use crate::client::Client;
use crate::output::{
    print_audit_table, print_compile_result, print_container_list, print_distro_instance,
    print_distro_template_list, print_image_list, print_image_manifest_create,
    print_image_manifest_push, print_image_push, print_inspect, print_logs, print_mcp_policy_list,
    print_mcp_status, print_network_list, print_passthrough_status, print_plugin_list,
    print_prune_result, print_sandbox_profile_list, print_session_list, print_session_timeline,
    print_snapshot_backend_list, print_snapshot_diff, print_snapshot_diff_v2,
    print_snapshot_job_status, print_snapshot_list, print_version_response, print_volume_list,
    OutputFormat,
};
use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use linpodx_common::approval::ApprovalRequest;
use linpodx_common::ipc::{
    responses, ApprovalDecisionParams, AuditQueryParams, AuditVerifyParams, ContainerExecParams,
    ContainerExecPtyParams, ContainerIdParams, ContainerListParams, ContainerLogsParams,
    ContainerLogsStreamParams, ContainerRemoveParams, ContainerStopParams, CreateOptions,
    DistroBuildParams, DistroCreateParams, DistroEnterParams, DistroRemoveParams, EventKind,
    EventTopic, ImageIdParams, ImageListParams, ImageManifestCreateParams, ImageManifestPushParams,
    ImagePullJobParams, ImagePullParams, ImagePushParams, ImageRemoveParams, ImageTagParams,
    K8sDeploymentScaleParams, K8sNamespaceCreateParams, K8sPodCreateParams, K8sPodDeleteParams,
    McpBridgeStartParams, McpBridgeStatusParams, McpBridgeStopParams, McpPolicyDecision,
    McpPolicyRule, McpPolicySetParams, Method, NetworkCreateParams, NetworkNameParams,
    NetworkRemoveParams, Notification, PluginInstallParams, PluginNameParams, PluginRemoveParams,
    SandboxProfileNameParams, ServerMessage, SessionIdParams, SessionListParams,
    SessionTimelineParams, SnapshotBranchParams, SnapshotCreateParams, SnapshotDiffParams,
    SnapshotDiffV2Params, SnapshotIdParams, SnapshotJobCreateParams, SnapshotJobStatusParams,
    SnapshotKeyRotateParams, SnapshotKeySource, SnapshotListParams, SnapshotPruneParams,
    SnapshotReEncryptAllParams, SnapshotRemoveParams, SnapshotRollbackParams, SubscribeParams,
    VolumeCreateParams, VolumeNameParams, VolumeRemoveParams,
};
use linpodx_common::passthrough::{AudioMode, DistroKind, PassthroughSpec};
use linpodx_common::state::{
    ContainerInspect, ContainerSummary, ImageInspect, ImageSummary, NetworkInspect, NetworkSummary,
    PortMapping, VolumeInspect, VolumeMount, VolumeSummary,
};
use linpodx_common::types::{ContainerId, ImageId, NetworkId, VolumeId};
use std::path::{Path, PathBuf};

/// linpodx CLI — talk to the linpodx daemon.
#[derive(Parser, Debug)]
#[command(name = "linpodx", version, about, long_about = None)]
struct Cli {
    /// Unix socket path. Default: `$XDG_RUNTIME_DIR/linpodx.sock` (or `/tmp/linpodx-$UID.sock`).
    #[arg(long, env = "LINPODX_SOCKET", global = true)]
    socket: Option<PathBuf>,

    /// Connect to a remote daemon over WebSocket instead of the local Unix socket.
    /// Accepts `host:port`, `ws://host:port[/ipc]`, or `wss://...`. When set,
    /// `--token` is required and `--socket` is ignored.
    #[arg(long, env = "LINPODX_REMOTE", global = true)]
    remote: Option<String>,

    /// Bearer token for the remote daemon (Phase 7). Required with `--remote`.
    #[arg(long, env = "LINPODX_REMOTE_TOKEN", global = true)]
    token: Option<String>,

    /// PEM client certificate for mTLS (Phase 8). Use with `--client-key` when the
    /// remote daemon was started with `--client-ca`.
    #[arg(long, env = "LINPODX_CLIENT_CERT", global = true)]
    client_cert: Option<PathBuf>,

    /// PEM client private key for mTLS (Phase 8). Use with `--client-cert`.
    #[arg(long, env = "LINPODX_CLIENT_KEY", global = true)]
    client_key: Option<PathBuf>,

    /// PEM CA bundle used to verify the remote daemon's server certificate
    /// (Phase 8). Required when the daemon serves a self-signed cert; omit to
    /// fall back to no extra roots.
    #[arg(long, env = "LINPODX_CA", global = true)]
    ca: Option<PathBuf>,

    /// Sandbox profiles directory. Used by `passthrough` / `network egress` to write back
    /// the mutated YAML before asking the daemon to reload. Default: same heuristic the
    /// daemon uses (`$LINPODX_SANDBOX_PROFILES_DIR` or `${XDG_CONFIG_HOME:-~/.config}/linpodx/profiles`).
    #[arg(long, env = "LINPODX_SANDBOX_PROFILES_DIR", global = true)]
    profiles_dir: Option<PathBuf>,

    /// Output format.
    #[arg(long, short, value_enum, default_value_t = OutputFormat::Table, global = true)]
    output: OutputFormat,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// List containers.
    Ps {
        /// Show all containers (default: only running).
        #[arg(long, short = 'a')]
        all: bool,
    },
    /// Create and start a container.
    Run {
        /// Assign a name to the container.
        #[arg(long)]
        name: Option<String>,
        /// Auto-remove on exit.
        #[arg(long)]
        rm: bool,
        /// Detach (foreground attach lands in Phase 1B with the event-bus subscription model).
        #[arg(short = 'd', long, default_value_t = true)]
        detach: bool,
        /// Set environment variables (KEY=VALUE).
        #[arg(short = 'e', long = "env", value_parser = parse_kv)]
        env: Vec<(String, String)>,
        /// Add labels (KEY=VALUE).
        #[arg(long = "label", value_parser = parse_kv)]
        labels: Vec<(String, String)>,
        /// Publish a port: `[HOST_IP:]HOST_PORT:CONTAINER_PORT[/PROTO]`.
        #[arg(short = 'p', long = "publish", value_parser = parse_port_mapping)]
        publish: Vec<PortMapping>,
        /// Mount a volume: `SRC:DST[:ro]`. SRC is a named volume or absolute host path.
        #[arg(short = 'v', long = "volume", value_parser = parse_volume_mount)]
        volume: Vec<VolumeMount>,
        /// Attach the container to a network (may be repeated).
        #[arg(long = "network")]
        network: Vec<String>,
        /// Apply the named sandbox profile before podman create (Phase 1C).
        #[arg(long = "sandbox")]
        sandbox: Option<String>,
        /// Image (e.g. `docker.io/library/alpine:latest`).
        image: String,
        /// Optional command to run inside the container.
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// Manage images.
    #[command(subcommand)]
    Images(ImagesCmd),
    /// Manage volumes.
    #[command(subcommand)]
    Volume(VolumeCmd),
    /// Manage networks.
    #[command(subcommand)]
    Network(NetworkCmd),
    /// Sandbox profiles + audit log (Phase 1C).
    #[command(subcommand)]
    Sandbox(SandboxCmd),
    /// Container snapshots (Phase 2B).
    #[command(subcommand)]
    Snapshot(SnapshotCmd),
    /// Agent sessions (Phase 2C).
    #[command(subcommand)]
    Session(SessionCmd),
    /// MCP host-stdio bridges (Phase 2D).
    #[command(subcommand)]
    Mcp(McpCmd),
    /// Multi-distro templates and instances (Phase 4).
    #[command(subcommand)]
    Distro(DistroCmd),
    /// Edit GUI / device passthrough grants on a sandbox profile (Phase 3).
    #[command(subcommand)]
    Passthrough(PassthroughCmd),
    /// Manage WASM approval-rule plugins (Phase 6).
    #[command(subcommand)]
    Plugin(PluginCmd),
    /// Kubernetes operations (read-only list in Phase 10, write-side in Phase 13).
    #[command(subcommand)]
    K8s(K8sCmd),
    /// Cluster Raft leader-elect queries (Phase 14).
    #[command(subcommand)]
    Cluster(ClusterCmd),
    /// Start an existing container.
    Start { id: String },
    /// Stop a running container.
    Stop {
        /// Timeout in seconds before SIGKILL (passed to `podman stop --time`).
        #[arg(short = 't', long)]
        time: Option<u32>,
        id: String,
    },
    /// Remove a container.
    Rm {
        /// Force remove a running container.
        #[arg(short = 'f', long)]
        force: bool,
        id: String,
    },
    /// Show low-level container info as pretty JSON.
    Inspect { id: String },
    /// Print captured stdout/stderr from a container.
    Logs {
        /// RFC3339 timestamp; only print lines after this time.
        #[arg(long)]
        since: Option<String>,
        /// Follow log output (stream new lines until Ctrl+C). Phase 11.
        #[arg(short = 'f', long)]
        follow: bool,
        id: String,
    },
    /// Run a one-shot command inside an existing container (Phase 11).
    /// Use `--` to separate the container id from the command, e.g.
    /// `linpodx exec my-container -- ls /tmp`.
    ///
    /// Phase 12: pass `-it` to allocate a PTY and proxy stdin/stdout over a
    /// WebSocket binary stream — this is the interactive mode used for shells.
    Exec {
        /// Set environment variables (KEY=VALUE).
        #[arg(short = 'e', long = "env", value_parser = parse_kv)]
        env: Vec<(String, String)>,
        /// Allocate a TTY for the command. Pair with `-i` for interactive mode.
        #[arg(short = 't', long)]
        tty: bool,
        /// Keep STDIN open and proxy it to the container. Pair with `-t` for
        /// interactive PTY mode (Phase 12).
        #[arg(short = 'i', long)]
        interactive: bool,
        /// Container id or name.
        id: String,
        /// Command + args to run.
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    /// Show client and daemon version info.
    Version,
    /// Stream daemon events (container / image / volume / network lifecycle).
    Events {
        /// Subscribe only to specific topics. Repeatable. Default = all topics.
        #[arg(long = "topic", value_parser = EventTopic::parse)]
        topics: Vec<EventTopic>,
        /// Print events as raw JSON instead of human-readable lines.
        #[arg(long)]
        json: bool,
    },
    /// Listen for sandbox approval requests and prompt the user (Phase 2A).
    Approvals {
        /// Print raw JSON instead of an interactive prompt. In JSON mode no decision is sent
        /// — pair with `linpodx ... approval-decide` to script responses.
        #[arg(long)]
        json: bool,
    },
    /// Daemon-side helpers (cert generation, etc.) (Phase 10).
    #[command(subcommand)]
    Daemon(DaemonCmd),
}

#[derive(Subcommand, Debug)]
enum DaemonCmd {
    /// mTLS / TLS certificate utilities.
    #[command(subcommand)]
    Cert(CertCmd),
    /// Manage pinned WebSocket client certificates (Phase 15).
    #[command(subcommand, name = "pin-client")]
    PinClient(PinClientCmd),
}

#[derive(Subcommand, Debug)]
enum PinClientCmd {
    /// Add a client certificate to the pin store. The leaf cert's SHA-256
    /// fingerprint is computed by the daemon and stored in the
    /// `pinned_clients` SQLite table.
    Add {
        /// Path to a PEM-encoded client certificate.
        cert: PathBuf,
        /// Operator-supplied label surfaced in audit + `pin-client list`.
        #[arg(long, default_value = "")]
        label: String,
    },
    /// List currently-pinned clients (fingerprint + label + enrolment time).
    List,
    /// Remove a pinned client by fingerprint (lowercase hex SHA-256).
    Remove {
        /// Fingerprint to remove. Use exactly the value `pin-client list`
        /// printed in its `fingerprint` column.
        fingerprint: String,
    },
    /// Toggle Trust-On-First-Use auto-enrolment of unknown client certs
    /// (Phase 16). When enabled, the next mTLS upgrade carrying a cert that
    /// is not yet in the pin store is auto-pinned with label `tofu-auto`
    /// instead of being rejected with HTTP 403.
    Tofu(PinClientTofuCmd),
}

#[derive(Args, Debug)]
struct PinClientTofuCmd {
    /// Enable TOFU auto-enrolment.
    #[arg(long, conflicts_with = "disable")]
    enable: bool,
    /// Disable TOFU auto-enrolment. Mutually exclusive with --enable.
    #[arg(long, conflicts_with = "enable")]
    disable: bool,
    /// Optional cap on the number of auto-enrolments to allow before TOFU
    /// latches off. Only meaningful with --enable; silently ignored when paired
    /// with --disable so operators can re-issue the same command unchanged.
    #[arg(long, value_name = "N")]
    max: Option<u32>,
    /// Phase 17 Stream C — auto-disable TOFU after this many seconds. Computed
    /// relative to the moment TOFU was enabled (the daemon captures that
    /// timestamp). Implicitly enables TOFU when paired with no other flag.
    /// Pass `0` to clear an existing expiry while keeping TOFU enabled.
    #[arg(long, value_name = "SECS")]
    expires_in: Option<u64>,
    /// Show the current TOFU + expiry state without changing it.
    #[arg(long, conflicts_with_all = ["enable", "disable", "max", "expires_in"])]
    status: bool,
}

#[derive(Subcommand, Debug)]
enum CertCmd {
    /// Generate a self-signed CA plus server + client leaf certs signed by it.
    /// Output layout: `ca.pem`, `ca-key.pem`, `server-cert.pem`, `server-key.pem`,
    /// `client-cert.pem`, `client-key.pem`.
    Generate {
        /// Output directory. Default: `${XDG_CONFIG_HOME:-~/.config}/linpodx/certs`.
        /// Created with mode 0700 if missing; private keys are written as 0600.
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum SandboxCmd {
    /// List loaded sandbox profiles.
    List,
    /// Show a profile's full YAML content.
    Show { name: String },
    /// Re-scan the profiles directory and reload everything.
    Reload,
    /// Run a container with a sandbox profile applied (shorthand for `linpodx run --sandbox`).
    Apply {
        /// Profile name (must already be loaded).
        profile: String,
        /// Optional container name.
        #[arg(long)]
        name: Option<String>,
        /// Auto-remove on exit.
        #[arg(long)]
        rm: bool,
        /// Image reference.
        image: String,
        /// Optional command to run.
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// Query the audit log.
    Audit {
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        kind: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: u32,
        #[arg(long)]
        json: bool,
    },
    /// Re-compute the SHA-256 hash chain and report any tamper.
    Verify {
        #[arg(long)]
        since_seq: Option<i64>,
    },
    /// Profile-scoped operations (Phase 11 secprofile compilation).
    Profile {
        #[command(subcommand)]
        cmd: SandboxProfileCmd,
    },
}

#[derive(Subcommand, Debug)]
enum SandboxProfileCmd {
    /// Compile a sandbox profile's seccomp + AppArmor extensions to on-disk artefacts.
    /// Pulls the profile YAML from the daemon, then compiles locally.
    Compile {
        /// Sandbox profile name (must be loaded by the daemon).
        name: String,
        /// Output directory for the compiled artefacts. Defaults to
        /// `${XDG_CACHE_HOME:-~/.cache}/linpodx/secprofiles`.
        #[arg(long = "secprofile-out")]
        secprofile_out: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum ImagesCmd {
    /// List images.
    Ls {
        /// Show all images including intermediate layers.
        #[arg(short = 'a', long)]
        all: bool,
        /// Only show dangling images.
        #[arg(long)]
        dangling: bool,
    },
    /// Pull an image from a registry.
    Pull {
        /// Stream pull progress lines as they arrive (Phase 11). Without this flag the
        /// CLI blocks on the synchronous `image_pull` IPC and prints only the final id.
        #[arg(long)]
        progress: bool,
        /// Image reference (e.g. `docker.io/library/alpine:latest`).
        reference: String,
    },
    /// Remove an image.
    Rm {
        /// Force remove.
        #[arg(short = 'f', long)]
        force: bool,
        id: String,
    },
    /// Show low-level image info as pretty JSON.
    Inspect { id: String },
    /// Tag an image with an additional name.
    Tag {
        /// Source image (id or `repo:tag`).
        source: String,
        /// Target tag (e.g. `myrepo/app:1.0`).
        target: String,
    },
    /// Push an image to a registry.
    Push {
        /// Image reference (e.g. `registry.example.com/me/app:1.0`).
        reference: String,
        /// Optional registry override; the destination becomes `<registry>/<reference>`.
        #[arg(long)]
        registry: Option<String>,
        /// Optional base64(`user:password`) auth blob. When omitted podman falls
        /// back to its configured auth file.
        #[arg(long)]
        auth: Option<String>,
        /// Path to a directory containing `cert.pem`, `key.pem`, and `ca.pem`
        /// for mTLS to a private registry. Mapped to `podman push --cert-dir`.
        /// Must exist and be a directory at parse time.
        #[arg(long, value_parser = parse_existing_dir)]
        cert_dir: Option<PathBuf>,
    },
    /// Manage multi-arch manifest lists.
    Manifest {
        #[command(subcommand)]
        cmd: ManifestCmd,
    },
}

#[derive(Subcommand, Debug)]
enum ManifestCmd {
    /// Create a local manifest list from one or more references.
    Create {
        /// Local manifest list name (e.g. `myapp:1.0`).
        target: String,
        /// References to add. Pass `--ref` once per reference.
        #[arg(long = "ref", required = true)]
        refs: Vec<String>,
    },
    /// Add a single reference to an existing manifest list.
    Add {
        /// Manifest list name (e.g. `myapp:1.0`).
        target: String,
        /// Reference to add (e.g. `myrepo/app:1.0-arm64`).
        reference: String,
    },
    /// Push a manifest list to a registry.
    Push {
        /// Manifest list name (e.g. `myapp:1.0`).
        manifest: String,
        /// Optional registry override; the destination becomes `<registry>/<manifest>`.
        #[arg(long)]
        registry: Option<String>,
        /// Optional base64(`user:password`) auth blob.
        #[arg(long)]
        auth: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum VolumeCmd {
    /// List named volumes.
    Ls,
    /// Create a named volume.
    Create {
        /// Volume driver (default: local).
        #[arg(long)]
        driver: Option<String>,
        /// Add a label (KEY=VALUE).
        #[arg(long = "label", value_parser = parse_kv)]
        labels: Vec<(String, String)>,
        /// Driver-specific option (KEY=VALUE).
        #[arg(long = "opt", value_parser = parse_kv)]
        opts: Vec<(String, String)>,
        /// Optional volume name (if omitted, podman generates one).
        name: Option<String>,
    },
    /// Remove a volume.
    Rm {
        #[arg(short = 'f', long)]
        force: bool,
        name: String,
    },
    /// Show volume metadata as pretty JSON.
    Inspect { name: String },
    /// Remove all unused volumes.
    Prune,
}

#[derive(Subcommand, Debug)]
enum NetworkCmd {
    /// List networks.
    Ls,
    /// Create a bridge network.
    Create {
        #[arg(long)]
        driver: Option<String>,
        #[arg(long)]
        subnet: Option<String>,
        #[arg(long)]
        gateway: Option<String>,
        /// Disconnect from external networks.
        #[arg(long)]
        internal: bool,
        /// Disable container DNS resolver on this network.
        #[arg(long = "no-dns")]
        no_dns: bool,
        /// Add a label (KEY=VALUE).
        #[arg(long = "label", value_parser = parse_kv)]
        labels: Vec<(String, String)>,
        name: String,
    },
    /// Remove a network.
    Rm {
        #[arg(short = 'f', long)]
        force: bool,
        name: String,
    },
    /// Show network metadata as pretty JSON.
    Inspect { name: String },
    /// Remove all unused networks.
    Prune,
    /// Sandbox-profile-scoped egress allowlist (Phase 3).
    #[command(subcommand)]
    Egress(NetworkEgressCmd),
}

#[derive(Subcommand, Debug)]
enum NetworkEgressCmd {
    /// Replace the egress allowlist on a sandbox profile with the given comma-separated domains.
    Set {
        /// Comma-separated domain list (e.g. `api.openai.com,registry.npmjs.org`).
        #[arg(long, value_delimiter = ',')]
        domains: Vec<String>,
        /// Sandbox profile name.
        profile: String,
    },
    /// Print the current network policy for a profile.
    Status {
        /// Sandbox profile name.
        profile: String,
    },
}

#[derive(Subcommand, Debug)]
enum SnapshotCmd {
    /// Snapshot a container into an OCI image (`linpodx-snap-<id>`).
    Create {
        /// Optional human-readable label.
        #[arg(long)]
        label: Option<String>,
        /// Container id or name.
        container: String,
    },
    /// List snapshots, optionally filtered by container.
    List {
        /// Filter by container id or name.
        #[arg(long)]
        container: Option<String>,
    },
    /// Show one snapshot row as pretty JSON.
    Inspect { id: i64 },
    /// Rebuild a container from a snapshot. Removes the original by default.
    Rollback {
        /// Name for the new container. Default: `<original>-restored`.
        #[arg(long)]
        new_name: Option<String>,
        /// Keep the original container instead of removing it.
        #[arg(long)]
        keep_original: bool,
        id: i64,
    },
    /// Remove a snapshot (image + DB row).
    Rm {
        /// Force remove even if other refs exist.
        #[arg(short = 'f', long)]
        force: bool,
        id: i64,
    },
    /// Prune snapshots, optionally keeping the N newest per scope.
    Prune {
        /// Limit to a single container.
        #[arg(long)]
        container: Option<String>,
        /// Keep this many newest snapshots. Default: 0 (delete all matching).
        #[arg(long)]
        keep_recent: Option<u32>,
    },
    /// Async snapshot jobs (Phase 2E) — non-blocking commit + Progress events.
    #[command(subcommand)]
    Job(SnapshotJobCmd),
    /// Show file-level diff between two snapshots (added / modified / deleted).
    /// Pass `--layers` to use the OCI layer-aware diff (Phase 7) instead of the
    /// classic `podman diff` set-difference.
    Diff {
        /// Use the layer-aware diff path (lists shared / a-only / b-only layers and
        /// per-layer file changes when available).
        #[arg(long)]
        layers: bool,
        /// Snapshot id "A" — the baseline.
        id_a: i64,
        /// Snapshot id "B" — the comparison.
        id_b: i64,
    },
    /// List the snapshot backends compiled into the daemon and their current
    /// availability on this host.
    BackendList,
    /// Branch an existing snapshot: tag its image with a fresh ref and link the new
    /// row to the parent. Both rows then share the same underlying image content unless
    /// `--fork` is passed, which runs a real `podman commit` from the parent's
    /// container so the new row owns its own image content (fork-on-write).
    Branch {
        /// Optional human-readable label for the new branch row.
        #[arg(long)]
        label: Option<String>,
        /// Materialise a new image via `podman commit` on the parent's container
        /// instead of just tagging. Requires the container to still be present.
        #[arg(long)]
        fork: bool,
        /// Parent snapshot id to branch from.
        parent_id: i64,
    },
    /// Phase 16 Stream B — show at-rest encryption metadata for a snapshot.
    /// Returns whether the snapshot's image was encrypted via the AES-256-GCM
    /// pipeline (LINPODX_SNAPSHOT_ENCRYPT_PASSPHRASE / LINPODX_SNAPSHOT_KEY)
    /// and surfaces the algorithm / key-source / ciphertext sha256 for audit.
    EncryptionStatus {
        /// Snapshot id (from `snapshot list`).
        id: i64,
    },
    /// Phase 17 Stream A — rotate the at-rest encryption key for a single
    /// snapshot. Decrypts the side-car blob under the daemon's current key
    /// and re-encrypts under the supplied passphrase or explicit base64 key.
    KeyRotate {
        /// Snapshot id to rotate (from `snapshot list`).
        id: i64,
        /// New passphrase (mixed through Argon2id by default). Mutually
        /// exclusive with `--new-key`.
        #[arg(long, conflicts_with = "new_key")]
        new_passphrase: Option<String>,
        /// Raw 32-byte base64 key. Mutually exclusive with `--new-passphrase`.
        #[arg(long, conflicts_with = "new_passphrase")]
        new_key: Option<String>,
    },
    /// Phase 17 Stream A — re-encrypt every snapshot in the DB under a new
    /// key. Skips never-encrypted snapshots and continues past per-row
    /// failures; the response reports total / re-encrypted / skipped / failed.
    ReEncryptAll {
        /// New passphrase (Argon2id by default). Mutually exclusive with
        /// `--new-key`.
        #[arg(long, conflicts_with = "new_key")]
        new_passphrase: Option<String>,
        /// Raw 32-byte base64 key. Mutually exclusive with `--new-passphrase`.
        #[arg(long, conflicts_with = "new_passphrase")]
        new_key: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum SnapshotJobCmd {
    /// Enqueue a snapshot job for a container; returns the job id immediately.
    Start {
        /// Optional human-readable label.
        #[arg(long)]
        label: Option<String>,
        /// Container id or name.
        container: String,
    },
    /// Show the current state of a snapshot job (queued / running / succeeded / failed).
    Status { job_id: String },
}

#[derive(Subcommand, Debug)]
enum SessionCmd {
    /// List sessions (one row per container lifetime).
    List {
        /// Filter by container id or name.
        #[arg(long)]
        container: Option<String>,
        /// Cap the number of rows returned.
        #[arg(long)]
        limit: Option<u32>,
    },
    /// Show one session row as pretty JSON.
    Inspect { id: i64 },
    /// Print the merged audit + MCP timeline for a session.
    Timeline {
        /// Filter to specific entry kinds. Repeatable.
        #[arg(long = "kind")]
        kinds: Vec<String>,
        id: i64,
    },
}

#[derive(Subcommand, Debug)]
enum McpCmd {
    /// Start a host-stdio MCP bridge for a container.
    Start {
        /// Allow only these MCP method names. Repeat the flag. Empty = audit-only.
        #[arg(long = "allow")]
        allowlist: Vec<String>,
        /// Container id or name to attach to.
        container: String,
        /// Host command to run as the MCP server (e.g. `/usr/bin/cat`).
        host_command: String,
        /// Trailing arguments forwarded to the host command.
        #[arg(trailing_var_arg = true)]
        host_args: Vec<String>,
    },
    /// Stop a running bridge by id.
    Stop { bridge_id: String },
    /// List currently running bridges.
    Status {
        /// Limit to a single bridge id.
        #[arg(long)]
        bridge_id: Option<String>,
    },
    /// Per-method MCP policy table (Phase 2E).
    #[command(subcommand)]
    Policy(McpPolicyCmd),
}

#[derive(Subcommand, Debug)]
enum McpPolicyCmd {
    /// Upsert one rule (method [+ tool]) → decision.
    Set {
        /// JSON-RPC method name (e.g. `tools/call`, `prompts/list`).
        #[arg(long)]
        method: String,
        /// Optional tool name (only meaningful with `tools/call`).
        #[arg(long)]
        tool: Option<String>,
        /// Decision: auto_allow | prompt | deny | audit_only.
        #[arg(long, value_parser = parse_mcp_decision)]
        decision: McpPolicyDecision,
        /// Optional free-form note recorded alongside the rule.
        #[arg(long)]
        note: Option<String>,
    },
    /// Print the current rule table.
    List,
}

#[derive(Subcommand, Debug)]
enum DistroCmd {
    /// List the distro templates the daemon knows about.
    List,
    /// Provision a new distro instance.
    Create {
        /// Template kind: ubuntu | fedora | arch | debian | alpine | nixos.
        #[arg(long, value_parser = parse_distro_kind)]
        kind: DistroKind,
        /// Persistent home volume + auto-restart + keep-user-id (a.k.a. "VM mode").
        #[arg(long = "vm-mode")]
        vm_mode: bool,
        /// Use a custom pre-built image instead of the template default.
        #[arg(long)]
        custom_image: Option<String>,
        /// Sandbox profile to apply.
        #[arg(long)]
        sandbox: Option<String>,
        /// Instance name (must be unique).
        name: String,
    },
    /// Pre-build the container image for a template (so create is fast later).
    Build {
        /// Template kind.
        #[arg(long, value_parser = parse_distro_kind)]
        kind: DistroKind,
        /// Override the template's default base tag (e.g. `24.04` for ubuntu).
        #[arg(long)]
        base_tag: Option<String>,
        /// Comma-separated list of additional packages to install (repeatable).
        #[arg(long = "include", value_delimiter = ',')]
        include: Vec<String>,
    },
    /// Suggest a shell command to enter an existing instance.
    Enter { name: String },
    /// Remove a distro instance. The persistent home volume is removed unless `--keep-volume`.
    Remove {
        /// Preserve the home volume so a future `create` can re-attach to it.
        #[arg(long = "keep-volume")]
        keep_volume: bool,
        name: String,
    },
}

#[derive(Subcommand, Debug)]
enum PassthroughCmd {
    /// Toggle desktop / device passthrough flags on a sandbox profile.
    Grant {
        #[arg(long)]
        wayland: bool,
        #[arg(long)]
        x11: bool,
        #[arg(long, value_parser = parse_audio_mode)]
        audio: Option<AudioMode>,
        #[arg(long)]
        gpu: bool,
        #[arg(long = "dbus")]
        dbus: bool,
        #[arg(long)]
        clipboard: bool,
        #[arg(long = "hidpi")]
        hidpi: bool,
        /// If set, generates `~/.local/share/applications/linpodx-<value>.desktop` on first run.
        #[arg(long = "register-app-menu")]
        register_app_menu: Option<String>,
        /// Sandbox profile name to mutate.
        profile: String,
    },
    /// Clear all passthrough fields on a profile (sets passthrough back to default).
    Revoke {
        /// Sandbox profile name.
        profile: String,
    },
    /// Show the current passthrough field values for a profile.
    Status {
        /// Sandbox profile name.
        profile: String,
    },
}

#[derive(Subcommand, Debug)]
enum PluginCmd {
    /// List installed plugins.
    List,
    /// Install a plugin from a directory containing `linpodx-plugin.toml` + the wasm binary.
    Install {
        /// Path to the plugin directory (or to the manifest file inside it).
        path: PathBuf,
        /// Optional path to a detached ed25519 signature (base64 of raw 64 bytes) over
        /// the wasm binary. If omitted, the daemon falls back to a `signature.b64`
        /// next to the manifest, then to `manifest.signature_b64`. Phase 15.
        #[arg(long, value_name = "PATH")]
        signature: Option<PathBuf>,
        /// Optional path to the ed25519 public key PEM used to verify the signature.
        /// If omitted, the daemon looks the key up in its trusted-keys registry by
        /// `manifest.publisher`. Phase 15.
        #[arg(long = "public-key", value_name = "PATH")]
        public_key: Option<PathBuf>,
    },
    /// Mark a plugin as enabled. Enabled plugins run during approval evaluation.
    Enable { name: String },
    /// Mark a plugin as disabled (left installed on disk).
    Disable { name: String },
    /// Remove a plugin row from the registry. With `--force`, also delete the on-disk
    /// plugin directory under the user's plugin root.
    Remove {
        #[arg(short = 'f', long)]
        force: bool,
        name: String,
    },
    /// Manage publisher signing keys in the trusted-keys registry (Phase 16).
    #[command(subcommand)]
    Key(PluginKeyCmd),
}

#[derive(Subcommand, Debug)]
enum PluginKeyCmd {
    /// List every publisher key the daemon's trusted-keys registry knows about,
    /// including any that have been revoked. Prints publisher, fingerprint
    /// (sha256 of pem bytes), status, and revocation metadata.
    List,
    /// Revoke a publisher key. Future plugin installs whose manifest names this
    /// publisher will be rejected (the .pem stays on disk so audit / forensic
    /// tooling can still inspect it).
    Revoke {
        /// Publisher name as it appears in `linpodx-plugin.toml`.
        publisher: String,
        /// Free-form reason recorded in the audit row + on-disk marker.
        #[arg(long, default_value = "operator-revoked")]
        reason: String,
        /// Phase 17 Stream C — propagate the revocation through the Raft log
        /// instead of (or in addition to) updating only the local node. The
        /// daemon must be the current Raft leader, otherwise the call fails
        /// with a "not_leader" error naming the actual leader. Followers
        /// pick up the change via the state-machine apply path.
        ///
        /// When this flag is set the local-only revoke path is skipped — the
        /// follower-side apply hook handles every node uniformly.
        #[arg(long)]
        cluster_wide: bool,
        /// Phase 17 Stream C — fingerprint of the publisher's PEM. Required
        /// when `--cluster-wide` is set; followers use it to identify the key
        /// even if they have not loaded the publisher's .pem file yet.
        /// Recommended value: take the `fingerprint` column of
        /// `linpodx plugin key list`.
        #[arg(long, value_name = "HEX")]
        fingerprint: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum K8sCmd {
    /// Pod operations.
    #[command(subcommand)]
    Pod(K8sPodCmd),
    /// Namespace operations.
    #[command(subcommand)]
    Ns(K8sNsCmd),
    /// Scale a deployment to N replicas.
    Scale {
        /// Deployment name.
        deployment: String,
        /// Namespace. Defaults to `default`.
        #[arg(short = 'n', long, default_value = "default")]
        namespace: String,
        /// New replica count.
        #[arg(long)]
        replicas: i32,
    },
}

#[derive(Subcommand, Debug)]
enum K8sPodCmd {
    /// Submit a pod manifest YAML to the cluster.
    Create {
        /// Path to a pod-spec YAML file (use `-` to read from stdin).
        yaml: PathBuf,
        /// Namespace. Defaults to `default`.
        #[arg(short = 'n', long, default_value = "default")]
        namespace: String,
    },
    /// Delete a pod by name.
    Delete {
        /// Pod name.
        name: String,
        /// Namespace. Defaults to `default`.
        #[arg(short = 'n', long, default_value = "default")]
        namespace: String,
    },
}

#[derive(Subcommand, Debug)]
enum K8sNsCmd {
    /// Create a namespace.
    Create {
        /// Namespace name.
        name: String,
    },
}

#[derive(Subcommand, Debug)]
enum ClusterCmd {
    /// Print the current Raft leader's node label (or `none` if no leader is
    /// known yet).
    Leader,
    /// Print this node's current Raft role (leader / follower / candidate /
    /// learner / unknown) plus the node label and any visible leader.
    Role,
    /// Print the cluster Raft membership table (voters + learners + term).
    /// Phase 15 — only meaningful when the daemon was started with
    /// `--cluster-raft`.
    Status,
    /// Promote a previously-added learner to a voter. The argument is the
    /// gossip node label / friendly id (the daemon hashes it the same way as
    /// `linpodx_cluster::node_id_from_string`). Phase 15.
    Promote {
        /// String node id (gossip label) of the learner to promote.
        node_id: String,
    },
    /// Phase 16 Stream A — replicated state machine queries. Requires the
    /// daemon to have been started with `--cluster-raft`.
    #[command(subcommand)]
    State(ClusterStateCmd),
}

#[derive(Debug, clap::Subcommand)]
enum ClusterStateCmd {
    /// Print the replicated container state machine (last_applied + entries).
    Get,
    /// Propose a synthetic container summary into the replicated state
    /// machine. Useful for end-to-end / integration testing without driving
    /// a real podman lifecycle.
    Propose {
        /// Source node label (the `node_id` field of the resulting entry).
        #[arg(long)]
        node_id: String,
        /// Container id to propose. A minimal `ContainerSummary` is built
        /// around it on the client side.
        #[arg(long)]
        container_id: String,
        /// Optional image tag to embed in the proposed summary.
        #[arg(long, default_value = "linpodx-test:latest")]
        image: String,
    },
}

fn parse_kv(raw: &str) -> std::result::Result<(String, String), String> {
    raw.split_once('=')
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .ok_or_else(|| format!("expected KEY=VALUE, got '{raw}'"))
}

fn parse_port_mapping(raw: &str) -> std::result::Result<PortMapping, String> {
    PortMapping::parse(raw)
}

fn parse_volume_mount(raw: &str) -> std::result::Result<VolumeMount, String> {
    VolumeMount::parse(raw)
}

fn parse_distro_kind(raw: &str) -> std::result::Result<DistroKind, String> {
    DistroKind::parse(raw)
}

fn parse_audio_mode(raw: &str) -> std::result::Result<AudioMode, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "none" | "off" => Ok(AudioMode::None),
        "pipewire" | "pipe_wire" | "pw" => Ok(AudioMode::PipeWire),
        "pulse" | "pulseaudio" | "pa" => Ok(AudioMode::Pulse),
        other => Err(format!(
            "unknown audio mode '{other}' (expected: none | pipewire | pulse)"
        )),
    }
}

fn parse_mcp_decision(raw: &str) -> std::result::Result<McpPolicyDecision, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "auto_allow" | "auto-allow" | "allow" => Ok(McpPolicyDecision::AutoAllow),
        "prompt" | "ask" => Ok(McpPolicyDecision::Prompt),
        "deny" => Ok(McpPolicyDecision::Deny),
        "audit_only" | "audit-only" | "audit" => Ok(McpPolicyDecision::AuditOnly),
        other => Err(format!(
            "unknown decision '{other}' (expected: auto_allow | prompt | deny | audit_only)"
        )),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing();

    // Phase 10: cert generation is a local-only helper — no daemon connection needed.
    // Handle it before opening a socket / WS so the user doesn't need a running daemon
    // to bootstrap their cert bundle.
    if let Cmd::Daemon(DaemonCmd::Cert(CertCmd::Generate { out })) = &cli.cmd {
        return handle_cert_generate(out.clone()).await;
    }

    let mut client = match cli.remote.clone() {
        Some(addr) => {
            let token = cli
                .token
                .clone()
                .ok_or_else(|| anyhow!("--remote requires --token (or LINPODX_REMOTE_TOKEN)"))?;
            let tls = crate::client::TlsClientConfig {
                ca: cli.ca.clone(),
                client_cert: cli.client_cert.clone(),
                client_key: cli.client_key.clone(),
            };
            Client::connect_remote(&addr, &token, tls).await?
        }
        None => {
            let socket = cli.socket.clone().unwrap_or_else(default_socket_path);
            Client::connect(&socket).await?
        }
    };

    match cli.cmd {
        Cmd::Ps { all } => {
            let containers: Vec<ContainerSummary> = client
                .call(Method::ContainerList(ContainerListParams { all }))
                .await?;
            print_container_list(&containers, cli.output)?;
        }
        Cmd::Run {
            name,
            rm,
            detach,
            env,
            labels,
            publish,
            volume,
            network,
            sandbox,
            image,
            command,
        } => {
            let opts = CreateOptions {
                image,
                name,
                command,
                env,
                labels,
                rm,
                detach,
                port_mappings: publish,
                volumes: volume,
                networks: network,
                sandbox_profile: sandbox,
                ..Default::default()
            };
            let id: ContainerId = client.call(Method::ContainerCreate(opts)).await?;
            client
                .call::<serde_json::Value>(Method::ContainerStart(ContainerIdParams {
                    id: id.clone(),
                }))
                .await?;
            println!("{}", id);
        }
        Cmd::Start { id } => {
            let id = ContainerId::from(id);
            let _: serde_json::Value = client
                .call(Method::ContainerStart(ContainerIdParams { id: id.clone() }))
                .await?;
            println!("{}", id);
        }
        Cmd::Stop { time, id } => {
            let id = ContainerId::from(id);
            let _: serde_json::Value = client
                .call(Method::ContainerStop(ContainerStopParams {
                    id: id.clone(),
                    timeout_secs: time,
                }))
                .await?;
            println!("{}", id);
        }
        Cmd::Rm { force, id } => {
            let id = ContainerId::from(id);
            let _: serde_json::Value = client
                .call(Method::ContainerRemove(ContainerRemoveParams {
                    id: id.clone(),
                    force,
                }))
                .await?;
            println!("{}", id);
        }
        Cmd::Inspect { id } => {
            let id = ContainerId::from(id);
            let inspect: ContainerInspect = client
                .call(Method::ContainerInspect(ContainerIdParams { id }))
                .await?;
            print_inspect(&inspect, cli.output)?;
        }
        Cmd::Logs { since, follow, id } => {
            if follow {
                handle_logs_follow(&mut client, id, since).await?;
            } else {
                let id_typed = ContainerId::from(id);
                let logs: responses::LogsResponse = client
                    .call(Method::ContainerLogs(ContainerLogsParams {
                        id: id_typed,
                        since,
                    }))
                    .await?;
                print_logs(&logs)?;
            }
        }
        Cmd::Exec {
            env,
            tty,
            interactive,
            id,
            command,
        } => {
            if interactive && tty {
                handle_exec_pty(
                    &mut client,
                    id,
                    command,
                    env,
                    cli.remote.as_deref(),
                    cli.token.as_deref(),
                    cli.ca.as_ref(),
                    cli.client_cert.as_ref(),
                    cli.client_key.as_ref(),
                )
                .await?;
            } else {
                handle_exec(&mut client, id, command, env, tty).await?;
            }
        }
        Cmd::Version => {
            let v: responses::VersionResponse = client.call(Method::Version).await?;
            print_version_response(&v, cli.output)?;
        }
        Cmd::Images(cmd) => handle_images(&mut client, cli.output, cmd).await?,
        Cmd::Volume(cmd) => handle_volume(&mut client, cli.output, cmd).await?,
        Cmd::Network(cmd) => handle_network(&mut client, cli.output, cmd).await?,
        Cmd::Sandbox(cmd) => handle_sandbox(&mut client, cli.output, cmd).await?,
        Cmd::Snapshot(cmd) => handle_snapshot(&mut client, cli.output, cmd).await?,
        Cmd::Session(cmd) => handle_session(&mut client, cli.output, cmd).await?,
        Cmd::Mcp(cmd) => handle_mcp(&mut client, cli.output, cmd).await?,
        Cmd::Distro(cmd) => handle_distro(&mut client, cli.output, cmd).await?,
        Cmd::Passthrough(cmd) => {
            handle_passthrough(&mut client, cli.output, cli.profiles_dir.clone(), cmd).await?
        }
        Cmd::Plugin(cmd) => handle_plugin(&mut client, cli.output, cmd).await?,
        Cmd::K8s(cmd) => handle_k8s(&mut client, cli.output, cmd).await?,
        Cmd::Cluster(cmd) => handle_cluster(&mut client, cli.output, cmd).await?,
        Cmd::Events { topics, json } => handle_events(&mut client, topics, json).await?,
        Cmd::Approvals { json } => handle_approvals(&mut client, json).await?,
        Cmd::Daemon(DaemonCmd::Cert(_)) => {
            // Unreachable — handled by the `handle_cert_generate` fast path above.
            unreachable!("Daemon::Cert handled before client setup");
        }
        Cmd::Daemon(DaemonCmd::PinClient(cmd)) => {
            handle_pin_client(&mut client, cli.output, cmd).await?;
        }
    }

    Ok(())
}

/// Phase 10: generate a self-signed CA + server-leaf + client-leaf bundle into
/// `out` (default `${XDG_CONFIG_HOME:-~/.config}/linpodx/certs`). Layout:
///   ca.pem            (CA cert)
///   ca-key.pem        (CA private key — keep offline once issuance is done)
///   server-cert.pem   (server leaf, SAN: localhost, 127.0.0.1)
///   server-key.pem
///   client-cert.pem   (client leaf, CN: linpodx-client)
///   client-key.pem
async fn handle_cert_generate(out: Option<PathBuf>) -> Result<()> {
    use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};

    let dir = match out {
        Some(p) => p,
        None => default_cert_dir()?,
    };

    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating cert dir {}", dir.display()))?;
    set_dir_mode_0700(&dir)?;

    // CA — long-lived issuer the daemon's `--client-ca` and the CLI's `--ca` both
    // trust. Generated locally so a fresh user can bootstrap without external
    // tooling. Validity: ~10 years to match typical homelab cadence.
    let mut ca_params =
        CertificateParams::new(Vec::<String>::new()).context("CA cert params init")?;
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "linpodx-ca");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    apply_validity(&mut ca_params, 365 * 10);
    let ca_key = KeyPair::generate().context("CA keypair")?;
    let ca_cert = ca_params.self_signed(&ca_key).context("CA self-sign")?;

    // Server leaf — covers `localhost` + the loopback IP so the most common
    // `--remote-listen 127.0.0.1:<port>` setup works out of the box.
    let mut server_params =
        CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .context("server cert params init")?;
    server_params.distinguished_name = DistinguishedName::new();
    server_params
        .distinguished_name
        .push(DnType::CommonName, "linpodx-daemon");
    apply_validity(&mut server_params, 365);
    let server_key = KeyPair::generate().context("server keypair")?;
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .context("server signed_by ca")?;

    // Client leaf — CN is just an identity tag the daemon's `remote_mtls_accepted`
    // audit entry surfaces.
    let mut client_params = CertificateParams::new(vec!["linpodx-client".to_string()])
        .context("client cert params init")?;
    client_params.distinguished_name = DistinguishedName::new();
    client_params
        .distinguished_name
        .push(DnType::CommonName, "linpodx-client");
    apply_validity(&mut client_params, 365);
    let client_key = KeyPair::generate().context("client keypair")?;
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .context("client signed_by ca")?;

    let ca_pem = dir.join("ca.pem");
    let ca_key_pem = dir.join("ca-key.pem");
    let server_cert_pem = dir.join("server-cert.pem");
    let server_key_pem = dir.join("server-key.pem");
    let client_cert_pem = dir.join("client-cert.pem");
    let client_key_pem = dir.join("client-key.pem");

    write_cert(&ca_pem, &ca_cert.pem())?;
    write_key(&ca_key_pem, &ca_key.serialize_pem())?;
    write_cert(&server_cert_pem, &server_cert.pem())?;
    write_key(&server_key_pem, &server_key.serialize_pem())?;
    write_cert(&client_cert_pem, &client_cert.pem())?;
    write_key(&client_key_pem, &client_key.serialize_pem())?;

    println!("wrote certs to {}", dir.display());
    println!("  CA          : {}", ca_pem.display());
    println!(
        "  CA key      : {} (mode 0600 — keep offline once done)",
        ca_key_pem.display()
    );
    println!("  server cert : {}", server_cert_pem.display());
    println!("  server key  : {} (mode 0600)", server_key_pem.display());
    println!("  client cert : {}", client_cert_pem.display());
    println!("  client key  : {} (mode 0600)", client_key_pem.display());
    println!();
    println!(
        "daemon: --remote-cert {} --remote-key {} --client-ca {}",
        server_cert_pem.display(),
        server_key_pem.display(),
        ca_pem.display()
    );
    println!(
        "client: --client-cert {} --client-key {} --ca {}",
        client_cert_pem.display(),
        client_key_pem.display(),
        ca_pem.display()
    );
    Ok(())
}

fn default_cert_dir() -> Result<PathBuf> {
    let base = if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        PathBuf::from(xdg)
    } else {
        let home = std::env::var("HOME").context("$HOME unset and --out not given")?;
        PathBuf::from(home).join(".config")
    };
    Ok(base.join("linpodx").join("certs"))
}

/// clap value parser: accept a path only when it exists and is a directory.
/// Used for `--cert-dir` on `image push` so that operators get a clean parse-time
/// error instead of a podman error mid-push.
fn parse_existing_dir(s: &str) -> std::result::Result<PathBuf, String> {
    let p = PathBuf::from(s);
    if !p.exists() {
        return Err(format!("path does not exist: {s}"));
    }
    if !p.is_dir() {
        return Err(format!("path is not a directory: {s}"));
    }
    Ok(p)
}

fn apply_validity(params: &mut rcgen::CertificateParams, days: i64) {
    use chrono::{Datelike, Duration, Utc};
    let now = Utc::now();
    let then = now + Duration::days(days);
    params.not_before = rcgen::date_time_ymd(now.year(), now.month() as u8, now.day() as u8);
    params.not_after = rcgen::date_time_ymd(then.year(), then.month() as u8, then.day() as u8);
}

fn write_cert(path: &Path, pem: &str) -> Result<()> {
    std::fs::write(path, pem).with_context(|| format!("writing cert {}", path.display()))?;
    Ok(())
}

fn write_key(path: &Path, pem: &str) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("opening key file {}", path.display()))?;
    use std::io::Write;
    f.write_all(pem.as_bytes())
        .with_context(|| format!("writing key {}", path.display()))?;
    Ok(())
}

fn set_dir_mode_0700(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .permissions();
    perms.set_mode(0o700);
    std::fs::set_permissions(path, perms).with_context(|| format!("chmod {}", path.display()))?;
    Ok(())
}

async fn handle_approvals(client: &mut Client, json: bool) -> Result<()> {
    use linpodx_common::ipc::responses::SubscribeResponse;
    let _ack: SubscribeResponse = client
        .call(Method::Subscribe(SubscribeParams {
            topics: EventTopic::ALL.to_vec(),
        }))
        .await?;
    eprintln!("listening for approval requests — press Ctrl+C to stop");

    loop {
        let msg = match client.next_server_message().await? {
            Some(m) => m,
            None => {
                eprintln!("daemon closed the connection");
                return Ok(());
            }
        };
        let req = match msg {
            ServerMessage::Notification(Notification { method, params, .. })
                if method == "approval_request" =>
            {
                match serde_json::from_value::<ApprovalRequest>(params) {
                    Ok(req) => req,
                    Err(e) => {
                        eprintln!("malformed approval request: {e}");
                        continue;
                    }
                }
            }
            _ => continue,
        };

        if json {
            println!("{}", serde_json::to_string(&req)?);
            continue;
        }

        let payload = serde_json::to_string(&req.payload).unwrap_or_default();
        eprint!(
            "[approval] profile={} category={} payload={} (y/n, timeout {}s): ",
            req.profile_name, req.category, payload, req.timeout_secs
        );

        let allow = read_yes_no_with_timeout(std::time::Duration::from_secs(
            req.timeout_secs.saturating_sub(2).max(1),
        ))
        .await;
        let resp = client
            .call::<linpodx_common::ipc::responses::ApprovalDecisionResponse>(
                Method::ApprovalDecision(ApprovalDecisionParams {
                    request_id: req.request_id.clone(),
                    allow,
                    by: Some(format!("cli-{}", whoami())),
                    reason: None,
                }),
            )
            .await;
        match resp {
            Ok(r) if r.accepted => {
                eprintln!("→ {} (sent)", if allow { "allow" } else { "deny" });
            }
            Ok(_) => {
                eprintln!(
                    "→ daemon already resolved request {} — too late",
                    req.request_id
                );
            }
            Err(e) => eprintln!("→ failed to send decision: {e}"),
        }
    }
}

async fn read_yes_no_with_timeout(timeout: std::time::Duration) -> bool {
    let read = tokio::task::spawn_blocking(|| {
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok();
        let answer = input.trim().to_ascii_lowercase();
        matches!(answer.as_str(), "y" | "yes")
    });
    match tokio::time::timeout(timeout, read).await {
        Ok(Ok(b)) => b,
        Ok(Err(_)) => false,
        Err(_) => {
            eprintln!("(no input — defaulting to deny)");
            false
        }
    }
}

fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "user".to_string())
}

async fn handle_sandbox(client: &mut Client, fmt: OutputFormat, cmd: SandboxCmd) -> Result<()> {
    use linpodx_common::ipc::responses::{
        AuditLogQueryResponse, AuditVerifyResponse, SandboxProfileGetResponse,
        SandboxProfileListResponse, SandboxProfileReloadResponse,
    };

    match cmd {
        SandboxCmd::List => {
            let profiles: SandboxProfileListResponse =
                client.call(Method::SandboxProfileList).await?;
            print_sandbox_profile_list(&profiles, fmt)?;
        }
        SandboxCmd::Show { name } => {
            let resp: SandboxProfileGetResponse = client
                .call(Method::SandboxProfileGet(SandboxProfileNameParams { name }))
                .await?;
            println!(
                "# {}  (yaml_hash={}, last_updated={})",
                resp.name, resp.yaml_hash, resp.last_updated
            );
            print!("{}", resp.yaml);
        }
        SandboxCmd::Reload => {
            let resp: SandboxProfileReloadResponse =
                client.call(Method::SandboxProfileReload).await?;
            println!("Loaded {} profile(s):", resp.loaded);
            for n in resp.names {
                println!("  {n}");
            }
        }
        SandboxCmd::Apply {
            profile,
            name,
            rm,
            image,
            command,
        } => {
            let opts = CreateOptions {
                image,
                name,
                command,
                rm,
                detach: true,
                sandbox_profile: Some(profile),
                ..Default::default()
            };
            let id: linpodx_common::types::ContainerId =
                client.call(Method::ContainerCreate(opts)).await?;
            client
                .call::<serde_json::Value>(Method::ContainerStart(ContainerIdParams {
                    id: id.clone(),
                }))
                .await?;
            println!("{id}");
        }
        SandboxCmd::Audit {
            profile,
            kind,
            limit,
            json,
        } => {
            let entries: AuditLogQueryResponse = client
                .call(Method::AuditLogQuery(AuditQueryParams {
                    profile_name: profile,
                    kind,
                    since: None,
                    until: None,
                    limit: Some(limit),
                }))
                .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else {
                print_audit_table(&entries)?;
            }
        }
        SandboxCmd::Verify { since_seq } => {
            let report: AuditVerifyResponse = client
                .call(Method::AuditLogVerify(AuditVerifyParams { since_seq }))
                .await?;
            match report.broken_at {
                Some(seq) => {
                    println!(
                        "TAMPER DETECTED: chain breaks at seq {} (verified {} entries up to seq {:?})",
                        seq, report.total, report.last_seq
                    );
                    std::process::exit(2);
                }
                None => {
                    println!(
                        "OK: verified {} entries (last seq {:?})",
                        report.total, report.last_seq
                    );
                }
            }
        }
        SandboxCmd::Profile { cmd } => match cmd {
            SandboxProfileCmd::Compile {
                name,
                secprofile_out,
            } => {
                handle_sandbox_profile_compile(client, name, secprofile_out, fmt).await?;
            }
        },
    }
    Ok(())
}

async fn handle_sandbox_profile_compile(
    client: &mut Client,
    name: String,
    secprofile_out: Option<PathBuf>,
    fmt: OutputFormat,
) -> Result<()> {
    use linpodx_common::audit_sink::NoopAuditSink;
    use linpodx_common::ipc::responses::SandboxProfileGetResponse;
    use linpodx_sandbox::SecProfileCompiler;
    use std::sync::Arc;

    let resp: SandboxProfileGetResponse = client
        .call(Method::SandboxProfileGet(SandboxProfileNameParams {
            name: name.clone(),
        }))
        .await?;
    let profile: linpodx_sandbox::SandboxProfile = serde_yml::from_str(&resp.yaml)
        .map_err(|e| anyhow::anyhow!("parse profile YAML for '{}': {e}", resp.name))?;

    let cache_dir = match secprofile_out {
        Some(p) => p,
        None => default_secprofile_cache_dir()?,
    };
    let compiler = SecProfileCompiler::new(cache_dir.clone(), Arc::new(NoopAuditSink));
    let compiled = compiler
        .compile(&profile)
        .await
        .map_err(|e| anyhow::anyhow!("secprofile compile failed: {e}"))?;
    print_compile_result(&resp.name, &cache_dir, &compiled, fmt)?;
    Ok(())
}

fn default_secprofile_cache_dir() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|h| {
                let mut p = PathBuf::from(h);
                p.push(".cache");
                p
            })
        })
        .ok_or_else(|| anyhow::anyhow!("neither XDG_CACHE_HOME nor HOME is set"))?;
    let mut p = base;
    p.push("linpodx");
    p.push("secprofiles");
    Ok(p)
}

async fn handle_events(client: &mut Client, topics: Vec<EventTopic>, json: bool) -> Result<()> {
    use linpodx_common::ipc::responses::SubscribeResponse;

    let _ack: SubscribeResponse = client
        .call(Method::Subscribe(SubscribeParams {
            topics: topics.clone(),
        }))
        .await?;

    let topics_human = if topics.is_empty() {
        "all".to_string()
    } else {
        topics
            .iter()
            .map(|t| t.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    eprintln!("subscribed to events ({topics_human}) — press Ctrl+C to stop");

    while let Some(event) = client.next_event().await? {
        if json {
            println!("{}", serde_json::to_string(&event)?);
        } else {
            let ts = event.timestamp.format("%H:%M:%S");
            let id_short = if event.resource_id.len() > 12 {
                &event.resource_id[..12]
            } else {
                &event.resource_id
            };
            let details = if event.details.is_null() {
                String::new()
            } else {
                format!(
                    " details={}",
                    serde_json::to_string(&event.details).unwrap_or_default()
                )
            };
            println!(
                "[{ts}] {}.{} id={id_short}{details}",
                event.topic, event.kind
            );
        }
    }
    eprintln!("daemon closed the event stream");
    Ok(())
}

/// Phase 11 — `linpodx exec <id> -- <cmd...>`. One-shot non-interactive command.
async fn handle_exec(
    client: &mut Client,
    container_id: String,
    command: Vec<String>,
    env: Vec<(String, String)>,
    tty: bool,
) -> Result<()> {
    let resp: responses::ContainerExecResponse = client
        .call(Method::ContainerExec(ContainerExecParams {
            container_id,
            command,
            interactive: false,
            tty,
            env,
        }))
        .await?;
    if !resp.stdout.is_empty() {
        print!("{}", resp.stdout);
        if !resp.stdout.ends_with('\n') {
            println!();
        }
    }
    if !resp.stderr.is_empty() {
        eprint!("{}", resp.stderr);
        if !resp.stderr.ends_with('\n') {
            eprintln!();
        }
    }
    if resp.exit_code != 0 {
        std::process::exit(resp.exit_code);
    }
    Ok(())
}

/// Phase 12 — `linpodx exec -it <id> -- <cmd...>`. Allocates a PTY on the daemon
/// side and proxies stdin/stdout over a WebSocket binary stream.
///
/// Requires the user to be talking to a remote daemon (`--remote <addr> --token <t>`)
/// because the PTY endpoint is served only by the WebSocket listener — the local
/// Unix socket transport has no place to upgrade. We surface that constraint as a
/// clear error rather than silently failing.
#[allow(clippy::too_many_arguments)]
async fn handle_exec_pty(
    client: &mut Client,
    container_id: String,
    command: Vec<String>,
    env: Vec<(String, String)>,
    remote: Option<&str>,
    token: Option<&str>,
    ca: Option<&PathBuf>,
    client_cert: Option<&PathBuf>,
    client_key: Option<&PathBuf>,
) -> Result<()> {
    use crossterm::terminal;

    let remote = remote.ok_or_else(|| {
        anyhow!(
            "interactive `exec -it` requires a remote daemon — pass --remote <addr> --token <t>.\n\
             The /pty/<bridge_id> endpoint is only served by the WebSocket listener, not the\n\
             local Unix socket. Start the daemon with `--remote-listen 127.0.0.1:8443 \\\n\
             --remote-token <t>` to attach to a local PTY."
        )
    })?;
    let token = token.ok_or_else(|| anyhow!("--remote requires --token"))?;

    // Detect terminal size for the initial PTY hint. Falls back to 80x24 if stdin
    // isn't a tty (test harness, piped input, etc).
    let (cols, rows) = terminal::size().unwrap_or((80, 24));

    // Step 1: allocate the PTY bridge on the daemon side.
    let resp: responses::ContainerExecPtyResponse = client
        .call(Method::ContainerExecPty(ContainerExecPtyParams {
            container_id: container_id.clone(),
            command,
            env,
            cols: Some(cols),
            rows: Some(rows),
        }))
        .await?;

    // Step 2: open a separate WebSocket to /pty/<bridge_id>?token=<t>. Re-use the
    // CLI's TLS config (--ca / --client-cert / --client-key) for `wss://` daemons.
    let pty_url = client::build_pty_ws_url(remote, &resp.bridge_id, token);
    let tls_cfg = client::TlsClientConfig {
        ca: ca.cloned(),
        client_cert: client_cert.cloned(),
        client_key: client_key.cloned(),
    };
    let mut pty_ws = client::PtyWsClient::connect(&pty_url, tls_cfg, Some(token)).await?;

    // Step 3: enter raw mode (single-char input, no echo) and install a panic hook
    // that disables raw mode so a panic doesn't leave the user's terminal wedged.
    terminal::enable_raw_mode().context("entering raw mode")?;
    let _raw_guard = RawModeGuard::new();

    // Step 4: bidirectional proxy. Two tasks share the WebSocket via a split.
    let result = pty_ws.proxy_stdio().await;

    // Drop guard restores raw mode. Any error from the proxy bubbles up here.
    drop(_raw_guard);
    result
}

/// Restores cooked mode on drop. Used by the PTY exec path so a panic, an early
/// `?`-return, or the WebSocket closing all leave the user's terminal usable.
struct RawModeGuard;

impl RawModeGuard {
    fn new() -> Self {
        Self
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

/// Phase 11 — `linpodx logs <id> --follow`. Subscribes to Container topic and prints
/// only `EventKind::Log` notifications whose `resource_id` matches the container.
async fn handle_logs_follow(
    client: &mut Client,
    container_id: String,
    since: Option<String>,
) -> Result<()> {
    use linpodx_common::ipc::responses::{ContainerLogsStreamResponse, SubscribeResponse};

    let _sub_ack: SubscribeResponse = client
        .call(Method::Subscribe(SubscribeParams {
            topics: vec![EventTopic::Container],
        }))
        .await?;
    let ack: ContainerLogsStreamResponse = client
        .call(Method::ContainerLogsStream(ContainerLogsStreamParams {
            container_id: container_id.clone(),
            follow: true,
            since,
        }))
        .await?;
    if !ack.started {
        bail!("daemon refused to start log stream for {}", container_id);
    }
    eprintln!("streaming logs for {} — press Ctrl+C to stop", container_id);
    while let Some(event) = client.next_event().await? {
        if event.topic != EventTopic::Container || event.kind != EventKind::Log {
            continue;
        }
        if event.resource_id != container_id {
            continue;
        }
        let stream = event
            .details
            .get("stream")
            .and_then(|s| s.as_str())
            .unwrap_or("stdout");
        let line = event
            .details
            .get("line")
            .and_then(|s| s.as_str())
            .unwrap_or_default();
        if stream == "stderr" {
            eprintln!("{line}");
        } else {
            println!("{line}");
        }
    }
    eprintln!("daemon closed the event stream");
    Ok(())
}

/// Phase 11 — `linpodx images pull --progress <ref>`. Subscribes to Image topic and
/// prints `EventKind::Progress` lines until the daemon reports `Succeeded` or `Failed`.
async fn handle_image_pull_progress(client: &mut Client, reference: String) -> Result<()> {
    use linpodx_common::ipc::responses::{ImagePullJobResponse, SubscribeResponse};

    let _sub_ack: SubscribeResponse = client
        .call(Method::Subscribe(SubscribeParams {
            topics: vec![EventTopic::Image],
        }))
        .await?;
    let job: ImagePullJobResponse = client
        .call(Method::ImagePullJob(ImagePullJobParams {
            reference: reference.clone(),
        }))
        .await?;
    eprintln!("pull job {} started for {}", job.job_id, reference);
    while let Some(event) = client.next_event().await? {
        if event.topic != EventTopic::Image || event.resource_id != job.job_id {
            continue;
        }
        match event.kind {
            EventKind::Progress => {
                let msg = event
                    .details
                    .get("message")
                    .and_then(|s| s.as_str())
                    .unwrap_or_default();
                println!("{msg}");
            }
            EventKind::Succeeded => {
                eprintln!("pull job {} succeeded", job.job_id);
                return Ok(());
            }
            EventKind::Failed => {
                eprintln!("pull job {} failed", job.job_id);
                std::process::exit(1);
            }
            _ => {}
        }
    }
    eprintln!("daemon closed the event stream before pull job terminated");
    Ok(())
}

async fn handle_images(client: &mut Client, fmt: OutputFormat, cmd: ImagesCmd) -> Result<()> {
    match cmd {
        ImagesCmd::Ls { all, dangling } => {
            let images: Vec<ImageSummary> = client
                .call(Method::ImageList(ImageListParams {
                    all,
                    dangling: if dangling { Some(true) } else { None },
                }))
                .await?;
            print_image_list(&images, fmt)?;
        }
        ImagesCmd::Pull {
            progress,
            reference,
        } => {
            if progress {
                handle_image_pull_progress(client, reference).await?;
            } else {
                let id: ImageId = client
                    .call(Method::ImagePull(ImagePullParams { reference }))
                    .await?;
                println!("{id}");
            }
        }
        ImagesCmd::Rm { force, id } => {
            let id = ImageId::from(id);
            let _: serde_json::Value = client
                .call(Method::ImageRemove(ImageRemoveParams {
                    id: id.clone(),
                    force,
                }))
                .await?;
            println!("{id}");
        }
        ImagesCmd::Inspect { id } => {
            let id = ImageId::from(id);
            let inspect: ImageInspect = client
                .call(Method::ImageInspect(ImageIdParams { id }))
                .await?;
            print_inspect(&inspect, fmt)?;
        }
        ImagesCmd::Tag { source, target } => {
            let source = ImageId::from(source);
            let _: serde_json::Value = client
                .call(Method::ImageTag(ImageTagParams {
                    source: source.clone(),
                    target,
                }))
                .await?;
            println!("{source}");
        }
        ImagesCmd::Push {
            reference,
            registry,
            auth,
            cert_dir,
        } => {
            let resp: responses::ImagePushResponse = client
                .call(Method::ImagePush(ImagePushParams {
                    reference,
                    registry,
                    auth,
                    cert_dir,
                }))
                .await?;
            print_image_push(&resp, fmt)?;
        }
        ImagesCmd::Manifest { cmd } => match cmd {
            ManifestCmd::Create { target, refs } => {
                let resp: responses::ImageManifestCreateResponse = client
                    .call(Method::ImageManifestCreate(ImageManifestCreateParams {
                        target,
                        refs,
                    }))
                    .await?;
                print_image_manifest_create(&resp, fmt)?;
            }
            ManifestCmd::Add { target, reference } => {
                // Reuse manifest_create with a single ref — it's idempotent on
                // the target manifest, so this becomes a single `manifest add`.
                let resp: responses::ImageManifestCreateResponse = client
                    .call(Method::ImageManifestCreate(ImageManifestCreateParams {
                        target,
                        refs: vec![reference],
                    }))
                    .await?;
                print_image_manifest_create(&resp, fmt)?;
            }
            ManifestCmd::Push {
                manifest,
                registry,
                auth,
            } => {
                let resp: responses::ImageManifestPushResponse = client
                    .call(Method::ImageManifestPush(ImageManifestPushParams {
                        manifest,
                        registry,
                        auth,
                    }))
                    .await?;
                print_image_manifest_push(&resp, fmt)?;
            }
        },
    }
    Ok(())
}

async fn handle_volume(client: &mut Client, fmt: OutputFormat, cmd: VolumeCmd) -> Result<()> {
    match cmd {
        VolumeCmd::Ls => {
            let volumes: Vec<VolumeSummary> = client.call(Method::VolumeList).await?;
            print_volume_list(&volumes, fmt)?;
        }
        VolumeCmd::Create {
            driver,
            labels,
            opts,
            name,
        } => {
            let id: VolumeId = client
                .call(Method::VolumeCreate(VolumeCreateParams {
                    name,
                    driver,
                    labels,
                    options: opts,
                }))
                .await?;
            println!("{id}");
        }
        VolumeCmd::Rm { force, name } => {
            let name = VolumeId::from(name);
            let _: serde_json::Value = client
                .call(Method::VolumeRemove(VolumeRemoveParams {
                    name: name.clone(),
                    force,
                }))
                .await?;
            println!("{name}");
        }
        VolumeCmd::Inspect { name } => {
            let name = VolumeId::from(name);
            let inspect: VolumeInspect = client
                .call(Method::VolumeInspect(VolumeNameParams { name }))
                .await?;
            print_inspect(&inspect, fmt)?;
        }
        VolumeCmd::Prune => {
            let removed: Vec<VolumeId> = client.call(Method::VolumePrune).await?;
            print_prune_result(
                "volumes",
                &removed.iter().map(VolumeId::to_string).collect::<Vec<_>>(),
            )?;
        }
    }
    Ok(())
}

async fn handle_network(client: &mut Client, fmt: OutputFormat, cmd: NetworkCmd) -> Result<()> {
    match cmd {
        NetworkCmd::Ls => {
            let networks: Vec<NetworkSummary> = client.call(Method::NetworkList).await?;
            print_network_list(&networks, fmt)?;
        }
        NetworkCmd::Create {
            driver,
            subnet,
            gateway,
            internal,
            no_dns,
            labels,
            name,
        } => {
            let id: NetworkId = client
                .call(Method::NetworkCreate(NetworkCreateParams {
                    name,
                    driver,
                    subnet,
                    gateway,
                    internal,
                    dns_enabled: !no_dns,
                    labels,
                }))
                .await?;
            println!("{id}");
        }
        NetworkCmd::Rm { force, name } => {
            let name = NetworkId::from(name);
            let _: serde_json::Value = client
                .call(Method::NetworkRemove(NetworkRemoveParams {
                    name: name.clone(),
                    force,
                }))
                .await?;
            println!("{name}");
        }
        NetworkCmd::Inspect { name } => {
            let name = NetworkId::from(name);
            let inspect: NetworkInspect = client
                .call(Method::NetworkInspect(NetworkNameParams { name }))
                .await?;
            print_inspect(&inspect, fmt)?;
        }
        NetworkCmd::Prune => {
            let removed: Vec<NetworkId> = client.call(Method::NetworkPrune).await?;
            print_prune_result(
                "networks",
                &removed.iter().map(NetworkId::to_string).collect::<Vec<_>>(),
            )?;
        }
        NetworkCmd::Egress(NetworkEgressCmd::Set { domains, profile }) => {
            handle_network_egress_set(client, &profile, &domains).await?;
        }
        NetworkCmd::Egress(NetworkEgressCmd::Status { profile }) => {
            handle_network_egress_status(client, &profile).await?;
        }
    }
    Ok(())
}

async fn handle_snapshot(client: &mut Client, fmt: OutputFormat, cmd: SnapshotCmd) -> Result<()> {
    use linpodx_common::ipc::responses::{
        SnapshotBranchResponse, SnapshotCreateResponse, SnapshotDiffResponse,
        SnapshotJobCreateResponse, SnapshotJobStatusResponse, SnapshotListResponse,
        SnapshotPruneResponse, SnapshotRollbackResponse, SnapshotSummary,
    };
    match cmd {
        SnapshotCmd::Create { label, container } => {
            let resp: SnapshotCreateResponse = client
                .call(Method::SnapshotCreate(SnapshotCreateParams {
                    container_id: container,
                    label,
                }))
                .await?;
            println!("{}\t{}", resp.id, resp.image_ref);
        }
        SnapshotCmd::List { container } => {
            let snapshots: SnapshotListResponse = client
                .call(Method::SnapshotList(SnapshotListParams {
                    container_id: container,
                }))
                .await?;
            print_snapshot_list(&snapshots, fmt)?;
        }
        SnapshotCmd::Inspect { id } => {
            let summary: SnapshotSummary = client
                .call(Method::SnapshotInspect(SnapshotIdParams { id }))
                .await?;
            print_inspect(&summary, fmt)?;
        }
        SnapshotCmd::Rollback {
            new_name,
            keep_original,
            id,
        } => {
            let resp: SnapshotRollbackResponse = client
                .call(Method::SnapshotRollback(SnapshotRollbackParams {
                    id,
                    new_name,
                    keep_original,
                }))
                .await?;
            println!("{}\t{}", resp.new_container_id, resp.new_container_name);
        }
        SnapshotCmd::Rm { force, id } => {
            let _: serde_json::Value = client
                .call(Method::SnapshotRemove(SnapshotRemoveParams { id, force }))
                .await?;
            println!("{id}");
        }
        SnapshotCmd::Prune {
            container,
            keep_recent,
        } => {
            let resp: SnapshotPruneResponse = client
                .call(Method::SnapshotPrune(SnapshotPruneParams {
                    container_id: container,
                    keep_recent,
                }))
                .await?;
            if resp.removed.is_empty() {
                println!("No snapshots to prune.");
            } else {
                println!("Removed {} snapshot(s):", resp.removed.len());
                for id in resp.removed {
                    println!("  {id}");
                }
            }
        }
        SnapshotCmd::Job(SnapshotJobCmd::Start { label, container }) => {
            let resp: SnapshotJobCreateResponse = client
                .call(Method::SnapshotJobCreate(SnapshotJobCreateParams {
                    container_id: container,
                    label,
                }))
                .await?;
            println!("{}\t{}", resp.job_id, resp.status);
        }
        SnapshotCmd::Job(SnapshotJobCmd::Status { job_id }) => {
            let resp: SnapshotJobStatusResponse = client
                .call(Method::SnapshotJobStatus(SnapshotJobStatusParams {
                    job_id,
                }))
                .await?;
            print_snapshot_job_status(&resp, fmt)?;
        }
        SnapshotCmd::Diff { layers, id_a, id_b } => {
            if layers {
                use linpodx_common::ipc::responses::SnapshotDiffV2Response;
                let resp: SnapshotDiffV2Response = client
                    .call(Method::SnapshotDiffV2(SnapshotDiffV2Params { id_a, id_b }))
                    .await?;
                print_snapshot_diff_v2(&resp, fmt)?;
            } else {
                let resp: SnapshotDiffResponse = client
                    .call(Method::SnapshotDiff(SnapshotDiffParams { id_a, id_b }))
                    .await?;
                print_snapshot_diff(&resp, fmt)?;
            }
        }
        SnapshotCmd::BackendList => {
            use linpodx_common::ipc::responses::SnapshotBackendListResponse;
            let resp: SnapshotBackendListResponse =
                client.call(Method::SnapshotBackendList).await?;
            print_snapshot_backend_list(&resp, fmt)?;
        }
        SnapshotCmd::Branch {
            label,
            fork,
            parent_id,
        } => {
            let resp: SnapshotBranchResponse = client
                .call(Method::SnapshotBranch(SnapshotBranchParams {
                    parent_id,
                    label,
                    fork,
                }))
                .await?;
            println!("{}\t{}", resp.id, resp.image_ref);
        }
        SnapshotCmd::EncryptionStatus { id } => {
            use linpodx_common::ipc::responses::SnapshotEncryptionStatusResponse;
            let resp: SnapshotEncryptionStatusResponse = client
                .call(Method::SnapshotEncryptionStatus(SnapshotIdParams { id }))
                .await?;
            match fmt {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                }
                OutputFormat::Table => {
                    let dash = "-".to_string();
                    println!("snapshot_id      : {}", resp.snapshot_id);
                    println!("encrypted        : {}", resp.encrypted);
                    println!(
                        "algorithm        : {}",
                        resp.algorithm.as_ref().unwrap_or(&dash)
                    );
                    println!(
                        "key_source       : {}",
                        resp.key_source.as_ref().unwrap_or(&dash)
                    );
                    println!(
                        "ciphertext_sha256: {}",
                        resp.ciphertext_sha256.as_ref().unwrap_or(&dash)
                    );
                }
            }
        }
        SnapshotCmd::KeyRotate {
            id,
            new_passphrase,
            new_key,
        } => {
            use linpodx_common::ipc::responses::SnapshotKeyRotateResponse;
            let new_key_src = build_new_key_source(new_passphrase, new_key)?;
            let resp: SnapshotKeyRotateResponse = client
                .call(Method::SnapshotKeyRotate(SnapshotKeyRotateParams {
                    snapshot_id: id,
                    new_key: new_key_src,
                }))
                .await?;
            match fmt {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&resp)?),
                OutputFormat::Table => {
                    println!("snapshot_id      : {}", resp.snapshot_id);
                    println!("rotated          : {}", resp.rotated);
                    println!("algorithm        : {}", resp.algorithm);
                    println!("kdf              : {}", resp.kdf);
                    println!("ciphertext_sha256: {}", resp.ciphertext_sha256);
                }
            }
        }
        SnapshotCmd::ReEncryptAll {
            new_passphrase,
            new_key,
        } => {
            use linpodx_common::ipc::responses::SnapshotReEncryptAllResponse;
            let new_key_src = build_new_key_source(new_passphrase, new_key)?;
            let resp: SnapshotReEncryptAllResponse = client
                .call(Method::SnapshotReEncryptAll(SnapshotReEncryptAllParams {
                    new_key: new_key_src,
                }))
                .await?;
            match fmt {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&resp)?),
                OutputFormat::Table => {
                    println!("total_seen   : {}", resp.total_seen);
                    println!("re_encrypted : {}", resp.re_encrypted);
                    println!("skipped      : {}", resp.skipped);
                    println!("failed       : {}", resp.failed);
                }
            }
        }
    }
    Ok(())
}

/// Phase 17 Stream A — build a `SnapshotKeySource` from `--new-passphrase` /
/// `--new-key`. Exactly one must be supplied; clap's `conflicts_with`
/// guarantees mutual exclusion, this helper only rejects the empty case.
fn build_new_key_source(
    new_passphrase: Option<String>,
    new_key: Option<String>,
) -> Result<SnapshotKeySource> {
    match (new_passphrase, new_key) {
        (Some(p), None) => Ok(SnapshotKeySource::Passphrase { passphrase: p }),
        (None, Some(k)) => Ok(SnapshotKeySource::Explicit { key_b64: k }),
        (None, None) => Err(anyhow::anyhow!(
            "supply either --new-passphrase <p> or --new-key <base64>"
        )),
        (Some(_), Some(_)) => unreachable!("clap conflicts_with enforces mutual exclusion"),
    }
}

async fn handle_session(client: &mut Client, fmt: OutputFormat, cmd: SessionCmd) -> Result<()> {
    use linpodx_common::ipc::responses::{
        SessionListResponse, SessionSummary, SessionTimelineResponse,
    };
    match cmd {
        SessionCmd::List { container, limit } => {
            let sessions: SessionListResponse = client
                .call(Method::SessionList(SessionListParams {
                    container_id: container,
                    limit,
                }))
                .await?;
            print_session_list(&sessions, fmt)?;
        }
        SessionCmd::Inspect { id } => {
            let summary: SessionSummary = client
                .call(Method::SessionInspect(SessionIdParams { id }))
                .await?;
            print_inspect(&summary, fmt)?;
        }
        SessionCmd::Timeline { kinds, id } => {
            let entries: SessionTimelineResponse = client
                .call(Method::SessionTimeline(SessionTimelineParams { id, kinds }))
                .await?;
            print_session_timeline(&entries)?;
        }
    }
    Ok(())
}

async fn handle_mcp(client: &mut Client, fmt: OutputFormat, cmd: McpCmd) -> Result<()> {
    use linpodx_common::ipc::responses::{
        McpBridgeStartResponse, McpBridgeStatusResponse, McpBridgeStopResponse,
        McpPolicyListResponse, McpPolicySetResponse,
    };
    match cmd {
        McpCmd::Start {
            allowlist,
            container,
            host_command,
            host_args,
        } => {
            let resp: McpBridgeStartResponse = client
                .call(Method::McpBridgeStart(McpBridgeStartParams {
                    container_id: container,
                    host_command,
                    host_args,
                    allowlist,
                }))
                .await?;
            println!("{}", resp.bridge_id);
        }
        McpCmd::Stop { bridge_id } => {
            let resp: McpBridgeStopResponse = client
                .call(Method::McpBridgeStop(McpBridgeStopParams {
                    bridge_id: bridge_id.clone(),
                }))
                .await?;
            if resp.stopped {
                println!("{}", resp.bridge_id);
            } else {
                eprintln!("bridge {} not found (already stopped?)", resp.bridge_id);
                std::process::exit(1);
            }
        }
        McpCmd::Status { bridge_id } => {
            let entries: McpBridgeStatusResponse = client
                .call(Method::McpBridgeStatus(McpBridgeStatusParams { bridge_id }))
                .await?;
            print_mcp_status(&entries, fmt)?;
        }
        McpCmd::Policy(McpPolicyCmd::Set {
            method,
            tool,
            decision,
            note,
        }) => {
            let rule = McpPolicyRule {
                method,
                tool_name: tool,
                decision,
                note,
            };
            let resp: McpPolicySetResponse = client
                .call(Method::McpPolicySet(McpPolicySetParams {
                    rules: vec![rule],
                    replace_all: false,
                }))
                .await?;
            println!("upserted={} deleted={}", resp.upserted, resp.deleted);
        }
        McpCmd::Policy(McpPolicyCmd::List) => {
            let rules: McpPolicyListResponse = client.call(Method::McpPolicyList).await?;
            print_mcp_policy_list(&rules, fmt)?;
        }
    }
    Ok(())
}

async fn handle_distro(client: &mut Client, fmt: OutputFormat, cmd: DistroCmd) -> Result<()> {
    use linpodx_common::ipc::responses::{
        DistroBuildResponse, DistroCreateResponse, DistroEnterResponse, DistroRemoveResponse,
        DistroTemplateListResponse,
    };
    match cmd {
        DistroCmd::List => {
            let entries: DistroTemplateListResponse =
                client.call(Method::DistroTemplateList).await?;
            print_distro_template_list(&entries, fmt)?;
        }
        DistroCmd::Create {
            kind,
            vm_mode,
            custom_image,
            sandbox,
            name,
        } => {
            let resp: DistroCreateResponse = client
                .call(Method::DistroCreate(DistroCreateParams {
                    kind,
                    name,
                    vm_mode,
                    passthrough: None,
                    custom_image,
                    sandbox_profile: sandbox,
                }))
                .await?;
            print_distro_instance(&resp.instance, fmt)?;
        }
        DistroCmd::Build {
            kind,
            base_tag,
            include,
        } => {
            let resp: DistroBuildResponse = client
                .call(Method::DistroBuild(DistroBuildParams {
                    kind,
                    base_tag,
                    include,
                }))
                .await?;
            println!("{}\t{} ms", resp.image_ref, resp.duration_ms);
        }
        DistroCmd::Enter { name } => {
            let resp: DistroEnterResponse = client
                .call(Method::DistroEnter(DistroEnterParams { name }))
                .await?;
            println!("# container_id={}", resp.container_id);
            println!("# suggested:");
            println!("{}", resp.suggested_command.join(" "));
        }
        DistroCmd::Remove { keep_volume, name } => {
            let resp: DistroRemoveResponse = client
                .call(Method::DistroRemove(DistroRemoveParams {
                    name,
                    keep_volume,
                }))
                .await?;
            if resp.kept_volume {
                println!("{} (volume kept)", resp.name);
            } else {
                println!("{}", resp.name);
            }
        }
    }
    Ok(())
}

async fn handle_passthrough(
    client: &mut Client,
    fmt: OutputFormat,
    profiles_dir_override: Option<PathBuf>,
    cmd: PassthroughCmd,
) -> Result<()> {
    match cmd {
        PassthroughCmd::Grant {
            wayland,
            x11,
            audio,
            gpu,
            dbus,
            clipboard,
            hidpi,
            register_app_menu,
            profile,
        } => {
            let mut value = fetch_profile_yaml(client, &profile).await?;
            let mut spec = read_passthrough_field(&value);
            if wayland {
                spec.wayland = true;
            }
            if x11 {
                spec.x11 = true;
            }
            if let Some(mode) = audio {
                spec.audio = mode;
            }
            if gpu {
                spec.gpu = true;
            }
            if dbus {
                spec.dbus_session = true;
            }
            if clipboard {
                spec.clipboard = true;
            }
            if hidpi {
                spec.hidpi_inherit = true;
            }
            if let Some(name) = register_app_menu {
                spec.register_app_menu = Some(name);
            }
            write_passthrough_field(&mut value, Some(&spec));
            persist_profile_and_reload(client, &profile, profiles_dir_override.as_deref(), &value)
                .await?;
            print_passthrough_status(&profile, &spec, fmt)?;
        }
        PassthroughCmd::Revoke { profile } => {
            let mut value = fetch_profile_yaml(client, &profile).await?;
            write_passthrough_field(&mut value, None);
            persist_profile_and_reload(client, &profile, profiles_dir_override.as_deref(), &value)
                .await?;
            print_passthrough_status(&profile, &PassthroughSpec::default(), fmt)?;
        }
        PassthroughCmd::Status { profile } => {
            let value = fetch_profile_yaml(client, &profile).await?;
            let spec = read_passthrough_field(&value);
            print_passthrough_status(&profile, &spec, fmt)?;
        }
    }
    Ok(())
}

async fn handle_network_egress_set(
    client: &mut Client,
    profile: &str,
    domains: &[String],
) -> Result<()> {
    let cli_profiles_dir = std::env::var("LINPODX_SANDBOX_PROFILES_DIR")
        .ok()
        .map(PathBuf::from);
    let mut value = fetch_profile_yaml(client, profile).await?;
    let domains_clean: Vec<String> = domains
        .iter()
        .map(|d| d.trim().to_string())
        .filter(|d| !d.is_empty())
        .collect();
    let mapping = value
        .as_mapping_mut()
        .ok_or_else(|| anyhow!("profile YAML root must be a mapping"))?;
    let mut net_map = serde_yml::Mapping::new();
    net_map.insert(
        serde_yml::Value::String("kind".into()),
        serde_yml::Value::String("allowlist".into()),
    );
    net_map.insert(
        serde_yml::Value::String("domains".into()),
        serde_yml::Value::Sequence(
            domains_clean
                .iter()
                .map(|d| serde_yml::Value::String(d.clone()))
                .collect(),
        ),
    );
    mapping.insert(
        serde_yml::Value::String("network".into()),
        serde_yml::Value::Mapping(net_map),
    );
    persist_profile_and_reload(client, profile, cli_profiles_dir.as_deref(), &value).await?;
    println!(
        "{}: egress allowlist set ({} domain(s))",
        profile,
        domains_clean.len()
    );
    for d in domains_clean {
        println!("  {d}");
    }
    Ok(())
}

async fn handle_network_egress_status(client: &mut Client, profile: &str) -> Result<()> {
    let value = fetch_profile_yaml(client, profile).await?;
    let net = value.get("network");
    match net {
        Some(serde_yml::Value::Mapping(m)) => {
            let kind = m
                .get(serde_yml::Value::String("kind".into()))
                .and_then(|v| v.as_str())
                .unwrap_or("none");
            println!("{profile}: network.kind = {kind}");
            if kind == "allowlist" {
                if let Some(serde_yml::Value::Sequence(seq)) =
                    m.get(serde_yml::Value::String("domains".into()))
                {
                    println!("  domains ({}):", seq.len());
                    for d in seq {
                        if let Some(s) = d.as_str() {
                            println!("    {s}");
                        }
                    }
                } else {
                    println!("  (no domains)");
                }
            }
        }
        _ => println!("{profile}: network.kind = none (default)"),
    }
    Ok(())
}

async fn fetch_profile_yaml(client: &mut Client, profile: &str) -> Result<serde_yml::Value> {
    use linpodx_common::ipc::responses::SandboxProfileGetResponse;
    let resp: SandboxProfileGetResponse = client
        .call(Method::SandboxProfileGet(SandboxProfileNameParams {
            name: profile.to_string(),
        }))
        .await
        .with_context(|| format!("fetching profile '{profile}'"))?;
    let value: serde_yml::Value = serde_yml::from_str(&resp.yaml)
        .with_context(|| format!("parsing profile '{profile}' as YAML"))?;
    Ok(value)
}

fn read_passthrough_field(value: &serde_yml::Value) -> PassthroughSpec {
    value
        .get("passthrough")
        .and_then(|v| serde_yml::from_value::<PassthroughSpec>(v.clone()).ok())
        .unwrap_or_default()
}

fn write_passthrough_field(value: &mut serde_yml::Value, spec: Option<&PassthroughSpec>) {
    let mapping = match value.as_mapping_mut() {
        Some(m) => m,
        None => return,
    };
    let key = serde_yml::Value::String("passthrough".into());
    match spec {
        Some(s) => {
            if let Ok(v) = serde_yml::to_value(s) {
                mapping.insert(key, v);
            }
        }
        None => {
            mapping.remove(&key);
        }
    }
}

fn default_profiles_dir() -> PathBuf {
    if let Ok(d) = std::env::var("LINPODX_SANDBOX_PROFILES_DIR") {
        return PathBuf::from(d);
    }
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(".config")
        });
    base.join("linpodx").join("profiles")
}

async fn persist_profile_and_reload(
    client: &mut Client,
    profile: &str,
    profiles_dir_override: Option<&Path>,
    value: &serde_yml::Value,
) -> Result<()> {
    let dir = profiles_dir_override
        .map(PathBuf::from)
        .unwrap_or_else(default_profiles_dir);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating profiles dir {}", dir.display()))?;

    let yaml = serde_yml::to_string(value).context("re-serializing profile YAML")?;
    let target = pick_profile_path(&dir, profile);
    std::fs::write(&target, yaml).with_context(|| format!("writing {}", target.display()))?;

    use linpodx_common::ipc::responses::SandboxProfileReloadResponse;
    let _ack: SandboxProfileReloadResponse = client.call(Method::SandboxProfileReload).await?;
    Ok(())
}

fn pick_profile_path(dir: &Path, profile: &str) -> PathBuf {
    for ext in ["yaml", "yml"] {
        let candidate = dir.join(format!("{profile}.{ext}"));
        if candidate.exists() {
            return candidate;
        }
    }
    dir.join(format!("{profile}.yaml"))
}

fn init_tracing() {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".to_string());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

fn default_socket_path() -> PathBuf {
    if let Ok(rt) = std::env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(rt).join("linpodx.sock");
    }
    let uid = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| {
                l.strip_prefix("Uid:")
                    .and_then(|rest| rest.split_whitespace().next())
                    .and_then(|n| n.parse::<u32>().ok())
            })
        })
        .unwrap_or(1000);
    PathBuf::from(format!("/tmp/linpodx-{uid}.sock"))
}

async fn handle_plugin(client: &mut Client, fmt: OutputFormat, cmd: PluginCmd) -> Result<()> {
    use linpodx_common::ipc::responses::{
        PluginInstallResponse, PluginListResponse, PluginRemoveResponse, PluginToggleResponse,
    };
    match cmd {
        PluginCmd::List => {
            let resp: PluginListResponse = client.call(Method::PluginList).await?;
            print_plugin_list(&resp, fmt)?;
        }
        PluginCmd::Install {
            path,
            signature,
            public_key,
        } => {
            let abs = path
                .canonicalize()
                .with_context(|| format!("could not resolve plugin path '{}'", path.display()))?;
            // Resolve override paths to absolutes too so the daemon doesn't have to
            // guess what the CLI's cwd was.
            let signature_path =
                match signature {
                    Some(p) => Some(p.canonicalize().with_context(|| {
                        format!("could not resolve --signature '{}'", p.display())
                    })?),
                    None => None,
                };
            let public_key_path = match public_key {
                Some(p) => Some(p.canonicalize().with_context(|| {
                    format!("could not resolve --public-key '{}'", p.display())
                })?),
                None => None,
            };
            let resp: PluginInstallResponse = client
                .call(Method::PluginInstall(PluginInstallParams {
                    manifest_path: abs.to_string_lossy().into_owned(),
                    signature_path,
                    public_key_path,
                }))
                .await?;
            println!("{}\t{}\t{}", resp.name, resp.version, resp.installed_path);
        }
        PluginCmd::Enable { name } => {
            let resp: PluginToggleResponse = client
                .call(Method::PluginEnable(PluginNameParams { name }))
                .await?;
            println!("{}\tenabled={}", resp.name, resp.enabled);
        }
        PluginCmd::Disable { name } => {
            let resp: PluginToggleResponse = client
                .call(Method::PluginDisable(PluginNameParams { name }))
                .await?;
            println!("{}\tenabled={}", resp.name, resp.enabled);
        }
        PluginCmd::Remove { force, name } => {
            let resp: PluginRemoveResponse = client
                .call(Method::PluginRemove(PluginRemoveParams { name, force }))
                .await?;
            println!("{}\tdeleted_files={}", resp.name, resp.deleted_files);
        }
        PluginCmd::Key(key_cmd) => handle_plugin_key(client, fmt, key_cmd).await?,
    }
    Ok(())
}

/// Phase 16 Stream C — `linpodx plugin key {list, revoke}` dispatcher.
async fn handle_plugin_key(
    client: &mut Client,
    fmt: OutputFormat,
    cmd: PluginKeyCmd,
) -> Result<()> {
    use linpodx_common::ipc::responses::{PluginKeyListResponse, PluginKeyRevokeResponse};
    use linpodx_common::ipc::PluginKeyRevokeParams;
    match cmd {
        PluginKeyCmd::List => {
            let resp: PluginKeyListResponse = client.call(Method::PluginKeyList).await?;
            match fmt {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&resp)?),
                OutputFormat::Table => {
                    if resp.is_empty() {
                        println!("(no publisher keys registered)");
                    } else {
                        let header_pub = "publisher";
                        let header_fp = "fingerprint";
                        let header_status = "status";
                        println!("{header_pub:<24}  {header_fp:<64}  {header_status:<8}  reason");
                        for entry in resp {
                            let reason = entry.reason.unwrap_or_default();
                            let publisher = entry.publisher;
                            let fp = entry.fingerprint;
                            let status = entry.status;
                            println!("{publisher:<24}  {fp:<64}  {status:<8}  {reason}");
                        }
                    }
                }
            }
        }
        PluginKeyCmd::Revoke {
            publisher,
            reason,
            cluster_wide,
            fingerprint,
        } => {
            if cluster_wide {
                use linpodx_common::ipc::responses::PluginKeyRevokePropagateResponse;
                use linpodx_common::ipc::PluginKeyRevokePropagateParams;
                let fp = fingerprint.ok_or_else(|| {
                    anyhow::anyhow!(
                        "--cluster-wide requires --fingerprint (take the value from \
                         `linpodx plugin key list`)"
                    )
                })?;
                let resp: PluginKeyRevokePropagateResponse = client
                    .call(Method::PluginKeyRevokePropagate(
                        linpodx_common::ipc::PluginKeyRevokePropagateParams {
                            publisher: publisher.clone(),
                            fingerprint: fp,
                            reason: Some(reason),
                        },
                    ))
                    .await
                    // suppress the unused-import warning when the inner match
                    // is the only use of PluginKeyRevokePropagateParams.
                    .inspect_err(|_| {
                        let _ = std::marker::PhantomData::<PluginKeyRevokePropagateParams>;
                    })?;
                match fmt {
                    OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&resp)?),
                    OutputFormat::Table => {
                        let idx = resp
                            .log_index
                            .map(|i| i.to_string())
                            .unwrap_or_else(|| "?".into());
                        println!(
                            "{}\tpropagated={}\tfingerprint={}\tlog_index={}",
                            resp.publisher, resp.propagated, resp.fingerprint, idx
                        );
                    }
                }
            } else {
                let resp: PluginKeyRevokeResponse = client
                    .call(Method::PluginKeyRevoke(PluginKeyRevokeParams {
                        publisher: publisher.clone(),
                        reason: Some(reason),
                    }))
                    .await?;
                match fmt {
                    OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&resp)?),
                    OutputFormat::Table => {
                        println!("{}\trevoked={}", resp.publisher, resp.revoked);
                    }
                }
            }
        }
    }
    Ok(())
}

async fn handle_k8s(client: &mut Client, fmt: OutputFormat, cmd: K8sCmd) -> Result<()> {
    use crate::output::{
        print_k8s_deployment_scaled, print_k8s_namespace_created, print_k8s_pod_created,
        print_k8s_pod_deleted,
    };
    use linpodx_common::ipc::responses::{
        K8sDeploymentScaleResponse, K8sNamespaceCreateResponse, K8sPodCreateResponse,
        K8sPodDeleteResponse,
    };
    match cmd {
        K8sCmd::Pod(K8sPodCmd::Create { yaml, namespace }) => {
            let pod_spec_yaml = read_yaml_input(&yaml)?;
            let resp: K8sPodCreateResponse = client
                .call(Method::K8sPodCreate(K8sPodCreateParams {
                    namespace,
                    pod_spec_yaml,
                }))
                .await?;
            print_k8s_pod_created(&resp, fmt)?;
        }
        K8sCmd::Pod(K8sPodCmd::Delete { name, namespace }) => {
            let resp: K8sPodDeleteResponse = client
                .call(Method::K8sPodDelete(K8sPodDeleteParams { namespace, name }))
                .await?;
            print_k8s_pod_deleted(&resp, fmt)?;
        }
        K8sCmd::Ns(K8sNsCmd::Create { name }) => {
            let resp: K8sNamespaceCreateResponse = client
                .call(Method::K8sNamespaceCreate(K8sNamespaceCreateParams {
                    name,
                }))
                .await?;
            print_k8s_namespace_created(&resp, fmt)?;
        }
        K8sCmd::Scale {
            deployment,
            namespace,
            replicas,
        } => {
            let resp: K8sDeploymentScaleResponse = client
                .call(Method::K8sDeploymentScale(K8sDeploymentScaleParams {
                    namespace,
                    name: deployment,
                    replicas,
                }))
                .await?;
            print_k8s_deployment_scaled(&resp, fmt)?;
        }
    }
    Ok(())
}

async fn handle_cluster(client: &mut Client, fmt: OutputFormat, cmd: ClusterCmd) -> Result<()> {
    use linpodx_common::ipc::responses::{
        ClusterLeaderGetResponse, ClusterRaftPromoteResponse, ClusterRaftStatusResponse,
        ClusterRoleGetResponse,
    };
    match cmd {
        ClusterCmd::Leader => {
            let resp: ClusterLeaderGetResponse = client.call(Method::ClusterLeaderGet).await?;
            match fmt {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&resp)?),
                OutputFormat::Table => match resp.leader.as_deref() {
                    Some(l) => println!("{l}"),
                    None => println!("none"),
                },
            }
        }
        ClusterCmd::Role => {
            let resp: ClusterRoleGetResponse = client.call(Method::ClusterRoleGet).await?;
            match fmt {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&resp)?),
                OutputFormat::Table => {
                    let role = cluster_role_str(resp.role);
                    let leader = resp.leader.as_deref().unwrap_or("none");
                    println!("node:   {}", resp.node_id);
                    println!("role:   {role}");
                    println!("leader: {leader}");
                }
            }
        }
        ClusterCmd::Status => {
            let resp: ClusterRaftStatusResponse = client.call(Method::ClusterRaftStatus).await?;
            match fmt {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&resp)?),
                OutputFormat::Table => {
                    let role = cluster_role_str(resp.local_role);
                    let leader = resp.leader.as_deref().unwrap_or("none");
                    println!("local node:  {}", resp.local_node_id);
                    println!("local role:  {role}");
                    println!("leader:      {leader}");
                    println!("term:        {}", resp.current_term);
                    println!();
                    println!("MEMBERSHIP");
                    println!("{:<10}  {:<24}  {:<6}", "NODE_ID", "LABEL/ADDR", "ROLE");
                    for v in &resp.voters {
                        println!(
                            "{:<10}  {:<24}  {:<6}",
                            v.node_id,
                            v.label.as_deref().unwrap_or("-"),
                            v.role
                        );
                    }
                    for l in &resp.learners {
                        println!(
                            "{:<10}  {:<24}  {:<6}",
                            l.node_id,
                            l.label.as_deref().unwrap_or("-"),
                            l.role
                        );
                    }
                    if resp.voters.is_empty() && resp.learners.is_empty() {
                        println!("(no members)");
                    }
                }
            }
        }
        ClusterCmd::Promote { node_id } => {
            let params = linpodx_common::ipc::ClusterRaftPromoteParams {
                node_id: node_id.clone(),
            };
            let resp: ClusterRaftPromoteResponse =
                client.call(Method::ClusterRaftPromote(params)).await?;
            match fmt {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&resp)?),
                OutputFormat::Table => {
                    println!("promoted: {} -> {}", resp.node_id, resp.new_role);
                }
            }
        }
        ClusterCmd::State(state) => handle_cluster_state(client, fmt, state).await?,
    }
    Ok(())
}

async fn handle_cluster_state(
    client: &mut Client,
    fmt: OutputFormat,
    cmd: ClusterStateCmd,
) -> Result<()> {
    use linpodx_common::ipc::responses::{
        ClusterStateGetResponse, ClusterStateProposeContainerResponse,
    };
    use linpodx_common::ipc::ClusterStateProposeContainerParams;
    use linpodx_common::state::{ContainerState, ContainerSummary};
    use linpodx_common::types::ContainerId;

    match cmd {
        ClusterStateCmd::Get => {
            let resp: ClusterStateGetResponse = client.call(Method::ClusterStateGet).await?;
            match fmt {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&resp)?),
                OutputFormat::Table => {
                    println!("last_applied: {}", resp.last_applied);
                    println!("state_bytes:  {}", resp.state_bytes);
                    println!("entries:      {}", resp.containers.len());
                    println!();
                    println!(
                        "{:<14}  {:<14}  {:<24}  {:<10}",
                        "NODE", "CONTAINER", "IMAGE", "STATE"
                    );
                    for e in &resp.containers {
                        println!(
                            "{:<14}  {:<14}  {:<24}  {:<10}",
                            e.node_id, e.container.id.0, e.container.image, e.container.state
                        );
                    }
                    if resp.containers.is_empty() {
                        println!("(no entries)");
                    }
                }
            }
        }
        ClusterStateCmd::Propose {
            node_id,
            container_id,
            image,
        } => {
            let summary = ContainerSummary {
                id: ContainerId(container_id.clone()),
                names: vec![format!("synthetic-{container_id}")],
                image: image.clone(),
                state: ContainerState::Running,
                status: "Up (proposed)".into(),
                created: chrono::Utc::now(),
                command: None,
                ports: vec![],
            };
            let params = ClusterStateProposeContainerParams {
                node_id: node_id.clone(),
                container: summary,
            };
            let resp: ClusterStateProposeContainerResponse = client
                .call(Method::ClusterStateProposeContainer(params))
                .await?;
            match fmt {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&resp)?),
                OutputFormat::Table => {
                    println!(
                        "proposed: node={node_id} container={container_id} \
                         log_index={} committed={}",
                        resp.log_index, resp.committed
                    );
                }
            }
        }
    }
    Ok(())
}

fn cluster_role_str(role: linpodx_common::ipc::responses::ClusterRole) -> &'static str {
    use linpodx_common::ipc::responses::ClusterRole;
    match role {
        ClusterRole::Leader => "leader",
        ClusterRole::Follower => "follower",
        ClusterRole::Candidate => "candidate",
        ClusterRole::Learner => "learner",
        ClusterRole::Unknown => "unknown",
    }
}

/// Phase 15 — `linpodx daemon pin-client {add,list,remove}` dispatcher.
async fn handle_pin_client(
    client: &mut Client,
    fmt: OutputFormat,
    cmd: PinClientCmd,
) -> Result<()> {
    use linpodx_common::ipc::responses::{
        DaemonPinClientAddResponse, DaemonPinClientListResponse, DaemonPinClientRemoveResponse,
    };
    use linpodx_common::ipc::{DaemonPinClientAddParams, DaemonPinClientRemoveParams};
    match cmd {
        PinClientCmd::Add { cert, label } => {
            let pem = std::fs::read_to_string(&cert)
                .with_context(|| format!("read cert pem from {}", cert.display()))?;
            let resp: DaemonPinClientAddResponse = client
                .call(Method::DaemonPinClientAdd(DaemonPinClientAddParams {
                    cert_pem: pem,
                    label,
                }))
                .await?;
            match fmt {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&resp)?),
                OutputFormat::Table => {
                    let status = if resp.inserted {
                        "added"
                    } else {
                        "already pinned"
                    };
                    println!("{} {}", status, resp.fingerprint);
                }
            }
        }
        PinClientCmd::List => {
            let resp: DaemonPinClientListResponse =
                client.call(Method::DaemonPinClientList).await?;
            match fmt {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&resp)?),
                OutputFormat::Table => {
                    if resp.is_empty() {
                        println!("(no pinned clients)");
                    } else {
                        let header_fp = "fingerprint";
                        let header_ts = "enrolled_at";
                        println!("{header_fp:<64}  {header_ts:<24}  label");
                        for entry in resp {
                            let ts = entry.enrolled_at.to_rfc3339();
                            let fp = entry.fingerprint;
                            let label = entry.label;
                            println!("{fp:<64}  {ts:<24}  {label}");
                        }
                    }
                }
            }
        }
        PinClientCmd::Remove { fingerprint } => {
            let resp: DaemonPinClientRemoveResponse = client
                .call(Method::DaemonPinClientRemove(DaemonPinClientRemoveParams {
                    fingerprint: fingerprint.clone(),
                }))
                .await?;
            match fmt {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&resp)?),
                OutputFormat::Table => {
                    if resp.removed {
                        println!("removed {}", resp.fingerprint);
                    } else {
                        println!("not pinned: {}", resp.fingerprint);
                    }
                }
            }
        }
        PinClientCmd::Tofu(t) => {
            use linpodx_common::ipc::responses::{
                DaemonPinClientTofuEnableResponse, DaemonPinClientTofuExpirySetResponse,
                DaemonPinClientTofuExpiryStatusResponse,
            };
            use linpodx_common::ipc::{
                DaemonPinClientTofuEnableParams, DaemonPinClientTofuExpirySetParams,
            };

            if t.status {
                let resp: DaemonPinClientTofuExpiryStatusResponse =
                    client.call(Method::DaemonPinClientTofuExpiryStatus).await?;
                match fmt {
                    OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&resp)?),
                    OutputFormat::Table => {
                        let max = resp
                            .max_age_secs
                            .map(|n| format!("{n}s"))
                            .unwrap_or_else(|| "none".into());
                        let anchor = resp
                            .enabled_at
                            .map(|n| n.to_string())
                            .unwrap_or_else(|| "none".into());
                        println!(
                            "tofu enabled={} max_age={} enabled_at={}",
                            resp.enabled, max, anchor
                        );
                    }
                }
                return Ok(());
            }

            // The expires-in flag implicitly enables TOFU when no other flag
            // was passed — saves operators an extra round-trip.
            let want_enable = t.enable || (t.expires_in.is_some() && !t.disable);
            if !want_enable && !t.disable {
                anyhow::bail!("specify one of --enable / --disable / --expires-in / --status");
            }
            let enable = want_enable;
            let max_enrollments = if enable { t.max } else { None };
            let resp: DaemonPinClientTofuEnableResponse = client
                .call(Method::DaemonPinClientTofuEnable(
                    DaemonPinClientTofuEnableParams {
                        enable,
                        max_enrollments,
                    },
                ))
                .await?;
            match fmt {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&resp)?),
                OutputFormat::Table => {
                    let max = resp
                        .max_enrollments
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "unlimited".into());
                    println!("tofu enabled={} max={}", resp.enabled, max);
                }
            }

            if enable {
                if let Some(secs) = t.expires_in {
                    // `0` means "clear the window while keeping TOFU on".
                    let max_age_secs = if secs == 0 { None } else { Some(secs) };
                    let expiry_resp: DaemonPinClientTofuExpirySetResponse = client
                        .call(Method::DaemonPinClientTofuExpirySet(
                            DaemonPinClientTofuExpirySetParams { max_age_secs },
                        ))
                        .await?;
                    match fmt {
                        OutputFormat::Json => {
                            println!("{}", serde_json::to_string_pretty(&expiry_resp)?)
                        }
                        OutputFormat::Table => {
                            let label = expiry_resp
                                .max_age_secs
                                .map(|n| format!("{n}s"))
                                .unwrap_or_else(|| "cleared".into());
                            println!("tofu expiry={label}");
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Read a pod-spec YAML payload from `path`, or from stdin when the path is `-`.
fn read_yaml_input(path: &Path) -> Result<String> {
    use std::io::Read;
    if path.as_os_str() == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("read pod spec yaml from stdin")?;
        Ok(buf)
    } else {
        std::fs::read_to_string(path)
            .with_context(|| format!("read pod spec yaml from '{}'", path.display()))
    }
}

#[allow(dead_code)]
fn _check_unused_bail() -> Result<()> {
    // Keep `bail!` import used; it'll be needed in Phase 1 for input validation.
    bail!("unreachable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parse_image_push_with_registry_and_auth() {
        let cli = Cli::parse_from([
            "linpodx",
            "images",
            "push",
            "docker.io/me/app:1.0",
            "--registry",
            "registry.example.com",
            "--auth",
            "YWxpY2U6czNjcmV0",
        ]);
        match cli.cmd {
            Cmd::Images(ImagesCmd::Push {
                reference,
                registry,
                auth,
                cert_dir,
            }) => {
                assert_eq!(reference, "docker.io/me/app:1.0");
                assert_eq!(registry.as_deref(), Some("registry.example.com"));
                assert_eq!(auth.as_deref(), Some("YWxpY2U6czNjcmV0"));
                assert!(cert_dir.is_none());
            }
            other => panic!("expected Images Push subcommand, got {other:?}"),
        }
    }

    // ---- Phase 14: image push --cert-dir ----

    #[test]
    fn parse_image_push_with_cert_dir_pointing_at_existing_directory() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let cli = Cli::parse_from([
            "linpodx",
            "images",
            "push",
            "registry.internal/me/app:1.0",
            "--cert-dir",
            tmp.path().to_str().expect("utf-8 tempdir path"),
        ]);
        match cli.cmd {
            Cmd::Images(ImagesCmd::Push {
                reference,
                registry,
                auth,
                cert_dir,
            }) => {
                assert_eq!(reference, "registry.internal/me/app:1.0");
                assert!(registry.is_none());
                assert!(auth.is_none());
                assert_eq!(cert_dir.as_deref(), Some(tmp.path()));
            }
            other => panic!("expected Images Push subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_image_push_rejects_nonexistent_cert_dir() {
        // Pick a path that's overwhelmingly unlikely to exist.
        let bogus = "/nonexistent/linpodx/cert-dir/should/not/exist/xyz123";
        let result = Cli::try_parse_from([
            "linpodx",
            "images",
            "push",
            "me/app:1.0",
            "--cert-dir",
            bogus,
        ]);
        assert!(result.is_err(), "expected clap parse error for missing dir");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("does not exist") || err.contains("not a directory"),
            "error should mention path existence problem: {err}"
        );
    }

    #[test]
    fn parse_image_push_rejects_cert_dir_that_is_a_file() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let file_path = tmp.path().join("not-a-dir.pem");
        std::fs::write(&file_path, b"dummy").expect("write tmp file");
        let result = Cli::try_parse_from([
            "linpodx",
            "images",
            "push",
            "me/app:1.0",
            "--cert-dir",
            file_path.to_str().expect("utf-8 path"),
        ]);
        assert!(
            result.is_err(),
            "expected clap parse error for non-dir path"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("not a directory"),
            "error should report 'not a directory': {err}"
        );
    }

    #[test]
    fn parse_image_manifest_create_collects_repeated_refs() {
        let cli = Cli::parse_from([
            "linpodx",
            "images",
            "manifest",
            "create",
            "myapp:1.0",
            "--ref",
            "myrepo/app:1.0-amd64",
            "--ref",
            "myrepo/app:1.0-arm64",
        ]);
        match cli.cmd {
            Cmd::Images(ImagesCmd::Manifest {
                cmd: ManifestCmd::Create { target, refs },
            }) => {
                assert_eq!(target, "myapp:1.0");
                assert_eq!(
                    refs,
                    vec![
                        "myrepo/app:1.0-amd64".to_string(),
                        "myrepo/app:1.0-arm64".to_string(),
                    ]
                );
            }
            other => panic!("expected Manifest Create subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_image_manifest_push_minimum_args() {
        let cli = Cli::parse_from(["linpodx", "images", "manifest", "push", "myapp:1.0"]);
        match cli.cmd {
            Cmd::Images(ImagesCmd::Manifest {
                cmd:
                    ManifestCmd::Push {
                        manifest,
                        registry,
                        auth,
                    },
            }) => {
                assert_eq!(manifest, "myapp:1.0");
                assert!(registry.is_none());
                assert!(auth.is_none());
            }
            other => panic!("expected Manifest Push subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_image_manifest_create_requires_at_least_one_ref() {
        let result = Cli::try_parse_from(["linpodx", "images", "manifest", "create", "myapp:1.0"]);
        assert!(result.is_err(), "manifest create with no --ref should fail");
    }

    // ---- Phase 11: exec / logs --follow / images pull --progress ----

    #[test]
    fn parse_exec_collects_command_after_double_dash() {
        let cli = Cli::parse_from(["linpodx", "exec", "my-cont", "--", "ls", "-la", "/tmp"]);
        match cli.cmd {
            Cmd::Exec {
                env,
                tty,
                interactive,
                id,
                command,
            } => {
                assert!(env.is_empty());
                assert!(!tty);
                assert!(!interactive);
                assert_eq!(id, "my-cont");
                assert_eq!(
                    command,
                    vec!["ls".to_string(), "-la".to_string(), "/tmp".to_string()]
                );
            }
            other => panic!("expected Exec subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_exec_with_env_and_tty_flags() {
        let cli = Cli::parse_from([
            "linpodx", "exec", "-t", "-e", "FOO=bar", "-e", "BAZ=qux", "my-cont", "--", "env",
        ]);
        match cli.cmd {
            Cmd::Exec {
                env,
                tty,
                interactive,
                id,
                command,
            } => {
                assert!(tty);
                assert!(!interactive);
                assert_eq!(id, "my-cont");
                assert_eq!(
                    env,
                    vec![
                        ("FOO".to_string(), "bar".to_string()),
                        ("BAZ".to_string(), "qux".to_string()),
                    ]
                );
                assert_eq!(command, vec!["env".to_string()]);
            }
            other => panic!("expected Exec subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_exec_with_combined_it_flag_enables_pty_mode() {
        // `-it` is the canonical short combo. Clap's value_parser treats the two
        // single-char flags as bundled, mirroring `docker exec -it`.
        let cli = Cli::parse_from(["linpodx", "exec", "-it", "my-cont", "--", "bash"]);
        match cli.cmd {
            Cmd::Exec {
                tty,
                interactive,
                id,
                command,
                ..
            } => {
                assert!(tty, "tty must be true with -it");
                assert!(interactive, "interactive must be true with -it");
                assert_eq!(id, "my-cont");
                assert_eq!(command, vec!["bash".to_string()]);
            }
            other => panic!("expected Exec subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_exec_with_separate_i_and_t_flags_enables_pty_mode() {
        let cli = Cli::parse_from(["linpodx", "exec", "-i", "-t", "my-cont", "--", "sh"]);
        match cli.cmd {
            Cmd::Exec {
                tty, interactive, ..
            } => {
                assert!(tty);
                assert!(interactive);
            }
            other => panic!("expected Exec subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_exec_requires_command() {
        let result = Cli::try_parse_from(["linpodx", "exec", "my-cont"]);
        assert!(result.is_err(), "exec with no command should fail");
    }

    #[test]
    fn parse_logs_with_follow_flag() {
        let cli = Cli::parse_from(["linpodx", "logs", "--follow", "my-cont"]);
        match cli.cmd {
            Cmd::Logs { follow, since, id } => {
                assert!(follow);
                assert!(since.is_none());
                assert_eq!(id, "my-cont");
            }
            other => panic!("expected Logs subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_logs_default_does_not_follow() {
        let cli = Cli::parse_from(["linpodx", "logs", "my-cont"]);
        match cli.cmd {
            Cmd::Logs { follow, .. } => assert!(!follow),
            other => panic!("expected Logs subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_image_pull_with_progress_flag() {
        let cli = Cli::parse_from(["linpodx", "images", "pull", "--progress", "alpine:latest"]);
        match cli.cmd {
            Cmd::Images(ImagesCmd::Pull {
                progress,
                reference,
            }) => {
                assert!(progress);
                assert_eq!(reference, "alpine:latest");
            }
            other => panic!("expected Images Pull subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_image_pull_default_no_progress() {
        let cli = Cli::parse_from(["linpodx", "images", "pull", "alpine:latest"]);
        match cli.cmd {
            Cmd::Images(ImagesCmd::Pull { progress, .. }) => assert!(!progress),
            other => panic!("expected Images Pull subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_k8s_pod_create_with_namespace() {
        let cli = Cli::parse_from([
            "linpodx",
            "k8s",
            "pod",
            "create",
            "/tmp/pod.yaml",
            "-n",
            "ci",
        ]);
        match cli.cmd {
            Cmd::K8s(K8sCmd::Pod(K8sPodCmd::Create { yaml, namespace })) => {
                assert_eq!(yaml, PathBuf::from("/tmp/pod.yaml"));
                assert_eq!(namespace, "ci");
            }
            other => panic!("expected K8s Pod Create subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_k8s_pod_delete_default_namespace() {
        let cli = Cli::parse_from(["linpodx", "k8s", "pod", "delete", "hello"]);
        match cli.cmd {
            Cmd::K8s(K8sCmd::Pod(K8sPodCmd::Delete { name, namespace })) => {
                assert_eq!(name, "hello");
                assert_eq!(namespace, "default");
            }
            other => panic!("expected K8s Pod Delete subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_k8s_namespace_create() {
        let cli = Cli::parse_from(["linpodx", "k8s", "ns", "create", "my-ns"]);
        match cli.cmd {
            Cmd::K8s(K8sCmd::Ns(K8sNsCmd::Create { name })) => {
                assert_eq!(name, "my-ns");
            }
            other => panic!("expected K8s Ns Create subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_k8s_scale_with_replicas() {
        let cli = Cli::parse_from([
            "linpodx",
            "k8s",
            "scale",
            "web",
            "--replicas",
            "3",
            "-n",
            "prod",
        ]);
        match cli.cmd {
            Cmd::K8s(K8sCmd::Scale {
                deployment,
                namespace,
                replicas,
            }) => {
                assert_eq!(deployment, "web");
                assert_eq!(namespace, "prod");
                assert_eq!(replicas, 3);
            }
            other => panic!("expected K8s Scale subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_cluster_leader_subcommand() {
        let cli = Cli::parse_from(["linpodx", "cluster", "leader"]);
        match cli.cmd {
            Cmd::Cluster(ClusterCmd::Leader) => {}
            other => panic!("expected Cluster Leader subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_cluster_role_subcommand() {
        let cli = Cli::parse_from(["linpodx", "cluster", "role"]);
        match cli.cmd {
            Cmd::Cluster(ClusterCmd::Role) => {}
            other => panic!("expected Cluster Role subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_cluster_status_subcommand() {
        let cli = Cli::parse_from(["linpodx", "cluster", "status"]);
        match cli.cmd {
            Cmd::Cluster(ClusterCmd::Status) => {}
            other => panic!("expected Cluster Status subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_cluster_promote_subcommand() {
        let cli = Cli::parse_from(["linpodx", "cluster", "promote", "node-b"]);
        match cli.cmd {
            Cmd::Cluster(ClusterCmd::Promote { node_id }) => {
                assert_eq!(node_id, "node-b");
            }
            other => panic!("expected Cluster Promote subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_cluster_state_get_subcommand() {
        let cli = Cli::parse_from(["linpodx", "cluster", "state", "get"]);
        match cli.cmd {
            Cmd::Cluster(ClusterCmd::State(ClusterStateCmd::Get)) => {}
            other => panic!("expected Cluster State Get subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_cluster_state_propose_subcommand() {
        let cli = Cli::parse_from([
            "linpodx",
            "cluster",
            "state",
            "propose",
            "--node-id",
            "alpha",
            "--container-id",
            "c1",
        ]);
        match cli.cmd {
            Cmd::Cluster(ClusterCmd::State(ClusterStateCmd::Propose {
                node_id,
                container_id,
                image,
            })) => {
                assert_eq!(node_id, "alpha");
                assert_eq!(container_id, "c1");
                assert_eq!(image, "linpodx-test:latest");
            }
            other => panic!("expected Cluster State Propose subcommand, got {other:?}"),
        }
    }

    #[test]
    fn cluster_raft_status_response_round_trips_via_serde() {
        use linpodx_common::ipc::responses::{
            ClusterRaftStatusResponse, ClusterRole, RaftMembershipNode,
        };
        let resp = ClusterRaftStatusResponse {
            local_node_id: "alpha".into(),
            local_role: ClusterRole::Leader,
            leader: Some("alpha".into()),
            voters: vec![RaftMembershipNode {
                node_id: "1".into(),
                label: Some("alpha".into()),
                role: "voter".into(),
            }],
            learners: vec![RaftMembershipNode {
                node_id: "1234567890".into(),
                label: Some("beta".into()),
                role: "learner".into(),
            }],
            current_term: 4,
        };
        let s = serde_json::to_string(&resp).unwrap();
        let back: ClusterRaftStatusResponse = serde_json::from_str(&s).unwrap();
        assert_eq!(back.local_node_id, "alpha");
        assert_eq!(back.voters.len(), 1);
        assert_eq!(back.learners.len(), 1);
        assert_eq!(back.current_term, 4);
        assert!(matches!(back.local_role, ClusterRole::Leader));
    }

    #[test]
    fn parse_daemon_pin_client_add_with_label() {
        let cli = Cli::parse_from([
            "linpodx",
            "daemon",
            "pin-client",
            "add",
            "/tmp/client.pem",
            "--label",
            "ci-runner",
        ]);
        match cli.cmd {
            Cmd::Daemon(DaemonCmd::PinClient(PinClientCmd::Add { cert, label })) => {
                assert_eq!(cert, PathBuf::from("/tmp/client.pem"));
                assert_eq!(label, "ci-runner");
            }
            other => panic!("expected Daemon PinClient Add, got {other:?}"),
        }
    }

    #[test]
    fn parse_daemon_pin_client_list_and_remove() {
        let listed = Cli::parse_from(["linpodx", "daemon", "pin-client", "list"]);
        assert!(matches!(
            listed.cmd,
            Cmd::Daemon(DaemonCmd::PinClient(PinClientCmd::List))
        ));
        let removed = Cli::parse_from(["linpodx", "daemon", "pin-client", "remove", "deadbeef"]);
        match removed.cmd {
            Cmd::Daemon(DaemonCmd::PinClient(PinClientCmd::Remove { fingerprint })) => {
                assert_eq!(fingerprint, "deadbeef");
            }
            other => panic!("expected Daemon PinClient Remove, got {other:?}"),
        }
    }

    // ----- Phase 16 Stream C — plugin key + pin-client tofu CLI parse tests -----

    #[test]
    fn parse_plugin_key_list_subcommand() {
        let cli = Cli::parse_from(["linpodx", "plugin", "key", "list"]);
        assert!(matches!(
            cli.cmd,
            Cmd::Plugin(PluginCmd::Key(PluginKeyCmd::List))
        ));
    }

    #[test]
    fn parse_plugin_key_revoke_with_reason() {
        let cli = Cli::parse_from([
            "linpodx", "plugin", "key", "revoke", "acme", "--reason", "rotated",
        ]);
        match cli.cmd {
            Cmd::Plugin(PluginCmd::Key(PluginKeyCmd::Revoke {
                publisher,
                reason,
                cluster_wide,
                fingerprint,
            })) => {
                assert_eq!(publisher, "acme");
                assert_eq!(reason, "rotated");
                assert!(!cluster_wide);
                assert!(fingerprint.is_none());
            }
            other => panic!("expected Plugin Key Revoke, got {other:?}"),
        }
    }

    #[test]
    fn parse_plugin_key_revoke_uses_default_reason() {
        let cli = Cli::parse_from(["linpodx", "plugin", "key", "revoke", "acme"]);
        match cli.cmd {
            Cmd::Plugin(PluginCmd::Key(PluginKeyCmd::Revoke {
                publisher,
                reason,
                cluster_wide,
                fingerprint,
            })) => {
                assert_eq!(publisher, "acme");
                assert_eq!(reason, "operator-revoked");
                assert!(!cluster_wide);
                assert!(fingerprint.is_none());
            }
            other => panic!("expected Plugin Key Revoke, got {other:?}"),
        }
    }

    // ----- Phase 17 Stream C — CLI parse for --cluster-wide / --fingerprint -----

    #[test]
    fn parse_plugin_key_revoke_cluster_wide_with_fingerprint() {
        let cli = Cli::parse_from([
            "linpodx",
            "plugin",
            "key",
            "revoke",
            "acme",
            "--reason",
            "compromised",
            "--cluster-wide",
            "--fingerprint",
            "abc123",
        ]);
        match cli.cmd {
            Cmd::Plugin(PluginCmd::Key(PluginKeyCmd::Revoke {
                publisher,
                reason,
                cluster_wide,
                fingerprint,
            })) => {
                assert_eq!(publisher, "acme");
                assert_eq!(reason, "compromised");
                assert!(cluster_wide);
                assert_eq!(fingerprint.as_deref(), Some("abc123"));
            }
            other => panic!("expected Plugin Key Revoke, got {other:?}"),
        }
    }

    #[test]
    fn parse_daemon_pin_client_tofu_expires_in() {
        let cli = Cli::parse_from([
            "linpodx",
            "daemon",
            "pin-client",
            "tofu",
            "--enable",
            "--expires-in",
            "3600",
        ]);
        match cli.cmd {
            Cmd::Daemon(DaemonCmd::PinClient(PinClientCmd::Tofu(t))) => {
                assert!(t.enable);
                assert_eq!(t.expires_in, Some(3600));
            }
            other => panic!("expected PinClient Tofu, got {other:?}"),
        }
    }

    #[test]
    fn parse_daemon_pin_client_tofu_status_flag() {
        let cli = Cli::parse_from(["linpodx", "daemon", "pin-client", "tofu", "--status"]);
        match cli.cmd {
            Cmd::Daemon(DaemonCmd::PinClient(PinClientCmd::Tofu(t))) => {
                assert!(t.status);
                assert!(!t.enable);
                assert!(!t.disable);
                assert!(t.expires_in.is_none());
            }
            other => panic!("expected PinClient Tofu, got {other:?}"),
        }
    }

    #[test]
    fn parse_daemon_pin_client_tofu_status_conflicts_with_others() {
        let res = Cli::try_parse_from([
            "linpodx",
            "daemon",
            "pin-client",
            "tofu",
            "--status",
            "--enable",
        ]);
        assert!(res.is_err(), "--status must conflict with --enable");
    }

    #[test]
    fn parse_daemon_pin_client_tofu_enable_with_max() {
        let cli = Cli::parse_from([
            "linpodx",
            "daemon",
            "pin-client",
            "tofu",
            "--enable",
            "--max",
            "5",
        ]);
        match cli.cmd {
            Cmd::Daemon(DaemonCmd::PinClient(PinClientCmd::Tofu(t))) => {
                assert!(t.enable);
                assert!(!t.disable);
                assert_eq!(t.max, Some(5));
            }
            other => panic!("expected PinClient Tofu, got {other:?}"),
        }
    }

    #[test]
    fn parse_daemon_pin_client_tofu_disable() {
        let cli = Cli::parse_from(["linpodx", "daemon", "pin-client", "tofu", "--disable"]);
        match cli.cmd {
            Cmd::Daemon(DaemonCmd::PinClient(PinClientCmd::Tofu(t))) => {
                assert!(!t.enable);
                assert!(t.disable);
                assert!(t.max.is_none());
            }
            other => panic!("expected PinClient Tofu, got {other:?}"),
        }
    }

    #[test]
    fn parse_daemon_pin_client_tofu_rejects_both_enable_and_disable() {
        // clap's conflicts_with should reject simultaneous --enable + --disable.
        let res = Cli::try_parse_from([
            "linpodx",
            "daemon",
            "pin-client",
            "tofu",
            "--enable",
            "--disable",
        ]);
        assert!(res.is_err(), "conflicts_with must reject both flags");
    }

    #[test]
    fn parse_daemon_pin_client_tofu_max_with_disable_is_silently_ignored() {
        // `--max` without `--enable` is allowed at parse time so operators can
        // re-issue the same command unchanged. The dispatch handler in
        // handle_pin_client coerces max → None whenever enable is false, so
        // the daemon never sees a bogus combination on the wire.
        let cli = Cli::parse_from([
            "linpodx",
            "daemon",
            "pin-client",
            "tofu",
            "--disable",
            "--max",
            "3",
        ]);
        match cli.cmd {
            Cmd::Daemon(DaemonCmd::PinClient(PinClientCmd::Tofu(t))) => {
                assert!(!t.enable);
                assert!(t.disable);
                // Parsed as-is; the runtime handler is what zeroes it out.
                assert_eq!(t.max, Some(3));
            }
            other => panic!("expected PinClient Tofu, got {other:?}"),
        }
    }
}
