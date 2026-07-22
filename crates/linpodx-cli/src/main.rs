#![forbid(unsafe_code)]

mod client;
mod commands;
mod output;

use crate::client::Client;
use crate::commands::cluster::ClusterCmd;
use crate::commands::completion::Shell as CompletionShell;
use crate::commands::container::ContainerCmd;
use crate::commands::daemon_mgmt::{CertCmd, DaemonCmd};
use crate::commands::distro::DistroCmd;
use crate::commands::exec::{handle_exec, handle_exec_pty, handle_logs_follow};
use crate::commands::image::ImagesCmd;
use crate::commands::k8s::K8sCmd;
use crate::commands::mcp::McpCmd;
use crate::commands::network::NetworkCmd;
use crate::commands::passthrough::PassthroughCmd;
use crate::commands::plugin::PluginCmd;
use crate::commands::pod::PodCmd;
use crate::commands::sandbox::SandboxCmd;
use crate::commands::session::SessionCmd;
use crate::commands::snapshot::SnapshotCmd;
use crate::commands::volume::VolumeCmd;
use crate::output::{
    print_container_list, print_inspect, print_logs, print_version_response, OutputFormat,
};
use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use linpodx_common::ipc::{
    responses, ContainerIdParams, ContainerListParams, ContainerLogsParams, ContainerRemoveParams,
    ContainerStopParams, CreateOptions, EventTopic, Method,
};
use linpodx_common::state::{ContainerInspect, ContainerSummary, PortMapping, VolumeMount};
use linpodx_common::types::ContainerId;
use std::path::PathBuf;

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
    /// Manage images. Accepts both `images` and the docker-compat alias `image`.
    #[command(subcommand, visible_alias = "image")]
    Images(ImagesCmd),
    /// Manage volumes. Accepts both `volume` and the docker-compat alias `volumes`.
    #[command(subcommand, visible_alias = "volumes")]
    Volume(VolumeCmd),
    /// Manage networks. Accepts both `network` and the docker-compat alias `networks`.
    #[command(subcommand, visible_alias = "networks")]
    Network(NetworkCmd),
    /// Manage pods (compose-style stacks). Accepts both `pod` and `pods` (Phase 26).
    #[command(subcommand, visible_alias = "pods")]
    Pod(PodCmd),
    /// Container lifecycle verbs grouped under one subcommand for users coming
    /// from `docker` / `podman`. Identical behavior to the flat `ps` / `run` /
    /// `start` / `stop` / `rm` / `inspect` / `logs` / `exec` verbs (Phase 18).
    #[command(subcommand)]
    Container(ContainerCmd),
    /// Generate a shell-completion script for the chosen shell to stdout
    /// (Phase 18). Run before opening a daemon connection — completion does
    /// not need one. Pipe the output into the appropriate shell-specific
    /// location, e.g. `linpodx completion bash | sudo tee
    /// /etc/bash_completion.d/linpodx >/dev/null`.
    Completion {
        /// Target shell (bash, zsh, fish, powershell, elvish).
        shell: CompletionShell,
    },
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
    /// First-run environment readiness diagnostics (Phase 18 Stream C).
    Doctor(crate::commands::doctor::DoctorArgs),
}

pub(crate) fn parse_kv(raw: &str) -> std::result::Result<(String, String), String> {
    raw.split_once('=')
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .ok_or_else(|| format!("expected KEY=VALUE, got '{raw}'"))
}

pub(crate) fn parse_port_mapping(raw: &str) -> std::result::Result<PortMapping, String> {
    PortMapping::parse(raw)
}

pub(crate) fn parse_volume_mount(raw: &str) -> std::result::Result<VolumeMount, String> {
    VolumeMount::parse(raw)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let mut cli = Cli::parse();
    init_tracing();

    // Phase 10: cert generation is a local-only helper — no daemon connection needed.
    // Handle it before opening a socket / WS so the user doesn't need a running daemon
    // to bootstrap their cert bundle.
    if let Cmd::Daemon(DaemonCmd::Cert(CertCmd::Generate { out })) = &cli.cmd {
        return crate::commands::daemon_mgmt::handle_cert_generate(out.clone()).await;
    }

    // Phase 18 Stream D — daemon lifecycle subcommands never connect to a
    // daemon. They spawn / signal / poll the daemon process directly.
    // Routing them here means `linpodx daemon start` works on a clean host
    // (instead of bailing out with "could not connect" before it has had a
    // chance to start anything).
    if matches!(
        &cli.cmd,
        Cmd::Daemon(
            DaemonCmd::Start(_) | DaemonCmd::Stop(_) | DaemonCmd::Status(_) | DaemonCmd::Logs(_)
        )
    ) {
        return crate::commands::daemon_mgmt::handle_daemon_mgmt(cli).await;
    }

    // Phase 18 Stream B — shell completion is a local-only renderer. Bail
    // out before opening a socket / WS so users don't need a running daemon
    // to bootstrap their tab-completion.
    if let Cmd::Completion { shell } = cli.cmd {
        commands::completion::render::<Cli, _>(shell, &mut std::io::stdout());
        return Ok(());
    }

    // Phase 18 Stream B — collapse the docker-compat `linpodx container <verb>`
    // surface onto the existing flat `Cmd::Ps / Run / Start / Stop / Rm /
    // Inspect / Logs / Exec` variants so the rest of the dispatcher runs
    // unchanged. There is exactly one code path per verb.
    cli.cmd = flatten_container_cmd(cli.cmd);

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
        Cmd::Images(cmd) => {
            crate::commands::image::handle_images(&mut client, cli.output, cmd).await?
        }
        Cmd::Volume(cmd) => {
            crate::commands::volume::handle_volume(&mut client, cli.output, cmd).await?
        }
        Cmd::Network(cmd) => {
            crate::commands::network::handle_network(&mut client, cli.output, cmd).await?
        }
        Cmd::Pod(cmd) => crate::commands::pod::handle_pod(&mut client, cli.output, cmd).await?,
        Cmd::Sandbox(cmd) => {
            crate::commands::sandbox::handle_sandbox(&mut client, cli.output, cmd).await?
        }
        Cmd::Snapshot(cmd) => {
            crate::commands::snapshot::handle_snapshot(&mut client, cli.output, cmd).await?
        }
        Cmd::Session(cmd) => {
            crate::commands::session::handle_session(&mut client, cli.output, cmd).await?
        }
        Cmd::Mcp(cmd) => crate::commands::mcp::handle_mcp(&mut client, cli.output, cmd).await?,
        Cmd::Distro(cmd) => {
            crate::commands::distro::handle_distro(&mut client, cli.output, cmd).await?
        }
        Cmd::Passthrough(cmd) => {
            crate::commands::passthrough::handle_passthrough(
                &mut client,
                cli.output,
                cli.profiles_dir.clone(),
                cmd,
            )
            .await?
        }
        Cmd::Plugin(cmd) => {
            crate::commands::plugin::handle_plugin(&mut client, cli.output, cmd).await?
        }
        Cmd::K8s(cmd) => crate::commands::k8s::handle_k8s(&mut client, cli.output, cmd).await?,
        Cmd::Cluster(cmd) => {
            crate::commands::cluster::handle_cluster(&mut client, cli.output, cmd).await?
        }
        Cmd::Events { topics, json } => {
            crate::commands::events::handle_events(&mut client, topics, json).await?
        }
        Cmd::Approvals { json } => {
            crate::commands::sandbox::handle_approvals(&mut client, json).await?
        }
        Cmd::Daemon(DaemonCmd::Cert(_)) => {
            // Unreachable — handled by the `handle_cert_generate` fast path above.
            unreachable!("Daemon::Cert handled before client setup");
        }
        Cmd::Daemon(DaemonCmd::PinClient(cmd)) => {
            crate::commands::daemon_pin::handle_pin_client(&mut client, cli.output, cmd).await?;
        }
        Cmd::Daemon(
            DaemonCmd::Start(_) | DaemonCmd::Stop(_) | DaemonCmd::Status(_) | DaemonCmd::Logs(_),
        ) => {
            // Unreachable — Phase 18 Stream D handles these on the fast path.
            unreachable!("Daemon lifecycle handled before client setup");
        }
        Cmd::Doctor(args) => {
            let code = crate::commands::doctor::handle(&mut client, args).await?;
            if code != 0 {
                std::process::exit(code);
            }
        }
        Cmd::Container(_) => {
            // Unreachable — `flatten_container_cmd` above rewrites every
            // `Cmd::Container(...)` value into the matching flat verb before
            // this match runs.
            unreachable!("Cmd::Container should have been flattened");
        }
        Cmd::Completion { .. } => {
            // Unreachable — handled by the Phase 18 Stream B completion fast
            // path above (no daemon connection required).
            unreachable!("Cmd::Completion handled before client setup");
        }
    }

    Ok(())
}

/// Phase 18 Stream B — collapse the docker-compat `linpodx container <verb>`
/// surface onto its flat equivalent. Every variant of `ContainerCmd` has a 1:1
/// counterpart in `Cmd`; this function is the single point of translation.
///
/// Non-container variants pass through untouched.
fn flatten_container_cmd(cmd: Cmd) -> Cmd {
    match cmd {
        Cmd::Container(ContainerCmd::Ls { all }) => Cmd::Ps { all },
        Cmd::Container(ContainerCmd::Run {
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
        }) => Cmd::Run {
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
        },
        Cmd::Container(ContainerCmd::Start { id }) => Cmd::Start { id },
        Cmd::Container(ContainerCmd::Stop { time, id }) => Cmd::Stop { time, id },
        Cmd::Container(ContainerCmd::Rm { force, id }) => Cmd::Rm { force, id },
        Cmd::Container(ContainerCmd::Inspect { id }) => Cmd::Inspect { id },
        Cmd::Container(ContainerCmd::Logs { since, follow, id }) => Cmd::Logs { since, follow, id },
        Cmd::Container(ContainerCmd::Exec {
            env,
            tty,
            interactive,
            id,
            command,
        }) => Cmd::Exec {
            env,
            tty,
            interactive,
            id,
            command,
        },
        other => other,
    }
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
