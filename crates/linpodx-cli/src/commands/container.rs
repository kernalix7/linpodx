//! Phase 18 Stream B — `linpodx container <...>` docker-compat group.
//!
//! Mirrors the flat top-level container lifecycle verbs (`ps` / `run` /
//! `start` / `stop` / `rm` / `inspect` / `logs` / `exec`) under a single
//! `container` subcommand so users coming from `docker` / `podman` can type
//! the long form without re-learning the flat surface.
//!
//! The enum here is intentionally a thin data-shape twin of the matching
//! flat `Cmd` variants in `main.rs`. The translation back to the flat shape
//! lives next to the dispatcher in `main.rs` (`flatten_container_cmd`) so
//! that the existing flat handlers run unchanged — `container` is pure
//! sugar, never a second code path.
//!
//! See also: `commands::completion` for the `linpodx completion <shell>`
//! generator.
#![forbid(unsafe_code)]

use clap::Subcommand;
use linpodx_common::state::{PortMapping, VolumeMount};

use crate::parse_kv;
use crate::parse_port_mapping;
use crate::parse_volume_mount;

/// Container lifecycle verbs grouped under `linpodx container <...>`.
///
/// Every variant has a 1:1 flat counterpart in `Cmd` (defined in `main.rs`).
/// The shape of the arguments is held identical so that `flatten_container_cmd`
/// in `main.rs` can re-emit the exact `Cmd::Ps { all }` / `Cmd::Run { .. }` /
/// etc. value the rest of the dispatcher already knows how to handle.
#[derive(Subcommand, Debug)]
pub(crate) enum ContainerCmd {
    /// List containers (alias of `linpodx ps`).
    Ls {
        /// Show all containers (default: only running).
        #[arg(long, short = 'a')]
        all: bool,
    },
    /// Create and start a container (alias of `linpodx run`).
    Run {
        /// Assign a name to the container.
        #[arg(long)]
        name: Option<String>,
        /// Auto-remove on exit.
        #[arg(long)]
        rm: bool,
        /// Detach (foreground attach lands later).
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
        /// Mount a volume: `SRC:DST[:ro]`.
        #[arg(short = 'v', long = "volume", value_parser = parse_volume_mount)]
        volume: Vec<VolumeMount>,
        /// Attach the container to a network (may be repeated).
        #[arg(long = "network")]
        network: Vec<String>,
        /// Apply the named sandbox profile before podman create.
        #[arg(long = "sandbox")]
        sandbox: Option<String>,
        /// Image reference.
        image: String,
        /// Optional command to run inside the container.
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// Start an existing container (alias of `linpodx start`).
    Start {
        /// Container id or name.
        id: String,
    },
    /// Stop a running container (alias of `linpodx stop`).
    Stop {
        /// Timeout in seconds before SIGKILL.
        #[arg(short = 't', long)]
        time: Option<u32>,
        /// Container id or name.
        id: String,
    },
    /// Remove a container (alias of `linpodx rm`).
    Rm {
        /// Force remove a running container.
        #[arg(short = 'f', long)]
        force: bool,
        /// Container id or name.
        id: String,
    },
    /// Show low-level container info as pretty JSON (alias of `linpodx inspect`).
    Inspect {
        /// Container id or name.
        id: String,
    },
    /// Print captured stdout/stderr from a container (alias of `linpodx logs`).
    Logs {
        /// RFC3339 timestamp; only print lines after this time.
        #[arg(long)]
        since: Option<String>,
        /// Follow log output until Ctrl+C.
        #[arg(short = 'f', long)]
        follow: bool,
        /// Container id or name.
        id: String,
    },
    /// Run a one-shot command inside an existing container (alias of `linpodx exec`).
    Exec {
        /// Set environment variables (KEY=VALUE).
        #[arg(short = 'e', long = "env", value_parser = parse_kv)]
        env: Vec<(String, String)>,
        /// Allocate a TTY for the command. Pair with `-i` for interactive mode.
        #[arg(short = 't', long)]
        tty: bool,
        /// Keep STDIN open and proxy it to the container. Pair with `-t` for PTY.
        #[arg(short = 'i', long)]
        interactive: bool,
        /// Container id or name.
        id: String,
        /// Command + args to run.
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{flatten_container_cmd, Cli, Cmd};
    use clap::Parser;

    #[test]
    fn parse_container_ls_with_all_flag() {
        let cli = Cli::parse_from(["linpodx", "container", "ls", "--all"]);
        match cli.cmd {
            Cmd::Container(ContainerCmd::Ls { all }) => assert!(all),
            other => panic!("expected Container::Ls, got {other:?}"),
        }
    }

    #[test]
    fn parse_container_ls_default_running_only() {
        let cli = Cli::parse_from(["linpodx", "container", "ls"]);
        match cli.cmd {
            Cmd::Container(ContainerCmd::Ls { all }) => assert!(!all),
            other => panic!("expected Container::Ls, got {other:?}"),
        }
    }

    #[test]
    fn parse_container_run_inherits_flat_flags() {
        let cli = Cli::parse_from([
            "linpodx",
            "container",
            "run",
            "--name",
            "test",
            "--rm",
            "-e",
            "FOO=bar",
            "alpine:latest",
            "echo",
            "hi",
        ]);
        match cli.cmd {
            Cmd::Container(ContainerCmd::Run {
                name,
                rm,
                env,
                image,
                command,
                ..
            }) => {
                assert_eq!(name.as_deref(), Some("test"));
                assert!(rm);
                assert_eq!(env, vec![("FOO".to_string(), "bar".to_string())]);
                assert_eq!(image, "alpine:latest");
                assert_eq!(command, vec!["echo".to_string(), "hi".to_string()]);
            }
            other => panic!("expected Container::Run, got {other:?}"),
        }
    }

    #[test]
    fn parse_container_exec_with_tty_and_interactive() {
        let cli = Cli::parse_from([
            "linpodx",
            "container",
            "exec",
            "-it",
            "my-container",
            "--",
            "sh",
        ]);
        match cli.cmd {
            Cmd::Container(ContainerCmd::Exec {
                tty,
                interactive,
                id,
                command,
                ..
            }) => {
                assert!(tty);
                assert!(interactive);
                assert_eq!(id, "my-container");
                assert_eq!(command, vec!["sh".to_string()]);
            }
            other => panic!("expected Container::Exec, got {other:?}"),
        }
    }

    #[test]
    fn flatten_container_ls_becomes_flat_ps() {
        let cli = Cli::parse_from(["linpodx", "container", "ls", "-a"]);
        match flatten_container_cmd(cli.cmd) {
            Cmd::Ps { all } => assert!(all),
            other => panic!("expected flat Cmd::Ps, got {other:?}"),
        }
    }

    #[test]
    fn flatten_container_logs_preserves_follow_and_since() {
        let cli = Cli::parse_from([
            "linpodx",
            "container",
            "logs",
            "--since",
            "2026-05-15T00:00:00Z",
            "-f",
            "my-id",
        ]);
        match flatten_container_cmd(cli.cmd) {
            Cmd::Logs { since, follow, id } => {
                assert_eq!(since.as_deref(), Some("2026-05-15T00:00:00Z"));
                assert!(follow);
                assert_eq!(id, "my-id");
            }
            other => panic!("expected flat Cmd::Logs, got {other:?}"),
        }
    }

    #[test]
    fn flatten_non_container_variant_passes_through_unchanged() {
        let cli = Cli::parse_from(["linpodx", "version"]);
        match flatten_container_cmd(cli.cmd) {
            Cmd::Version => {}
            other => panic!("expected flat Cmd::Version, got {other:?}"),
        }
    }
}
