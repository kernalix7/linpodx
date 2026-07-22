//! `linpodx pod {ls,create,start,stop,rm}` — pod (compose-style stack)
//! lifecycle management against the Phase 26 `Method::Pod*` IPC surface.
//!
//! This module owns its own table rendering rather than adding to
//! `output.rs` (outside this lane's owned paths) — `print_pod_list` /
//! `print_pod_action` below are private to this file and follow the same
//! `comfy_table` shape as `output.rs`'s existing `print_*_list` helpers.

#![forbid(unsafe_code)]

use crate::client::Client;
use crate::output::OutputFormat;
use crate::parse_kv;
use anyhow::Result;
use clap::Subcommand;
use comfy_table::{presets::UTF8_FULL, Cell, ContentArrangement, Table};
use linpodx_common::ipc::{
    responses::{PodActionResponse, PodCreateResponse, PodListResponse},
    Method, PodActionParams, PodCreateParams, PodRemoveParams,
};

#[derive(Subcommand, Debug)]
pub(crate) enum PodCmd {
    /// List pods.
    Ls,
    /// Create a pod (an infra container that other containers can attach to).
    Create {
        /// Publish a port, e.g. `8080:80` or `8080:80/udp` (repeatable).
        #[arg(short = 'p', long = "publish", value_parser = crate::parse_port_mapping)]
        ports: Vec<linpodx_common::state::PortMapping>,
        /// Add a label (KEY=VALUE, repeatable). Stack tooling groups pods by
        /// `com.docker.compose.project` / `io.podman.compose.project`.
        #[arg(long = "label", value_parser = parse_kv)]
        labels: Vec<(String, String)>,
        /// Pod name.
        name: String,
    },
    /// Start a pod.
    Start {
        /// Pod id or name.
        id_or_name: String,
    },
    /// Stop a pod.
    Stop {
        /// Pod id or name.
        id_or_name: String,
    },
    /// Remove a pod.
    Rm {
        /// Remove even if the pod holds running containers.
        #[arg(short = 'f', long)]
        force: bool,
        /// Pod id or name.
        id_or_name: String,
    },
}

pub(crate) async fn handle_pod(client: &mut Client, fmt: OutputFormat, cmd: PodCmd) -> Result<()> {
    match cmd {
        PodCmd::Ls => {
            let resp: PodListResponse = client.call(Method::PodList).await?;
            print_pod_list(&resp, fmt)?;
        }
        PodCmd::Create {
            ports,
            labels,
            name,
        } => {
            let resp: PodCreateResponse = client
                .call(Method::PodCreate(PodCreateParams {
                    name,
                    ports,
                    labels: labels.into_iter().collect(),
                }))
                .await?;
            print_pod_create(&resp, fmt)?;
        }
        PodCmd::Start { id_or_name } => {
            let resp: PodActionResponse = client
                .call(Method::PodStart(PodActionParams { id_or_name }))
                .await?;
            print_pod_action(&resp, fmt)?;
        }
        PodCmd::Stop { id_or_name } => {
            let resp: PodActionResponse = client
                .call(Method::PodStop(PodActionParams { id_or_name }))
                .await?;
            print_pod_action(&resp, fmt)?;
        }
        PodCmd::Rm { force, id_or_name } => {
            let resp: PodActionResponse = client
                .call(Method::PodRemove(PodRemoveParams { id_or_name, force }))
                .await?;
            print_pod_action(&resp, fmt)?;
        }
    }
    Ok(())
}

fn print_json<T: serde::Serialize + ?Sized>(value: &T) -> Result<()> {
    let s = serde_json::to_string_pretty(value)?;
    println!("{s}");
    Ok(())
}

fn print_pod_list(resp: &PodListResponse, fmt: OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_json(resp),
        OutputFormat::Table => {
            if resp.pods.is_empty() {
                println!("No pods.");
                return Ok(());
            }
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec![
                    "POD ID",
                    "NAME",
                    "STATUS",
                    "CONTAINERS",
                    "INFRA ID",
                    "CREATED",
                ]);
            for pod in &resp.pods {
                let id_short = if pod.id.len() > 16 {
                    &pod.id[..16]
                } else {
                    &pod.id
                };
                let infra_short = pod
                    .infra_id
                    .as_deref()
                    .map(|i| if i.len() > 12 { &i[..12] } else { i })
                    .unwrap_or("<none>");
                table.add_row(vec![
                    Cell::new(id_short),
                    Cell::new(&pod.name),
                    Cell::new(&pod.status),
                    Cell::new(pod.num_containers.to_string()),
                    Cell::new(infra_short),
                    Cell::new(&pod.created),
                ]);
            }
            println!("{table}");
            Ok(())
        }
    }
}

fn print_pod_create(resp: &PodCreateResponse, fmt: OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_json(resp),
        OutputFormat::Table => {
            println!("{} ({})", resp.id, resp.name);
            Ok(())
        }
    }
}

fn print_pod_action(resp: &PodActionResponse, fmt: OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_json(resp),
        OutputFormat::Table => {
            println!("{} -> {}", resp.id, resp.status);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cli, Cmd};
    use clap::Parser;

    #[test]
    fn parse_pod_ls() {
        let cli = Cli::parse_from(["linpodx", "pod", "ls"]);
        assert!(matches!(cli.cmd, Cmd::Pod(PodCmd::Ls)));
    }

    #[test]
    fn parse_pod_create_with_ports_and_labels() {
        let cli = Cli::parse_from([
            "linpodx",
            "pod",
            "create",
            "--publish",
            "8080:80",
            "--label",
            "com.docker.compose.project=myapp",
            "my-pod",
        ]);
        match cli.cmd {
            Cmd::Pod(PodCmd::Create {
                ports,
                labels,
                name,
            }) => {
                assert_eq!(name, "my-pod");
                assert_eq!(ports.len(), 1);
                assert_eq!(ports[0].host_port, 8080);
                assert_eq!(ports[0].container_port, 80);
                assert_eq!(
                    labels,
                    vec![(
                        "com.docker.compose.project".to_string(),
                        "myapp".to_string()
                    )]
                );
            }
            other => panic!("expected Pod Create subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_pod_create_minimum_args() {
        let cli = Cli::parse_from(["linpodx", "pod", "create", "my-pod"]);
        match cli.cmd {
            Cmd::Pod(PodCmd::Create {
                ports,
                labels,
                name,
            }) => {
                assert_eq!(name, "my-pod");
                assert!(ports.is_empty());
                assert!(labels.is_empty());
            }
            other => panic!("expected Pod Create subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_pod_start() {
        let cli = Cli::parse_from(["linpodx", "pod", "start", "my-pod"]);
        match cli.cmd {
            Cmd::Pod(PodCmd::Start { id_or_name }) => assert_eq!(id_or_name, "my-pod"),
            other => panic!("expected Pod Start subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_pod_stop() {
        let cli = Cli::parse_from(["linpodx", "pod", "stop", "my-pod"]);
        match cli.cmd {
            Cmd::Pod(PodCmd::Stop { id_or_name }) => assert_eq!(id_or_name, "my-pod"),
            other => panic!("expected Pod Stop subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_pod_rm_with_force() {
        let cli = Cli::parse_from(["linpodx", "pod", "rm", "--force", "my-pod"]);
        match cli.cmd {
            Cmd::Pod(PodCmd::Rm { force, id_or_name }) => {
                assert!(force);
                assert_eq!(id_or_name, "my-pod");
            }
            other => panic!("expected Pod Rm subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_pod_rm_default_no_force() {
        let cli = Cli::parse_from(["linpodx", "pod", "rm", "my-pod"]);
        match cli.cmd {
            Cmd::Pod(PodCmd::Rm { force, .. }) => assert!(!force),
            other => panic!("expected Pod Rm subcommand, got {other:?}"),
        }
    }
}
