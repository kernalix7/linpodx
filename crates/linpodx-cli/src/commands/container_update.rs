//! `linpodx container-update <id>` — live resource-limit updates against an
//! existing container via `podman update` (Phase 27's `Method::ContainerUpdate`
//! IPC surface).
//!
//! This is a flat top-level verb (`linpodx container-update ...`), not
//! nested under the existing `linpodx container <verb>` docker-compat alias
//! group in `commands::container` — that module is owned by a different
//! lane, so this one stays confined to its own new file plus a couple of
//! lines in `main.rs` / `mod.rs`.

#![forbid(unsafe_code)]

use crate::client::Client;
use crate::output::OutputFormat;
use anyhow::{anyhow, Result};
use clap::Args;
use linpodx_common::ipc::{responses::ContainerUpdateResponse, ContainerUpdateParams, Method};

#[derive(Args, Debug)]
pub(crate) struct ContainerUpdateArgs {
    /// Container id or name.
    pub(crate) id: String,
    /// New memory limit, in MiB.
    #[arg(long = "memory-mib")]
    pub(crate) memory_mib: Option<u64>,
    /// New memory+swap limit, in MiB.
    #[arg(long = "memory-swap-mib")]
    pub(crate) memory_swap_mib: Option<u64>,
    /// New CPU quota (fractional cores, e.g. `1.5`).
    #[arg(long = "cpus")]
    pub(crate) cpus: Option<f64>,
    /// New PIDs limit.
    #[arg(long = "pids-limit")]
    pub(crate) pids_limit: Option<i64>,
    /// New restart policy (e.g. `no`, `on-failure`, `always`, `unless-stopped`).
    #[arg(long = "restart")]
    pub(crate) restart: Option<String>,
}

pub(crate) async fn handle_container_update(
    client: &mut Client,
    fmt: OutputFormat,
    args: ContainerUpdateArgs,
) -> Result<()> {
    let memory_bytes = args.memory_mib.map(mib_to_bytes).transpose()?;
    let memory_swap_bytes = args.memory_swap_mib.map(mib_to_bytes).transpose()?;

    let resp: ContainerUpdateResponse = client
        .call(Method::ContainerUpdate(ContainerUpdateParams {
            id: args.id,
            memory_bytes,
            memory_swap_bytes,
            cpus: args.cpus,
            pids_limit: args.pids_limit,
            restart_policy: args.restart,
        }))
        .await?;
    print_container_update(&resp, fmt)
}

fn mib_to_bytes(mib: u64) -> Result<u64> {
    mib.checked_mul(1024 * 1024).ok_or_else(|| {
        anyhow!(
            "--memory-mib / --memory-swap-mib value too large (overflow converting MiB to bytes)"
        )
    })
}

fn print_container_update(resp: &ContainerUpdateResponse, fmt: OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Json => {
            let s = serde_json::to_string_pretty(resp)?;
            println!("{s}");
            Ok(())
        }
        OutputFormat::Table => {
            if resp.applied.is_empty() {
                println!("{} -> no changes requested", resp.id);
            } else {
                println!("{} -> applied: {}", resp.id, resp.applied.join(", "));
            }
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
    fn parse_container_update_minimum_args() {
        let cli = Cli::parse_from(["linpodx", "container-update", "my-container"]);
        match cli.cmd {
            Cmd::ContainerUpdate(args) => {
                assert_eq!(args.id, "my-container");
                assert!(args.memory_mib.is_none());
                assert!(args.memory_swap_mib.is_none());
                assert!(args.cpus.is_none());
                assert!(args.pids_limit.is_none());
                assert!(args.restart.is_none());
            }
            other => panic!("expected ContainerUpdate command, got {other:?}"),
        }
    }

    #[test]
    fn parse_container_update_all_flags() {
        let cli = Cli::parse_from([
            "linpodx",
            "container-update",
            "--memory-mib",
            "512",
            "--memory-swap-mib",
            "1024",
            "--cpus",
            "1.5",
            "--pids-limit",
            "100",
            "--restart",
            "on-failure",
            "my-container",
        ]);
        match cli.cmd {
            Cmd::ContainerUpdate(args) => {
                assert_eq!(args.id, "my-container");
                assert_eq!(args.memory_mib, Some(512));
                assert_eq!(args.memory_swap_mib, Some(1024));
                assert_eq!(args.cpus, Some(1.5));
                assert_eq!(args.pids_limit, Some(100));
                assert_eq!(args.restart, Some("on-failure".to_string()));
            }
            other => panic!("expected ContainerUpdate command, got {other:?}"),
        }
    }

    #[test]
    fn mib_to_bytes_converts() {
        assert_eq!(mib_to_bytes(1).unwrap(), 1024 * 1024);
    }

    #[test]
    fn mib_to_bytes_overflow_errors() {
        assert!(mib_to_bytes(u64::MAX).is_err());
    }
}
