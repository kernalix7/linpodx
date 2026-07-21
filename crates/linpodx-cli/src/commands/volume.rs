//! `linpodx volume(s) <...>` — named volume CRUD.
//!
//! `Cmd::Volume(VolumeCmd)` in `main.rs` already lives at the singular
//! `volume` path; the plural form `volumes` is attached as a `clap` visible
//! alias. Both forms dispatch through the same `handle_volume` handler — no
//! parallel implementation, no behavior delta.
#![forbid(unsafe_code)]

use crate::client::Client;
use crate::output::{print_inspect, print_prune_result, print_volume_list, OutputFormat};
use crate::parse_kv;
use anyhow::Result;
use clap::Subcommand;
use linpodx_common::ipc::{Method, VolumeCreateParams, VolumeNameParams, VolumeRemoveParams};
use linpodx_common::state::{VolumeInspect, VolumeSummary};
use linpodx_common::types::VolumeId;

#[derive(Subcommand, Debug)]
pub(crate) enum VolumeCmd {
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

pub(crate) async fn handle_volume(
    client: &mut Client,
    fmt: OutputFormat,
    cmd: VolumeCmd,
) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cli, Cmd};
    use clap::Parser;

    #[test]
    fn parse_volumes_plural_alias_resolves_to_volume_subcommand() {
        let cli = Cli::parse_from(["linpodx", "volumes", "ls"]);
        match cli.cmd {
            Cmd::Volume(VolumeCmd::Ls) => {}
            other => panic!("expected Volume::Ls, got {other:?}"),
        }
    }
}
