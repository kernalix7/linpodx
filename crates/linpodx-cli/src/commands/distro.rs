//! `linpodx distro <...>` — multi-distro templates and instances (Phase 4).
#![forbid(unsafe_code)]

use crate::client::Client;
use crate::output::{print_distro_instance, print_distro_template_list, OutputFormat};
use anyhow::Result;
use clap::Subcommand;
use linpodx_common::ipc::{
    DistroBuildParams, DistroCreateParams, DistroEnterParams, DistroRemoveParams, Method,
};
use linpodx_common::passthrough::DistroKind;

#[derive(Subcommand, Debug)]
pub(crate) enum DistroCmd {
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

fn parse_distro_kind(raw: &str) -> std::result::Result<DistroKind, String> {
    DistroKind::parse(raw)
}

pub(crate) async fn handle_distro(
    client: &mut Client,
    fmt: OutputFormat,
    cmd: DistroCmd,
) -> Result<()> {
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
