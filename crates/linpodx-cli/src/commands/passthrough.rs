//! `linpodx passthrough <...>` — edit GUI / device passthrough grants on a
//! sandbox profile (Phase 3).
#![forbid(unsafe_code)]

use crate::client::Client;
use crate::commands::util::{
    fetch_profile_yaml, persist_profile_and_reload, read_passthrough_field, write_passthrough_field,
};
use crate::output::{print_passthrough_status, OutputFormat};
use anyhow::Result;
use clap::Subcommand;
use linpodx_common::passthrough::{AudioMode, PassthroughSpec};
use std::path::PathBuf;

#[derive(Subcommand, Debug)]
pub(crate) enum PassthroughCmd {
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

pub(crate) async fn handle_passthrough(
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
