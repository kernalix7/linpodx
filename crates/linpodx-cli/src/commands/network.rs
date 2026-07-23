//! `linpodx network(s) <...>` — bridge network CRUD + sandbox-profile-scoped
//! egress allowlist management.
//!
//! `Cmd::Network(NetworkCmd)` in `main.rs` already lives at the singular
//! `network` path; the plural form `networks` is attached as a `clap`
//! visible alias. Both forms dispatch through the same `handle_network`
//! handler — no parallel implementation, no behavior delta.
#![forbid(unsafe_code)]

use crate::client::Client;
use crate::commands::util::{fetch_profile_yaml, persist_profile_and_reload};
use crate::output::{print_inspect, print_network_list, print_prune_result, OutputFormat};
use crate::parse_kv;
use anyhow::{anyhow, Result};
use clap::Subcommand;
use linpodx_common::ipc::{Method, NetworkCreateParams, NetworkNameParams, NetworkRemoveParams};
use linpodx_common::state::{NetworkInspect, NetworkSummary};
use linpodx_common::types::NetworkId;
use std::path::PathBuf;

#[derive(Subcommand, Debug)]
pub(crate) enum NetworkCmd {
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
pub(crate) enum NetworkEgressCmd {
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

pub(crate) async fn handle_network(
    client: &mut Client,
    fmt: OutputFormat,
    profiles_dir_override: Option<PathBuf>,
    cmd: NetworkCmd,
) -> Result<()> {
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
            handle_network_egress_set(client, &profile, &domains, profiles_dir_override.as_deref())
                .await?;
        }
        NetworkCmd::Egress(NetworkEgressCmd::Status { profile }) => {
            handle_network_egress_status(client, &profile).await?;
        }
    }
    Ok(())
}

async fn handle_network_egress_set(
    client: &mut Client,
    profile: &str,
    domains: &[String],
    profiles_dir_override: Option<&std::path::Path>,
) -> Result<()> {
    let mut value = fetch_profile_yaml(client, profile).await?;
    let domains_clean: Vec<String> = domains
        .iter()
        .map(|d| d.trim().to_string())
        .filter(|d| !d.is_empty())
        .collect();
    let mapping = value
        .as_mapping_mut()
        .ok_or_else(|| anyhow!("profile YAML root must be a mapping"))?;
    let mut net_map = serde_norway::Mapping::new();
    net_map.insert(
        serde_norway::Value::String("kind".into()),
        serde_norway::Value::String("allowlist".into()),
    );
    net_map.insert(
        serde_norway::Value::String("domains".into()),
        serde_norway::Value::Sequence(
            domains_clean
                .iter()
                .map(|d| serde_norway::Value::String(d.clone()))
                .collect(),
        ),
    );
    mapping.insert(
        serde_norway::Value::String("network".into()),
        serde_norway::Value::Mapping(net_map),
    );
    persist_profile_and_reload(client, profile, profiles_dir_override, &value).await?;
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
        Some(serde_norway::Value::Mapping(m)) => {
            let kind = m
                .get(serde_norway::Value::String("kind".into()))
                .and_then(|v| v.as_str())
                .unwrap_or("none");
            println!("{profile}: network.kind = {kind}");
            if kind == "allowlist" {
                if let Some(serde_norway::Value::Sequence(seq)) =
                    m.get(serde_norway::Value::String("domains".into()))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cli, Cmd};
    use clap::Parser;

    #[test]
    fn parse_networks_plural_alias_resolves_to_network_subcommand() {
        let cli = Cli::parse_from(["linpodx", "networks", "ls"]);
        match cli.cmd {
            Cmd::Network(NetworkCmd::Ls) => {}
            other => panic!("expected Network::Ls, got {other:?}"),
        }
    }
}
