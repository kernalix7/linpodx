//! `linpodx plugin <...>` — WASM approval-rule plugins (Phase 6) and
//! publisher signing-key registry management (Phase 16/17).
#![forbid(unsafe_code)]

use crate::client::Client;
use crate::output::{print_plugin_list, OutputFormat};
use anyhow::{Context, Result};
use clap::Subcommand;
use linpodx_common::ipc::{
    Method, PluginInstallParams, PluginKeyRevokeParams, PluginNameParams, PluginRemoveParams,
};
use std::path::PathBuf;

#[derive(Subcommand, Debug)]
pub(crate) enum PluginCmd {
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
pub(crate) enum PluginKeyCmd {
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

pub(crate) async fn handle_plugin(
    client: &mut Client,
    fmt: OutputFormat,
    cmd: PluginCmd,
) -> Result<()> {
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
                        PluginKeyRevokePropagateParams {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cli, Cmd};
    use clap::Parser;

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
}
