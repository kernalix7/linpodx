//! `linpodx daemon pin-client <...>` — pinned WebSocket client certificates
//! (Phase 15) + Trust-On-First-Use auto-enrolment (Phase 16/17).
#![forbid(unsafe_code)]

use crate::client::Client;
use crate::output::OutputFormat;
use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use linpodx_common::ipc::{
    DaemonPinClientAddParams, DaemonPinClientRemoveParams, DaemonPinClientTofuEnableParams,
    DaemonPinClientTofuExpirySetParams, Method,
};
use std::path::PathBuf;

#[derive(Subcommand, Debug)]
pub(crate) enum PinClientCmd {
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
pub(crate) struct PinClientTofuCmd {
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

/// Phase 15 — `linpodx daemon pin-client {add,list,remove}` dispatcher.
pub(crate) async fn handle_pin_client(
    client: &mut Client,
    fmt: OutputFormat,
    cmd: PinClientCmd,
) -> Result<()> {
    use linpodx_common::ipc::responses::{
        DaemonPinClientAddResponse, DaemonPinClientListResponse, DaemonPinClientRemoveResponse,
    };
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cli, Cmd};
    use clap::Parser;
    use std::path::PathBuf;

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
            Cmd::Daemon(crate::commands::daemon_mgmt::DaemonCmd::PinClient(
                PinClientCmd::Add { cert, label },
            )) => {
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
            Cmd::Daemon(crate::commands::daemon_mgmt::DaemonCmd::PinClient(
                PinClientCmd::List
            ))
        ));
        let removed = Cli::parse_from(["linpodx", "daemon", "pin-client", "remove", "deadbeef"]);
        match removed.cmd {
            Cmd::Daemon(crate::commands::daemon_mgmt::DaemonCmd::PinClient(
                PinClientCmd::Remove { fingerprint },
            )) => {
                assert_eq!(fingerprint, "deadbeef");
            }
            other => panic!("expected Daemon PinClient Remove, got {other:?}"),
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
            Cmd::Daemon(crate::commands::daemon_mgmt::DaemonCmd::PinClient(
                PinClientCmd::Tofu(t),
            )) => {
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
            Cmd::Daemon(crate::commands::daemon_mgmt::DaemonCmd::PinClient(
                PinClientCmd::Tofu(t),
            )) => {
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
            Cmd::Daemon(crate::commands::daemon_mgmt::DaemonCmd::PinClient(
                PinClientCmd::Tofu(t),
            )) => {
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
            Cmd::Daemon(crate::commands::daemon_mgmt::DaemonCmd::PinClient(
                PinClientCmd::Tofu(t),
            )) => {
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
            Cmd::Daemon(crate::commands::daemon_mgmt::DaemonCmd::PinClient(
                PinClientCmd::Tofu(t),
            )) => {
                assert!(!t.enable);
                assert!(t.disable);
                // Parsed as-is; the runtime handler is what zeroes it out.
                assert_eq!(t.max, Some(3));
            }
            other => panic!("expected PinClient Tofu, got {other:?}"),
        }
    }
}
