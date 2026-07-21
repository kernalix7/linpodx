//! `linpodx sandbox <...>` — sandbox profiles + tamper-evident audit log
//! (Phase 1C), secprofile compilation (Phase 11), and the interactive
//! approval-gate listener (`linpodx approvals`, Phase 2A).
#![forbid(unsafe_code)]

use crate::client::Client;
use crate::output::{
    print_audit_table, print_compile_result, print_sandbox_profile_list, OutputFormat,
};
use anyhow::Result;
use clap::Subcommand;
use linpodx_common::approval::ApprovalRequest;
use linpodx_common::ipc::{
    responses::SubscribeResponse, ApprovalDecisionParams, AuditQueryParams, AuditVerifyParams,
    CreateOptions, EventTopic, Method, Notification, SandboxProfileNameParams, ServerMessage,
    SubscribeParams,
};
use std::path::PathBuf;

#[derive(Subcommand, Debug)]
pub(crate) enum SandboxCmd {
    /// List loaded sandbox profiles.
    List,
    /// Show a profile's full YAML content.
    Show { name: String },
    /// Re-scan the profiles directory and reload everything.
    Reload,
    /// Run a container with a sandbox profile applied (shorthand for `linpodx run --sandbox`).
    Apply {
        /// Profile name (must already be loaded).
        profile: String,
        /// Optional container name.
        #[arg(long)]
        name: Option<String>,
        /// Auto-remove on exit.
        #[arg(long)]
        rm: bool,
        /// Image reference.
        image: String,
        /// Optional command to run.
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// Query the audit log.
    Audit {
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        kind: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: u32,
        #[arg(long)]
        json: bool,
    },
    /// Re-compute the SHA-256 hash chain and report any tamper.
    Verify {
        #[arg(long)]
        since_seq: Option<i64>,
    },
    /// Profile-scoped operations (Phase 11 secprofile compilation).
    Profile {
        #[command(subcommand)]
        cmd: SandboxProfileCmd,
    },
}

#[derive(Subcommand, Debug)]
pub(crate) enum SandboxProfileCmd {
    /// Compile a sandbox profile's seccomp + AppArmor extensions to on-disk artefacts.
    /// Pulls the profile YAML from the daemon, then compiles locally.
    Compile {
        /// Sandbox profile name (must be loaded by the daemon).
        name: String,
        /// Output directory for the compiled artefacts. Defaults to
        /// `${XDG_CACHE_HOME:-~/.cache}/linpodx/secprofiles`.
        #[arg(long = "secprofile-out")]
        secprofile_out: Option<PathBuf>,
    },
}

pub(crate) async fn handle_sandbox(
    client: &mut Client,
    fmt: OutputFormat,
    cmd: SandboxCmd,
) -> Result<()> {
    use linpodx_common::ipc::responses::{
        AuditLogQueryResponse, AuditVerifyResponse, SandboxProfileGetResponse,
        SandboxProfileListResponse, SandboxProfileReloadResponse,
    };

    match cmd {
        SandboxCmd::List => {
            let profiles: SandboxProfileListResponse =
                client.call(Method::SandboxProfileList).await?;
            print_sandbox_profile_list(&profiles, fmt)?;
        }
        SandboxCmd::Show { name } => {
            let resp: SandboxProfileGetResponse = client
                .call(Method::SandboxProfileGet(SandboxProfileNameParams { name }))
                .await?;
            println!(
                "# {}  (yaml_hash={}, last_updated={})",
                resp.name, resp.yaml_hash, resp.last_updated
            );
            print!("{}", resp.yaml);
        }
        SandboxCmd::Reload => {
            let resp: SandboxProfileReloadResponse =
                client.call(Method::SandboxProfileReload).await?;
            println!("Loaded {} profile(s):", resp.loaded);
            for n in resp.names {
                println!("  {n}");
            }
        }
        SandboxCmd::Apply {
            profile,
            name,
            rm,
            image,
            command,
        } => {
            let opts = CreateOptions {
                image,
                name,
                command,
                rm,
                detach: true,
                sandbox_profile: Some(profile),
                ..Default::default()
            };
            let id: linpodx_common::types::ContainerId =
                client.call(Method::ContainerCreate(opts)).await?;
            client
                .call::<serde_json::Value>(Method::ContainerStart(
                    linpodx_common::ipc::ContainerIdParams { id: id.clone() },
                ))
                .await?;
            println!("{id}");
        }
        SandboxCmd::Audit {
            profile,
            kind,
            limit,
            json,
        } => {
            let entries: AuditLogQueryResponse = client
                .call(Method::AuditLogQuery(AuditQueryParams {
                    profile_name: profile,
                    kind,
                    since: None,
                    until: None,
                    limit: Some(limit),
                }))
                .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else {
                print_audit_table(&entries)?;
            }
        }
        SandboxCmd::Verify { since_seq } => {
            let report: AuditVerifyResponse = client
                .call(Method::AuditLogVerify(AuditVerifyParams { since_seq }))
                .await?;
            match report.broken_at {
                Some(seq) => {
                    println!(
                        "TAMPER DETECTED: chain breaks at seq {} (verified {} entries up to seq {:?})",
                        seq, report.total, report.last_seq
                    );
                    std::process::exit(2);
                }
                None => {
                    println!(
                        "OK: verified {} entries (last seq {:?})",
                        report.total, report.last_seq
                    );
                }
            }
        }
        SandboxCmd::Profile { cmd } => match cmd {
            SandboxProfileCmd::Compile {
                name,
                secprofile_out,
            } => {
                handle_sandbox_profile_compile(client, name, secprofile_out, fmt).await?;
            }
        },
    }
    Ok(())
}

async fn handle_sandbox_profile_compile(
    client: &mut Client,
    name: String,
    secprofile_out: Option<PathBuf>,
    fmt: OutputFormat,
) -> Result<()> {
    use linpodx_common::audit_sink::NoopAuditSink;
    use linpodx_common::ipc::responses::SandboxProfileGetResponse;
    use linpodx_sandbox::SecProfileCompiler;
    use std::sync::Arc;

    let resp: SandboxProfileGetResponse = client
        .call(Method::SandboxProfileGet(SandboxProfileNameParams {
            name: name.clone(),
        }))
        .await?;
    let profile: linpodx_sandbox::SandboxProfile = serde_norway::from_str(&resp.yaml)
        .map_err(|e| anyhow::anyhow!("parse profile YAML for '{}': {e}", resp.name))?;

    let cache_dir = match secprofile_out {
        Some(p) => p,
        None => default_secprofile_cache_dir()?,
    };
    let compiler = SecProfileCompiler::new(cache_dir.clone(), Arc::new(NoopAuditSink));
    let compiled = compiler
        .compile(&profile)
        .await
        .map_err(|e| anyhow::anyhow!("secprofile compile failed: {e}"))?;
    print_compile_result(&resp.name, &cache_dir, &compiled, fmt)?;
    Ok(())
}

fn default_secprofile_cache_dir() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|h| {
                let mut p = PathBuf::from(h);
                p.push(".cache");
                p
            })
        })
        .ok_or_else(|| anyhow::anyhow!("neither XDG_CACHE_HOME nor HOME is set"))?;
    let mut p = base;
    p.push("linpodx");
    p.push("secprofiles");
    Ok(p)
}

/// `linpodx approvals` — listen for sandbox approval requests and prompt the
/// user (Phase 2A).
pub(crate) async fn handle_approvals(client: &mut Client, json: bool) -> Result<()> {
    let _ack: SubscribeResponse = client
        .call(Method::Subscribe(SubscribeParams {
            topics: EventTopic::ALL.to_vec(),
        }))
        .await?;
    eprintln!("listening for approval requests — press Ctrl+C to stop");

    loop {
        let msg = match client.next_server_message().await? {
            Some(m) => m,
            None => {
                eprintln!("daemon closed the connection");
                return Ok(());
            }
        };
        let req = match msg {
            ServerMessage::Notification(Notification { method, params, .. })
                if method == "approval_request" =>
            {
                match serde_json::from_value::<ApprovalRequest>(params) {
                    Ok(req) => req,
                    Err(e) => {
                        eprintln!("malformed approval request: {e}");
                        continue;
                    }
                }
            }
            _ => continue,
        };

        if json {
            println!("{}", serde_json::to_string(&req)?);
            continue;
        }

        let payload = serde_json::to_string(&req.payload).unwrap_or_default();
        eprint!(
            "[approval] profile={} category={} payload={} (y/n, timeout {}s): ",
            req.profile_name, req.category, payload, req.timeout_secs
        );

        let allow = read_yes_no_with_timeout(std::time::Duration::from_secs(
            req.timeout_secs.saturating_sub(2).max(1),
        ))
        .await;
        let resp = client
            .call::<linpodx_common::ipc::responses::ApprovalDecisionResponse>(
                Method::ApprovalDecision(ApprovalDecisionParams {
                    request_id: req.request_id.clone(),
                    allow,
                    by: Some(format!("cli-{}", whoami())),
                    reason: None,
                }),
            )
            .await;
        match resp {
            Ok(r) if r.accepted => {
                eprintln!("→ {} (sent)", if allow { "allow" } else { "deny" });
            }
            Ok(_) => {
                eprintln!(
                    "→ daemon already resolved request {} — too late",
                    req.request_id
                );
            }
            Err(e) => eprintln!("→ failed to send decision: {e}"),
        }
    }
}

async fn read_yes_no_with_timeout(timeout: std::time::Duration) -> bool {
    let read = tokio::task::spawn_blocking(|| {
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok();
        let answer = input.trim().to_ascii_lowercase();
        matches!(answer.as_str(), "y" | "yes")
    });
    match tokio::time::timeout(timeout, read).await {
        Ok(Ok(b)) => b,
        Ok(Err(_)) => false,
        Err(_) => {
            eprintln!("(no input — defaulting to deny)");
            false
        }
    }
}

fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "user".to_string())
}
