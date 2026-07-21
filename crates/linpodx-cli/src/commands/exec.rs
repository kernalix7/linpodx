//! `linpodx exec` / `linpodx logs --follow` — one-shot and interactive
//! (PTY, Phase 12) exec, and streaming log tail (Phase 11).
#![forbid(unsafe_code)]

use crate::client::{self, Client};
use anyhow::{anyhow, bail, Context, Result};
use linpodx_common::ipc::{
    responses, ContainerExecParams, ContainerExecPtyParams, ContainerLogsStreamParams, EventKind,
    EventTopic, Method, SubscribeParams,
};
use std::path::PathBuf;

/// Phase 11 — `linpodx exec <id> -- <cmd...>`. One-shot non-interactive command.
pub(crate) async fn handle_exec(
    client: &mut Client,
    container_id: String,
    command: Vec<String>,
    env: Vec<(String, String)>,
    tty: bool,
) -> Result<()> {
    let resp: responses::ContainerExecResponse = client
        .call(Method::ContainerExec(ContainerExecParams {
            container_id,
            command,
            interactive: false,
            tty,
            env,
        }))
        .await?;
    if !resp.stdout.is_empty() {
        print!("{}", resp.stdout);
        if !resp.stdout.ends_with('\n') {
            println!();
        }
    }
    if !resp.stderr.is_empty() {
        eprint!("{}", resp.stderr);
        if !resp.stderr.ends_with('\n') {
            eprintln!();
        }
    }
    if resp.exit_code != 0 {
        std::process::exit(resp.exit_code);
    }
    Ok(())
}

/// Phase 12 — `linpodx exec -it <id> -- <cmd...>`. Allocates a PTY on the daemon
/// side and proxies stdin/stdout over a WebSocket binary stream.
///
/// Requires the user to be talking to a remote daemon (`--remote <addr> --token <t>`)
/// because the PTY endpoint is served only by the WebSocket listener — the local
/// Unix socket transport has no place to upgrade. We surface that constraint as a
/// clear error rather than silently failing.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_exec_pty(
    client: &mut Client,
    container_id: String,
    command: Vec<String>,
    env: Vec<(String, String)>,
    remote: Option<&str>,
    token: Option<&str>,
    ca: Option<&PathBuf>,
    client_cert: Option<&PathBuf>,
    client_key: Option<&PathBuf>,
) -> Result<()> {
    use crossterm::terminal;

    let remote = remote.ok_or_else(|| {
        anyhow!(
            "interactive `exec -it` requires a remote daemon — pass --remote <addr> --token <t>.\n\
             The /pty/<bridge_id> endpoint is only served by the WebSocket listener, not the\n\
             local Unix socket. Start the daemon with `--remote-listen 127.0.0.1:8443 \\\n\
             --remote-token <t>` to attach to a local PTY."
        )
    })?;
    let token = token.ok_or_else(|| anyhow!("--remote requires --token"))?;

    // Detect terminal size for the initial PTY hint. Falls back to 80x24 if stdin
    // isn't a tty (test harness, piped input, etc).
    let (cols, rows) = terminal::size().unwrap_or((80, 24));

    // Step 1: allocate the PTY bridge on the daemon side.
    let resp: responses::ContainerExecPtyResponse = client
        .call(Method::ContainerExecPty(ContainerExecPtyParams {
            container_id: container_id.clone(),
            command,
            env,
            cols: Some(cols),
            rows: Some(rows),
        }))
        .await?;

    // Step 2: open a separate WebSocket to /pty/<bridge_id>?token=<t>. Re-use the
    // CLI's TLS config (--ca / --client-cert / --client-key) for `wss://` daemons.
    let pty_url = client::build_pty_ws_url(remote, &resp.bridge_id, token);
    let tls_cfg = client::TlsClientConfig {
        ca: ca.cloned(),
        client_cert: client_cert.cloned(),
        client_key: client_key.cloned(),
    };
    let mut pty_ws = client::PtyWsClient::connect(&pty_url, tls_cfg, Some(token)).await?;

    // Step 3: enter raw mode (single-char input, no echo) and install a panic hook
    // that disables raw mode so a panic doesn't leave the user's terminal wedged.
    terminal::enable_raw_mode().context("entering raw mode")?;
    let _raw_guard = RawModeGuard::new();

    // Step 4: bidirectional proxy. Two tasks share the WebSocket via a split.
    let result = pty_ws.proxy_stdio().await;

    // Drop guard restores raw mode. Any error from the proxy bubbles up here.
    drop(_raw_guard);
    result
}

/// Restores cooked mode on drop. Used by the PTY exec path so a panic, an early
/// `?`-return, or the WebSocket closing all leave the user's terminal usable.
struct RawModeGuard;

impl RawModeGuard {
    fn new() -> Self {
        Self
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

/// Phase 11 — `linpodx logs <id> --follow`. Subscribes to Container topic and prints
/// only `EventKind::Log` notifications whose `resource_id` matches the container.
pub(crate) async fn handle_logs_follow(
    client: &mut Client,
    container_id: String,
    since: Option<String>,
) -> Result<()> {
    use linpodx_common::ipc::responses::{ContainerLogsStreamResponse, SubscribeResponse};

    let _sub_ack: SubscribeResponse = client
        .call(Method::Subscribe(SubscribeParams {
            topics: vec![EventTopic::Container],
        }))
        .await?;
    let ack: ContainerLogsStreamResponse = client
        .call(Method::ContainerLogsStream(ContainerLogsStreamParams {
            container_id: container_id.clone(),
            follow: true,
            since,
        }))
        .await?;
    if !ack.started {
        bail!("daemon refused to start log stream for {}", container_id);
    }
    eprintln!("streaming logs for {} — press Ctrl+C to stop", container_id);
    while let Some(event) = client.next_event().await? {
        if event.topic != EventTopic::Container || event.kind != EventKind::Log {
            continue;
        }
        if event.resource_id != container_id {
            continue;
        }
        let stream = event
            .details
            .get("stream")
            .and_then(|s| s.as_str())
            .unwrap_or("stdout");
        let line = event
            .details
            .get("line")
            .and_then(|s| s.as_str())
            .unwrap_or_default();
        if stream == "stderr" {
            eprintln!("{line}");
        } else {
            println!("{line}");
        }
    }
    eprintln!("daemon closed the event stream");
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::Cmd;
    use clap::Parser;

    #[test]
    fn parse_exec_collects_command_after_double_dash() {
        let cli = crate::Cli::parse_from(["linpodx", "exec", "my-cont", "--", "ls", "-la", "/tmp"]);
        match cli.cmd {
            Cmd::Exec {
                env,
                tty,
                interactive,
                id,
                command,
            } => {
                assert!(env.is_empty());
                assert!(!tty);
                assert!(!interactive);
                assert_eq!(id, "my-cont");
                assert_eq!(
                    command,
                    vec!["ls".to_string(), "-la".to_string(), "/tmp".to_string()]
                );
            }
            other => panic!("expected Exec subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_exec_with_env_and_tty_flags() {
        let cli = crate::Cli::parse_from([
            "linpodx", "exec", "-t", "-e", "FOO=bar", "-e", "BAZ=qux", "my-cont", "--", "env",
        ]);
        match cli.cmd {
            Cmd::Exec {
                env,
                tty,
                interactive,
                id,
                command,
            } => {
                assert!(tty);
                assert!(!interactive);
                assert_eq!(id, "my-cont");
                assert_eq!(
                    env,
                    vec![
                        ("FOO".to_string(), "bar".to_string()),
                        ("BAZ".to_string(), "qux".to_string()),
                    ]
                );
                assert_eq!(command, vec!["env".to_string()]);
            }
            other => panic!("expected Exec subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_exec_with_combined_it_flag_enables_pty_mode() {
        // `-it` is the canonical short combo. Clap's value_parser treats the two
        // single-char flags as bundled, mirroring `docker exec -it`.
        let cli = crate::Cli::parse_from(["linpodx", "exec", "-it", "my-cont", "--", "bash"]);
        match cli.cmd {
            Cmd::Exec {
                tty,
                interactive,
                id,
                command,
                ..
            } => {
                assert!(tty, "tty must be true with -it");
                assert!(interactive, "interactive must be true with -it");
                assert_eq!(id, "my-cont");
                assert_eq!(command, vec!["bash".to_string()]);
            }
            other => panic!("expected Exec subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_exec_with_separate_i_and_t_flags_enables_pty_mode() {
        let cli = crate::Cli::parse_from(["linpodx", "exec", "-i", "-t", "my-cont", "--", "sh"]);
        match cli.cmd {
            Cmd::Exec {
                tty, interactive, ..
            } => {
                assert!(tty);
                assert!(interactive);
            }
            other => panic!("expected Exec subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_exec_requires_command() {
        let result = crate::Cli::try_parse_from(["linpodx", "exec", "my-cont"]);
        assert!(result.is_err(), "exec with no command should fail");
    }

    #[test]
    fn parse_logs_with_follow_flag() {
        let cli = crate::Cli::parse_from(["linpodx", "logs", "--follow", "my-cont"]);
        match cli.cmd {
            Cmd::Logs { follow, since, id } => {
                assert!(follow);
                assert!(since.is_none());
                assert_eq!(id, "my-cont");
            }
            other => panic!("expected Logs subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_logs_default_does_not_follow() {
        let cli = crate::Cli::parse_from(["linpodx", "logs", "my-cont"]);
        match cli.cmd {
            Cmd::Logs { follow, .. } => assert!(!follow),
            other => panic!("expected Logs subcommand, got {other:?}"),
        }
    }
}
