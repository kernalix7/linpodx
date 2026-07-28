//! `linpodx secret {ls,create,rm}` — podman secret management against the
//! Phase 27 `Method::Secret*` IPC surface.
//!
//! Secret **values** never touch argv, environment, or any log/output path:
//! `create` takes only a `NAME` argument and reads the value from stdin —
//! either piped (`printf '%s' "$VALUE" | linpodx secret create db-pass`) or,
//! when stdin is a real terminal, an interactive hidden prompt (crossterm
//! raw mode, no echo, same mechanism `commands::exec`'s PTY path uses for
//! the terminal itself). There is intentionally no `--value` flag — that
//! would land the secret in `ps aux` output and shell history.

#![forbid(unsafe_code)]

use crate::client::Client;
use crate::output::OutputFormat;
use anyhow::{bail, Context, Result};
use clap::Subcommand;
use comfy_table::{presets::UTF8_FULL, Cell, ContentArrangement, Table};
use linpodx_common::ipc::{
    responses::{SecretCreateResponse, SecretListResponse, SecretRemoveResponse},
    Method, SecretCreateParams, SecretRemoveParams,
};
use std::io::{IsTerminal, Read, Write};

#[derive(Subcommand, Debug)]
pub(crate) enum SecretCmd {
    /// List secrets.
    Ls,
    /// Create a secret. The value is read from stdin — piped, or an
    /// interactive hidden prompt when stdin is a terminal — never as an
    /// argument.
    Create {
        /// Secret name.
        name: String,
    },
    /// Remove a secret.
    Rm {
        /// Skip the confirmation prompt.
        #[arg(short = 'f', long)]
        force: bool,
        /// Secret name.
        name: String,
    },
}

pub(crate) async fn handle_secret(
    client: &mut Client,
    fmt: OutputFormat,
    cmd: SecretCmd,
) -> Result<()> {
    match cmd {
        SecretCmd::Ls => {
            let resp: SecretListResponse = client.call(Method::SecretList).await?;
            print_secret_list(&resp, fmt)?;
        }
        SecretCmd::Create { name } => {
            let value = read_secret_value()?;
            let resp: SecretCreateResponse = client
                .call(Method::SecretCreate(SecretCreateParams { name, value }))
                .await?;
            print_secret_create(&resp, fmt)?;
        }
        SecretCmd::Rm { force, name } => {
            if !force && !confirm_remove(&name)? {
                bail!("aborted");
            }
            let resp: SecretRemoveResponse = client
                .call(Method::SecretRemove(SecretRemoveParams { name }))
                .await?;
            print_secret_remove(&resp, fmt)?;
        }
    }
    Ok(())
}

/// Reads the secret value from stdin. When stdin is piped/redirected, reads
/// the raw bytes as-is (no trimming — a trailing newline is part of the
/// payload for formats like PEM that require one). When stdin is a real
/// terminal, prompts interactively with echo disabled instead of blocking
/// on an EOF that will never come.
fn read_secret_value() -> Result<String> {
    if std::io::stdin().is_terminal() {
        read_hidden_line("Secret value: ")
    } else {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("reading secret value from stdin")?;
        Ok(buf)
    }
}

/// Interactive, echo-disabled line read via crossterm raw mode. Ctrl-C
/// aborts. The typed value lives only in this local `String`, returned to
/// the caller — it is never printed, logged, or traced.
fn read_hidden_line(prompt: &str) -> Result<String> {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    use crossterm::terminal;

    eprint!("{prompt}");
    std::io::stderr().flush().ok();

    terminal::enable_raw_mode().context("entering raw mode for secret prompt")?;
    struct RawGuard;
    impl Drop for RawGuard {
        fn drop(&mut self) {
            let _ = crossterm::terminal::disable_raw_mode();
        }
    }
    let _guard = RawGuard;

    let mut value = String::new();
    loop {
        if let Event::Key(key) = event::read().context("reading secret input")? {
            if key.kind == KeyEventKind::Release {
                continue;
            }
            match key.code {
                KeyCode::Enter => break,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    drop(_guard);
                    eprintln!();
                    bail!("aborted");
                }
                KeyCode::Backspace => {
                    value.pop();
                }
                KeyCode::Char(c) => value.push(c),
                _ => {}
            }
        }
    }
    drop(_guard);
    eprintln!();
    Ok(value)
}

fn confirm_remove(name: &str) -> Result<bool> {
    if !std::io::stdin().is_terminal() {
        bail!("refusing to remove secret '{name}' without --force on a non-interactive stdin");
    }
    eprint!("Remove secret '{name}'? [y/N] ");
    std::io::stderr().flush().ok();
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("reading confirmation")?;
    let answer = input.trim().to_ascii_lowercase();
    Ok(matches!(answer.as_str(), "y" | "yes"))
}

fn print_json<T: serde::Serialize + ?Sized>(value: &T) -> Result<()> {
    let s = serde_json::to_string_pretty(value)?;
    println!("{s}");
    Ok(())
}

fn print_secret_list(resp: &SecretListResponse, fmt: OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_json(resp),
        OutputFormat::Table => {
            if resp.secrets.is_empty() {
                println!("No secrets.");
                return Ok(());
            }
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec!["SECRET ID", "NAME", "DRIVER", "CREATED"]);
            for secret in &resp.secrets {
                let id_short = if secret.id.len() > 12 {
                    &secret.id[..12]
                } else {
                    &secret.id
                };
                table.add_row(vec![
                    Cell::new(id_short),
                    Cell::new(&secret.name),
                    Cell::new(&secret.driver),
                    Cell::new(&secret.created),
                ]);
            }
            println!("{table}");
            Ok(())
        }
    }
}

fn print_secret_create(resp: &SecretCreateResponse, fmt: OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_json(resp),
        OutputFormat::Table => {
            println!("{} ({})", resp.id, resp.name);
            Ok(())
        }
    }
}

fn print_secret_remove(resp: &SecretRemoveResponse, fmt: OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_json(resp),
        OutputFormat::Table => {
            println!("{} -> removed={}", resp.name, resp.removed);
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
    fn parse_secret_ls() {
        let cli = Cli::parse_from(["linpodx", "secret", "ls"]);
        assert!(matches!(cli.cmd, Cmd::Secret(SecretCmd::Ls)));
    }

    #[test]
    fn parse_secret_create() {
        let cli = Cli::parse_from(["linpodx", "secret", "create", "db-password"]);
        match cli.cmd {
            Cmd::Secret(SecretCmd::Create { name }) => assert_eq!(name, "db-password"),
            other => panic!("expected Secret Create subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_secret_create_rejects_inline_value() {
        // There is intentionally no way to pass the value as a second
        // positional / flag — only `name` is accepted.
        let result = Cli::try_parse_from(["linpodx", "secret", "create", "db-password", "hunter2"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_secret_rm_with_force() {
        let cli = Cli::parse_from(["linpodx", "secret", "rm", "--force", "db-password"]);
        match cli.cmd {
            Cmd::Secret(SecretCmd::Rm { force, name }) => {
                assert!(force);
                assert_eq!(name, "db-password");
            }
            other => panic!("expected Secret Rm subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_secret_rm_default_no_force() {
        let cli = Cli::parse_from(["linpodx", "secret", "rm", "db-password"]);
        match cli.cmd {
            Cmd::Secret(SecretCmd::Rm { force, .. }) => assert!(!force),
            other => panic!("expected Secret Rm subcommand, got {other:?}"),
        }
    }
}
