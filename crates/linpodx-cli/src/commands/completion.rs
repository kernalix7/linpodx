//! Phase 18 Stream B — `linpodx completion <shell>` shell-completion generator.
//!
//! Renders the CLI's full subcommand surface as a completion script for the
//! requested shell. The generated script is written to stdout; users redirect
//! it into the appropriate shell-specific location, e.g.:
//!
//! ```sh
//! # bash
//! linpodx completion bash | sudo tee /etc/bash_completion.d/linpodx >/dev/null
//! # zsh
//! linpodx completion zsh > "${fpath[1]}/_linpodx"
//! # fish
//! linpodx completion fish > ~/.config/fish/completions/linpodx.fish
//! ```
//!
//! Re-exports `clap_complete::Shell` so callers don't need to depend on
//! `clap_complete` directly.
#![forbid(unsafe_code)]

pub use clap_complete::Shell;

use clap::CommandFactory;
use clap_complete::generate;
use std::io::Write;

/// Render the completion script for `shell` to `out`.
///
/// Wraps `clap_complete::generate` so the binary name is hard-pinned to
/// `linpodx` (matching `Cli`'s `#[command(name = "linpodx")]`) and the
/// `clap::Command` is built fresh via `CommandFactory` for each call. This
/// guarantees the script reflects whatever subcommands are currently
/// compiled into the binary, including new docker-compat groups.
pub(crate) fn render<C: CommandFactory, W: Write>(shell: Shell, out: &mut W) {
    let mut cmd = C::command();
    generate(shell, &mut cmd, "linpodx", out);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cli, Cmd};
    use clap::Parser;

    #[test]
    fn parse_completion_accepts_each_clap_complete_shell() {
        for (arg, expected) in [
            ("bash", Shell::Bash),
            ("zsh", Shell::Zsh),
            ("fish", Shell::Fish),
            ("powershell", Shell::PowerShell),
            ("elvish", Shell::Elvish),
        ] {
            let cli = Cli::parse_from(["linpodx", "completion", arg]);
            match cli.cmd {
                Cmd::Completion { shell } => assert_eq!(shell, expected, "{arg}"),
                other => panic!("expected Completion for {arg}, got {other:?}"),
            }
        }
    }

    #[test]
    fn completion_render_produces_non_empty_bash_script() {
        let mut buf: Vec<u8> = Vec::new();
        render::<Cli, _>(Shell::Bash, &mut buf);
        let s = String::from_utf8(buf).expect("bash completion is valid utf-8");
        assert!(
            s.contains("linpodx"),
            "completion script must mention binary name"
        );
        // bash completion uses `complete -F`. zsh / fish / powershell wrappers
        // use different markers; this test pins the bash dialect we ship.
        assert!(
            s.contains("complete "),
            "bash completion script must call `complete`"
        );
    }

    #[test]
    fn completion_render_covers_all_shells_without_panic() {
        for shell in [
            Shell::Bash,
            Shell::Zsh,
            Shell::Fish,
            Shell::PowerShell,
            Shell::Elvish,
        ] {
            let mut buf: Vec<u8> = Vec::new();
            render::<Cli, _>(shell, &mut buf);
            assert!(!buf.is_empty(), "{shell:?} produced an empty script");
        }
    }
}
