//! `linpodx doctor` — first-run readiness diagnostics (Phase 18 Stream C).
//!
//! Walks a fixed environment checklist by asking the daemon for the structured
//! report and rendering it either as a coloured table (default) or raw JSON
//! (`--json`, machine-parsable). The dispatch body lives in
//! `linpodx-daemon::dispatch::Dispatcher::run_doctor`; the CLI is only
//! responsible for the human-readable rendering.
//!
//! Stable exit codes:
//!   `0` → every check passed (or only warnings).
//!   `1` → at least one `fail` outcome — surfaced so shell pipelines can fail
//!         (`linpodx doctor && cargo build`).
//!   `2` → IPC error / unreachable daemon.
//!
//! Output style mirrors `cargo` / `pre-commit`: status icon + label, optional
//! detail line, optional fix-hint indented under the row.

use crate::client::Client;
use anyhow::{Context, Result};
use clap::Args;
use linpodx_common::ipc::{responses, DoctorRunParams, Method};
use std::io::{self, IsTerminal, Write};

/// `linpodx doctor` flags.
#[derive(Args, Debug, Default, Clone)]
pub struct DoctorArgs {
    /// Print the report as JSON instead of a human-readable table.
    #[arg(long)]
    pub json: bool,
    /// Show the optional `detail` and `fix_hint` lines even on passing checks.
    #[arg(long, short = 'v')]
    pub verbose: bool,
}

/// Coloured status icon for a single check, suppressing ANSI codes when stdout
/// is not a TTY (or `NO_COLOR` is set) so piped output stays clean.
fn status_icon(outcome: responses::DoctorOutcome, colour: bool) -> &'static str {
    if !colour {
        return match outcome {
            responses::DoctorOutcome::Pass => "[OK]  ",
            responses::DoctorOutcome::Warn => "[WARN]",
            responses::DoctorOutcome::Fail => "[FAIL]",
        };
    }
    match outcome {
        responses::DoctorOutcome::Pass => "\x1b[32m[OK]\x1b[0m  ",
        responses::DoctorOutcome::Warn => "\x1b[33m[WARN]\x1b[0m",
        responses::DoctorOutcome::Fail => "\x1b[31m[FAIL]\x1b[0m",
    }
}

/// Whether the running terminal should receive ANSI colour codes.
fn want_colour() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    io::stdout().is_terminal()
}

/// Render `report` to `out` as a human-readable table. Used in tests with a
/// `Vec<u8>` sink and at runtime with `io::stdout()`.
pub fn render_text<W: Write>(
    out: &mut W,
    report: &responses::DoctorRunResponse,
    verbose: bool,
    colour: bool,
) -> io::Result<()> {
    writeln!(out, "linpodx doctor — first-run readiness")?;
    writeln!(out)?;
    for check in &report.checks {
        writeln!(
            out,
            "{}  {:<28}  {}",
            status_icon(check.outcome, colour),
            check.label,
            check.detail.as_deref().unwrap_or(match check.outcome {
                responses::DoctorOutcome::Pass => "ok",
                responses::DoctorOutcome::Warn => "needs attention",
                responses::DoctorOutcome::Fail => "blocker",
            }),
        )?;
        if let Some(hint) = check.fix_hint.as_deref() {
            let show = matches!(
                check.outcome,
                responses::DoctorOutcome::Warn | responses::DoctorOutcome::Fail
            ) || verbose;
            if show {
                writeln!(out, "         fix: {hint}")?;
            }
        }
    }
    writeln!(out)?;
    writeln!(
        out,
        "summary: {} pass / {} warn / {} fail",
        report.pass_count, report.warn_count, report.fail_count
    )?;
    Ok(())
}

/// Compute the exit code from a report. Pulled out for unit testing.
pub fn exit_code(report: &responses::DoctorRunResponse) -> i32 {
    if report.fail_count > 0 {
        1
    } else {
        0
    }
}

/// Entry point invoked by `main.rs`. Returns the requested exit code so the
/// CLI's outer `main` can propagate it via `std::process::exit`.
pub async fn handle(client: &mut Client, args: DoctorArgs) -> Result<i32> {
    let report: responses::DoctorRunResponse = client
        .call(Method::DoctorRun(DoctorRunParams { json: args.json }))
        .await
        .context("calling doctor.run on the daemon")?;

    if args.json {
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        serde_json::to_writer_pretty(&mut handle, &report)
            .context("serialising doctor report as JSON")?;
        handle.write_all(b"\n").ok();
    } else {
        let colour = want_colour();
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        render_text(&mut handle, &report, args.verbose, colour)
            .context("rendering doctor report")?;
    }

    Ok(exit_code(&report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use linpodx_common::ipc::responses::{DoctorCheck, DoctorOutcome, DoctorRunResponse};

    fn check(
        id: &str,
        outcome: DoctorOutcome,
        detail: Option<&str>,
        hint: Option<&str>,
    ) -> DoctorCheck {
        DoctorCheck {
            id: id.to_string(),
            label: id.to_string(),
            outcome,
            detail: detail.map(str::to_string),
            fix_hint: hint.map(str::to_string),
        }
    }

    fn report_all_pass() -> DoctorRunResponse {
        DoctorRunResponse {
            checks: vec![
                check("podman", DoctorOutcome::Pass, Some("podman 4.9.4"), None),
                check("rootless", DoctorOutcome::Pass, Some("rootless"), None),
            ],
            pass_count: 2,
            warn_count: 0,
            fail_count: 0,
        }
    }

    fn report_mixed() -> DoctorRunResponse {
        DoctorRunResponse {
            checks: vec![
                check(
                    "podman",
                    DoctorOutcome::Fail,
                    Some("podman not found in PATH"),
                    Some("sudo apt install podman / sudo dnf install podman"),
                ),
                check(
                    "wayland",
                    DoctorOutcome::Warn,
                    Some("XDG_SESSION_TYPE unset"),
                    Some("set XDG_SESSION_TYPE=wayland in your shell rc"),
                ),
                check("db_dir", DoctorOutcome::Pass, None, None),
            ],
            pass_count: 1,
            warn_count: 1,
            fail_count: 1,
        }
    }

    #[test]
    fn exit_code_pass() {
        assert_eq!(exit_code(&report_all_pass()), 0);
    }

    #[test]
    fn exit_code_warn_only_is_zero() {
        let r = DoctorRunResponse {
            checks: vec![check("x", DoctorOutcome::Warn, None, None)],
            pass_count: 0,
            warn_count: 1,
            fail_count: 0,
        };
        assert_eq!(exit_code(&r), 0);
    }

    #[test]
    fn exit_code_fail() {
        assert_eq!(exit_code(&report_mixed()), 1);
    }

    #[test]
    fn icon_no_colour() {
        assert_eq!(status_icon(DoctorOutcome::Pass, false), "[OK]  ");
        assert_eq!(status_icon(DoctorOutcome::Warn, false), "[WARN]");
        assert_eq!(status_icon(DoctorOutcome::Fail, false), "[FAIL]");
    }

    #[test]
    fn icon_with_colour() {
        // The exact ANSI string contains escape codes; we only verify that the
        // outcome maps to a distinct, non-empty marker so a regression that
        // swaps Pass↔Fail would be caught.
        let a = status_icon(DoctorOutcome::Pass, true);
        let b = status_icon(DoctorOutcome::Warn, true);
        let c = status_icon(DoctorOutcome::Fail, true);
        assert!(a.contains("32"));
        assert!(b.contains("33"));
        assert!(c.contains("31"));
    }

    #[test]
    fn render_text_all_pass_no_colour() {
        let r = report_all_pass();
        let mut buf = Vec::new();
        render_text(&mut buf, &r, false, false).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("linpodx doctor"));
        assert!(s.contains("[OK]"));
        assert!(s.contains("podman 4.9.4"));
        assert!(s.contains("2 pass / 0 warn / 0 fail"));
        // No fix hint shown when no fix hint is set
        assert!(!s.contains("fix:"));
    }

    #[test]
    fn render_text_mixed_shows_fix_for_warn_and_fail() {
        let r = report_mixed();
        let mut buf = Vec::new();
        render_text(&mut buf, &r, false, false).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("[FAIL]"));
        assert!(s.contains("[WARN]"));
        assert!(s.contains("fix: sudo apt install podman"));
        assert!(s.contains("fix: set XDG_SESSION_TYPE=wayland"));
        // Pass row has no hint
        assert!(!s.contains("fix: ok"));
        assert!(s.contains("1 pass / 1 warn / 1 fail"));
    }

    #[test]
    fn render_text_verbose_shows_pass_hint() {
        let report = DoctorRunResponse {
            checks: vec![check(
                "podman",
                DoctorOutcome::Pass,
                Some("podman 4.9.4"),
                Some("see docs/INSTALL.md"),
            )],
            pass_count: 1,
            warn_count: 0,
            fail_count: 0,
        };
        let mut buf = Vec::new();
        render_text(&mut buf, &report, true, false).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("fix: see docs/INSTALL.md"));
    }

    #[test]
    fn render_text_non_verbose_omits_pass_hint() {
        let report = DoctorRunResponse {
            checks: vec![check(
                "podman",
                DoctorOutcome::Pass,
                Some("podman 4.9.4"),
                Some("see docs/INSTALL.md"),
            )],
            pass_count: 1,
            warn_count: 0,
            fail_count: 0,
        };
        let mut buf = Vec::new();
        render_text(&mut buf, &report, false, false).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(!s.contains("fix:"));
    }

    #[test]
    fn json_round_trip_preserves_outcomes_and_counts() {
        let r = report_mixed();
        let s = serde_json::to_string(&r).expect("serialise");
        // The discriminant names are part of the public schema — snake-case.
        assert!(s.contains("\"fail\""));
        assert!(s.contains("\"warn\""));
        assert!(s.contains("\"pass\""));
        // Round-trip back.
        let back: DoctorRunResponse = serde_json::from_str(&s).expect("deserialise");
        assert_eq!(back.fail_count, 1);
        assert_eq!(back.warn_count, 1);
        assert_eq!(back.pass_count, 1);
        assert_eq!(back.checks.len(), 3);
    }

    #[test]
    fn render_text_uses_default_detail_for_missing() {
        let report = DoctorRunResponse {
            checks: vec![check("db_dir", DoctorOutcome::Pass, None, None)],
            pass_count: 1,
            warn_count: 0,
            fail_count: 0,
        };
        let mut buf = Vec::new();
        render_text(&mut buf, &report, false, false).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("db_dir"));
        assert!(s.contains(" ok"));
    }
}
