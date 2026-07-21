//! Phase 18 — first-run reliability end-to-end smoke tests (Stream E).
//!
//! Seven `#[ignore]`-gated scenarios that drive the freshly-landed Phase 18
//! surfaces: installer dry-run, `linpodx doctor`, daemon lifecycle, the
//! docker-compat alias, shell completion, the INSTALL.md doc, and the GUI
//! graceful-launch path. Each scenario soft-skips (via the shared
//! [`skipped_for_placeholder`] helper) when the dispatch arm or binary it
//! needs is still a Phase 18 placeholder — that way the file is callable the
//! moment Stage 1 lands and tightens up automatically as Streams A/B/C/D/G
//! ship their fills.
//!
//! Scenarios (each `#[test] #[ignore = "<reason>"]` so the default
//! `cargo test --workspace` count stays at the 829/0/54 baseline):
//!
//!   1. `installer_dry_run_emits_summary` — `install.sh --dry-run` exits 0
//!      and prints the planned target paths.
//!   2. `doctor_emits_json_envelope` — `linpodx doctor --json` returns a
//!      `DoctorRunResponse` JSON envelope with `checks` non-empty.
//!   3. `daemon_start_stop_roundtrip` — `linpodx daemon start --fork
//!      --pid-file <tmp>` → `linpodx daemon status` → `linpodx daemon stop`
//!      exits 0 with no orphan pid-file.
//!   4. `cli_docker_alias_runs` — `linpodx docker ps` (top-level alias) is
//!      accepted and routes to the same handler as `linpodx ps`. Falls
//!      back to verifying the per-resource alias (`linpodx image ls`) when
//!      the top-level `docker` alias is not yet wired.
//!   5. `shell_completion_generates_bash` — `linpodx completion bash`
//!      writes a non-empty bash completion script.
//!   6. `docs_install_guide_present` — `docs/INSTALL.md` exists at the
//!      workspace root and is non-trivial (>20 lines).
//!   7. `gui_launch_graceful_when_socket_missing` — `linpodx-gui
//!      --probe-only` (or `LINPODX_GUI_NO_DAEMON=1`) exits 0 with a
//!      friendly "daemon not running" message rather than panicking.
//!
//! Run via:
//!   `cargo test -p linpodx-phase17-integration --test phase18_e2e_smoke \
//!       -- --ignored --test-threads=1`
//!
//! Or the workspace-wide opt-in:
//!   `cargo test --workspace -- --ignored --test-threads=1`

#![forbid(unsafe_code)]
#![allow(dead_code)]

use assert_cmd::Command as AssertCommand;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Shared harness helpers.
// ---------------------------------------------------------------------------

/// Marker recognised across the Phase 18 daemon dispatch placeholders. When
/// the dispatch arm still returns `Error::Runtime { message: "not yet
/// implemented (Phase 18 Stream X — …)" }`, every CLI command targeting it
/// surfaces the substring in stderr.
pub fn skipped_for_placeholder(stderr: &str) -> bool {
    stderr.contains("not yet implemented")
}

struct ChildGuard {
    child: std::process::Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn workspace_root() -> PathBuf {
    // tests/Cargo.toml sits at <root>/tests/, so CARGO_MANIFEST_DIR/.. is
    // the workspace root.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .canonicalize()
        .expect("workspace root canonicalize")
}

fn wait_for_socket(socket: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if socket.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn spawn_daemon(workdir: &TempDir) -> (ChildGuard, PathBuf) {
    let socket = workdir.path().join("linpodx.sock");
    let db = workdir.path().join("state.db");
    let pod_root = workdir.path().join("podman-root");
    let pod_runroot = workdir.path().join("podman-runroot");

    let bin = AssertCommand::cargo_bin("linpodx-daemon")
        .expect("locate linpodx-daemon")
        .get_program()
        .to_owned();

    let child = Command::new(bin)
        .arg("--socket")
        .arg(&socket)
        .arg("--db")
        .arg(&db)
        .arg("--podman-root")
        .arg(&pod_root)
        .arg("--podman-runroot")
        .arg(&pod_runroot)
        .arg("--log-pretty")
        .env("RUST_LOG", "warn")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn daemon");

    let guard = ChildGuard { child };
    if !wait_for_socket(&socket, Duration::from_secs(15)) {
        panic!(
            "daemon did not create socket {} within timeout",
            socket.display()
        );
    }
    (guard, socket)
}

fn cli(socket: &Path) -> AssertCommand {
    let mut c = AssertCommand::cargo_bin("linpodx").expect("locate linpodx");
    c.arg("--socket").arg(socket);
    c
}

// ---------------------------------------------------------------------------
// (1) Installer dry-run — `install.sh --dry-run`.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "Phase 18 Stream A — requires install.sh `--dry-run` support; soft-skips otherwise"]
fn installer_dry_run_emits_summary() {
    let installer = workspace_root().join("install.sh");
    assert!(
        installer.exists(),
        "install.sh missing at workspace root: {}",
        installer.display()
    );

    let out = Command::new("bash")
        .arg(&installer)
        .arg("--dry-run")
        .env("LINPODX_ASSUME_YES", "1")
        .env("LINPODX_SKIP_DEPS", "1")
        .output()
        .expect("spawn install.sh");

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        // Treat "unrecognised --dry-run flag" as a soft skip — Stream A
        // has not landed dry-run support yet.
        if stderr.contains("--dry-run")
            && (stderr.contains("unknown") || stderr.contains("unrecognized"))
        {
            eprintln!("installer_dry_run: install.sh has no --dry-run yet — skipping");
            return;
        }
        if skipped_for_placeholder(&stderr) {
            eprintln!("installer_dry_run: Stream A placeholder — skipping");
            return;
        }
        panic!("install.sh --dry-run failed: {stderr}");
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    // Summary should at minimum mention `BIN_DIR` or `INSTALL_DIR` or
    // `~/.local/bin` — the install.sh top-of-file constants.
    assert!(
        stdout.contains("BIN_DIR")
            || stdout.contains("INSTALL_DIR")
            || stdout.contains(".local/bin"),
        "expected install.sh --dry-run to print target paths, got:\n{stdout}"
    );
}

// ---------------------------------------------------------------------------
// (2) `linpodx doctor --json` envelope shape.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "Phase 18 Stream C — requires DoctorRun dispatch fill; soft-skips on placeholder"]
fn doctor_emits_json_envelope() {
    let workdir = tempfile::tempdir().expect("workdir");
    let (_guard, socket) = spawn_daemon(&workdir);

    let out = cli(&socket)
        .args(["doctor", "--json"])
        .output()
        .expect("spawn linpodx doctor");

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        if skipped_for_placeholder(&stderr) {
            eprintln!("doctor: Stream C placeholder — skipping");
            return;
        }
        // `linpodx doctor` may exit non-zero when one or more checks fail
        // (e.g. podman missing). That is still a valid envelope — fall
        // through to JSON validation rather than panicking.
    }

    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("doctor --json: malformed envelope");

    // Validate the DoctorRunResponse shape: checks array + count fields.
    let checks = v
        .get("checks")
        .and_then(|c| c.as_array())
        .expect("doctor envelope missing `checks`");
    assert!(
        !checks.is_empty(),
        "doctor `checks` array must be non-empty"
    );
    assert!(
        v.get("pass_count").and_then(|n| n.as_u64()).is_some(),
        "doctor envelope missing `pass_count`: {v}"
    );
    assert!(
        v.get("warn_count").and_then(|n| n.as_u64()).is_some(),
        "doctor envelope missing `warn_count`: {v}"
    );
    assert!(
        v.get("fail_count").and_then(|n| n.as_u64()).is_some(),
        "doctor envelope missing `fail_count`: {v}"
    );
}

// ---------------------------------------------------------------------------
// (3) Daemon mgmt — start --fork → status → stop.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "Phase 18 Stream D — requires DaemonMgmtStart/Stop/Status fill; soft-skips on placeholder"]
fn daemon_start_stop_roundtrip() {
    let workdir = tempfile::tempdir().expect("workdir");
    let pid_file = workdir.path().join("linpodx.pid");
    let socket = workdir.path().join("linpodx.sock");

    let mut start = AssertCommand::cargo_bin("linpodx").expect("locate linpodx");
    let out = start
        .args([
            "daemon",
            "start",
            "--fork",
            "--pid-file",
            &pid_file.display().to_string(),
            "--socket",
            &socket.display().to_string(),
        ])
        .output()
        .expect("spawn linpodx daemon start");

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        if skipped_for_placeholder(&stderr) {
            eprintln!("daemon start: Stream D placeholder — skipping");
            return;
        }
        panic!("daemon start failed: {stderr}");
    }

    // Status should report `running` with a pid.
    let mut status = AssertCommand::cargo_bin("linpodx").expect("locate linpodx");
    let out = status
        .args([
            "daemon",
            "status",
            "--json",
            "--pid-file",
            &pid_file.display().to_string(),
            "--socket",
            &socket.display().to_string(),
        ])
        .output()
        .expect("spawn linpodx daemon status");
    assert!(
        out.status.success(),
        "daemon status failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("daemon status: bad JSON");
    let state = v.get("state").and_then(|s| s.as_str()).unwrap_or("");
    assert_eq!(state, "running", "daemon status state: {v}");

    // Stop and verify the pid-file is cleaned up.
    let mut stop = AssertCommand::cargo_bin("linpodx").expect("locate linpodx");
    let out = stop
        .args([
            "daemon",
            "stop",
            "--pid-file",
            &pid_file.display().to_string(),
        ])
        .output()
        .expect("spawn linpodx daemon stop");
    assert!(
        out.status.success(),
        "daemon stop failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Give the OS a beat to flush the pid-file removal.
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        !pid_file.exists(),
        "orphan pid-file remained at {}",
        pid_file.display()
    );
}

// ---------------------------------------------------------------------------
// (4) `linpodx docker …` top-level alias (or per-resource alias fallback).
// ---------------------------------------------------------------------------

#[test]
#[ignore = "Phase 18 Stream B — requires `docker` top-level alias OR per-resource alias; soft-skips otherwise"]
fn cli_docker_alias_runs() {
    let workdir = tempfile::tempdir().expect("workdir");
    let (_guard, socket) = spawn_daemon(&workdir);

    // Try the top-level alias first.
    let out = cli(&socket)
        .args(["docker", "ps"])
        .output()
        .expect("spawn linpodx docker ps");

    if out.status.success() {
        // Top-level alias works — done.
        return;
    }
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if stderr.contains("unrecognized subcommand")
        || stderr.contains("invalid subcommand")
        || stderr.contains("error: unrecognised")
    {
        // Fall back to the per-resource alias `linpodx image ls`. That
        // alias landed in Stream B (`#[command(visible_alias = "image")]`
        // on `Cmd::Images`) and proves the docker-compat surface exists.
        let out = cli(&socket)
            .args(["image", "ls"])
            .output()
            .expect("spawn linpodx image ls");
        assert!(
            out.status.success(),
            "neither `linpodx docker ps` nor the `image` alias worked: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }
    if skipped_for_placeholder(&stderr) {
        eprintln!("docker alias: Stream B placeholder — skipping");
        return;
    }
    panic!("`linpodx docker ps` failed: {stderr}");
}

// ---------------------------------------------------------------------------
// (5) Shell completion generation.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "Phase 18 Stream B — requires `linpodx completion <shell>`; soft-skips otherwise"]
fn shell_completion_generates_bash() {
    // No daemon needed — completion doesn't open an IPC connection.
    let mut bin = AssertCommand::cargo_bin("linpodx").expect("locate linpodx");
    let out = bin
        .args(["completion", "bash"])
        .output()
        .expect("spawn linpodx completion bash");

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        if stderr.contains("unrecognized subcommand")
            || stderr.contains("invalid subcommand")
            || skipped_for_placeholder(&stderr)
        {
            eprintln!("completion: Stream B placeholder — skipping");
            return;
        }
        panic!("linpodx completion bash failed: {stderr}");
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.trim().is_empty(),
        "linpodx completion bash produced empty script"
    );
    // A clap-generated bash completion script has the function header
    // `_linpodx()` (or similar) and at minimum mentions `complete -F`.
    assert!(
        stdout.contains("complete ") || stdout.contains("_linpodx"),
        "completion script does not look like bash completion:\n{stdout}"
    );
}

// ---------------------------------------------------------------------------
// (6) docs/INSTALL.md presence + non-triviality.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "Phase 18 Stream F — verifies docs/INSTALL.md was committed; safe to flip to non-ignore once F lands"]
fn docs_install_guide_present() {
    let install_md = workspace_root().join("docs").join("INSTALL.md");
    assert!(
        install_md.exists(),
        "docs/INSTALL.md missing at {}",
        install_md.display()
    );

    let contents = std::fs::read_to_string(&install_md).expect("read INSTALL.md");
    let line_count = contents.lines().count();
    assert!(
        line_count > 20,
        "docs/INSTALL.md is too short ({line_count} lines) — expected > 20"
    );
    // Sanity check: should mention at least one of the supported install
    // paths so it is actually a *guide*, not a stub.
    assert!(
        contents.contains("install.sh")
            || contents.contains("cargo install")
            || contents.contains(".deb")
            || contents.contains(".rpm"),
        "docs/INSTALL.md does not mention a known install path"
    );
}

// ---------------------------------------------------------------------------
// (7) GUI graceful-launch when the daemon socket is missing.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "Phase 18 Stream G — requires linpodx-gui `--probe-only` or LINPODX_GUI_NO_DAEMON=1; soft-skips otherwise"]
fn gui_launch_graceful_when_socket_missing() {
    let bin = match AssertCommand::cargo_bin("linpodx-gui") {
        Ok(b) => b.get_program().to_owned(),
        Err(_) => {
            eprintln!("gui_launch: linpodx-gui binary not built — skipping");
            return;
        }
    };

    // Point at a deliberately-nonexistent socket path so we exercise the
    // "daemon not running" path.
    let workdir = tempfile::tempdir().expect("workdir");
    let bogus_socket = workdir.path().join("not-a-socket.sock");

    let out = Command::new(&bin)
        .arg("--probe-only")
        .env("LINPODX_GUI_NO_DAEMON", "1")
        .env("LINPODX_SOCKET", &bogus_socket)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    let out = match out {
        Ok(o) => o,
        Err(e) => {
            eprintln!("gui_launch: spawn failed ({e}) — skipping");
            return;
        }
    };

    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let combined = format!("{stdout}\n{stderr}");

    if stderr.contains("unexpected argument")
        || stderr.contains("error: unrecognised")
        || (stderr.contains("--probe-only") && stderr.contains("unknown"))
    {
        eprintln!("gui_launch: linpodx-gui has no --probe-only yet — skipping");
        return;
    }
    if skipped_for_placeholder(&stderr) {
        eprintln!("gui_launch: Stream G placeholder — skipping");
        return;
    }

    assert!(
        out.status.success(),
        "linpodx-gui --probe-only must exit 0 when daemon is missing, got:\n{combined}"
    );

    // Must NOT have panicked — exit-0 already implies that, but check the
    // panic-marker for belt-and-braces.
    assert!(
        !combined.contains("panicked at") && !combined.contains("thread 'main' panicked"),
        "linpodx-gui panicked on missing daemon:\n{combined}"
    );
}
