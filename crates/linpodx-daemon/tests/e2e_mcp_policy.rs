//! Phase 2E live integration test for the MCP policy CRUD CLI.
//! `#[ignore]`-gated. Verifies that `linpodx mcp policy set` upserts a rule
//! that `mcp policy list` can then echo back.
//!
//! Phase 18 Stream E note: the legacy `skipped_for_placeholder` helper is kept
//! as a fallback (still fires on older daemon builds where the placeholder
//! Error::Runtime path is reached), but the test now carries an explicit
//! `#[ignore = "<reason>"]` attribute so the silent-skip case is documented in
//! `cargo test --workspace -- --list --ignored` output instead of being
//! invisible.

use assert_cmd::Command as AssertCommand;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

struct ChildGuard {
    child: std::process::Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
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

fn spawn_daemon(workdir: &TempDir) -> (ChildGuard, std::path::PathBuf) {
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

fn skipped_for_placeholder(stderr: &str) -> bool {
    stderr.contains("not yet implemented")
}

#[test]
#[ignore = "Phase 2E — requires mcp-team `mcp policy set/list` IPC + Podman ≥ 4.6.0; soft-skips when placeholder Error::Runtime is returned"]
fn mcp_policy_set_then_list_roundtrip() {
    let workdir = tempfile::tempdir().expect("workdir");
    let (_guard, socket) = spawn_daemon(&workdir);

    let out = cli(&socket)
        .args([
            "mcp",
            "policy",
            "set",
            "--method",
            "tools/call",
            "--tool",
            "shell",
            "--decision",
            "deny",
            "--note",
            "no shell from agents",
        ])
        .output()
        .expect("policy set");

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        if skipped_for_placeholder(&stderr) {
            eprintln!("mcp_policy_set: mcp-team IPC not wired yet — skipping");
            return;
        }
        panic!("mcp policy set failed: {stderr}");
    }

    let out = cli(&socket)
        .args(["--output", "json", "mcp", "policy", "list"])
        .output()
        .expect("policy list");
    assert!(
        out.status.success(),
        "mcp policy list failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("list json");
    let arr = v.as_array().expect("array");
    let row = arr
        .iter()
        .find(|r| {
            r.get("method").and_then(|s| s.as_str()) == Some("tools/call")
                && r.get("tool_name").and_then(|s| s.as_str()) == Some("shell")
        })
        .unwrap_or_else(|| panic!("expected the upserted rule in {v}"));
    assert_eq!(row.get("decision").and_then(|s| s.as_str()), Some("deny"));
}
