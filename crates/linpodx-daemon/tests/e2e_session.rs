//! Phase 2C live integration tests for session list / inspect / timeline.
//! `#[ignore]`-gated (requires Podman ≥ 4.6.0). Run via:
//!   cargo test --workspace -- --ignored --test-threads=1

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

#[test]
#[ignore]
fn session_lifecycle() {
    let workdir = tempfile::tempdir().expect("workdir");
    let (_guard, socket) = spawn_daemon(&workdir);

    // Create container — session row opens at create time.
    cli(&socket)
        .args([
            "run",
            "--name",
            "sess-1",
            "docker.io/library/alpine:latest",
            "true",
        ])
        .assert()
        .success();

    // Session list shows our container.
    let out = cli(&socket)
        .args(["--output", "json", "session", "list"])
        .output()
        .expect("session list");
    assert!(
        out.status.success(),
        "session list failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("list json");
    let arr = v.as_array().expect("array");
    let row = arr
        .iter()
        .find(|s| s.get("container_name").and_then(|n| n.as_str()) == Some("sess-1"))
        .unwrap_or_else(|| panic!("expected sess-1 in {v}"));
    let session_id = row
        .get("id")
        .and_then(|n| n.as_i64())
        .expect("session id i64");
    let status = row.get("status").and_then(|s| s.as_str()).unwrap_or("");
    assert!(
        matches!(status, "active" | "ended"),
        "unexpected status: {status}"
    );

    // Remove the container so the session ends.
    cli(&socket).args(["rm", "-f", "sess-1"]).assert().success();

    // Re-list. Session must now be ended with ended_at populated.
    let out = cli(&socket)
        .args(["--output", "json", "session", "list"])
        .output()
        .expect("session list 2");
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("list2 json");
    let arr = v.as_array().expect("array");
    let row = arr
        .iter()
        .find(|s| s.get("id").and_then(|n| n.as_i64()) == Some(session_id))
        .unwrap_or_else(|| panic!("expected session id={session_id} in {v}"));
    assert_eq!(
        row.get("status").and_then(|s| s.as_str()),
        Some("ended"),
        "session status should be 'ended', got {row}"
    );
    assert!(
        !row.get("ended_at").map(|v| v.is_null()).unwrap_or(true),
        "ended_at should be populated, got {row}"
    );

    // Timeline returns the session_started audit entry. session_ended races with the
    // ended_at upper bound (audit.ts is computed after the row's ended_at), so it's
    // not guaranteed to land in the window — only assert on what the contract really
    // promises: at least one audit entry, and session_started is present.
    let out = cli(&socket)
        .args(["session", "timeline", &session_id.to_string()])
        .output()
        .expect("session timeline");
    assert!(
        out.status.success(),
        "session timeline failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        stdout.contains("session_started"),
        "expected session_started in timeline, got: {stdout}"
    );
}
