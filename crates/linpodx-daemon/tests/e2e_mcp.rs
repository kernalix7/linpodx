//! Phase 2D live integration tests for the MCP host-stdio bridge.
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
fn mcp_bridge_lifecycle() {
    let workdir = tempfile::tempdir().expect("workdir");
    let (_guard, socket) = spawn_daemon(&workdir);

    // Container the bridge attaches to.
    cli(&socket)
        .args([
            "run",
            "--name",
            "mcp-target",
            "docker.io/library/alpine:latest",
            "sleep",
            "30",
        ])
        .assert()
        .success();

    // Start a bridge using `cat` as a no-op host MCP "server".
    let out = cli(&socket)
        .args(["mcp", "start", "mcp-target", "/bin/cat"])
        .output()
        .expect("mcp start");
    assert!(
        out.status.success(),
        "mcp start failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let bridge_id = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(bridge_id.starts_with("br-"), "got bridge_id={bridge_id}");

    // Status should list exactly one bridge.
    let out = cli(&socket)
        .args(["--output", "json", "mcp", "status"])
        .output()
        .expect("mcp status");
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("status json");
    let arr = v.as_array().expect("array");
    assert!(
        arr.iter()
            .any(|e| e.get("bridge_id").and_then(|s| s.as_str()) == Some(bridge_id.as_str())),
        "expected bridge_id={bridge_id} in status, got {v}"
    );

    // Audit must show McpBridgeStarted.
    let out = cli(&socket)
        .args([
            "sandbox",
            "audit",
            "--kind",
            "mcp_bridge_started",
            "--limit",
            "10",
            "--json",
        ])
        .output()
        .expect("audit started");
    assert!(out.status.success());
    let entries: serde_json::Value = serde_json::from_slice(&out.stdout).expect("audit json");
    assert!(
        entries.as_array().map(|a| !a.is_empty()).unwrap_or(false),
        "expected mcp_bridge_started audit entry, got {entries}"
    );

    // Stop the bridge.
    let out = cli(&socket)
        .args(["mcp", "stop", &bridge_id])
        .output()
        .expect("mcp stop");
    assert!(
        out.status.success(),
        "mcp stop failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stopped_id = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert_eq!(stopped_id, bridge_id, "stop should echo the bridge id");

    // Audit must show McpBridgeStopped.
    let out = cli(&socket)
        .args([
            "sandbox",
            "audit",
            "--kind",
            "mcp_bridge_stopped",
            "--limit",
            "10",
            "--json",
        ])
        .output()
        .expect("audit stopped");
    assert!(out.status.success());
    let entries: serde_json::Value = serde_json::from_slice(&out.stdout).expect("audit json");
    assert!(
        entries.as_array().map(|a| !a.is_empty()).unwrap_or(false),
        "expected mcp_bridge_stopped audit entry, got {entries}"
    );

    // Cleanup the container.
    cli(&socket)
        .args(["rm", "-f", "mcp-target"])
        .assert()
        .success();
}
