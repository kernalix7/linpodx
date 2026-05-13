//! Phase 2B live integration tests for the snapshot lifecycle.
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
fn snapshot_lifecycle() {
    let workdir = tempfile::tempdir().expect("workdir");
    let (_guard, socket) = spawn_daemon(&workdir);

    // Start a long-running container so podman commit has something to snapshot.
    cli(&socket)
        .args([
            "run",
            "--name",
            "snap-target",
            "docker.io/library/alpine:latest",
            "sleep",
            "60",
        ])
        .assert()
        .success();

    // Create snapshot with a label.
    let out = cli(&socket)
        .args(["snapshot", "create", "--label", "v1", "snap-target"])
        .output()
        .expect("snapshot create");
    assert!(
        out.status.success(),
        "snapshot create failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let snap_id: i64 = stdout
        .split('\t')
        .next()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or_else(|| panic!("expected `<id>\\t<image>`, got: {stdout}"));

    // List should show the snapshot.
    let out = cli(&socket)
        .args(["--output", "json", "snapshot", "list"])
        .output()
        .expect("snapshot list");
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("list json");
    let arr = v.as_array().expect("array");
    assert!(
        arr.iter()
            .any(|s| s.get("id").and_then(|n| n.as_i64()) == Some(snap_id)
                && s.get("label").and_then(|l| l.as_str()) == Some("v1")),
        "expected snapshot id={snap_id} label=v1 in {v}"
    );

    // Inspect by id round-trips.
    let out = cli(&socket)
        .args(["snapshot", "inspect", &snap_id.to_string()])
        .output()
        .expect("snapshot inspect");
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("inspect json");
    assert_eq!(v.get("id").and_then(|n| n.as_i64()), Some(snap_id));
    assert_eq!(v.get("label").and_then(|s| s.as_str()), Some("v1"));

    // Audit log should have a snapshot_created entry.
    let out = cli(&socket)
        .args([
            "sandbox",
            "audit",
            "--kind",
            "snapshot_created",
            "--limit",
            "10",
            "--json",
        ])
        .output()
        .expect("audit snapshot_created");
    assert!(out.status.success());
    let entries: serde_json::Value = serde_json::from_slice(&out.stdout).expect("audit json");
    assert!(
        entries.as_array().map(|a| !a.is_empty()).unwrap_or(false),
        "expected at least one snapshot_created entry, got {entries}"
    );

    // Remove with force (snapshot is referenced indirectly by the snap-target container).
    cli(&socket)
        .args(["snapshot", "rm", "--force", &snap_id.to_string()])
        .assert()
        .success();

    // List should be empty for our id.
    let out = cli(&socket)
        .args(["--output", "json", "snapshot", "list"])
        .output()
        .expect("snapshot list 2");
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("list2 json");
    let arr = v.as_array().expect("array");
    assert!(
        arr.iter()
            .all(|s| s.get("id").and_then(|n| n.as_i64()) != Some(snap_id)),
        "snapshot {snap_id} should be gone, got {v}"
    );

    // Cleanup.
    cli(&socket)
        .args(["rm", "-f", "snap-target"])
        .assert()
        .success();
}
