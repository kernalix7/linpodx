//! Phase 2E live integration test for the async snapshot job CLI.
//! `#[ignore]`-gated. Verifies that `snapshot job start` returns a job id and
//! `snapshot job status` reports a terminal state. Treats `not yet implemented`
//! from the runtime-team placeholder as a soft skip.

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

fn poll_until_terminal(socket: &Path, job_id: &str) -> Option<String> {
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        let out = cli(socket)
            .args(["--output", "json", "snapshot", "job", "status", job_id])
            .output()
            .expect("status poll");
        if !out.status.success() {
            return None;
        }
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("status json");
        let status = v
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or("unknown")
            .to_string();
        if matches!(status.as_str(), "succeeded" | "failed") {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    None
}

#[test]
#[ignore]
fn snapshot_job_lifecycle() {
    let workdir = tempfile::tempdir().expect("workdir");
    let (_guard, socket) = spawn_daemon(&workdir);

    cli(&socket)
        .args([
            "run",
            "--name",
            "snap-async-target",
            "docker.io/library/alpine:latest",
            "sleep",
            "60",
        ])
        .assert()
        .success();

    let out = cli(&socket)
        .args([
            "snapshot",
            "job",
            "start",
            "--label",
            "async-v1",
            "snap-async-target",
        ])
        .output()
        .expect("job start");

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        if skipped_for_placeholder(&stderr) {
            eprintln!("snapshot_job_start: runtime-team IPC not wired yet — skipping");
            cli(&socket)
                .args(["rm", "-f", "snap-async-target"])
                .assert()
                .success();
            return;
        }
        cli(&socket)
            .args(["rm", "-f", "snap-async-target"])
            .assert()
            .success();
        panic!("snapshot job start failed: {stderr}");
    }

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let job_id = stdout
        .split('\t')
        .next()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    assert!(
        !job_id.is_empty(),
        "expected `<job_id>\\t<status>`, got: {stdout}"
    );

    let final_status = poll_until_terminal(&socket, &job_id);
    cli(&socket)
        .args(["rm", "-f", "snap-async-target"])
        .assert()
        .success();
    let final_status = final_status.expect("job did not reach a terminal status in time");
    assert!(
        matches!(final_status.as_str(), "succeeded" | "failed"),
        "unexpected terminal status: {final_status}"
    );
}
