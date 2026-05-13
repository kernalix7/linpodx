//! End-to-end test: spawn the real daemon as a subprocess, drive it with the
//! real `linpodx` CLI binary, and verify a full container lifecycle.
//!
//! Marked `#[ignore]` because it requires Podman (>= MIN_PODMAN_VERSION) on the
//! host. Run explicitly with `cargo test --workspace -- --ignored`.

use assert_cmd::Command as AssertCommand;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

struct DaemonGuard {
    child: std::process::Child,
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        // Best-effort SIGKILL — graceful shutdown isn't needed for the test
        // because the entire run uses a disposable podman root + socket dir.
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

fn spawn_daemon(workdir: &TempDir) -> (DaemonGuard, std::path::PathBuf) {
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
        .env("RUST_LOG", "info,linpodx=debug")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn daemon");

    let guard = DaemonGuard { child };

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
fn end_to_end_alpine_lifecycle() {
    let workdir = tempfile::tempdir().expect("workdir");
    let (_guard, socket) = spawn_daemon(&workdir);

    // version: client + daemon should agree on IPC version.
    cli(&socket)
        .args(["--output", "json", "version"])
        .assert()
        .success();

    // ps --all on a fresh root should show an empty list.
    let out = cli(&socket)
        .args(["--output", "json", "ps", "--all"])
        .output()
        .expect("ps");
    assert!(
        out.status.success(),
        "ps failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let listed: serde_json::Value = serde_json::from_slice(&out.stdout).expect("ps json");
    assert!(listed.as_array().map(|a| a.is_empty()).unwrap_or(false));

    // run a short-lived alpine container.
    let out = cli(&socket)
        .args([
            "run",
            "--name",
            "linpodx-e2e",
            "docker.io/library/alpine:latest",
            "sleep",
            "30",
        ])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let id = String::from_utf8(out.stdout)
        .expect("run stdout")
        .trim()
        .to_string();
    assert!(!id.is_empty(), "run returned empty id");

    // ps --all should now list it.
    let out = cli(&socket)
        .args(["--output", "json", "ps", "--all"])
        .output()
        .expect("ps2");
    let listed: serde_json::Value = serde_json::from_slice(&out.stdout).expect("ps2 json");
    assert!(
        listed.as_array().map(|a| !a.is_empty()).unwrap_or(false),
        "expected container in ps, got {listed}"
    );

    // inspect should return JSON with our id.
    let out = cli(&socket)
        .args(["inspect", &id])
        .output()
        .expect("inspect");
    assert!(
        out.status.success(),
        "inspect failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let inspect_json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("inspect json");
    assert!(inspect_json.get("name").is_some());

    // stop and remove.
    cli(&socket)
        .args(["stop", "-t", "2", &id])
        .assert()
        .success();
    cli(&socket).args(["rm", "-f", &id]).assert().success();

    // ps --all should be empty again.
    let out = cli(&socket)
        .args(["--output", "json", "ps", "--all"])
        .output()
        .expect("ps3");
    let listed: serde_json::Value = serde_json::from_slice(&out.stdout).expect("ps3 json");
    assert!(listed.as_array().map(|a| a.is_empty()).unwrap_or(false));
}
