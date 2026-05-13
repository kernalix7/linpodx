//! End-to-end test for Phase 1B daemon event bus + Subscribe protocol.
//!
//! Spawns the daemon, runs `linpodx events --json` in the background, then triggers a container
//! lifecycle via the CLI and verifies the expected events appear on the events stream.
//!
//! `#[ignore]`-gated (requires Podman ≥ 4.6.0). Run via:
//!   cargo test --workspace -- --ignored --test-threads=1

use assert_cmd::Command as AssertCommand;
use std::io::Read;
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
fn events_stream_receives_container_lifecycle() {
    let workdir = tempfile::tempdir().expect("workdir");
    let (_daemon_guard, socket) = spawn_daemon(&workdir);

    // Spawn `linpodx events --json` capturing stdout.
    let bin = AssertCommand::cargo_bin("linpodx").expect("locate linpodx");
    let events_child = Command::new(bin.get_program())
        .arg("--socket")
        .arg(&socket)
        .arg("events")
        .arg("--json")
        .arg("--topic")
        .arg("container")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn events");
    let mut events_guard = ChildGuard {
        child: events_child,
    };

    // Give the subscriber a moment to settle (Subscribe handshake).
    std::thread::sleep(Duration::from_millis(800));

    // Drive a container lifecycle via the CLI.
    cli(&socket)
        .args([
            "run",
            "--name",
            "ev-probe",
            "docker.io/library/alpine:latest",
            "true",
        ])
        .assert()
        .success();
    cli(&socket)
        .args(["rm", "-f", "ev-probe"])
        .assert()
        .success();

    // Give events a moment to flush, then kill the subscriber and read its stdout.
    std::thread::sleep(Duration::from_millis(500));
    let _ = events_guard.child.kill();
    let mut stdout = events_guard.child.stdout.take().expect("events stdout");
    drop(events_guard); // wait inside Drop

    let mut captured = String::new();
    stdout.read_to_string(&mut captured).ok();

    // Expect at least one of: container.created, container.started, container.removed.
    let saw_created = captured.contains("\"kind\":\"created\"");
    let saw_started = captured.contains("\"kind\":\"started\"");
    let saw_removed = captured.contains("\"kind\":\"removed\"");
    assert!(
        saw_created && saw_started && saw_removed,
        "expected created/started/removed events, captured:\n{captured}"
    );
}
