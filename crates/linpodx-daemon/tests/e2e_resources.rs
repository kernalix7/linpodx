//! Live integration tests for Phase 1A — image / volume / network management
//! and port mapping. Marked `#[ignore]` (requires Podman ≥ 4.6.0).
//!
//! Run with: `cargo test --workspace -- --ignored`

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
fn images_lifecycle() {
    let workdir = tempfile::tempdir().expect("workdir");
    let (_g, socket) = spawn_daemon(&workdir);

    // ls on empty store.
    let out = cli(&socket)
        .args(["--output", "json", "images", "ls"])
        .output()
        .expect("ls");
    assert!(
        out.status.success(),
        "images ls failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("ls json");
    assert!(v.as_array().map(|a| a.is_empty()).unwrap_or(false));

    // pull alpine.
    let out = cli(&socket)
        .args(["images", "pull", "docker.io/library/alpine:latest"])
        .output()
        .expect("pull");
    assert!(
        out.status.success(),
        "pull failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let id = String::from_utf8(out.stdout)
        .expect("pull stdout")
        .trim()
        .to_string();
    assert!(
        id.starts_with("sha256:") || id.len() >= 12,
        "expected an image id, got '{id}'"
    );

    // ls now returns one image.
    let out = cli(&socket)
        .args(["--output", "json", "images", "ls"])
        .output()
        .expect("ls2");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("ls2 json");
    assert!(
        v.as_array().map(|a| !a.is_empty()).unwrap_or(false),
        "expected images, got {v}"
    );

    // inspect should give us back the image.
    let out = cli(&socket)
        .args(["images", "inspect", "docker.io/library/alpine:latest"])
        .output()
        .expect("inspect");
    assert!(
        out.status.success(),
        "inspect failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let inspect: serde_json::Value = serde_json::from_slice(&out.stdout).expect("inspect json");
    assert!(inspect.get("id").is_some());

    // rm by tag (force, in case it's referenced).
    cli(&socket)
        .args(["images", "rm", "-f", "docker.io/library/alpine:latest"])
        .assert()
        .success();

    // ls is empty again.
    let out = cli(&socket)
        .args(["--output", "json", "images", "ls"])
        .output()
        .expect("ls3");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("ls3 json");
    assert!(v.as_array().map(|a| a.is_empty()).unwrap_or(false));
}

#[test]
#[ignore]
fn volumes_lifecycle() {
    let workdir = tempfile::tempdir().expect("workdir");
    let (_g, socket) = spawn_daemon(&workdir);

    // create.
    let out = cli(&socket)
        .args(["volume", "create", "demo-vol"])
        .output()
        .expect("create");
    assert!(
        out.status.success(),
        "create failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "demo-vol");

    // ls.
    let out = cli(&socket)
        .args(["--output", "json", "volume", "ls"])
        .output()
        .expect("ls");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("ls json");
    assert!(v
        .as_array()
        .map(|a| a
            .iter()
            .any(|x| x.get("name").and_then(|s| s.as_str()) == Some("demo-vol")))
        .unwrap_or(false));

    // inspect.
    let out = cli(&socket)
        .args(["volume", "inspect", "demo-vol"])
        .output()
        .expect("inspect");
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("inspect json");
    assert_eq!(v.get("name").and_then(|s| s.as_str()), Some("demo-vol"));

    // mount into a container that exits immediately.
    cli(&socket)
        .args([
            "run",
            "--name",
            "demo-vmounter",
            "-v",
            "demo-vol:/data",
            "docker.io/library/alpine:latest",
            "true",
        ])
        .assert()
        .success();

    // remove the container; volume must still exist.
    cli(&socket)
        .args(["rm", "-f", "demo-vmounter"])
        .assert()
        .success();
    let out = cli(&socket)
        .args(["--output", "json", "volume", "ls"])
        .output()
        .expect("ls2");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("ls2 json");
    assert!(v
        .as_array()
        .map(|a| a
            .iter()
            .any(|x| x.get("name").and_then(|s| s.as_str()) == Some("demo-vol")))
        .unwrap_or(false));

    // rm volume.
    cli(&socket)
        .args(["volume", "rm", "demo-vol"])
        .assert()
        .success();
    let out = cli(&socket)
        .args(["--output", "json", "volume", "ls"])
        .output()
        .expect("ls3");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("ls3 json");
    assert!(v
        .as_array()
        .map(|a| a
            .iter()
            .all(|x| x.get("name").and_then(|s| s.as_str()) != Some("demo-vol")))
        .unwrap_or(false));
}

#[test]
#[ignore]
fn networks_lifecycle() {
    let workdir = tempfile::tempdir().expect("workdir");
    let (_g, socket) = spawn_daemon(&workdir);

    // create.
    let out = cli(&socket)
        .args([
            "network",
            "create",
            "--subnet",
            "10.99.0.0/24",
            "--gateway",
            "10.99.0.1",
            "demo-net",
        ])
        .output()
        .expect("create");
    assert!(
        out.status.success(),
        "create failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // ls.
    let out = cli(&socket)
        .args(["--output", "json", "network", "ls"])
        .output()
        .expect("ls");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("ls json");
    assert!(
        v.as_array()
            .map(|a| a
                .iter()
                .any(|x| x.get("name").and_then(|s| s.as_str()) == Some("demo-net")))
            .unwrap_or(false),
        "expected demo-net in {v}"
    );

    // inspect — subnet should be retained.
    let out = cli(&socket)
        .args(["network", "inspect", "demo-net"])
        .output()
        .expect("inspect");
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("inspect json");
    assert_eq!(
        v.get("subnet").and_then(|s| s.as_str()),
        Some("10.99.0.0/24")
    );

    // attach a container — exits quickly.
    cli(&socket)
        .args([
            "run",
            "--name",
            "demo-netter",
            "--network",
            "demo-net",
            "docker.io/library/alpine:latest",
            "true",
        ])
        .assert()
        .success();
    cli(&socket)
        .args(["rm", "-f", "demo-netter"])
        .assert()
        .success();

    // rm network.
    cli(&socket)
        .args(["network", "rm", "demo-net"])
        .assert()
        .success();
    let out = cli(&socket)
        .args(["--output", "json", "network", "ls"])
        .output()
        .expect("ls2");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("ls2 json");
    assert!(
        v.as_array()
            .map(|a| a
                .iter()
                .all(|x| x.get("name").and_then(|s| s.as_str()) != Some("demo-net")))
            .unwrap_or(false),
        "demo-net should be gone, got {v}"
    );

    // prune (no-op on empty).
    cli(&socket).args(["network", "prune"]).assert().success();
}

#[test]
#[ignore]
fn port_mapping() {
    let workdir = tempfile::tempdir().expect("workdir");
    let (_g, socket) = spawn_daemon(&workdir);

    // Create a container with a published port. We don't actually start a server in it — just
    // verify the publish flag round-trips through the CLI → IPC → podman → inspect path.
    // Use a high host port to minimize collision risk with services on the test host.
    // Podman's `--publish` rejects host port 0 even though some runtimes allow dynamic
    // assignment; pin to a fixed test port instead.
    cli(&socket)
        .args([
            "run",
            "--name",
            "demo-port",
            "-p",
            "18080:8080/tcp",
            "docker.io/library/alpine:latest",
            "sleep",
            "5",
        ])
        .assert()
        .success();

    // Inspect — the resulting JSON should mention both the host and container ports.
    let out = cli(&socket)
        .args(["inspect", "demo-port"])
        .output()
        .expect("inspect");
    assert!(
        out.status.success(),
        "inspect failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let raw = String::from_utf8(out.stdout).expect("inspect stdout");
    assert!(
        raw.contains("18080"),
        "expected host port 18080 in inspect output, got: {}",
        raw
    );
    assert!(
        raw.contains("8080"),
        "expected container port 8080 in inspect output, got: {}",
        raw
    );

    // Cleanup.
    cli(&socket)
        .args(["stop", "-t", "1", "demo-port"])
        .assert()
        .success();
    cli(&socket)
        .args(["rm", "-f", "demo-port"])
        .assert()
        .success();
}
