//! Phase 4 live integration test for the multi-distro CLI surface.
//! `#[ignore]`-gated. Verifies that the daemon answers DistroTemplateList with
//! the 6 known kinds. The full create → enter → remove path is gated on the
//! distro-team's IPC implementation.
//!
//! Phase 18 Stream E note: the legacy `skipped_for_placeholder` helper is kept
//! as a fallback (still fires on older daemon builds where the placeholder
//! Error::Runtime path is reached), but each test now carries an explicit
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
#[ignore = "Phase 4 — requires distro-team DistroTemplateList IPC + Podman ≥ 4.6.0; soft-skips when placeholder Error::Runtime is returned"]
fn distro_template_list_returns_six() {
    let workdir = tempfile::tempdir().expect("workdir");
    let (_guard, socket) = spawn_daemon(&workdir);

    let out = cli(&socket)
        .args(["--output", "json", "distro", "list"])
        .output()
        .expect("distro list");

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        if skipped_for_placeholder(&stderr) {
            eprintln!("distro_template_list: distro-team IPC not wired yet — skipping");
            return;
        }
        panic!("distro list failed: {stderr}");
    }

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("list json");
    let arr = v.as_array().expect("array");
    assert_eq!(arr.len(), 6, "expected 6 templates, got {arr:?}");
    let kinds: Vec<&str> = arr
        .iter()
        .filter_map(|e| e.get("kind").and_then(|k| k.as_str()))
        .collect();
    for expected in ["ubuntu", "fedora", "arch", "debian", "alpine", "nixos"] {
        assert!(
            kinds.contains(&expected),
            "missing kind {expected}, got {kinds:?}"
        );
    }
}

#[test]
#[ignore = "Phase 4 — requires distro-team `distro create/enter/remove` IPC + Podman ≥ 4.6.0 + alpine pull; soft-skips when placeholder Error::Runtime is returned"]
fn distro_alpine_create_enter_remove_lifecycle() {
    let workdir = tempfile::tempdir().expect("workdir");
    let (_guard, socket) = spawn_daemon(&workdir);

    let out = cli(&socket)
        .args(["distro", "create", "--kind", "alpine", "qa-alpine"])
        .output()
        .expect("distro create");
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        if skipped_for_placeholder(&stderr) {
            eprintln!("distro_create: distro-team IPC not wired yet — skipping");
            return;
        }
        panic!("distro create failed: {stderr}");
    }

    let out = cli(&socket)
        .args(["distro", "enter", "qa-alpine"])
        .output()
        .expect("distro enter");
    assert!(
        out.status.success(),
        "distro enter failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        stdout.contains("container_id="),
        "expected container_id= line in: {stdout}"
    );

    cli(&socket)
        .args(["distro", "remove", "qa-alpine"])
        .assert()
        .success();
}
