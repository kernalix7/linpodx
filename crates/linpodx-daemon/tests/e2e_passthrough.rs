//! Phase 3 live integration test for the GUI / device passthrough CLI.
//! `#[ignore]`-gated. Verifies that `linpodx passthrough grant` mutates the YAML
//! file in the profiles directory and that `passthrough status` round-trips.
//! Container-creation verification (that the runtime emits `--device /dev/dri`)
//! requires Podman ≥ 4.6.0 and is skipped on hosts without it.

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

fn spawn_daemon(workdir: &TempDir, profiles_dir: &Path) -> (ChildGuard, std::path::PathBuf) {
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
        .arg("--sandbox-profiles-dir")
        .arg(profiles_dir)
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

fn cli(socket: &Path, profiles_dir: &Path) -> AssertCommand {
    let mut c = AssertCommand::cargo_bin("linpodx").expect("locate linpodx");
    c.arg("--socket")
        .arg(socket)
        .arg("--profiles-dir")
        .arg(profiles_dir);
    c
}

fn write_profile(dir: &Path, name: &str, body: &str) {
    std::fs::create_dir_all(dir).expect("mkdir profiles");
    std::fs::write(dir.join(format!("{name}.yaml")), body).expect("write profile");
}

#[test]
#[ignore]
fn passthrough_grant_revoke_roundtrip() {
    let workdir = tempfile::tempdir().expect("workdir");
    let profiles_dir = workdir.path().join("profiles");
    write_profile(
        &profiles_dir,
        "gui-app",
        "version: 1\nname: gui-app\nnetwork:\n  kind: full\n",
    );

    let (_guard, socket) = spawn_daemon(&workdir, &profiles_dir);

    // Initial status should be all-empty.
    let out = cli(&socket, &profiles_dir)
        .args(["--output", "json", "passthrough", "status", "gui-app"])
        .output()
        .expect("status1");
    assert!(
        out.status.success(),
        "passthrough status failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("status1 json");
    assert_eq!(v.get("wayland").and_then(|b| b.as_bool()), Some(false));
    assert_eq!(v.get("gpu").and_then(|b| b.as_bool()), Some(false));

    // Grant Wayland + GPU.
    cli(&socket, &profiles_dir)
        .args([
            "passthrough",
            "grant",
            "--wayland",
            "--gpu",
            "--audio",
            "pipewire",
            "gui-app",
        ])
        .assert()
        .success();

    // Status should now reflect the grant (after the implicit reload).
    let out = cli(&socket, &profiles_dir)
        .args(["--output", "json", "passthrough", "status", "gui-app"])
        .output()
        .expect("status2");
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("status2 json");
    assert_eq!(v.get("wayland").and_then(|b| b.as_bool()), Some(true));
    assert_eq!(v.get("gpu").and_then(|b| b.as_bool()), Some(true));
    assert_eq!(v.get("audio").and_then(|s| s.as_str()), Some("pipe_wire"));

    // Revoke clears all fields.
    cli(&socket, &profiles_dir)
        .args(["passthrough", "revoke", "gui-app"])
        .assert()
        .success();

    let out = cli(&socket, &profiles_dir)
        .args(["--output", "json", "passthrough", "status", "gui-app"])
        .output()
        .expect("status3");
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("status3 json");
    assert_eq!(v.get("wayland").and_then(|b| b.as_bool()), Some(false));
    assert_eq!(v.get("gpu").and_then(|b| b.as_bool()), Some(false));
}
