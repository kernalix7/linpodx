//! Phase 3 live integration test for the egress allowlist CLI.
//! `#[ignore]`-gated. Verifies that `linpodx network egress set` mutates the
//! sandbox profile YAML and that `network egress status` reflects the new rule.
//! Real DNS-proxy enforcement (NXDOMAIN for non-allowlisted) requires the
//! runtime team's hickory-DNS proxy and is exercised in the runtime crate.

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
fn network_egress_set_status_roundtrip() {
    let workdir = tempfile::tempdir().expect("workdir");
    let profiles_dir = workdir.path().join("profiles");
    write_profile(
        &profiles_dir,
        "egress-test",
        "version: 1\nname: egress-test\nnetwork:\n  kind: none\n",
    );

    let (_guard, socket) = spawn_daemon(&workdir, &profiles_dir);

    // Status should report `none` initially.
    let out = cli(&socket, &profiles_dir)
        .args(["network", "egress", "status", "egress-test"])
        .output()
        .expect("status1");
    assert!(out.status.success());
    let stdout1 = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        stdout1.contains("network.kind = none"),
        "expected network.kind = none in: {stdout1}"
    );

    // Set an allowlist with three domains.
    cli(&socket, &profiles_dir)
        .args([
            "network",
            "egress",
            "set",
            "--domains",
            "api.openai.com,registry.npmjs.org,github.com",
            "egress-test",
        ])
        .assert()
        .success();

    // Status should now report the allowlist with all three entries.
    let out = cli(&socket, &profiles_dir)
        .args(["network", "egress", "status", "egress-test"])
        .output()
        .expect("status2");
    assert!(out.status.success());
    let stdout2 = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        stdout2.contains("network.kind = allowlist"),
        "expected allowlist in: {stdout2}"
    );
    for d in ["api.openai.com", "registry.npmjs.org", "github.com"] {
        assert!(stdout2.contains(d), "expected {d} in: {stdout2}");
    }
}
