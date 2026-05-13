//! End-to-end: spawn the daemon with a `--remote-listen` WebSocket binding, then
//! drive a CLI subcommand over `--remote` instead of the Unix socket.
//!
//! `#[ignore]` because it needs the daemon binary built (which transitively needs
//! Podman to start successfully — `Version` succeeds because the daemon refuses to
//! boot without `podman`).

use assert_cmd::Command as AssertCommand;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

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

#[test]
#[ignore]
fn remote_version_call_roundtrips() {
    // Re-spawn with a fixed loopback port so we know what to point the CLI at.
    let workdir = tempfile::tempdir().expect("tempdir");
    let socket = workdir.path().join("linpodx.sock");
    let db = workdir.path().join("state.db");
    let pod_root = workdir.path().join("podman-root");
    let pod_runroot = workdir.path().join("podman-runroot");
    let port = pick_free_port();
    let listen = format!("127.0.0.1:{port}");

    let bin = AssertCommand::cargo_bin("linpodx-daemon")
        .expect("locate linpodx-daemon")
        .get_program()
        .to_owned();
    let child = Command::new(&bin)
        .arg("--socket")
        .arg(&socket)
        .arg("--db")
        .arg(&db)
        .arg("--podman-root")
        .arg(&pod_root)
        .arg("--podman-runroot")
        .arg(&pod_runroot)
        .arg("--remote-listen")
        .arg(&listen)
        .arg("--remote-token")
        .arg("hunter2")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn daemon");
    let _guard = DaemonGuard { child };

    assert!(
        wait_for_socket(&socket, Duration::from_secs(20)),
        "daemon never created Unix socket"
    );
    // Give the WS listener an extra moment to bind after the unix socket appears.
    std::thread::sleep(Duration::from_millis(500));

    let url = format!("ws://{listen}/ipc");
    let mut cmd = AssertCommand::cargo_bin("linpodx").expect("locate cli");
    cmd.arg("--remote")
        .arg(&url)
        .arg("--token")
        .arg("hunter2")
        .arg("version");
    let out = cmd.output().expect("run cli");
    assert!(
        out.status.success(),
        "cli failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
#[ignore]
fn remote_rejects_bad_token() {
    let workdir = tempfile::tempdir().expect("tempdir");
    let socket = workdir.path().join("linpodx.sock");
    let db = workdir.path().join("state.db");
    let pod_root = workdir.path().join("podman-root");
    let pod_runroot = workdir.path().join("podman-runroot");
    let port = pick_free_port();
    let listen = format!("127.0.0.1:{port}");

    let bin = AssertCommand::cargo_bin("linpodx-daemon")
        .expect("locate linpodx-daemon")
        .get_program()
        .to_owned();
    let child = Command::new(&bin)
        .arg("--socket")
        .arg(&socket)
        .arg("--db")
        .arg(&db)
        .arg("--podman-root")
        .arg(&pod_root)
        .arg("--podman-runroot")
        .arg(&pod_runroot)
        .arg("--remote-listen")
        .arg(&listen)
        .arg("--remote-token")
        .arg("hunter2")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn daemon");
    let _guard = DaemonGuard { child };

    assert!(
        wait_for_socket(&socket, Duration::from_secs(20)),
        "daemon never created Unix socket"
    );
    std::thread::sleep(Duration::from_millis(500));

    let url = format!("ws://{listen}/ipc");
    let mut cmd = AssertCommand::cargo_bin("linpodx").expect("locate cli");
    cmd.arg("--remote")
        .arg(&url)
        .arg("--token")
        .arg("WRONG")
        .arg("version");
    let out = cmd.output().expect("run cli");
    assert!(
        !out.status.success(),
        "cli unexpectedly succeeded with bad token"
    );
}

fn pick_free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = l.local_addr().expect("addr").port();
    drop(l);
    port
}
