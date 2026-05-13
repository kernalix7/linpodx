//! Phase 2A live integration tests for sandbox approval gates.
//! `#[ignore]`-gated (requires Podman ≥ 4.6.0). Run via:
//!   cargo test --workspace -- --ignored --test-threads=1
//!
//! Each test spawns the daemon plus an in-process auto-responder that subscribes,
//! waits for an approval_request notification, and replies with a fixed decision.

use assert_cmd::Command as AssertCommand;
use linpodx_common::approval::ApprovalRequest;
use linpodx_common::ipc::{
    ApprovalDecisionParams, JsonRpcVersion, Method, Notification, RpcRequest, ServerMessage,
    SubscribeParams,
};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

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

fn write_profile(dir: &Path, name: &str, contents: &str) {
    std::fs::write(dir.join(format!("{name}.yaml")), contents).expect("write profile");
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

fn cli(socket: &Path) -> AssertCommand {
    let mut c = AssertCommand::cargo_bin("linpodx").expect("locate linpodx");
    c.arg("--socket").arg(socket);
    c
}

const GATED_PROFILE: &str = r#"
version: 1
name: gated
description: gates host-path mounts
network:
  kind: full
mounts: []
limits: {}
capabilities:
  drop: ["ALL"]
  add: []
read_only_rootfs: false
approval_gates: ["mount_host_path"]
approval_timeout_secs: 5
"#;

/// Spawn an auto-responder that subscribes and replies to the first approval_request with
/// a fixed decision. Returns a JoinHandle; the caller awaits or aborts as needed.
async fn spawn_auto_responder(
    socket: std::path::PathBuf,
    allow: bool,
) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    tokio::spawn(async move {
        static NEXT_ID: AtomicI64 = AtomicI64::new(1000);

        let stream = UnixStream::connect(&socket).await?;
        let (read, mut write) = stream.into_split();
        let mut reader = BufReader::new(read);

        // Subscribe to all topics so approval requests fan out to us.
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let req = RpcRequest {
            jsonrpc: JsonRpcVersion::V2,
            id: Some(linpodx_common::ipc::RequestId::Number(id)),
            method: Method::Subscribe(SubscribeParams {
                topics: linpodx_common::ipc::EventTopic::ALL.to_vec(),
            }),
        };
        let mut buf = serde_json::to_vec(&req)?;
        buf.push(b'\n');
        write.write_all(&buf).await?;

        // Drain responses until we get the approval_request notification, then reply.
        loop {
            let mut line = String::new();
            let n = reader.read_line(&mut line).await?;
            if n == 0 {
                anyhow::bail!("daemon closed connection");
            }
            let trimmed = line.trim_end();
            if trimmed.is_empty() {
                continue;
            }
            let msg: ServerMessage = serde_json::from_str(trimmed)?;
            if let ServerMessage::Notification(Notification { method, params, .. }) = msg {
                if method == "approval_request" {
                    let req: ApprovalRequest = serde_json::from_value(params)?;
                    let decision_id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
                    let decision = RpcRequest {
                        jsonrpc: JsonRpcVersion::V2,
                        id: Some(linpodx_common::ipc::RequestId::Number(decision_id)),
                        method: Method::ApprovalDecision(ApprovalDecisionParams {
                            request_id: req.request_id,
                            allow,
                            by: Some("auto-responder".into()),
                            reason: Some(if allow {
                                "test allow".into()
                            } else {
                                "test deny".into()
                            }),
                        }),
                    };
                    let mut buf = serde_json::to_vec(&decision)?;
                    buf.push(b'\n');
                    write.write_all(&buf).await?;
                    return Ok(());
                }
            }
        }
    })
}

#[test]
#[ignore]
fn approval_granted_path() {
    let workdir = tempfile::tempdir().expect("workdir");
    let profiles_dir = tempfile::tempdir().expect("profiles dir");
    write_profile(profiles_dir.path(), "gated", GATED_PROFILE);
    let (_guard, socket) = spawn_daemon(&workdir, profiles_dir.path());

    let rt = tokio::runtime::Runtime::new().unwrap();
    let responder = rt.block_on(spawn_auto_responder(socket.clone(), true));
    // Give the subscriber a moment to register.
    std::thread::sleep(Duration::from_millis(400));

    cli(&socket)
        .args([
            "run",
            "--name",
            "ag-allow",
            "--sandbox",
            "gated",
            "-v",
            "/tmp:/host_tmp",
            "docker.io/library/alpine:latest",
            "true",
        ])
        .assert()
        .success();

    rt.block_on(async { responder.await.ok() });

    let out = cli(&socket)
        .args([
            "sandbox",
            "audit",
            "--profile",
            "gated",
            "--kind",
            "approval_granted",
            "--limit",
            "5",
            "--json",
        ])
        .output()
        .expect("audit");
    assert!(
        out.status.success(),
        "audit failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        v.as_array().map(|a| !a.is_empty()).unwrap_or(false),
        "expected ApprovalGranted, got {v}"
    );

    cli(&socket)
        .args(["rm", "-f", "ag-allow"])
        .assert()
        .success();
}

#[test]
#[ignore]
fn approval_denied_path() {
    let workdir = tempfile::tempdir().expect("workdir");
    let profiles_dir = tempfile::tempdir().expect("profiles dir");
    write_profile(profiles_dir.path(), "gated", GATED_PROFILE);
    let (_guard, socket) = spawn_daemon(&workdir, profiles_dir.path());

    let rt = tokio::runtime::Runtime::new().unwrap();
    let responder = rt.block_on(spawn_auto_responder(socket.clone(), false));
    std::thread::sleep(Duration::from_millis(400));

    let out = cli(&socket)
        .args([
            "run",
            "--name",
            "ag-deny",
            "--sandbox",
            "gated",
            "-v",
            "/tmp:/host_tmp",
            "docker.io/library/alpine:latest",
            "true",
        ])
        .output()
        .expect("run");
    assert!(!out.status.success(), "expected deny but command succeeded");

    rt.block_on(async { responder.await.ok() });

    let out = cli(&socket)
        .args([
            "sandbox",
            "audit",
            "--profile",
            "gated",
            "--kind",
            "approval_denied",
            "--limit",
            "5",
            "--json",
        ])
        .output()
        .expect("audit");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        v.as_array().map(|a| !a.is_empty()).unwrap_or(false),
        "expected ApprovalDenied, got {v}"
    );
}

#[test]
#[ignore]
fn approval_no_listener() {
    let workdir = tempfile::tempdir().expect("workdir");
    let profiles_dir = tempfile::tempdir().expect("profiles dir");
    write_profile(profiles_dir.path(), "gated", GATED_PROFILE);
    let (_guard, socket) = spawn_daemon(&workdir, profiles_dir.path());

    // No responder spawned. Daemon should resolve to NoListener (broadcast channel sees zero subscribers).
    let out = cli(&socket)
        .args([
            "run",
            "--name",
            "ag-nolistener",
            "--sandbox",
            "gated",
            "-v",
            "/tmp:/host_tmp",
            "docker.io/library/alpine:latest",
            "true",
        ])
        .output()
        .expect("run");
    assert!(!out.status.success(), "expected deny without listener");

    let out = cli(&socket)
        .args([
            "sandbox",
            "audit",
            "--profile",
            "gated",
            "--kind",
            "approval_no_listener",
            "--limit",
            "5",
            "--json",
        ])
        .output()
        .expect("audit");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        v.as_array().map(|a| !a.is_empty()).unwrap_or(false),
        "expected ApprovalNoListener, got {v}"
    );
}

#[test]
#[ignore]
fn approval_chain_intact_after_round_trip() {
    let workdir = tempfile::tempdir().expect("workdir");
    let profiles_dir = tempfile::tempdir().expect("profiles dir");
    write_profile(profiles_dir.path(), "gated", GATED_PROFILE);
    let (_guard, socket) = spawn_daemon(&workdir, profiles_dir.path());

    let rt = tokio::runtime::Runtime::new().unwrap();
    let responder = rt.block_on(spawn_auto_responder(socket.clone(), true));
    std::thread::sleep(Duration::from_millis(400));

    cli(&socket)
        .args([
            "run",
            "--name",
            "ag-chain",
            "--sandbox",
            "gated",
            "-v",
            "/tmp:/host_tmp",
            "docker.io/library/alpine:latest",
            "true",
        ])
        .assert()
        .success();
    rt.block_on(async { responder.await.ok() });

    cli(&socket)
        .args(["rm", "-f", "ag-chain"])
        .assert()
        .success();

    let out = cli(&socket)
        .args(["sandbox", "verify"])
        .output()
        .expect("verify");
    assert!(
        out.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("OK:"),
        "expected OK from verify, got: {stdout}"
    );
}
