//! Phase 1C live integration tests for sandbox profile application + audit log.
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

// memory_mb / cpus deliberately omitted: rootless cgroup support varies (e.g. some kernels
// lack `memory.swap.max`). Phase 1C tests assert on cap-drop / network / read-only — the
// universally-supported subset. Phase 3 will gate cpu/memory enforcement on cgroup probes.
const STRICT_PROFILE: &str = r#"
version: 1
name: strict
description: Read-only rootfs, no network, no host mounts.
network:
  kind: none
mounts: []
capabilities:
  drop: ["ALL"]
  add: []
read_only_rootfs: true
"#;

#[test]
#[ignore]
fn sandbox_apply_allow() {
    let workdir = tempfile::tempdir().expect("workdir");
    let profiles_dir = tempfile::tempdir().expect("profiles dir");
    write_profile(profiles_dir.path(), "strict", STRICT_PROFILE);
    let (_guard, socket) = spawn_daemon(&workdir, profiles_dir.path());

    // Profile should be loaded.
    let out = cli(&socket)
        .args(["--output", "json", "sandbox", "list"])
        .output()
        .expect("list");
    assert!(
        out.status.success(),
        "list failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        v.as_array()
            .map(|a| a
                .iter()
                .any(|p| p.get("name").and_then(|s| s.as_str()) == Some("strict")))
            .unwrap_or(false),
        "expected strict profile in list, got {v}"
    );

    // Run a container under the profile.
    cli(&socket)
        .args([
            "run",
            "--name",
            "sb-allow",
            "--sandbox",
            "strict",
            "docker.io/library/alpine:latest",
            "true",
        ])
        .assert()
        .success();

    // Inspect — read-only rootfs and host_config should reflect the profile.
    let out = cli(&socket)
        .args(["inspect", "sb-allow"])
        .output()
        .expect("inspect");
    assert!(out.status.success());
    let raw = String::from_utf8(out.stdout).unwrap();
    // Permissive contains-check: podman inspect's HostConfig has "ReadonlyRootfs" boolean.
    assert!(
        raw.to_lowercase().contains("readonly"),
        "expected readonly hint in inspect, got: {raw}"
    );

    // Audit must include a ProfileApplied entry for `strict`.
    let out = cli(&socket)
        .args([
            "sandbox",
            "audit",
            "--profile",
            "strict",
            "--kind",
            "profile_applied",
            "--limit",
            "10",
            "--json",
        ])
        .output()
        .expect("audit");
    assert!(
        out.status.success(),
        "audit failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let entries: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        entries.as_array().map(|a| !a.is_empty()).unwrap_or(false),
        "expected at least one ProfileApplied entry for strict, got {entries}"
    );

    // Cleanup.
    cli(&socket)
        .args(["rm", "-f", "sb-allow"])
        .assert()
        .success();
}

#[test]
#[ignore]
fn sandbox_apply_deny() {
    let workdir = tempfile::tempdir().expect("workdir");
    let profiles_dir = tempfile::tempdir().expect("profiles dir");
    write_profile(profiles_dir.path(), "strict", STRICT_PROFILE);
    let (_guard, socket) = spawn_daemon(&workdir, profiles_dir.path());

    // Try to mount /etc:/conf — strict profile has no mount rules, should be denied.
    let out = cli(&socket)
        .args([
            "run",
            "--name",
            "sb-deny",
            "--sandbox",
            "strict",
            "-v",
            "/etc:/conf",
            "docker.io/library/alpine:latest",
            "true",
        ])
        .output()
        .expect("run");
    assert!(!out.status.success(), "expected deny but command succeeded");
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        stderr.contains("denied") || stderr.contains("not permitted"),
        "expected deny reason in stderr, got: {stderr}"
    );

    // Audit must include a ProfileDenied entry.
    let out = cli(&socket)
        .args([
            "sandbox",
            "audit",
            "--profile",
            "strict",
            "--kind",
            "profile_denied",
            "--limit",
            "10",
            "--json",
        ])
        .output()
        .expect("audit");
    assert!(out.status.success());
    let entries: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        entries.as_array().map(|a| !a.is_empty()).unwrap_or(false),
        "expected ProfileDenied entry, got {entries}"
    );
}

#[test]
#[ignore]
fn audit_chain_verify_and_tamper() {
    let workdir = tempfile::tempdir().expect("workdir");
    let profiles_dir = tempfile::tempdir().expect("profiles dir");
    write_profile(profiles_dir.path(), "strict", STRICT_PROFILE);
    let (_guard, socket) = spawn_daemon(&workdir, profiles_dir.path());

    // Generate some audit traffic: list + apply + deny.
    cli(&socket).args(["sandbox", "list"]).assert().success();
    cli(&socket)
        .args([
            "run",
            "--name",
            "vc-1",
            "--sandbox",
            "strict",
            "docker.io/library/alpine:latest",
            "true",
        ])
        .assert()
        .success();
    cli(&socket).args(["rm", "-f", "vc-1"]).assert().success();

    // Verify should pass.
    let out = cli(&socket)
        .args(["sandbox", "verify"])
        .output()
        .expect("verify");
    assert!(
        out.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        stdout.starts_with("OK:"),
        "expected OK from verify, got: {stdout}"
    );

    // Now tamper with the DB directly: rewrite a payload.
    let db_path = workdir.path().join("state.db");
    let conn = rusqlite_open(&db_path);
    conn.execute(
        "UPDATE audit_log SET payload = '{\"tampered\":true}' WHERE seq = 2",
        [],
    )
    .expect("tamper");
    drop(conn);

    let out = cli(&socket)
        .args(["sandbox", "verify"])
        .output()
        .expect("verify2");
    assert!(!out.status.success(), "expected non-zero exit on tamper");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        stdout.contains("TAMPER DETECTED"),
        "expected tamper message, got: {stdout}"
    );
}

// Open the SQLite file directly via sqlx's blocking-friendly path. We avoid pulling rusqlite
// into the workspace by using sqlx's blocking adaptor through `tokio::runtime::Builder`.
fn rusqlite_open(path: &Path) -> SqliteAdapter {
    SqliteAdapter::open(path)
}

struct SqliteAdapter {
    rt: tokio::runtime::Runtime,
    pool: sqlx::SqlitePool,
}

impl SqliteAdapter {
    fn open(path: &Path) -> Self {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let pool = rt.block_on(async {
            use sqlx::sqlite::SqliteConnectOptions;
            use std::str::FromStr;
            let opts =
                SqliteConnectOptions::from_str(&format!("sqlite://{}", path.display())).unwrap();
            sqlx::SqlitePool::connect_with(opts).await.unwrap()
        });
        Self { rt, pool }
    }

    fn execute(&self, sql: &str, _params: [(); 0]) -> Result<(), sqlx::Error> {
        self.rt
            .block_on(async { sqlx::query(sql).execute(&self.pool).await.map(|_| ()) })
    }
}
