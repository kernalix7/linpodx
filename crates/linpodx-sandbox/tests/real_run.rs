//! Phase 18 Stream G — real-podman sandbox integration tests.
//!
//! Every test in this file is `#[ignore]` so `cargo test --workspace` skips
//! them. Run them explicitly on a host with Podman ≥ 4.6.0 installed:
//!
//! ```bash
//! cargo test --test real_run -p linpodx-sandbox -- --ignored --test-threads=1
//! ```
//!
//! All tests use a disposable Podman `--root` / `--runroot` so the user's
//! real container state is never touched, and a per-test tempdir for the
//! sandbox state database.
//!
//! Coverage:
//! 1. `profile_apply_audits_and_chain_verifies` — load an example profile,
//!    apply it to a `CreateOptions`, verify the audit log fires
//!    `ProfileApplied` + the tamper-evident hash chain stays intact (no
//!    podman invocation required — this test will run anywhere).
//! 2. `real_podman_create_after_apply_emits_sandbox_event` — same plus an
//!    actual `podman create` against the transformed opts so we know the
//!    podman CLI accepts everything the sandbox layer produces.
//! 3. `approval_gate_grant_path` — use the stock `NoopApprovalGateway`
//!    (always grants) against a profile whose host-path mount triggers a
//!    `mount_host_path` gate, and confirm both `ApprovalRequested` and
//!    `ApprovalGranted` land on the chain.
//! 4. `approval_gate_deny_path` — same profile with the stock
//!    `DenyAllApprovalGateway`; expect `apply_to_create` to return
//!    `InvalidArgument` and the chain to record `ApprovalDenied`.

use linpodx_common::approval::{DenyAllApprovalGateway, NoopApprovalGateway};
use linpodx_common::db::Database;
use linpodx_common::events::{EventPublisher, NoopEventPublisher};
use linpodx_common::ipc::CreateOptions;
use linpodx_common::state::VolumeMount;
use linpodx_runtime::podman::{Podman, PodmanConfig};
use linpodx_sandbox::audit::{self, AuditFilters};
use linpodx_sandbox::{SandboxManager, SessionManager, SnapshotManager};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

const EXAMPLE_PROFILE_RELATIVE: &str = "examples/profiles/generic-cli-agent.yaml";

/// Skip-if-no-podman helper. Equivalent in spirit to the
/// `skipped_for_placeholder()` helper in `tests/phase18_e2e_smoke.rs` —
/// returns `true` when the host has no usable `podman` binary so the test
/// can short-circuit cleanly instead of producing a confusing failure deep
/// in the test body. Run via `cargo test ... -- --ignored` on a host with
/// podman ≥ 4.6.0 installed to exercise these in earnest.
async fn podman_available(podman: &Podman) -> bool {
    match podman.check().await {
        Ok(_) => true,
        Err(e) => {
            eprintln!("skipping: podman not available ({e})");
            false
        }
    }
}

/// Locate the example profile by walking up from the crate manifest dir
/// until we hit the workspace root (where `examples/profiles/` lives).
fn example_profile_path() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut cur: &Path = &manifest;
    loop {
        let candidate = cur.join(EXAMPLE_PROFILE_RELATIVE);
        if candidate.exists() {
            return candidate;
        }
        cur = cur
            .parent()
            .expect("walked past filesystem root without finding example profiles");
    }
}

/// Disposable podman + DB + sandbox manager wired up against the `Noop`
/// approval gateway (always grants). Returns the manager plus the tempdirs
/// so the caller can keep them alive for the duration of the test.
struct Fixture {
    manager: SandboxManager,
    db: Arc<Database>,
    podman: Podman,
    _root: TempDir,
    _runroot: TempDir,
    _state_dir: TempDir,
    _profiles_dir: TempDir,
}

async fn build_fixture_noop() -> Fixture {
    let root = tempfile::tempdir().expect("podman root tempdir");
    let runroot = tempfile::tempdir().expect("podman runroot tempdir");
    let state_dir = tempfile::tempdir().expect("state tempdir");
    let profiles_dir = tempfile::tempdir().expect("profiles tempdir");

    // Copy the example profile into the sandbox's profile dir so `reload()`
    // picks it up by name.
    let src = example_profile_path();
    let dest = profiles_dir.path().join("sandbox.yaml");
    std::fs::copy(&src, &dest).expect("copy example profile");

    let db_path = state_dir.path().join("state.db");
    let db = Database::open(&db_path).await.expect("open state db");
    db.migrate().await.expect("migrate state db");
    let db = Arc::new(db);

    let publisher: Arc<dyn EventPublisher> = Arc::new(NoopEventPublisher);
    let snapshot = Arc::new(SnapshotManager::new(
        Arc::clone(&db),
        Arc::clone(&publisher),
    ));
    let session = Arc::new(SessionManager::new(Arc::clone(&db), Arc::clone(&publisher)));
    let gateway = Arc::new(NoopApprovalGateway);

    let manager = SandboxManager::new(
        Arc::clone(&db),
        profiles_dir.path().to_path_buf(),
        Arc::clone(&publisher),
        gateway,
        Duration::from_secs(2),
        snapshot,
        session,
    );
    manager.reload().await.expect("reload profiles");

    let podman = Podman::with_config(PodmanConfig {
        binary: None,
        root: Some(root.path().to_path_buf()),
        runroot: Some(runroot.path().to_path_buf()),
    });

    Fixture {
        manager,
        db,
        podman,
        _root: root,
        _runroot: runroot,
        _state_dir: state_dir,
        _profiles_dir: profiles_dir,
    }
}

#[tokio::test]
#[ignore]
async fn profile_apply_audits_and_chain_verifies() {
    let fx = build_fixture_noop().await;

    let opts = CreateOptions {
        image: "docker.io/library/alpine:latest".into(),
        name: Some("linpodx-sandbox-real-1".into()),
        command: vec!["true".into()],
        detach: true,
        rm: false,
        ..Default::default()
    };
    let (_opts, _applied) = fx
        .manager
        .apply_to_create("generic-cli-agent", opts)
        .await
        .expect("apply_to_create");

    let entries = fx
        .manager
        .query_audit(AuditFilters::default())
        .await
        .expect("query audit");
    assert!(
        entries.iter().any(|e| e.kind == "profile_applied"),
        "expected profile_applied in audit chain, got {entries:#?}"
    );

    let report = fx.manager.verify_chain(None).await.expect("verify chain");
    assert!(
        report.broken_at.is_none(),
        "audit chain broken at seq {:?}",
        report.broken_at
    );
    assert!(
        report.total >= 2,
        "expected at least 2 entries, got {report:?}"
    );
    // Pin the `db` field so its `Arc` stays alive — the chain verify reused it.
    drop(fx.db);
}

#[tokio::test]
#[ignore]
async fn real_podman_create_after_apply_emits_sandbox_event() {
    let fx = build_fixture_noop().await;

    if !podman_available(&fx.podman).await {
        return;
    }
    fx.podman
        .pull("docker.io/library/alpine:latest")
        .await
        .expect("pull alpine");

    let opts = CreateOptions {
        image: "docker.io/library/alpine:latest".into(),
        name: Some("linpodx-sandbox-real-2".into()),
        command: vec!["sleep".into(), "5".into()],
        detach: true,
        rm: false,
        ..Default::default()
    };
    let (transformed, _applied) = fx
        .manager
        .apply_to_create("generic-cli-agent", opts)
        .await
        .expect("apply_to_create");

    let id = fx
        .podman
        .create(&transformed)
        .await
        .expect("podman create transformed opts");
    // Best-effort teardown — we don't need start/stop for this assertion.
    let _ = fx.podman.remove(&id, true).await;

    let entries = fx
        .manager
        .query_audit(AuditFilters::default())
        .await
        .expect("query audit");
    assert!(
        entries.iter().any(|e| e.kind == "profile_applied"),
        "expected profile_applied after real podman create"
    );
    drop(fx.db);
}

/// Write a sandbox profile that whitelists *only* the named `project`
/// volume but enables an `approval_gates: [mount_host_path]` so an off-list
/// host-path mount triggers the gate instead of an immediate deny.
async fn write_approval_profile(dir: &Path) {
    let yaml = r#"version: 1
name: real-approval
description: integration test profile — mount gate
mounts:
  - source:
      kind: named
      name: project
    destination: /project
    read_only: false
approval_gates:
  - mount_host_path
network:
  kind: none
capabilities:
  drop: ["ALL"]
read_only_rootfs: true
"#;
    let path = dir.join("real-approval.yaml");
    tokio::fs::write(&path, yaml).await.expect("write profile");
}

#[tokio::test]
#[ignore]
async fn approval_gate_grant_path() {
    let state_dir = tempfile::tempdir().expect("state tempdir");
    let profiles_dir = tempfile::tempdir().expect("profiles tempdir");
    write_approval_profile(profiles_dir.path()).await;

    let db = Database::open(state_dir.path().join("state.db"))
        .await
        .expect("db open");
    db.migrate().await.expect("migrate");
    let db = Arc::new(db);
    let publisher: Arc<dyn EventPublisher> = Arc::new(NoopEventPublisher);
    let snapshot = Arc::new(SnapshotManager::new(
        Arc::clone(&db),
        Arc::clone(&publisher),
    ));
    let session = Arc::new(SessionManager::new(Arc::clone(&db), Arc::clone(&publisher)));
    let gateway = Arc::new(NoopApprovalGateway);
    let manager = SandboxManager::new(
        Arc::clone(&db),
        profiles_dir.path().to_path_buf(),
        Arc::clone(&publisher),
        gateway,
        Duration::from_secs(2),
        snapshot,
        session,
    );
    manager.reload().await.expect("reload");

    let opts = CreateOptions {
        image: "docker.io/library/alpine:latest".into(),
        name: Some("linpodx-sandbox-grant".into()),
        // host-path mount NOT on the allow-list → triggers the gate.
        volumes: vec![VolumeMount {
            source: "/tmp/linpodx-real-grant".into(),
            destination: "/data".into(),
            read_only: false,
        }],
        ..Default::default()
    };
    let _ = manager
        .apply_to_create("real-approval", opts)
        .await
        .expect("granted path returns Allow");

    let entries = audit::query(&db, AuditFilters::default())
        .await
        .expect("query audit");
    assert!(
        entries.iter().any(|e| e.kind == "approval_requested"),
        "expected approval_requested in chain, got {entries:#?}"
    );
    assert!(
        entries.iter().any(|e| e.kind == "approval_granted"),
        "expected approval_granted in chain"
    );
    assert!(
        entries.iter().any(|e| e.kind == "profile_applied"),
        "expected profile_applied after grant"
    );

    let report = audit::verify_chain(&db, None).await.expect("verify");
    assert!(report.broken_at.is_none());

    drop((state_dir, profiles_dir));
}

#[tokio::test]
#[ignore]
async fn approval_gate_deny_path() {
    let state_dir = tempfile::tempdir().expect("state tempdir");
    let profiles_dir = tempfile::tempdir().expect("profiles tempdir");
    write_approval_profile(profiles_dir.path()).await;

    let db = Database::open(state_dir.path().join("state.db"))
        .await
        .expect("db open");
    db.migrate().await.expect("migrate");
    let db = Arc::new(db);
    let publisher: Arc<dyn EventPublisher> = Arc::new(NoopEventPublisher);
    let snapshot = Arc::new(SnapshotManager::new(
        Arc::clone(&db),
        Arc::clone(&publisher),
    ));
    let session = Arc::new(SessionManager::new(Arc::clone(&db), Arc::clone(&publisher)));
    let gateway = Arc::new(DenyAllApprovalGateway);
    let manager = SandboxManager::new(
        Arc::clone(&db),
        profiles_dir.path().to_path_buf(),
        Arc::clone(&publisher),
        gateway,
        Duration::from_secs(2),
        snapshot,
        session,
    );
    manager.reload().await.expect("reload");

    let opts = CreateOptions {
        image: "docker.io/library/alpine:latest".into(),
        name: Some("linpodx-sandbox-deny".into()),
        volumes: vec![VolumeMount {
            source: "/tmp/linpodx-real-deny".into(),
            destination: "/data".into(),
            read_only: false,
        }],
        ..Default::default()
    };
    let err = manager
        .apply_to_create("real-approval", opts)
        .await
        .expect_err("denied path must error");
    let msg = format!("{err}");
    assert!(
        msg.contains("denied") || msg.contains("approval"),
        "unexpected error message: {msg}"
    );

    let entries = audit::query(&db, AuditFilters::default())
        .await
        .expect("query audit");
    assert!(
        entries.iter().any(|e| e.kind == "approval_denied"),
        "expected approval_denied"
    );
    assert!(
        !entries.iter().any(|e| e.kind == "profile_applied"),
        "profile_applied must NOT fire on deny"
    );

    let report = audit::verify_chain(&db, None).await.expect("verify");
    assert!(report.broken_at.is_none());

    drop((state_dir, profiles_dir));
}
