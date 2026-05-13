//! Live Podman integration tests for distro instance lifecycle. Marked `#[ignore]`
//! so `cargo test` skips them by default. Run explicitly with
//! `cargo test -p linpodx-distro -- --ignored --test-threads=1` on a machine with
//! Podman installed (>= 4.6.0).
//!
//! All tests use a disposable `--root`/`--runroot` so the user's real Podman state is
//! never touched, and a fresh tempdir-backed SQLite database.

use linpodx_common::audit_sink::NoopAuditSink;
use linpodx_common::db::Database;
use linpodx_common::events::NoopEventPublisher;
use linpodx_common::ipc::DistroCreateParams;
use linpodx_common::passthrough::DistroKind;
use linpodx_distro::InstanceManager;
use linpodx_runtime::{Podman, PodmanConfig};
use std::sync::Arc;
use tempfile::TempDir;

fn podman() -> (Podman, TempDir, TempDir) {
    let root = tempfile::tempdir().expect("root tempdir");
    let runroot = tempfile::tempdir().expect("runroot tempdir");
    let p = Podman::with_config(PodmanConfig {
        binary: None,
        root: Some(root.path().to_path_buf()),
        runroot: Some(runroot.path().to_path_buf()),
    });
    (p, root, runroot)
}

async fn fresh_db() -> Database {
    let dir = Box::leak(Box::new(tempfile::tempdir().expect("tempdir")));
    let path = dir.path().join("distro-it.db");
    let db = Database::open(&path).await.expect("open");
    db.migrate().await.expect("migrate");
    db
}

#[tokio::test]
#[ignore]
async fn alpine_create_enter_remove_cycle() {
    let (p, _root, _runroot) = podman();
    p.check().await.expect("podman check");
    p.pull("docker.io/library/alpine:latest")
        .await
        .expect("pull alpine");

    let db = Arc::new(fresh_db().await);
    let mgr = InstanceManager::new(
        Arc::clone(&db),
        Arc::new(NoopEventPublisher),
        Arc::new(NoopAuditSink),
    );

    let create = mgr
        .create(
            &p,
            &DistroCreateParams {
                kind: DistroKind::Alpine,
                name: "alp-it".into(),
                vm_mode: false,
                passthrough: None,
                custom_image: None,
                sandbox_profile: None,
            },
        )
        .await
        .expect("create alpine instance");
    assert_eq!(create.instance.name, "alp-it");
    assert_eq!(create.instance.kind, DistroKind::Alpine);
    assert!(create.instance.home_volume.is_none());
    assert!(!create.instance.vm_mode);
    assert!(!create.instance.container_id.is_empty());

    // List should include the new row.
    let listed = mgr.list().await.expect("list");
    assert!(listed.iter().any(|r| r.name == "alp-it"));

    // Enter returns a sane podman exec command shape.
    let enter = mgr.enter("alp-it").await.expect("enter");
    assert_eq!(enter.container_id, create.instance.container_id);
    assert_eq!(enter.suggested_command[0], "podman");
    assert_eq!(enter.suggested_command[1], "exec");
    assert_eq!(enter.suggested_command[2], "-it");
    // Last two: container id, then shell.
    assert!(enter.suggested_command.contains(&"ash".to_string()));

    // Remove and confirm row drops out of list.
    let remove = mgr.remove(&p, "alp-it", false).await.expect("remove");
    assert_eq!(remove.name, "alp-it");
    assert!(!remove.kept_volume); // No volume to keep in non-VM mode.
    let after = mgr.list().await.expect("list-after");
    assert!(after.iter().all(|r| r.name != "alp-it"));
}
