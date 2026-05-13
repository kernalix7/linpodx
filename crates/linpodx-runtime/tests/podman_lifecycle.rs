//! Live Podman integration tests. Marked `#[ignore]` so `cargo test` skips them
//! by default. Run explicitly with `cargo test -p linpodx-runtime -- --ignored`
//! on a machine with Podman installed (>= MIN_PODMAN_VERSION).
//!
//! All tests use a disposable `--root` and `--runroot` so the user's real
//! Podman state is never touched.

use linpodx_common::ipc::CreateOptions;
use linpodx_runtime::podman::{Podman, PodmanConfig};
use std::time::Duration;
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

#[tokio::test]
#[ignore]
async fn check_succeeds() {
    let (p, _r, _rr) = podman();
    let v = p.check().await.expect("podman check");
    assert!(!v.is_empty());
    eprintln!("detected podman version: {v}");
}

#[tokio::test]
#[ignore]
async fn full_lifecycle_alpine() {
    let (p, _r, _rr) = podman();
    p.check().await.expect("podman check");

    // Pull alpine into the disposable root.
    p.pull("docker.io/library/alpine:latest")
        .await
        .expect("pull alpine");

    // Create a detached container that sleeps a short while.
    let opts = CreateOptions {
        image: "docker.io/library/alpine:latest".into(),
        name: Some("linpodx-int-test".into()),
        command: vec!["sleep".into(), "30".into()],
        env: vec![],
        labels: vec![("linpodx.test".into(), "true".into())],
        rm: false,
        detach: true,
        ..Default::default()
    };
    let id = p.create(&opts).await.expect("create");
    assert!(!id.as_str().is_empty());

    p.start(&id).await.expect("start");

    // ps --all should show our container.
    let listed = p.list(true).await.expect("list all");
    assert!(listed
        .iter()
        .any(|c| c.id.as_str().starts_with(id.as_str()) || c.id == id));

    // inspect should give us back the container.
    let inspected = p.inspect(&id).await.expect("inspect");
    assert_eq!(inspected.name, "linpodx-int-test");

    // stop with a short timeout.
    p.stop(&id, Some(Duration::from_secs(2)))
        .await
        .expect("stop");

    // remove force.
    p.remove(&id, true).await.expect("remove");

    // ps --all should no longer list it.
    let after = p.list(true).await.expect("list after rm");
    assert!(after.iter().all(|c| c.id != id));
}
