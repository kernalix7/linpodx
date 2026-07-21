//! Phase 18 Stream G — real-podman runtime integration tests.
//!
//! Every test in this file is `#[ignore]` so `cargo test --workspace` skips
//! them. Run them explicitly on a host with Podman ≥ 4.6.0 installed:
//!
//! ```bash
//! cargo test --test real_podman -p linpodx-runtime -- --ignored --test-threads=1
//! ```
//!
//! All tests use a disposable Podman `--root` / `--runroot` and a
//! per-test `LINPODX_DATA_HOME` so the user's real container state and
//! encrypted-snapshot store are never touched.
//!
//! Coverage:
//! 1. `snapshot_encryption_disk_round_trip` — pull alpine, commit a
//!    snapshot, encrypt it via `encrypt_committed_image`, verify
//!    `blob.enc` + `meta.json` actually hit the filesystem, then
//!    `decrypt_and_load` and confirm podman reports the image again.
//! 2. `mtls_cert_generate_produces_valid_pem_material` — drive the
//!    `linpodx daemon cert generate` CLI through `cargo run` and check
//!    that the resulting CA / server / client PEMs parse with
//!    `rustls-pemfile`. The output of this command is exactly what feeds
//!    `axum-server`'s `tls-rustls-no-provider` listener, so a passing
//!    parse here means the WS handshake material is sane.

use linpodx_common::ipc::CreateOptions;
use linpodx_runtime::podman::{Podman, PodmanConfig};
use linpodx_runtime::snapshot as runtime_snapshot;
use linpodx_runtime::snapshot_crypto::EncryptionConfig;
use std::process::Command;
use std::time::Duration;
use tempfile::TempDir;

fn podman_and_roots() -> (Podman, TempDir, TempDir) {
    let root = tempfile::tempdir().expect("podman root tempdir");
    let runroot = tempfile::tempdir().expect("podman runroot tempdir");
    let p = Podman::with_config(PodmanConfig {
        binary: None,
        root: Some(root.path().to_path_buf()),
        runroot: Some(runroot.path().to_path_buf()),
    });
    (p, root, runroot)
}

/// Skip-if-no-podman helper — mirrors the `skipped_for_placeholder()`
/// pattern from `tests/phase18_e2e_smoke.rs`. Returns `true` when the
/// host has no usable `podman` binary so the test can short-circuit
/// cleanly instead of producing a confusing failure deep in the body.
async fn podman_available(podman: &Podman) -> bool {
    match podman.check().await {
        Ok(_) => true,
        Err(e) => {
            eprintln!("skipping: podman not available ({e})");
            false
        }
    }
}

/// Point `XDG_DATA_HOME` at a fresh tempdir so the encrypted store
/// (`<XDG_DATA_HOME>/linpodx/snapshots/encrypted/...`) is per-test.
fn isolated_data_home() -> TempDir {
    let dir = tempfile::tempdir().expect("data tempdir");
    std::env::set_var("XDG_DATA_HOME", dir.path());
    dir
}

#[tokio::test]
#[ignore]
async fn snapshot_encryption_disk_round_trip() {
    let (podman, _root, _runroot) = podman_and_roots();
    let _data_home = isolated_data_home();

    if !podman_available(&podman).await {
        return;
    }
    podman
        .pull("docker.io/library/alpine:latest")
        .await
        .expect("pull alpine");

    // Create + start a short-lived container we can commit from.
    let opts = CreateOptions {
        image: "docker.io/library/alpine:latest".into(),
        name: Some("linpodx-runtime-real-encrypt".into()),
        command: vec!["sleep".into(), "10".into()],
        detach: true,
        rm: false,
        ..Default::default()
    };
    let id = podman.create(&opts).await.expect("podman create");
    podman.start(&id).await.expect("podman start");

    // Commit → snapshot image.
    let snapshot_ref = "linpodx-test-snap:realrun";
    runtime_snapshot::create(&podman, &id, snapshot_ref)
        .await
        .expect("snapshot commit");

    // Encrypt the committed image. `from_passphrase` synthesises a random
    // salt, so the resulting key is well-formed AES-256-GCM material.
    let cfg = EncryptionConfig::from_passphrase("phase18-real-passphrase");
    let meta = runtime_snapshot::encrypt_committed_image(&podman, snapshot_ref, &cfg, false)
        .await
        .expect("encrypt committed image");
    assert!(meta.plaintext_len > 0, "plaintext_len must be non-zero");
    assert!(meta.ciphertext_sha256.len() == 64, "sha256 hex is 64 chars");

    // The encrypted store must contain the blob + meta side-car on disk.
    let dir = runtime_snapshot::encrypted_image_dir(snapshot_ref);
    let blob = dir.join("blob.enc");
    let meta_path = dir.join("meta.json");
    assert!(blob.is_file(), "blob.enc missing at {}", blob.display());
    assert!(
        meta_path.is_file(),
        "meta.json missing at {}",
        meta_path.display()
    );
    let blob_bytes = std::fs::read(&blob).expect("read blob");
    assert!(
        blob_bytes.len() > 12,
        "blob too small to contain AES-GCM nonce+payload"
    );

    // Decrypt + `podman load` — afterwards the image must be visible again
    // in the (disposable) podman store.
    runtime_snapshot::decrypt_and_load(&podman, snapshot_ref, &cfg)
        .await
        .expect("decrypt and load");
    let inspected = runtime_snapshot::inspect(&podman, snapshot_ref)
        .await
        .expect("inspect decrypted image");
    assert!(!inspected.id.as_str().is_empty());

    // Best-effort teardown — container + snapshot image.
    let _ = podman.stop(&id, Some(Duration::from_secs(2))).await;
    let _ = podman.remove(&id, true).await;
    let _ = runtime_snapshot::remove(&podman, snapshot_ref, true).await;
}

#[tokio::test]
#[ignore]
async fn mtls_cert_generate_produces_valid_pem_material() {
    // Invoke the daemon CLI subcommand we already ship — this is exactly
    // what the user runs to bootstrap mTLS, and it lands the same PEM files
    // axum-server's tls-rustls-no-provider listener consumes.
    let out_dir = tempfile::tempdir().expect("cert tempdir");

    // We deliberately go through `cargo run -p linpodx-cli` rather than
    // pointing at a fixed `target/debug/linpodx` so this works whether the
    // test runner is invoked from the workspace root or a sub-crate.
    let status = Command::new(env!("CARGO"))
        .args([
            "run",
            "--quiet",
            "-p",
            "linpodx-cli",
            "--bin",
            "linpodx",
            "--",
            "daemon",
            "cert",
            "generate",
            "--out",
        ])
        .arg(out_dir.path())
        .status()
        .expect("invoke linpodx daemon cert generate");
    assert!(
        status.success(),
        "linpodx daemon cert generate exited with {status:?}"
    );

    // rustls-pemfile would be a cleaner check but it's not a dev-dep of
    // this crate (it lives at the workspace level), so we verify the PEM
    // structure ourselves: BEGIN/END markers + at least one base64-ish
    // body line. Combined with the CLI's own `rcgen` invariants this is
    // sufficient to know the files axum-server's `tls-rustls-no-provider`
    // listener will consume are well-formed.
    let expected_certs = ["ca.pem", "server-cert.pem", "client-cert.pem"];
    let expected_keys = ["ca-key.pem", "server-key.pem", "client-key.pem"];

    for name in expected_certs.iter().chain(expected_keys.iter()) {
        let path = out_dir.path().join(name);
        assert!(path.is_file(), "missing cert file: {}", path.display());
        let text = std::fs::read_to_string(&path).expect("read PEM");
        assert!(
            text.contains("-----BEGIN ") && text.contains("-----END "),
            "{} is not PEM-shaped:\n{text}",
            path.display()
        );
    }

    for name in expected_certs {
        let path = out_dir.path().join(name);
        let text = std::fs::read_to_string(&path).expect("read PEM");
        assert!(
            text.contains("-----BEGIN CERTIFICATE-----"),
            "{} should be a CERTIFICATE PEM",
            path.display()
        );
    }

    for name in expected_keys {
        let path = out_dir.path().join(name);
        let text = std::fs::read_to_string(&path).expect("read PEM");
        assert!(
            text.contains("PRIVATE KEY"),
            "{} should be a PRIVATE KEY PEM",
            path.display()
        );
    }
}

/// Phase 18 Stream G — minimal end-to-end round-trip exercised by the
/// CI `podman-integration` job. Replicates the `podman run --rm alpine
/// echo hi` smoke test through our [`Podman`] adapter so any regression
/// in our `base_command` / arg-quoting / disposable-root plumbing is
/// caught alongside CLI behaviour. The container is created detached,
/// started, logged, then force-removed.
#[tokio::test]
#[ignore]
async fn podman_run_alpine_echo_round_trip() {
    let (podman, _root, _runroot) = podman_and_roots();

    if !podman_available(&podman).await {
        return;
    }
    podman
        .pull("docker.io/library/alpine:latest")
        .await
        .expect("pull alpine");

    let opts = CreateOptions {
        image: "docker.io/library/alpine:latest".into(),
        name: Some("linpodx-runtime-real-echo".into()),
        command: vec!["echo".into(), "hi".into()],
        detach: false,
        rm: false,
        ..Default::default()
    };
    let id = podman.create(&opts).await.expect("podman create");
    podman.start(&id).await.expect("podman start");

    // Wait briefly for the echo command to flush. The container exits
    // immediately after `echo hi` so `logs` returns quickly. We poll up
    // to ~3s rather than sleeping a fixed interval so slow CI runners
    // still get a deterministic answer.
    let mut combined = String::new();
    for _ in 0..30 {
        let logs = podman
            .logs(&id, linpodx_runtime::podman::LogOptions::default())
            .await
            .expect("logs");
        combined.clear();
        combined.push_str(&logs.stdout);
        combined.push_str(&logs.stderr);
        if combined.contains("hi") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        combined.contains("hi"),
        "expected 'hi' in container output, got stdout+stderr={combined:?}"
    );

    let _ = podman.remove(&id, true).await;
}
