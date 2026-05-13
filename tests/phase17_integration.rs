//! Phase 17 cross-crate integration tests.
//!
//! Scenarios (all `#[ignore]`-gated — they exercise either Podman, the running
//! daemon, or a multi-node Raft cluster, none of which are available in the
//! default `cargo test` workspace run):
//!
//!   1. argon2id encrypt → decrypt round-trip — proves the Phase 17 KDF
//!      replacement composes with the existing AES-256-GCM layer.
//!   2. key-rotation round-trip — encrypt under old passphrase, rotate to a
//!      new passphrase, decrypt under the new key (and reject the old).
//!   3. re-encrypt-all sweep — 2+ snapshot side-cars rotated in one pass.
//!   4. sandbox auto-trigger — `SandboxSnapshotAutoTriggerEnableParams`
//!      flow turns on auto-encrypt and a synthetic commit event encrypts the
//!      blob automatically.
//!   5. TOFU expiry — `tofu_expires_at` elapsed → `should_enroll = false` +
//!      a `TofuExpired` audit row is written.
//!   6. plugin-key revocation Raft propagation — the leader revokes a key,
//!      the follower picks it up via the Raft log.
//!
//! Scenarios 4-6 depend on Stream B/C code that has not landed yet — those
//! tests are still here as compile-checked stubs so the harness is ready the
//! moment those streams ship.

use linpodx_common::audit_sink::AuditSinkKind;
use linpodx_common::ipc::{
    DaemonPinClientTofuExpirySetParams, PluginKeyRevokePropagateParams,
    SandboxSnapshotAutoTriggerEnableParams, SnapshotKeyRotateParams, SnapshotKeySource,
    SnapshotReEncryptAllParams,
};
use linpodx_runtime::snapshot_crypto::{
    decrypt_bytes, derive_key_from_passphrase, encrypt_bytes, sha256_hex, CryptoError,
    EncryptionConfig, KDF_SALT_DEFAULT, KEY_LEN,
};

// ---------------------------------------------------------------------------
// Phase 17 — argon2id KDF (Stream A surface).
// ---------------------------------------------------------------------------

/// Local argon2id helper that mirrors the parameters Stream A will commit.
/// We keep it in-test so the harness can verify round-trip behaviour even if
/// Stream A is still landing.
fn argon2id_derive(passphrase: &str, salt: &[u8; 16]) -> [u8; KEY_LEN] {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(19_456, 2, 1, Some(KEY_LEN)).expect("argon2 params");
    let kdf = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; KEY_LEN];
    kdf.hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .expect("argon2id hash");
    out
}

#[test]
fn argon2id_encrypt_decrypt_round_trip() {
    let key = argon2id_derive("hunter2-correct-horse", KDF_SALT_DEFAULT);
    let cfg = EncryptionConfig::from_key(key);
    let plain = b"phase17 snapshot meta payload";
    let blob = encrypt_bytes(plain, &cfg).expect("encrypt");
    assert!(blob.len() > plain.len(), "expected nonce + ct + tag");
    let recovered = decrypt_bytes(&blob, &cfg).expect("decrypt");
    assert_eq!(recovered, plain);
}

#[test]
fn argon2id_is_deterministic_for_same_passphrase_and_salt() {
    let a = argon2id_derive("same", KDF_SALT_DEFAULT);
    let b = argon2id_derive("same", KDF_SALT_DEFAULT);
    let c = argon2id_derive("different", KDF_SALT_DEFAULT);
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn argon2id_diverges_from_legacy_sha256_rounds() {
    // The two KDFs must produce different keys for the same passphrase so a
    // migration is always observable.
    let argon = argon2id_derive("hunter2", KDF_SALT_DEFAULT);
    let legacy = derive_key_from_passphrase("hunter2", KDF_SALT_DEFAULT);
    assert_ne!(argon, legacy);
}

// ---------------------------------------------------------------------------
// Phase 17 — key rotation round-trip (Stream A logical contract).
// ---------------------------------------------------------------------------

#[test]
fn key_rotation_round_trip_in_memory() {
    // 1) Encrypt under the *old* key.
    let old_key = argon2id_derive("old-passphrase", KDF_SALT_DEFAULT);
    let old_cfg = EncryptionConfig::from_key(old_key);
    let plain = b"snapshot side-car payload";
    let old_blob = encrypt_bytes(plain, &old_cfg).expect("encrypt-old");
    let old_sha = sha256_hex(&old_blob);

    // 2) "Rotate" — decrypt under old, re-encrypt under new.
    let recovered = decrypt_bytes(&old_blob, &old_cfg).expect("decrypt-old");
    let new_key = argon2id_derive("new-passphrase", KDF_SALT_DEFAULT);
    let new_cfg = EncryptionConfig::from_key(new_key);
    let new_blob = encrypt_bytes(&recovered, &new_cfg).expect("encrypt-new");
    let new_sha = sha256_hex(&new_blob);

    // 3) Old key must no longer decrypt the new blob.
    assert!(matches!(
        decrypt_bytes(&new_blob, &old_cfg),
        Err(CryptoError::Decrypt)
    ));

    // 4) New key recovers the plaintext.
    let recovered_2 = decrypt_bytes(&new_blob, &new_cfg).expect("decrypt-new");
    assert_eq!(recovered_2, plain);

    // 5) Ciphertext fingerprint must change so the daemon can record the
    //    rotation in the `snapshots.rotated_from_snapshot_id` column.
    assert_ne!(old_sha, new_sha);
}

// ---------------------------------------------------------------------------
// Phase 17 — IPC schema sanity (Stage 1 deliverable, callable now).
// ---------------------------------------------------------------------------

/// The IPC params for the Phase 17 arms must serialise/deserialise cleanly so
/// daemon dispatch + the JSON-RPC layer agree on the wire format. Run on every
/// `cargo test` invocation (no `#[ignore]`).
#[test]
fn phase17_ipc_params_round_trip_through_json() {
    let rot = SnapshotKeyRotateParams {
        snapshot_id: 42,
        new_key: SnapshotKeySource::Env {
            var: "LINPODX_SNAPSHOT_KEY".into(),
        },
    };
    let s = serde_json::to_string(&rot).unwrap();
    let back: SnapshotKeyRotateParams = serde_json::from_str(&s).unwrap();
    assert_eq!(back.snapshot_id, 42);

    let re = SnapshotReEncryptAllParams {
        new_key: SnapshotKeySource::Explicit {
            key_b64: "AAAA".into(),
        },
    };
    let _: SnapshotReEncryptAllParams =
        serde_json::from_str(&serde_json::to_string(&re).unwrap()).unwrap();

    let prop = PluginKeyRevokePropagateParams {
        publisher: "linpodx-publisher".into(),
        fingerprint: "deadbeef".into(),
        reason: Some("rotated".into()),
    };
    let _: PluginKeyRevokePropagateParams =
        serde_json::from_str(&serde_json::to_string(&prop).unwrap()).unwrap();

    let auto = SandboxSnapshotAutoTriggerEnableParams { enabled: true };
    let _: SandboxSnapshotAutoTriggerEnableParams =
        serde_json::from_str(&serde_json::to_string(&auto).unwrap()).unwrap();

    let tofu = DaemonPinClientTofuExpirySetParams {
        max_age_secs: Some(3600),
    };
    let _: DaemonPinClientTofuExpirySetParams =
        serde_json::from_str(&serde_json::to_string(&tofu).unwrap()).unwrap();
}

/// New AuditSinkKind variants must serialise to the documented wire strings.
#[test]
fn phase17_audit_kind_wire_strings() {
    assert_eq!(
        AuditSinkKind::SnapshotKeyRotated.as_str(),
        "snapshot_key_rotated"
    );
    assert_eq!(
        AuditSinkKind::SnapshotReEncryptCompleted.as_str(),
        "snapshot_re_encrypt_completed"
    );
    assert_eq!(
        AuditSinkKind::SandboxSnapshotAutoTriggered.as_str(),
        "sandbox_snapshot_auto_triggered"
    );
    assert_eq!(AuditSinkKind::TofuExpired.as_str(), "tofu_expired");
    assert_eq!(
        AuditSinkKind::PluginKeyRevokePropagated.as_str(),
        "plugin_key_revoke_propagated"
    );
}

// ---------------------------------------------------------------------------
// Phase 17 — migration 0017 schema sanity (no daemon spin-up needed).
// ---------------------------------------------------------------------------

/// Apply migrations 0001-0017 against an in-memory SQLite and verify the
/// Phase 17 columns + table exist. Catches accidental migration corruption
/// before any daemon code touches the new schema.
#[tokio::test]
async fn migration_0017_columns_and_tables_present() {
    use sqlx::sqlite::SqlitePoolOptions;

    // Use a temp file (in-memory pools share the schema only inside the same
    // connection — easier to keep a real file in /tmp).
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("phase17.sqlite");
    let url = format!("sqlite://{}?mode=rwc", db_path.display());
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("connect sqlite");

    // sqlx::migrate! resolves relative to CARGO_MANIFEST_DIR of the crate that
    // invokes the macro. Here that is the tests crate, so reach back into
    // linpodx-common explicitly.
    let migrations_dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../crates/linpodx-common/migrations"
    );
    let migrator = sqlx::migrate::Migrator::new(std::path::Path::new(migrations_dir))
        .await
        .expect("load migrations");
    migrator.run(&pool).await.expect("run migrations");

    // Phase 17 snapshot columns.
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM pragma_table_info('snapshots') WHERE name = 'kdf_algorithm'",
    )
    .fetch_one(&pool)
    .await
    .expect("query kdf_algorithm");
    assert_eq!(row.0, 1, "snapshots.kdf_algorithm missing");

    for col in ["kdf_params", "rotated_from_snapshot_id", "rotated_at"] {
        let q = format!("SELECT COUNT(*) FROM pragma_table_info('snapshots') WHERE name = '{col}'");
        let row: (i64,) = sqlx::query_as(&q).fetch_one(&pool).await.expect("col");
        assert_eq!(row.0, 1, "snapshots.{col} missing");
    }

    // Phase 17 pinned_clients column.
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM pragma_table_info('pinned_clients') WHERE name = 'tofu_expires_at'",
    )
    .fetch_one(&pool)
    .await
    .expect("query tofu_expires_at");
    assert_eq!(row.0, 1, "pinned_clients.tofu_expires_at missing");

    // Phase 17 plugin_key_revocations table.
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='plugin_key_revocations'",
    )
    .fetch_one(&pool)
    .await
    .expect("query plugin_key_revocations");
    assert_eq!(row.0, 1, "plugin_key_revocations table missing");
}

// ---------------------------------------------------------------------------
// Stream A — re-encrypt-all sweep (Podman-gated; `#[ignore]`).
// ---------------------------------------------------------------------------

/// Re-encrypt-all over 2+ snapshot side-cars. Skeleton — Stream A wires the
/// daemon-side dispatch; until that lands we exercise the in-memory contract.
#[tokio::test]
#[ignore]
async fn re_encrypt_all_two_snapshots_in_memory() {
    let old = EncryptionConfig::from_key(argon2id_derive("old-pw", KDF_SALT_DEFAULT));
    let new_key = argon2id_derive("new-pw", KDF_SALT_DEFAULT);
    let new = EncryptionConfig::from_key(new_key);

    let payloads: [&[u8]; 3] = [
        b"snapshot 1 payload",
        b"snapshot 2 payload (slightly larger)",
        b"snapshot 3 payload (yet larger so the sweep walks distinct blobs)",
    ];

    let mut old_blobs = Vec::with_capacity(payloads.len());
    for p in payloads.iter() {
        old_blobs.push(encrypt_bytes(p, &old).expect("encrypt old"));
    }

    // "Sweep" — decrypt with old, re-encrypt with new.
    let mut new_blobs = Vec::with_capacity(payloads.len());
    for blob in old_blobs.iter() {
        let plain = decrypt_bytes(blob, &old).expect("decrypt old");
        new_blobs.push(encrypt_bytes(&plain, &new).expect("encrypt new"));
    }

    // Verify every new blob decrypts under the new key and not the old.
    for (i, blob) in new_blobs.iter().enumerate() {
        let recovered = decrypt_bytes(blob, &new).expect("decrypt new");
        assert_eq!(recovered, payloads[i]);
        assert!(matches!(
            decrypt_bytes(blob, &old),
            Err(CryptoError::Decrypt)
        ));
    }
}

// ---------------------------------------------------------------------------
// Stream B — sandbox auto-trigger (Podman + sandbox runtime; `#[ignore]`).
// ---------------------------------------------------------------------------

/// Marker test: once Stream B's `SandboxSnapshotAutoTriggerEnable` IPC arm is
/// wired into the daemon, this should drive a real commit event through it.
/// Until then we only verify the params type can be constructed (proving the
/// schema contract is intact).
#[tokio::test]
#[ignore]
async fn sandbox_auto_trigger_enables_and_records_commit() {
    let params = SandboxSnapshotAutoTriggerEnableParams { enabled: true };
    // TODO(stream-b): spawn daemon, send the arm, fire a commit event, and
    // assert a `SandboxSnapshotAutoTriggered` audit row appears.
    assert!(params.enabled);
}

// ---------------------------------------------------------------------------
// Stream C — TOFU expiry (daemon-gated; `#[ignore]`).
// ---------------------------------------------------------------------------

/// Marker test for the TOFU expiry path. Once Stream C lands its
/// `DaemonPinClientTofuExpirySet` + `should_enroll` plumbing this should
/// fast-forward time and assert `TofuExpired` is recorded.
#[tokio::test]
#[ignore]
async fn tofu_expiry_disables_enrollment_after_max_age() {
    let params = DaemonPinClientTofuExpirySetParams {
        max_age_secs: Some(1),
    };
    // TODO(stream-c): spawn daemon, enable TOFU, set 1s expiry, sleep 2s,
    // verify `should_enroll == false` and a `TofuExpired` audit row exists.
    assert_eq!(params.max_age_secs, Some(1));
}

// ---------------------------------------------------------------------------
// Stream C — plugin key revocation Raft propagation (multi-node; `#[ignore]`).
// ---------------------------------------------------------------------------

/// Marker test for the Raft revocation propagation path. Stream C lands the
/// leader→follower replication of plugin-key revocations; this test will
/// spin up a 2-node cluster and assert the follower writes a `.revoked`
/// marker once Stream C is in.
#[tokio::test]
#[ignore]
async fn plugin_key_revocation_propagates_through_raft() {
    let params = PluginKeyRevokePropagateParams {
        publisher: "linpodx-publisher".into(),
        fingerprint: "deadbeefcafef00d".into(),
        reason: Some("compromised".into()),
    };
    // TODO(stream-c): spawn 2-node Raft cluster, leader revokes, assert the
    // follower's KeyRegistry has the `.revoked` marker.
    assert_eq!(params.publisher, "linpodx-publisher");
}
