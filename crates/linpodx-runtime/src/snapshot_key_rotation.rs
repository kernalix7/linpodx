//! Phase 17 Stream A — snapshot key rotation + re-encryption.
//!
//! Takes a snapshot that was previously encrypted via
//! [`crate::snapshot::encrypt_committed_image`] and replaces its at-rest key
//! material without re-running `podman commit`. The blob is decrypted in
//! memory under the old key, re-encrypted under the new key, and the side-car
//! `meta.json` is rewritten atomically. The `snapshots` row's
//! `kdf_algorithm` / `kdf_params` / `rotated_from_snapshot_id` / `rotated_at`
//! columns (added in migration 0017) are then updated so the daemon's
//! `snapshot.encryption_status` arm can answer authoritatively without
//! re-reading the side-car.
//!
//! The module deliberately has no direct knowledge of the daemon dispatcher —
//! it takes a `&Database` and is callable from both the JSON-RPC path and
//! integration tests.

use crate::snapshot::{encrypted_image_dir, is_image_encrypted, EncryptedSnapshotMeta};
use crate::snapshot_crypto::{
    self, decrypt_bytes, encrypt_bytes, sha256_hex, EncryptionConfig, Kdf, KeySource,
    KDF_SALT_DEFAULT,
};
use chrono::Utc;
use linpodx_common::db::Database;
use linpodx_common::error::{Error, Result};
use sqlx::Row;
use tracing::{instrument, warn};

/// Source of the **new** key material applied during rotation. Mirrors the
/// IPC-level enum `linpodx_common::ipc::SnapshotKeySource` but stays inside
/// the runtime crate so callers don't need to depend on the IPC schema.
#[derive(Debug, Clone)]
pub enum NewKeySource {
    /// Derive the new key from a passphrase using the supplied KDF.
    Passphrase { passphrase: String, kdf: Kdf },
    /// Use a base64-encoded raw 32-byte key directly. The persisted `kdf`
    /// becomes `Argon2id` with default params for forward-compat (the actual
    /// key bypasses the KDF, but rotating into the same shape keeps meta.json
    /// uniform).
    Explicit { key_b64: String },
    /// Resolve the new key from an environment variable (raw base64 key,
    /// identical handling to `LINPODX_SNAPSHOT_KEY`).
    Env { var: String },
}

impl NewKeySource {
    /// Turn the supplied source into an [`EncryptionConfig`] ready to encrypt
    /// the freshly-decrypted plaintext under.
    pub fn into_config(self) -> Result<EncryptionConfig> {
        match self {
            NewKeySource::Passphrase { passphrase, kdf } => {
                let key =
                    snapshot_crypto::derive_key(passphrase.as_bytes(), KDF_SALT_DEFAULT, &kdf)
                        .map_err(|e| Error::Runtime {
                            message: format!("rotate: derive new key: {e}"),
                        })?;
                Ok(EncryptionConfig {
                    key,
                    algorithm: snapshot_crypto::ALGORITHM,
                    key_source: KeySource::Passphrase,
                    kdf,
                })
            }
            NewKeySource::Explicit { key_b64 } => {
                let key =
                    snapshot_crypto::key_from_base64(&key_b64).map_err(|e| Error::Runtime {
                        message: format!("rotate: decode explicit key: {e}"),
                    })?;
                Ok(EncryptionConfig {
                    key,
                    algorithm: snapshot_crypto::ALGORITHM,
                    key_source: KeySource::Explicit,
                    kdf: Kdf::argon2id_default(),
                })
            }
            NewKeySource::Env { var } => {
                let raw = std::env::var(&var).map_err(|_| Error::Runtime {
                    message: format!("rotate: env var {var} is not set"),
                })?;
                let key = snapshot_crypto::key_from_base64(&raw).map_err(|e| Error::Runtime {
                    message: format!("rotate: decode env key from {var}: {e}"),
                })?;
                Ok(EncryptionConfig {
                    key,
                    algorithm: snapshot_crypto::ALGORITHM,
                    key_source: KeySource::Env,
                    kdf: Kdf::argon2id_default(),
                })
            }
        }
    }
}

/// Result of a single-snapshot rotation. Returned to the dispatch arm so the
/// `SnapshotKeyRotateResponse` can echo the new ciphertext sha + algorithm
/// without re-reading meta.json.
#[derive(Debug, Clone)]
pub struct RotateOutcome {
    pub snapshot_id: i64,
    pub image_ref: String,
    pub algorithm: String,
    pub kdf: String,
    pub ciphertext_sha256: String,
    pub rotated_at: chrono::DateTime<chrono::Utc>,
}

/// Aggregate result of [`re_encrypt_all`].
#[derive(Debug, Clone, Default)]
pub struct ReEncryptAllOutcome {
    pub total_seen: u32,
    pub re_encrypted: u32,
    pub skipped: u32,
    pub failed: u32,
}

/// Rotate the at-rest encryption key for a single snapshot. Looks up the row
/// in `snapshots`, opens the side-car under `old_cfg`, re-encrypts under
/// `new_cfg`, then rewrites meta.json + blob.enc atomically and updates the
/// rotation columns added by migration 0017.
#[instrument(skip(db, old_cfg, new_cfg), fields(snapshot_id))]
pub async fn rotate_snapshot_key(
    db: &Database,
    snapshot_id: i64,
    old_cfg: &EncryptionConfig,
    new_cfg: &EncryptionConfig,
) -> Result<RotateOutcome> {
    let image_ref: String = sqlx::query_scalar("SELECT image_ref FROM snapshots WHERE id = ?")
        .bind(snapshot_id)
        .fetch_optional(db.pool())
        .await
        .map_err(Error::Sqlx)?
        .ok_or_else(|| Error::NotFound(format!("snapshot id {snapshot_id}")))?;

    if !is_image_encrypted(&image_ref) {
        return Err(Error::Runtime {
            message: format!(
                "snapshot {snapshot_id} ({image_ref}) is not encrypted — nothing to rotate"
            ),
        });
    }

    let (new_meta, rotated_at) = rotate_on_disk(&image_ref, snapshot_id, old_cfg, new_cfg).await?;

    let kdf_params = serde_json::to_string(&new_meta.kdf).map_err(|e| Error::Runtime {
        message: format!("serialise kdf params: {e}"),
    })?;
    let rotated_at_unix = rotated_at.timestamp();

    sqlx::query(
        "UPDATE snapshots SET algorithm = ?, ciphertext_sha256 = ?, key_source = ?, \
         kdf_algorithm = ?, kdf_params = ?, rotated_from_snapshot_id = ?, rotated_at = ? \
         WHERE id = ?",
    )
    .bind(&new_meta.algorithm)
    .bind(&new_meta.ciphertext_sha256)
    .bind(&new_meta.key_source)
    .bind(new_meta.kdf.as_str())
    .bind(&kdf_params)
    .bind(snapshot_id)
    .bind(rotated_at_unix)
    .bind(snapshot_id)
    .execute(db.pool())
    .await
    .map_err(Error::Sqlx)?;

    Ok(RotateOutcome {
        snapshot_id,
        image_ref,
        algorithm: new_meta.algorithm,
        kdf: new_meta.kdf.as_str().to_string(),
        ciphertext_sha256: new_meta.ciphertext_sha256,
        rotated_at,
    })
}

/// Re-encrypt every encrypted snapshot in the DB under `new_cfg`. Snapshots
/// without a side-car (never-encrypted rows) are counted as `skipped` rather
/// than failed. Errors on individual rows are recorded under `failed` and the
/// sweep continues — callers reading the aggregate can decide whether a
/// partial success is acceptable.
#[instrument(skip(db, old_cfg, new_cfg))]
pub async fn re_encrypt_all(
    db: &Database,
    old_cfg: &EncryptionConfig,
    new_cfg: &EncryptionConfig,
) -> Result<ReEncryptAllOutcome> {
    let rows = sqlx::query("SELECT id FROM snapshots ORDER BY id ASC")
        .fetch_all(db.pool())
        .await
        .map_err(Error::Sqlx)?;

    let mut outcome = ReEncryptAllOutcome::default();
    for row in rows {
        outcome.total_seen += 1;
        let id: i64 = row.try_get(0).map_err(Error::Sqlx)?;
        match rotate_snapshot_key(db, id, old_cfg, new_cfg).await {
            Ok(_) => outcome.re_encrypted += 1,
            Err(Error::Runtime { message }) if message.contains("is not encrypted") => {
                outcome.skipped += 1;
            }
            Err(e) => {
                outcome.failed += 1;
                warn!(snapshot_id = id, error = %e, "re_encrypt_all: row failed (continuing)");
            }
        }
    }
    Ok(outcome)
}

/// On-disk side of the rotation: read blob.enc + meta.json, decrypt, re-encrypt,
/// rewrite both files atomically. Returns the freshly-written meta plus the
/// rotation timestamp.
async fn rotate_on_disk(
    image_ref: &str,
    snapshot_id: i64,
    old_cfg: &EncryptionConfig,
    new_cfg: &EncryptionConfig,
) -> Result<(EncryptedSnapshotMeta, chrono::DateTime<chrono::Utc>)> {
    let dir = encrypted_image_dir(image_ref);
    let old_cfg = old_cfg.clone();
    let new_cfg = new_cfg.clone();
    let image_ref_owned = image_ref.to_string();

    tokio::task::spawn_blocking(
        move || -> Result<(EncryptedSnapshotMeta, chrono::DateTime<chrono::Utc>)> {
            let meta_path = dir.join("meta.json");
            let blob_path = dir.join("blob.enc");
            let meta_bytes = std::fs::read(&meta_path).map_err(|e| Error::Runtime {
                message: format!("rotate: read {}: {e}", meta_path.display()),
            })?;
            let old_meta: EncryptedSnapshotMeta =
                serde_json::from_slice(&meta_bytes).map_err(|e| Error::Runtime {
                    message: format!("rotate: parse meta.json: {e}"),
                })?;
            let blob = std::fs::read(&blob_path).map_err(|e| Error::Runtime {
                message: format!("rotate: read {}: {e}", blob_path.display()),
            })?;

            // Tamper check against the recorded sha matches the decrypt path.
            let actual_sha = sha256_hex(&blob);
            if actual_sha != old_meta.ciphertext_sha256 {
                return Err(Error::Runtime {
                    message: format!(
                        "rotate: ciphertext sha mismatch (meta={} disk={})",
                        old_meta.ciphertext_sha256, actual_sha
                    ),
                });
            }

            let plain = decrypt_bytes(&blob, &old_cfg).map_err(|e| Error::Runtime {
                message: format!("rotate: decrypt under old key: {e}"),
            })?;

            let new_blob = encrypt_bytes(&plain, &new_cfg).map_err(|e| Error::Runtime {
                message: format!("rotate: encrypt under new key: {e}"),
            })?;
            let new_sha = sha256_hex(&new_blob);
            let rotated_at = Utc::now();

            let new_meta = EncryptedSnapshotMeta {
                algorithm: new_cfg.algorithm.to_string(),
                key_source: new_cfg.key_source.as_str().to_string(),
                ciphertext_sha256: new_sha,
                original_image_ref: image_ref_owned,
                created_at: old_meta.created_at,
                plaintext_len: old_meta.plaintext_len,
                kdf: new_cfg.kdf,
                rotated_from_snapshot_id: Some(snapshot_id),
                rotated_at: Some(rotated_at),
            };

            // Atomic rewrite: blob.enc first (so a partial failure leaves the old
            // meta dangling instead of leaving a meta with no matching blob).
            let blob_tmp = dir.join("blob.enc.tmp");
            std::fs::write(&blob_tmp, &new_blob).map_err(|e| Error::Runtime {
                message: format!("rotate: write {}: {e}", blob_tmp.display()),
            })?;
            std::fs::rename(&blob_tmp, &blob_path).map_err(|e| Error::Runtime {
                message: format!(
                    "rotate: rename {} -> {}: {e}",
                    blob_tmp.display(),
                    blob_path.display()
                ),
            })?;

            let meta_tmp = dir.join("meta.json.tmp");
            let bytes = serde_json::to_vec_pretty(&new_meta).map_err(|e| Error::Runtime {
                message: format!("rotate: serialise meta.json: {e}"),
            })?;
            std::fs::write(&meta_tmp, &bytes).map_err(|e| Error::Runtime {
                message: format!("rotate: write {}: {e}", meta_tmp.display()),
            })?;
            std::fs::rename(&meta_tmp, &meta_path).map_err(|e| Error::Runtime {
                message: format!(
                    "rotate: rename {} -> {}: {e}",
                    meta_tmp.display(),
                    meta_path.display()
                ),
            })?;

            Ok((new_meta, rotated_at))
        },
    )
    .await
    .map_err(|e| Error::Runtime {
        message: format!("rotate: blocking join: {e}"),
    })?
}

/// Sanity wrapper used by callers that already have a `read_encrypted_meta`
/// result and just want to know whether the on-disk record claims a rotation
/// has happened. Cheap — no I/O beyond the cached `meta`.
pub fn meta_indicates_rotation(meta: &EncryptedSnapshotMeta) -> bool {
    meta.rotated_at.is_some() || meta.rotated_from_snapshot_id.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{encrypted_image_dir, read_encrypted_meta, EncryptedSnapshotMeta};
    use crate::snapshot_crypto::{encrypt_bytes, sha256_hex, EncryptionConfig, Kdf, KeySource};
    use linpodx_common::db::Database;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    struct EncRootGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        prev: Option<String>,
        _tmp: tempfile::TempDir,
    }
    impl EncRootGuard {
        fn new() -> Self {
            let lock = env_lock().lock().unwrap_or_else(|p| p.into_inner());
            let prev = std::env::var("LINPODX_ENCRYPTED_SNAPSHOT_ROOT").ok();
            let tmp = tempfile::tempdir().expect("encroot tmp");
            std::env::set_var(
                "LINPODX_ENCRYPTED_SNAPSHOT_ROOT",
                tmp.path().to_string_lossy().to_string(),
            );
            Self {
                _lock: lock,
                prev,
                _tmp: tmp,
            }
        }
    }
    impl Drop for EncRootGuard {
        fn drop(&mut self) {
            match self.prev.take() {
                Some(v) => std::env::set_var("LINPODX_ENCRYPTED_SNAPSHOT_ROOT", v),
                None => std::env::remove_var("LINPODX_ENCRYPTED_SNAPSHOT_ROOT"),
            }
        }
    }

    /// Write a fake meta.json + blob.enc for `image_ref` under the current
    /// encrypted-root. Returns the ciphertext sha for downstream assertions.
    fn seed_encrypted_snapshot(
        image_ref: &str,
        plaintext: &[u8],
        cfg: &EncryptionConfig,
    ) -> EncryptedSnapshotMeta {
        let dir = encrypted_image_dir(image_ref);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let blob = encrypt_bytes(plaintext, cfg).expect("encrypt");
        let sha = sha256_hex(&blob);
        std::fs::write(dir.join("blob.enc"), &blob).expect("write blob");
        let meta = EncryptedSnapshotMeta {
            algorithm: cfg.algorithm.to_string(),
            key_source: cfg.key_source.as_str().to_string(),
            ciphertext_sha256: sha,
            original_image_ref: image_ref.to_string(),
            created_at: chrono::Utc::now(),
            plaintext_len: plaintext.len() as u64,
            kdf: cfg.kdf,
            rotated_from_snapshot_id: None,
            rotated_at: None,
        };
        let bytes = serde_json::to_vec_pretty(&meta).unwrap();
        std::fs::write(dir.join("meta.json"), &bytes).expect("write meta");
        meta
    }

    async fn open_test_db() -> Database {
        let db = Database::open("sqlite::memory:")
            .await
            .expect("open sqlite memory");
        // Minimal snapshots schema reproducing the migrations used by the
        // rotation path. We deliberately mirror the columns the rotation
        // module writes so the SQL `UPDATE` doesn't error on missing columns
        // when the test runs without the daemon migration suite.
        sqlx::query(
            "CREATE TABLE snapshots (\
                id INTEGER PRIMARY KEY AUTOINCREMENT, \
                container_id TEXT NOT NULL, \
                label TEXT, \
                image_ref TEXT NOT NULL, \
                parent_id INTEGER, \
                created_at TEXT, \
                size_bytes INTEGER, \
                backend TEXT, \
                encrypted INTEGER NOT NULL DEFAULT 0, \
                algorithm TEXT, \
                key_source TEXT, \
                ciphertext_sha256 TEXT, \
                kdf_algorithm TEXT, \
                kdf_params TEXT, \
                rotated_from_snapshot_id INTEGER, \
                rotated_at INTEGER\
            )",
        )
        .execute(db.pool())
        .await
        .expect("create snapshots");
        db
    }

    async fn insert_snapshot(db: &Database, image_ref: &str) -> i64 {
        let row = sqlx::query(
            "INSERT INTO snapshots (container_id, image_ref, encrypted, algorithm) \
             VALUES (?, ?, 1, 'aes-256-gcm') RETURNING id",
        )
        .bind("ctr-fake")
        .bind(image_ref)
        .fetch_one(db.pool())
        .await
        .expect("insert snapshot");
        row.try_get::<i64, _>(0).expect("id")
    }

    #[tokio::test]
    async fn rotate_round_trips_blob_under_new_argon2id_key() {
        let _g = EncRootGuard::new();
        let db = open_test_db().await;
        let image_ref = "rotate-test/image:tag";
        let id = insert_snapshot(&db, image_ref).await;

        let old_cfg = EncryptionConfig {
            kdf: Kdf::sha256_legacy(),
            key_source: KeySource::Passphrase,
            ..EncryptionConfig::from_key([7u8; 32])
        };
        let plaintext = b"the quick brown fox jumps over the lazy dog";
        seed_encrypted_snapshot(image_ref, plaintext, &old_cfg);

        let new_cfg = EncryptionConfig {
            kdf: Kdf::argon2id_default(),
            key_source: KeySource::Passphrase,
            ..EncryptionConfig::from_key([42u8; 32])
        };

        let outcome = rotate_snapshot_key(&db, id, &old_cfg, &new_cfg)
            .await
            .expect("rotate");
        assert_eq!(outcome.snapshot_id, id);
        assert_eq!(outcome.kdf, "argon2id");

        // Side-car was rewritten and now decrypts only under the new key.
        let meta = read_encrypted_meta(image_ref).expect("read").expect("some");
        assert_eq!(meta.ciphertext_sha256, outcome.ciphertext_sha256);
        assert!(matches!(meta.kdf, Kdf::Argon2id { .. }));
        assert_eq!(meta.rotated_from_snapshot_id, Some(id));
        assert!(meta.rotated_at.is_some());

        // DB columns reflect the new state.
        let row: (String, String, Option<i64>, Option<i64>) = sqlx::query_as(
            "SELECT kdf_algorithm, ciphertext_sha256, rotated_from_snapshot_id, rotated_at \
             FROM snapshots WHERE id = ?",
        )
        .bind(id)
        .fetch_one(db.pool())
        .await
        .expect("select");
        assert_eq!(row.0, "argon2id");
        assert_eq!(row.1, outcome.ciphertext_sha256);
        assert_eq!(row.2, Some(id));
        assert!(row.3.is_some());

        // Re-encrypted blob is decryptable under the new key, not the old one.
        let dir = encrypted_image_dir(image_ref);
        let blob = std::fs::read(dir.join("blob.enc")).expect("read blob");
        let plain_new =
            crate::snapshot_crypto::decrypt_bytes(&blob, &new_cfg).expect("decrypt under new key");
        assert_eq!(plain_new, plaintext);
        let err = crate::snapshot_crypto::decrypt_bytes(&blob, &old_cfg)
            .expect_err("old key must reject");
        assert!(matches!(err, crate::snapshot_crypto::CryptoError::Decrypt));
    }

    #[tokio::test]
    async fn rotate_rejects_when_snapshot_not_encrypted() {
        let _g = EncRootGuard::new();
        let db = open_test_db().await;
        let id = insert_snapshot(&db, "bare-image:plain").await;
        let cfg = EncryptionConfig::from_key([0u8; 32]);
        let err = rotate_snapshot_key(&db, id, &cfg, &cfg).await.unwrap_err();
        assert!(matches!(err, Error::Runtime { ref message } if message.contains("not encrypted")));
    }

    #[tokio::test]
    async fn rotate_unknown_id_is_not_found() {
        let _g = EncRootGuard::new();
        let db = open_test_db().await;
        let cfg = EncryptionConfig::from_key([0u8; 32]);
        let err = rotate_snapshot_key(&db, 9999, &cfg, &cfg)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::NotFound(_)));
    }

    #[tokio::test]
    async fn re_encrypt_all_counts_skipped_and_rotated() {
        let _g = EncRootGuard::new();
        let db = open_test_db().await;

        let old_cfg = EncryptionConfig {
            kdf: Kdf::sha256_legacy(),
            ..EncryptionConfig::from_key([3u8; 32])
        };
        let new_cfg = EncryptionConfig {
            kdf: Kdf::argon2id_default(),
            ..EncryptionConfig::from_key([9u8; 32])
        };

        let id_a = insert_snapshot(&db, "alpha:tag").await;
        let id_b = insert_snapshot(&db, "beta:tag").await;
        let id_unencrypted = insert_snapshot(&db, "gamma:tag").await;
        // Only seed side-cars for the first two.
        seed_encrypted_snapshot("alpha:tag", b"alpha-plain", &old_cfg);
        seed_encrypted_snapshot("beta:tag", b"beta-plain", &old_cfg);

        let outcome = re_encrypt_all(&db, &old_cfg, &new_cfg)
            .await
            .expect("sweep");
        assert_eq!(outcome.total_seen, 3);
        assert_eq!(outcome.re_encrypted, 2);
        assert_eq!(outcome.skipped, 1);
        assert_eq!(outcome.failed, 0);

        // Both rotated rows now show argon2id; the bare row stays untouched.
        let kdf_a: Option<String> =
            sqlx::query_scalar("SELECT kdf_algorithm FROM snapshots WHERE id = ?")
                .bind(id_a)
                .fetch_one(db.pool())
                .await
                .unwrap();
        let kdf_b: Option<String> =
            sqlx::query_scalar("SELECT kdf_algorithm FROM snapshots WHERE id = ?")
                .bind(id_b)
                .fetch_one(db.pool())
                .await
                .unwrap();
        let kdf_c: Option<String> =
            sqlx::query_scalar("SELECT kdf_algorithm FROM snapshots WHERE id = ?")
                .bind(id_unencrypted)
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(kdf_a.as_deref(), Some("argon2id"));
        assert_eq!(kdf_b.as_deref(), Some("argon2id"));
        assert!(kdf_c.is_none());
    }

    #[test]
    fn meta_indicates_rotation_false_for_fresh() {
        let meta = EncryptedSnapshotMeta {
            algorithm: "aes-256-gcm".into(),
            key_source: "passphrase".into(),
            ciphertext_sha256: "00".repeat(32),
            original_image_ref: "x".into(),
            created_at: chrono::Utc::now(),
            plaintext_len: 0,
            kdf: Kdf::argon2id_default(),
            rotated_from_snapshot_id: None,
            rotated_at: None,
        };
        assert!(!meta_indicates_rotation(&meta));
    }

    #[test]
    fn meta_indicates_rotation_true_after_rotation_fields_set() {
        let meta = EncryptedSnapshotMeta {
            algorithm: "aes-256-gcm".into(),
            key_source: "passphrase".into(),
            ciphertext_sha256: "00".repeat(32),
            original_image_ref: "x".into(),
            created_at: chrono::Utc::now(),
            plaintext_len: 0,
            kdf: Kdf::argon2id_default(),
            rotated_from_snapshot_id: Some(7),
            rotated_at: Some(chrono::Utc::now()),
        };
        assert!(meta_indicates_rotation(&meta));
    }

    /// Legacy Phase 16 meta.json files do **not** carry a `kdf` field. The
    /// `#[serde(default = "default_legacy_kdf")]` shim must classify them as
    /// `Sha256Rounds { rounds: 1000 }` so existing snapshots still decrypt.
    #[test]
    fn meta_without_kdf_field_deserialises_as_legacy_sha256() {
        let json = serde_json::json!({
            "algorithm": "aes-256-gcm",
            "key_source": "passphrase",
            "ciphertext_sha256": "ab".repeat(32),
            "original_image_ref": "legacy:ref",
            "created_at": chrono::Utc::now(),
            "plaintext_len": 1234,
        });
        let meta: EncryptedSnapshotMeta = serde_json::from_value(json).expect("de");
        match meta.kdf {
            Kdf::Sha256Rounds { rounds } => assert_eq!(rounds, 1000),
            other => panic!("expected legacy sha256, got {other:?}"),
        }
    }

    #[test]
    fn new_key_source_explicit_decodes_base64() {
        let raw = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [11u8; 32]);
        let cfg = NewKeySource::Explicit { key_b64: raw }
            .into_config()
            .expect("explicit");
        assert_eq!(cfg.key, [11u8; 32]);
        assert_eq!(cfg.key_source, KeySource::Explicit);
    }

    #[test]
    fn new_key_source_explicit_rejects_garbage() {
        let err = NewKeySource::Explicit {
            key_b64: "not base64!!!".into(),
        }
        .into_config()
        .expect_err("must fail");
        assert!(matches!(err, Error::Runtime { .. }));
    }

    #[test]
    fn new_key_source_passphrase_uses_supplied_kdf() {
        let cfg = NewKeySource::Passphrase {
            passphrase: "rotate-me".into(),
            kdf: Kdf::sha256_legacy(),
        }
        .into_config()
        .expect("pass");
        assert!(matches!(cfg.kdf, Kdf::Sha256Rounds { rounds: 1000 }));
        // Matches the standalone helper exactly.
        assert_eq!(
            cfg.key,
            crate::snapshot_crypto::derive_key_from_passphrase("rotate-me", KDF_SALT_DEFAULT)
        );
    }

    #[test]
    fn new_key_source_env_missing_var_errors() {
        // Use a deliberately unusual name to avoid collisions with other tests.
        let var = "LINPODX_TEST_ROTATE_ENV_MISSING_VAR";
        std::env::remove_var(var);
        let err = NewKeySource::Env { var: var.into() }
            .into_config()
            .expect_err("missing");
        assert!(matches!(err, Error::Runtime { .. }));
    }
}
