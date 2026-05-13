//! SQLite-backed plugin registry (Phase 6).
//!
//! Tracks one row per installed plugin in the `plugins` table (migration 0011). The
//! on-disk wasm files live under `linpodx_plugin::manifest::user_plugin_root()` and are
//! managed via `linpodx-plugin`'s install/remove helpers. This store wires the audit
//! sink and the IPC response shapes the daemon serves.

use crate::audit::{self, AuditKind};
use chrono::Utc;
use linpodx_common::audit_sink::{AuditSink, AuditSinkKind};
use linpodx_common::db::Database;
use linpodx_common::error::{Error, Result};
use linpodx_common::ipc::responses::{
    PluginInstallResponse, PluginListResponse, PluginRemoveResponse, PluginSummary,
    PluginToggleResponse,
};
use linpodx_common::ipc::{PluginInstallParams, PluginRemoveParams};
use linpodx_plugin::{
    install_to_user_dir, parse_from_dir, remove_user_dir, verify_plugin_signature, KeyRegistry,
    PluginError, PluginManifest, PluginSpec, SigningError,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{instrument, warn};

const ALLOW_UNSIGNED_ENV: &str = "LINPODX_ALLOW_UNSIGNED_PLUGINS";
const DETACHED_SIG_FILENAME: &str = "signature.b64";

/// Outcome of running the install-time signature checks. The install path uses this to
/// decide whether to abort and which audit kind to emit.
#[derive(Debug)]
enum SignatureOutcome {
    /// Signature was supplied and `verify_plugin_signature` returned `Ok`.
    Verified {
        publisher: Option<String>,
        key_source: String,
        signature_source: String,
    },
    /// No signature material was supplied (manifest has no publisher / no signature
    /// file) AND `LINPODX_ALLOW_UNSIGNED_PLUGINS=1` is set. Install proceeds, audit
    /// records the unsigned acceptance.
    UnsignedAccepted { reason: String },
    /// Signature check failed OR no signature was supplied without the env override.
    /// Install must abort.
    Rejected { reason: String },
}

pub struct PluginStore {
    db: Arc<Database>,
}

impl PluginStore {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    pub fn database(&self) -> &Arc<Database> {
        &self.db
    }

    #[instrument(skip(self))]
    pub async fn list(&self) -> Result<PluginListResponse> {
        let rows: Vec<PluginRow> = sqlx::query_as::<_, PluginRow>(
            "SELECT id, name, version, manifest_path, wasm_path, hooks, enabled, installed_at \
             FROM plugins ORDER BY id ASC",
        )
        .fetch_all(self.db.pool())
        .await
        .map_err(Error::Sqlx)?;
        rows.into_iter().map(PluginRow::into_summary).collect()
    }

    /// Same as [`Self::list`] but only rows with `enabled = 1`. Used by the daemon when
    /// it builds a `PluginRegistry` for the next approval call.
    pub async fn list_enabled_specs(&self) -> Result<Vec<PluginSpec>> {
        let rows: Vec<PluginRow> = sqlx::query_as::<_, PluginRow>(
            "SELECT id, name, version, manifest_path, wasm_path, hooks, enabled, installed_at \
             FROM plugins WHERE enabled = 1 ORDER BY id ASC",
        )
        .fetch_all(self.db.pool())
        .await
        .map_err(Error::Sqlx)?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let hooks: Vec<String> = serde_json::from_str(&row.hooks).map_err(Error::Json)?;
            out.push(PluginSpec {
                manifest: PluginManifest {
                    name: row.name,
                    version: row.version,
                    hooks,
                    wasm: row.wasm_path.clone(),
                    // The DB only persists the lifecycle row; signature metadata is a
                    // pre-install gate, not stored per-plugin. Always omitted here.
                    publisher: None,
                    signature_b64: None,
                },
                wasm_path: PathBuf::from(row.wasm_path),
            });
        }
        Ok(out)
    }

    #[instrument(skip(self, audit_sink))]
    pub async fn install(
        &self,
        audit_sink: &dyn AuditSink,
        params: &PluginInstallParams,
    ) -> Result<PluginInstallResponse> {
        let src = PathBuf::from(&params.manifest_path);
        let src_dir = if src.is_dir() {
            src.clone()
        } else {
            src.parent().map(PathBuf::from).ok_or_else(|| {
                Error::InvalidArgument(format!(
                    "plugin install path '{}' must be a directory or a manifest file",
                    src.display()
                ))
            })?
        };

        // Reject if a row with the same name already exists. (manifest::install_to_user_dir
        // also rejects a duplicate on-disk dir, but checking the DB first means we don't
        // depend on filesystem state.)
        let (manifest_preview, wasm_preview) = parse_from_dir(&src_dir).map_err(plugin_to_err)?;
        if let Some(existing) = self.row_by_name(&manifest_preview.name).await? {
            return Err(Error::InvalidArgument(format!(
                "plugin '{}' already installed (id={})",
                existing.name, existing.id
            )));
        }

        // Phase 15 — verify (or reject) the wasm signature *before* copying the plugin
        // into the user dir. We read wasm bytes from the source directory so a verify
        // failure leaves no on-disk artifacts behind.
        let outcome = check_signature(&src_dir, &wasm_preview, &manifest_preview, params)?;
        self.emit_signature_outcome(audit_sink, &manifest_preview, &outcome)
            .await;
        if let SignatureOutcome::Rejected { reason } = &outcome {
            return Err(Error::InvalidArgument(format!(
                "plugin '{}' signature check failed: {reason}",
                manifest_preview.name
            )));
        }

        let (installed_dir, manifest, wasm_abs) =
            install_to_user_dir(&src_dir).map_err(plugin_to_err)?;
        let manifest_path = installed_dir.join("linpodx-plugin.toml");
        let hooks_json = serde_json::to_string(&manifest.hooks).map_err(Error::Json)?;
        let now = Utc::now();
        let now_str = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        let row: (i64,) = sqlx::query_as(
            "INSERT INTO plugins (name, version, manifest_path, wasm_path, hooks, enabled, installed_at) \
             VALUES (?, ?, ?, ?, ?, 1, ?) RETURNING id",
        )
        .bind(&manifest.name)
        .bind(&manifest.version)
        .bind(manifest_path.to_string_lossy().as_ref())
        .bind(wasm_abs.to_string_lossy().as_ref())
        .bind(&hooks_json)
        .bind(&now_str)
        .fetch_one(self.db.pool())
        .await
        .map_err(Error::Sqlx)?;

        let payload = serde_json::json!({
            "id": row.0,
            "name": manifest.name,
            "version": manifest.version,
            "hooks": manifest.hooks,
            "installed_path": installed_dir.to_string_lossy(),
        });
        audit_sink
            .record(AuditSinkKind::PluginInstalled, None, None, payload.clone())
            .await;
        // Also write through to the local hash chain so the row participates in
        // `audit verify` even when callers pass a NoopAuditSink.
        if let Err(e) =
            audit::append(&self.db, AuditKind::PluginInstalled, None, None, payload).await
        {
            warn!(error = %e, "plugin install: local audit append failed");
        }

        Ok(PluginInstallResponse {
            name: manifest.name,
            version: manifest.version,
            installed_path: installed_dir.to_string_lossy().into_owned(),
        })
    }

    pub async fn enable(
        &self,
        audit_sink: &dyn AuditSink,
        name: &str,
    ) -> Result<PluginToggleResponse> {
        self.set_enabled(audit_sink, name, true).await
    }

    pub async fn disable(
        &self,
        audit_sink: &dyn AuditSink,
        name: &str,
    ) -> Result<PluginToggleResponse> {
        self.set_enabled(audit_sink, name, false).await
    }

    async fn set_enabled(
        &self,
        audit_sink: &dyn AuditSink,
        name: &str,
        enabled: bool,
    ) -> Result<PluginToggleResponse> {
        let row = self
            .row_by_name(name)
            .await?
            .ok_or_else(|| Error::NotFound(format!("plugin '{name}'")))?;
        let value: i64 = if enabled { 1 } else { 0 };
        sqlx::query("UPDATE plugins SET enabled = ? WHERE id = ?")
            .bind(value)
            .bind(row.id)
            .execute(self.db.pool())
            .await
            .map_err(Error::Sqlx)?;

        let kind = if enabled {
            AuditSinkKind::PluginEnabled
        } else {
            AuditSinkKind::PluginDisabled
        };
        let local_kind = if enabled {
            AuditKind::PluginEnabled
        } else {
            AuditKind::PluginDisabled
        };
        let payload = serde_json::json!({"id": row.id, "name": row.name, "enabled": enabled});
        audit_sink.record(kind, None, None, payload.clone()).await;
        if let Err(e) = audit::append(&self.db, local_kind, None, None, payload).await {
            warn!(error = %e, "plugin toggle: local audit append failed");
        }

        Ok(PluginToggleResponse {
            name: row.name,
            enabled,
        })
    }

    #[instrument(skip(self, audit_sink))]
    pub async fn remove(
        &self,
        audit_sink: &dyn AuditSink,
        params: &PluginRemoveParams,
    ) -> Result<PluginRemoveResponse> {
        let row = self
            .row_by_name(&params.name)
            .await?
            .ok_or_else(|| Error::NotFound(format!("plugin '{}'", params.name)))?;

        sqlx::query("DELETE FROM plugins WHERE id = ?")
            .bind(row.id)
            .execute(self.db.pool())
            .await
            .map_err(Error::Sqlx)?;

        let mut deleted_files = false;
        if params.force {
            match remove_user_dir(&row.name) {
                Ok(removed) => deleted_files = removed,
                Err(e) => warn!(error = %e, plugin = %row.name, "remove_user_dir failed"),
            }
        }

        let payload = serde_json::json!({
            "id": row.id,
            "name": row.name,
            "deleted_files": deleted_files,
            "force": params.force,
        });
        audit_sink
            .record(AuditSinkKind::PluginRemoved, None, None, payload.clone())
            .await;
        if let Err(e) = audit::append(&self.db, AuditKind::PluginRemoved, None, None, payload).await
        {
            warn!(error = %e, "plugin remove: local audit append failed");
        }

        Ok(PluginRemoveResponse {
            name: row.name,
            deleted_files,
        })
    }

    /// Emit the appropriate audit kind for a [`SignatureOutcome`]. `Verified` →
    /// `PluginSignatureVerified`. Both `UnsignedAccepted` (env-bypass) and `Rejected`
    /// → `PluginSignatureRejected` — the payload `accepted` field distinguishes the
    /// two so audit consumers can alert on hard-rejects only.
    async fn emit_signature_outcome(
        &self,
        audit_sink: &dyn AuditSink,
        manifest: &PluginManifest,
        outcome: &SignatureOutcome,
    ) {
        let (kind, local_kind, payload) = match outcome {
            SignatureOutcome::Verified {
                publisher,
                key_source,
                signature_source,
            } => (
                AuditSinkKind::PluginSignatureVerified,
                AuditKind::PluginSignatureVerified,
                serde_json::json!({
                    "name": manifest.name,
                    "version": manifest.version,
                    "publisher": publisher,
                    "key_source": key_source,
                    "signature_source": signature_source,
                }),
            ),
            SignatureOutcome::UnsignedAccepted { reason } => (
                AuditSinkKind::PluginSignatureRejected,
                AuditKind::PluginSignatureRejected,
                serde_json::json!({
                    "name": manifest.name,
                    "version": manifest.version,
                    "accepted": true,
                    "reason": reason,
                    "bypass": ALLOW_UNSIGNED_ENV,
                }),
            ),
            SignatureOutcome::Rejected { reason } => (
                AuditSinkKind::PluginSignatureRejected,
                AuditKind::PluginSignatureRejected,
                serde_json::json!({
                    "name": manifest.name,
                    "version": manifest.version,
                    "accepted": false,
                    "reason": reason,
                }),
            ),
        };
        audit_sink.record(kind, None, None, payload.clone()).await;
        if let Err(e) = audit::append(&self.db, local_kind, None, None, payload).await {
            warn!(error = %e, "plugin signature: local audit append failed");
        }
    }

    async fn row_by_name(&self, name: &str) -> Result<Option<PluginRow>> {
        sqlx::query_as::<_, PluginRow>(
            "SELECT id, name, version, manifest_path, wasm_path, hooks, enabled, installed_at \
             FROM plugins WHERE name = ?",
        )
        .bind(name)
        .fetch_optional(self.db.pool())
        .await
        .map_err(Error::Sqlx)
    }
}

/// Resolve signature material + public key for an install request and run
/// `verify_plugin_signature`. Returns a [`SignatureOutcome`] the caller turns into an
/// audit row. Failures while reading override files or the registry surface as
/// `Rejected` (we never silently degrade to "unsigned").
fn check_signature(
    src_dir: &Path,
    wasm_path: &Path,
    manifest: &PluginManifest,
    params: &PluginInstallParams,
) -> Result<SignatureOutcome> {
    let wasm_bytes = std::fs::read(wasm_path).map_err(Error::Io)?;

    // ---- Resolve signature ----
    let (signature_b64_opt, signature_source) = match &params.signature_path {
        Some(path) => {
            let raw = std::fs::read_to_string(path).map_err(|e| {
                Error::InvalidArgument(format!(
                    "could not read --signature '{}': {e}",
                    path.display()
                ))
            })?;
            (Some(raw), format!("override:{}", path.display()))
        }
        None => {
            let detached = src_dir.join(DETACHED_SIG_FILENAME);
            if detached.is_file() {
                let raw = std::fs::read_to_string(&detached).map_err(|e| {
                    Error::InvalidArgument(format!(
                        "could not read detached signature '{}': {e}",
                        detached.display()
                    ))
                })?;
                (Some(raw), format!("detached:{}", detached.display()))
            } else if let Some(b64) = &manifest.signature_b64 {
                (Some(b64.clone()), "manifest:signature_b64".to_string())
            } else {
                (None, String::new())
            }
        }
    };

    // ---- Resolve public key ----
    let (pubkey_pem_opt, key_source) = match &params.public_key_path {
        Some(path) => {
            let raw = std::fs::read_to_string(path).map_err(|e| {
                Error::InvalidArgument(format!(
                    "could not read --public-key '{}': {e}",
                    path.display()
                ))
            })?;
            (Some(raw), format!("override:{}", path.display()))
        }
        None => match &manifest.publisher {
            Some(publisher) => {
                let registry = KeyRegistry::from_env();
                match registry.load_pem(publisher) {
                    Ok(pem) => (Some(pem), format!("registry:{publisher}")),
                    Err(e) => {
                        return Ok(SignatureOutcome::Rejected {
                            reason: format!("publisher key lookup failed: {e}"),
                        });
                    }
                }
            }
            None => (None, String::new()),
        },
    };

    match (signature_b64_opt, pubkey_pem_opt) {
        (Some(sig_b64), Some(pem)) => match verify_plugin_signature(&wasm_bytes, &sig_b64, &pem) {
            Ok(()) => Ok(SignatureOutcome::Verified {
                publisher: manifest.publisher.clone(),
                key_source,
                signature_source,
            }),
            Err(SigningError::VerifyFailed(m)) => Ok(SignatureOutcome::Rejected {
                reason: format!("ed25519 verify failed: {m}"),
            }),
            Err(other) => Ok(SignatureOutcome::Rejected {
                reason: other.to_string(),
            }),
        },
        _ => {
            // Either signature or public key missing → treat as unsigned.
            if unsigned_allowed() {
                Ok(SignatureOutcome::UnsignedAccepted {
                    reason: "no signature/public key supplied".into(),
                })
            } else {
                Ok(SignatureOutcome::Rejected {
                    reason: format!(
                        "unsigned plugin install requires {ALLOW_UNSIGNED_ENV}=1 \
                         (publisher={:?}, signature_present={})",
                        manifest.publisher,
                        manifest.signature_b64.is_some()
                    ),
                })
            }
        }
    }
}

fn unsigned_allowed() -> bool {
    matches!(
        std::env::var(ALLOW_UNSIGNED_ENV).as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

fn plugin_to_err(e: PluginError) -> Error {
    match e {
        PluginError::NotFound(n) => Error::NotFound(format!("plugin '{n}'")),
        PluginError::Duplicate(n) => Error::InvalidArgument(format!("plugin '{n}' already exists")),
        PluginError::Manifest(m) => Error::InvalidArgument(format!("plugin manifest: {m}")),
        PluginError::WasmLoad(m) => Error::Runtime {
            message: format!("plugin wasm load: {m}"),
        },
        PluginError::HostRejected(m) => Error::Runtime {
            message: format!("plugin host call: {m}"),
        },
        PluginError::Io(io) => Error::Io(io),
        PluginError::NotImplemented(m) => Error::Runtime {
            message: format!("plugin not implemented: {m}"),
        },
    }
}

#[derive(sqlx::FromRow)]
struct PluginRow {
    id: i64,
    name: String,
    version: String,
    manifest_path: String,
    wasm_path: String,
    hooks: String,
    enabled: i64,
    installed_at: String,
}

impl PluginRow {
    fn into_summary(self) -> Result<PluginSummary> {
        let hooks: Vec<String> = serde_json::from_str(&self.hooks).map_err(Error::Json)?;
        let installed_at = chrono::DateTime::parse_from_rfc3339(&self.installed_at)
            .map(|d| d.with_timezone(&chrono::Utc))
            .map_err(|e| Error::Runtime {
                message: format!("invalid plugin installed_at '{}': {e}", self.installed_at),
            })?;
        Ok(PluginSummary {
            name: self.name,
            version: self.version,
            hooks,
            enabled: self.enabled != 0,
            manifest_path: self.manifest_path,
            installed_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linpodx_common::audit_sink::NoopAuditSink;
    use tokio::sync::Mutex;

    // `LINPODX_PLUGIN_DIR` is a process-global env var; tests that mutate it must
    // serialize so parallel `cargo test` runs don't fight each other.
    static ENV_LOCK: Mutex<()> = Mutex::const_new(());

    async fn fresh_db() -> Database {
        let dir = Box::leak(Box::new(tempfile::tempdir().expect("tempdir")));
        let path = dir.path().join("plugin-store-test.db");
        let db = Database::open(&path).await.expect("open");
        db.migrate().await.expect("migrate");
        db
    }

    fn write_plugin_dir(name: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let body = format!(
            r#"
name = "{name}"
version = "0.1.0"
hooks = ["approval"]
wasm = "p.wasm"
"#
        );
        std::fs::write(dir.path().join("linpodx-plugin.toml"), body).unwrap();
        // Minimal valid wasm module: magic + version (no exports — load() will fail but
        // install() only needs parse_from_dir() to confirm the file exists).
        let wasm = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        std::fs::write(dir.path().join("p.wasm"), wasm).unwrap();
        dir
    }

    #[tokio::test]
    async fn empty_list_returns_no_rows() {
        let db = Arc::new(fresh_db().await);
        let store = PluginStore::new(db);
        assert!(store.list().await.unwrap().is_empty());
        assert!(store.list_enabled_specs().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn install_list_enable_disable_remove_cycle() {
        let _guard = ENV_LOCK.lock().await;
        let install_root = tempfile::tempdir().expect("install root");
        std::env::set_var("LINPODX_PLUGIN_DIR", install_root.path());
        // The cycle test installs an unsigned plugin — set the bypass so the install
        // path emits PluginSignatureRejected (audit-only) instead of erroring.
        std::env::set_var(ALLOW_UNSIGNED_ENV, "1");

        let db = Arc::new(fresh_db().await);
        let store = PluginStore::new(Arc::clone(&db));
        let sink = NoopAuditSink;

        let src = write_plugin_dir("cycle-test");
        let installed = store
            .install(
                &sink,
                &PluginInstallParams {
                    manifest_path: src.path().to_string_lossy().into_owned(),
                    signature_path: None,
                    public_key_path: None,
                },
            )
            .await
            .expect("install");
        assert_eq!(installed.name, "cycle-test");

        let listed = store.list().await.expect("list");
        assert_eq!(listed.len(), 1);
        assert!(listed[0].enabled);

        let specs = store.list_enabled_specs().await.expect("specs");
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].manifest.name, "cycle-test");

        let toggled = store.disable(&sink, "cycle-test").await.expect("disable");
        assert!(!toggled.enabled);
        assert!(store
            .list_enabled_specs()
            .await
            .expect("specs after disable")
            .is_empty());

        let toggled = store.enable(&sink, "cycle-test").await.expect("enable");
        assert!(toggled.enabled);

        // Audit chain has at least install + disable + enable rows for this plugin.
        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM audit_log WHERE kind LIKE 'plugin_%'")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert!(count.0 >= 3);

        let removed = store
            .remove(
                &sink,
                &PluginRemoveParams {
                    name: "cycle-test".into(),
                    force: true,
                },
            )
            .await
            .expect("remove");
        assert_eq!(removed.name, "cycle-test");
        assert!(removed.deleted_files);
        assert!(store.list().await.expect("list after remove").is_empty());

        std::env::remove_var("LINPODX_PLUGIN_DIR");
        std::env::remove_var(ALLOW_UNSIGNED_ENV);
    }

    #[tokio::test]
    async fn install_duplicate_name_rejected() {
        let _guard = ENV_LOCK.lock().await;
        let install_root = tempfile::tempdir().expect("install root");
        std::env::set_var("LINPODX_PLUGIN_DIR", install_root.path());
        std::env::set_var(ALLOW_UNSIGNED_ENV, "1");

        let db = Arc::new(fresh_db().await);
        let store = PluginStore::new(Arc::clone(&db));
        let sink = NoopAuditSink;
        let src = write_plugin_dir("dup-test");
        store
            .install(
                &sink,
                &PluginInstallParams {
                    manifest_path: src.path().to_string_lossy().into_owned(),
                    signature_path: None,
                    public_key_path: None,
                },
            )
            .await
            .expect("first install");
        let second = store
            .install(
                &sink,
                &PluginInstallParams {
                    manifest_path: src.path().to_string_lossy().into_owned(),
                    signature_path: None,
                    public_key_path: None,
                },
            )
            .await;
        assert!(matches!(second, Err(Error::InvalidArgument(_))));

        // Cleanup so the next test gets a fresh install root.
        let _ = store
            .remove(
                &sink,
                &PluginRemoveParams {
                    name: "dup-test".into(),
                    force: true,
                },
            )
            .await;
        std::env::remove_var("LINPODX_PLUGIN_DIR");
        std::env::remove_var(ALLOW_UNSIGNED_ENV);
    }

    #[tokio::test]
    async fn enable_unknown_returns_not_found() {
        let db = Arc::new(fresh_db().await);
        let store = PluginStore::new(db);
        let sink = NoopAuditSink;
        match store.enable(&sink, "nope").await {
            Err(Error::NotFound(_)) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    // ---- Phase 15 — signature verification install-path tests ----

    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use ed25519_dalek::pkcs8::EncodePublicKey;
    use ed25519_dalek::{Signer, SigningKey};

    /// Wasm bytes used by every signature test — minimal valid module header so
    /// `parse_from_dir` accepts it.
    const TEST_WASM: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

    fn write_signed_plugin_dir(name: &str, publisher: Option<&str>) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let publisher_line = publisher
            .map(|p| format!("publisher = \"{p}\"\n"))
            .unwrap_or_default();
        let body = format!(
            r#"
name = "{name}"
version = "0.1.0"
hooks = ["approval"]
wasm = "p.wasm"
{publisher_line}"#
        );
        std::fs::write(dir.path().join("linpodx-plugin.toml"), body).unwrap();
        std::fs::write(dir.path().join("p.wasm"), TEST_WASM).unwrap();
        dir
    }

    fn fixed_key() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    fn write_pubkey_pem(dir: &Path, key: &SigningKey) -> PathBuf {
        let pem = key
            .verifying_key()
            .to_public_key_pem(Default::default())
            .unwrap();
        let path = dir.join("publisher.pem");
        std::fs::write(&path, pem).unwrap();
        path
    }

    fn write_sig_b64(dir: &Path, key: &SigningKey, msg: &[u8]) -> PathBuf {
        let sig = key.sign(msg);
        let b64 = B64.encode(sig.to_bytes());
        let path = dir.join("sig.b64");
        std::fs::write(&path, b64).unwrap();
        path
    }

    /// Lock the signature/install env so the new tests don't race the existing
    /// cycle/dup tests' `LINPODX_PLUGIN_DIR` toggling. Reuses the parent ENV_LOCK.
    async fn signature_test_setup() -> (
        tokio::sync::MutexGuard<'static, ()>,
        tempfile::TempDir,
        Arc<Database>,
    ) {
        let guard = ENV_LOCK.lock().await;
        let install_root = tempfile::tempdir().expect("install root");
        std::env::set_var("LINPODX_PLUGIN_DIR", install_root.path());
        std::env::remove_var(ALLOW_UNSIGNED_ENV);
        std::env::remove_var("LINPODX_PLUGIN_KEYS_DIR");
        let db = Arc::new(fresh_db().await);
        (guard, install_root, db)
    }

    #[tokio::test]
    async fn install_with_valid_signature_overrides_succeeds() {
        let (_guard, _root, db) = signature_test_setup().await;
        let store = PluginStore::new(Arc::clone(&db));
        let sink = NoopAuditSink;

        let key = fixed_key();
        let src = write_signed_plugin_dir("sig-ok", Some("test-publisher"));
        let pubkey_path = write_pubkey_pem(src.path(), &key);
        let sig_path = write_sig_b64(src.path(), &key, &TEST_WASM);

        let resp = store
            .install(
                &sink,
                &PluginInstallParams {
                    manifest_path: src.path().to_string_lossy().into_owned(),
                    signature_path: Some(sig_path),
                    public_key_path: Some(pubkey_path),
                },
            )
            .await
            .expect("install");
        assert_eq!(resp.name, "sig-ok");

        let (kind,): (String,) = sqlx::query_as(
            "SELECT kind FROM audit_log WHERE kind = 'plugin_signature_verified' LIMIT 1",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(kind, "plugin_signature_verified");
        std::env::remove_var("LINPODX_PLUGIN_DIR");
    }

    #[tokio::test]
    async fn install_with_bad_signature_is_rejected() {
        let (_guard, _root, db) = signature_test_setup().await;
        let store = PluginStore::new(Arc::clone(&db));
        let sink = NoopAuditSink;

        let key = fixed_key();
        let src = write_signed_plugin_dir("sig-bad", Some("test-publisher"));
        let pubkey_path = write_pubkey_pem(src.path(), &key);
        // Sign over the WRONG bytes so verification fails.
        let sig_path = write_sig_b64(src.path(), &key, b"definitely not the wasm");

        let err = store
            .install(
                &sink,
                &PluginInstallParams {
                    manifest_path: src.path().to_string_lossy().into_owned(),
                    signature_path: Some(sig_path),
                    public_key_path: Some(pubkey_path),
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(m) if m.contains("signature check failed")));

        let (kind,): (String,) = sqlx::query_as(
            "SELECT kind FROM audit_log WHERE kind = 'plugin_signature_rejected' LIMIT 1",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(kind, "plugin_signature_rejected");
        // No row was inserted into the plugins table.
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM plugins")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(count.0, 0);
        std::env::remove_var("LINPODX_PLUGIN_DIR");
    }

    #[tokio::test]
    async fn install_unsigned_without_env_is_rejected() {
        let (_guard, _root, db) = signature_test_setup().await;
        let store = PluginStore::new(Arc::clone(&db));
        let sink = NoopAuditSink;

        let src = write_signed_plugin_dir("unsigned", None);
        let err = store
            .install(
                &sink,
                &PluginInstallParams {
                    manifest_path: src.path().to_string_lossy().into_owned(),
                    signature_path: None,
                    public_key_path: None,
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(m) if m.contains("signature check failed")));
        std::env::remove_var("LINPODX_PLUGIN_DIR");
    }

    #[tokio::test]
    async fn install_unsigned_with_env_bypass_succeeds_and_audits() {
        let (_guard, _root, db) = signature_test_setup().await;
        let store = PluginStore::new(Arc::clone(&db));
        let sink = NoopAuditSink;
        std::env::set_var(ALLOW_UNSIGNED_ENV, "1");

        let src = write_signed_plugin_dir("bypass", None);
        let resp = store
            .install(
                &sink,
                &PluginInstallParams {
                    manifest_path: src.path().to_string_lossy().into_owned(),
                    signature_path: None,
                    public_key_path: None,
                },
            )
            .await
            .expect("install with bypass");
        assert_eq!(resp.name, "bypass");

        // The bypass path emits PluginSignatureRejected with `accepted=true` so audit
        // consumers can alert specifically on the install-blocking variant.
        let (kind, payload): (String, String) = sqlx::query_as(
            "SELECT kind, payload FROM audit_log WHERE kind = 'plugin_signature_rejected' LIMIT 1",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(kind, "plugin_signature_rejected");
        let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(v["accepted"], serde_json::Value::Bool(true));
        std::env::remove_var(ALLOW_UNSIGNED_ENV);
        std::env::remove_var("LINPODX_PLUGIN_DIR");
    }

    #[tokio::test]
    async fn install_uses_registry_lookup_when_publisher_set() {
        let (_guard, _root, db) = signature_test_setup().await;
        let store = PluginStore::new(Arc::clone(&db));
        let sink = NoopAuditSink;

        let key = fixed_key();
        let keys_dir = tempfile::tempdir().unwrap();
        std::fs::write(
            keys_dir.path().join("trusted-acme.pem"),
            key.verifying_key()
                .to_public_key_pem(Default::default())
                .unwrap(),
        )
        .unwrap();
        std::env::set_var("LINPODX_PLUGIN_KEYS_DIR", keys_dir.path());

        let src = write_signed_plugin_dir("registry-ok", Some("trusted-acme"));
        let sig_path = write_sig_b64(src.path(), &key, &TEST_WASM);

        let resp = store
            .install(
                &sink,
                &PluginInstallParams {
                    manifest_path: src.path().to_string_lossy().into_owned(),
                    signature_path: Some(sig_path),
                    public_key_path: None, // ← force registry lookup
                },
            )
            .await
            .expect("install");
        assert_eq!(resp.name, "registry-ok");

        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM audit_log WHERE kind = 'plugin_signature_verified'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert!(count.0 >= 1);

        std::env::remove_var("LINPODX_PLUGIN_KEYS_DIR");
        std::env::remove_var("LINPODX_PLUGIN_DIR");
    }

    #[tokio::test]
    async fn install_rejects_when_publisher_key_missing_from_registry() {
        let (_guard, _root, db) = signature_test_setup().await;
        let store = PluginStore::new(Arc::clone(&db));
        let sink = NoopAuditSink;

        // Empty registry directory — no key for the publisher.
        let keys_dir = tempfile::tempdir().unwrap();
        std::env::set_var("LINPODX_PLUGIN_KEYS_DIR", keys_dir.path());

        let key = fixed_key();
        let src = write_signed_plugin_dir("missing-key", Some("ghost-publisher"));
        let sig_path = write_sig_b64(src.path(), &key, &TEST_WASM);

        let err = store
            .install(
                &sink,
                &PluginInstallParams {
                    manifest_path: src.path().to_string_lossy().into_owned(),
                    signature_path: Some(sig_path),
                    public_key_path: None,
                },
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::InvalidArgument(m) if m.contains("publisher key lookup failed"))
        );

        std::env::remove_var("LINPODX_PLUGIN_KEYS_DIR");
        std::env::remove_var("LINPODX_PLUGIN_DIR");
    }

    #[tokio::test]
    async fn install_uses_manifest_signature_b64_fallback() {
        let (_guard, _root, db) = signature_test_setup().await;
        let store = PluginStore::new(Arc::clone(&db));
        let sink = NoopAuditSink;

        let key = fixed_key();
        let dir = tempfile::tempdir().expect("tempdir");
        let sig_b64 = B64.encode(key.sign(&TEST_WASM).to_bytes());
        let body = format!(
            r#"
name = "manifest-sig"
version = "0.1.0"
hooks = ["approval"]
wasm = "p.wasm"
publisher = "inline-pub"
signature_b64 = "{sig_b64}"
"#
        );
        std::fs::write(dir.path().join("linpodx-plugin.toml"), body).unwrap();
        std::fs::write(dir.path().join("p.wasm"), TEST_WASM).unwrap();
        let pubkey_path = write_pubkey_pem(dir.path(), &key);

        let resp = store
            .install(
                &sink,
                &PluginInstallParams {
                    manifest_path: dir.path().to_string_lossy().into_owned(),
                    signature_path: None, // ← force manifest fallback
                    public_key_path: Some(pubkey_path),
                },
            )
            .await
            .expect("install");
        assert_eq!(resp.name, "manifest-sig");
        std::env::remove_var("LINPODX_PLUGIN_DIR");
    }

    #[tokio::test]
    async fn install_uses_detached_signature_file_fallback() {
        let (_guard, _root, db) = signature_test_setup().await;
        let store = PluginStore::new(Arc::clone(&db));
        let sink = NoopAuditSink;

        let key = fixed_key();
        let src = write_signed_plugin_dir("detached-sig", Some("anyone"));
        // Write detached signature.b64 next to the manifest (no override path passed).
        let sig = key.sign(&TEST_WASM);
        std::fs::write(
            src.path().join(DETACHED_SIG_FILENAME),
            B64.encode(sig.to_bytes()),
        )
        .unwrap();
        let pubkey_path = write_pubkey_pem(src.path(), &key);

        let resp = store
            .install(
                &sink,
                &PluginInstallParams {
                    manifest_path: src.path().to_string_lossy().into_owned(),
                    signature_path: None,
                    public_key_path: Some(pubkey_path),
                },
            )
            .await
            .expect("install");
        assert_eq!(resp.name, "detached-sig");
        std::env::remove_var("LINPODX_PLUGIN_DIR");
    }
}
