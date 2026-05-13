//! Phase 17 Stream B — sandbox-driven auto-encryption trigger.
//!
//! Phase 16 shipped manual snapshot encryption via
//! [`linpodx_runtime::snapshot::encrypt_committed_image`]. This module wires a
//! sandbox-side hook so a commit-snapshot event recorded under a profile that
//! sets `auto_encrypt_snapshots = true` (the default) automatically dispatches
//! through a runtime-provided [`SnapshotEncryptor`] implementation. The hook
//! also appends an [`AuditKind::SandboxSnapshotAutoTriggered`] entry to the
//! tamper-evident chain so the audit log records the policy decision.
//!
//! Wiring path: `linpodx-runtime` owns the encryption implementation and
//! exposes `KeySource` (re-exported here). `linpodx-daemon` plugs a runtime
//! implementor into the sandbox via [`AutoEncryptHook::with_encryptor`] so the
//! sandbox crate keeps zero knowledge of the actual crypto module.

use crate::audit::{self, AuditKind};
use crate::schema::SandboxProfile;
use linpodx_common::db::Database;
use linpodx_common::error::Result;
pub use linpodx_runtime::KeySource;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::{info, warn};

/// Failure cases surfaced by the auto-encrypt chain. Distinct from
/// [`linpodx_common::error::Error`] so the daemon dispatch can map specific
/// reasons to friendly user-facing strings without string-matching.
#[derive(Debug, Error)]
pub enum SandboxError {
    /// The hook fired but no [`SnapshotEncryptor`] was injected — daemon
    /// configuration error, treated as audit + warn (not a hard failure for
    /// snapshot commit).
    #[error("no SnapshotEncryptor wired into the sandbox auto-trigger hook")]
    NoEncryptor,
    /// The underlying encrypt implementation returned an error.
    #[error("snapshot encryptor failed: {0}")]
    Encryptor(String),
    /// Audit chain append failed. Wraps `linpodx_common::error::Error` rendered
    /// as a string so the trait stays object-safe even if Error gains non-Send
    /// variants later.
    #[error("audit append failed: {0}")]
    Audit(String),
}

/// Result alias used by the trigger surface.
pub type TriggerResult<T> = std::result::Result<T, SandboxError>;

/// Runtime-provided snapshot encryption entry point. The sandbox crate only
/// knows about this trait so the encryption implementation can evolve in
/// `linpodx-runtime` without forcing a sandbox-crate change.
///
/// `image_ref` is the committed OCI image tag the runtime has just emitted
/// (e.g. `linpodx-snap-42`). `key_source` lets callers pin which env-variable
/// the encrypt path uses; daemons typically pass `KeySource::Env` or
/// `KeySource::Passphrase` after resolving the active configuration.
pub trait SnapshotEncryptor: Send + Sync {
    fn encrypt(&self, image_ref: &str, key_source: KeySource) -> TriggerResult<()>;
}

/// Status snapshot the daemon returns over the IPC arm
/// `SandboxSnapshotAutoTriggerStatus`. The fields mirror
/// [`linpodx_common::ipc::responses::SandboxSnapshotAutoTriggerStatusResponse`]
/// — kept here as a plain struct so the sandbox crate doesn't depend on the
/// IPC `responses` namespace directly.
#[derive(Debug, Clone)]
pub struct AutoEncryptStatus {
    pub enabled: bool,
    pub last_image_ref: Option<String>,
    pub trigger_count: u64,
}

/// Sandbox-side hook that turns commit-snapshot events into encrypt calls.
///
/// The hook holds:
/// * `enabled` — a runtime-mutable global toggle. When `false`, the hook
///   short-circuits without consulting the profile (and without auditing).
///   Default `true`.
/// * `encryptor` — the runtime-provided [`SnapshotEncryptor`]. `None` means the
///   daemon hasn't wired one in (e.g. running without encryption env vars set);
///   the hook records the no-op and audits but never returns an error.
/// * `last_image_ref` + `trigger_count` — lifetime statistics exposed via
///   [`AutoEncryptHook::status`] for the IPC `Status` arm.
pub struct AutoEncryptHook {
    db: Arc<Database>,
    enabled: AtomicBool,
    encryptor: Mutex<Option<Arc<dyn SnapshotEncryptor>>>,
    trigger_count: AtomicU64,
    last_image_ref: Mutex<Option<String>>,
    default_key_source: KeySource,
}

impl AutoEncryptHook {
    /// Construct a hook with no encryptor wired and the global toggle set to
    /// `enabled` (typically `true`). The default key source is
    /// [`KeySource::Env`] — matching the daemon's preferred resolution order
    /// in `EncryptionConfig::from_env`.
    pub fn new(db: Arc<Database>, enabled: bool) -> Self {
        Self {
            db,
            enabled: AtomicBool::new(enabled),
            encryptor: Mutex::new(None),
            trigger_count: AtomicU64::new(0),
            last_image_ref: Mutex::new(None),
            default_key_source: KeySource::Env,
        }
    }

    /// Override the default `KeySource` reported to the encryptor. Daemons
    /// resolving a `Passphrase` config at startup should call this with
    /// `KeySource::Passphrase` so audit entries show the correct provenance.
    pub fn set_default_key_source(&mut self, source: KeySource) {
        self.default_key_source = source;
    }

    /// Inject the runtime-side encryptor. Subsequent commit-snapshot events
    /// will dispatch through it.
    pub async fn with_encryptor(
        self: Arc<Self>,
        encryptor: Arc<dyn SnapshotEncryptor>,
    ) -> Arc<Self> {
        {
            let mut guard = self.encryptor.lock().await;
            *guard = Some(encryptor);
        }
        self
    }

    /// Test/runtime helper: replace the encryptor in place.
    pub async fn set_encryptor(&self, encryptor: Option<Arc<dyn SnapshotEncryptor>>) {
        let mut guard = self.encryptor.lock().await;
        *guard = encryptor;
    }

    /// Toggle the global enable bit. Returns the previous value so the caller
    /// can record an idempotent no-change in audit entries if desired.
    pub fn set_enabled(&self, enabled: bool) -> bool {
        self.enabled.swap(enabled, Ordering::SeqCst)
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    /// Snapshot the public counters / last-image-ref / enabled flag in a
    /// single call. The two reads aren't atomic together but the values are
    /// loose statistics; callers that need strict consistency can grab the
    /// `Mutex<Option<String>>` directly.
    pub async fn status(&self) -> AutoEncryptStatus {
        let last = self.last_image_ref.lock().await.clone();
        AutoEncryptStatus {
            enabled: self.is_enabled(),
            last_image_ref: last,
            trigger_count: self.trigger_count.load(Ordering::SeqCst),
        }
    }

    /// Entry point invoked by sandbox-driven commit-snapshot paths.
    ///
    /// Logic:
    /// 1. If the global toggle is `false`, return `Ok(false)` without auditing
    ///    — operators can chase missing encryption via the toggle status, no
    ///    need to spam the chain.
    /// 2. If the profile sets `auto_encrypt_snapshots = false`, return
    ///    `Ok(false)` — same rationale.
    /// 3. Otherwise, if an encryptor is wired, invoke it. Append a
    ///    `SandboxSnapshotAutoTriggered` entry that records the image ref,
    ///    profile name, key source, and outcome. Returns `Ok(true)` on
    ///    success.
    /// 4. If no encryptor is wired, audit with `outcome: "no_encryptor"` and
    ///    return `Ok(false)`. The hook is a *trigger*, not a hard guarantee —
    ///    a daemon without encryption configured stays silently consistent
    ///    rather than failing commits.
    pub async fn on_commit_snapshot(
        &self,
        image_ref: &str,
        profile: Option<&SandboxProfile>,
    ) -> TriggerResult<bool> {
        if !self.is_enabled() {
            return Ok(false);
        }
        let profile_name = profile.map(|p| p.name.clone());
        let per_profile_allow = profile.map(|p| p.auto_encrypt_snapshots).unwrap_or(true);
        if !per_profile_allow {
            return Ok(false);
        }

        let key_source = self.default_key_source;
        let encryptor = self.encryptor.lock().await.clone();

        let outcome = match encryptor {
            Some(enc) => match enc.encrypt(image_ref, key_source) {
                Ok(()) => "encrypted",
                Err(e) => {
                    warn!(image_ref, error = %e, "auto-encrypt hook: encryptor failed");
                    "encryptor_failed"
                }
            },
            None => {
                warn!(image_ref, "auto-encrypt hook fired but no encryptor wired");
                "no_encryptor"
            }
        };

        let count = self.trigger_count.fetch_add(1, Ordering::SeqCst) + 1;
        {
            let mut guard = self.last_image_ref.lock().await;
            *guard = Some(image_ref.to_string());
        }

        let payload = serde_json::json!({
            "image_ref": image_ref,
            "profile_name": profile_name,
            "key_source": key_source.as_str(),
            "outcome": outcome,
            "trigger_count": count,
        });
        append_audit(&self.db, profile_name.as_deref(), payload)
            .await
            .map_err(|e| SandboxError::Audit(e.to_string()))?;

        info!(image_ref, outcome, count, "sandbox auto-encrypt hook fired");
        Ok(outcome == "encrypted")
    }
}

async fn append_audit(
    db: &Database,
    profile_name: Option<&str>,
    payload: serde_json::Value,
) -> Result<()> {
    audit::append(
        db,
        AuditKind::SandboxSnapshotAutoTriggered,
        profile_name.map(|s| s.to_string()),
        None,
        payload,
    )
    .await
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{Capabilities, NetworkPolicy, SandboxProfile};
    use std::sync::atomic::AtomicU32;

    /// In-memory encryptor that records every call. `fail` flips it to return
    /// an error so the hook's failure-audit path is exercised.
    struct MockEncryptor {
        calls: AtomicU32,
        last_image: Mutex<Option<String>>,
        last_key_source: Mutex<Option<KeySource>>,
        fail: AtomicBool,
    }

    impl MockEncryptor {
        fn new() -> Self {
            Self {
                calls: AtomicU32::new(0),
                last_image: Mutex::new(None),
                last_key_source: Mutex::new(None),
                fail: AtomicBool::new(false),
            }
        }

        fn calls(&self) -> u32 {
            self.calls.load(Ordering::SeqCst)
        }

        fn set_fail(&self, v: bool) {
            self.fail.store(v, Ordering::SeqCst);
        }
    }

    impl SnapshotEncryptor for MockEncryptor {
        fn encrypt(&self, image_ref: &str, key_source: KeySource) -> TriggerResult<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            // try_lock is fine for tests — we never hold these across awaits.
            *self.last_image.try_lock().unwrap() = Some(image_ref.to_string());
            *self.last_key_source.try_lock().unwrap() = Some(key_source);
            if self.fail.load(Ordering::SeqCst) {
                Err(SandboxError::Encryptor("forced".into()))
            } else {
                Ok(())
            }
        }
    }

    fn empty_profile(name: &str) -> SandboxProfile {
        SandboxProfile {
            version: 1,
            name: name.into(),
            description: String::new(),
            network: NetworkPolicy::Full,
            mounts: vec![],
            limits: Default::default(),
            capabilities: Capabilities {
                drop: vec![],
                add: vec![],
            },
            read_only_rootfs: false,
            approval_gates: vec![],
            approval_timeout_secs: None,
            snapshot_before_run: false,
            passthrough: None,
            distro_kind: None,
            systemd: false,
            snapshot_backend: None,
            syscall_allowlist: None,
            apparmor_extra: None,
            selinux_label: None,
            selinux_type: None,
            auto_encrypt_snapshots: true,
        }
    }

    async fn fresh_db() -> Database {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let path = dir.path().join("trigger-test.db");
        let db = Database::open(&path).await.expect("open");
        db.migrate().await.expect("migrate");
        db
    }

    async fn audit_kinds(db: &Database) -> Vec<String> {
        sqlx::query_scalar::<_, String>("SELECT kind FROM audit_log ORDER BY seq ASC")
            .fetch_all(db.pool())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn default_profile_auto_encrypt_is_true() {
        let p = empty_profile("p1");
        assert!(p.auto_encrypt_snapshots);
    }

    #[tokio::test]
    async fn yaml_default_auto_encrypt_is_true_when_absent() {
        let yaml = "version: 1\nname: minimal";
        let parsed: SandboxProfile = serde_yml::from_str(yaml).expect("parse");
        assert!(parsed.auto_encrypt_snapshots);
    }

    #[tokio::test]
    async fn hook_disabled_short_circuits_without_audit() {
        let db = Arc::new(fresh_db().await);
        let hook = AutoEncryptHook::new(Arc::clone(&db), false);
        let enc = Arc::new(MockEncryptor::new());
        hook.set_encryptor(Some(enc.clone())).await;

        let p = empty_profile("p1");
        let fired = hook
            .on_commit_snapshot("linpodx-snap-1", Some(&p))
            .await
            .expect("ok");
        assert!(!fired);
        assert_eq!(enc.calls(), 0);
        assert!(audit_kinds(&db).await.is_empty());
    }

    #[tokio::test]
    async fn hook_per_profile_opt_out_short_circuits() {
        let db = Arc::new(fresh_db().await);
        let hook = AutoEncryptHook::new(Arc::clone(&db), true);
        let enc = Arc::new(MockEncryptor::new());
        hook.set_encryptor(Some(enc.clone())).await;

        let mut p = empty_profile("p1");
        p.auto_encrypt_snapshots = false;
        let fired = hook
            .on_commit_snapshot("linpodx-snap-1", Some(&p))
            .await
            .expect("ok");
        assert!(!fired);
        assert_eq!(enc.calls(), 0);
        assert!(audit_kinds(&db).await.is_empty());
    }

    #[tokio::test]
    async fn hook_with_encryptor_invokes_and_audits() {
        let db = Arc::new(fresh_db().await);
        let hook = AutoEncryptHook::new(Arc::clone(&db), true);
        let enc = Arc::new(MockEncryptor::new());
        hook.set_encryptor(Some(enc.clone())).await;

        let p = empty_profile("p1");
        let fired = hook
            .on_commit_snapshot("linpodx-snap-42", Some(&p))
            .await
            .expect("ok");
        assert!(fired);
        assert_eq!(enc.calls(), 1);
        assert_eq!(
            enc.last_image.try_lock().unwrap().as_deref(),
            Some("linpodx-snap-42")
        );

        let kinds = audit_kinds(&db).await;
        assert_eq!(kinds, vec!["sandbox_snapshot_auto_triggered".to_string()]);
    }

    #[tokio::test]
    async fn hook_without_encryptor_audits_no_encryptor() {
        let db = Arc::new(fresh_db().await);
        let hook = AutoEncryptHook::new(Arc::clone(&db), true);

        let p = empty_profile("p1");
        let fired = hook
            .on_commit_snapshot("linpodx-snap-1", Some(&p))
            .await
            .expect("ok");
        assert!(!fired);

        let payload: (String, String) =
            sqlx::query_as("SELECT kind, payload FROM audit_log ORDER BY seq DESC LIMIT 1")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(payload.0, "sandbox_snapshot_auto_triggered");
        let json: serde_json::Value = serde_json::from_str(&payload.1).unwrap();
        assert_eq!(
            json.get("outcome").and_then(|v| v.as_str()),
            Some("no_encryptor")
        );
    }

    #[tokio::test]
    async fn hook_records_encryptor_failure_in_audit() {
        let db = Arc::new(fresh_db().await);
        let hook = AutoEncryptHook::new(Arc::clone(&db), true);
        let enc = Arc::new(MockEncryptor::new());
        enc.set_fail(true);
        hook.set_encryptor(Some(enc.clone())).await;

        let p = empty_profile("p1");
        let fired = hook
            .on_commit_snapshot("linpodx-snap-7", Some(&p))
            .await
            .expect("ok");
        // outcome != "encrypted" so fired == false
        assert!(!fired);
        assert_eq!(enc.calls(), 1);

        let payload: (String,) =
            sqlx::query_as("SELECT payload FROM audit_log ORDER BY seq DESC LIMIT 1")
                .fetch_one(db.pool())
                .await
                .unwrap();
        let json: serde_json::Value = serde_json::from_str(&payload.0).unwrap();
        assert_eq!(
            json.get("outcome").and_then(|v| v.as_str()),
            Some("encryptor_failed")
        );
    }

    #[tokio::test]
    async fn status_counters_advance_on_each_trigger() {
        let db = Arc::new(fresh_db().await);
        let hook = AutoEncryptHook::new(Arc::clone(&db), true);
        let enc = Arc::new(MockEncryptor::new());
        hook.set_encryptor(Some(enc.clone())).await;

        let p = empty_profile("p1");
        assert_eq!(hook.status().await.trigger_count, 0);

        for i in 0..3 {
            let img = format!("linpodx-snap-{i}");
            hook.on_commit_snapshot(&img, Some(&p)).await.unwrap();
        }
        let s = hook.status().await;
        assert_eq!(s.trigger_count, 3);
        assert_eq!(s.last_image_ref.as_deref(), Some("linpodx-snap-2"));
        assert!(s.enabled);
    }

    #[tokio::test]
    async fn set_enabled_returns_previous_value() {
        let db = Arc::new(fresh_db().await);
        let hook = AutoEncryptHook::new(Arc::clone(&db), true);
        assert!(hook.is_enabled());
        let prev = hook.set_enabled(false);
        assert!(prev);
        assert!(!hook.is_enabled());
        let prev2 = hook.set_enabled(true);
        assert!(!prev2);
        assert!(hook.is_enabled());
    }

    #[tokio::test]
    async fn missing_profile_treats_as_default_allow() {
        let db = Arc::new(fresh_db().await);
        let hook = AutoEncryptHook::new(Arc::clone(&db), true);
        let enc = Arc::new(MockEncryptor::new());
        hook.set_encryptor(Some(enc.clone())).await;

        let fired = hook
            .on_commit_snapshot("linpodx-snap-ad-hoc", None)
            .await
            .expect("ok");
        assert!(fired);
        assert_eq!(enc.calls(), 1);
    }

    #[tokio::test]
    async fn audit_payload_includes_key_source_and_profile_name() {
        let db = Arc::new(fresh_db().await);
        let mut hook = AutoEncryptHook::new(Arc::clone(&db), true);
        hook.set_default_key_source(KeySource::Passphrase);
        let hook = Arc::new(hook);
        let enc = Arc::new(MockEncryptor::new());
        hook.set_encryptor(Some(enc.clone())).await;

        let p = empty_profile("ai-agent");
        hook.on_commit_snapshot("linpodx-snap-9", Some(&p))
            .await
            .unwrap();

        let payload: (String, Option<String>) =
            sqlx::query_as("SELECT payload, profile_name FROM audit_log ORDER BY seq DESC LIMIT 1")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(payload.1.as_deref(), Some("ai-agent"));
        let json: serde_json::Value = serde_json::from_str(&payload.0).unwrap();
        assert_eq!(
            json.get("key_source").and_then(|v| v.as_str()),
            Some("passphrase")
        );
        assert_eq!(
            json.get("profile_name").and_then(|v| v.as_str()),
            Some("ai-agent")
        );
    }

    #[tokio::test]
    async fn set_encryptor_clears_existing() {
        let db = Arc::new(fresh_db().await);
        let hook = AutoEncryptHook::new(Arc::clone(&db), true);
        let enc = Arc::new(MockEncryptor::new());
        hook.set_encryptor(Some(enc.clone())).await;
        hook.set_encryptor(None).await;

        let p = empty_profile("p1");
        hook.on_commit_snapshot("linpodx-snap-1", Some(&p))
            .await
            .unwrap();
        assert_eq!(enc.calls(), 0);
    }

    #[tokio::test]
    async fn audit_chain_links_two_consecutive_triggers() {
        let db = Arc::new(fresh_db().await);
        let hook = AutoEncryptHook::new(Arc::clone(&db), true);
        let enc = Arc::new(MockEncryptor::new());
        hook.set_encryptor(Some(enc.clone())).await;

        let p = empty_profile("p1");
        hook.on_commit_snapshot("linpodx-snap-1", Some(&p))
            .await
            .unwrap();
        hook.on_commit_snapshot("linpodx-snap-2", Some(&p))
            .await
            .unwrap();

        let rows: Vec<(i64, String, String)> =
            sqlx::query_as("SELECT seq, prev_hash, this_hash FROM audit_log ORDER BY seq ASC")
                .fetch_all(db.pool())
                .await
                .unwrap();
        assert_eq!(rows.len(), 2);
        // Second row's prev_hash must equal first row's this_hash — chain
        // integrity.
        assert_eq!(rows[0].2, rows[1].1);
    }

    #[tokio::test]
    async fn default_key_source_is_env() {
        let db = Arc::new(fresh_db().await);
        let hook = AutoEncryptHook::new(Arc::clone(&db), true);
        let enc = Arc::new(MockEncryptor::new());
        hook.set_encryptor(Some(enc.clone())).await;

        let p = empty_profile("p1");
        hook.on_commit_snapshot("linpodx-snap-1", Some(&p))
            .await
            .unwrap();
        let ks = *enc.last_key_source.try_lock().unwrap();
        assert_eq!(ks, Some(KeySource::Env));
    }

    #[tokio::test]
    async fn with_encryptor_wires_encryptor_via_arc_helper() {
        let db = Arc::new(fresh_db().await);
        let hook = Arc::new(AutoEncryptHook::new(Arc::clone(&db), true));
        let enc: Arc<dyn SnapshotEncryptor> = Arc::new(MockEncryptor::new());
        let wired = Arc::clone(&hook).with_encryptor(Arc::clone(&enc)).await;
        // The Arc returned is the same instance — the helper is a fluent
        // builder, not a clone.
        assert!(Arc::ptr_eq(&hook, &wired));

        let p = empty_profile("p1");
        hook.on_commit_snapshot("linpodx-snap-1", Some(&p))
            .await
            .unwrap();
        // Status records the lifetime trigger.
        assert_eq!(hook.status().await.trigger_count, 1);
    }
}
