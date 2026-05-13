use crate::audit::{self, AuditKind, VerifyReport};
use crate::policy::{self, AppliedPolicy, PolicyDecision};
use crate::profile;
use crate::schema::SandboxProfile;
use crate::secprofile::SecProfileCompiler;
use crate::session::SessionManager;
use crate::snapshot::SnapshotManager;
use crate::snapshot_trigger::AutoEncryptHook;
use chrono::Utc;
use linpodx_common::approval::{ApprovalGateway, ApprovalOutcome, ApprovalRequest};
use linpodx_common::db::Database;
use linpodx_common::error::{Error, Result};
use linpodx_common::events::EventPublisher;
use linpodx_common::ipc::{CreateOptions, Event, EventKind, EventTopic};
use linpodx_common::types::ContainerId;
use linpodx_plugin::{PluginRegistry, ValidatorDecision};
use linpodx_runtime::Podman;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{info, instrument, warn};

/// Subsystem-level handle for sandbox profile + audit operations.
/// The daemon constructs one of these and shares it with the dispatcher.
pub struct SandboxManager {
    db: Arc<Database>,
    profiles_dir: PathBuf,
    profiles: RwLock<HashMap<String, LoadedProfile>>,
    publisher: Arc<dyn EventPublisher>,
    /// Approval gateway used when a profile requires user confirmation. Daemon plugs in
    /// `ApprovalRegistry`; tests use `NoopApprovalGateway` / `DenyAllApprovalGateway`.
    gateway: Arc<dyn ApprovalGateway>,
    /// Default timeout when a profile doesn't override it. Set from daemon config.
    default_approval_timeout: Duration,
    /// Snapshot manager — used by `pre_run_snapshot` when a profile sets
    /// `snapshot_before_run: true`.
    snapshot: Arc<SnapshotManager>,
    /// Session manager — used by the dispatcher around container start/remove.
    session: Arc<SessionManager>,
    /// Optional plugin registry. When set, every profile's YAML is fed through every
    /// `profile_validator` plugin during reload — any `Reject` skips that profile (other
    /// profiles still load) and an `AuditKind::ProfileValidatorRejected` entry is written
    /// per offending plugin.
    plugin_registry: Option<Arc<RwLock<PluginRegistry>>>,
    /// Optional Phase 11 security profile compiler. When `Some`, every profile that
    /// carries a `syscall_allowlist` or `apparmor_extra` triggers a compile after the
    /// policy engine returns Allow, and the resulting paths/names are pushed onto
    /// `CreateOptions.security_opts` so podman receives `--security-opt seccomp=...` /
    /// `--security-opt apparmor=...`.
    secprofile: Option<Arc<SecProfileCompiler>>,
    /// Phase 17 Stream B — sandbox-side auto-encrypt hook. When set, the daemon
    /// dispatch + `pre_run_snapshot` paths route every successful commit through
    /// this hook so the runtime-provided encryptor can fire and audit. `None`
    /// keeps behaviour identical to Phase 16.
    auto_encrypt: Option<Arc<AutoEncryptHook>>,
}

#[derive(Debug, Clone)]
struct LoadedProfile {
    profile: SandboxProfile,
    yaml: String,
    yaml_hash: String,
    last_updated: chrono::DateTime<chrono::Utc>,
}

impl SandboxManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db: Arc<Database>,
        profiles_dir: PathBuf,
        publisher: Arc<dyn EventPublisher>,
        gateway: Arc<dyn ApprovalGateway>,
        default_approval_timeout: Duration,
        snapshot: Arc<SnapshotManager>,
        session: Arc<SessionManager>,
    ) -> Self {
        Self {
            db,
            profiles_dir,
            profiles: RwLock::new(HashMap::new()),
            publisher,
            gateway,
            default_approval_timeout,
            snapshot,
            session,
            plugin_registry: None,
            secprofile: None,
            auto_encrypt: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_plugins(
        db: Arc<Database>,
        profiles_dir: PathBuf,
        publisher: Arc<dyn EventPublisher>,
        gateway: Arc<dyn ApprovalGateway>,
        default_approval_timeout: Duration,
        snapshot: Arc<SnapshotManager>,
        session: Arc<SessionManager>,
        plugin_registry: Arc<RwLock<PluginRegistry>>,
    ) -> Self {
        Self {
            db,
            profiles_dir,
            profiles: RwLock::new(HashMap::new()),
            publisher,
            gateway,
            default_approval_timeout,
            snapshot,
            session,
            plugin_registry: Some(plugin_registry),
            secprofile: None,
            auto_encrypt: None,
        }
    }

    /// Wire a [`SecProfileCompiler`] for Phase 11 seccomp/AppArmor generation. Without
    /// this, profiles with `syscall_allowlist` / `apparmor_extra` are honoured by the
    /// schema (so callers can `sandbox profile compile` directly) but
    /// `apply_to_create` skips the compile/inject step.
    pub fn set_secprofile_compiler(&mut self, compiler: Arc<SecProfileCompiler>) {
        self.secprofile = Some(compiler);
    }

    pub fn secprofile_compiler(&self) -> Option<&Arc<SecProfileCompiler>> {
        self.secprofile.as_ref()
    }

    /// Phase 17 Stream B — wire the auto-encrypt hook so `pre_run_snapshot`
    /// (and the daemon dispatch arms) can route commit-snapshot events through
    /// the runtime-provided `SnapshotEncryptor`. Idempotent; calling twice
    /// replaces the previous hook.
    pub fn set_auto_encrypt_hook(&mut self, hook: Arc<AutoEncryptHook>) {
        self.auto_encrypt = Some(hook);
    }

    pub fn auto_encrypt_hook(&self) -> Option<&Arc<AutoEncryptHook>> {
        self.auto_encrypt.as_ref()
    }

    /// Return a cloned copy of the profile named `name`, if loaded. Used by
    /// the daemon dispatch to feed profile context into the auto-encrypt hook
    /// without exposing the internal `LoadedProfile` wrapper.
    pub async fn get_profile(&self, name: &str) -> Option<SandboxProfile> {
        let guard = self.profiles.read().await;
        guard.get(name).map(|lp| lp.profile.clone())
    }

    pub fn snapshot_manager(&self) -> &Arc<SnapshotManager> {
        &self.snapshot
    }

    pub fn session_manager(&self) -> &Arc<SessionManager> {
        &self.session
    }

    /// If profile `name` is loaded and has `snapshot_before_run: true`, take a snapshot
    /// of `container_id` labelled `pre-run-<unix-ms>`. Returns `Ok(None)` when the profile
    /// is missing or doesn't request a pre-run snapshot.
    ///
    /// Phase 17 Stream B — when [`set_auto_encrypt_hook`](Self::set_auto_encrypt_hook)
    /// has been wired, a successful snapshot fires the hook so the runtime-provided
    /// encryptor can encrypt the committed image. Hook failures are warned-and-swallowed
    /// (audit chain still records the attempt) so a missing encryptor or environment
    /// variable doesn't break the pre-run path.
    #[instrument(skip(self, podman))]
    pub async fn pre_run_snapshot(
        &self,
        podman: &Podman,
        profile_name: &str,
        container_id: &ContainerId,
    ) -> Result<Option<i64>> {
        let (wants, profile_for_hook) = {
            let guard = self.profiles.read().await;
            match guard.get(profile_name) {
                Some(lp) => (lp.profile.snapshot_before_run, Some(lp.profile.clone())),
                None => (false, None),
            }
        };
        if !wants {
            return Ok(None);
        }
        let label = format!("pre-run-{}", chrono::Utc::now().timestamp_millis());
        let summary = self
            .snapshot
            .create(podman, container_id, Some(label))
            .await?;
        if let Some(hook) = self.auto_encrypt.as_ref() {
            if let Err(e) = hook
                .on_commit_snapshot(&summary.image_ref, profile_for_hook.as_ref())
                .await
            {
                warn!(error = %e, image_ref = %summary.image_ref, "auto-encrypt hook returned an error; continuing");
            }
        }
        Ok(Some(summary.id))
    }

    pub fn profiles_dir(&self) -> &PathBuf {
        &self.profiles_dir
    }

    /// Reload all profiles from disk. Replaces the in-memory cache atomically.
    /// Records `ProfilesReloaded` audit + emits a Sandbox event.
    #[instrument(skip(self))]
    pub async fn reload(&self) -> Result<Vec<String>> {
        let loaded_pairs = profile::load_profiles_from_dir(&self.profiles_dir).await?;
        let mut new_map = HashMap::with_capacity(loaded_pairs.len());
        let now = Utc::now();
        let mut names = Vec::with_capacity(loaded_pairs.len());

        for (profile, yaml) in loaded_pairs {
            let yaml_hash = sha256_hex(&yaml);

            // Run profile_validator plugin chain. Any Reject for this profile means we
            // skip it entirely — but other profiles in the directory still load. Audit one
            // entry per offending plugin so operators can trace which rule caught it.
            // Wasmtime stores aren't Send, so the call runs inside spawn_blocking.
            if let Some(reg) = self.plugin_registry.as_ref() {
                let reg_clone = Arc::clone(reg);
                let yaml_clone = yaml.clone();
                let outcomes = match tokio::task::spawn_blocking(move || {
                    let mut guard = reg_clone.blocking_write();
                    guard.evaluate_profile_validator(&yaml_clone)
                })
                .await
                {
                    Ok(o) => o,
                    Err(e) => {
                        warn!(profile = %profile.name, error = %e, "profile_validator task join failed; skipping profile");
                        continue;
                    }
                };
                let mut rejected = false;
                for (plugin_name, decision) in outcomes {
                    if let ValidatorDecision::Reject { reason } = decision {
                        rejected = true;
                        audit::append(
                            &self.db,
                            AuditKind::ProfileValidatorRejected,
                            Some(profile.name.clone()),
                            None,
                            serde_json::json!({
                                "plugin": plugin_name,
                                "reason": reason,
                                "yaml_hash": yaml_hash,
                            }),
                        )
                        .await?;
                    }
                }
                if rejected {
                    warn!(profile = %profile.name, "skipping profile rejected by profile_validator plugin");
                    continue;
                }
            }

            // Per-profile audit (ProfileLoaded) so the chain captures intent.
            audit::append(
                &self.db,
                AuditKind::ProfileLoaded,
                Some(profile.name.clone()),
                None,
                serde_json::json!({
                    "yaml_hash": yaml_hash,
                    "version": profile.version,
                }),
            )
            .await?;
            // Upsert into sandbox_profile cache table.
            sqlx::query(
                "INSERT INTO sandbox_profile (name, yaml_content, yaml_hash, updated_at) \
                 VALUES (?, ?, ?, ?) \
                 ON CONFLICT(name) DO UPDATE SET yaml_content=excluded.yaml_content, \
                     yaml_hash=excluded.yaml_hash, updated_at=excluded.updated_at",
            )
            .bind(&profile.name)
            .bind(&yaml)
            .bind(&yaml_hash)
            .bind(now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
            .execute(self.db.pool())
            .await
            .map_err(Error::Sqlx)?;

            names.push(profile.name.clone());
            new_map.insert(
                profile.name.clone(),
                LoadedProfile {
                    profile,
                    yaml,
                    yaml_hash,
                    last_updated: now,
                },
            );
        }

        let count = new_map.len();
        {
            let mut guard = self.profiles.write().await;
            *guard = new_map;
        }

        // Reload audit + event
        audit::append(
            &self.db,
            AuditKind::ProfilesReloaded,
            None,
            None,
            serde_json::json!({"count": count, "names": names}),
        )
        .await?;
        self.publisher.publish(Event {
            topic: EventTopic::Sandbox,
            kind: EventKind::Renamed, // overload — represents "reloaded"; future: add EventKind::Reloaded
            resource_id: "profiles".into(),
            timestamp: Utc::now(),
            details: serde_json::json!({"count": count, "names": names}),
        });
        info!(count, "sandbox profiles reloaded");

        Ok(names)
    }

    /// Return the L4 egress allowlist (Phase 5) for a named profile, or an empty vector
    /// when the profile's network policy is not `Allowlist` or the profile is unknown.
    /// Used by the daemon's `NetworkEgressApply` arm to pull rules out of the loaded
    /// profile cache without re-parsing YAML.
    pub async fn l4_rules_for_profile(
        &self,
        name: &str,
    ) -> Vec<linpodx_common::network::EgressRule> {
        let guard = self.profiles.read().await;
        match guard.get(name) {
            Some(lp) => match &lp.profile.network {
                crate::schema::NetworkPolicy::Allowlist { l4_rules, .. } => l4_rules.clone(),
                _ => Vec::new(),
            },
            None => Vec::new(),
        }
    }

    pub async fn list(&self) -> Vec<linpodx_common::ipc::responses::SandboxProfileSummary> {
        let guard = self.profiles.read().await;
        let mut summaries: Vec<_> = guard
            .values()
            .map(|lp| linpodx_common::ipc::responses::SandboxProfileSummary {
                name: lp.profile.name.clone(),
                description: lp.profile.description.clone(),
                version: lp.profile.version,
                yaml_hash: lp.yaml_hash.clone(),
                last_updated: lp.last_updated,
            })
            .collect();
        summaries.sort_by(|a, b| a.name.cmp(&b.name));
        summaries
    }

    pub async fn get(
        &self,
        name: &str,
    ) -> Result<linpodx_common::ipc::responses::SandboxProfileGetResponse> {
        let guard = self.profiles.read().await;
        let lp = guard
            .get(name)
            .ok_or_else(|| Error::NotFound(format!("sandbox profile '{name}'")))?;
        Ok(linpodx_common::ipc::responses::SandboxProfileGetResponse {
            name: lp.profile.name.clone(),
            yaml: lp.yaml.clone(),
            yaml_hash: lp.yaml_hash.clone(),
            last_updated: lp.last_updated,
        })
    }

    /// Apply a named profile to `opts`. On Allow, returns the transformed opts and emits
    /// a `ProfileApplied` audit + Sandbox event. On Deny, audits + returns `Err`.
    #[instrument(skip(self, opts), fields(profile = %name))]
    pub async fn apply_to_create(
        &self,
        name: &str,
        opts: CreateOptions,
    ) -> Result<(CreateOptions, AppliedPolicy)> {
        let profile = {
            let guard = self.profiles.read().await;
            guard
                .get(name)
                .ok_or_else(|| Error::NotFound(format!("sandbox profile '{name}'")))?
                .profile
                .clone()
        };

        match policy::apply(&profile, opts) {
            PolicyDecision::Allow(d) => {
                let mut opts = d.opts;
                self.maybe_compile_security_opts(&profile, &mut opts)
                    .await?;
                self.audit_and_publish_applied(name, &d.applied).await?;
                Ok((opts, d.applied))
            }
            PolicyDecision::NeedsApproval(d) => {
                let timeout = profile
                    .approval_timeout_secs
                    .map(Duration::from_secs)
                    .unwrap_or(self.default_approval_timeout);
                for gate in &d.gates {
                    let req = ApprovalRequest {
                        request_id: new_request_id(),
                        category: gate.category,
                        profile_name: name.to_string(),
                        timeout_secs: timeout.as_secs(),
                        created_at: Utc::now(),
                        payload: gate.payload.clone(),
                        container_hint: None,
                    };
                    audit::append(
                        &self.db,
                        AuditKind::ApprovalRequested,
                        Some(name.to_string()),
                        None,
                        serde_json::to_value(&req).unwrap_or(serde_json::Value::Null),
                    )
                    .await?;
                    let outcome = self.gateway.request(req).await;
                    let (kind, granted, payload) = match outcome {
                        ApprovalOutcome::Granted { .. } => (
                            AuditKind::ApprovalGranted,
                            true,
                            serde_json::to_value(&outcome).unwrap_or(serde_json::Value::Null),
                        ),
                        ApprovalOutcome::Denied { .. } => (
                            AuditKind::ApprovalDenied,
                            false,
                            serde_json::to_value(&outcome).unwrap_or(serde_json::Value::Null),
                        ),
                        ApprovalOutcome::TimedOut => {
                            (AuditKind::ApprovalTimedOut, false, serde_json::Value::Null)
                        }
                        ApprovalOutcome::NoListener => (
                            AuditKind::ApprovalNoListener,
                            false,
                            serde_json::Value::Null,
                        ),
                    };
                    audit::append(&self.db, kind, Some(name.to_string()), None, payload).await?;
                    if !granted {
                        return Err(Error::InvalidArgument(format!(
                            "sandbox profile '{name}' denied: approval not granted ({})",
                            kind.as_str()
                        )));
                    }
                }
                // All gates approved → proceed as Allow.
                let mut opts = d.opts;
                self.maybe_compile_security_opts(&profile, &mut opts)
                    .await?;
                self.audit_and_publish_applied(name, &d.applied).await?;
                Ok((opts, d.applied))
            }
            PolicyDecision::Deny { reason } => {
                let payload = serde_json::json!({ "reason": reason });
                audit::append(
                    &self.db,
                    AuditKind::ProfileDenied,
                    Some(name.to_string()),
                    None,
                    payload.clone(),
                )
                .await?;
                self.publisher.publish(Event {
                    topic: EventTopic::Sandbox,
                    kind: EventKind::Stopped, // overload — represents "denied"
                    resource_id: name.to_string(),
                    timestamp: Utc::now(),
                    details: payload,
                });
                warn!(profile = name, %reason, "sandbox denied container create");
                Err(Error::InvalidArgument(format!(
                    "sandbox profile '{name}' denied: {reason}"
                )))
            }
        }
    }

    pub async fn query_audit(
        &self,
        filters: audit::AuditFilters,
    ) -> Result<Vec<audit::AuditEntry>> {
        audit::query(&self.db, filters).await
    }

    pub async fn verify_chain(&self, since_seq: Option<i64>) -> Result<VerifyReport> {
        let report = audit::verify_chain(&self.db, since_seq).await?;
        // Also record the verify event itself (chained on top — non-mutating).
        audit::append(
            &self.db,
            AuditKind::ChainVerified,
            None,
            None,
            serde_json::json!({
                "total": report.total,
                "last_seq": report.last_seq,
                "broken_at": report.broken_at,
            }),
        )
        .await?;
        Ok(report)
    }
}

impl SandboxManager {
    /// Run the secprofile compiler when one is wired *and* the profile carries
    /// `syscall_allowlist`, `apparmor_extra`, `selinux_type`, or `selinux_label`.
    /// Pushes the compiled artefacts onto `opts.security_opts` so podman receives
    /// `--security-opt seccomp=...` / `--security-opt apparmor=...` /
    /// `--security-opt label=type:...`. Compile failures bubble up as `Err` —
    /// the create attempt aborts rather than silently dropping the security gate.
    async fn maybe_compile_security_opts(
        &self,
        profile: &SandboxProfile,
        opts: &mut CreateOptions,
    ) -> Result<()> {
        let needs_compile = profile.syscall_allowlist.is_some()
            || profile.apparmor_extra.is_some()
            || profile.selinux_type.is_some()
            || profile.selinux_label.is_some();
        if !needs_compile {
            return Ok(());
        }
        let Some(compiler) = &self.secprofile else {
            warn!(profile = %profile.name,
                "sandbox profile requests secprofile but no SecProfileCompiler is wired; skipping");
            return Ok(());
        };
        let compiled = compiler.compile(profile).await?;
        let opts_strs = compiled.to_security_opts();
        if !opts_strs.is_empty() {
            opts.security_opts.extend(opts_strs);
        }
        Ok(())
    }

    async fn audit_and_publish_applied(
        &self,
        name: &str,
        applied: &policy::AppliedPolicy,
    ) -> Result<()> {
        let payload = serde_json::to_value(applied).unwrap_or(serde_json::Value::Null);
        audit::append(
            &self.db,
            AuditKind::ProfileApplied,
            Some(name.to_string()),
            None,
            payload.clone(),
        )
        .await?;
        self.publisher.publish(Event {
            topic: EventTopic::Sandbox,
            kind: EventKind::Created,
            resource_id: name.to_string(),
            timestamp: Utc::now(),
            details: payload,
        });
        Ok(())
    }
}

/// Monotonic + epoch-based request id. UUID would be cleaner but adds a dep; for Phase 2A
/// the stronger `request_id` is just a uniqueness handle on the daemon side.
fn new_request_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = chrono::Utc::now().timestamp_millis();
    format!("req-{now}-{n}")
}

fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    let mut out = String::with_capacity(64);
    for b in h.finalize() {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use linpodx_common::approval::NoopApprovalGateway;
    use linpodx_common::events::NoopEventPublisher;

    // Reject every profile whose YAML body contains the substring "blocked".
    const REJECT_IF_BLOCKED_WAT: &str = r#"
        (module
          (import "linpodx_host" "host_get_payload" (func $get (param i32 i32) (result i32)))
          (import "linpodx_host" "host_return_validator_decision" (func $ret (param i32 i32 i32)))
          (memory (export "memory") 1)
          (data (i32.const 1024) "rejected by test plugin")
          (data (i32.const 2048) "blocked")
          ;; Read up to 256 bytes of payload into memory at offset 256, then byte-scan for
          ;; the literal "blocked" stored at offset 2048. If found, reject; otherwise pass.
          (func (export "evaluate_profile_validator") (local $copied i32) (local $i i32) (local $j i32) (local $ok i32)
            (local.set $copied (call $get (i32.const 256) (i32.const 256)))
            (local.set $i (i32.const 0))
            (block $done
              (loop $scan
                ;; if i + 7 > copied, done
                (br_if $done (i32.gt_s (i32.add (local.get $i) (i32.const 7)) (local.get $copied)))
                (local.set $j (i32.const 0))
                (local.set $ok (i32.const 1))
                (block $cmp_done
                  (loop $cmp
                    (br_if $cmp_done (i32.ge_s (local.get $j) (i32.const 7)))
                    (if (i32.ne
                          (i32.load8_u (i32.add (i32.add (i32.const 256) (local.get $i)) (local.get $j)))
                          (i32.load8_u (i32.add (i32.const 2048) (local.get $j))))
                      (then (local.set $ok (i32.const 0)) (br $cmp_done)))
                    (local.set $j (i32.add (local.get $j) (i32.const 1)))
                    (br $cmp)))
                (if (i32.eq (local.get $ok) (i32.const 1))
                  (then
                    (call $ret (i32.const 1) (i32.const 1024) (i32.const 23))
                    (return)))
                (local.set $i (i32.add (local.get $i) (i32.const 1)))
                (br $scan)))
            (call $ret (i32.const 0) (i32.const 0) (i32.const 0))))
    "#;

    async fn fresh_db() -> Arc<linpodx_common::db::Database> {
        let dir = Box::leak(Box::new(tempfile::tempdir().expect("tempdir")));
        let path = dir.path().join("manager-test.db");
        let db = linpodx_common::db::Database::open(&path)
            .await
            .expect("open");
        db.migrate().await.expect("migrate");
        Arc::new(db)
    }

    fn install_validator_plugin(
        name: &str,
        wat: &str,
    ) -> (
        tempfile::TempDir,
        linpodx_plugin::PluginManifest,
        std::path::PathBuf,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let wasm_filename = format!("{}.wasm", name.replace('-', "_"));
        let wasm_bytes = wat::parse_str(wat).expect("compile wat");
        std::fs::write(dir.path().join(&wasm_filename), wasm_bytes).expect("write wasm");
        let manifest_body = format!(
            "name = \"{name}\"\nversion = \"0.1.0\"\nhooks = [\"profile_validator\"]\nwasm = \"{wasm_filename}\"\n",
        );
        std::fs::write(dir.path().join("linpodx-plugin.toml"), manifest_body).expect("write toml");
        let (manifest, wasm_abs) =
            linpodx_plugin::parse_from_dir(dir.path()).expect("parse_from_dir");
        (dir, manifest, wasm_abs)
    }

    fn build_manager(
        db: Arc<linpodx_common::db::Database>,
        profiles_dir: PathBuf,
        plugin_registry: Option<Arc<RwLock<PluginRegistry>>>,
    ) -> SandboxManager {
        let publisher: Arc<dyn EventPublisher> = Arc::new(NoopEventPublisher);
        let gateway: Arc<dyn ApprovalGateway> = Arc::new(NoopApprovalGateway);
        let snapshot = Arc::new(SnapshotManager::new(
            Arc::clone(&db),
            Arc::clone(&publisher),
        ));
        let session = Arc::new(SessionManager::new(Arc::clone(&db), Arc::clone(&publisher)));
        match plugin_registry {
            Some(reg) => SandboxManager::new_with_plugins(
                db,
                profiles_dir,
                publisher,
                gateway,
                Duration::from_secs(30),
                snapshot,
                session,
                reg,
            ),
            None => SandboxManager::new(
                db,
                profiles_dir,
                publisher,
                gateway,
                Duration::from_secs(30),
                snapshot,
                session,
            ),
        }
    }

    #[tokio::test]
    async fn reload_skips_profile_rejected_by_validator_plugin_and_audits_it() {
        let db = fresh_db().await;
        let profiles_dir = tempfile::tempdir().expect("profiles tempdir");
        // Two profiles: one clean, one whose body contains "blocked" — only the clean one
        // should land in the in-memory cache.
        tokio::fs::write(
            profiles_dir.path().join("clean.yaml"),
            "version: 1\nname: clean\n",
        )
        .await
        .unwrap();
        tokio::fs::write(
            profiles_dir.path().join("bad.yaml"),
            "version: 1\nname: bad\n# blocked profile for tests\n",
        )
        .await
        .unwrap();

        let mut reg = PluginRegistry::new().expect("registry");
        let (_pd, m, w) = install_validator_plugin("v-blocker", REJECT_IF_BLOCKED_WAT);
        reg.load_one(&m, &w).expect("load plugin");
        let plugin_registry = Arc::new(RwLock::new(reg));

        let mgr = build_manager(
            Arc::clone(&db),
            profiles_dir.path().to_path_buf(),
            Some(plugin_registry),
        );
        let names = mgr.reload().await.expect("reload");
        assert_eq!(
            names,
            vec!["clean".to_string()],
            "rejected profile must be skipped"
        );

        // Audit log must record the rejection with the plugin name + reason.
        let row: (String, String, Option<String>) = sqlx::query_as(
            "SELECT kind, payload, profile_name FROM audit_log \
             WHERE kind = 'profile_validator_rejected' AND profile_name = 'bad'",
        )
        .fetch_one(db.pool())
        .await
        .expect("audit row");
        assert_eq!(row.0, "profile_validator_rejected");
        assert!(
            row.1.contains("v-blocker"),
            "audit payload should name the plugin"
        );
        assert!(
            row.1.contains("rejected by test plugin"),
            "audit payload should carry the reason"
        );
        assert_eq!(row.2.as_deref(), Some("bad"));
    }

    #[tokio::test]
    async fn reload_without_plugin_registry_loads_every_profile() {
        let db = fresh_db().await;
        let profiles_dir = tempfile::tempdir().expect("profiles tempdir");
        tokio::fs::write(
            profiles_dir.path().join("a.yaml"),
            "version: 1\nname: a\n# blocked\n",
        )
        .await
        .unwrap();
        tokio::fs::write(profiles_dir.path().join("b.yaml"), "version: 1\nname: b\n")
            .await
            .unwrap();

        let mgr = build_manager(Arc::clone(&db), profiles_dir.path().to_path_buf(), None);
        let names = mgr.reload().await.expect("reload");
        assert_eq!(names, vec!["a".to_string(), "b".to_string()]);
    }
}
