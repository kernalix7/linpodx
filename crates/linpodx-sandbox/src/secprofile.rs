//! Phase 11 — seccomp + AppArmor profile compiler.
//!
//! Translates a [`SandboxProfile`]'s `syscall_allowlist` and `apparmor_extra` fields
//! into on-disk artefacts that podman can consume via `--security-opt seccomp=<path>`
//! and `--security-opt apparmor=<name>`:
//!
//! * **seccomp** — emitted as an OCI/runtime-spec style JSON profile (the schema podman
//!   accepts directly). The seccompiler crate's `json` feature is used to round-trip
//!   the output through `compile_from_json` as a syscall-name sanity check on supported
//!   architectures (x86_64 / aarch64 / riscv64). Failures during validation are logged
//!   but never block compile — podman applies its own validation when the file is read.
//! * **AppArmor** — emitted as a textual profile derived from the sandbox profile's
//!   mounts / network / capabilities plus the user-supplied extra deny/allow rules.
//!   Loaded into the kernel via `apparmor_parser -r`. When AppArmor is unavailable the
//!   compile silently skips this branch and `CompiledProfile::apparmor_name` is `None`.
//! * **SELinux** (Phase 12) — when `selinux_type` is set on the profile, a SELinux
//!   module `.te` file is synthesized, packaged via `checkmodule + semodule_package`,
//!   and installed via `semodule -i`. Podman then receives
//!   `--security-opt label=type:<selinux_type>` at create time. Hosts without the
//!   `checkmodule + semodule_package + semodule` toolchain (or with SELinux disabled)
//!   skip this branch with a warn and `CompiledProfile::selinux_module_name` is `None`.
//!
//! Cache: compiled artefacts are content-addressed — the filename embeds a digest of
//! the exact bytes written (`{stem}.{digest}.seccomp.json` / `.apparmor`). A cache hit
//! is only possible when the compiled output is byte-identical, so any change to the
//! profile (e.g. tightening `syscall_allowlist`) lands on a fresh filename and never
//! re-serves stale, looser artefacts. The `{stem}` is a sanitized profile name that
//! cannot traverse out of the cache dir. Stale same-stem files are pruned best-effort.

use crate::schema::{Capabilities, MountRule, NetworkPolicy, SandboxProfile, SourcePattern};
use linpodx_common::audit_sink::{AuditSink, AuditSinkKind};
use linpodx_common::error::{Error, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use tokio::process::Command;
use tracing::{debug, instrument, warn};

/// Maximum length of a sanitized profile-name cache stem. Caps pathological
/// names so a filename can never blow past the OS limit.
const MAX_CACHE_STEM_LEN: usize = 128;

/// Sanitize a profile name into a safe filesystem stem. Keeps `[A-Za-z0-9_-]`
/// verbatim and folds every other byte (path separators, `.`, whitespace, …) to
/// `_`, then caps the length. This makes it impossible for a crafted profile name
/// such as `../../etc/cron.d/x` or `/etc/shadow` to escape `cache_dir` when the
/// stem is joined into it — every traversal / absolute-path character becomes a
/// literal underscore. Mirrors (and is stricter than) `selinux::module_name`.
fn sanitize_profile_stem(profile_name: &str) -> String {
    let mut s = String::with_capacity(profile_name.len().min(MAX_CACHE_STEM_LEN));
    for c in profile_name.chars() {
        if s.len() >= MAX_CACHE_STEM_LEN {
            break;
        }
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
            s.push(c);
        } else {
            s.push('_');
        }
    }
    if s.is_empty() {
        s.push('_');
    }
    s
}

/// Short (8-byte / 16-hex) content digest used to make cache filenames
/// content-addressed: any change to the compiled artefact's bytes yields a
/// different digest, so a tightened profile can never be served a stale, looser
/// cached file.
fn content_digest(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let full = h.finalize();
    let mut s = String::with_capacity(16);
    for b in &full[..8] {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

const APPARMOR_PROFILE_PREFIX: &str = "linpodx-";
const SELINUX_MODULE_PREFIX: &str = "linpodx_";
/// Phase 15 — when set to `1`, a dynamic `.te` compile/install failure does NOT
/// hard-error. Instead the compiler falls back to the conservative system label
/// `container_t` and emits an audit record so operators can spot drift.
const SELINUX_RUNTIME_FALLBACK_ENV: &str = "LINPODX_SELINUX_RUNTIME_FALLBACK";
/// Phase 15 — fallback label used when [`SELINUX_RUNTIME_FALLBACK_ENV`] is set
/// and the dynamic SELinux compile path fails. Chosen to match the default
/// container domain Podman/CRI-O ship with, so the resulting `--security-opt
/// label=type:container_t` is always recognised by the kernel policy.
const SELINUX_RUNTIME_FALLBACK_LABEL: &str = "container_t";

/// Result of compiling a sandbox profile to security-profile artefacts. Each field
/// may be `None` when the profile didn't request that flavour (or the host lacked
/// support).
#[derive(Debug, Clone, Default)]
pub struct CompiledProfile {
    /// Path to the OCI-style seccomp JSON file. Pass to podman as
    /// `--security-opt seccomp=<path>`.
    pub seccomp_path: Option<PathBuf>,
    /// AppArmor profile name (no path — kernel resolves by name once
    /// `apparmor_parser -r` has loaded it). Pass to podman as
    /// `--security-opt apparmor=<name>`.
    pub apparmor_name: Option<PathBuf>,
    /// SELinux module name (the type, not the module file). Pass to podman as
    /// `--security-opt label=type:<name>`. Phase 12.
    pub selinux_module_name: Option<String>,
    /// Phase 14 — static SELinux label applied verbatim. Set when the profile
    /// declared `selinux_label` (a fixed system type like `container_t`); skips
    /// the dynamic `.te` synthesize / install path entirely. Mutually exclusive
    /// with `selinux_module_name` at profile-validation time. Pass to podman as
    /// `--security-opt label=type:<value>`.
    pub selinux_static_label: Option<String>,
}

impl CompiledProfile {
    /// Convert to the `--security-opt <s>` strings podman expects. Empty when the
    /// profile didn't request anything. The static SELinux label takes precedence
    /// over the dynamic module name; profile validation guarantees only one path
    /// is active per profile, but the precedence gate here makes the runtime
    /// behaviour obvious.
    pub fn to_security_opts(&self) -> Vec<String> {
        let mut v = Vec::new();
        if let Some(p) = &self.seccomp_path {
            v.push(format!("seccomp={}", p.display()));
        }
        if let Some(name) = &self.apparmor_name {
            v.push(format!("apparmor={}", name.display()));
        }
        if let Some(label) = &self.selinux_static_label {
            v.push(format!("label=type:{label}"));
        } else if let Some(name) = &self.selinux_module_name {
            v.push(format!("label=type:{name}"));
        }
        v
    }
}

/// Compiles `SandboxProfile` security extensions into on-disk seccomp JSON +
/// AppArmor profile text, with last-updated mtime caching.
pub struct SecProfileCompiler {
    cache_dir: PathBuf,
    audit: Arc<dyn AuditSink>,
}

impl SecProfileCompiler {
    pub fn new(cache_dir: PathBuf, audit: Arc<dyn AuditSink>) -> Self {
        Self { cache_dir, audit }
    }

    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    /// Compile both flavours (when configured on the profile) and write them under
    /// `cache_dir/`. Returns the resulting paths/names.
    #[instrument(skip(self, profile), fields(profile = %profile.name))]
    pub async fn compile(&self, profile: &SandboxProfile) -> Result<CompiledProfile> {
        tokio::fs::create_dir_all(&self.cache_dir)
            .await
            .map_err(|e| Error::Runtime {
                message: format!(
                    "secprofile: create cache dir {}: {e}",
                    self.cache_dir.display()
                ),
            })?;

        let mut compiled = CompiledProfile::default();

        if let Some(syscalls) = profile.syscall_allowlist.as_ref() {
            let path =
                self.compile_seccomp(profile, syscalls)
                    .await
                    .map_err(|e| Error::Runtime {
                        message: format!("secprofile: seccomp compile failed: {e}"),
                    })?;
            compiled.seccomp_path = Some(path);
        }

        if profile.apparmor_extra.is_some() {
            if is_apparmor_available() {
                match self.compile_apparmor(profile).await {
                    Ok(name) => compiled.apparmor_name = Some(PathBuf::from(name)),
                    Err(e) => {
                        warn!(profile = %profile.name, error = %e,
                            "secprofile: apparmor compile failed; continuing without it");
                    }
                }
            } else {
                debug!(profile = %profile.name,
                    "secprofile: apparmor_parser not in PATH — skipping apparmor compile");
            }
        }

        // Phase 14 — static SELinux label takes precedence. When set, skip the
        // dynamic .te / checkmodule / semodule pipeline entirely and just hand
        // the verbatim label down to podman. Validation in
        // `linpodx-sandbox::profile` guarantees `selinux_label` and
        // `selinux_type` are not both populated.
        if let Some(label) = profile.selinux_label.as_deref() {
            let trimmed = label.trim();
            if !trimmed.is_empty() {
                compiled.selinux_static_label = Some(trimmed.to_string());
                self.audit
                    .record(
                        AuditSinkKind::SelinuxStaticLabelApplied,
                        Some(profile.name.clone()),
                        None,
                        serde_json::json!({
                            "label": trimmed,
                        }),
                    )
                    .await;
            }
        } else if profile.selinux_type.is_some() {
            if selinux::is_selinux_available() {
                match self.compile_selinux(profile).await {
                    Ok(Some(name)) => compiled.selinux_module_name = Some(name),
                    Ok(None) => {
                        warn!(profile = %profile.name,
                            "secprofile: selinux module install failed; continuing without it");
                        self.maybe_apply_runtime_fallback(profile, &mut compiled, "install_failed")
                            .await;
                    }
                    Err(e) => {
                        warn!(profile = %profile.name, error = %e,
                            "secprofile: selinux compile failed; continuing without it");
                        self.maybe_apply_runtime_fallback(profile, &mut compiled, "compile_error")
                            .await;
                    }
                }
            } else {
                debug!(profile = %profile.name,
                    "secprofile: SELinux toolchain or enforcement unavailable — skipping selinux compile");
            }
        }

        Ok(compiled)
    }

    async fn compile_seccomp(
        &self,
        profile: &SandboxProfile,
        syscalls: &[String],
    ) -> Result<PathBuf> {
        let json = render_seccomp_json(syscalls);
        validate_seccomp_json(&json);

        let serialized = serde_json::to_string_pretty(&json).map_err(|e| Error::Runtime {
            message: format!("seccomp serialize: {e}"),
        })?;

        // Content-addressed cache: the filename embeds a digest of the exact bytes
        // we are about to write. A cache hit is therefore only possible when the
        // compiled artefact is byte-identical, so any change to `syscall_allowlist`
        // (e.g. tightening it) lands on a fresh filename and never re-serves the
        // old, looser JSON.
        let stem = sanitize_profile_stem(&profile.name);
        let digest = content_digest(serialized.as_bytes());
        let path = self.seccomp_path_for(&stem, &digest);
        if tokio::fs::metadata(&path).await.is_ok() {
            debug!(profile = %profile.name, path = %path.display(),
                "secprofile: seccomp cache hit");
            return Ok(path);
        }

        // Best-effort: drop stale seccomp artefacts for this profile so the cache
        // dir doesn't accumulate a file per historical allowlist.
        self.prune_stale(&stem, ".seccomp.json", &path).await;

        tokio::fs::write(&path, &serialized)
            .await
            .map_err(|e| Error::Runtime {
                message: format!("write {}: {e}", path.display()),
            })?;

        self.audit
            .record(
                AuditSinkKind::SeccompCompiled,
                Some(profile.name.clone()),
                None,
                serde_json::json!({
                    "path": path.display().to_string(),
                    "syscall_count": syscalls.len(),
                }),
            )
            .await;
        Ok(path)
    }

    async fn compile_apparmor(&self, profile: &SandboxProfile) -> std::io::Result<String> {
        let name = apparmor_profile_name(&profile.name);
        let body = render_apparmor_profile(profile, &name);
        // Content-addressed cache (same rationale as seccomp): the digest of the
        // rendered profile body keys the filename, so any profile change misses.
        let stem = sanitize_profile_stem(&profile.name);
        let digest = content_digest(body.as_bytes());
        let path = self.apparmor_path_for(&stem, &digest);
        let cache_hit = tokio::fs::metadata(&path).await.is_ok();
        if !cache_hit {
            self.prune_stale(&stem, ".apparmor", &path).await;
            tokio::fs::write(&path, body.as_bytes()).await?;
        }

        // Always (re-)load via apparmor_parser even on cache hit — the kernel may have
        // forgotten the profile across reboots, and `apparmor_parser -r` is a no-op when
        // the in-kernel definition already matches.
        let mut cmd = Command::new("apparmor_parser");
        cmd.arg("-r")
            .arg(&path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = cmd.output().await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            warn!(profile = %profile.name, %stderr,
                "secprofile: apparmor_parser -r failed; profile written but not loaded");
        }

        self.audit
            .record(
                AuditSinkKind::ApparmorCompiled,
                Some(profile.name.clone()),
                None,
                serde_json::json!({
                    "path": path.display().to_string(),
                    "name": name,
                    "loaded": output.status.success(),
                }),
            )
            .await;
        Ok(name)
    }

    /// Synthesize, package and install the SELinux module described by `profile`.
    /// Returns the module/type name (without prefix) when `semodule -i` succeeded,
    /// `Ok(None)` when any of the toolchain steps failed (a warn is also emitted),
    /// and `Err` only on I/O / setup failures.
    async fn compile_selinux(&self, profile: &SandboxProfile) -> Result<Option<String>> {
        let selinux_type = match profile.selinux_type.as_deref() {
            Some(t) if !t.is_empty() => t,
            _ => return Ok(None),
        };
        let module_name = selinux::module_name(&profile.name);
        let te_path = self.selinux_te_path_for(&profile.name);
        let mod_path = self.selinux_mod_path_for(&profile.name);
        let pp_path = self.selinux_pp_path_for(&profile.name);

        let te_text = selinux::render_selinux_te(
            &module_name,
            selinux_type,
            &profile.capabilities,
            &profile.mounts,
            &profile.network,
        );
        tokio::fs::write(&te_path, te_text.as_bytes())
            .await
            .map_err(|e| Error::Runtime {
                message: format!("write {}: {e}", te_path.display()),
            })?;

        let installed = selinux::package_and_install(&te_path, &mod_path, &pp_path).await;

        self.audit
            .record(
                AuditSinkKind::SelinuxCompiled,
                Some(profile.name.clone()),
                None,
                serde_json::json!({
                    "te_path": te_path.display().to_string(),
                    "pp_path": pp_path.display().to_string(),
                    "module_name": module_name,
                    "selinux_type": selinux_type,
                    "installed": installed,
                }),
            )
            .await;

        if installed {
            self.audit
                .record(
                    AuditSinkKind::SelinuxApplied,
                    Some(profile.name.clone()),
                    None,
                    serde_json::json!({
                        "module_name": module_name,
                        "selinux_type": selinux_type,
                    }),
                )
                .await;
            Ok(Some(selinux_type.to_string()))
        } else {
            Ok(None)
        }
    }

    /// Phase 15 — when the dynamic `.te` install path failed but the operator
    /// has opted into runtime fallback via `LINPODX_SELINUX_RUNTIME_FALLBACK=1`,
    /// substitute the conservative `container_t` static label and record an
    /// audit entry. Without the env var set, this is a no-op and the caller
    /// continues with `selinux_module_name = None` (existing behaviour).
    async fn maybe_apply_runtime_fallback(
        &self,
        profile: &SandboxProfile,
        compiled: &mut CompiledProfile,
        reason: &str,
    ) {
        if !runtime_fallback_enabled() {
            return;
        }
        compiled.selinux_static_label = Some(SELINUX_RUNTIME_FALLBACK_LABEL.to_string());
        self.audit
            .record(
                AuditSinkKind::SelinuxLabelRuntimeFallback,
                Some(profile.name.clone()),
                None,
                serde_json::json!({
                    "fallback_label": SELINUX_RUNTIME_FALLBACK_LABEL,
                    "reason": reason,
                    "requested_type": profile.selinux_type.clone(),
                }),
            )
            .await;
        warn!(profile = %profile.name, reason,
            "secprofile: applied SELinux runtime fallback label '{SELINUX_RUNTIME_FALLBACK_LABEL}'");
    }

    /// Build the seccomp cache path from an already-sanitized `stem` and a
    /// content `digest`. Callers MUST pass a stem produced by
    /// [`sanitize_profile_stem`] so a crafted profile name cannot traverse out of
    /// `cache_dir`.
    fn seccomp_path_for(&self, stem: &str, digest: &str) -> PathBuf {
        self.cache_dir.join(format!("{stem}.{digest}.seccomp.json"))
    }

    /// Build the AppArmor cache path from a sanitized `stem` and content
    /// `digest`. See [`Self::seccomp_path_for`] for the sanitization contract.
    fn apparmor_path_for(&self, stem: &str, digest: &str) -> PathBuf {
        self.cache_dir.join(format!("{stem}.{digest}.apparmor"))
    }

    /// Best-effort removal of stale content-addressed cache files for `stem` that
    /// carry a different digest than `keep`. Matches files named
    /// `{stem}.<something>{suffix}` in `cache_dir`. Any I/O error is ignored — a
    /// leftover stale file is a cosmetic disk-space issue, never a correctness one
    /// (it is never served because the live path is content-addressed).
    async fn prune_stale(&self, stem: &str, suffix: &str, keep: &Path) {
        let prefix = format!("{stem}.");
        let mut rd = match tokio::fs::read_dir(&self.cache_dir).await {
            Ok(rd) => rd,
            Err(_) => return,
        };
        while let Ok(Some(entry)) = rd.next_entry().await {
            let p = entry.path();
            if p == keep {
                continue;
            }
            if let Some(fname) = p.file_name().and_then(|s| s.to_str()) {
                if fname.starts_with(&prefix) && fname.ends_with(suffix) {
                    let _ = tokio::fs::remove_file(&p).await;
                }
            }
        }
    }

    fn selinux_te_path_for(&self, profile_name: &str) -> PathBuf {
        self.cache_dir
            .join(format!("{}.te", selinux::module_name(profile_name)))
    }

    fn selinux_mod_path_for(&self, profile_name: &str) -> PathBuf {
        self.cache_dir
            .join(format!("{}.mod", selinux::module_name(profile_name)))
    }

    fn selinux_pp_path_for(&self, profile_name: &str) -> PathBuf {
        self.cache_dir
            .join(format!("{}.pp", selinux::module_name(profile_name)))
    }
}

pub use selinux::is_selinux_available;

/// Phase 15 — returns true when `SELINUX_RUNTIME_FALLBACK_ENV` is set to `1`.
/// Public for unit-test wiring; runtime callers go through
/// `SecProfileCompiler::maybe_apply_runtime_fallback`.
pub fn runtime_fallback_enabled() -> bool {
    std::env::var(SELINUX_RUNTIME_FALLBACK_ENV)
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// Returns true if the host has `apparmor_parser` in PATH. Honours the
/// `LINPODX_TEST_APPARMOR=1` environment override so unit tests run deterministically
/// without relying on the host's AppArmor install state.
pub fn is_apparmor_available() -> bool {
    if let Ok(val) = std::env::var("LINPODX_TEST_APPARMOR") {
        return val == "1";
    }
    which_in_path("apparmor_parser")
}

fn which_in_path(binary: &str) -> bool {
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    for dir in std::env::split_paths(&paths) {
        if dir.join(binary).is_file() {
            return true;
        }
    }
    false
}

/// Phase 12 SELinux module synthesis + install. Public surface:
/// [`is_selinux_available`], `render_selinux_te`, `module_name`.
pub mod selinux {
    use super::{which_in_path, MountRule, NetworkPolicy, SourcePattern, SELINUX_MODULE_PREFIX};
    use crate::schema::Capabilities;
    use std::path::Path;
    use std::process::Stdio;
    use tokio::process::Command;
    use tracing::warn;

    /// Returns true if the SELinux toolchain is present *and* the kernel reports
    /// SELinux as Enforcing or Permissive (i.e. not Disabled). Honours the
    /// `LINPODX_TEST_SELINUX=1`/`0` environment override so unit tests run
    /// deterministically without depending on the host SELinux state.
    pub fn is_selinux_available() -> bool {
        if let Ok(val) = std::env::var("LINPODX_TEST_SELINUX") {
            return val == "1";
        }
        if !which_in_path("checkmodule")
            || !which_in_path("semodule_package")
            || !which_in_path("semodule")
        {
            return false;
        }
        match std::process::Command::new("getenforce").output() {
            Ok(out) if out.status.success() => {
                let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                !s.eq_ignore_ascii_case("Disabled") && !s.is_empty()
            }
            _ => false,
        }
    }

    /// Sanitize a profile name into a valid SELinux module identifier.
    pub fn module_name(profile_name: &str) -> String {
        let mut s = String::with_capacity(SELINUX_MODULE_PREFIX.len() + profile_name.len());
        s.push_str(SELINUX_MODULE_PREFIX);
        for c in profile_name.chars() {
            if c.is_ascii_alphanumeric() || c == '_' {
                s.push(c);
            } else {
                s.push('_');
            }
        }
        s
    }

    /// Synthesize a minimal SELinux module (.te) describing the requested domain
    /// type, the capabilities it may use, the mounts it can read/write, and
    /// whether network access is allowed.
    pub fn render_selinux_te(
        module_name: &str,
        selinux_type: &str,
        caps: &Capabilities,
        mounts: &[MountRule],
        network: &NetworkPolicy,
    ) -> String {
        let mut body = String::new();
        body.push_str("# Auto-generated by linpodx secprofile compiler. Do not edit by hand.\n");
        body.push_str(&format!("module {module_name} 1.0;\n\n"));
        body.push_str("require {\n");
        body.push_str("    type container_t;\n");
        body.push_str("    type container_file_t;\n");
        body.push_str("    class capability { ");
        body.push_str(&render_cap_class_list(caps));
        body.push_str(" };\n");
        body.push_str("    class file { read write open getattr };\n");
        body.push_str("    class dir { read search getattr };\n");
        body.push_str("    class tcp_socket { create connect bind listen };\n");
        body.push_str("    class udp_socket { create connect bind };\n");
        body.push_str("}\n\n");

        body.push_str(&format!("type {selinux_type};\n"));
        body.push_str(&format!("typeattribute {selinux_type} container_t;\n\n"));

        // Whether the profile drops ALL or named caps, only the explicit caps.add
        // list is permitted. SELinux is allow-listed (denies are implicit), so we
        // emit only the additions.
        for cap in &caps.add {
            body.push_str(&format!(
                "allow {selinux_type} self:capability {};\n",
                cap.to_ascii_lowercase()
            ));
        }

        body.push('\n');
        for rule in mounts {
            let access = if rule.read_only {
                "{ read open getattr }"
            } else {
                "{ read write open getattr }"
            };
            let dir_access = "{ read search getattr }";
            match &rule.source {
                SourcePattern::HostPath { path } => {
                    body.push_str(&format!("# mount host:{} -> {}\n", path, rule.destination));
                }
                SourcePattern::Named { name } => {
                    body.push_str(&format!(
                        "# mount volume:{} -> {}\n",
                        name, rule.destination
                    ));
                }
            }
            body.push_str(&format!(
                "allow {selinux_type} container_file_t:file {access};\n"
            ));
            body.push_str(&format!(
                "allow {selinux_type} container_file_t:dir {dir_access};\n"
            ));
        }

        body.push('\n');
        match network {
            NetworkPolicy::None => {
                body.push_str("# network=none — no socket allow rules emitted\n");
            }
            NetworkPolicy::Allowlist { .. } | NetworkPolicy::Full => {
                body.push_str(&format!(
                    "allow {selinux_type} self:tcp_socket {{ create connect bind listen }};\n"
                ));
                body.push_str(&format!(
                    "allow {selinux_type} self:udp_socket {{ create connect bind }};\n"
                ));
            }
        }

        body
    }

    /// Render the capability class permission list used in the `require` block.
    /// Always includes a baseline ("net_bind_service") so the require block is
    /// well-formed even when the profile drops everything; profile-specific caps
    /// are appended (deduplicated, lowercase).
    fn render_cap_class_list(caps: &Capabilities) -> String {
        let mut out: Vec<String> = vec!["net_bind_service".to_string()];
        for cap in &caps.add {
            let lower = cap.to_ascii_lowercase();
            if !out.contains(&lower) {
                out.push(lower);
            }
        }
        out.join(" ")
    }

    /// Run `checkmodule -> semodule_package -> semodule -i` against the .te file
    /// at `te_path`, writing intermediate `.mod` and `.pp` files. Returns true
    /// when all three steps succeeded; false (with a `warn` log) otherwise.
    pub(super) async fn package_and_install(
        te_path: &Path,
        mod_path: &Path,
        pp_path: &Path,
    ) -> bool {
        if !run_step(
            Command::new("checkmodule")
                .arg("-M")
                .arg("-m")
                .arg("-o")
                .arg(mod_path)
                .arg(te_path),
            "checkmodule",
        )
        .await
        {
            return false;
        }
        if !run_step(
            Command::new("semodule_package")
                .arg("-o")
                .arg(pp_path)
                .arg("-m")
                .arg(mod_path),
            "semodule_package",
        )
        .await
        {
            return false;
        }
        if !run_step(Command::new("semodule").arg("-i").arg(pp_path), "semodule").await {
            return false;
        }
        true
    }

    /// Helper accepting an `&mut Command` builder — runs to completion and
    /// returns whether the exit status was successful, logging `stderr` on
    /// failure. The caller frames each step's name for log clarity.
    async fn run_step(cmd: &mut Command, step: &str) -> bool {
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        match cmd.output().await {
            Ok(out) if out.status.success() => true,
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                warn!(step, %stderr, "secprofile: SELinux step failed");
                false
            }
            Err(e) => {
                warn!(step, error = %e, "secprofile: SELinux step could not be spawned");
                false
            }
        }
    }
}

/// OCI runtime-spec style seccomp profile. This is the shape podman + crun consume
/// when handed `--security-opt seccomp=<file>`.
#[derive(Debug, Clone, Serialize)]
struct OciSeccompProfile {
    #[serde(rename = "defaultAction")]
    default_action: String,
    architectures: Vec<String>,
    syscalls: Vec<OciSeccompSyscallGroup>,
}

#[derive(Debug, Clone, Serialize)]
struct OciSeccompSyscallGroup {
    names: Vec<String>,
    action: String,
}

fn render_seccomp_json(syscalls: &[String]) -> OciSeccompProfile {
    let mut sorted: Vec<String> = syscalls.to_vec();
    sorted.sort();
    sorted.dedup();
    OciSeccompProfile {
        default_action: "SCMP_ACT_ERRNO".to_string(),
        architectures: vec![
            "SCMP_ARCH_X86_64".to_string(),
            "SCMP_ARCH_X86".to_string(),
            "SCMP_ARCH_X32".to_string(),
            "SCMP_ARCH_AARCH64".to_string(),
        ],
        syscalls: vec![OciSeccompSyscallGroup {
            names: sorted,
            action: "SCMP_ACT_ALLOW".to_string(),
        }],
    }
}

/// Best-effort sanity check: feed our OCI JSON through seccompiler's *seccompiler*-style
/// JSON parser. The two schemas don't fully overlap (OCI uses `SCMP_ACT_*` strings while
/// seccompiler uses `allow`/`errno`/etc.), so a parse failure is *expected* and logged as
/// debug only. The validation call is retained because future versions of seccompiler may
/// grow OCI-shape compatibility — at that point this becomes a real check with no code
/// changes here.
fn validate_seccomp_json(profile: &OciSeccompProfile) {
    let Ok(serialized) = serde_json::to_vec(profile) else {
        return;
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => seccompiler::TargetArch::x86_64,
        "aarch64" => seccompiler::TargetArch::aarch64,
        "riscv64" => seccompiler::TargetArch::riscv64,
        _ => return,
    };
    if let Err(e) = seccompiler::compile_from_json(serialized.as_slice(), arch) {
        debug!(error = %e, "secprofile: seccompiler JSON validation skipped (OCI-format mismatch is expected)");
    }
}

fn apparmor_profile_name(profile_name: &str) -> String {
    let mut s = String::with_capacity(APPARMOR_PROFILE_PREFIX.len() + profile_name.len());
    s.push_str(APPARMOR_PROFILE_PREFIX);
    for c in profile_name.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
            s.push(c);
        } else {
            s.push('_');
        }
    }
    s
}

fn render_apparmor_profile(profile: &SandboxProfile, profile_name: &str) -> String {
    let mut body = String::new();
    body.push_str("# Auto-generated by linpodx secprofile compiler. Do not edit by hand.\n");
    body.push_str("#include <tunables/global>\n\n");
    body.push_str(&format!(
        "profile {profile_name} flags=(attach_disconnected,mediate_deleted) {{\n"
    ));
    body.push_str("  #include <abstractions/base>\n");

    body.push_str("\n  # ---- Capabilities (derived from sandbox profile) ----\n");
    render_apparmor_caps(&profile.capabilities, &mut body);

    body.push_str("\n  # ---- Network (derived from network policy) ----\n");
    render_apparmor_network(&profile.network, &mut body);

    body.push_str("\n  # ---- Mounts (derived from allowed mount whitelist) ----\n");
    render_apparmor_mounts(&profile.mounts, &mut body);

    if let Some(extras) = profile.apparmor_extra.as_ref() {
        if !extras.deny.is_empty() {
            body.push_str("\n  # ---- Extra deny rules ----\n");
            for rule in &extras.deny {
                body.push_str(&format!("  deny {rule},\n"));
            }
        }
        if !extras.allow.is_empty() {
            body.push_str("\n  # ---- Extra allow rules ----\n");
            for rule in &extras.allow {
                body.push_str(&format!("  {rule},\n"));
            }
        }
    }

    body.push_str("}\n");
    body
}

fn render_apparmor_caps(caps: &Capabilities, body: &mut String) {
    let drops_all = caps.drop.iter().any(|c| c.eq_ignore_ascii_case("ALL"));
    if drops_all {
        body.push_str("  deny capability,\n");
        for cap in &caps.add {
            body.push_str(&format!("  capability {},\n", cap.to_ascii_lowercase()));
        }
    } else {
        for cap in &caps.drop {
            body.push_str(&format!(
                "  deny capability {},\n",
                cap.to_ascii_lowercase()
            ));
        }
        for cap in &caps.add {
            body.push_str(&format!("  capability {},\n", cap.to_ascii_lowercase()));
        }
    }
}

fn render_apparmor_network(net: &NetworkPolicy, body: &mut String) {
    match net {
        NetworkPolicy::None => {
            body.push_str("  deny network,\n");
        }
        NetworkPolicy::Allowlist { .. } => {
            // L4/DNS allowlists are enforced elsewhere (DNS proxy + netfilter helper).
            // AppArmor network mediation is left wide open here.
            body.push_str("  network,\n");
        }
        NetworkPolicy::Full => {
            body.push_str("  network,\n");
        }
    }
}

fn render_apparmor_mounts(mounts: &[MountRule], body: &mut String) {
    if mounts.is_empty() {
        body.push_str("  deny mount,\n");
        return;
    }
    for rule in mounts {
        let dst = &rule.destination;
        let access = if rule.read_only { "r" } else { "rw" };
        match &rule.source {
            SourcePattern::HostPath { path } => {
                body.push_str(&format!("  {path}/** {access},\n"));
                body.push_str(&format!("  {dst}/** {access},\n"));
            }
            SourcePattern::Named { name } => {
                body.push_str(&format!("  # named volume {name}\n"));
                body.push_str(&format!("  {dst}/** {access},\n"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{Capabilities, MountRule, SandboxProfile, SourcePattern};
    use linpodx_common::audit_sink::NoopAuditSink;

    fn profile_fixture(name: &str) -> SandboxProfile {
        SandboxProfile {
            version: 1,
            name: name.to_string(),
            description: String::new(),
            network: NetworkPolicy::None,
            mounts: vec![],
            limits: Default::default(),
            capabilities: Capabilities::default(),
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

    #[test]
    fn render_seccomp_json_is_oci_shape_with_dedup_sorted_syscalls() {
        let p = render_seccomp_json(&["write".into(), "read".into(), "write".into()]);
        assert_eq!(p.default_action, "SCMP_ACT_ERRNO");
        assert_eq!(p.syscalls.len(), 1);
        assert_eq!(p.syscalls[0].action, "SCMP_ACT_ALLOW");
        assert_eq!(p.syscalls[0].names, vec!["read", "write"]);
        let serialized = serde_json::to_string(&p).unwrap();
        assert!(serialized.contains("SCMP_ARCH_X86_64"));
    }

    #[test]
    fn apparmor_profile_name_sanitises_invalid_chars() {
        assert_eq!(apparmor_profile_name("ai-agent"), "linpodx-ai-agent");
        assert_eq!(apparmor_profile_name("foo bar/x"), "linpodx-foo_bar_x");
    }

    #[test]
    fn render_apparmor_profile_includes_caps_network_mounts_and_extras() {
        let mut p = profile_fixture("ai-agent");
        p.capabilities = Capabilities {
            drop: vec!["ALL".into()],
            add: vec!["NET_BIND_SERVICE".into()],
        };
        p.mounts.push(MountRule {
            source: SourcePattern::HostPath {
                path: "/srv/work".into(),
            },
            destination: "/work".into(),
            read_only: false,
        });
        p.apparmor_extra = Some(crate::schema::AppArmorExtras {
            deny: vec!["/etc/shadow r".into()],
            allow: vec!["/tmp/** rw".into()],
        });
        let body = render_apparmor_profile(&p, "linpodx-ai-agent");
        assert!(body.contains("profile linpodx-ai-agent"));
        assert!(body.contains("deny capability,"));
        assert!(body.contains("capability net_bind_service,"));
        assert!(body.contains("deny network,"));
        assert!(body.contains("/srv/work/** rw,"));
        assert!(body.contains("/work/** rw,"));
        assert!(body.contains("deny /etc/shadow r,"));
        assert!(body.contains("/tmp/** rw,"));
    }

    #[test]
    fn render_apparmor_with_no_mounts_denies_all_mounts() {
        let p = profile_fixture("strict");
        let body = render_apparmor_profile(&p, "linpodx-strict");
        assert!(body.contains("deny mount,"));
        // Default profile drops ALL caps -> deny capability with no `capability X,` adds.
        assert!(body.contains("deny capability,"));
        assert!(!body.contains("capability "));
    }

    /// Process-wide lock for tests that mutate `LINPODX_TEST_*` /
    /// `LINPODX_SELINUX_RUNTIME_FALLBACK` env vars. Without it libtest's parallel
    /// runner races set/remove pairs across tests and the "available?" gates
    /// observe the wrong value. Mirrors the pattern in `plugin_store::tests`.
    static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn is_apparmor_available_respects_test_override() {
        let _g = ENV_LOCK.lock().await;
        std::env::set_var("LINPODX_TEST_APPARMOR", "0");
        assert!(!is_apparmor_available());
        std::env::set_var("LINPODX_TEST_APPARMOR", "1");
        assert!(is_apparmor_available());
        std::env::remove_var("LINPODX_TEST_APPARMOR");
    }

    #[tokio::test]
    async fn compile_writes_seccomp_json_when_allowlist_set() {
        let dir = tempfile::tempdir().expect("tempdir");
        let compiler = SecProfileCompiler::new(dir.path().to_path_buf(), Arc::new(NoopAuditSink));
        let mut p = profile_fixture("net-tools");
        p.syscall_allowlist = Some(vec!["read".into(), "write".into(), "exit".into()]);

        let compiled = compiler.compile(&p).await.expect("compile");
        let path = compiled.seccomp_path.clone().expect("seccomp path");
        assert!(path.exists());
        let body = std::fs::read_to_string(&path).expect("read seccomp json");
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("parse");
        assert_eq!(parsed["defaultAction"], "SCMP_ACT_ERRNO");
        let names = parsed["syscalls"][0]["names"].as_array().unwrap();
        assert_eq!(names.len(), 3);
        // to_security_opts gives podman-ready strings.
        let opts = compiled.to_security_opts();
        assert_eq!(opts.len(), 1);
        assert!(opts[0].starts_with("seccomp="));
    }

    #[tokio::test]
    async fn compile_skips_seccomp_when_no_allowlist() {
        let dir = tempfile::tempdir().expect("tempdir");
        let compiler = SecProfileCompiler::new(dir.path().to_path_buf(), Arc::new(NoopAuditSink));
        let p = profile_fixture("plain");
        let compiled = compiler.compile(&p).await.expect("compile");
        assert!(compiled.seccomp_path.is_none());
        assert!(compiled.apparmor_name.is_none());
        assert!(compiled.to_security_opts().is_empty());
    }

    #[tokio::test]
    async fn compile_seccomp_cache_hit_does_not_rewrite_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let compiler = SecProfileCompiler::new(dir.path().to_path_buf(), Arc::new(NoopAuditSink));
        let mut p = profile_fixture("cache-test");
        p.syscall_allowlist = Some(vec!["read".into()]);

        let first = compiler.compile(&p).await.expect("compile 1");
        let path = first.seccomp_path.clone().expect("path");
        let mtime_before = std::fs::metadata(&path).unwrap().modified().unwrap();

        // Sleep briefly to ensure mtime resolution would catch a rewrite.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let second = compiler.compile(&p).await.expect("compile 2");
        assert_eq!(second.seccomp_path.as_ref(), Some(&path));
        let mtime_after = std::fs::metadata(&path).unwrap().modified().unwrap();
        assert_eq!(
            mtime_before, mtime_after,
            "cache hit should not rewrite the file"
        );
    }

    #[test]
    fn sanitize_profile_stem_neutralises_traversal_and_absolute_names() {
        // Path traversal and absolute names must become inert single-segment stems.
        assert_eq!(
            sanitize_profile_stem("../../etc/cron.d/x"),
            "______etc_cron_d_x"
        );
        assert_eq!(sanitize_profile_stem("/etc/shadow"), "_etc_shadow");
        assert_eq!(sanitize_profile_stem("a/../b"), "a____b");
        // Normal names are preserved verbatim.
        assert_eq!(sanitize_profile_stem("ai-agent"), "ai-agent");
        assert_eq!(sanitize_profile_stem("plain_1"), "plain_1");
        // Empty / all-invalid names never yield an empty stem.
        assert!(!sanitize_profile_stem("").is_empty());
        assert!(!sanitize_profile_stem("///").is_empty());
        // Length is capped.
        assert!(sanitize_profile_stem(&"x".repeat(500)).len() <= MAX_CACHE_STEM_LEN);
    }

    #[tokio::test]
    async fn compile_seccomp_traversal_name_stays_inside_cache_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache_root = dir.path().to_path_buf();
        let compiler = SecProfileCompiler::new(cache_root.clone(), Arc::new(NoopAuditSink));
        let mut p = profile_fixture("../../../../tmp/pwned");
        p.syscall_allowlist = Some(vec!["read".into()]);

        let compiled = compiler.compile(&p).await.expect("compile");
        let path = compiled.seccomp_path.expect("seccomp path");
        // The written file must live directly inside the cache dir — no escape.
        let canon_cache = std::fs::canonicalize(&cache_root).expect("canon cache");
        let canon_parent =
            std::fs::canonicalize(path.parent().expect("parent")).expect("canon parent");
        assert_eq!(canon_parent, canon_cache);
        assert!(path.exists());
    }

    #[tokio::test]
    async fn compile_seccomp_changed_allowlist_uses_new_cache_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let compiler = SecProfileCompiler::new(dir.path().to_path_buf(), Arc::new(NoopAuditSink));
        let mut p = profile_fixture("evolving");
        p.syscall_allowlist = Some(vec!["read".into(), "write".into()]);
        let first = compiler.compile(&p).await.expect("compile 1");
        let path_a = first.seccomp_path.expect("path a");

        // Tighten the allowlist — the cache must miss and a *different* file used.
        p.syscall_allowlist = Some(vec!["read".into()]);
        let second = compiler.compile(&p).await.expect("compile 2");
        let path_b = second.seccomp_path.expect("path b");

        assert_ne!(
            path_a, path_b,
            "a changed allowlist must produce a distinct content-addressed cache file"
        );
        assert!(path_b.exists());
        let body = std::fs::read_to_string(&path_b).expect("read new seccomp");
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("parse");
        assert_eq!(parsed["syscalls"][0]["names"].as_array().unwrap().len(), 1);
        // Stale file for the old allowlist is pruned.
        assert!(!path_a.exists(), "old cache file should be pruned");
    }

    #[tokio::test]
    async fn compile_skips_apparmor_when_unavailable() {
        let _g = ENV_LOCK.lock().await;
        std::env::set_var("LINPODX_TEST_APPARMOR", "0");
        let dir = tempfile::tempdir().expect("tempdir");
        let compiler = SecProfileCompiler::new(dir.path().to_path_buf(), Arc::new(NoopAuditSink));
        let mut p = profile_fixture("aa-skip");
        p.apparmor_extra = Some(crate::schema::AppArmorExtras::default());
        let compiled = compiler.compile(&p).await.expect("compile");
        assert!(compiled.apparmor_name.is_none());
        std::env::remove_var("LINPODX_TEST_APPARMOR");
    }

    // ---- Phase 12 SELinux tests ----

    #[test]
    fn selinux_module_name_sanitises_invalid_chars() {
        assert_eq!(selinux::module_name("ai-agent"), "linpodx_ai_agent");
        assert_eq!(selinux::module_name("foo bar/x"), "linpodx_foo_bar_x");
        assert_eq!(selinux::module_name("plain_1"), "linpodx_plain_1");
    }

    #[test]
    fn render_selinux_te_emits_stable_module_for_fixture_profile() {
        let mut p = profile_fixture("ai-agent");
        p.capabilities = Capabilities {
            drop: vec!["ALL".into()],
            add: vec!["NET_BIND_SERVICE".into()],
        };
        p.mounts.push(MountRule {
            source: SourcePattern::HostPath {
                path: "/srv/work".into(),
            },
            destination: "/work".into(),
            read_only: false,
        });
        let te = selinux::render_selinux_te(
            "linpodx_ai_agent",
            "linpodx_ai_agent_t",
            &p.capabilities,
            &p.mounts,
            &p.network,
        );
        assert!(te.contains("module linpodx_ai_agent 1.0;"));
        assert!(te.contains("type linpodx_ai_agent_t;"));
        assert!(te.contains("typeattribute linpodx_ai_agent_t container_t;"));
        assert!(te.contains("allow linpodx_ai_agent_t self:capability net_bind_service;"));
        // network=None branch should NOT emit socket allows.
        assert!(!te.contains("self:tcp_socket"));
        // mount comment + container_file_t allow
        assert!(te.contains("# mount host:/srv/work -> /work"));
        assert!(te.contains("allow linpodx_ai_agent_t container_file_t:file"));
    }

    #[test]
    fn render_selinux_te_with_network_full_emits_socket_allows() {
        let mut p = profile_fixture("net-on");
        p.network = NetworkPolicy::Full;
        let te = selinux::render_selinux_te(
            "linpodx_net_on",
            "linpodx_net_on_t",
            &p.capabilities,
            &p.mounts,
            &p.network,
        );
        assert!(te.contains("self:tcp_socket { create connect bind listen };"));
        assert!(te.contains("self:udp_socket { create connect bind };"));
    }

    #[test]
    fn render_selinux_te_readonly_mount_excludes_write() {
        let mut p = profile_fixture("ro-mount");
        p.mounts.push(MountRule {
            source: SourcePattern::Named {
                name: "data".into(),
            },
            destination: "/data".into(),
            read_only: true,
        });
        let te = selinux::render_selinux_te(
            "linpodx_ro_mount",
            "linpodx_ro_mount_t",
            &p.capabilities,
            &p.mounts,
            &p.network,
        );
        assert!(te.contains("# mount volume:data -> /data"));
        assert!(te.contains("container_file_t:file { read open getattr };"));
        assert!(!te.contains("container_file_t:file { read write open getattr };"));
    }

    #[tokio::test]
    async fn is_selinux_available_respects_test_override() {
        let _g = ENV_LOCK.lock().await;
        std::env::set_var("LINPODX_TEST_SELINUX", "0");
        assert!(!selinux::is_selinux_available());
        std::env::set_var("LINPODX_TEST_SELINUX", "1");
        assert!(selinux::is_selinux_available());
        std::env::remove_var("LINPODX_TEST_SELINUX");
    }

    #[tokio::test]
    async fn compile_skips_selinux_when_unavailable() {
        let _g = ENV_LOCK.lock().await;
        std::env::set_var("LINPODX_TEST_SELINUX", "0");
        let dir = tempfile::tempdir().expect("tempdir");
        let compiler = SecProfileCompiler::new(dir.path().to_path_buf(), Arc::new(NoopAuditSink));
        let mut p = profile_fixture("se-skip");
        p.selinux_type = Some("linpodx_se_skip_t".into());
        let compiled = compiler.compile(&p).await.expect("compile");
        assert!(compiled.selinux_module_name.is_none());
        assert!(compiled.to_security_opts().is_empty());
        std::env::remove_var("LINPODX_TEST_SELINUX");
    }

    #[tokio::test]
    async fn compile_attempts_selinux_when_available_and_returns_none_on_missing_tools() {
        let _g = ENV_LOCK.lock().await;
        // With LINPODX_TEST_SELINUX=1 the availability gate is forced true, but
        // checkmodule/semodule_package/semodule are unlikely to be on the test
        // host. The compiler should write the .te file, fail gracefully on the
        // missing tools, and report selinux_module_name=None without erroring.
        std::env::set_var("LINPODX_TEST_SELINUX", "1");
        let dir = tempfile::tempdir().expect("tempdir");
        let compiler = SecProfileCompiler::new(dir.path().to_path_buf(), Arc::new(NoopAuditSink));
        let mut p = profile_fixture("se-attempt");
        p.selinux_type = Some("linpodx_se_attempt_t".into());
        let compiled = compiler.compile(&p).await.expect("compile");
        // .te file should have been written even when the tool chain is absent.
        let te_path = dir.path().join("linpodx_se_attempt.te");
        if which_in_path("checkmodule")
            && which_in_path("semodule_package")
            && which_in_path("semodule")
        {
            // Toolchain present — the install attempt may succeed (root) or fail
            // (unprivileged); we only check that no error bubbled up.
            let _ = compiled.selinux_module_name;
        } else {
            assert!(compiled.selinux_module_name.is_none());
        }
        assert!(te_path.exists(), "expected .te at {}", te_path.display());
        std::env::remove_var("LINPODX_TEST_SELINUX");
    }

    #[tokio::test]
    async fn compile_skips_selinux_when_type_is_none() {
        let _g = ENV_LOCK.lock().await;
        std::env::set_var("LINPODX_TEST_SELINUX", "1");
        let dir = tempfile::tempdir().expect("tempdir");
        let compiler = SecProfileCompiler::new(dir.path().to_path_buf(), Arc::new(NoopAuditSink));
        let p = profile_fixture("no-se");
        let compiled = compiler.compile(&p).await.expect("compile");
        assert!(compiled.selinux_module_name.is_none());
        std::env::remove_var("LINPODX_TEST_SELINUX");
    }

    // ---- Phase 14: SELinux static-label flow ----

    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;

    /// Counting audit sink reused by the static-label tests so we can assert
    /// `SelinuxStaticLabelApplied` is recorded exactly once on success and not
    /// at all when the static-label gate is skipped.
    #[derive(Default)]
    struct CountingSink {
        events: Mutex<Vec<(AuditSinkKind, serde_json::Value)>>,
    }

    impl CountingSink {
        fn count(&self, want: AuditSinkKind) -> usize {
            self.events
                .lock()
                .unwrap()
                .iter()
                .filter(|(k, _)| *k == want)
                .count()
        }
    }

    impl AuditSink for CountingSink {
        fn record(
            &self,
            kind: AuditSinkKind,
            _profile_name: Option<String>,
            _container_id: Option<String>,
            payload: serde_json::Value,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.events.lock().unwrap().push((kind, payload));
            Box::pin(async {})
        }
    }

    #[tokio::test]
    async fn compile_static_selinux_label_skips_dynamic_te_and_audits() {
        let dir = tempfile::tempdir().expect("tempdir");
        let counting = Arc::new(CountingSink::default());
        let sink: Arc<dyn AuditSink> = Arc::clone(&counting) as Arc<dyn AuditSink>;
        let compiler = SecProfileCompiler::new(dir.path().to_path_buf(), sink);
        let mut p = profile_fixture("static-se");
        p.selinux_label = Some("container_t".into());

        let compiled = compiler.compile(&p).await.expect("compile");
        assert_eq!(
            compiled.selinux_static_label.as_deref(),
            Some("container_t")
        );
        assert!(compiled.selinux_module_name.is_none());
        // Static path must NOT touch the dynamic .te file.
        let te_path = dir.path().join("linpodx_static_se.te");
        assert!(
            !te_path.exists(),
            "static label flow must not write a .te file at {}",
            te_path.display()
        );
        // Audit recorded exactly once with the verbatim label payload.
        assert_eq!(counting.count(AuditSinkKind::SelinuxStaticLabelApplied), 1);
        // Static label takes precedence in the security-opts list.
        let opts = compiled.to_security_opts();
        assert_eq!(opts, vec!["label=type:container_t".to_string()]);
    }

    #[tokio::test]
    async fn compile_static_label_takes_precedence_over_dynamic_module() {
        // Even if both fields were somehow populated (validation rejects this
        // upstream), the compile should prefer the static label and never call
        // the dynamic pipeline. We pin this so a future regression that relaxes
        // validation can't silently drop the operator-supplied static label.
        std::env::set_var("LINPODX_TEST_SELINUX", "1");
        let dir = tempfile::tempdir().expect("tempdir");
        let compiler = SecProfileCompiler::new(dir.path().to_path_buf(), Arc::new(NoopAuditSink));
        let mut p = profile_fixture("dual-se");
        p.selinux_label = Some("system_t".into());
        p.selinux_type = Some("ignored_dyn_t".into());

        let compiled = compiler.compile(&p).await.expect("compile");
        assert_eq!(compiled.selinux_static_label.as_deref(), Some("system_t"));
        assert!(compiled.selinux_module_name.is_none());
        let opts = compiled.to_security_opts();
        assert_eq!(opts, vec!["label=type:system_t".to_string()]);
        std::env::remove_var("LINPODX_TEST_SELINUX");
    }

    #[tokio::test]
    async fn compile_empty_static_label_is_treated_as_unset() {
        let dir = tempfile::tempdir().expect("tempdir");
        let counting = Arc::new(CountingSink::default());
        let sink: Arc<dyn AuditSink> = Arc::clone(&counting) as Arc<dyn AuditSink>;
        let compiler = SecProfileCompiler::new(dir.path().to_path_buf(), sink);
        let mut p = profile_fixture("blank-se");
        p.selinux_label = Some("   ".into());

        let compiled = compiler.compile(&p).await.expect("compile");
        assert!(compiled.selinux_static_label.is_none());
        assert_eq!(counting.count(AuditSinkKind::SelinuxStaticLabelApplied), 0);
        assert!(compiled.to_security_opts().is_empty());
    }

    #[test]
    fn to_security_opts_emits_static_label_only_when_both_present() {
        // Direct shape test of the precedence inside CompiledProfile so a future
        // refactor that swaps the fields can't silently regress podman behaviour.
        let mut compiled = CompiledProfile {
            selinux_static_label: Some("container_t".into()),
            selinux_module_name: Some("linpodx_dyn_t".into()),
            ..Default::default()
        };
        let opts = compiled.to_security_opts();
        assert_eq!(opts, vec!["label=type:container_t".to_string()]);
        // Drop static label → dynamic module name surfaces.
        compiled.selinux_static_label = None;
        let opts = compiled.to_security_opts();
        assert_eq!(opts, vec!["label=type:linpodx_dyn_t".to_string()]);
    }

    // ---- Phase 15: SELinux runtime fallback ----
    //
    // Tests below also take the module-wide `ENV_LOCK` so they don't race the
    // `LINPODX_TEST_SELINUX` and `LINPODX_SELINUX_RUNTIME_FALLBACK` env vars
    // against the Phase 12/14 tests above.

    #[tokio::test]
    async fn runtime_fallback_triggers_when_env_set_and_dynamic_path_fails() {
        let _g = ENV_LOCK.lock().await;
        // Force the dynamic path to be tried (LINPODX_TEST_SELINUX=1 makes
        // is_selinux_available return true) and toggle the runtime fallback env on.
        // Since the test host is unlikely to actually have checkmodule/semodule, the
        // install will return false; with the env set we should see the fallback
        // label substituted and one SelinuxLabelRuntimeFallback audit recorded.
        std::env::set_var("LINPODX_TEST_SELINUX", "1");
        std::env::set_var("LINPODX_SELINUX_RUNTIME_FALLBACK", "1");
        let dir = tempfile::tempdir().expect("tempdir");
        let counting = Arc::new(CountingSink::default());
        let sink: Arc<dyn AuditSink> = Arc::clone(&counting) as Arc<dyn AuditSink>;
        let compiler = SecProfileCompiler::new(dir.path().to_path_buf(), sink);
        let mut p = profile_fixture("se-fallback");
        p.selinux_type = Some("linpodx_se_fallback_t".into());

        let compiled = compiler.compile(&p).await.expect("compile");

        // Only assert fallback semantics on hosts that actually lack the toolchain;
        // a CI runner with checkmodule + root could legitimately succeed and skip
        // fallback entirely.
        if !which_in_path("checkmodule")
            || !which_in_path("semodule_package")
            || !which_in_path("semodule")
        {
            assert_eq!(
                compiled.selinux_static_label.as_deref(),
                Some("container_t"),
                "expected runtime fallback label when env set and toolchain absent"
            );
            assert!(compiled.selinux_module_name.is_none());
            assert_eq!(
                counting.count(AuditSinkKind::SelinuxLabelRuntimeFallback),
                1
            );
            assert_eq!(
                compiled.to_security_opts(),
                vec!["label=type:container_t".to_string()]
            );
        }
        std::env::remove_var("LINPODX_SELINUX_RUNTIME_FALLBACK");
        std::env::remove_var("LINPODX_TEST_SELINUX");
    }

    #[tokio::test]
    async fn runtime_fallback_skipped_without_env() {
        let _g = ENV_LOCK.lock().await;
        // Dynamic path attempted but the env var is NOT set — behaviour should
        // match the pre-Phase-15 contract: no static label, no fallback audit,
        // and security_opts stays empty.
        std::env::set_var("LINPODX_TEST_SELINUX", "1");
        std::env::remove_var("LINPODX_SELINUX_RUNTIME_FALLBACK");
        let dir = tempfile::tempdir().expect("tempdir");
        let counting = Arc::new(CountingSink::default());
        let sink: Arc<dyn AuditSink> = Arc::clone(&counting) as Arc<dyn AuditSink>;
        let compiler = SecProfileCompiler::new(dir.path().to_path_buf(), sink);
        let mut p = profile_fixture("se-no-fallback");
        p.selinux_type = Some("linpodx_se_no_fallback_t".into());

        let compiled = compiler.compile(&p).await.expect("compile");
        if !which_in_path("checkmodule")
            || !which_in_path("semodule_package")
            || !which_in_path("semodule")
        {
            assert!(compiled.selinux_static_label.is_none());
            assert!(compiled.selinux_module_name.is_none());
            assert_eq!(
                counting.count(AuditSinkKind::SelinuxLabelRuntimeFallback),
                0
            );
            assert!(compiled.to_security_opts().is_empty());
        }
        std::env::remove_var("LINPODX_TEST_SELINUX");
    }

    #[tokio::test]
    async fn runtime_fallback_enabled_reads_env_strictly() {
        let _g = ENV_LOCK.lock().await;
        // Only the literal string "1" enables it. Any other value (including
        // "true" / "yes" / empty) leaves the gate closed so future operators
        // don't accidentally enable it via a spurious export.
        std::env::remove_var("LINPODX_SELINUX_RUNTIME_FALLBACK");
        assert!(!runtime_fallback_enabled());
        std::env::set_var("LINPODX_SELINUX_RUNTIME_FALLBACK", "0");
        assert!(!runtime_fallback_enabled());
        std::env::set_var("LINPODX_SELINUX_RUNTIME_FALLBACK", "true");
        assert!(!runtime_fallback_enabled());
        std::env::set_var("LINPODX_SELINUX_RUNTIME_FALLBACK", "1");
        assert!(runtime_fallback_enabled());
        std::env::remove_var("LINPODX_SELINUX_RUNTIME_FALLBACK");
    }
}
