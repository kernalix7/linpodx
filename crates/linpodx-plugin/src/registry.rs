//! In-memory registry of loaded plugins.
//!
//! The daemon constructs a fresh registry per IPC call (Stage 2-A wiring), populating
//! it from the SQLite `plugins` table. A future stage may keep one long-lived registry
//! once we add cache invalidation on enable/disable.

use crate::loader::{self, LoadedPlugin};
use crate::manifest::PluginManifest;
use crate::{
    FilterDecision, InjectorPayload, NetworkDecision, NetworkTraceEvent, PluginDecision, Result,
    ValidatorDecision,
};
use std::path::Path;
use tracing::warn;
use wasmtime::{Config, Engine};

/// One row's worth of plugin info — the registry needs the manifest + on-disk wasm
/// path together. The daemon builds this from a `PluginSummary` row.
pub struct PluginSpec {
    pub manifest: PluginManifest,
    pub wasm_path: std::path::PathBuf,
}

pub struct PluginRegistry {
    engine: Engine,
    plugins: Vec<LoadedPlugin>,
}

impl PluginRegistry {
    pub fn new() -> Result<Self> {
        let mut cfg = Config::new();
        cfg.wasm_multi_memory(false);
        // Cranelift is enabled by feature; explicit strategy keeps behavior stable.
        let engine = Engine::new(&cfg).map_err(|e| {
            crate::PluginError::WasmLoad(format!("wasmtime engine init failed: {e}"))
        })?;
        Ok(Self {
            engine,
            plugins: Vec::new(),
        })
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    pub fn names(&self) -> Vec<&str> {
        self.plugins.iter().map(|p| p.name()).collect()
    }

    /// Bulk-load a list of plugin specs. Failures for a single plugin emit a warn-level
    /// trace and skip that entry — a broken plugin must not knock the daemon over.
    pub fn load_all(&mut self, specs: &[PluginSpec]) {
        for s in specs {
            match loader::load(&self.engine, &s.manifest, &s.wasm_path) {
                Ok(p) => self.plugins.push(p),
                Err(e) => warn!(
                    plugin = %s.manifest.name,
                    error = %e,
                    "failed to load plugin; skipping"
                ),
            }
        }
    }

    pub fn load_one(&mut self, manifest: &PluginManifest, wasm_path: &Path) -> Result<()> {
        let p = loader::load(&self.engine, manifest, wasm_path)?;
        self.plugins.push(p);
        Ok(())
    }

    /// Invoke every plugin that subscribes to the `approval` hook with `payload`.
    /// Returns one `(plugin_name, decision, reason)` triple per invocation. A plugin
    /// trap turns into a `Defer` with the trap message in the reason field — never an
    /// error from this function.
    pub fn evaluate_approval(&mut self, payload: &[u8]) -> Vec<(String, PluginDecision, String)> {
        let mut out = Vec::new();
        for p in self.plugins.iter_mut() {
            if !p.hooks().iter().any(|h| h == "approval") || !p.has_approval {
                continue;
            }
            let name = p.name().to_string();
            match loader::evaluate(p, payload) {
                Ok((d, r)) => out.push((name, d, r)),
                Err(e) => {
                    warn!(plugin = %name, error = %e, "plugin trap during approval; treating as Defer");
                    out.push((name, PluginDecision::Defer, e.to_string()));
                }
            }
        }
        out
    }

    /// Chain every `audit_filter` plugin over `payload`. Semantics:
    ///   * Plugins are invoked in registry order.
    ///   * `Drop` short-circuits — return immediately so the audit entry is suppressed.
    ///   * `Transform` rewrites the payload threaded into the next plugin.
    ///   * `Forward` is the no-op default.
    ///
    /// Trapping plugins are skipped (logged as warn) so a single broken plugin can't
    /// silently drop every audit entry. The first element of each tuple is the plugin
    /// name (useful for tracing); the final return value is the chain outcome plus the
    /// payload bytes the audit log should persist (the original payload when no plugin
    /// ran or every plugin returned Forward).
    pub fn evaluate_audit_filter(&mut self, payload: &[u8]) -> AuditFilterChainResult {
        let mut current = payload.to_vec();
        let mut steps = Vec::new();
        for p in self.plugins.iter_mut() {
            if !p.hooks().iter().any(|h| h == "audit_filter") || !p.has_audit_filter {
                continue;
            }
            let name = p.name().to_string();
            match loader::evaluate_audit_filter(p, &current) {
                Ok(FilterDecision::Drop) => {
                    steps.push((name, FilterDecision::Drop));
                    return AuditFilterChainResult {
                        outcome: FilterDecision::Drop,
                        payload: current,
                        steps,
                    };
                }
                Ok(FilterDecision::Transform { payload: new }) => {
                    current = new.clone();
                    steps.push((name, FilterDecision::Transform { payload: new }));
                }
                Ok(FilterDecision::Forward) => {
                    steps.push((name, FilterDecision::Forward));
                }
                Err(e) => {
                    warn!(plugin = %name, error = %e, "plugin trap during audit_filter; skipping");
                }
            }
        }
        AuditFilterChainResult {
            outcome: FilterDecision::Forward,
            payload: current,
            steps,
        }
    }

    /// Run every `profile_validator` plugin over the YAML body of a sandbox profile and
    /// return one `(plugin_name, ValidatorDecision)` tuple per plugin. The caller decides
    /// what "any reject" means — the sandbox treats *any* `Reject` as a hard fail and
    /// records `ProfileValidatorRejected` per offending plugin.
    pub fn evaluate_profile_validator(&mut self, yaml: &str) -> Vec<(String, ValidatorDecision)> {
        let mut out = Vec::new();
        for p in self.plugins.iter_mut() {
            if !p.hooks().iter().any(|h| h == "profile_validator") || !p.has_profile_validator {
                continue;
            }
            let name = p.name().to_string();
            match loader::evaluate_profile_validator(p, yaml) {
                Ok(d) => out.push((name, d)),
                Err(e) => {
                    warn!(plugin = %name, error = %e, "plugin trap during profile_validator; treating as Reject");
                    out.push((
                        name,
                        ValidatorDecision::Reject {
                            reason: format!("plugin trap: {e}"),
                        },
                    ));
                }
            }
        }
        out
    }
}

/// Result of [`PluginRegistry::evaluate_audit_filter`]. `outcome` is the chain-level
/// verdict (`Drop` if any plugin asked to drop, otherwise `Forward`); `payload` is the
/// (potentially transformed) bytes the audit log should persist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditFilterChainResult {
    pub outcome: FilterDecision,
    pub payload: Vec<u8>,
    pub steps: Vec<(String, FilterDecision)>,
}

impl PluginRegistry {
    /// Chain every `network_trace` plugin over `event` and combine their decisions.
    /// Resolution rules (in order):
    ///   * If any plugin says `Deny`, return `Deny` (deny wins).
    ///   * Otherwise if any plugin says `AuditOnly`, return `AuditOnly`.
    ///   * Otherwise return `Allow` (the default — no plugin ran or every plugin said
    ///     allow).
    ///
    /// Plugins that trap are logged at warn and skipped (they neither block nor allow).
    pub fn evaluate_network_trace(&mut self, event: &NetworkTraceEvent) -> NetworkDecision {
        let mut any_audit = false;
        for p in self.plugins.iter_mut() {
            if !p.hooks().iter().any(|h| h == "network_trace") || !p.has_network_trace {
                continue;
            }
            let name = p.name().to_string();
            match loader::evaluate_network_trace(p, event) {
                Ok(NetworkDecision::Deny) => return NetworkDecision::Deny,
                Ok(NetworkDecision::AuditOnly) => any_audit = true,
                Ok(NetworkDecision::Allow) => {}
                Err(e) => {
                    warn!(
                        plugin = %name,
                        error = %e,
                        "plugin trap during network_trace; treating as Allow"
                    );
                }
            }
        }
        if any_audit {
            NetworkDecision::AuditOnly
        } else {
            NetworkDecision::Allow
        }
    }

    /// Chain every `runtime_injector` plugin over `opts_json` and merge their payloads
    /// by concatenating each `Vec` field. Plugins that trap are logged at warn and skip
    /// the merge entirely.
    pub fn evaluate_runtime_injector(&mut self, opts_json: &[u8]) -> InjectorPayload {
        let mut merged = InjectorPayload::default();
        for p in self.plugins.iter_mut() {
            if !p.hooks().iter().any(|h| h == "runtime_injector") || !p.has_runtime_injector {
                continue;
            }
            let name = p.name().to_string();
            match loader::evaluate_runtime_injector(p, opts_json) {
                Ok(payload) => merged.extend_from(payload),
                Err(e) => {
                    warn!(
                        plugin = %name,
                        error = %e,
                        "plugin trap during runtime_injector; skipping"
                    );
                }
            }
        }
        merged
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_registry_evaluates_to_no_decisions() {
        let mut reg = PluginRegistry::new().expect("registry");
        let out = reg.evaluate_approval(b"{}");
        assert!(out.is_empty());
        assert_eq!(reg.len(), 0);
        assert!(reg.is_empty());
    }

    #[test]
    fn empty_registry_audit_filter_forwards_unchanged() {
        let mut reg = PluginRegistry::new().expect("registry");
        let res = reg.evaluate_audit_filter(b"{\"k\":\"v\"}");
        assert_eq!(res.outcome, FilterDecision::Forward);
        assert_eq!(res.payload, b"{\"k\":\"v\"}");
        assert!(res.steps.is_empty());
    }

    #[test]
    fn empty_registry_profile_validator_returns_empty() {
        let mut reg = PluginRegistry::new().expect("registry");
        let out = reg.evaluate_profile_validator("version: 1\nname: x");
        assert!(out.is_empty());
    }

    #[test]
    fn engine_handle_is_accessible() {
        let reg = PluginRegistry::new().expect("registry");
        let _ = reg.engine();
    }

    // ---------- Phase 13: network_trace + runtime_injector chain tests ----------

    /// `evaluate_network_trace` recording a fixed code, then returning. `code` is the
    /// integer baked into the wasm at module compile time.
    fn network_wat(code: i32) -> String {
        format!(
            r#"
            (module
              (import "linpodx_host" "host_return_network_decision" (func $rnd (param i32 i32 i32)))
              (memory (export "memory") 1)
              (func (export "evaluate_network_trace")
                (call $rnd (i32.const {code}) (i32.const 0) (i32.const 0))))
            "#
        )
    }

    /// `evaluate_runtime_injector` writing a fixed JSON `InjectorPayload` then returning.
    /// The JSON is placed at offset 1024 in linear memory and its byte length is recorded
    /// at the call site.
    fn injector_wat(json: &str) -> String {
        let escaped = json.replace('\\', "\\\\").replace('"', "\\\"");
        let len = json.len();
        format!(
            r#"
            (module
              (import "linpodx_host" "host_return_injector_payload" (func $rip (param i32 i32)))
              (memory (export "memory") 1)
              (data (i32.const 1024) "{escaped}")
              (func (export "evaluate_runtime_injector")
                (call $rip (i32.const 1024) (i32.const {len}))))
            "#
        )
    }

    fn install_plugin(name: &str, hook: &str, wat_src: &str) -> (tempfile::TempDir, PluginSpec) {
        let dir = tempfile::tempdir().expect("tempdir");
        let wasm_filename = format!("{}.wasm", name.replace('-', "_"));
        let wasm_bytes = wat::parse_str(wat_src).expect("compile wat");
        std::fs::write(dir.path().join(&wasm_filename), wasm_bytes).expect("write wasm");
        let manifest_body = format!(
            "name = \"{name}\"\nversion = \"0.1.0\"\nhooks = [\"{hook}\"]\nwasm = \"{wasm_filename}\"\n",
        );
        std::fs::write(dir.path().join("linpodx-plugin.toml"), manifest_body).expect("write toml");
        let (manifest, wasm_abs) = crate::parse_from_dir(dir.path()).expect("parse_from_dir");
        let spec = PluginSpec {
            manifest,
            wasm_path: wasm_abs,
        };
        (dir, spec)
    }

    fn sample_event() -> NetworkTraceEvent {
        NetworkTraceEvent {
            kind: "dns_query".into(),
            host: "example.com".into(),
            port: None,
        }
    }

    #[test]
    fn network_trace_chain_returns_allow_when_no_plugins() {
        let mut reg = PluginRegistry::new().expect("registry");
        assert_eq!(
            reg.evaluate_network_trace(&sample_event()),
            NetworkDecision::Allow
        );
    }

    #[test]
    fn network_trace_chain_audit_only_wins_over_allow() {
        let mut reg = PluginRegistry::new().expect("registry");
        let (_d1, s1) = install_plugin("net-allow", "network_trace", &network_wat(0));
        let (_d2, s2) = install_plugin("net-audit", "network_trace", &network_wat(2));
        reg.load_all(&[s1, s2]);
        assert_eq!(
            reg.evaluate_network_trace(&sample_event()),
            NetworkDecision::AuditOnly
        );
    }

    #[test]
    fn network_trace_chain_deny_wins_regardless_of_position() {
        let mut reg = PluginRegistry::new().expect("registry");
        let (_d1, s1) = install_plugin("net-audit", "network_trace", &network_wat(2));
        let (_d2, s2) = install_plugin("net-deny", "network_trace", &network_wat(1));
        let (_d3, s3) = install_plugin("net-allow", "network_trace", &network_wat(0));
        reg.load_all(&[s1, s2, s3]);
        assert_eq!(
            reg.evaluate_network_trace(&sample_event()),
            NetworkDecision::Deny
        );
    }

    #[test]
    fn runtime_injector_chain_empty_returns_default() {
        let mut reg = PluginRegistry::new().expect("registry");
        let payload = reg.evaluate_runtime_injector(b"{}");
        assert!(payload.is_empty());
    }

    #[test]
    fn runtime_injector_chain_merges_multi_plugin_payloads() {
        let mut reg = PluginRegistry::new().expect("registry");
        let p1_json =
            r#"{"env_add":[["A","1"]],"args_append":["--x"],"security_opts_add":["seccomp=foo"]}"#;
        let p2_json = r#"{"env_add":[["B","2"]],"args_append":["--y"],"security_opts_add":["label=type:bar"]}"#;
        let (_d1, s1) = install_plugin("inj-1", "runtime_injector", &injector_wat(p1_json));
        let (_d2, s2) = install_plugin("inj-2", "runtime_injector", &injector_wat(p2_json));
        reg.load_all(&[s1, s2]);
        let merged = reg.evaluate_runtime_injector(b"{}");
        assert_eq!(merged.env_add.len(), 2);
        assert_eq!(
            merged.args_append,
            vec!["--x".to_string(), "--y".to_string()]
        );
        assert_eq!(merged.security_opts_add.len(), 2);
    }

    #[test]
    fn runtime_injector_chain_skips_plugins_without_hook() {
        // A plugin that only exports network_trace must not be picked up by the injector
        // chain even if it happens to be loaded.
        let mut reg = PluginRegistry::new().expect("registry");
        let (_d, s) = install_plugin("net-only", "network_trace", &network_wat(0));
        reg.load_all(&[s]);
        let merged = reg.evaluate_runtime_injector(b"{}");
        assert!(merged.is_empty());
    }
}
