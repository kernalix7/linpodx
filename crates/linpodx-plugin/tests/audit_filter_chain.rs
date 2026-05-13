//! Integration tests for the `audit_filter` and `profile_validator` plugin chains.
//!
//! Each test compiles a small WAT module on the fly, writes it to a tempfile, parses a
//! matching `linpodx-plugin.toml`, then loads it into a real `PluginRegistry` and runs
//! the chain. This exercises the full host ABI surface (`host_get_payload`,
//! `host_return_payload`, `host_return_filter_decision`,
//! `host_return_validator_decision`) end-to-end without needing a wasm32 toolchain in CI.
//!
//! NB: addresses inside the WAT modules use the raw payload at offset 0 (the host writes
//! the request bytes there before each call) and any constants/output buffers at
//! offsets ≥ 1024 to keep them out of harm's way.

use linpodx_plugin::{
    parse_from_dir, FilterDecision, PluginManifest, PluginRegistry, ValidatorDecision,
};

const FORWARD_WAT: &str = r#"
(module
  (import "linpodx_host" "host_return_filter_decision" (func $ret (param i32 i32 i32)))
  (memory (export "memory") 1)
  (func (export "evaluate_audit_filter")
    (call $ret (i32.const 0) (i32.const 0) (i32.const 0))))
"#;

const DROP_WAT: &str = r#"
(module
  (import "linpodx_host" "host_return_filter_decision" (func $ret (param i32 i32 i32)))
  (memory (export "memory") 1)
  (func (export "evaluate_audit_filter")
    (call $ret (i32.const 1) (i32.const 0) (i32.const 0))))
"#;

// Transform plugin: writes the byte sequence "REPLACED" at offset 1024, then calls
// host_return_payload(1024, 8) followed by host_return_filter_decision(2, ...).
const TRANSFORM_WAT: &str = r#"
(module
  (import "linpodx_host" "host_return_payload" (func $rp (param i32 i32)))
  (import "linpodx_host" "host_return_filter_decision" (func $rfd (param i32 i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 1024) "REPLACED")
  (func (export "evaluate_audit_filter")
    (call $rp (i32.const 1024) (i32.const 8))
    (call $rfd (i32.const 2) (i32.const 0) (i32.const 0))))
"#;

const VALIDATOR_PASS_WAT: &str = r#"
(module
  (import "linpodx_host" "host_return_validator_decision" (func $ret (param i32 i32 i32)))
  (memory (export "memory") 1)
  (func (export "evaluate_profile_validator")
    (call $ret (i32.const 0) (i32.const 0) (i32.const 0))))
"#;

// Validator reject plugin: writes the reason "nope" at offset 1024 and rejects.
const VALIDATOR_REJECT_WAT: &str = r#"
(module
  (import "linpodx_host" "host_return_validator_decision" (func $ret (param i32 i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 1024) "nope")
  (func (export "evaluate_profile_validator")
    (call $ret (i32.const 1) (i32.const 1024) (i32.const 4))))
"#;

fn install(
    name: &str,
    hook: &str,
    entry: &str,
    wat: &str,
) -> (tempfile::TempDir, PluginManifest, std::path::PathBuf) {
    let _ = entry; // kept for future use
    let dir = tempfile::tempdir().expect("tempdir");
    let wasm_filename = format!("{}.wasm", name.replace('-', "_"));
    let wasm_bytes = wat::parse_str(wat).expect("compile WAT");
    std::fs::write(dir.path().join(&wasm_filename), wasm_bytes).expect("write wasm");
    let manifest_body = format!(
        "name = \"{name}\"\nversion = \"0.1.0\"\nhooks = [\"{hook}\"]\nwasm = \"{wasm_filename}\"\n",
    );
    std::fs::write(dir.path().join("linpodx-plugin.toml"), manifest_body).expect("write toml");
    let (manifest, wasm_abs) = parse_from_dir(dir.path()).expect("parse_from_dir");
    (dir, manifest, wasm_abs)
}

#[test]
fn audit_filter_forward_only_returns_original_payload() {
    let mut reg = PluginRegistry::new().expect("registry");
    let (_d, m, w) = install(
        "p-fwd",
        "audit_filter",
        "evaluate_audit_filter",
        FORWARD_WAT,
    );
    reg.load_one(&m, &w).expect("load");

    let res = reg.evaluate_audit_filter(b"{\"k\":1}");
    assert_eq!(res.outcome, FilterDecision::Forward);
    assert_eq!(res.payload, b"{\"k\":1}");
    assert_eq!(res.steps.len(), 1);
}

#[test]
fn audit_filter_transform_rewrites_payload_for_next_plugin() {
    let mut reg = PluginRegistry::new().expect("registry");
    let (_d1, m1, w1) = install(
        "p-xform",
        "audit_filter",
        "evaluate_audit_filter",
        TRANSFORM_WAT,
    );
    let (_d2, m2, w2) = install(
        "p-fwd2",
        "audit_filter",
        "evaluate_audit_filter",
        FORWARD_WAT,
    );
    reg.load_one(&m1, &w1).expect("load xform");
    reg.load_one(&m2, &w2).expect("load fwd");

    let res = reg.evaluate_audit_filter(b"{\"orig\":true}");
    assert_eq!(res.outcome, FilterDecision::Forward);
    // Transform happened first, then forward was a no-op on the new payload.
    assert_eq!(res.payload, b"REPLACED");
    assert_eq!(res.steps.len(), 2);
    assert!(matches!(res.steps[0].1, FilterDecision::Transform { .. }));
    assert!(matches!(res.steps[1].1, FilterDecision::Forward));
}

#[test]
fn audit_filter_drop_short_circuits_chain() {
    let mut reg = PluginRegistry::new().expect("registry");
    let (_d1, m1, w1) = install("p-drop", "audit_filter", "evaluate_audit_filter", DROP_WAT);
    let (_d2, m2, w2) = install(
        "p-after-drop",
        "audit_filter",
        "evaluate_audit_filter",
        TRANSFORM_WAT,
    );
    reg.load_one(&m1, &w1).expect("load drop");
    reg.load_one(&m2, &w2).expect("load xform");

    let res = reg.evaluate_audit_filter(b"{\"orig\":true}");
    assert_eq!(res.outcome, FilterDecision::Drop);
    // After Drop the chain stops — the second plugin must not have executed.
    assert_eq!(res.steps.len(), 1);
}

#[test]
fn profile_validator_pass_records_outcome_per_plugin() {
    let mut reg = PluginRegistry::new().expect("registry");
    let (_d, m, w) = install(
        "v-pass",
        "profile_validator",
        "evaluate_profile_validator",
        VALIDATOR_PASS_WAT,
    );
    reg.load_one(&m, &w).expect("load");

    let out = reg.evaluate_profile_validator("version: 1\nname: ok\n");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0, "v-pass");
    assert_eq!(out[0].1, ValidatorDecision::Pass);
}

#[test]
fn profile_validator_reject_carries_reason() {
    let mut reg = PluginRegistry::new().expect("registry");
    let (_d1, m1, w1) = install(
        "v-pass",
        "profile_validator",
        "evaluate_profile_validator",
        VALIDATOR_PASS_WAT,
    );
    let (_d2, m2, w2) = install(
        "v-reject",
        "profile_validator",
        "evaluate_profile_validator",
        VALIDATOR_REJECT_WAT,
    );
    reg.load_one(&m1, &w1).expect("load pass");
    reg.load_one(&m2, &w2).expect("load reject");

    let out = reg.evaluate_profile_validator("version: 1\nname: x\n");
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].1, ValidatorDecision::Pass);
    match &out[1].1 {
        ValidatorDecision::Reject { reason } => assert_eq!(reason, "nope"),
        other => panic!("expected Reject, got {other:?}"),
    }
}

#[test]
fn audit_filter_chain_with_zero_audit_plugins_forwards_unchanged() {
    let mut reg = PluginRegistry::new().expect("registry");
    // Load only a profile_validator plugin — the audit_filter chain must still be a no-op.
    let (_d, m, w) = install(
        "v-only",
        "profile_validator",
        "evaluate_profile_validator",
        VALIDATOR_PASS_WAT,
    );
    reg.load_one(&m, &w).expect("load");

    let res = reg.evaluate_audit_filter(b"original");
    assert_eq!(res.outcome, FilterDecision::Forward);
    assert_eq!(res.payload, b"original");
    assert!(res.steps.is_empty());
}
