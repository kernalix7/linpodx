//! Wasmtime-backed plugin loader.
//!
//! A [`LoadedPlugin`] owns its `Store<HostState>` + `Instance` plus typed handles to the
//! optional entry exports — `evaluate_approval`, `evaluate_audit_filter`,
//! `evaluate_profile_validator`. Each evaluation resets the host state, then calls the
//! relevant wasm function. The plugin reads the payload via `host_get_payload` and writes
//! its decision back via the matching `host_return_*` helper.

use crate::host_api::{
    host_get_payload_impl, host_log_impl, host_return_decision_impl,
    host_return_filter_decision_impl, host_return_injector_payload_impl,
    host_return_network_decision_impl, host_return_payload_impl,
    host_return_validator_decision_impl, HostState,
};
use crate::manifest::PluginManifest;
use crate::{
    FilterDecision, InjectorPayload, NetworkDecision, NetworkTraceEvent, PluginDecision,
    PluginError, Result, ValidatorDecision,
};
use std::path::Path;
use wasmtime::{Engine, Instance, Linker, Module, Store, TypedFunc};

const HOST_NAMESPACE: &str = "linpodx_host";

/// Per-invocation fuel budget. wasmtime charges roughly one fuel unit per executed wasm
/// instruction, so 200M units bounds a runaway or infinite-loop plugin to a few tens of
/// milliseconds of CPU on modern hardware while leaving enormous headroom for legitimate
/// policy plugins (which run on the order of thousands of instructions per call). The
/// budget is re-armed before every host entry point, so it is a per-call — not
/// per-lifetime — ceiling. Requires `Config::consume_fuel(true)` (set in the registry).
pub(crate) const CALL_FUEL_BUDGET: u64 = 200_000_000;

const ENTRY_APPROVAL: &str = "evaluate_approval";
const ENTRY_AUDIT_FILTER: &str = "evaluate_audit_filter";
const ENTRY_PROFILE_VALIDATOR: &str = "evaluate_profile_validator";
const ENTRY_NETWORK_TRACE: &str = "evaluate_network_trace";
const ENTRY_RUNTIME_INJECTOR: &str = "evaluate_runtime_injector";

pub struct LoadedPlugin {
    pub name: String,
    pub version: String,
    pub hooks: Vec<String>,
    pub has_approval: bool,
    pub has_audit_filter: bool,
    pub has_profile_validator: bool,
    pub has_network_trace: bool,
    pub has_runtime_injector: bool,
    store: Store<HostState>,
    instance: Instance,
    entry_approval: Option<TypedFunc<(), ()>>,
    entry_audit_filter: Option<TypedFunc<(), ()>>,
    entry_profile_validator: Option<TypedFunc<(), ()>>,
    entry_network_trace: Option<TypedFunc<(), ()>>,
    entry_runtime_injector: Option<TypedFunc<(), ()>>,
}

impl LoadedPlugin {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn hooks(&self) -> &[String] {
        &self.hooks
    }
}

pub fn load(engine: &Engine, manifest: &PluginManifest, wasm_path: &Path) -> Result<LoadedPlugin> {
    let module = Module::from_file(engine, wasm_path)
        .map_err(|e| PluginError::WasmLoad(format!("{}: {e}", wasm_path.display())))?;
    let mut linker: Linker<HostState> = Linker::new(engine);
    linker
        .func_wrap(HOST_NAMESPACE, "host_log", host_log_impl)
        .map_err(|e| PluginError::WasmLoad(format!("link host_log: {e}")))?;
    linker
        .func_wrap(HOST_NAMESPACE, "host_get_payload", host_get_payload_impl)
        .map_err(|e| PluginError::WasmLoad(format!("link host_get_payload: {e}")))?;
    linker
        .func_wrap(
            HOST_NAMESPACE,
            "host_return_decision",
            host_return_decision_impl,
        )
        .map_err(|e| PluginError::WasmLoad(format!("link host_return_decision: {e}")))?;
    linker
        .func_wrap(
            HOST_NAMESPACE,
            "host_return_payload",
            host_return_payload_impl,
        )
        .map_err(|e| PluginError::WasmLoad(format!("link host_return_payload: {e}")))?;
    linker
        .func_wrap(
            HOST_NAMESPACE,
            "host_return_filter_decision",
            host_return_filter_decision_impl,
        )
        .map_err(|e| PluginError::WasmLoad(format!("link host_return_filter_decision: {e}")))?;
    linker
        .func_wrap(
            HOST_NAMESPACE,
            "host_return_validator_decision",
            host_return_validator_decision_impl,
        )
        .map_err(|e| PluginError::WasmLoad(format!("link host_return_validator_decision: {e}")))?;
    linker
        .func_wrap(
            HOST_NAMESPACE,
            "host_return_network_decision",
            host_return_network_decision_impl,
        )
        .map_err(|e| PluginError::WasmLoad(format!("link host_return_network_decision: {e}")))?;
    linker
        .func_wrap(
            HOST_NAMESPACE,
            "host_return_injector_payload",
            host_return_injector_payload_impl,
        )
        .map_err(|e| PluginError::WasmLoad(format!("link host_return_injector_payload: {e}")))?;

    let mut store = Store::new(engine, HostState::new(manifest.name.clone()));
    // Apply the per-store memory/table/instance caps (HostState::limits). Must be wired
    // before instantiation so an over-cap declared minimum memory is rejected up front.
    store.limiter(|state| &mut state.limits);
    // Arm the fuel budget before instantiation so a module with a start function that
    // loops can never hang the daemon at load time.
    store
        .set_fuel(CALL_FUEL_BUDGET)
        .map_err(|e| PluginError::WasmLoad(format!("set fuel for {}: {e}", manifest.name)))?;
    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| PluginError::WasmLoad(format!("instantiate {}: {e}", manifest.name)))?;

    let entry_approval = instance
        .get_typed_func::<(), ()>(&mut store, ENTRY_APPROVAL)
        .ok();
    let entry_audit_filter = instance
        .get_typed_func::<(), ()>(&mut store, ENTRY_AUDIT_FILTER)
        .ok();
    let entry_profile_validator = instance
        .get_typed_func::<(), ()>(&mut store, ENTRY_PROFILE_VALIDATOR)
        .ok();
    let entry_network_trace = instance
        .get_typed_func::<(), ()>(&mut store, ENTRY_NETWORK_TRACE)
        .ok();
    let entry_runtime_injector = instance
        .get_typed_func::<(), ()>(&mut store, ENTRY_RUNTIME_INJECTOR)
        .ok();

    if entry_approval.is_none()
        && entry_audit_filter.is_none()
        && entry_profile_validator.is_none()
        && entry_network_trace.is_none()
        && entry_runtime_injector.is_none()
    {
        return Err(PluginError::WasmLoad(format!(
            "plugin {} exports none of the supported entries (evaluate_approval, \
             evaluate_audit_filter, evaluate_profile_validator, evaluate_network_trace, \
             evaluate_runtime_injector)",
            manifest.name
        )));
    }

    Ok(LoadedPlugin {
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        hooks: manifest.hooks.clone(),
        has_approval: entry_approval.is_some(),
        has_audit_filter: entry_audit_filter.is_some(),
        has_profile_validator: entry_profile_validator.is_some(),
        has_network_trace: entry_network_trace.is_some(),
        has_runtime_injector: entry_runtime_injector.is_some(),
        store,
        instance,
        entry_approval,
        entry_audit_filter,
        entry_profile_validator,
        entry_network_trace,
        entry_runtime_injector,
    })
}

/// Re-arm the per-call fuel budget before invoking a plugin export. Fuel is consumed as
/// wasm executes, so it must be reset before every call or a plugin that ran near the
/// budget last time would trap prematurely. A fuel-exhaustion trap during the subsequent
/// `.call` surfaces as [`PluginError::HostRejected`], which callers treat as trap-like
/// (Defer / skip) — never poisoning the registry for other plugins.
fn arm_fuel(plugin: &mut LoadedPlugin) -> Result<()> {
    plugin
        .store
        .set_fuel(CALL_FUEL_BUDGET)
        .map_err(|e| PluginError::HostRejected(format!("plugin {}: arm fuel: {e}", plugin.name)))
}

/// Run the `evaluate_approval` export with `payload` (typically a serialized
/// `ApprovalRequest`) and return the (decision, reason) the plugin recorded. Returns a
/// `WasmLoad` error if the plugin doesn't export this entry — call `has_approval` first.
pub fn evaluate(plugin: &mut LoadedPlugin, payload: &[u8]) -> Result<(PluginDecision, String)> {
    let entry = plugin.entry_approval.clone().ok_or_else(|| {
        PluginError::WasmLoad(format!(
            "plugin {} has no evaluate_approval export",
            plugin.name
        ))
    })?;
    plugin.store.data_mut().reset(payload.to_vec());
    arm_fuel(plugin)?;
    entry
        .call(&mut plugin.store, ())
        .map_err(|e| PluginError::HostRejected(format!("plugin {}: {e}", plugin.name)))?;
    Ok(plugin.store.data().take_decision())
}

/// Run the `evaluate_audit_filter` export with `payload` (raw audit-entry bytes — usually a
/// JSON-serialized payload). Returns `Forward`/`Drop`/`Transform`. Plugins that lack the
/// export return a `WasmLoad` error; the registry filters them out so end users never see
/// it.
pub fn evaluate_audit_filter(plugin: &mut LoadedPlugin, payload: &[u8]) -> Result<FilterDecision> {
    let entry = plugin.entry_audit_filter.clone().ok_or_else(|| {
        PluginError::WasmLoad(format!(
            "plugin {} has no evaluate_audit_filter export",
            plugin.name
        ))
    })?;
    plugin.store.data_mut().reset(payload.to_vec());
    arm_fuel(plugin)?;
    entry
        .call(&mut plugin.store, ())
        .map_err(|e| PluginError::HostRejected(format!("plugin {}: {e}", plugin.name)))?;
    let (raw, _reason, transformed) = plugin.store.data().take_filter_outputs();
    Ok(match raw {
        1 => FilterDecision::Drop,
        2 => match transformed {
            Some(p) => FilterDecision::Transform { payload: p },
            // Plugin asked for Transform but never wrote a payload — fall back to Forward
            // so a buggy plugin can never erase the audit entry by accident.
            None => FilterDecision::Forward,
        },
        _ => FilterDecision::Forward,
    })
}

/// Run the `evaluate_profile_validator` export with `yaml` (the profile's raw YAML body).
/// Returns `Pass` or `Reject { reason }` — the reason flows into the
/// `ProfileValidatorRejected` audit entry so operators can see *why* a profile was
/// rejected.
pub fn evaluate_profile_validator(
    plugin: &mut LoadedPlugin,
    yaml: &str,
) -> Result<ValidatorDecision> {
    let entry = plugin.entry_profile_validator.clone().ok_or_else(|| {
        PluginError::WasmLoad(format!(
            "plugin {} has no evaluate_profile_validator export",
            plugin.name
        ))
    })?;
    plugin.store.data_mut().reset(yaml.as_bytes().to_vec());
    arm_fuel(plugin)?;
    entry
        .call(&mut plugin.store, ())
        .map_err(|e| PluginError::HostRejected(format!("plugin {}: {e}", plugin.name)))?;
    let (raw, reason) = plugin.store.data().take_validator_outputs();
    Ok(match raw {
        1 => ValidatorDecision::Reject { reason },
        _ => ValidatorDecision::Pass,
    })
}

/// Run the `evaluate_network_trace` export with `event` (JSON-serialized
/// [`NetworkTraceEvent`]) and return the [`NetworkDecision`] the plugin recorded. The
/// runtime egress filter calls this for each observed DNS query / connect / send.
pub fn evaluate_network_trace(
    plugin: &mut LoadedPlugin,
    event: &NetworkTraceEvent,
) -> Result<NetworkDecision> {
    let entry = plugin.entry_network_trace.clone().ok_or_else(|| {
        PluginError::WasmLoad(format!(
            "plugin {} has no evaluate_network_trace export",
            plugin.name
        ))
    })?;
    let payload = serde_json::to_vec(event)
        .map_err(|e| PluginError::HostRejected(format!("serialize network event: {e}")))?;
    plugin.store.data_mut().reset(payload);
    arm_fuel(plugin)?;
    entry
        .call(&mut plugin.store, ())
        .map_err(|e| PluginError::HostRejected(format!("plugin {}: {e}", plugin.name)))?;
    let (d, _reason) = plugin.store.data().take_network_outputs();
    Ok(d)
}

/// Run the `evaluate_runtime_injector` export with `opts_json` (the JSON-encoded
/// `CreateOptions` the daemon is about to hand to podman) and return the
/// [`InjectorPayload`] the plugin recorded. Plugins that record nothing return
/// `InjectorPayload::default()`.
pub fn evaluate_runtime_injector(
    plugin: &mut LoadedPlugin,
    opts_json: &[u8],
) -> Result<InjectorPayload> {
    let entry = plugin.entry_runtime_injector.clone().ok_or_else(|| {
        PluginError::WasmLoad(format!(
            "plugin {} has no evaluate_runtime_injector export",
            plugin.name
        ))
    })?;
    plugin.store.data_mut().reset(opts_json.to_vec());
    arm_fuel(plugin)?;
    entry
        .call(&mut plugin.store, ())
        .map_err(|e| PluginError::HostRejected(format!("plugin {}: {e}", plugin.name)))?;
    Ok(plugin
        .store
        .data()
        .take_injector_payload()
        .unwrap_or_default())
}

/// Borrow the wasm `Instance` (used by tests / introspection only). Most callers
/// should not need this.
pub fn instance(plugin: &LoadedPlugin) -> &Instance {
    &plugin.instance
}

#[cfg(test)]
mod tests {
    use wasmtime::{Config, Engine};

    #[test]
    fn engine_creation_succeeds() {
        let cfg = Config::new();
        let engine = Engine::new(&cfg).expect("engine");
        let _ = engine;
    }
}
