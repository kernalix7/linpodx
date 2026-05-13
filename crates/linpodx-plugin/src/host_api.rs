//! Host functions exposed to wasm plugins.
//!
//! ABI (`linpodx_host` namespace, all functions take/return i32 because wasmtime's
//! `func_wrap` is most ergonomic with primitive types):
//!
//! * `host_log(level: i32, ptr: i32, len: i32) -> ()` — emit a tracing event.
//! * `host_get_payload(ptr: i32, max: i32) -> i32` — copy the request payload bytes
//!   into wasm memory and return the actual length. If `max` is smaller than the
//!   payload the function copies nothing and returns the *required* length so the
//!   plugin can re-allocate.
//! * `host_return_decision(decision: i32, reason_ptr: i32, reason_len: i32) -> ()` —
//!   record the plugin's decision (0=Defer, 1=Allow, 2=Deny) plus a reason string.
//!
//! The state lives in [`HostState`] inside the wasm `Store`. Each call to
//! [`crate::loader::evaluate`] resets `decision`/`reason` so a single LoadedPlugin can
//! be invoked repeatedly.

use crate::{InjectorPayload, NetworkDecision, PluginDecision};
use std::sync::Mutex;
use tracing::{debug, error, info, warn};

/// Per-invocation host state stored inside the wasmtime `Store`. Fields the wasm callbacks
/// mutate go through `std::sync::Mutex` so the whole struct is `Send + Sync` — that lets
/// `Arc<RwLock<PluginRegistry>>` be stored across `.await` points (the registry is still
/// only ever invoked inside `spawn_blocking`; the lock here is for type-system
/// satisfaction, not real contention).
pub struct HostState {
    pub request_payload: Vec<u8>,
    pub decision: Mutex<PluginDecision>,
    pub reason: Mutex<String>,
    /// Raw filter/validator decision code recorded by the latest call to
    /// [`host_return_filter_decision_impl`] / [`host_return_validator_decision_impl`].
    /// Sandbox-side callers map this back into [`crate::FilterDecision`] /
    /// [`crate::ValidatorDecision`].
    pub raw_decision: Mutex<i32>,
    /// Bytes written by the plugin via [`host_return_payload_impl`]. Populated only when
    /// the plugin chooses Transform; otherwise stays `None` and the host falls back to
    /// the original payload.
    pub transformed_payload: Mutex<Option<Vec<u8>>>,
    /// Decision recorded by the latest call to [`host_return_network_decision_impl`]. The
    /// runtime egress filter resets to `Allow` before each `evaluate_network_trace` call.
    pub network_decision: Mutex<NetworkDecision>,
    /// JSON-encoded `InjectorPayload` recorded by the latest call to
    /// [`host_return_injector_payload_impl`]. Daemon-side `evaluate_runtime_injector` parses
    /// it back into [`crate::InjectorPayload`]. `None` means "plugin returned no payload"
    /// — treated as the empty payload.
    pub injector_payload: Mutex<Option<InjectorPayload>>,
    pub plugin_name: String,
}

impl HostState {
    pub fn new(plugin_name: String) -> Self {
        Self {
            request_payload: Vec::new(),
            decision: Mutex::new(PluginDecision::Defer),
            reason: Mutex::new(String::new()),
            raw_decision: Mutex::new(0),
            transformed_payload: Mutex::new(None),
            network_decision: Mutex::new(NetworkDecision::Allow),
            injector_payload: Mutex::new(None),
            plugin_name,
        }
    }

    pub fn reset(&mut self, payload: Vec<u8>) {
        self.request_payload = payload;
        *self.decision.lock().expect("decision lock poisoned") = PluginDecision::Defer;
        self.reason.lock().expect("reason lock poisoned").clear();
        *self
            .raw_decision
            .lock()
            .expect("raw_decision lock poisoned") = 0;
        *self
            .transformed_payload
            .lock()
            .expect("transformed_payload lock poisoned") = None;
        *self
            .network_decision
            .lock()
            .expect("network_decision lock poisoned") = NetworkDecision::Allow;
        *self
            .injector_payload
            .lock()
            .expect("injector_payload lock poisoned") = None;
    }

    pub fn take_decision(&self) -> (PluginDecision, String) {
        let d = *self.decision.lock().expect("decision lock poisoned");
        let r = self.reason.lock().expect("reason lock poisoned").clone();
        (d, r)
    }

    pub fn take_filter_outputs(&self) -> (i32, String, Option<Vec<u8>>) {
        let d = *self
            .raw_decision
            .lock()
            .expect("raw_decision lock poisoned");
        let r = self.reason.lock().expect("reason lock poisoned").clone();
        let p = self
            .transformed_payload
            .lock()
            .expect("transformed_payload lock poisoned")
            .take();
        (d, r, p)
    }

    pub fn take_validator_outputs(&self) -> (i32, String) {
        let d = *self
            .raw_decision
            .lock()
            .expect("raw_decision lock poisoned");
        let r = self.reason.lock().expect("reason lock poisoned").clone();
        (d, r)
    }

    /// Returns the (decision, reason) pair recorded by the latest
    /// `host_return_network_decision` call. The default before any call is
    /// (`NetworkDecision::Allow`, "") so a plugin that forgets to record falls back to
    /// "do nothing".
    pub fn take_network_outputs(&self) -> (NetworkDecision, String) {
        let d = *self
            .network_decision
            .lock()
            .expect("network_decision lock poisoned");
        let r = self.reason.lock().expect("reason lock poisoned").clone();
        (d, r)
    }

    /// Returns the `InjectorPayload` recorded by the latest
    /// `host_return_injector_payload` call. `None` means "the plugin did not record one"
    /// and the host treats that as the empty payload.
    pub fn take_injector_payload(&self) -> Option<InjectorPayload> {
        self.injector_payload
            .lock()
            .expect("injector_payload lock poisoned")
            .take()
    }
}

/// Read `len` bytes starting at `ptr` from the linker-default wasm memory exported as
/// `memory`. Returns an empty Vec if anything goes wrong (out-of-range, no memory) so
/// host functions stay infallible from the plugin's perspective.
pub fn read_memory_bytes(
    caller: &mut wasmtime::Caller<'_, HostState>,
    ptr: i32,
    len: i32,
) -> Vec<u8> {
    if len <= 0 {
        return Vec::new();
    }
    let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
        Some(m) => m,
        None => return Vec::new(),
    };
    let data = mem.data(&caller);
    let start = ptr as usize;
    let end = start.saturating_add(len as usize);
    if end > data.len() {
        return Vec::new();
    }
    data[start..end].to_vec()
}

pub fn write_memory_bytes(
    caller: &mut wasmtime::Caller<'_, HostState>,
    ptr: i32,
    bytes: &[u8],
) -> bool {
    let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
        Some(m) => m,
        None => return false,
    };
    let data = mem.data_mut(&mut *caller);
    let start = ptr as usize;
    let end = start.saturating_add(bytes.len());
    if end > data.len() {
        return false;
    }
    data[start..end].copy_from_slice(bytes);
    true
}

/// `host_log(level, ptr, len)` — bridge wasm-emitted strings into the host tracing
/// layer with the plugin name as a structured field.
pub fn host_log_impl(mut caller: wasmtime::Caller<'_, HostState>, level: i32, ptr: i32, len: i32) {
    let bytes = read_memory_bytes(&mut caller, ptr, len);
    let msg = String::from_utf8_lossy(&bytes).into_owned();
    let plugin = caller.data().plugin_name.clone();
    match level {
        0 => debug!(plugin = %plugin, "{msg}"),
        1 => info!(plugin = %plugin, "{msg}"),
        2 => warn!(plugin = %plugin, "{msg}"),
        _ => error!(plugin = %plugin, "{msg}"),
    }
}

/// `host_get_payload(ptr, max) -> i32`. Returns required length when `max` is too small
/// (so the guest can reallocate), otherwise the byte count actually copied.
pub fn host_get_payload_impl(
    mut caller: wasmtime::Caller<'_, HostState>,
    ptr: i32,
    max: i32,
) -> i32 {
    let needed = caller.data().request_payload.len();
    if max < 0 || (needed > max as usize) {
        return needed as i32;
    }
    if needed == 0 {
        return 0;
    }
    let bytes = caller.data().request_payload.clone();
    if write_memory_bytes(&mut caller, ptr, &bytes) {
        bytes.len() as i32
    } else {
        -1
    }
}

/// `host_return_decision(decision, reason_ptr, reason_len)`. `decision` follows
/// `PluginDecision::from_u8` (0=Defer, 1=Allow, 2=Deny). Reason is best-effort UTF-8.
pub fn host_return_decision_impl(
    mut caller: wasmtime::Caller<'_, HostState>,
    decision: i32,
    reason_ptr: i32,
    reason_len: i32,
) {
    let reason_bytes = read_memory_bytes(&mut caller, reason_ptr, reason_len);
    let reason = String::from_utf8_lossy(&reason_bytes).into_owned();
    let mapped = if decision >= 0 && decision <= u8::MAX as i32 {
        PluginDecision::from_u8(decision as u8)
    } else {
        PluginDecision::Defer
    };
    let state = caller.data_mut();
    if let Ok(mut d) = state.decision.lock() {
        *d = mapped;
    }
    if let Ok(mut r) = state.reason.lock() {
        *r = reason;
    }
}

/// `host_return_payload(ptr, len)` — write back a transformed payload (audit_filter only).
/// The plugin calls this *before* `host_return_filter_decision` with a Transform code.
/// Bytes are copied into a fresh Vec stored in `HostState.transformed_payload`. If the
/// pointer/length are invalid the call is a no-op and the host treats the decision as if
/// no transform was attached.
pub fn host_return_payload_impl(mut caller: wasmtime::Caller<'_, HostState>, ptr: i32, len: i32) {
    let bytes = read_memory_bytes(&mut caller, ptr, len);
    if let Ok(mut p) = caller.data_mut().transformed_payload.lock() {
        *p = Some(bytes);
    }
}

/// `host_return_filter_decision(decision, reason_ptr, reason_len)` —
/// `decision`: 0 = Forward, 1 = Drop, 2 = Transform. The reason field is best-effort UTF-8
/// and used for tracing only (never surfaced to end users).
pub fn host_return_filter_decision_impl(
    mut caller: wasmtime::Caller<'_, HostState>,
    decision: i32,
    reason_ptr: i32,
    reason_len: i32,
) {
    let reason_bytes = read_memory_bytes(&mut caller, reason_ptr, reason_len);
    let reason = String::from_utf8_lossy(&reason_bytes).into_owned();
    let state = caller.data_mut();
    if let Ok(mut d) = state.raw_decision.lock() {
        *d = decision;
    }
    if let Ok(mut r) = state.reason.lock() {
        *r = reason;
    }
}

/// `host_return_validator_decision(decision, reason_ptr, reason_len)` —
/// `decision`: 0 = Pass, 1 = Reject. Reason is the user-facing message stored in the audit
/// log when the validator rejects.
pub fn host_return_validator_decision_impl(
    mut caller: wasmtime::Caller<'_, HostState>,
    decision: i32,
    reason_ptr: i32,
    reason_len: i32,
) {
    let reason_bytes = read_memory_bytes(&mut caller, reason_ptr, reason_len);
    let reason = String::from_utf8_lossy(&reason_bytes).into_owned();
    let state = caller.data_mut();
    if let Ok(mut d) = state.raw_decision.lock() {
        *d = decision;
    }
    if let Ok(mut r) = state.reason.lock() {
        *r = reason;
    }
}

/// `host_return_network_decision(decision, reason_ptr, reason_len)` —
/// `decision`: 0 = Allow, 1 = Deny, 2 = AuditOnly. Reason is best-effort UTF-8 and used
/// for tracing only. Out-of-range codes fall back to `Allow` so a buggy plugin can never
/// break egress in the deny direction by accident.
pub fn host_return_network_decision_impl(
    mut caller: wasmtime::Caller<'_, HostState>,
    decision: i32,
    reason_ptr: i32,
    reason_len: i32,
) {
    let reason_bytes = read_memory_bytes(&mut caller, reason_ptr, reason_len);
    let reason = String::from_utf8_lossy(&reason_bytes).into_owned();
    let mapped = NetworkDecision::from_i32(decision);
    let state = caller.data_mut();
    if let Ok(mut d) = state.network_decision.lock() {
        *d = mapped;
    }
    if let Ok(mut r) = state.reason.lock() {
        *r = reason;
    }
}

/// `host_return_injector_payload(ptr, len)` — read JSON-encoded `InjectorPayload` from
/// wasm memory and stash it in `HostState`. Malformed JSON or out-of-range pointers are
/// no-ops (no payload recorded) so a buggy plugin never crashes the daemon.
pub fn host_return_injector_payload_impl(
    mut caller: wasmtime::Caller<'_, HostState>,
    ptr: i32,
    len: i32,
) {
    let bytes = read_memory_bytes(&mut caller, ptr, len);
    if bytes.is_empty() {
        return;
    }
    let parsed: Option<InjectorPayload> = match serde_json::from_slice(&bytes) {
        Ok(p) => Some(p),
        Err(e) => {
            warn!(error = %e, "host_return_injector_payload: malformed JSON, ignoring");
            None
        }
    };
    if let Some(payload) = parsed {
        if let Ok(mut p) = caller.data_mut().injector_payload.lock() {
            *p = Some(payload);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_state_reset_clears_previous_decision() {
        let mut s = HostState::new("p".into());
        *s.decision.lock().unwrap() = PluginDecision::Allow;
        *s.reason.lock().unwrap() = "old".into();
        *s.raw_decision.lock().unwrap() = 7;
        *s.transformed_payload.lock().unwrap() = Some(b"old-payload".to_vec());
        s.reset(b"new".to_vec());
        assert_eq!(s.request_payload, b"new");
        let (d, r) = s.take_decision();
        assert!(matches!(d, PluginDecision::Defer));
        assert!(r.is_empty());
        assert_eq!(*s.raw_decision.lock().unwrap(), 0);
        assert!(s.transformed_payload.lock().unwrap().is_none());
    }

    #[test]
    fn take_filter_outputs_consumes_transformed_payload() {
        let s = HostState::new("p".into());
        *s.raw_decision.lock().unwrap() = 2;
        *s.reason.lock().unwrap() = "transformed".into();
        *s.transformed_payload.lock().unwrap() = Some(b"hello".to_vec());
        let (d, r, p) = s.take_filter_outputs();
        assert_eq!(d, 2);
        assert_eq!(r, "transformed");
        assert_eq!(p.as_deref(), Some(b"hello".as_slice()));
        // Consumed: a second take returns None for the payload.
        let (_, _, p2) = s.take_filter_outputs();
        assert!(p2.is_none());
    }

    #[test]
    fn reset_clears_network_and_injector_state() {
        let mut s = HostState::new("p".into());
        *s.network_decision.lock().unwrap() = NetworkDecision::Deny;
        *s.injector_payload.lock().unwrap() = Some(InjectorPayload {
            env_add: vec![("FOO".into(), "BAR".into())],
            ..Default::default()
        });
        s.reset(b"x".to_vec());
        assert_eq!(*s.network_decision.lock().unwrap(), NetworkDecision::Allow);
        assert!(s.injector_payload.lock().unwrap().is_none());
    }

    #[test]
    fn take_injector_payload_consumes_value() {
        let s = HostState::new("p".into());
        *s.injector_payload.lock().unwrap() = Some(InjectorPayload {
            args_append: vec!["--debug".into()],
            ..Default::default()
        });
        let first = s.take_injector_payload();
        assert!(first.is_some());
        let second = s.take_injector_payload();
        assert!(second.is_none());
    }

    #[test]
    fn network_decision_from_i32_clamps_unknown_to_allow() {
        assert_eq!(NetworkDecision::from_i32(0), NetworkDecision::Allow);
        assert_eq!(NetworkDecision::from_i32(1), NetworkDecision::Deny);
        assert_eq!(NetworkDecision::from_i32(2), NetworkDecision::AuditOnly);
        assert_eq!(NetworkDecision::from_i32(99), NetworkDecision::Allow);
        assert_eq!(NetworkDecision::from_i32(-3), NetworkDecision::Allow);
    }

    #[test]
    fn injector_payload_extend_concats_each_field() {
        let mut a = InjectorPayload {
            env_add: vec![("A".into(), "1".into())],
            args_append: vec!["--x".into()],
            security_opts_add: vec!["seccomp=foo".into()],
        };
        let b = InjectorPayload {
            env_add: vec![("B".into(), "2".into())],
            args_append: vec!["--y".into()],
            security_opts_add: vec!["label=type:bar".into()],
        };
        a.extend_from(b);
        assert_eq!(a.env_add.len(), 2);
        assert_eq!(a.args_append, vec!["--x".to_string(), "--y".to_string()]);
        assert_eq!(a.security_opts_add.len(), 2);
    }
}
