//! Sample linpodx approval-rule plugin.
//!
//! Decides on every approval request the host hands it. The decision policy is
//! deliberately simple: if the request category JSON contains the substring "mount"
//! return Allow with a short reason; otherwise return Defer (no opinion).
//!
//! Plugins are wasm32-unknown-unknown cdylibs. We talk to the host via three imported
//! functions (the linpodx host ABI):
//!   * host_log(level, ptr, len) — emit a tracing event
//!   * host_get_payload(ptr, max) -> i32 — copy the request payload bytes into wasm
//!     memory; returns required length when `max` is too small.
//!   * host_return_decision(decision, reason_ptr, reason_len) — record the decision.
//!     decision: 0 = Defer, 1 = Allow, 2 = Deny.
//!
//! `unsafe` is required to use `extern "C"` and raw pointer math against linear memory
//! — every linpodx plugin needs this. The host code itself has #![forbid(unsafe_code)].
#![allow(unsafe_code)]

extern "C" {
    fn host_log(level: i32, ptr: i32, len: i32);
    fn host_get_payload(ptr: i32, max: i32) -> i32;
    fn host_return_decision(decision: i32, reason_ptr: i32, reason_len: i32);
}

const ALLOW: i32 = 1;
const DEFER: i32 = 0;

fn log(msg: &str) {
    let bytes = msg.as_bytes();
    unsafe {
        host_log(1, bytes.as_ptr() as i32, bytes.len() as i32);
    }
}

fn return_decision(decision: i32, reason: &str) {
    let bytes = reason.as_bytes();
    unsafe {
        host_return_decision(decision, bytes.as_ptr() as i32, bytes.len() as i32);
    }
}

fn read_payload() -> Vec<u8> {
    let needed = unsafe { host_get_payload(0, 0) };
    if needed <= 0 {
        return Vec::new();
    }
    let mut buf = vec![0u8; needed as usize];
    let copied = unsafe { host_get_payload(buf.as_mut_ptr() as i32, needed) };
    if copied < 0 {
        return Vec::new();
    }
    buf.truncate(copied as usize);
    buf
}

#[no_mangle]
pub extern "C" fn evaluate_approval() {
    let payload = read_payload();
    log(&format!("auto-allow-mount: payload {} bytes", payload.len()));

    let body = match std::str::from_utf8(&payload) {
        Ok(s) => s,
        Err(_) => {
            return_decision(DEFER, "non-utf8 payload");
            return;
        }
    };

    if body.contains("mount") {
        return_decision(ALLOW, "auto-allow-mount: matched 'mount' substring");
    } else {
        return_decision(DEFER, "auto-allow-mount: no opinion");
    }
}
