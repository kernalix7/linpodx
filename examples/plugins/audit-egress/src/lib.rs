//! Sample linpodx `network_trace` plugin.
//!
//! Receives every observed network event (DNS query / TCP connect / UDP send) the
//! runtime sees, logs the `host:port` via `host_log`, and unconditionally returns
//! `AuditOnly` so the runtime keeps doing whatever it would have done — this plugin
//! only observes, it never blocks.
//!
//! Decision codes (must match `host_return_network_decision_impl` in linpodx-plugin):
//!   * 0 = Allow
//!   * 1 = Deny
//!   * 2 = AuditOnly
//!
//! `unsafe` is required to talk to the host across `extern "C"` and raw pointer math
//! against linear memory.
#![allow(unsafe_code)]

extern "C" {
    fn host_log(level: i32, ptr: i32, len: i32);
    fn host_get_payload(ptr: i32, max: i32) -> i32;
    fn host_return_network_decision(decision: i32, reason_ptr: i32, reason_len: i32);
}

const AUDIT_ONLY: i32 = 2;

fn log(msg: &str) {
    let bytes = msg.as_bytes();
    unsafe {
        host_log(1, bytes.as_ptr() as i32, bytes.len() as i32);
    }
}

fn return_decision(decision: i32, reason: &str) {
    let bytes = reason.as_bytes();
    unsafe {
        host_return_network_decision(decision, bytes.as_ptr() as i32, bytes.len() as i32);
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

/// Extract the value of a JSON string key — `"name":"value"` → `Some("value")`. Tiny
/// hand-rolled parser so the wasm artifact stays under 50 KB; for real plugins prefer a
/// proper JSON parser like `serde_json` (the cdylib will grow but functionality is
/// identical).
fn extract_string(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let i = json.find(&needle)?;
    let rest = &json[i + needle.len()..];
    let after_colon = rest.find(':')?;
    let after = &rest[after_colon + 1..];
    let q1 = after.find('"')?;
    let after_q1 = &after[q1 + 1..];
    let q2 = after_q1.find('"')?;
    Some(after_q1[..q2].to_string())
}

/// Extract the value of a JSON numeric key — `"port":443` → `Some(443)`. Returns None
/// for null / missing / non-numeric. Same caveat as `extract_string`.
fn extract_number(json: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\"");
    let i = json.find(&needle)?;
    let rest = &json[i + needle.len()..];
    let after_colon = rest.find(':')?;
    let after = rest[after_colon + 1..].trim_start();
    let mut end = 0;
    for (idx, c) in after.char_indices() {
        if c.is_ascii_digit() {
            end = idx + c.len_utf8();
        } else {
            break;
        }
    }
    if end == 0 {
        return None;
    }
    after[..end].parse().ok()
}

#[no_mangle]
pub extern "C" fn evaluate_network_trace() {
    let payload = read_payload();
    let body = match std::str::from_utf8(&payload) {
        Ok(s) => s,
        Err(_) => {
            log("audit-egress: non-utf8 payload, audit-only");
            return_decision(AUDIT_ONLY, "non-utf8");
            return;
        }
    };
    let kind = extract_string(body, "kind").unwrap_or_else(|| "unknown".into());
    let host = extract_string(body, "host").unwrap_or_else(|| "unknown".into());
    let port = extract_number(body, "port");
    let line = match port {
        Some(p) => format!("audit-egress: {kind} {host}:{p}"),
        None => format!("audit-egress: {kind} {host}"),
    };
    log(&line);
    return_decision(AUDIT_ONLY, "observed");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_string_finds_quoted_value() {
        let body = r#"{"kind":"dns_query","host":"example.com","port":null}"#;
        assert_eq!(extract_string(body, "kind").as_deref(), Some("dns_query"));
        assert_eq!(extract_string(body, "host").as_deref(), Some("example.com"));
        assert!(extract_string(body, "missing").is_none());
    }

    #[test]
    fn extract_number_finds_numeric_value() {
        let body = r#"{"port":443}"#;
        assert_eq!(extract_number(body, "port"), Some(443));
        assert!(extract_number(body, "missing").is_none());
    }

    #[test]
    fn extract_number_returns_none_for_null() {
        let body = r#"{"port":null}"#;
        assert_eq!(extract_number(body, "port"), None);
    }
}
