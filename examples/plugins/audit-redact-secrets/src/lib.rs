//! Sample linpodx `audit_filter` plugin.
//!
//! Scans every audit payload (JSON bytes) for substrings that look like sensitive keys
//! (`password`, `token`, `key`, `secret`) and rewrites the value following the next `:`
//! to `"***"`. The match is intentionally simple — the goal is to demonstrate the
//! Transform path of the audit_filter ABI, not to be a production-grade redactor.
//!
//! Decision codes (must match `host_return_filter_decision_impl` in linpodx-plugin):
//!   * 0 = Forward (no change)
//!   * 1 = Drop    (suppress the audit entry entirely)
//!   * 2 = Transform (use the bytes written via `host_return_payload`)
//!
//! `unsafe` is required to talk to the host across `extern "C"` and raw pointer math
//! against linear memory.
#![allow(unsafe_code)]

extern "C" {
    fn host_log(level: i32, ptr: i32, len: i32);
    fn host_get_payload(ptr: i32, max: i32) -> i32;
    fn host_return_payload(ptr: i32, len: i32);
    fn host_return_filter_decision(decision: i32, reason_ptr: i32, reason_len: i32);
}

const FORWARD: i32 = 0;
const TRANSFORM: i32 = 2;

const SECRET_KEYS: &[&str] = &["password", "token", "secret", "api_key", "key"];

fn log(msg: &str) {
    let bytes = msg.as_bytes();
    unsafe {
        host_log(1, bytes.as_ptr() as i32, bytes.len() as i32);
    }
}

fn return_decision(decision: i32, reason: &str) {
    let bytes = reason.as_bytes();
    unsafe {
        host_return_filter_decision(decision, bytes.as_ptr() as i32, bytes.len() as i32);
    }
}

fn return_payload(bytes: &[u8]) {
    unsafe {
        host_return_payload(bytes.as_ptr() as i32, bytes.len() as i32);
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

/// Scan `body` for `"<key>": "<value>"` patterns where `<key>` matches one of
/// [`SECRET_KEYS`] (case-insensitive substring match) and replace the value with `"***"`.
/// Returns the rewritten string + a count of redactions for the log line. Non-string
/// values (numbers, bools, nested objects) are left alone — we only rewrite quoted strings
/// to avoid breaking JSON shape.
fn redact(body: &str) -> (String, usize) {
    let lower = body.to_ascii_lowercase();
    let mut out = String::with_capacity(body.len());
    let mut redactions = 0;
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Look for `"<key>"` then `:` then `"<value>"`.
        if bytes[i] == b'"' {
            // Find matching closing quote for the key.
            let key_start = i + 1;
            let mut j = key_start;
            while j < bytes.len() && bytes[j] != b'"' {
                if bytes[j] == b'\\' && j + 1 < bytes.len() {
                    j += 2;
                    continue;
                }
                j += 1;
            }
            if j >= bytes.len() {
                out.push_str(&body[i..]);
                break;
            }
            let key = &lower[key_start..j];
            let key_matches = SECRET_KEYS.iter().any(|k| key.contains(k));
            // Append `"<key>"`
            out.push_str(&body[i..=j]);
            i = j + 1;
            if !key_matches {
                continue;
            }
            // Skip optional whitespace + ':' + whitespace.
            let mut k = i;
            while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                k += 1;
            }
            if k >= bytes.len() || bytes[k] != b':' {
                continue;
            }
            k += 1;
            while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                k += 1;
            }
            if k >= bytes.len() || bytes[k] != b'"' {
                // Non-string value (number, bool, object) — leave alone.
                out.push_str(&body[i..k]);
                i = k;
                continue;
            }
            // Append everything from `i` up to (and including) the opening quote of the value.
            out.push_str(&body[i..=k]);
            i = k + 1;
            // Find the matching closing quote.
            let val_start = i;
            let mut m = val_start;
            while m < bytes.len() && bytes[m] != b'"' {
                if bytes[m] == b'\\' && m + 1 < bytes.len() {
                    m += 2;
                    continue;
                }
                m += 1;
            }
            if m >= bytes.len() {
                out.push_str(&body[val_start..]);
                break;
            }
            // Replace the value with `***` and append the closing quote.
            out.push_str("***");
            out.push('"');
            redactions += 1;
            i = m + 1;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    (out, redactions)
}

#[no_mangle]
pub extern "C" fn evaluate_audit_filter() {
    let payload = read_payload();
    let body = match std::str::from_utf8(&payload) {
        Ok(s) => s,
        Err(_) => {
            log("audit-redact-secrets: non-utf8 payload, forwarding unchanged");
            return_decision(FORWARD, "non-utf8");
            return;
        }
    };
    let (rewritten, count) = redact(body);
    if count == 0 {
        return_decision(FORWARD, "no secret keys matched");
        return;
    }
    log(&format!(
        "audit-redact-secrets: redacted {count} value(s)"
    ));
    return_payload(rewritten.as_bytes());
    return_decision(TRANSFORM, "redacted secrets");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_password_value() {
        let (out, n) = redact("{\"user\":\"alice\",\"password\":\"hunter2\"}");
        assert_eq!(n, 1);
        assert_eq!(out, "{\"user\":\"alice\",\"password\":\"***\"}");
    }

    #[test]
    fn leaves_non_secret_keys_alone() {
        let (out, n) = redact("{\"hostname\":\"node-7\",\"port\":443}");
        assert_eq!(n, 0);
        assert_eq!(out, "{\"hostname\":\"node-7\",\"port\":443}");
    }

    #[test]
    fn redacts_multiple_secret_keys() {
        let (_, n) = redact("{\"token\":\"abc\",\"api_key\":\"def\",\"secret\":\"ghi\"}");
        assert_eq!(n, 3);
    }

    #[test]
    fn skips_non_string_secret_values() {
        // password as a number — leave alone (we only rewrite strings).
        let (out, n) = redact("{\"password\":42}");
        assert_eq!(n, 0);
        assert_eq!(out, "{\"password\":42}");
    }
}
