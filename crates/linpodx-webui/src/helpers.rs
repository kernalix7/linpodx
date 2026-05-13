//! Pure-Rust helper functions used by the leptos modal components.
//!
//! These are factored out of the `components/` modules so they compile (and are
//! testable) on the host target. The `components/` modules themselves only
//! compile under `cfg(target_arch = "wasm32")` because they pull in leptos /
//! gloo / wasm-bindgen, which the workspace host build deliberately skips.
//!
//! Keep these helpers free of any `web-sys` / `gloo` / `leptos` types.

use serde_json::Value;

/// Convert a raw command line into argv tokens. Plain whitespace split — no
/// shell quoting. The daemon executes argv directly via `podman exec`, never
/// through `sh -c`, so a literal space inside an argument is impossible from
/// the modal. Use the CLI when you need shell semantics.
pub fn parse_command(line: &str) -> Vec<String> {
    line.split_whitespace().map(str::to_string).collect()
}

/// Format an exec response object into a single string for the result panel.
/// Falls back to a plain `value.to_string()` rendering if the response is not
/// the expected `{exit_code, stdout, stderr}` shape (e.g. transport oddity).
pub fn format_exec_result(v: &Value) -> String {
    let obj = match v.as_object() {
        Some(o) => o,
        None => return v.to_string(),
    };
    let exit = obj.get("exit_code").and_then(|x| x.as_i64()).unwrap_or(-1);
    let stdout = obj
        .get("stdout")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let stderr = obj
        .get("stderr")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let mut out = format!("exit: {exit}\n");
    if !stdout.is_empty() {
        out.push_str("\n--- stdout ---\n");
        out.push_str(&stdout);
        if !stdout.ends_with('\n') {
            out.push('\n');
        }
    }
    if !stderr.is_empty() {
        out.push_str("\n--- stderr ---\n");
        out.push_str(&stderr);
        if !stderr.ends_with('\n') {
            out.push('\n');
        }
    }
    out
}

/// Hint shown in the LogsModal — the actual scrollback buffer is owned by
/// xterm.js (Phase 13 Stream B), which uses its own internal ring. We keep
/// this constant as a UI label so users have a sense of how far back they can
/// scroll without diving into xterm.js options.
pub const LOGS_MAX_LINES: usize = 1000;

/// Extract a single log line from an `EventTopic::Container` + `EventKind::Log`
/// notification's `details` payload. The daemon emits `{"stream": "stdout"|"stderr",
/// "line": "..."}`; we render it prefixed with the stream tag.
///
/// Returns `None` if the payload is not the expected shape (caller should skip
/// the event in that case).
pub fn extract_log_line(details: &Value) -> Option<String> {
    let obj = details.as_object()?;
    let line = obj.get("line")?.as_str()?;
    let stream = obj
        .get("stream")
        .and_then(|s| s.as_str())
        .unwrap_or("stdout");
    Some(format!("[{stream}] {line}"))
}

/// True when an event JSON-RPC notification's `params.resource_id` matches the
/// container we're streaming logs for. Notifications for other containers are
/// dropped without touching the LogsModal scrollback.
pub fn event_matches_container(notif: &Value, container_id: &str) -> bool {
    notif
        .pointer("/params/resource_id")
        .and_then(|v| v.as_str())
        == Some(container_id)
}

/// True when the JSON-RPC notification carries `EventKind::Log`. Other kinds
/// (created/started/etc.) flow over the same `EventTopic::Container` channel
/// but should be ignored by the LogsModal.
pub fn event_is_log_kind(notif: &Value) -> bool {
    notif.pointer("/params/kind").and_then(|v| v.as_str()) == Some("log")
}

/// Extract the `bridge_id` and `endpoint` fields from a `container_exec_pty`
/// JSON-RPC response. Returns `Err(message)` for any shape mismatch so the
/// caller can surface a friendly error in the modal status line.
pub fn parse_pty_response(v: &Value) -> Result<(String, String), String> {
    let obj = v
        .as_object()
        .ok_or_else(|| "pty response: not an object".to_string())?;
    let bridge_id = obj
        .get("bridge_id")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "pty response: missing bridge_id".to_string())?
        .to_string();
    let endpoint = obj
        .get("endpoint")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "pty response: missing endpoint".to_string())?
        .to_string();
    if bridge_id.is_empty() || endpoint.is_empty() {
        return Err("pty response: empty bridge_id or endpoint".into());
    }
    Ok((bridge_id, endpoint))
}

/// Compose a WebSocket URL from a host, protocol scheme, endpoint path
/// (e.g. `/pty/abc`) and an optional bearer token. The token is appended as a
/// percent-encoded `?token=` query string (the browser's WebSocket constructor
/// can't carry an Authorization header).
///
/// `proto` is one of `"ws"` / `"wss"`. The endpoint path is taken verbatim —
/// callers must include the leading `/`.
pub fn build_pty_url(proto: &str, host: &str, endpoint: &str, token: Option<&str>) -> String {
    match token {
        Some(t) if !t.is_empty() => {
            format!(
                "{proto}://{host}{endpoint}?token={}",
                percent_encode_token(t)
            )
        }
        _ => format!("{proto}://{host}{endpoint}"),
    }
}

/// Mirror of `ws.rs::url_encode_component` so the helper is unit-testable on
/// the host. Encodes everything outside `[A-Za-z0-9-_.~]`.
pub fn percent_encode_token(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for b in raw.as_bytes() {
        let c = *b;
        let safe = c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'~');
        if safe {
            out.push(c as char);
        } else {
            out.push_str(&format!("%{c:02X}"));
        }
    }
    out
}

/// Validate a user-typed `cols`/`rows` PTY size hint. Empty input maps to the
/// daemon defaults via `Ok(None)`. Out-of-range or non-numeric input returns
/// `Err(message)` for inline display in the modal.
pub fn parse_pty_size(raw: &str, label: &str) -> Result<Option<u16>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let n: u16 = trimmed
        .parse()
        .map_err(|_| format!("{label} must be a number"))?;
    if !(1..=4096).contains(&n) {
        return Err(format!("{label} must be between 1 and 4096"));
    }
    Ok(Some(n))
}

// ---------------------------------------------------------------------------
// Phase 17 — KDF badge + TOFU expiry helpers (host-testable).
// ---------------------------------------------------------------------------

/// Compose a human-readable KDF badge for a row in the Snapshots table. The
/// caller passes the optional algorithm and `key_source` strings (returned by
/// `snapshot_encryption_status`). Returns "—" when nothing is cached, "plaintext"
/// when the snapshot isn't encrypted, otherwise an `<algo> / <kdf>` label.
pub fn snapshot_kdf_badge(encrypted: bool, algorithm: Option<&str>, kdf: Option<&str>) -> String {
    if !encrypted {
        return "plaintext".to_string();
    }
    match (algorithm, kdf) {
        (Some(a), Some(k)) => format!("{a} / {k}"),
        (Some(a), None) => a.to_string(),
        (None, Some(k)) => k.to_string(),
        (None, None) => "encrypted".to_string(),
    }
}

/// Parse a free-form TOFU expiry input ("3600", "30s", "5m", "2h", "1d",
/// "clear"). Mirrors the iced GUI parser so the two clients accept identical
/// inputs.
pub fn parse_tofu_expiry(raw: &str) -> Result<Option<u64>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.eq_ignore_ascii_case("clear") || trimmed.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    let (number_part, multiplier): (&str, u64) =
        if let Some(rest) = trimmed.strip_suffix(['s', 'S']) {
            (rest, 1)
        } else if let Some(rest) = trimmed.strip_suffix(['m', 'M']) {
            (rest, 60)
        } else if let Some(rest) = trimmed.strip_suffix(['h', 'H']) {
            (rest, 3600)
        } else if let Some(rest) = trimmed.strip_suffix(['d', 'D']) {
            (rest, 86_400)
        } else {
            (trimmed, 1)
        };
    let n: u64 = number_part
        .trim()
        .parse()
        .map_err(|_| format!("invalid expiry value: {raw:?}"))?;
    if n == 0 {
        return Err("expiry must be greater than zero (type 'clear' to disable)".into());
    }
    Ok(Some(n.saturating_mul(multiplier)))
}

/// Render the countdown / expired message for a TOFU expiry status payload.
/// Pure-Rust so we can pin the string output in tests; the leptos component
/// just inserts the result via `view!`.
pub fn tofu_countdown_label(
    enabled: bool,
    max_age_secs: Option<u64>,
    enabled_at: Option<i64>,
    now_secs: i64,
) -> String {
    if !enabled {
        return "TOFU disabled".to_string();
    }
    let Some(max_age) = max_age_secs else {
        return "no expiry set (TOFU stays on until manually disabled)".to_string();
    };
    let Some(start) = enabled_at else {
        return format!("expiry {max_age}s — will start when TOFU is enabled");
    };
    let elapsed = now_secs.saturating_sub(start);
    if elapsed < 0 {
        return format!("expiry {max_age}s (clock skew)");
    }
    let remaining = max_age as i64 - elapsed;
    if remaining <= 0 {
        format!("EXPIRED ({}s past max_age={max_age}s)", (-remaining) as u64)
    } else {
        format!("expires in {remaining}s (max_age={max_age}s)")
    }
}

/// True when the TOFU enrollment window already elapsed — used by the leptos
/// component to flip a red `.expired` modifier on the badge.
pub fn tofu_is_expired(
    enabled: bool,
    max_age_secs: Option<u64>,
    enabled_at: Option<i64>,
    now_secs: i64,
) -> bool {
    if !enabled {
        return false;
    }
    let (Some(max_age), Some(start)) = (max_age_secs, enabled_at) else {
        return false;
    };
    let elapsed = now_secs.saturating_sub(start);
    elapsed >= 0 && (elapsed as u64) >= max_age
}

/// Map a propagation-status payload (returned by the daemon's
/// `plugin_key_revoke_propagate` response or held in a leptos signal) into a
/// short human-readable label.
pub fn plugin_propagation_label(state: &str, log_index: Option<u64>) -> String {
    match state {
        "this_node" | "local" => "this node".to_string(),
        "pending" => "pending (raft)".to_string(),
        "cluster" => match log_index {
            Some(idx) => format!("cluster-wide (idx {idx})"),
            None => "cluster-wide".to_string(),
        },
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_command_splits_on_whitespace() {
        assert!(parse_command("").is_empty());
        assert_eq!(parse_command("ls"), vec!["ls"]);
        assert_eq!(
            parse_command("  ls   -la  /etc  "),
            vec!["ls", "-la", "/etc"]
        );
    }

    #[test]
    fn format_exec_result_shows_exit_and_streams() {
        let v = json!({"exit_code": 0, "stdout": "hello\n", "stderr": ""});
        let s = format_exec_result(&v);
        assert!(s.contains("exit: 0"));
        assert!(s.contains("--- stdout ---"));
        assert!(s.contains("hello"));
        assert!(!s.contains("--- stderr ---"));
    }

    #[test]
    fn format_exec_result_includes_stderr_when_present() {
        let v = json!({"exit_code": 1, "stdout": "", "stderr": "boom"});
        let s = format_exec_result(&v);
        assert!(s.contains("exit: 1"));
        assert!(s.contains("--- stderr ---"));
        assert!(s.contains("boom"));
    }

    #[test]
    fn format_exec_result_falls_back_for_non_object() {
        let v = json!("oops");
        let s = format_exec_result(&v);
        assert!(s.contains("oops"));
    }

    #[test]
    fn extract_log_line_prefixes_stream() {
        let v = json!({"stream": "stderr", "line": "boom"});
        assert_eq!(extract_log_line(&v).as_deref(), Some("[stderr] boom"));
    }

    #[test]
    fn extract_log_line_defaults_stream_to_stdout() {
        let v = json!({"line": "hi"});
        assert_eq!(extract_log_line(&v).as_deref(), Some("[stdout] hi"));
    }

    #[test]
    fn extract_log_line_rejects_missing_line() {
        let v = json!({"stream": "stdout"});
        assert!(extract_log_line(&v).is_none());
    }

    #[test]
    fn event_matches_container_compares_resource_id() {
        let notif = json!({
            "method": "event",
            "params": {"resource_id": "abc123", "kind": "log"}
        });
        assert!(event_matches_container(&notif, "abc123"));
        assert!(!event_matches_container(&notif, "other"));
    }

    #[test]
    fn event_is_log_kind_only_matches_log() {
        let log = json!({"params": {"kind": "log"}});
        let started = json!({"params": {"kind": "started"}});
        assert!(event_is_log_kind(&log));
        assert!(!event_is_log_kind(&started));
    }

    #[test]
    fn parse_pty_response_extracts_bridge_and_endpoint() {
        let v = json!({"bridge_id": "abcd1234", "endpoint": "/pty/abcd1234"});
        let (b, e) = parse_pty_response(&v).expect("ok");
        assert_eq!(b, "abcd1234");
        assert_eq!(e, "/pty/abcd1234");
    }

    #[test]
    fn parse_pty_response_rejects_missing_fields() {
        assert!(parse_pty_response(&json!({})).is_err());
        assert!(parse_pty_response(&json!({"bridge_id": "x"})).is_err());
        assert!(parse_pty_response(&json!({"endpoint": "/pty/x"})).is_err());
        assert!(parse_pty_response(&json!("oops")).is_err());
    }

    #[test]
    fn parse_pty_response_rejects_empty_strings() {
        assert!(parse_pty_response(&json!({"bridge_id": "", "endpoint": "/pty/x"})).is_err());
        assert!(parse_pty_response(&json!({"bridge_id": "x", "endpoint": ""})).is_err());
    }

    #[test]
    fn build_pty_url_appends_token_when_present() {
        let u = build_pty_url("wss", "host:8443", "/pty/abc", Some("tok en"));
        assert_eq!(u, "wss://host:8443/pty/abc?token=tok%20en");
    }

    #[test]
    fn build_pty_url_omits_query_when_token_missing() {
        let u = build_pty_url("ws", "localhost:7777", "/pty/abc", None);
        assert_eq!(u, "ws://localhost:7777/pty/abc");
        let u = build_pty_url("ws", "localhost:7777", "/pty/abc", Some(""));
        assert_eq!(u, "ws://localhost:7777/pty/abc");
    }

    #[test]
    fn percent_encode_token_preserves_unreserved() {
        assert_eq!(percent_encode_token("ABCxyz0-9_.~"), "ABCxyz0-9_.~");
    }

    #[test]
    fn percent_encode_token_escapes_specials() {
        assert_eq!(percent_encode_token("a b/c"), "a%20b%2Fc");
        assert_eq!(percent_encode_token("k=v&x=y"), "k%3Dv%26x%3Dy");
    }

    #[test]
    fn parse_pty_size_accepts_blank_as_none() {
        assert_eq!(parse_pty_size("", "cols").unwrap(), None);
        assert_eq!(parse_pty_size("   ", "rows").unwrap(), None);
    }

    #[test]
    fn parse_pty_size_accepts_in_range_value() {
        assert_eq!(parse_pty_size("80", "cols").unwrap(), Some(80));
        assert_eq!(parse_pty_size("4096", "rows").unwrap(), Some(4096));
        assert_eq!(parse_pty_size("1", "cols").unwrap(), Some(1));
    }

    #[test]
    fn parse_pty_size_rejects_zero_or_overflow() {
        assert!(parse_pty_size("0", "cols").is_err());
        assert!(parse_pty_size("4097", "cols").is_err());
        assert!(parse_pty_size("not-a-number", "cols").is_err());
    }

    // ---- Phase 17 helpers ----

    #[test]
    fn snapshot_kdf_badge_handles_all_combinations() {
        assert_eq!(snapshot_kdf_badge(false, None, None), "plaintext");
        assert_eq!(
            snapshot_kdf_badge(true, Some("aes-256-gcm"), Some("argon2id")),
            "aes-256-gcm / argon2id"
        );
        assert_eq!(
            snapshot_kdf_badge(true, Some("aes-256-gcm"), None),
            "aes-256-gcm"
        );
        assert_eq!(
            snapshot_kdf_badge(true, None, Some("sha256-1k")),
            "sha256-1k"
        );
        assert_eq!(snapshot_kdf_badge(true, None, None), "encrypted");
    }

    #[test]
    fn parse_tofu_expiry_blank_and_clear() {
        assert_eq!(parse_tofu_expiry("").unwrap(), None);
        assert_eq!(parse_tofu_expiry("   ").unwrap(), None);
        assert_eq!(parse_tofu_expiry("clear").unwrap(), None);
        assert_eq!(parse_tofu_expiry("NONE").unwrap(), None);
    }

    #[test]
    fn parse_tofu_expiry_units() {
        assert_eq!(parse_tofu_expiry("60").unwrap(), Some(60));
        assert_eq!(parse_tofu_expiry("60s").unwrap(), Some(60));
        assert_eq!(parse_tofu_expiry("5m").unwrap(), Some(300));
        assert_eq!(parse_tofu_expiry("2h").unwrap(), Some(7_200));
        assert_eq!(parse_tofu_expiry("1d").unwrap(), Some(86_400));
    }

    #[test]
    fn parse_tofu_expiry_errors_on_zero_and_garbage() {
        assert!(parse_tofu_expiry("0").is_err());
        assert!(parse_tofu_expiry("oops").is_err());
        assert!(parse_tofu_expiry("60x").is_err());
    }

    #[test]
    fn tofu_countdown_label_covers_states() {
        assert_eq!(
            tofu_countdown_label(false, Some(60), Some(1), 100),
            "TOFU disabled"
        );
        assert!(tofu_countdown_label(true, None, Some(1), 100).contains("no expiry"));
        assert!(tofu_countdown_label(true, Some(60), None, 100).contains("will start"));
        assert_eq!(
            tofu_countdown_label(true, Some(3_600), Some(1_000), 2_000),
            "expires in 2600s (max_age=3600s)"
        );
        let expired = tofu_countdown_label(true, Some(60), Some(1_000), 2_000);
        assert!(expired.starts_with("EXPIRED"));
        assert!(expired.contains("max_age=60s"));
    }

    #[test]
    fn tofu_is_expired_returns_false_when_disabled_or_missing_fields() {
        assert!(!tofu_is_expired(false, Some(60), Some(1), 9_999));
        assert!(!tofu_is_expired(true, None, Some(1), 9_999));
        assert!(!tofu_is_expired(true, Some(60), None, 9_999));
    }

    #[test]
    fn tofu_is_expired_compares_elapsed_against_max_age() {
        assert!(!tofu_is_expired(true, Some(60), Some(1_000), 1_030));
        assert!(tofu_is_expired(true, Some(60), Some(1_000), 1_060));
        assert!(tofu_is_expired(true, Some(60), Some(1_000), 9_999));
    }

    #[test]
    fn plugin_propagation_label_covers_known_states() {
        assert_eq!(plugin_propagation_label("this_node", None), "this node");
        assert_eq!(plugin_propagation_label("local", None), "this node");
        assert_eq!(plugin_propagation_label("pending", None), "pending (raft)");
        assert_eq!(plugin_propagation_label("cluster", None), "cluster-wide");
        assert_eq!(
            plugin_propagation_label("cluster", Some(42)),
            "cluster-wide (idx 42)"
        );
        // Unknown variants are echoed verbatim so the daemon can introduce new
        // states without breaking the renderer.
        assert_eq!(plugin_propagation_label("future", None), "future");
    }
}
