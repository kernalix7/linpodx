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

// ===========================================================================
// App-shell v5 — pure helpers shared by dashboard / command-palette / charts.
// All of the following are `web-sys`/`leptos`-free so the host `cargo test`
// covers the geometry + scoring + formatting logic without a wasm toolchain.
// ===========================================================================

/// Human-readable byte size, base-1024, one decimal for >= 1 KiB.
///
/// Rendered with SI-ish suffixes (`KB`/`MB`/`GB`) even though the divisor is
/// 1024 — this matches how Docker Desktop / `podman system df` present sizes.
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut val = bytes as f64;
    let mut unit = 0usize;
    while val >= 1024.0 && unit < UNITS.len() - 1 {
        val /= 1024.0;
        unit += 1;
    }
    format!("{val:.1} {}", UNITS[unit])
}

/// Trim an id / hash to a short display form (first 12 chars, or the whole
/// string when shorter). Never panics on multi-byte input — it walks chars.
pub fn short_id(id: &str) -> String {
    id.chars().take(12).collect()
}

/// Subsequence fuzzy score for the command palette.
///
/// Returns `Some(score)` when every char of `query` appears in `hay` in order
/// (case-insensitive), `None` otherwise. Higher scores are better. The scoring
/// rewards contiguous runs, word-boundary hits (`/`, `-`, `_`, ` `, `.` or the
/// first char) and a prefix match, so `"cnt"` ranks `container` above a
/// scattered hit. An empty query scores `0` (matches everything, neutral rank).
pub fn fuzzy_score(query: &str, hay: &str) -> Option<i32> {
    if query.is_empty() {
        return Some(0);
    }
    let q: Vec<char> = query.to_lowercase().chars().collect();
    let h: Vec<char> = hay.to_lowercase().chars().collect();
    if q.len() > h.len() {
        return None;
    }

    let is_boundary = |i: usize| -> bool {
        if i == 0 {
            return true;
        }
        matches!(h[i - 1], '/' | '-' | '_' | ' ' | '.' | ':')
    };

    let mut qi = 0usize;
    let mut score = 0i32;
    let mut prev_match: Option<usize> = None;
    for (i, &hc) in h.iter().enumerate() {
        if qi >= q.len() {
            break;
        }
        if hc == q[qi] {
            score += 1;
            if is_boundary(i) {
                score += 8;
            }
            if let Some(p) = prev_match {
                if p + 1 == i {
                    // Contiguous run — the strongest signal.
                    score += 6;
                }
            }
            if qi == 0 && i == 0 {
                // Whole-query prefix bonus.
                score += 10;
            }
            prev_match = Some(i);
            qi += 1;
        }
    }
    if qi == q.len() {
        // Shorter haystacks with the same run rank slightly higher.
        Some(score - (h.len() as i32 - q.len() as i32).min(20))
    } else {
        None
    }
}

// --------------------------------------------------------------------------
// Inline-SVG chart geometry. Charts render into a caller-chosen `w`×`h` pixel
// viewBox with a uniform `pad` inset. Every function is a pure transform over
// `&[(f64 ts, f64 value)]` samples so the component layer stays declarative.
// --------------------------------------------------------------------------

/// (min, max) of the sample values. Empty → `(0.0, 1.0)`. A flat series is
/// padded to a unit span so a horizontal line still has vertical headroom.
/// When `zero_floor` is set the minimum is pinned to `0.0` (area charts read
/// better from a zero baseline for CPU / memory / throughput).
pub fn value_bounds(pts: &[(f64, f64)], zero_floor: bool) -> (f64, f64) {
    if pts.is_empty() {
        return (0.0, 1.0);
    }
    let mut lo = f64::INFINITY;
    let mut hi = f64::NEG_INFINITY;
    for &(_, v) in pts {
        if v < lo {
            lo = v;
        }
        if v > hi {
            hi = v;
        }
    }
    if zero_floor && lo > 0.0 {
        lo = 0.0;
    }
    if (hi - lo).abs() < f64::EPSILON {
        // Flat line: give it a symmetric unit span (or [0,1] at the origin).
        if hi.abs() < f64::EPSILON {
            return (0.0, 1.0);
        }
        return (lo - hi.abs() * 0.5, hi + hi.abs() * 0.5);
    }
    (lo, hi)
}

/// (min, max) of the sample timestamps. Empty → `(0.0, 1.0)`. A single point
/// gets a unit span so the x-projection doesn't divide by zero.
pub fn ts_bounds(pts: &[(f64, f64)]) -> (f64, f64) {
    if pts.is_empty() {
        return (0.0, 1.0);
    }
    let mut lo = f64::INFINITY;
    let mut hi = f64::NEG_INFINITY;
    for &(t, _) in pts {
        if t < lo {
            lo = t;
        }
        if t > hi {
            hi = t;
        }
    }
    if (hi - lo).abs() < f64::EPSILON {
        return (lo, lo + 1.0);
    }
    (lo, hi)
}

/// Project one `(ts, value)` sample into the `w`×`h` viewBox with `pad` inset.
/// Values are clamped into `vb`; the y-axis is inverted (SVG origin top-left).
pub fn project_point(
    ts: f64,
    val: f64,
    tb: (f64, f64),
    vb: (f64, f64),
    w: f64,
    h: f64,
    pad: f64,
) -> (f64, f64) {
    let (t0, t1) = tb;
    let (v0, v1) = vb;
    let plot_w = (w - pad * 2.0).max(1.0);
    let plot_h = (h - pad * 2.0).max(1.0);
    let tx = if (t1 - t0).abs() < f64::EPSILON {
        0.5
    } else {
        ((ts - t0) / (t1 - t0)).clamp(0.0, 1.0)
    };
    let vclamped = val.clamp(v0.min(v1), v0.max(v1));
    let vy = if (v1 - v0).abs() < f64::EPSILON {
        0.5
    } else {
        ((vclamped - v0) / (v1 - v0)).clamp(0.0, 1.0)
    };
    let x = pad + tx * plot_w;
    let y = pad + (1.0 - vy) * plot_h; // invert
    (x, y)
}

/// Map a whole series to viewBox coordinates.
pub fn project_series(
    pts: &[(f64, f64)],
    w: f64,
    h: f64,
    pad: f64,
    zero_floor: bool,
) -> Vec<(f64, f64)> {
    let tb = ts_bounds(pts);
    let vb = value_bounds(pts, zero_floor);
    pts.iter()
        .map(|&(t, v)| project_point(t, v, tb, vb, w, h, pad))
        .collect()
}

/// `M …L…` polyline path for projected coordinates. Empty → empty string.
pub fn line_path(coords: &[(f64, f64)]) -> String {
    if coords.is_empty() {
        return String::new();
    }
    let mut out = String::with_capacity(coords.len() * 14);
    for (i, &(x, y)) in coords.iter().enumerate() {
        if i == 0 {
            out.push_str(&format!("M{x:.2} {y:.2}"));
        } else {
            out.push_str(&format!(" L{x:.2} {y:.2}"));
        }
    }
    out
}

/// Closed area path: the polyline dropped to `baseline_y` and closed. Empty
/// input → empty string; a single point becomes a 1px-wide sliver so the fill
/// is still visible.
pub fn area_path(coords: &[(f64, f64)], baseline_y: f64) -> String {
    if coords.is_empty() {
        return String::new();
    }
    if coords.len() == 1 {
        let (x, y) = coords[0];
        return format!(
            "M{x:.2} {by:.2} L{x:.2} {y:.2} L{x2:.2} {y:.2} L{x2:.2} {by:.2} Z",
            by = baseline_y,
            x2 = x + 1.0
        );
    }
    let mut out = line_path(coords);
    let (last_x, _) = coords[coords.len() - 1];
    let (first_x, _) = coords[0];
    out.push_str(&format!(
        " L{last_x:.2} {by:.2} L{first_x:.2} {by:.2} Z",
        by = baseline_y
    ));
    out
}

/// Format an epoch-seconds timestamp as a `HH:MM:SS` UTC clock for chart
/// tooltips. Avoids a `chrono` dependency in the wasm build by doing the
/// modular arithmetic directly. Negative / absurd inputs clamp to `00:00:00`.
pub fn clock_hms(epoch_secs: i64) -> String {
    if epoch_secs < 0 {
        return "00:00:00".to_string();
    }
    let secs_of_day = epoch_secs.rem_euclid(86_400);
    let h = secs_of_day / 3_600;
    let m = (secs_of_day % 3_600) / 60;
    let s = secs_of_day % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

/// Index of the sample whose projected x is nearest to `mouse_x`. Part of the
/// pure hover hit-testing API (host-tested); charts may drive the crosshair
/// from either this or per-sample hit-rects, so it can read as unused on wasm.
#[allow(dead_code)]
pub fn nearest_index_by_x(coords: &[(f64, f64)], mouse_x: f64) -> Option<usize> {
    if coords.is_empty() {
        return None;
    }
    let mut best = 0usize;
    let mut best_d = f64::INFINITY;
    for (i, &(x, _)) in coords.iter().enumerate() {
        let d = (x - mouse_x).abs();
        if d < best_d {
            best_d = d;
            best = i;
        }
    }
    Some(best)
}

// ===========================================================================
// Container-detail drawer — pure helpers (port-link builder, log-line
// classification, cumulative→delta throughput). Host-compiled + unit-tested so
// the wasm-only drawer component consumes proven logic.
// ===========================================================================

/// A parsed published-port entry for the container-detail Overview tab. When
/// `href` is `Some`, the drawer renders a clickable `localhost:<port>` anchor;
/// otherwise the `display` string is emitted as plain text (udp / unpublished).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortLink {
    pub display: String,
    pub href: Option<String>,
}

/// Turn podman-form port strings (`0.0.0.0:8080->80/tcp`, `:::8080->80/tcp`,
/// `53->53/udp`, `80/tcp`) into renderable [`PortLink`]s. Only host-published
/// **tcp** ports get an `http://localhost:<hostport>` href; udp and
/// non-published container ports render as plain text.
pub fn parse_published_ports(ports: &[String]) -> Vec<PortLink> {
    ports
        .iter()
        .map(|raw| {
            let s = raw.trim();
            let Some((host_side, cont_side)) = s.split_once("->") else {
                // No host mapping → not published.
                return PortLink {
                    display: s.to_string(),
                    href: None,
                };
            };
            let cont = cont_side.trim();
            // Host side is `ip:port`, `[::]:port` or a bare `port`; the port is
            // always the final `:`-delimited segment.
            let host_port = host_side.rsplit(':').next().unwrap_or("").trim();
            let proto = cont.rsplit('/').next().unwrap_or("tcp").trim();
            let is_tcp = proto.eq_ignore_ascii_case("tcp");
            match host_port.parse::<u32>() {
                Ok(p) if is_tcp => PortLink {
                    display: format!("localhost:{p} \u{2192} {cont}"),
                    href: Some(format!("http://localhost:{p}")),
                },
                Ok(p) => PortLink {
                    display: format!("localhost:{p} \u{2192} {cont}"),
                    href: None,
                },
                Err(_) => PortLink {
                    display: s.to_string(),
                    href: None,
                },
            }
        })
        .collect()
}

/// True when a streamed follow-log line carries the `[stderr]` stream tag
/// produced by [`extract_log_line`]. Drives the `.log-line--stderr` modifier.
pub fn log_line_is_stderr(line: &str) -> bool {
    line.starts_with("[stderr]")
}

/// Split a raw multi-line log stream string into its non-empty lines, trimming
/// a single trailing newline. Used to fan a `{stdout}`/`{stderr}` blob into
/// per-line `<div class="log-line">` rows.
pub fn split_log_lines(blob: &str) -> Vec<String> {
    blob.lines()
        .map(str::to_string)
        .filter(|l| !l.is_empty())
        .collect()
}

/// Convert a cumulative counter series (e.g. `net_rx` total bytes) into a
/// per-interval delta series for the throughput chart. Negative deltas (counter
/// reset / container restart) clamp to zero; a series shorter than two points
/// yields flat-zero points so the chart still has a baseline.
pub fn cumulative_to_delta(pts: &[(f64, f64)]) -> Vec<(f64, f64)> {
    if pts.len() < 2 {
        return pts.iter().map(|&(t, _)| (t, 0.0)).collect();
    }
    pts.windows(2)
        .map(|w| {
            let (_, v0) = w[0];
            let (t1, v1) = w[1];
            (t1, (v1 - v0).max(0.0))
        })
        .collect()
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

    // ---- app-shell v5 helpers ------------------------------------------

    #[test]
    fn format_bytes_scales_by_1024() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(4_509_715_660), "4.2 GB");
    }

    #[test]
    fn short_id_truncates_and_is_utf8_safe() {
        assert_eq!(short_id("abcdef0123456789"), "abcdef012345");
        assert_eq!(short_id("short"), "short");
        assert_eq!(short_id(""), "");
        // Multi-byte input must not panic or split a codepoint.
        assert_eq!(short_id("héllo"), "héllo");
    }

    #[test]
    fn fuzzy_score_empty_query_matches_neutral() {
        assert_eq!(fuzzy_score("", "anything"), Some(0));
    }

    #[test]
    fn fuzzy_score_requires_subsequence() {
        assert!(fuzzy_score("cnt", "container").is_some());
        assert!(fuzzy_score("xyz", "container").is_none());
        // Out-of-order chars never match.
        assert!(fuzzy_score("tac", "cat").is_none());
        // Query longer than the haystack cannot match.
        assert!(fuzzy_score("containers", "cat").is_none());
    }

    #[test]
    fn fuzzy_score_prefers_prefix_and_contiguous() {
        let prefix = fuzzy_score("con", "container").unwrap();
        let scattered = fuzzy_score("con", "beacon").unwrap();
        assert!(
            prefix > scattered,
            "prefix {prefix} should beat scattered {scattered}"
        );
    }

    #[test]
    fn fuzzy_score_word_boundary_beats_midword() {
        let boundary = fuzzy_score("web", "my-web-app").unwrap();
        let midword = fuzzy_score("web", "cobweb").unwrap();
        assert!(boundary > midword);
    }

    #[test]
    fn value_bounds_handles_empty_flat_and_range() {
        assert_eq!(value_bounds(&[], false), (0.0, 1.0));
        // Flat non-zero series gets symmetric headroom.
        let (lo, hi) = value_bounds(&[(0.0, 4.0), (1.0, 4.0)], false);
        assert!(lo < 4.0 && hi > 4.0);
        // Flat zero series pins to the unit origin span.
        assert_eq!(value_bounds(&[(0.0, 0.0)], false), (0.0, 1.0));
        // Ranged series is returned verbatim.
        assert_eq!(value_bounds(&[(0.0, 2.0), (1.0, 8.0)], false), (2.0, 8.0));
        // zero_floor pulls the min down to 0.
        assert_eq!(value_bounds(&[(0.0, 2.0), (1.0, 8.0)], true), (0.0, 8.0));
    }

    #[test]
    fn ts_bounds_handles_empty_and_single() {
        assert_eq!(ts_bounds(&[]), (0.0, 1.0));
        assert_eq!(ts_bounds(&[(5.0, 9.0)]), (5.0, 6.0));
        assert_eq!(ts_bounds(&[(2.0, 0.0), (10.0, 0.0)]), (2.0, 10.0));
    }

    #[test]
    fn project_point_inverts_y_and_clamps() {
        let tb = (0.0, 10.0);
        let vb = (0.0, 100.0);
        // Max value maps near the top (small y); min value near the bottom.
        let (_, y_hi) = project_point(0.0, 100.0, tb, vb, 100.0, 100.0, 5.0);
        let (_, y_lo) = project_point(0.0, 0.0, tb, vb, 100.0, 100.0, 5.0);
        assert!(y_hi < y_lo, "higher value must sit higher (smaller y)");
        // Out-of-range value is clamped, not extrapolated past the plot.
        let (_, y_over) = project_point(0.0, 500.0, tb, vb, 100.0, 100.0, 5.0);
        assert!((y_over - y_hi).abs() < 1e-9);
    }

    #[test]
    fn line_and_area_paths_handle_edge_cases() {
        assert_eq!(line_path(&[]), "");
        assert_eq!(area_path(&[], 50.0), "");
        let one = line_path(&[(1.0, 2.0)]);
        assert!(one.starts_with("M1.00 2.00"));
        let two = line_path(&[(0.0, 0.0), (10.0, 5.0)]);
        assert!(two.contains(" L10.00 5.00"));
        // Single-point area still produces a closed, fillable sliver.
        let a1 = area_path(&[(4.0, 9.0)], 50.0);
        assert!(a1.starts_with('M') && a1.ends_with('Z'));
        let a2 = area_path(&[(0.0, 0.0), (10.0, 5.0)], 50.0);
        assert!(a2.ends_with("50.00 Z") || a2.ends_with(" Z"));
    }

    #[test]
    fn clock_hms_formats_utc_time_of_day() {
        assert_eq!(clock_hms(0), "00:00:00");
        assert_eq!(clock_hms(-5), "00:00:00");
        // 2026-07-21T12:00:00Z is a whole number of days plus 12h.
        assert_eq!(clock_hms(3_600 + 120 + 5), "01:02:05");
        assert_eq!(clock_hms(86_400 + 45_296), "12:34:56");
    }

    #[test]
    fn nearest_index_by_x_picks_closest() {
        let coords = vec![(0.0, 0.0), (10.0, 0.0), (20.0, 0.0)];
        assert_eq!(nearest_index_by_x(&coords, 9.0), Some(1));
        assert_eq!(nearest_index_by_x(&coords, 0.0), Some(0));
        assert_eq!(nearest_index_by_x(&coords, 100.0), Some(2));
        assert_eq!(nearest_index_by_x(&[], 5.0), None);
    }

    // ---- container-detail drawer helpers -------------------------------

    #[test]
    fn parse_published_ports_links_only_tcp() {
        let links = parse_published_ports(&[
            "0.0.0.0:8080->80/tcp".to_string(),
            ":::9090->90/tcp".to_string(),
            "0.0.0.0:53->53/udp".to_string(),
            "80/tcp".to_string(),
        ]);
        assert_eq!(links[0].href.as_deref(), Some("http://localhost:8080"));
        assert!(links[0].display.starts_with("localhost:8080"));
        // IPv6 host mapping still resolves the trailing port.
        assert_eq!(links[1].href.as_deref(), Some("http://localhost:9090"));
        // udp is published but never gets an http link.
        assert_eq!(links[2].href, None);
        assert!(links[2].display.starts_with("localhost:53"));
        // Unpublished container port renders verbatim, no link.
        assert_eq!(links[3].href, None);
        assert_eq!(links[3].display, "80/tcp");
    }

    #[test]
    fn parse_published_ports_handles_empty_and_bare() {
        assert!(parse_published_ports(&[]).is_empty());
        let links = parse_published_ports(&["garbage".to_string()]);
        assert_eq!(links[0].href, None);
        assert_eq!(links[0].display, "garbage");
    }

    #[test]
    fn log_line_is_stderr_matches_stream_tag() {
        assert!(log_line_is_stderr("[stderr] boom"));
        assert!(!log_line_is_stderr("[stdout] ok"));
        assert!(!log_line_is_stderr("plain line"));
    }

    #[test]
    fn split_log_lines_drops_blanks() {
        assert_eq!(split_log_lines(""), Vec::<String>::new());
        assert_eq!(split_log_lines("a\n\nb\n"), vec!["a", "b"]);
        assert_eq!(split_log_lines("single"), vec!["single"]);
    }

    #[test]
    fn cumulative_to_delta_diffs_and_clamps() {
        // Fewer than two points → flat-zero baseline.
        assert_eq!(cumulative_to_delta(&[]), Vec::<(f64, f64)>::new());
        assert_eq!(cumulative_to_delta(&[(1.0, 500.0)]), vec![(1.0, 0.0)]);
        // Normal increasing counter → per-interval deltas keyed on the later ts.
        assert_eq!(
            cumulative_to_delta(&[(1.0, 100.0), (2.0, 250.0), (3.0, 300.0)]),
            vec![(2.0, 150.0), (3.0, 50.0)]
        );
        // Counter reset (v decreases) clamps the delta to zero.
        assert_eq!(
            cumulative_to_delta(&[(1.0, 900.0), (2.0, 10.0)]),
            vec![(2.0, 0.0)]
        );
    }
}
