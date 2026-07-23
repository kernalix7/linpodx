//! Container-detail slide-over drawer (Docker/Rancher-Desktop parity).
//!
//! Rendered as the *body* of the app-shell drawer: `app.rs` owns the
//! `.drawer` / `.drawer-backdrop` chrome + the `#container/<id>` deep-link and
//! Esc/backdrop close, and mounts this component inside `.drawer-body`. We read
//! the shared [`DrawerState`] (`Some(container_id)` = open) and [`AuthToken`]
//! contexts, then render a sticky tab strip over five self-fetching panes:
//!
//!   * **Overview** — `GET /containers/:id/inspect`; published tcp ports become
//!     clickable `http://localhost:<port>` links (see
//!     [`crate::helpers::parse_published_ports`]). A Healthcheck section
//!     ([`healthcheck_section`]) reads `raw.Config.Healthcheck` /
//!     `raw.State.Health` — the verbatim `podman inspect` object — since
//!     `ContainerInspect` does not model healthcheck fields itself.
//!   * **Logs** — `GET /containers/:id/logs?tail=500`, plus an optional live
//!     follow that subscribes to the `container` topic and appends `Log` events.
//!   * **Terminal** — reuses [`super::exec_pty_modal::PtyTerminal`] (the same
//!     exec-PTY machinery as the standalone modal) scoped to the drawer body.
//!   * **Stats** — `GET /metrics/:id/history` bootstrap + a 2 s
//!     `GET /metrics/:id` poll, drawn with the inline-SVG chart primitives.
//!   * **Inspect** — pretty-printed raw JSON with a clipboard "Copy" button.
//!
//! XSS posture: every value is interpolated through leptos `view!` (escaped);
//! log text is rendered as text nodes, never `inner_html`. Port hrefs are
//! constructed from a parsed integer host-port, so no user string reaches the
//! `href` verbatim.

use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::spawn_local;
use web_sys::Element;

use super::charts::{AreaChart, LineChart, TwoSeriesChart};
use super::exec_pty_modal::PtyTerminal;
use crate::api_client::{
    build_container_update_body, fetch_container_inspect, fetch_container_logs,
    fetch_metrics_history, fetch_metrics_latest, update_container_limits,
};
use crate::app::{AuthToken, DrawerState};
use crate::helpers::{
    cumulative_to_delta, event_is_log_kind, event_matches_container, extract_log_line,
    format_bytes, log_line_is_stderr, parse_published_ports, short_id, split_log_lines,
};
use crate::ws::{send_rpc, subscribe};

/// Cap on rendered log lines (initial tail + streamed follow).
const LOG_CAP: usize = 2000;
/// Cap on the per-container metrics ring shown in the Stats tab (~4 min @ 2 s).
const STAT_CAP: usize = 120;

#[derive(Clone, Copy, PartialEq, Eq)]
enum DetailTab {
    Overview,
    Logs,
    Terminal,
    Stats,
    Inspect,
}

impl DetailTab {
    const ALL: [DetailTab; 5] = [
        DetailTab::Overview,
        DetailTab::Logs,
        DetailTab::Terminal,
        DetailTab::Stats,
        DetailTab::Inspect,
    ];

    fn label(self) -> &'static str {
        match self {
            DetailTab::Overview => "Overview",
            DetailTab::Logs => "Logs",
            DetailTab::Terminal => "Terminal",
            DetailTab::Stats => "Stats",
            DetailTab::Inspect => "Inspect",
        }
    }
}

/// Map a lowercase `ContainerState` string to a `.chip--*` modifier.
fn state_chip_class(state: &str) -> &'static str {
    match state {
        "running" => "chip chip--running",
        "paused" | "created" => "chip chip--warn",
        "exited" | "stopped" => "chip chip--stopped",
        "dead" => "chip chip--error",
        _ => "chip chip--neutral",
    }
}

// Chart value formatters (fn pointers handed to the chart primitives).
fn pct_fmt(v: f64) -> String {
    format!("{v:.1}%")
}
fn bytes_fmt(v: f64) -> String {
    format_bytes(v.max(0.0) as u64)
}
fn rate_fmt(v: f64) -> String {
    format!("{}/s", format_bytes(v.max(0.0) as u64))
}

/// Resolve a `MetricsSample.ts` RFC3339 string to epoch seconds; falls back to
/// the wall clock when the field is missing / unparseable.
fn sample_ts(sample: &Value) -> f64 {
    sample
        .get("ts")
        .and_then(Value::as_str)
        .map(|s| js_sys::Date::parse(s) / 1000.0)
        .filter(|f| f.is_finite())
        .unwrap_or_else(|| js_sys::Date::now() / 1000.0)
}

/// Push `(ts, val)` onto a fixed-capacity ring-buffer signal.
fn push_capped(sig: RwSignal<Vec<(f64, f64)>>, ts: f64, val: f64) {
    sig.update(|buf| {
        buf.push((ts, val));
        if buf.len() > STAT_CAP {
            let excess = buf.len() - STAT_CAP;
            buf.drain(0..excess);
        }
    });
}

/// Fan a `MetricsSample` JSON object into the four Stats ring buffers.
fn push_metric_sample(
    cpu: RwSignal<Vec<(f64, f64)>>,
    mem: RwSignal<Vec<(f64, f64)>>,
    rx: RwSignal<Vec<(f64, f64)>>,
    tx: RwSignal<Vec<(f64, f64)>>,
    ts: f64,
    s: &Value,
) {
    if let Some(c) = s.get("cpu_pct").and_then(Value::as_f64) {
        push_capped(cpu, ts, c * 100.0);
    }
    if let Some(m) = s.get("mem_bytes").and_then(Value::as_f64) {
        push_capped(mem, ts, m);
    }
    if let Some(r) = s.get("net_rx").and_then(Value::as_f64) {
        push_capped(rx, ts, r);
    }
    if let Some(t) = s.get("net_tx").and_then(Value::as_f64) {
        push_capped(tx, ts, t);
    }
}

/// `window.setTimeout`-backed async sleep for the metrics poll loop.
async fn sleep_ms(ms: i32) {
    let promise = js_sys::Promise::new(&mut |resolve, _reject| {
        if let Some(win) = web_sys::window() {
            let _ = win.set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms);
        }
    });
    let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
}

/// Best-effort `navigator.clipboard.writeText`. Reached via `js_sys::Reflect`
/// so no extra `web-sys` feature (`Navigator`/`Clipboard`) is required.
fn copy_to_clipboard(text: &str) {
    let Some(win) = web_sys::window() else {
        return;
    };
    let win_val: JsValue = win.into();
    let Ok(nav) = js_sys::Reflect::get(&win_val, &JsValue::from_str("navigator")) else {
        return;
    };
    let Ok(clip) = js_sys::Reflect::get(&nav, &JsValue::from_str("clipboard")) else {
        return;
    };
    if clip.is_undefined() || clip.is_null() {
        return;
    }
    let Ok(write) = js_sys::Reflect::get(&clip, &JsValue::from_str("writeText")) else {
        return;
    };
    if let Ok(func) = write.dyn_into::<js_sys::Function>() {
        let _ = func.call1(&clip, &JsValue::from_str(text));
    }
}

fn download_text_file(filename: &str, text: &str) {
    let Some(win) = web_sys::window() else {
        return;
    };
    let Some(doc) = win.document() else {
        return;
    };
    let parts = js_sys::Array::new();
    parts.push(&JsValue::from_str(text));
    let Ok(blob) = web_sys::Blob::new_with_str_sequence(parts.as_ref()) else {
        return;
    };
    let Ok(url_ctor) = js_sys::Reflect::get(&win, &JsValue::from_str("URL")) else {
        return;
    };
    let Ok(create) = js_sys::Reflect::get(&url_ctor, &JsValue::from_str("createObjectURL")) else {
        return;
    };
    let Ok(create) = create.dyn_into::<js_sys::Function>() else {
        return;
    };
    let Ok(url) = create.call1(&url_ctor, &blob) else {
        return;
    };
    let Some(url) = url.as_string() else {
        return;
    };
    let Ok(anchor) = doc.create_element("a") else {
        revoke_object_url(&url_ctor, &url);
        return;
    };
    let _ = anchor.set_attribute("href", &url);
    let _ = anchor.set_attribute("download", filename);
    if let Some(body) = doc.body() {
        if body.append_child(&anchor).is_ok() {
            if let Ok(anchor) = anchor.dyn_into::<web_sys::HtmlElement>() {
                anchor.click();
                let _ = body.remove_child(&anchor);
            }
        }
    }
    revoke_object_url(&url_ctor, &url);
}

fn revoke_object_url(url_ctor: &JsValue, url: &str) {
    let Ok(revoke) = js_sys::Reflect::get(url_ctor, &JsValue::from_str("revokeObjectURL")) else {
        return;
    };
    if let Ok(revoke) = revoke.dyn_into::<js_sys::Function>() {
        let _ = revoke.call1(url_ctor, &JsValue::from_str(url));
    }
}

fn case_insensitive_ranges(text: &str, query: &str) -> Vec<(usize, usize)> {
    let needle = query.trim();
    if needle.is_empty() {
        return Vec::new();
    }
    let lower_text = text.to_lowercase();
    let lower_needle = needle.to_lowercase();
    if lower_needle.is_empty() {
        return Vec::new();
    }

    let mut lower_to_original = Vec::with_capacity(lower_text.len());
    for (original_idx, ch) in text.char_indices() {
        let lowered = ch.to_lowercase().to_string();
        lower_to_original.extend(std::iter::repeat_n(original_idx, lowered.len()));
    }

    let mut ranges = Vec::new();
    let mut search_from = 0;
    while let Some(relative) = lower_text[search_from..].find(&lower_needle) {
        let start_lower = search_from + relative;
        let end_lower = start_lower + lower_needle.len();
        let Some(&start) = lower_to_original.get(start_lower) else {
            break;
        };
        let end = lower_to_original
            .get(end_lower)
            .copied()
            .unwrap_or(text.len());
        if start < end && text.is_char_boundary(start) && text.is_char_boundary(end) {
            ranges.push((start, end));
        }
        search_from = end_lower;
        if search_from >= lower_text.len() {
            break;
        }
    }
    ranges
}

fn rendered_log_line(
    line: String,
    is_err: bool,
    query: &str,
    active_match: usize,
    first_match: usize,
) -> AnyView {
    let cls = if is_err {
        "log-line log-line--stderr"
    } else {
        "log-line"
    };
    let ranges = case_insensitive_ranges(&line, query);
    if ranges.is_empty() {
        return view! { <div class=cls>{line}</div> }.into_any();
    }

    let mut last = 0;
    let mut parts: Vec<AnyView> = Vec::new();
    for (idx, (start, end)) in ranges.into_iter().enumerate() {
        if start > last {
            parts.push(view! { <>{line[last..start].to_string()}</> }.into_any());
        }
        let mark_cls = if first_match + idx == active_match {
            "log-hl log-hl--active"
        } else {
            "log-hl"
        };
        parts.push(view! { <mark class=mark_cls>{line[start..end].to_string()}</mark> }.into_any());
        last = end;
    }
    if last < line.len() {
        parts.push(view! { <>{line[last..].to_string()}</> }.into_any());
    }
    view! { <div class=cls>{parts}</div> }.into_any()
}

fn scroll_into_view_center(el: &Element) {
    let opts = js_sys::Object::new();
    let _ = js_sys::Reflect::set(
        &opts,
        &JsValue::from_str("block"),
        &JsValue::from_str("center"),
    );
    if let Ok(method) = js_sys::Reflect::get(el, &JsValue::from_str("scrollIntoView")) {
        if let Ok(method) = method.dyn_into::<js_sys::Function>() {
            let _ = method.call1(el, &opts);
        }
    }
}

fn as_positive_u64(v: Option<&Value>) -> Option<u64> {
    v.and_then(Value::as_u64).filter(|n| *n > 0).or_else(|| {
        v.and_then(Value::as_i64)
            .and_then(|n| u64::try_from(n).ok())
            .filter(|n| *n > 0)
    })
}

fn inspect_memory_limit(v: &Value) -> Option<u64> {
    as_positive_u64(v.pointer("/raw/HostConfig/Memory"))
        .or_else(|| as_positive_u64(v.pointer("/raw/HostConfig/MemoryLimit")))
}

fn inspect_cpu_limit(v: &Value) -> Option<f64> {
    v.pointer("/raw/HostConfig/NanoCpus")
        .and_then(Value::as_f64)
        .filter(|n| *n > 0.0)
        .map(|n| n / 1_000_000_000.0)
}

fn inspect_pids_limit(v: &Value) -> Option<i64> {
    v.pointer("/raw/HostConfig/PidsLimit")
        .and_then(Value::as_i64)
        .filter(|n| *n >= 0)
}

fn inspect_restart_policy(v: &Value) -> Option<String> {
    v.pointer("/raw/HostConfig/RestartPolicy/Name")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(String::from)
}

fn optional_text<T: ToString>(value: Option<T>) -> String {
    value
        .map(|v| v.to_string())
        .unwrap_or_else(|| "—".to_string())
}

fn parse_optional_u64(input: &str, label: &str) -> Result<Option<u64>, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    trimmed
        .parse::<u64>()
        .map(Some)
        .map_err(|_| format!("{label} must be a whole number"))
}

fn parse_optional_i64(input: &str, label: &str) -> Result<Option<i64>, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    trimmed
        .parse::<i64>()
        .map(Some)
        .map_err(|_| format!("{label} must be a whole number"))
}

fn parse_optional_cpus(input: &str) -> Result<Option<f64>, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let cpus = trimmed
        .parse::<f64>()
        .map_err(|_| "cpus must be a number".to_string())?;
    if !cpus.is_finite() || cpus <= 0.0 {
        return Err("cpus must be greater than 0".to_string());
    }
    Ok(Some(cpus))
}

#[component]
pub fn ContainerDetail() -> impl IntoView {
    let auth = use_context::<AuthToken>().expect("AuthToken context provided by AppRoot");
    let drawer = use_context::<DrawerState>().expect("DrawerState context provided by AppRoot");
    let target = Signal::derive(move || drawer.0.get());

    let tab = RwSignal::new(DetailTab::Overview);

    // Shared inspect record (Overview renders it; Stats/Terminal read run state).
    // `None` = loading/closed, `Some(Ok)` = record, `Some(Err)` = fetch error.
    let inspect: RwSignal<Option<Result<Value, String>>> = RwSignal::new(None);
    let live_mem_limit: RwSignal<Option<u64>> = RwSignal::new(None);

    let memory_mib = RwSignal::new(String::new());
    let cpus_input = RwSignal::new(String::new());
    let pids_input = RwSignal::new(String::new());
    let restart_policy = RwSignal::new(String::new());
    let update_status: RwSignal<Option<Result<String, String>>> = RwSignal::new(None);
    let update_busy = RwSignal::new(false);

    // Reset the tab back to Overview whenever a different container is opened.
    Effect::new(move |prev: Option<Option<String>>| {
        let id = target.get();
        if prev.flatten() != id {
            tab.set(DetailTab::Overview);
            live_mem_limit.set(None);
            memory_mib.set(String::new());
            cpus_input.set(String::new());
            pids_input.set(String::new());
            restart_policy.set(String::new());
            update_status.set(None);
            update_busy.set(false);
        }
        id
    });

    // Fetch the inspect record on every container change.
    Effect::new(move |_| {
        let Some(id) = target.get() else {
            inspect.set(None);
            return;
        };
        let Some(tok) = auth.0.get_untracked() else {
            inspect.set(Some(Err(
                "set a bearer token to load container detail".into()
            )));
            return;
        };
        inspect.set(None);
        spawn_local(async move {
            inspect.set(Some(fetch_container_inspect(&id, &tok).await));
        });
    });

    // Fetch one latest sample for `mem_limit`, which is sometimes fresher than
    // the inspect record and is also shown in the resource-limit editor.
    Effect::new(move |_| {
        let Some(id) = target.get() else {
            live_mem_limit.set(None);
            return;
        };
        let Some(tok) = auth.0.get_untracked() else {
            live_mem_limit.set(None);
            return;
        };
        spawn_local(async move {
            if let Ok(sample) = fetch_metrics_latest(&id, &tok).await {
                live_mem_limit.set(sample.get("mem_limit").and_then(Value::as_u64));
            }
        });
    });

    let running = Signal::derive(move || match inspect.get() {
        Some(Ok(v)) => v.get("state").and_then(Value::as_str) == Some("running"),
        _ => false,
    });

    // ---- Logs state ------------------------------------------------------
    let log_lines: RwSignal<Vec<(String, bool)>> = RwSignal::new(Vec::new());
    let logs_status: RwSignal<Option<String>> = RwSignal::new(None);
    let follow = RwSignal::new(false);
    let stick_bottom = RwSignal::new(true);
    let logs_loaded_for: RwSignal<Option<String>> = RwSignal::new(None);
    let log_query = RwSignal::new(String::new());
    let active_log_match = RwSignal::new(0usize);
    let log_ref = NodeRef::<leptos::html::Div>::new();

    // Tail fetch — runs the first time the Logs tab is opened for a container.
    Effect::new(move |_| {
        if tab.get() != DetailTab::Logs {
            return;
        }
        let Some(id) = target.get() else {
            return;
        };
        if logs_loaded_for.get_untracked().as_deref() == Some(id.as_str()) {
            return;
        }
        logs_loaded_for.set(Some(id.clone()));
        log_lines.set(Vec::new());
        let Some(tok) = auth.0.get_untracked() else {
            logs_status.set(Some("set a bearer token to load logs".into()));
            return;
        };
        logs_status.set(Some("loading…".into()));
        spawn_local(async move {
            match fetch_container_logs(&id, Some(500), None, &tok).await {
                Ok(v) => {
                    let stdout = v.get("stdout").and_then(Value::as_str).unwrap_or_default();
                    let stderr = v.get("stderr").and_then(Value::as_str).unwrap_or_default();
                    let mut lines: Vec<(String, bool)> = split_log_lines(stdout)
                        .into_iter()
                        .map(|l| (l, false))
                        .collect();
                    lines.extend(split_log_lines(stderr).into_iter().map(|l| (l, true)));
                    log_lines.set(lines);
                    logs_status.set(None);
                }
                Err(e) => logs_status.set(Some(e)),
            }
        });
    });

    // Follow stream — subscribe once, gated on the live `follow` flag + target.
    Effect::new(move |prev: Option<()>| {
        if prev.is_some() {
            return;
        }
        subscribe("container", move |notif| {
            if !follow.get_untracked() {
                return;
            }
            if !event_is_log_kind(&notif) {
                return;
            }
            let Some(cur) = target.get_untracked() else {
                return;
            };
            if !event_matches_container(&notif, &cur) {
                return;
            }
            let Some(details) = notif.pointer("/params/details") else {
                return;
            };
            if let Some(line) = extract_log_line(details) {
                let is_err = log_line_is_stderr(&line);
                log_lines.update(|buf| {
                    buf.push((line, is_err));
                    if buf.len() > LOG_CAP {
                        let excess = buf.len() - LOG_CAP;
                        buf.drain(0..excess);
                    }
                });
            }
        });
    });

    // When follow is switched on, ask the daemon to start emitting Log events.
    Effect::new(move |_| {
        if !follow.get() {
            return;
        }
        if tab.get_untracked() != DetailTab::Logs {
            return;
        }
        let Some(id) = target.get_untracked() else {
            return;
        };
        spawn_local(async move {
            let _ = send_rpc(
                "container_logs_stream",
                json!({ "container_id": id, "follow": true }),
            )
            .await;
        });
    });

    // Autoscroll the log viewport to the bottom while the user hasn't scrolled up.
    Effect::new(move |_| {
        let _ = log_lines.get();
        if !stick_bottom.get_untracked() {
            return;
        }
        if let Some(node) = log_ref.get() {
            if let Some(el) = (*node).dyn_ref::<Element>() {
                el.set_scroll_top(el.scroll_height());
            }
        }
    });

    let log_match_count = Signal::derive(move || {
        let query = log_query.get();
        if query.trim().is_empty() {
            return 0;
        }
        log_lines
            .get()
            .iter()
            .map(|(line, _)| case_insensitive_ranges(line, &query).len())
            .sum::<usize>()
    });

    Effect::new(move |_| {
        let total = log_match_count.get();
        if total == 0 || active_log_match.get() >= total {
            active_log_match.set(0);
        }
    });

    Effect::new(move |_| {
        let _ = active_log_match.get();
        let _ = log_query.get();
        let _ = log_lines.get();
        if log_match_count.get_untracked() == 0 {
            return;
        }
        if let Some(node) = log_ref.get() {
            if let Some(el) = (*node).dyn_ref::<Element>() {
                if let Ok(Some(active)) = el.query_selector(".log-hl--active") {
                    scroll_into_view_center(&active);
                }
            }
        }
    });

    // ---- Stats state -----------------------------------------------------
    let cpu: RwSignal<Vec<(f64, f64)>> = RwSignal::new(Vec::new());
    let mem: RwSignal<Vec<(f64, f64)>> = RwSignal::new(Vec::new());
    let net_rx: RwSignal<Vec<(f64, f64)>> = RwSignal::new(Vec::new());
    let net_tx: RwSignal<Vec<(f64, f64)>> = RwSignal::new(Vec::new());
    let stats_err: RwSignal<Option<String>> = RwSignal::new(None);
    // Generation token — bumping it cancels the running poll loop.
    let poll_gen = RwSignal::new(0u32);

    Effect::new(move |_| {
        let is_stats = tab.get() == DetailTab::Stats;
        let id = target.get();
        poll_gen.update(|g| *g = g.wrapping_add(1));
        let my_gen = poll_gen.get_untracked();
        if !is_stats {
            return;
        }
        let Some(cid) = id else {
            return;
        };
        let Some(tok) = auth.0.get_untracked() else {
            stats_err.set(Some("set a bearer token to load metrics".into()));
            return;
        };
        cpu.set(Vec::new());
        mem.set(Vec::new());
        net_rx.set(Vec::new());
        net_tx.set(Vec::new());
        stats_err.set(None);
        spawn_local(async move {
            match fetch_metrics_history(&cid, None, &tok).await {
                Ok(Value::Array(arr)) => {
                    for s in &arr {
                        if let Some(limit) = s.get("mem_limit").and_then(Value::as_u64) {
                            live_mem_limit.set(Some(limit));
                        }
                        push_metric_sample(cpu, mem, net_rx, net_tx, sample_ts(s), s);
                    }
                }
                Ok(_) => {}
                Err(e) => stats_err.set(Some(e)),
            }
            loop {
                if poll_gen.get_untracked() != my_gen {
                    break;
                }
                if let Ok(m) = fetch_metrics_latest(&cid, &tok).await {
                    if m.is_object() {
                        if let Some(limit) = m.get("mem_limit").and_then(Value::as_u64) {
                            live_mem_limit.set(Some(limit));
                        }
                        push_metric_sample(
                            cpu,
                            mem,
                            net_rx,
                            net_tx,
                            js_sys::Date::now() / 1000.0,
                            &m,
                        );
                    }
                }
                sleep_ms(2_000).await;
            }
        });
    });

    // Stop the poll loop when the drawer body unmounts.
    on_cleanup(move || poll_gen.update(|g| *g = g.wrapping_add(1)));

    // ---- Terminal props (fixed /bin/sh, reusing PtyTerminal) -------------
    let term_status: RwSignal<Option<String>> = RwSignal::new(None);
    let term_attached = RwSignal::new(false);
    let sh_cmd = Signal::derive(|| String::from("/bin/sh"));
    let empty_sig = Signal::derive(String::new);
    let term_active = Signal::derive(move || running.get());

    let submit_limits = Callback::new(move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if update_busy.get_untracked() {
            return;
        }
        let Some(id) = target.get_untracked() else {
            update_status.set(Some(Err("open a container first".to_string())));
            return;
        };
        let Some(tok) = auth.0.get_untracked() else {
            update_status.set(Some(Err(
                "set a bearer token before updating limits".to_string()
            )));
            return;
        };

        let memory_mib_parsed = match parse_optional_u64(&memory_mib.get_untracked(), "memory MiB")
        {
            Ok(v) => v,
            Err(e) => {
                update_status.set(Some(Err(e)));
                return;
            }
        };
        let memory_bytes = match memory_mib_parsed {
            Some(mib) => match mib.checked_mul(1024 * 1024) {
                Some(bytes) => Some(bytes),
                None => {
                    update_status.set(Some(Err("memory MiB is too large".to_string())));
                    return;
                }
            },
            None => None,
        };
        let cpus = match parse_optional_cpus(&cpus_input.get_untracked()) {
            Ok(v) => v,
            Err(e) => {
                update_status.set(Some(Err(e)));
                return;
            }
        };
        let pids_limit = match parse_optional_i64(&pids_input.get_untracked(), "pids limit") {
            Ok(v) => v,
            Err(e) => {
                update_status.set(Some(Err(e)));
                return;
            }
        };
        if pids_limit.is_some_and(|n| n < -1) {
            update_status.set(Some(Err("pids limit must be -1 or greater".to_string())));
            return;
        }
        let restart = restart_policy.get_untracked();
        let restart = restart.trim();
        let restart = (!restart.is_empty()).then_some(restart);

        if memory_bytes.is_none() && cpus.is_none() && pids_limit.is_none() && restart.is_none() {
            update_status.set(Some(Err("enter at least one limit change".to_string())));
            return;
        }

        let body = build_container_update_body(memory_bytes, None, cpus, pids_limit, restart);
        update_busy.set(true);
        update_status.set(None);
        spawn_local(async move {
            match update_container_limits(&id, body, &tok).await {
                Ok(v) => {
                    let applied = v
                        .get("applied")
                        .and_then(Value::as_array)
                        .map(|a| {
                            a.iter()
                                .filter_map(Value::as_str)
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| "no fields".to_string());
                    update_status.set(Some(Ok(format!("Applied: {applied}"))));
                    memory_mib.set(String::new());
                    cpus_input.set(String::new());
                    pids_input.set(String::new());
                    restart_policy.set(String::new());
                    inspect.set(Some(fetch_container_inspect(&id, &tok).await));
                }
                Err(e) => update_status.set(Some(Err(e))),
            }
            update_busy.set(false);
        });
    });

    // Derived throughput (cumulative counters → per-interval deltas).
    let rx_series = Signal::derive(move || cumulative_to_delta(&net_rx.get()));
    let tx_series = Signal::derive(move || cumulative_to_delta(&net_tx.get()));

    // ---- Header (name + short-id + state chip) ---------------------------
    let header = move || match inspect.get() {
        Some(Ok(v)) => {
            let name = v
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("(unnamed)")
                .to_string();
            let id = v
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let state = v
                .get("state")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            let chip = state_chip_class(&state);
            view! {
                <div class="detail-head">
                    <span class="detail-head__name">{name}</span>
                    <span class="mono detail-head__id">{short_id(&id)}</span>
                    <span class=chip>{state}</span>
                </div>
            }
            .into_any()
        }
        Some(Err(e)) => view! {
            <div class="error-state"><span>{e}</span></div>
        }
        .into_any(),
        None => view! { <div class="loading-inline">"Loading…"</div> }.into_any(),
    };

    let scroll_handler = move |ev: web_sys::Event| {
        let Some(t) = ev.target() else {
            return;
        };
        if let Ok(el) = t.dyn_into::<Element>() {
            let at_bottom = f64::from(el.scroll_top()) + f64::from(el.client_height())
                >= f64::from(el.scroll_height()) - 4.0;
            stick_bottom.set(at_bottom);
        }
    };

    let jump_bottom = move |_| {
        stick_bottom.set(true);
        if let Some(node) = log_ref.get_untracked() {
            if let Some(el) = (*node).dyn_ref::<Element>() {
                el.set_scroll_top(el.scroll_height());
            }
        }
    };

    let current_log_text = move || {
        log_lines
            .get_untracked()
            .into_iter()
            .map(|(line, _)| line)
            .collect::<Vec<_>>()
            .join("\n")
    };

    let download_logs = move |_| {
        let id = target
            .get_untracked()
            .unwrap_or_else(|| "unknown".to_string());
        let filename = format!("container-{}-logs.txt", short_id(&id));
        download_text_file(&filename, &current_log_text());
    };

    let previous_match = move |_| {
        let total = log_match_count.get_untracked();
        if total == 0 {
            return;
        }
        active_log_match.update(|idx| {
            *idx = if *idx == 0 { total - 1 } else { *idx - 1 };
        });
    };

    let next_match = move |_| {
        let total = log_match_count.get_untracked();
        if total == 0 {
            return;
        }
        active_log_match.update(|idx| {
            *idx = (*idx + 1) % total;
        });
    };

    // ---- Tab body --------------------------------------------------------
    let body = move || {
        match tab.get() {
        DetailTab::Overview => match inspect.get() {
            None => view! { <div class="loading-inline">"Loading inspect…"</div> }.into_any(),
            Some(Err(e)) => view! { <div class="error-state"><span>{e}</span></div> }.into_any(),
            Some(Ok(v)) => overview_pane(
                &v,
                LimitsEditorState {
                    live_mem_limit,
                    memory_mib,
                    cpus_input,
                    pids_input,
                    restart_policy,
                    update_status,
                    update_busy,
                    submit_limits,
                },
            ),
        },
        DetailTab::Logs => view! {
            <div class="drawer-pane">
                <div class="page-actions">
                    <label class="modal-inline">
                        <input
                            class="checkbox"
                            type="checkbox"
                            prop:checked=move || follow.get()
                            on:change=move |_| follow.update(|f| *f = !*f)
                        />
                        " follow (live tail)"
                    </label>
                    <button type="button" class="btn btn--sm" on:click=jump_bottom>
                        "Jump to bottom"
                    </button>
                    {move || logs_status.get().map(|m| view! { <span class="status">{m}</span> })}
                </div>
                <div class="logs-toolbar">
                    <span class="log-search">
                        <input
                            class="log-search__input"
                            type="search"
                            placeholder="Search logs"
                            prop:value=move || log_query.get()
                            on:input=move |ev| {
                                log_query.set(event_target_value(&ev));
                                active_log_match.set(0);
                            }
                        />
                        <span class="log-search__count">
                            {move || {
                                let total = log_match_count.get();
                                if total == 0 {
                                    "0/0".to_string()
                                } else {
                                    format!("{}/{}", active_log_match.get() + 1, total)
                                }
                            }}
                        </span>
                        <span class="log-search__nav">
                            <button
                                type="button"
                                class="btn btn--sm"
                                prop:disabled=move || log_match_count.get() == 0
                                on:click=previous_match
                            >
                                "Prev"
                            </button>
                            <button
                                type="button"
                                class="btn btn--sm"
                                prop:disabled=move || log_match_count.get() == 0
                                on:click=next_match
                            >
                                "Next"
                            </button>
                        </span>
                    </span>
                    <button
                        type="button"
                        class="btn btn--sm log-download"
                        prop:disabled=move || log_lines.get().is_empty()
                        on:click=download_logs
                    >
                        "Download"
                    </button>
                </div>
                {move || {
                    let lines = log_lines.get();
                    if lines.is_empty() && logs_status.get().is_none() {
                        view! {
                            <div class="empty-state">
                                <span class="empty-state__title">"No output yet."</span>
                            </div>
                        }
                        .into_any()
                    } else {
                        view! {
                            <div class="log-block" node_ref=log_ref on:scroll=scroll_handler>
                                {{
                                    let query = log_query.get();
                                    let active = active_log_match.get();
                                    let mut seen = 0usize;
                                    lines
                                        .into_iter()
                                        .map(|(line, is_err)| {
                                            let first = seen;
                                            seen += case_insensitive_ranges(&line, &query).len();
                                            rendered_log_line(line, is_err, &query, active, first)
                                        })
                                        .collect_view()
                                }}
                            </div>
                        }
                        .into_any()
                    }
                }}
            </div>
        }
        .into_any(),
        DetailTab::Terminal => {
            if running.get() {
                view! {
                    <div class="drawer-pane">
                        {move || term_status.get().map(|m| view! { <p class="status">{m}</p> })}
                        <PtyTerminal
                            target=target
                            active=term_active
                            command=sh_cmd
                            cols=empty_sig
                            rows=empty_sig
                            status=term_status
                            attached=term_attached
                        />
                    </div>
                }
                .into_any()
            } else {
                view! {
                    <div class="empty-state">
                        <span class="empty-state__title">"Container is not running"</span>
                        <span class="empty-state__hint">
                            "Start it to open an interactive terminal."
                        </span>
                    </div>
                }
                .into_any()
            }
        }
        DetailTab::Stats => view! {
            <div class="drawer-pane">
                {move || stats_err.get().map(|m| view! { <div class="error-state"><span>{m}</span></div> })}
                {move || {
                    if !cpu.get().is_empty() {
                        None
                    } else if running.get() {
                        // Container is running but the collector hasn't produced a
                        // sample yet — distinct from "not running" so users don't
                        // think metrics are broken while they warm up.
                        Some(
                            view! {
                                <div class="empty-state">
                                    <span class="empty-state__title">"Waiting for the first sample…"</span>
                                    <span class="empty-state__hint">
                                        "Samples appear within seconds of the daemon seeing the container run."
                                    </span>
                                </div>
                            }
                            .into_any(),
                        )
                    } else {
                        Some(
                            view! {
                                <div class="empty-state">
                                    <span class="empty-state__hint">
                                        "Metrics available only while running."
                                    </span>
                                </div>
                            }
                            .into_any(),
                        )
                    }
                }}
                <LineChart data=cpu title="CPU" value_fmt=pct_fmt/>
                <AreaChart data=mem title="Memory" value_fmt=bytes_fmt/>
                <TwoSeriesChart
                    series_a=rx_series
                    series_b=tx_series
                    title="Network"
                    label_a="rx"
                    label_b="tx"
                    value_fmt=rate_fmt
                />
            </div>
        }
        .into_any(),
        DetailTab::Inspect => match inspect.get() {
            None => view! { <div class="loading-inline">"Loading inspect…"</div> }.into_any(),
            Some(Err(e)) => view! { <div class="error-state"><span>{e}</span></div> }.into_any(),
            Some(Ok(v)) => {
                let raw = v.get("raw").filter(|r| !r.is_null()).unwrap_or(&v);
                let pretty =
                    serde_json::to_string_pretty(raw).unwrap_or_else(|_| raw.to_string());
                let for_copy = pretty.clone();
                view! {
                    <div class="drawer-pane">
                        <div class="page-actions">
                            <button
                                type="button"
                                class="btn btn--sm"
                                on:click=move |_| copy_to_clipboard(&for_copy)
                            >
                                "Copy"
                            </button>
                        </div>
                        <pre class="code-block">{pretty}</pre>
                    </div>
                }
                .into_any()
            }
        },
    }
    };

    view! {
        <div class="container-detail">
            {header}
            <nav class="drawer-tabs">
                {DetailTab::ALL
                    .into_iter()
                    .map(|t| {
                        let is_terminal = matches!(t, DetailTab::Terminal);
                        let cls = move || {
                            if tab.get() == t {
                                "drawer-tab active"
                            } else {
                                "drawer-tab"
                            }
                        };
                        let disabled = move || is_terminal && !running.get();
                        view! {
                            <button
                                type="button"
                                class=cls
                                prop:disabled=disabled
                                title=t.label()
                                on:click=move |_| tab.set(t)
                            >
                                {t.label()}
                            </button>
                        }
                    })
                    .collect_view()}
            </nav>
            <div class="drawer-tab-body">{body}</div>
        </div>
    }
}

/// Render the healthcheck section: config (test/interval/timeout/retries/
/// start-period) + current health-state chip, sourced entirely from
/// `raw.Config.Healthcheck` / `raw.State.Health` (the verbatim `podman
/// inspect` object — `ContainerInspect` does not model healthcheck fields).
/// Falls back to the top-level `status` string's `(healthy)`/`(unhealthy)`/
/// `(starting)` suffix when `raw.State.Health.Status` is absent (container
/// never ran, or podman omitted the field). Renders a clean empty-state when
/// the container defines no `HEALTHCHECK` at all.
fn healthcheck_section(v: &Value) -> AnyView {
    let raw = v.get("raw");
    let hc = raw.and_then(|r| r.pointer("/Config/Healthcheck"));
    let test = hc.and_then(|h| h.get("Test")).and_then(Value::as_array);
    let has_test = test.map(|a| !a.is_empty()).unwrap_or(false);

    if !has_test {
        return view! {
            <div class="empty-state">
                <span class="empty-state__title">"No healthcheck configured"</span>
                <span class="empty-state__hint">
                    "This container's image does not define a HEALTHCHECK."
                </span>
            </div>
        }
        .into_any();
    }

    let test_cmd = test
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join(" ");

    let status_word = raw
        .and_then(|r| r.pointer("/State/Health/Status"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            let status = v.get("status").and_then(Value::as_str).unwrap_or("");
            if status.contains("(healthy)") {
                Some("healthy".to_string())
            } else if status.contains("(unhealthy)") {
                Some("unhealthy".to_string())
            } else if status.contains("(starting)") {
                Some("starting".to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".to_string());

    let chip_class = match status_word.as_str() {
        "healthy" => "chip chip--running",
        "unhealthy" => "chip chip--error",
        "starting" => "chip chip--warn",
        _ => "chip chip--neutral",
    };

    let ns_to_secs = |ns: i64| format!("{:.1}s", ns as f64 / 1_000_000_000.0);
    let interval = hc
        .and_then(|h| h.get("Interval"))
        .and_then(Value::as_i64)
        .map(ns_to_secs)
        .unwrap_or_else(|| "—".to_string());
    let timeout = hc
        .and_then(|h| h.get("Timeout"))
        .and_then(Value::as_i64)
        .map(ns_to_secs)
        .unwrap_or_else(|| "—".to_string());
    let retries = hc
        .and_then(|h| h.get("Retries"))
        .and_then(Value::as_i64)
        .map(|n| n.to_string())
        .unwrap_or_else(|| "—".to_string());
    let start_period = hc
        .and_then(|h| h.get("StartPeriod"))
        .and_then(Value::as_i64)
        .filter(|ns| *ns != 0)
        .map(ns_to_secs)
        .unwrap_or_else(|| "—".to_string());

    view! {
        <div class="detail-grid">
            <div class="detail-grid__key">"Health"</div>
            <div class="detail-grid__val"><span class=chip_class>{status_word}</span></div>

            <div class="detail-grid__key">"Test command"</div>
            <div class="detail-grid__val"><span class="mono">{test_cmd}</span></div>

            <div class="detail-grid__key">"Interval"</div>
            <div class="detail-grid__val"><span class="mono">{interval}</span></div>

            <div class="detail-grid__key">"Timeout"</div>
            <div class="detail-grid__val"><span class="mono">{timeout}</span></div>

            <div class="detail-grid__key">"Retries"</div>
            <div class="detail-grid__val"><span class="mono">{retries}</span></div>

            <div class="detail-grid__key">"Start period"</div>
            <div class="detail-grid__val"><span class="mono">{start_period}</span></div>
        </div>
    }
    .into_any()
}

/// Bundles the `Edit limits` form's signals + submit callback into one value
/// so `overview_pane` takes two arguments instead of nine (clippy
/// `too_many_arguments`). All fields are `Copy` (leptos signals / callbacks),
/// so this struct is cheap to construct and pass by value.
#[derive(Clone, Copy)]
struct LimitsEditorState {
    live_mem_limit: RwSignal<Option<u64>>,
    memory_mib: RwSignal<String>,
    cpus_input: RwSignal<String>,
    pids_input: RwSignal<String>,
    restart_policy: RwSignal<String>,
    update_status: RwSignal<Option<Result<String, String>>>,
    update_busy: RwSignal<bool>,
    submit_limits: Callback<leptos::ev::SubmitEvent>,
}

/// Render the Overview detail-grid from an inspect record.
fn overview_pane(v: &Value, limits: LimitsEditorState) -> AnyView {
    let LimitsEditorState {
        live_mem_limit,
        memory_mib,
        cpus_input,
        pids_input,
        restart_policy,
        update_status,
        update_busy,
        submit_limits,
    } = limits;
    let image = v
        .get("image")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let image_id = v
        .get("image_id")
        .and_then(Value::as_str)
        .map(short_id)
        .unwrap_or_default();
    let state = v
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let chip = state_chip_class(&state);
    let created = v
        .get("created")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let command = v
        .get("command")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    let args = v
        .get("args")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    let cmd_line = if args.is_empty() {
        command
    } else {
        format!("{command} {args}")
    };

    let ip = v
        .pointer("/network_settings/ip_address")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let ports_raw: Vec<String> = v
        .pointer("/network_settings/ports")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let port_links = parse_published_ports(&ports_raw);
    // Published (host-mapped tcp) ports render as clickable chips; exposed-only
    // / udp ports render as muted text — they aren't reachable via a link.
    let ports_view = if port_links.is_empty() {
        view! { <span class="cell-muted">"—"</span> }.into_any()
    } else {
        port_links
            .into_iter()
            .map(|pl| match pl.href {
                Some(href) => view! {
                    <a class="badge badge--info mono" href=href target="_blank" rel="noreferrer">{pl.display}</a>
                    " "
                }
                .into_any(),
                None => view! { <span class="cell-muted mono">{pl.display}</span>" " }.into_any(),
            })
            .collect_view()
            .into_any()
    };

    let mounts = v
        .get("mounts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mounts_view = if mounts.is_empty() {
        view! { <span class="cell-muted">"—"</span> }.into_any()
    } else {
        mounts
            .into_iter()
            .map(|m| {
                let src = m
                    .get("source")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let dst = m
                    .get("destination")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let ro = m.get("read_only").and_then(Value::as_bool).unwrap_or(false);
                view! {
                    <div class="mono">
                        {format!("{src} \u{2192} {dst}")}
                        {ro.then(|| view! { " "<span class="chip chip--neutral">"ro"</span> })}
                    </div>
                }
            })
            .collect_view()
            .into_any()
    };

    let env = v
        .get("env")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let env_count = env.len();
    let env_text: String = env
        .iter()
        .map(|(k, val)| format!("{k}={}\n", val.as_str().unwrap_or("")))
        .collect();

    let image_id_view = (!image_id.is_empty())
        .then(|| view! { " "<span class="mono cell-muted">{image_id}</span> });

    let inspect_mem_limit = inspect_memory_limit(v);
    let current_memory =
        move || optional_text(live_mem_limit.get().or(inspect_mem_limit).map(format_bytes));
    let current_cpus = inspect_cpu_limit(v).map(|n| n.to_string());
    let current_pids = inspect_pids_limit(v);
    let current_restart = inspect_restart_policy(v);

    view! {
        <div class="drawer-pane">
            <div class="detail-grid">
                <div class="detail-grid__key">"State"</div>
                <div class="detail-grid__val"><span class=chip>{state}</span></div>

                <div class="detail-grid__key">"Image"</div>
                <div class="detail-grid__val">
                    <span class="mono">{image}</span>{image_id_view}
                </div>

                <div class="detail-grid__key">"Command"</div>
                <div class="detail-grid__val"><span class="mono">{cmd_line}</span></div>

                <div class="detail-grid__key">"Created"</div>
                <div class="detail-grid__val"><span class="mono">{created}</span></div>

                <div class="detail-grid__key">"IP"</div>
                <div class="detail-grid__val">
                    <span class="mono">{if ip.is_empty() { "—".to_string() } else { ip }}</span>
                </div>

                <div class="detail-grid__key">"Ports"</div>
                <div class="detail-grid__val">{ports_view}</div>

                <div class="detail-grid__key">"Mounts"</div>
                <div class="detail-grid__val">{mounts_view}</div>

                <div class="detail-grid__key">"Env"</div>
                <div class="detail-grid__val">
                    <details>
                        <summary>{format!("{env_count} variable(s)")}</summary>
                        <pre class="code-block">{env_text}</pre>
                    </details>
                </div>
            </div>
            <div class="section-title">"Healthcheck"</div>
            {healthcheck_section(v)}
            <div class="section-title">"Edit limits"</div>
            <div class="detail-grid">
                <div class="detail-grid__key">"Memory"</div>
                <div class="detail-grid__val"><span class="mono">{current_memory}</span></div>

                <div class="detail-grid__key">"CPUs"</div>
                <div class="detail-grid__val"><span class="mono">{optional_text(current_cpus)}</span></div>

                <div class="detail-grid__key">"PIDs"</div>
                <div class="detail-grid__val"><span class="mono">{optional_text(current_pids)}</span></div>

                <div class="detail-grid__key">"Restart"</div>
                <div class="detail-grid__val"><span class="mono">{optional_text(current_restart)}</span></div>
            </div>
            <form on:submit=move |ev| submit_limits.run(ev)>
                <div class="modal-form">
                    <div class="field-group">
                        <label for="limit-memory-mib">"Memory MiB"</label>
                        <input
                            id="limit-memory-mib"
                            class="input"
                            type="number"
                            min="0"
                            prop:value=move || memory_mib.get()
                            on:input=move |ev| memory_mib.set(event_target_value(&ev))
                        />
                    </div>
                    <div class="field-group">
                        <label for="limit-cpus">"CPUs"</label>
                        <input
                            id="limit-cpus"
                            class="input"
                            type="number"
                            min="0"
                            step="0.1"
                            prop:value=move || cpus_input.get()
                            on:input=move |ev| cpus_input.set(event_target_value(&ev))
                        />
                    </div>
                    <div class="field-group">
                        <label for="limit-pids">"PIDs limit"</label>
                        <input
                            id="limit-pids"
                            class="input"
                            type="number"
                            min="-1"
                            prop:value=move || pids_input.get()
                            on:input=move |ev| pids_input.set(event_target_value(&ev))
                        />
                    </div>
                    <div class="field-group">
                        <label for="limit-restart">"Restart policy"</label>
                        <select
                            id="limit-restart"
                            class="select"
                            prop:value=move || restart_policy.get()
                            on:change=move |ev| restart_policy.set(event_target_value(&ev))
                        >
                            <option value="">"Leave unchanged"</option>
                            <option value="no">"no"</option>
                            <option value="on-failure">"on-failure"</option>
                            <option value="always">"always"</option>
                            <option value="unless-stopped">"unless-stopped"</option>
                        </select>
                    </div>
                    <div class="page-actions">
                        <button
                            type="submit"
                            class="btn btn--sm btn--primary"
                            prop:disabled=move || update_busy.get()
                        >
                            {move || if update_busy.get() { "Applying…" } else { "Apply" }}
                        </button>
                        {move || update_status.get().map(|result| match result {
                            Ok(message) => view! { <span class="status">{message}</span> }.into_any(),
                            Err(message) => view! { <span class="error-state"><span>{message}</span></span> }.into_any(),
                        })}
                    </div>
                </div>
            </form>
        </div>
    }
    .into_any()
}
