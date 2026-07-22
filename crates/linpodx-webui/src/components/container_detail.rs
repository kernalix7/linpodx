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
//!     [`crate::helpers::parse_published_ports`]).
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
    fetch_container_inspect, fetch_container_logs, fetch_metrics_history, fetch_metrics_latest,
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

#[component]
pub fn ContainerDetail() -> impl IntoView {
    let auth = use_context::<AuthToken>().expect("AuthToken context provided by AppRoot");
    let drawer = use_context::<DrawerState>().expect("DrawerState context provided by AppRoot");
    let target = Signal::derive(move || drawer.0.get());

    let tab = RwSignal::new(DetailTab::Overview);

    // Shared inspect record (Overview renders it; Stats/Terminal read run state).
    // `None` = loading/closed, `Some(Ok)` = record, `Some(Err)` = fetch error.
    let inspect: RwSignal<Option<Result<Value, String>>> = RwSignal::new(None);

    // Reset the tab back to Overview whenever a different container is opened.
    Effect::new(move |prev: Option<Option<String>>| {
        let id = target.get();
        if prev.flatten() != id {
            tab.set(DetailTab::Overview);
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

    // ---- Tab body --------------------------------------------------------
    let body = move || {
        match tab.get() {
        DetailTab::Overview => match inspect.get() {
            None => view! { <div class="loading-inline">"Loading inspect…"</div> }.into_any(),
            Some(Err(e)) => view! { <div class="error-state"><span>{e}</span></div> }.into_any(),
            Some(Ok(v)) => overview_pane(&v),
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
                                {lines
                                    .into_iter()
                                    .map(|(line, is_err)| {
                                        let cls = if is_err {
                                            "log-line log-line--stderr"
                                        } else {
                                            "log-line"
                                        };
                                        view! { <div class=cls>{line}</div> }
                                    })
                                    .collect_view()}
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

/// Render the Overview detail-grid from an inspect record.
fn overview_pane(v: &Value) -> AnyView {
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
        </div>
    }
    .into_any()
}
