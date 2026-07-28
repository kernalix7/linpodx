//! Phase 17 Stream C — TOFU pin-store status card for the Web UI.
//!
//! Reads `daemon_pin_client_tofu_expiry_status` via JSON-RPC, renders a
//! countdown card with a red `.expired` modifier when the window has elapsed,
//! and provides a "Set expiry" input that parses via the shared helper before
//! firing `daemon_pin_client_tofu_expiry_set`.
//!
//! Below the status card, a filterable table lists the actually-pinned
//! clients. Vision-triage fix (2026-07): this now prefers
//! `GET /api/v1/daemon/pinned-clients` (added alongside this fix, backed by
//! the existing `Method::DaemonPinClientList` dispatch arm) and falls back to
//! the `daemon_pin_client_list` JSON-RPC method for daemons running an older
//! build without that route — same defensive pattern as `plugins.rs`.
//! Renders its own `<table>` rather than `ListTable`, following the same
//! pattern as `pods.rs` / `stacks.rs`.

use leptos::prelude::*;
use serde_json::Value;
use wasm_bindgen_futures::spawn_local;

use super::icons::Icon;
use super::illustrations::EmptySpot;
use crate::api_client::{build_tofu_expiry_body, paths};
use crate::app::AuthToken;
use crate::helpers::{
    humanize_timestamp, parse_tofu_expiry, short_id, tofu_countdown_label, tofu_is_expired,
};
use crate::ws::{fetch_list, send_rpc};

#[derive(Clone, Debug)]
struct TofuStatus {
    enabled: bool,
    max_age_secs: Option<u64>,
    enabled_at: Option<i64>,
}

impl TofuStatus {
    fn from_value(v: &Value) -> Option<Self> {
        let obj = v.as_object()?;
        Some(Self {
            enabled: obj
                .get("enabled")
                .and_then(|x| x.as_bool())
                .unwrap_or(false),
            max_age_secs: obj.get("max_age_secs").and_then(|x| x.as_u64()),
            enabled_at: obj.get("enabled_at").and_then(|x| x.as_i64()),
        })
    }
}

/// One row of `DaemonPinClientListResponse` (`Vec<PinnedClientSummary>` on
/// the daemon side — `fingerprint` / `label` / `enrolled_at`).
#[derive(Clone, Debug)]
struct PinnedClientRow {
    fingerprint: String,
    label: String,
    enrolled_at: String,
}

impl PinnedClientRow {
    fn from_value(v: &Value) -> Option<Self> {
        let obj = v.as_object()?;
        Some(Self {
            fingerprint: obj.get("fingerprint")?.as_str()?.to_string(),
            label: obj
                .get("label")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            enrolled_at: obj
                .get("enrolled_at")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
        })
    }
}

#[component]
pub fn PinnedClientsView() -> impl IntoView {
    let auth = use_context::<AuthToken>().expect("AuthToken context provided by AppRoot");
    let status: RwSignal<Option<TofuStatus>> = RwSignal::new(None);
    let input = RwSignal::new(String::new());
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let busy = RwSignal::new(false);
    // Covers only the initial fetch; a later refresh failure (e.g. after
    // "Apply") still leaves the last-known `status` on screen and surfaces
    // via the `.error-state` block below the input row.
    let loading = RwSignal::new(true);

    // The pinned-client list itself — separate loading/error/filter state
    // from the TOFU-expiry status card above, since they're two independent
    // RPC round-trips and one failing shouldn't blank out the other.
    let clients: RwSignal<Result<Vec<PinnedClientRow>, String>> = RwSignal::new(Ok(Vec::new()));
    let clients_loading = RwSignal::new(true);
    let clients_filter = RwSignal::new(String::new());

    let reload = move || {
        spawn_local(async move {
            // `Value::Null`, not `json!({})` — see `ws::send_rpc`'s doc
            // comment: this is a unit-variant RPC method and an empty-object
            // `params` fails to deserialize on the daemon side, hanging this
            // call forever instead of erroring (previously manifested as
            // "Loading status…" never resolving).
            match send_rpc("daemon_pin_client_tofu_expiry_status", Value::Null).await {
                Ok(v) => {
                    status.set(TofuStatus::from_value(&v));
                    error.set(None);
                }
                Err(e) => error.set(Some(e)),
            }
            loading.set(false);
        });
    };

    let reload_clients = move || {
        clients_loading.set(true);
        let token = auth.0.get_untracked();
        spawn_local(async move {
            // Prefer the REST route (bearer-gated, matches every other list
            // panel); fall back to the JSON-RPC method for a daemon running
            // an older build without `/api/v1/daemon/pinned-clients` mounted
            // yet. `fetch_list` needs an explicit token even though the
            // WebSocket path pulls it from `localStorage` itself.
            let rest_result = match token.as_deref() {
                Some(t) => Some(fetch_list("daemon/pinned-clients", t).await),
                None => None,
            };
            let outcome = match rest_result {
                Some(Ok(v)) => Ok(v),
                _ => send_rpc("daemon_pin_client_list", Value::Null).await,
            };
            match outcome {
                Ok(v) => {
                    let arr = v.as_array().cloned().unwrap_or_default();
                    let parsed = arr.iter().filter_map(PinnedClientRow::from_value).collect();
                    clients.set(Ok(parsed));
                }
                Err(e) => clients.set(Err(e)),
            }
            clients_loading.set(false);
        });
    };

    Effect::new(move |prev: Option<()>| {
        if prev.is_some() {
            return;
        }
        let _ = auth.0.get();
        reload();
        reload_clients();
    });

    let apply = move |_| {
        let raw = input.get_untracked();
        let parsed = match parse_tofu_expiry(&raw) {
            Ok(v) => v,
            Err(e) => {
                error.set(Some(e));
                return;
            }
        };
        let body = build_tofu_expiry_body(parsed);
        busy.set(true);
        spawn_local(async move {
            match send_rpc("daemon_pin_client_tofu_expiry_set", body).await {
                Ok(_) => {
                    input.set(String::new());
                    error.set(None);
                    // Refresh the displayed status from the same call surface.
                    match send_rpc("daemon_pin_client_tofu_expiry_status", Value::Null).await {
                        Ok(v) => status.set(TofuStatus::from_value(&v)),
                        Err(e) => error.set(Some(e)),
                    }
                }
                Err(e) => error.set(Some(e)),
            }
            busy.set(false);
        });
    };

    view! {
        <div class="pinned-clients-panel section-scope--system">
            <header class="page-head">
                <div class="page-head__lead">
                    <div class="page-head__disc"><Icon name="pin"/></div>
                    <div class="page-head__titles">
                        <div class="page-head__eyebrow">"System"</div>
                        <div class="page-head__title">"TOFU pin-store"</div>
                        <div class="page-head__sub">"Trust-on-first-use client pin expiry."</div>
                    </div>
                </div>
            </header>
            <div class="surface-card">
                <p class="rest-hint">{format!("REST: PUT {}", paths::TOFU_EXPIRY)}</p>
                {move || match status.get() {
                    None if loading.get() => view! {
                        <div class="loading-inline"><span class="spinner"></span>"Loading status…"</div>
                    }
                    .into_any(),
                    // Loaded, but never got a successful response — the
                    // `.error-state` block below already surfaces the
                    // failure, so this branch stays silent.
                    None => ().into_any(),
                    Some(s) => {
                        let now = js_now_secs();
                        let countdown = tofu_countdown_label(s.enabled, s.max_age_secs, s.enabled_at, now);
                        let expired = tofu_is_expired(s.enabled, s.max_age_secs, s.enabled_at, now);
                        let badge_cls = if expired { "chip chip--error" } else { "chip chip--info" };
                        view! {
                            <div class="detail-grid">
                                <span class="detail-grid__key">"enabled"</span>
                                <span class="detail-grid__val">{s.enabled.to_string()}</span>
                                <span class="detail-grid__key">"max_age_secs"</span>
                                <span class="detail-grid__val mono">{
                                    s.max_age_secs.map(|n| n.to_string()).unwrap_or_else(|| "(unset)".into())
                                }</span>
                                <span class="detail-grid__key">"enabled_at"</span>
                                <span class="detail-grid__val mono">{
                                    s.enabled_at.map(|n| n.to_string()).unwrap_or_else(|| "(never)".into())
                                }</span>
                            </div>
                            <p><span class=badge_cls>{countdown}</span></p>
                        }.into_any()
                    }
                }}
                <div class="set-expiry-row">
                    <input
                        class="input"
                        type="text"
                        placeholder="e.g. 3600, 30s, 5m, 2h, 1d, clear"
                        prop:value=move || input.get()
                        on:input=move |ev| input.set(event_target_value(&ev))
                    />
                    <button
                        type="button"
                        class="btn btn--primary"
                        prop:disabled=move || busy.get()
                        on:click=apply
                    >
                        {move || if busy.get() { "Working…" } else { "Apply" }}
                    </button>
                </div>
                {move || error.get().map(|e| view! {
                    <div class="error-state">
                        <span class="error-state__icon"><Icon name="pin"/></span>
                        <span>{e}</span>
                    </div>
                })}
            </div>
            <div class="panel-toolbar">
                <span class="search-box">
                    <span class="search-box__icon"><Icon name="search"/></span>
                    <input
                        class="input"
                        type="search"
                        placeholder="Filter…"
                        on:input=move |ev| clients_filter.set(event_target_value(&ev))
                    />
                </span>
            </div>
            {move || {
                if clients_loading.get() {
                    return view! {
                        <div class="loading-inline"><span class="spinner"></span>"Loading pinned clients…"</div>
                    }
                    .into_any();
                }
                match clients.get() {
                    Err(msg) => view! {
                        <div class="error-state">
                            <span class="error-state__icon"><Icon name="pin"/></span>
                            <span>{msg}</span>
                        </div>
                    }
                    .into_any(),
                    Ok(all_rows) => {
                        let needle = clients_filter.get().trim().to_lowercase();
                        let filtered: Vec<PinnedClientRow> = if needle.is_empty() {
                            all_rows
                        } else {
                            all_rows
                                .into_iter()
                                .filter(|r| {
                                    r.label.to_lowercase().contains(&needle)
                                        || r.fingerprint.to_lowercase().contains(&needle)
                                })
                                .collect()
                        };
                        if filtered.is_empty() {
                            return view! {
                                <div class="empty-state empty-state--spot">
                                    <span class="empty-state__spot"><EmptySpot motif="generic"/></span>
                                    <span class="empty-state__title">"No pinned clients"</span>
                                    <span class="empty-state__hint">
                                        "TOFU-pinned remote clients appear here once a WebSocket client enrolls under --pin-clients."
                                    </span>
                                </div>
                            }
                            .into_any();
                        }
                        let now = js_now_secs();
                        let count = filtered.len();
                        // A single global TOFU badge, computed once from the
                        // status card above and applied to every row: the
                        // pinned-client rows don't carry their own per-entry
                        // TOFU state, but "was this pin-store enrolled under
                        // an active/expired TOFU window" is still useful
                        // at-a-glance context next to the fingerprint. `.get()`
                        // (not `_untracked`) so this table re-renders once the
                        // status card's own fetch resolves — otherwise the
                        // badge freezes at whatever `status` held during this
                        // closure's very first (pre-fetch) run.
                        let (tofu_label, tofu_cls) = match status.get() {
                            Some(s) if !s.enabled => ("static".to_string(), "chip chip--neutral"),
                            Some(s) if tofu_is_expired(s.enabled, s.max_age_secs, s.enabled_at, now) => {
                                ("TOFU expired".to_string(), "chip chip--error")
                            }
                            Some(_) => ("TOFU".to_string(), "chip chip--info"),
                            None => ("—".to_string(), "chip chip--neutral"),
                        };
                        let body_rows = filtered
                            .into_iter()
                            .map(|row| {
                                let enrolled = humanize_timestamp(now, &row.enrolled_at);
                                let short_fp = short_id(&row.fingerprint);
                                view! {
                                    <tr>
                                        <td><span class="cell">{row.label.clone()}</span></td>
                                        <td>
                                            <span class="cell-id mono" title=row.fingerprint.clone()>
                                                {short_fp}
                                            </span>
                                        </td>
                                        <td><span class="cell">{enrolled}</span></td>
                                        <td><span class=tofu_cls>{tofu_label.clone()}</span></td>
                                    </tr>
                                }
                            })
                            .collect_view();
                        view! {
                            <div class="data-table-wrap">
                                <table class="data-table">
                                    <thead>
                                        <tr>
                                            <th>"Label"</th>
                                            <th>"Fingerprint"</th>
                                            <th>"Enrolled"</th>
                                            <th>"TOFU"</th>
                                        </tr>
                                    </thead>
                                    <tbody>{body_rows}</tbody>
                                </table>
                            </div>
                            <div class="table-footer">
                                <span class="row-count">{format!("{count} item(s)")}</span>
                            </div>
                        }
                        .into_any()
                    }
                }
            }}
        </div>
    }
}

/// `Date.now() / 1000` rounded down to an integer. Browsers always have a
/// `Date` object, but we still guard against `None` so a host-side smoke test
/// (which wouldn't run this code anyway) compiles cleanly.
fn js_now_secs() -> i64 {
    let now_ms = js_sys::Date::now();
    (now_ms / 1000.0) as i64
}
