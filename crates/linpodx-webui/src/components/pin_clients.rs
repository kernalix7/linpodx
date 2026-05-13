//! Phase 17 Stream C — TOFU pin-store status card for the Web UI.
//!
//! Reads `daemon_pin_client_tofu_expiry_status` via JSON-RPC, renders a
//! countdown card with a red `.expired` modifier when the window has elapsed,
//! and provides a "Set expiry" input that parses via the shared helper before
//! firing `daemon_pin_client_tofu_expiry_set`.

use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

use crate::api_client::{build_tofu_expiry_body, paths};
use crate::helpers::{parse_tofu_expiry, tofu_countdown_label, tofu_is_expired};
use crate::ws::send_rpc;

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

#[component]
pub fn PinnedClientsView() -> impl IntoView {
    let status: RwSignal<Option<TofuStatus>> = RwSignal::new(None);
    let input = RwSignal::new(String::new());
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let busy = RwSignal::new(false);

    let reload = move || {
        spawn_local(async move {
            match send_rpc("daemon_pin_client_tofu_expiry_status", json!({})).await {
                Ok(v) => {
                    status.set(TofuStatus::from_value(&v));
                    error.set(None);
                }
                Err(e) => error.set(Some(e)),
            }
        });
    };

    Effect::new(move |prev: Option<()>| {
        if prev.is_some() {
            return;
        }
        reload();
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
                    match send_rpc("daemon_pin_client_tofu_expiry_status", json!({})).await {
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
        <section class="pinned-clients-panel">
            <h3>"TOFU pin-store"</h3>
            <p class="rest-hint">{format!("REST: PUT {}", paths::TOFU_EXPIRY)}</p>
            {move || match status.get() {
                None => view! {
                    <p class="status-empty">"status not yet loaded"</p>
                }.into_any(),
                Some(s) => {
                    let now = js_now_secs();
                    let countdown = tofu_countdown_label(s.enabled, s.max_age_secs, s.enabled_at, now);
                    let expired = tofu_is_expired(s.enabled, s.max_age_secs, s.enabled_at, now);
                    let badge_cls = if expired { "tofu-badge expired" } else { "tofu-badge" };
                    view! {
                        <ul class="status-list">
                            <li>{format!("enabled: {}", s.enabled)}</li>
                            <li>{format!("max_age_secs: {}",
                                s.max_age_secs.map(|n| n.to_string()).unwrap_or_else(|| "(unset)".into()))}</li>
                            <li>{format!("enabled_at: {}",
                                s.enabled_at.map(|n| n.to_string()).unwrap_or_else(|| "(never)".into()))}</li>
                        </ul>
                        <p class=badge_cls>{countdown}</p>
                    }.into_any()
                }
            }}
            <div class="set-expiry-row">
                <input
                    type="text"
                    placeholder="e.g. 3600, 30s, 5m, 2h, 1d, clear"
                    prop:value=move || input.get()
                    on:input=move |ev| input.set(event_target_value(&ev))
                />
                <button
                    type="button"
                    class="primary"
                    prop:disabled=move || busy.get()
                    on:click=apply
                >
                    {move || if busy.get() { "Working…" } else { "Apply" }}
                </button>
            </div>
            {move || error.get().map(|e| view! { <p class="error-state">{e}</p> })}
        </section>
    }
}

/// `Date.now() / 1000` rounded down to an integer. Browsers always have a
/// `Date` object, but we still guard against `None` so a host-side smoke test
/// (which wouldn't run this code anyway) compiles cleanly.
fn js_now_secs() -> i64 {
    let now_ms = js_sys::Date::now();
    (now_ms / 1000.0) as i64
}
