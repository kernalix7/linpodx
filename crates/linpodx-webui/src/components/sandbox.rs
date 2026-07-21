use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

use super::icons::Icon;
use super::list_table::{ListTable, PanelSpec};
use crate::api_client::{build_auto_encrypt_body, paths};
use crate::app::AuthToken;
use crate::ws::send_rpc;

#[component]
pub fn SandboxList() -> impl IntoView {
    let spec = PanelSpec {
        api_path: "sandbox/profiles",
        topic: "sandbox",
        columns: &["name", "version", "category", "rules"],
        empty_msg: "no profiles loaded",
    };
    view! {
        <div class="sandbox-panel">
            <div class="page-header">
                <div class="page-header__titles">
                    <div class="page-title">"Sandbox profiles"</div>
                    <div class="page-subtitle">"policy engine profiles + MCP allowlist"</div>
                </div>
            </div>
            <AutoEncryptCard/>
            <ListTable spec=spec/>
        </div>
    }
}

/// Phase 17 Stream B — toggle for `auto_encrypt_snapshots`. Reads the status
/// via the JSON-RPC `sandbox_snapshot_auto_trigger_status` method, then flips
/// it via `sandbox_snapshot_auto_trigger_enable`. The card also surfaces the
/// daemon's reported trigger counter so the user sees how often the chain
/// fired since the daemon started.
#[component]
fn AutoEncryptCard() -> impl IntoView {
    let _auth = use_context::<AuthToken>().expect("AuthToken context provided by AppRoot");
    let status: RwSignal<Option<AutoEncryptStatus>> = RwSignal::new(None);
    let busy = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);

    let reload = move || {
        spawn_local(async move {
            match send_rpc("sandbox_snapshot_auto_trigger_status", json!({})).await {
                Ok(v) => {
                    status.set(AutoEncryptStatus::from_value(&v));
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

    let toggle = move |_| {
        let next = match status.get_untracked() {
            Some(s) => !s.enabled,
            None => true,
        };
        busy.set(true);
        // Mirror the iced GUI: we send the JSON-RPC for the dispatch arm and
        // also poke the REST endpoint so external consumers receive the same
        // signal. We only block on the RPC for the status refresh.
        spawn_local(async move {
            let body = build_auto_encrypt_body(next);
            match send_rpc("sandbox_snapshot_auto_trigger_enable", body).await {
                Ok(_) => {
                    error.set(None);
                    // Refresh the displayed status.
                    match send_rpc("sandbox_snapshot_auto_trigger_status", json!({})).await {
                        Ok(v) => status.set(AutoEncryptStatus::from_value(&v)),
                        Err(e) => error.set(Some(e)),
                    }
                }
                Err(e) => error.set(Some(e)),
            }
            busy.set(false);
        });
    };

    view! {
        <section class="auto-encrypt-card surface-card">
            <div class="section-title">"Sandbox auto-encrypt snapshots"</div>
            <p class="rest-hint">{format!("REST: PUT {}", paths::SANDBOX_AUTO_ENCRYPT)}</p>
            {move || match status.get() {
                None => view! { <p class="status-empty">"status not yet loaded"</p> }.into_any(),
                Some(s) => view! {
                    <div class="detail-grid">
                        <span class="detail-grid__key">"Enabled"</span>
                        <span class="detail-grid__val">
                            <span class=move || if s.enabled { "chip chip--running" } else { "chip chip--stopped" }>
                                {if s.enabled { "enabled" } else { "disabled" }}
                            </span>
                        </span>
                        <span class="detail-grid__key">"Trigger count"</span>
                        <span class="detail-grid__val mono">{s.trigger_count.to_string()}</span>
                        <span class="detail-grid__key">"Last image ref"</span>
                        <span class="detail-grid__val mono">{
                            match &s.last_image_ref {
                                Some(r) => r.clone(),
                                None => "(none)".to_string(),
                            }
                        }</span>
                    </div>
                }.into_any(),
            }}
            <button
                type="button"
                class="btn btn--primary"
                prop:disabled=move || busy.get()
                on:click=toggle
            >
                {move || {
                    let label = match status.get() {
                        Some(s) if s.enabled => "Disable",
                        Some(_) => "Enable",
                        None => "Enable",
                    };
                    if busy.get() { "Working…" } else { label }
                }}
            </button>
            {move || error.get().map(|e| view! {
                <div class="error-state"><Icon name="sandbox"/><span>{e}</span></div>
            })}
        </section>
    }
}

#[derive(Clone, Debug)]
struct AutoEncryptStatus {
    enabled: bool,
    last_image_ref: Option<String>,
    trigger_count: u64,
}

impl AutoEncryptStatus {
    fn from_value(v: &Value) -> Option<Self> {
        let obj = v.as_object()?;
        Some(Self {
            enabled: obj
                .get("enabled")
                .and_then(|x| x.as_bool())
                .unwrap_or(false),
            last_image_ref: obj
                .get("last_image_ref")
                .and_then(|x| x.as_str())
                .map(str::to_string),
            trigger_count: obj
                .get("trigger_count")
                .and_then(|x| x.as_u64())
                .unwrap_or(0),
        })
    }
}
