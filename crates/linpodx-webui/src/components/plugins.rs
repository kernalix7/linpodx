//! Phase 17 Stream C — plugin key registry + cluster-wide revocation surface.
//!
//! Renders the daemon's `plugin_key_list` payload as a card-stack panel with a
//! "Revoke cluster-wide" button per row. Submitting opens a confirm modal that
//! issues `plugin_key_revoke_propagate` over the JSON-RPC bridge.

use std::collections::HashMap;

use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

use crate::api_client::{build_revoke_cluster_body, paths};
use crate::app::AuthToken;
use crate::helpers::plugin_propagation_label;
use crate::ws::{fetch_list, send_rpc};

#[derive(Clone, Debug)]
struct KeyRow {
    publisher: String,
    fingerprint: String,
    status: String,
    revoked_at: Option<String>,
    reason: Option<String>,
}

impl KeyRow {
    fn from_value(v: &Value) -> Option<Self> {
        let obj = v.as_object()?;
        Some(Self {
            publisher: obj.get("publisher")?.as_str()?.to_string(),
            fingerprint: obj.get("fingerprint")?.as_str()?.to_string(),
            status: obj
                .get("status")
                .and_then(|x| x.as_str())
                .unwrap_or("active")
                .to_string(),
            revoked_at: obj
                .get("revoked_at")
                .and_then(|x| x.as_str())
                .map(str::to_string),
            reason: obj
                .get("reason")
                .and_then(|x| x.as_str())
                .map(str::to_string),
        })
    }
}

#[derive(Clone, Debug)]
enum Propagation {
    ThisNode,
    Pending,
    Cluster { log_index: Option<u64> },
}

impl Propagation {
    fn label(&self) -> String {
        match self {
            Propagation::ThisNode => plugin_propagation_label("this_node", None),
            Propagation::Pending => plugin_propagation_label("pending", None),
            Propagation::Cluster { log_index } => plugin_propagation_label("cluster", *log_index),
        }
    }
}

#[component]
pub fn PluginsView() -> impl IntoView {
    let auth = use_context::<AuthToken>().expect("AuthToken context provided by AppRoot");
    let rows: RwSignal<Vec<KeyRow>> = RwSignal::new(Vec::new());
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let pending_revoke: RwSignal<Option<(String, String)>> = RwSignal::new(None);
    let propagation: RwSignal<HashMap<(String, String), Propagation>> =
        RwSignal::new(HashMap::new());
    let busy = RwSignal::new(false);
    let status: RwSignal<Option<String>> = RwSignal::new(None);

    let reload = move || {
        let token = match auth.0.get_untracked() {
            Some(t) => t,
            None => {
                error.set(Some("set a bearer token to load plugin keys".into()));
                return;
            }
        };
        spawn_local(async move {
            match fetch_list("plugin/keys", &token).await {
                Ok(v) => {
                    let arr = if let Value::Array(a) = v { a } else { vec![v] };
                    let parsed: Vec<KeyRow> = arr.iter().filter_map(KeyRow::from_value).collect();
                    rows.set(parsed);
                    error.set(None);
                }
                Err(_) => {
                    // Fall back to the JSON-RPC method if the REST list isn't
                    // mounted yet (the daemon ships both surfaces).
                    match send_rpc("plugin_key_list", json!({})).await {
                        Ok(v) => {
                            let arr = if let Value::Array(a) = v { a } else { vec![v] };
                            let parsed: Vec<KeyRow> =
                                arr.iter().filter_map(KeyRow::from_value).collect();
                            rows.set(parsed);
                            error.set(None);
                        }
                        Err(e) => error.set(Some(e)),
                    }
                }
            }
        });
    };

    Effect::new(move |prev: Option<()>| {
        if prev.is_some() {
            return;
        }
        let _ = auth.0.get();
        reload();
    });

    let confirm = move |_| {
        let pair = match pending_revoke.get_untracked() {
            Some(p) => p,
            None => return,
        };
        let (publisher, fingerprint) = pair.clone();
        propagation.update(|m| {
            m.insert(pair.clone(), Propagation::Pending);
        });
        busy.set(true);
        status.set(Some("propagating…".into()));
        let body = build_revoke_cluster_body(&publisher, &fingerprint, None);
        spawn_local(async move {
            match send_rpc("plugin_key_revoke_propagate", body).await {
                Ok(v) => {
                    let log_index = v.get("log_index").and_then(|x| x.as_u64());
                    propagation.update(|m| {
                        m.insert(
                            (publisher.clone(), fingerprint.clone()),
                            Propagation::Cluster { log_index },
                        );
                    });
                    status.set(Some("done".into()));
                    pending_revoke.set(None);
                }
                Err(e) => {
                    status.set(Some(format!("error: {e}")));
                    propagation.update(|m| {
                        m.insert(
                            (publisher.clone(), fingerprint.clone()),
                            Propagation::ThisNode,
                        );
                    });
                }
            }
            busy.set(false);
        });
    };

    let cancel = move |_| {
        pending_revoke.set(None);
        status.set(None);
    };

    let modal_view = move || {
        pending_revoke.get().map(|(publisher, fingerprint)| {
            let publisher_for_view = publisher.clone();
            let fingerprint_for_view = fingerprint.clone();
            let st = status.get();
            view! {
                <div class="modal-backdrop">
                    <div class="modal-card">
                        <h3>"Revoke plugin key (cluster-wide)"</h3>
                        <p class="modal-confirm">{format!("Publisher: {}", publisher_for_view)}</p>
                        <p class="modal-confirm">{format!("Fingerprint: {}", fingerprint_for_view)}</p>
                        <p class="rest-hint">{format!("REST: POST {}", paths::PLUGIN_REVOKE_CLUSTER)}</p>
                        {st.map(|m| view! { <p class="status">{m}</p> })}
                        <div class="modal-actions">
                            <button
                                type="button"
                                class="primary danger"
                                prop:disabled=move || busy.get()
                                on:click=confirm
                            >
                                {move || if busy.get() { "Working…" } else { "Confirm" }}
                            </button>
                            <button type="button" on:click=cancel>"Cancel"</button>
                        </div>
                    </div>
                </div>
            }
        })
    };

    let body_view = move || {
        let items = rows.get();
        if items.is_empty() {
            return view! { <div class="empty-state">"no plugin keys registered"</div> }.into_any();
        }
        let map = propagation.get();
        items
            .into_iter()
            .map(|k| {
                let row_key = (k.publisher.clone(), k.fingerprint.clone());
                let prop_label = map
                    .get(&row_key)
                    .map(Propagation::label)
                    .unwrap_or_else(|| "this node".to_string());
                let active = k.status == "active";
                let publisher = k.publisher.clone();
                let fingerprint = k.fingerprint.clone();
                let open = move |_| {
                    pending_revoke.set(Some((publisher.clone(), fingerprint.clone())));
                    status.set(None);
                };
                view! {
                    <div class="card">
                        <div class="field"><span class="field-label">"publisher"</span><span class="field-value">{k.publisher}</span></div>
                        <div class="field"><span class="field-label">"fingerprint"</span><span class="field-value">{k.fingerprint}</span></div>
                        <div class="field"><span class="field-label">"status"</span><span class="field-value">{k.status}</span></div>
                        <div class="field"><span class="field-label">"propagation"</span><span class="field-value">{prop_label}</span></div>
                        {k.revoked_at.map(|ts| view! {
                            <div class="field"><span class="field-label">"revoked_at"</span><span class="field-value">{ts}</span></div>
                        })}
                        {k.reason.map(|r| view! {
                            <div class="field"><span class="field-label">"reason"</span><span class="field-value">{r}</span></div>
                        })}
                        <div class="card-actions">
                            {active.then(|| view! {
                                <button type="button" class="row-action danger" on:click=open>"Revoke cluster-wide"</button>
                            })}
                        </div>
                    </div>
                }
            })
            .collect_view()
            .into_any()
    };

    view! {
        <section class="plugins-panel">
            <h3>"Plugin keys"</h3>
            {move || error.get().map(|e| view! { <p class="error-state">{e}</p> })}
            <div class="card-stack">
                {body_view}
            </div>
            {modal_view}
        </section>
    }
}
