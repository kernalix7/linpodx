//! Networks panel — Docker/Rancher-parity upgrade: an on-demand "in use"
//! sweep, bulk row selection with a floating action bar, and a client-side
//! "prune unused" sweep.
//!
//! Renders its own `<table>` rather than delegating to the shared
//! `ListTable` (`list_table.rs`, outside this panel's owned paths) so it can
//! carry the extra checkbox / badge columns. Every class used is drawn from
//! the existing `style.css` contract.
//!
//! **In-use detection.** `ContainerInspect.network_settings` (the typed
//! field) only carries the container's IP + published ports — it has no
//! network *name*, so there is no reliable way to tell which network a
//! container is attached to from the typed shape alone. The raw podman
//! inspect JSON (`ContainerInspect.raw`) does: `NetworkSettings.Networks` is
//! an object keyed by network name. The sweep reads that; when `raw` is
//! unavailable a container simply contributes nothing (rather than guessing
//! wrong), which is safer for a "prune unused" action. Because the sweep
//! means walking every container's full inspect, it stays opt-in via a
//! toolbar button rather than running on every list refresh (mirrors the
//! same trade-off in `volumes.rs`).

use std::collections::HashSet;

use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

use super::icons::Icon;
use crate::api_client::fetch_container_inspect;
use crate::app::AuthToken;
use crate::ws::{fetch_list, send_rpc, subscribe};

#[derive(Clone, Copy, PartialEq, Eq)]
enum BulkKind {
    Selected,
    Unused,
}

#[derive(Clone)]
struct Toast {
    id: u64,
    text: String,
    kind: &'static str,
}

fn row_name(row: &Value) -> String {
    row.get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// Network names a single container's raw inspect JSON says it's attached
/// to (`NetworkSettings.Networks` object keys). Empty when `raw` is null —
/// see the module doc for why we don't guess from the typed shape.
fn extract_network_names(inspect: &Value) -> Vec<String> {
    inspect
        .pointer("/raw/NetworkSettings/Networks")
        .and_then(|v| v.as_object())
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

#[component]
pub fn NetworkList() -> impl IntoView {
    let auth = use_context::<AuthToken>().expect("AuthToken context provided by AppRoot");

    let rows: RwSignal<Result<Vec<Value>, String>> = RwSignal::new(Ok(Vec::new()));
    let loading = RwSignal::new(true);
    let filter = RwSignal::new(String::new());
    let selected: RwSignal<HashSet<String>> = RwSignal::new(HashSet::new());
    let in_use: RwSignal<HashSet<String>> = RwSignal::new(HashSet::new());
    let usage_computed = RwSignal::new(false);
    let sweeping = RwSignal::new(false);
    let busy = RwSignal::new(false);
    let pending_bulk: RwSignal<Option<BulkKind>> = RwSignal::new(None);
    let toasts: RwSignal<Vec<Toast>> = RwSignal::new(Vec::new());
    let toast_seq: RwSignal<u64> = RwSignal::new(0);

    let push_toast = move |text: String, kind: &'static str| {
        let id = toast_seq.get_untracked() + 1;
        toast_seq.set(id);
        toasts.update(|t| {
            t.push(Toast { id, text, kind });
            let overflow = t.len().saturating_sub(6);
            if overflow > 0 {
                t.drain(0..overflow);
            }
        });
    };

    let reload = move || {
        let token = match auth.0.get_untracked() {
            Some(t) => t,
            None => {
                rows.set(Err("set a bearer token to load data".into()));
                loading.set(false);
                return;
            }
        };
        spawn_local(async move {
            match fetch_list("networks", &token).await {
                Ok(v) => {
                    let arr = if let Value::Array(a) = v { a } else { vec![v] };
                    rows.set(Ok(arr));
                }
                Err(e) => rows.set(Err(e)),
            }
            loading.set(false);
        });
    };

    Effect::new(move |_| {
        let _ = auth.0.get();
        reload();
    });
    Effect::new(move |prev: Option<()>| {
        if prev.is_some() {
            return;
        }
        subscribe("network", move |_e| reload());
    });

    let compute_usage = move |_| {
        let token = match auth.0.get_untracked() {
            Some(t) => t,
            None => return,
        };
        sweeping.set(true);
        spawn_local(async move {
            let containers = fetch_list("containers?all=true", &token)
                .await
                .map(|v| v.as_array().cloned().unwrap_or_default())
                .unwrap_or_default();
            let mut used: HashSet<String> = HashSet::new();
            for c in &containers {
                let cid = c.get("id").and_then(|v| v.as_str()).unwrap_or("");
                if cid.is_empty() {
                    continue;
                }
                if let Ok(inspect) = fetch_container_inspect(cid, &token).await {
                    for name in extract_network_names(&inspect) {
                        used.insert(name);
                    }
                }
            }
            in_use.set(used);
            usage_computed.set(true);
            sweeping.set(false);
        });
    };

    let remove_names = move |names: Vec<String>| {
        if names.is_empty() {
            return;
        }
        busy.set(true);
        spawn_local(async move {
            for name in names {
                match send_rpc("network_remove", json!({ "name": name, "force": false })).await {
                    Ok(_) => {
                        push_toast(format!("removed {name}"), "success");
                        selected.update(|s| {
                            s.remove(&name);
                        });
                    }
                    Err(e) => push_toast(format!("failed to remove {name}: {e}"), "error"),
                }
            }
            busy.set(false);
            reload();
        });
    };

    let unused_names = move || -> Vec<String> {
        if !usage_computed.get() {
            return Vec::new();
        }
        let used = in_use.get();
        rows.get()
            .unwrap_or_default()
            .iter()
            .map(row_name)
            .filter(|n| !n.is_empty() && !used.contains(n))
            .collect()
    };

    let confirm_bulk = move |_| {
        let names = match pending_bulk.get_untracked() {
            Some(BulkKind::Selected) => selected.get_untracked().into_iter().collect::<Vec<_>>(),
            Some(BulkKind::Unused) => unused_names(),
            None => Vec::new(),
        };
        pending_bulk.set(None);
        remove_names(names);
    };

    let usage_line = move || {
        rows.get()
            .map(|items| format!("Networks: {}", items.len()))
            .unwrap_or_default()
    };

    let body_view = move || {
        if loading.get() {
            return skeleton_rows(7);
        }
        match rows.get() {
            Err(msg) => view! {
                <div class="error-state"><Icon name="approval"/><span>{msg}</span></div>
            }
            .into_any(),
            Ok(items) if items.is_empty() => view! {
                <div class="empty-state">
                    <span class="empty-state__icon"><Icon name="network"/></span>
                    <span class="empty-state__title">"no networks"</span>
                    <span class="empty-state__hint">
                        "Nothing here yet — create one with the linpodx CLI."
                    </span>
                </div>
            }
            .into_any(),
            Ok(items) => {
                let needle = filter.get().trim().to_lowercase();
                let computed = usage_computed.get();
                let used = in_use.get();
                let filtered: Vec<Value> = items
                    .into_iter()
                    .filter(|row| {
                        needle.is_empty() || row_name(row).to_lowercase().contains(&needle)
                    })
                    .collect();
                if filtered.is_empty() {
                    return view! {
                        <div class="empty-state">
                            <span class="empty-state__icon"><Icon name="network"/></span>
                            <span class="empty-state__title">"no rows match your filter"</span>
                        </div>
                    }
                    .into_any();
                }
                let count = filtered.len();
                let sel = selected.get();
                let filtered_names: Vec<String> = filtered.iter().map(row_name).collect();
                let filtered_names_for_header = filtered_names.clone();
                let all_selected =
                    !filtered_names.is_empty() && filtered_names.iter().all(|n| sel.contains(n));

                let body_rows = filtered
                    .into_iter()
                    .map(|row| {
                        let name = row_name(&row);
                        let name_check = name.clone();
                        let driver = row
                            .get("driver")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let subnet = row
                            .get("subnet")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let gateway = row
                            .get("gateway")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let internal = row
                            .get("internal")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        let checked = sel.contains(&name);
                        let badge = if !computed {
                            view! {
                                <span class="badge badge--neutral" title="Click \"Compute usage\" to check">
                                    "unknown"
                                </span>
                            }
                            .into_any()
                        } else if used.contains(&name) {
                            view! { <span class="badge badge--info">"in use"</span> }.into_any()
                        } else {
                            view! { <span class="badge badge--neutral">"unused"</span> }.into_any()
                        };
                        view! {
                            <tr>
                                <td>
                                    <input
                                        type="checkbox"
                                        class="checkbox"
                                        prop:checked=checked
                                        on:change=move |ev| {
                                            let on = event_target_checked(&ev);
                                            selected.update(|s| {
                                                if on {
                                                    s.insert(name_check.clone());
                                                } else {
                                                    s.remove(&name_check);
                                                }
                                            });
                                        }
                                    />
                                </td>
                                <td><span class="cell-id" title=name.clone()>{name.clone()}</span></td>
                                <td><span class="cell">{driver}</span></td>
                                <td><span class="cell">{subnet}</span></td>
                                <td><span class="cell">{gateway}</span></td>
                                <td><span class="cell">{internal.to_string()}</span></td>
                                <td>{badge}</td>
                            </tr>
                        }
                    })
                    .collect_view();

                view! {
                    <div class="data-table-wrap">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th class="cell-actions">
                                        <input
                                            type="checkbox"
                                            class="checkbox"
                                            prop:checked=all_selected
                                            on:change=move |ev| {
                                                let on = event_target_checked(&ev);
                                                selected.update(|s| {
                                                    for n in &filtered_names_for_header {
                                                        if on {
                                                            s.insert(n.clone());
                                                        } else {
                                                            s.remove(n);
                                                        }
                                                    }
                                                });
                                            }
                                        />
                                    </th>
                                    <th>"Name"</th>
                                    <th>"Driver"</th>
                                    <th>"Subnet"</th>
                                    <th>"Gateway"</th>
                                    <th>"Internal"</th>
                                    <th>"Usage"</th>
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
    };

    view! {
        <div class="panel">
            <div class="toolbar page-actions">
                <span class="search-box">
                    <span class="search-box__icon"><Icon name="search"/></span>
                    <input
                        class="input"
                        type="search"
                        placeholder="Filter…"
                        on:input=move |ev| filter.set(event_target_value(&ev))
                    />
                </span>
                <span class="toolbar__spacer"></span>
                <button
                    type="button"
                    class="btn btn--secondary btn--sm"
                    prop:disabled=move || sweeping.get()
                    on:click=compute_usage
                >
                    {move || if sweeping.get() { "Computing…" } else { "Compute usage" }}
                </button>
                <button
                    type="button"
                    class="btn btn--secondary btn--sm"
                    title="Compute usage first, then prune the networks it finds unused."
                    prop:disabled=move || !usage_computed.get() || unused_names().is_empty()
                    on:click=move |_| pending_bulk.set(Some(BulkKind::Unused))
                >
                    "Prune unused"
                </button>
            </div>
            <div class="usage-summary">{usage_line}</div>
            {body_view}
            <Show when=move || !selected.get().is_empty() fallback=|| view! { <></> }>
                <div class="bulk-bar">
                    <span class="bulk-bar__count">{move || format!("{} selected", selected.get().len())}</span>
                    <span class="bulk-bar__actions">
                        <button
                            type="button"
                            class="btn btn--danger btn--sm"
                            prop:disabled=move || busy.get()
                            on:click=move |_| pending_bulk.set(Some(BulkKind::Selected))
                        >
                            {move || if busy.get() { "Removing…" } else { "Remove selected" }}
                        </button>
                        <button
                            type="button"
                            class="btn btn--ghost btn--sm"
                            on:click=move |_| selected.set(HashSet::new())
                        >
                            "Clear"
                        </button>
                    </span>
                </div>
            </Show>
            <Show when=move || pending_bulk.get().is_some() fallback=|| view! { <></> }>
                <div class="modal-backdrop">
                    <div class="modal-card">
                        <h3>"Confirm removal"</h3>
                        <p class="modal-confirm">
                            {move || match pending_bulk.get() {
                                Some(BulkKind::Selected) => format!(
                                    "Remove {} selected network(s)? This cannot be undone.",
                                    selected.get().len()
                                ),
                                Some(BulkKind::Unused) => format!(
                                    "Remove {} unused network(s)? This cannot be undone.",
                                    unused_names().len()
                                ),
                                None => String::new(),
                            }}
                        </p>
                        <div class="modal-actions">
                            <button type="button" class="btn btn--danger" on:click=confirm_bulk>"Remove"</button>
                            <button type="button" class="btn" on:click=move |_| pending_bulk.set(None)>"Cancel"</button>
                        </div>
                    </div>
                </div>
            </Show>
            <div class="toast-stack">
                {move || toasts.get().into_iter().map(|t| {
                    let cls = format!("toast toast--{}", t.kind);
                    let tid = t.id;
                    view! {
                        <div class=cls on:click=move |_| toasts.update(|v| v.retain(|x| x.id != tid))>
                            <span>{t.text}</span>
                        </div>
                    }
                }).collect_view()}
            </div>
        </div>
    }
}

fn skeleton_rows(n_cols: usize) -> AnyView {
    let rows = (0..5)
        .map(|_| {
            let cells = (0..n_cols)
                .map(|_| view! { <td><span class="skeleton-line"></span></td> })
                .collect_view();
            view! { <tr>{cells}</tr> }
        })
        .collect_view();
    view! {
        <div class="data-table-wrap">
            <table class="data-table"><tbody>{rows}</tbody></table>
        </div>
    }
    .into_any()
}
