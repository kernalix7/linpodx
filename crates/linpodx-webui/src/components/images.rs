//! Images panel — Docker/Rancher-parity upgrade: in-use badges (cross-
//! referenced live against the container list), a size column + a
//! disk-usage summary line sourced from `GET /api/v1/system/df`, bulk row
//! selection with a floating action bar, and a client-side "prune unused"
//! sweep.
//!
//! This panel renders its own `<table>` instead of delegating to the shared
//! `ListTable` (`list_table.rs`) — the extra columns (checkbox, in-use
//! badge, formatted size) aren't expressible through `PanelSpec`'s flat
//! column-name list, and `list_table.rs` is outside this panel's owned
//! paths. Every class used below (`.data-table`, `.badge`, `.bulk-bar`,
//! `.usage-summary`, `.toast`, …) comes straight from the existing
//! `style.css` contract — no new CSS is introduced here.
//!
//! Mutations (`image_remove`) go through the existing `send_rpc` JSON-RPC
//! channel exactly like the CLI would; "bulk remove" and "prune unused" are
//! just client-side loops over that same per-item call — no new daemon
//! surface is required, keeping the "read-only Web UI; CLI mutates" posture.

use std::collections::HashSet;

use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

use super::icons::Icon;
use super::push_modal::PushModal;
use crate::api_client::fetch_system_df;
use crate::app::AuthToken;
use crate::helpers::{format_bytes, short_id};
use crate::ws::{fetch_list, send_rpc, subscribe};

/// What a pending confirm-modal / bulk removal is about to act on.
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

fn row_id(row: &Value) -> String {
    row.get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn image_display_name(row: &Value) -> String {
    row.get("repo_tags")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| short_id(&row_id(row)))
}

/// True when any container's `image` field resolves to this image — matches
/// a repo tag, the full id, or the short (12-char) id.
fn image_in_use(row: &Value, containers: &[Value]) -> bool {
    let id = row_id(row);
    if id.is_empty() {
        return false;
    }
    let short = short_id(&id);
    let repo_tags: Vec<&str> = row
        .get("repo_tags")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    containers.iter().any(|c| {
        let cimg = c.get("image").and_then(|v| v.as_str()).unwrap_or("");
        !cimg.is_empty() && (cimg == id || cimg == short || repo_tags.contains(&cimg))
    })
}

#[component]
pub fn ImageList() -> impl IntoView {
    let auth = use_context::<AuthToken>().expect("AuthToken context provided by AppRoot");

    let rows: RwSignal<Result<Vec<Value>, String>> = RwSignal::new(Ok(Vec::new()));
    let loading = RwSignal::new(true);
    let filter = RwSignal::new(String::new());
    let containers: RwSignal<Vec<Value>> = RwSignal::new(Vec::new());
    let df: RwSignal<Option<Value>> = RwSignal::new(None);
    let selected: RwSignal<HashSet<String>> = RwSignal::new(HashSet::new());
    let busy = RwSignal::new(false);
    let pending_bulk: RwSignal<Option<BulkKind>> = RwSignal::new(None);
    let toasts: RwSignal<Vec<Toast>> = RwSignal::new(Vec::new());
    let toast_seq: RwSignal<u64> = RwSignal::new(0);
    let push_open: RwSignal<Option<String>> = RwSignal::new(None);

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
        let token_containers = token.clone();
        let token_df = token.clone();
        spawn_local(async move {
            match fetch_list("images", &token).await {
                Ok(v) => {
                    let arr = if let Value::Array(a) = v { a } else { vec![v] };
                    rows.set(Ok(arr));
                }
                Err(e) => rows.set(Err(e)),
            }
            loading.set(false);
        });
        spawn_local(async move {
            if let Ok(v) = fetch_list("containers?all=true", &token_containers).await {
                containers.set(v.as_array().cloned().unwrap_or_default());
            }
        });
        spawn_local(async move {
            if let Ok(v) = fetch_system_df(&token_df).await {
                df.set(Some(v));
            }
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
        subscribe("image", move |_e| reload());
    });
    Effect::new(move |prev: Option<()>| {
        if prev.is_some() {
            return;
        }
        subscribe("container", move |_e| reload());
    });

    let remove_ids = move |ids: Vec<String>| {
        if ids.is_empty() {
            return;
        }
        busy.set(true);
        spawn_local(async move {
            for id in ids {
                let short = short_id(&id);
                match send_rpc("image_remove", json!({ "id": id, "force": false })).await {
                    Ok(_) => {
                        push_toast(format!("removed {short}"), "success");
                        selected.update(|s| {
                            s.remove(&id);
                        });
                    }
                    Err(e) => push_toast(format!("failed to remove {short}: {e}"), "error"),
                }
            }
            busy.set(false);
            reload();
        });
    };

    let unused_ids = move || -> Vec<String> {
        let items = rows.get().unwrap_or_default();
        let c = containers.get();
        items
            .iter()
            .filter(|r| !image_in_use(r, &c))
            .map(row_id)
            .filter(|id| !id.is_empty())
            .collect()
    };

    let confirm_bulk = move |_| {
        let ids = match pending_bulk.get_untracked() {
            Some(BulkKind::Selected) => selected.get_untracked().into_iter().collect::<Vec<_>>(),
            Some(BulkKind::Unused) => unused_ids(),
            None => Vec::new(),
        };
        pending_bulk.set(None);
        remove_ids(ids);
    };

    let usage_line = move || {
        df.get().map(|d| {
            let total = d
                .pointer("/images/total")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let size = d.pointer("/images/size_bytes").and_then(|v| v.as_u64());
            let reclaim = d
                .pointer("/images/reclaimable_bytes")
                .and_then(|v| v.as_u64());
            let mut s = format!("Images: {total}");
            if let Some(sz) = size {
                s.push_str(&format!(" · {}", format_bytes(sz)));
            }
            if let Some(r) = reclaim {
                s.push_str(&format!(" ({} reclaimable)", format_bytes(r)));
            }
            s
        })
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
                    <span class="empty-state__icon"><Icon name="image"/></span>
                    <span class="empty-state__title">"no images"</span>
                    <span class="empty-state__hint">
                        "Nothing here yet — pull one with the linpodx CLI."
                    </span>
                </div>
            }
            .into_any(),
            Ok(items) => {
                let needle = filter.get().trim().to_lowercase();
                let c = containers.get();
                let filtered: Vec<Value> = items
                    .into_iter()
                    .filter(|row| {
                        needle.is_empty()
                            || image_display_name(row).to_lowercase().contains(&needle)
                            || row_id(row).to_lowercase().contains(&needle)
                    })
                    .collect();
                if filtered.is_empty() {
                    return view! {
                        <div class="empty-state">
                            <span class="empty-state__icon"><Icon name="image"/></span>
                            <span class="empty-state__title">"no rows match your filter"</span>
                        </div>
                    }
                    .into_any();
                }
                let count = filtered.len();
                let sel = selected.get();
                let filtered_ids: Vec<String> = filtered.iter().map(row_id).collect();
                let filtered_ids_for_header = filtered_ids.clone();
                let all_selected =
                    !filtered_ids.is_empty() && filtered_ids.iter().all(|id| sel.contains(id));

                let body_rows = filtered
                    .into_iter()
                    .map(|row| {
                        let id = row_id(&row);
                        let id_check = id.clone();
                        let seed = row
                            .get("repo_tags")
                            .and_then(|v| v.as_array())
                            .and_then(|a| a.first())
                            .and_then(|v| v.as_str())
                            .map(str::to_string)
                            .unwrap_or_else(|| id.clone());
                        let name = image_display_name(&row);
                        let size = row.get("size_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
                        let created = row
                            .get("created")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let in_use = image_in_use(&row, &c);
                        let checked = sel.contains(&id);
                        let title_id = id.clone();
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
                                                    s.insert(id_check.clone());
                                                } else {
                                                    s.remove(&id_check);
                                                }
                                            });
                                        }
                                    />
                                </td>
                                <td><span class="cell">{name}</span></td>
                                <td><span class="cell-id" title=title_id>{short_id(&id)}</span></td>
                                <td><span class="cell-num">{format_bytes(size)}</span></td>
                                <td><span class="cell">{created}</span></td>
                                <td>
                                    {if in_use {
                                        view! { <span class="badge badge--info">"in use"</span> }.into_any()
                                    } else {
                                        view! { <span class="badge badge--neutral">"unused"</span> }.into_any()
                                    }}
                                </td>
                                <td class="cell-actions">
                                    <button
                                        type="button"
                                        class="row-action"
                                        on:click=move |_| push_open.set(Some(seed.clone()))
                                    >
                                        "Push"
                                    </button>
                                </td>
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
                                                    for id in &filtered_ids_for_header {
                                                        if on {
                                                            s.insert(id.clone());
                                                        } else {
                                                            s.remove(id);
                                                        }
                                                    }
                                                });
                                            }
                                        />
                                    </th>
                                    <th>"Name"</th>
                                    <th>"ID"</th>
                                    <th>"Size"</th>
                                    <th>"Created"</th>
                                    <th>"Usage"</th>
                                    <th class="cell-actions"></th>
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
        <div class="images-panel">
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
                    prop:disabled=move || unused_ids().is_empty()
                    on:click=move |_| pending_bulk.set(Some(BulkKind::Unused))
                >
                    "Prune unused"
                </button>
                <button
                    type="button"
                    class="btn btn--primary btn--sm"
                    on:click=move |_| push_open.set(Some(String::new()))
                >
                    "Push image"
                </button>
            </div>
            <div class="usage-summary">{move || usage_line().unwrap_or_else(|| "—".to_string())}</div>
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
                                    "Remove {} selected image(s)? This cannot be undone.",
                                    selected.get().len()
                                ),
                                Some(BulkKind::Unused) => format!(
                                    "Remove {} unused image(s)? This cannot be undone.",
                                    unused_ids().len()
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
            <PushModal open=push_open/>
        </div>
    }
}

/// `n_cols`-wide skeleton table body shown before the first fetch resolves.
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
