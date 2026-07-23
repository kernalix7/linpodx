//! Networks panel — Docker/Rancher-parity upgrade: an on-demand "in use"
//! sweep, bulk row selection with a floating action bar, a client-side
//! "prune unused" sweep, and (Phase 27) a per-network IPAM inspector that
//! expands inline to show subnets/gateways + the attached containers, with
//! per-member detach and an "attach container" control.
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
//!
//! **Inspector.** The expand toggle calls `network_inspect_detail` (the
//! Phase 27 richer inspect) over the IPC WebSocket, and pulls the running
//! container list for the attach select. Attach/detach go through
//! `network_connect` / `network_disconnect`; detach is confirmed first.

use std::collections::HashSet;

use leptos::ev;
use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

use super::context_menu;

use super::icons::Icon;
use super::illustrations::EmptySpot;
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

/// Display name for a running-container summary (`names[0]`, leading `/`
/// stripped) falling back to the id. Used both as the select label and the
/// value passed to `podman network connect` (podman resolves either).
fn container_label(c: &Value) -> String {
    let name = c
        .get("names")
        .and_then(|n| n.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .map(|s| s.trim_start_matches('/').to_string())
        .filter(|s| !s.is_empty());
    name.unwrap_or_else(|| {
        c.get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .chars()
            .take(12)
            .collect()
    })
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

    // ----- Phase 27 inspector state -----
    // Currently-expanded network name (only one open at a time).
    let expanded: RwSignal<Option<String>> = RwSignal::new(None);
    // Inspect result for the expanded network. `None` == loading.
    let detail: RwSignal<Option<Result<Value, String>>> = RwSignal::new(None);
    // Running containers offered in the attach select.
    let running: RwSignal<Vec<Value>> = RwSignal::new(Vec::new());
    // Selected container in the attach dropdown.
    let attach_sel = RwSignal::new(String::new());
    // Attach/detach in flight.
    let action_busy = RwSignal::new(false);
    // (network, container) awaiting detach confirmation.
    let pending_disconnect: RwSignal<Option<(String, String)>> = RwSignal::new(None);
    let focused_row: RwSignal<Option<String>> = RwSignal::new(None);
    let context_menu = context_menu::ContextMenuState::new();

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

    // Fetch the richer inspect + the running-container list for the attach
    // select. Called on expand and after every attach/detach so the member
    // table stays fresh.
    let load_detail = move |net: String| {
        detail.set(None);
        let net_for_rpc = net.clone();
        spawn_local(async move {
            match send_rpc("network_inspect_detail", json!({ "name": net_for_rpc })).await {
                Ok(v) => detail.set(Some(Ok(v))),
                Err(e) => detail.set(Some(Err(e))),
            }
        });
        if let Some(token) = auth.0.get_untracked() {
            spawn_local(async move {
                let list = fetch_list("containers", &token)
                    .await
                    .map(|v| v.as_array().cloned().unwrap_or_default())
                    .unwrap_or_default();
                running.set(list);
            });
        }
    };

    let toggle_row = move |net: String| {
        if expanded.get_untracked().as_deref() == Some(net.as_str()) {
            expanded.set(None);
        } else {
            attach_sel.set(String::new());
            expanded.set(Some(net.clone()));
            load_detail(net);
        }
    };

    let do_attach = move |net: String| {
        let container = attach_sel.get_untracked();
        if container.is_empty() {
            return;
        }
        action_busy.set(true);
        spawn_local(async move {
            match send_rpc(
                "network_connect",
                json!({ "network": net.clone(), "container": container.clone() }),
            )
            .await
            {
                Ok(_) => push_toast(format!("attached {container} to {net}"), "success"),
                Err(e) => push_toast(format!("attach failed: {e}"), "error"),
            }
            action_busy.set(false);
            attach_sel.set(String::new());
            load_detail(net);
        });
    };

    let confirm_disconnect = move |_| {
        let (net, container) = match pending_disconnect.get_untracked() {
            Some(pair) => pair,
            None => return,
        };
        pending_disconnect.set(None);
        action_busy.set(true);
        spawn_local(async move {
            match send_rpc(
                "network_disconnect",
                json!({ "network": net.clone(), "container": container.clone(), "force": false }),
            )
            .await
            {
                Ok(_) => push_toast(format!("disconnected {container}"), "success"),
                Err(e) => push_toast(format!("disconnect failed: {e}"), "error"),
            }
            action_busy.set(false);
            load_detail(net);
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

    let visible_names = move || -> Vec<String> {
        let needle = filter.get_untracked().trim().to_lowercase();
        rows.get_untracked()
            .unwrap_or_default()
            .into_iter()
            .filter(|row| needle.is_empty() || row_name(row).to_lowercase().contains(&needle))
            .map(|row| row_name(&row))
            .filter(|name| !name.is_empty())
            .collect()
    };

    let key_handle = window_event_listener(ev::keydown, move |kev: web_sys::KeyboardEvent| {
        let blocked = pending_bulk.get_untracked().is_some()
            || pending_disconnect.get_untracked().is_some()
            || context_menu.0.get_untracked().is_some();
        context_menu::handle_table_key(&kev, visible_names(), focused_row, blocked, move |name| {
            toggle_row(name);
        });
    });
    on_cleanup(move || key_handle.remove());

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

    // Render the expanded IPAM detail for one network (subnets grid + member
    // table + attach control).
    let render_detail = move |net: String| -> AnyView {
        match detail.get() {
            None => view! {
                <div class="loading-inline"><span class="spinner"></span><span>"Loading…"</span></div>
            }
            .into_any(),
            Some(Err(e)) => view! {
                <div class="error-state"><Icon name="approval"/><span>{e}</span></div>
            }
            .into_any(),
            Some(Ok(v)) => {
                let driver = v
                    .get("driver")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let dns = v.get("dns_enabled").and_then(|x| x.as_bool()).unwrap_or(false);
                let internal = v.get("internal").and_then(|x| x.as_bool()).unwrap_or(false);

                let subnet_rows = v
                    .get("subnets")
                    .and_then(|x| x.as_array())
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|s| {
                        let sn = s
                            .get("subnet")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string();
                        let gw = s
                            .get("gateway")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string();
                        view! {
                            <>
                                <div class="detail-grid__key">{sn}</div>
                                <div class="detail-grid__val">{if gw.is_empty() { "—".to_string() } else { gw }}</div>
                            </>
                        }
                    })
                    .collect_view();

                let members = v
                    .get("containers")
                    .and_then(|x| x.as_array())
                    .cloned()
                    .unwrap_or_default();
                let member_count = members.len();
                let net_for_rows = net.clone();
                let member_rows = members
                    .into_iter()
                    .map(|m| {
                        let cname = m
                            .get("name")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string();
                        let cid = m
                            .get("id")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string();
                        let ipv4 = m
                            .get("ipv4")
                            .and_then(|x| x.as_str())
                            .unwrap_or("—")
                            .to_string();
                        let mac = m
                            .get("mac")
                            .and_then(|x| x.as_str())
                            .unwrap_or("—")
                            .to_string();
                        let label = if cname.is_empty() {
                            cid.chars().take(12).collect::<String>()
                        } else {
                            cname.clone()
                        };
                        let target = if cname.is_empty() { cid.clone() } else { cname };
                        let net_click = net_for_rows.clone();
                        view! {
                            <tr>
                                <td><span class="cell-id" title=label.clone()>{label.clone()}</span></td>
                                <td><span class="cell mono">{ipv4}</span></td>
                                <td><span class="cell mono">{mac}</span></td>
                                <td class="cell-actions">
                                    <button
                                        type="button"
                                        class="btn btn--ghost btn--sm"
                                        prop:disabled=move || action_busy.get()
                                        on:click=move |_| {
                                            pending_disconnect.set(Some((net_click.clone(), target.clone())));
                                        }
                                    >
                                        "Disconnect"
                                    </button>
                                </td>
                            </tr>
                        }
                    })
                    .collect_view();

                let members_view = if member_count == 0 {
                    view! { <p class="cell-muted">"No containers attached."</p> }.into_any()
                } else {
                    view! {
                        <div class="data-table-wrap">
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>"Container"</th>
                                        <th>"IPv4"</th>
                                        <th>"MAC"</th>
                                        <th class="cell-actions">"Actions"</th>
                                    </tr>
                                </thead>
                                <tbody>{member_rows}</tbody>
                            </table>
                        </div>
                    }
                    .into_any()
                };

                let options = running
                    .get()
                    .into_iter()
                    .map(|c| {
                        let label = container_label(&c);
                        let value = label.clone();
                        view! { <option value=value>{label}</option> }
                    })
                    .collect_view();
                let net_attach = net.clone();

                view! {
                    <div class="drawer-body">
                        <div class="detail-grid">
                            <div class="detail-grid__key">"Driver"</div>
                            <div class="detail-grid__val">{driver}</div>
                            <div class="detail-grid__key">"DNS enabled"</div>
                            <div class="detail-grid__val">{dns.to_string()}</div>
                            <div class="detail-grid__key">"Internal"</div>
                            <div class="detail-grid__val">{internal.to_string()}</div>
                            {subnet_rows}
                        </div>
                        <div class="section-title">"Connected containers"</div>
                        {members_view}
                        <div class="section-title">"Attach container"</div>
                        <div class="set-expiry-row">
                            <select
                                class="select"
                                prop:disabled=move || action_busy.get()
                                on:change=move |ev| attach_sel.set(event_target_value(&ev))
                            >
                                <option value="">"Select a running container…"</option>
                                {options}
                            </select>
                            <button
                                type="button"
                                class="btn btn--primary btn--sm"
                                prop:disabled=move || action_busy.get() || attach_sel.get().is_empty()
                                on:click=move |_| do_attach(net_attach.clone())
                            >
                                {move || if action_busy.get() { "Working…" } else { "Attach" }}
                            </button>
                        </div>
                    </div>
                }
                .into_any()
            }
        }
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
                <div class="empty-state empty-state--spot">
                    <span class="empty-state__spot"><EmptySpot motif="networks"/></span>
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
                        let name_toggle = name.clone();
                        let name_show = name.clone();
                        let name_detail = name.clone();
                        let name_for_context = name.clone();
                        let name_for_click = name.clone();
                        let row_key = name.clone();
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
                        let chevron = {
                            let n = name_show.clone();
                            move || {
                                if expanded.get().as_deref() == Some(n.as_str()) {
                                    "▾"
                                } else {
                                    "▸"
                                }
                            }
                        };
                        let show_name = name_show.clone();
                        view! {
                            <tr
                                class=move || context_menu::focused_row_class(focused_row, &row_key)
                                on:click=move |_| focused_row.set(Some(name_for_click.clone()))
                                on:contextmenu=move |ev| {
                                    focused_row.set(Some(name_for_context.clone()));
                                    let name_inspect = name_for_context.clone();
                                    let name_connect = name_for_context.clone();
                                    let name_remove = name_for_context.clone();
                                    context_menu.open(
                                        &ev,
                                        vec![
                                            context_menu::ContextMenuEntry::item(
                                                "Inspect",
                                                None,
                                                false,
                                                name_inspect.is_empty(),
                                                Callback::new(move |_| toggle_row(name_inspect.clone())),
                                            ),
                                            context_menu::ContextMenuEntry::item(
                                                "Connect container..",
                                                None,
                                                false,
                                                name_connect.is_empty(),
                                                Callback::new(move |_| {
                                                    if expanded.get_untracked().as_deref() != Some(name_connect.as_str()) {
                                                        toggle_row(name_connect.clone());
                                                    }
                                                }),
                                            ),
                                            context_menu::ContextMenuEntry::separator(),
                                            context_menu::ContextMenuEntry::item(
                                                "Remove",
                                                None,
                                                true,
                                                name_remove.is_empty(),
                                                Callback::new(move |_| remove_names(vec![name_remove.clone()])),
                                            ),
                                        ],
                                    );
                                }
                            >
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
                                <td>
                                    <button
                                        type="button"
                                        class="btn btn--ghost btn--sm"
                                        title="Inspect IPAM + attached containers"
                                        on:click=move |_| toggle_row(name_toggle.clone())
                                    >
                                        <span class="mono">{chevron}</span>
                                        " "
                                        <span class="cell-id" title=name.clone()>{name.clone()}</span>
                                    </button>
                                </td>
                                <td><span class="cell">{driver}</span></td>
                                <td><span class="cell">{subnet}</span></td>
                                <td><span class="cell">{gateway}</span></td>
                                <td><span class="cell">{internal.to_string()}</span></td>
                                <td>{badge}</td>
                            </tr>
                            <Show
                                when=move || expanded.get().as_deref() == Some(show_name.as_str())
                                fallback=|| view! { <></> }
                            >
                                <tr>
                                    <td colspan="7">{render_detail(name_detail.clone())}</td>
                                </tr>
                            </Show>
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
        <div class="panel section-scope--resources">
            <header class="page-head">
                <div class="page-head__lead">
                    <div class="page-head__disc"><Icon name="network"/></div>
                    <div class="page-head__titles">
                        <div class="page-head__eyebrow">"Resources"</div>
                        <div class="page-head__title">"Networks"</div>
                        <div class="page-head__sub">"Container networks."</div>
                    </div>
                </div>
            </header>
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
            <Show when=move || pending_disconnect.get().is_some() fallback=|| view! { <></> }>
                <div class="modal-backdrop">
                    <div class="modal-card">
                        <h3>"Confirm disconnect"</h3>
                        <p class="modal-confirm">
                            {move || match pending_disconnect.get() {
                                Some((net, container)) => format!(
                                    "Disconnect '{container}' from network '{net}'?"
                                ),
                                None => String::new(),
                            }}
                        </p>
                        <div class="modal-actions">
                            <button type="button" class="btn btn--danger" on:click=confirm_disconnect>"Disconnect"</button>
                            <button type="button" class="btn" on:click=move |_| pending_disconnect.set(None)>"Cancel"</button>
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
            <context_menu::ContextMenu state=context_menu/>
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
