//! Pods panel — `GET /api/v1/pods` list + start/stop/remove row actions and a
//! "New pod" creation modal, all against the Phase 26 pod (compose-style
//! stack) REST surface. Unlike the image/volume panels (which mutate through
//! the `/ipc` JSON-RPC socket via `ws::send_rpc`), pod mutations are plain
//! `POST /api/v1/pods/...` calls — that's the wire shape this lane's IPC
//! contract specifies, so this panel posts JSON bodies directly via
//! `gloo_net` rather than routing through `send_rpc`.
//!
//! Renders its own `<table>` rather than delegating to the shared
//! `ListTable` (`list_table.rs`, outside this panel's owned paths) so it can
//! carry the status chip / stack badge / per-row action columns. Every class
//! used below comes from the existing `style.css` contract.
//!
//! `PodSummary.labels` carries the compose-style stack grouping keys
//! (`com.docker.compose.project`, then `io.podman.compose.project` as a
//! fallback) — this panel surfaces whichever is present as a "Stack" column
//! so a future stacks view has something to key off, but does not itself
//! group rows by stack.

use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

use super::icons::Icon;
use super::illustrations::EmptySpot;
use crate::app::AuthToken;
use crate::helpers::{humanize_timestamp, short_id, status_chip_modifier};
use crate::ws::{fetch_list, subscribe};

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

fn row_name(row: &Value) -> String {
    row.get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// Compose-style stack label — checks `com.docker.compose.project` first,
/// then falls back to `io.podman.compose.project`. `None` when neither key is
/// present on `labels`.
fn stack_label(row: &Value) -> Option<String> {
    let labels = row.get("labels")?.as_object()?;
    labels
        .get("com.docker.compose.project")
        .or_else(|| labels.get("io.podman.compose.project"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// `POST` a JSON body to `path` (already absolute, e.g. `/api/v1/pods/create`)
/// with the bearer token, returning the decoded JSON response body. Written
/// locally (rather than added to `api_client.rs`, outside this panel's owned
/// paths) following the same shape as that module's `send_post_json`.
async fn post_json(path: &str, body: Value, token: &str) -> Result<Value, String> {
    let resp = gloo_net::http::Request::post(path)
        .header("Authorization", &format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .map_err(|e| format!("request build error: {e:?}"))?
        .send()
        .await
        .map_err(|e| format!("fetch error: {e}"))?;
    if !resp.ok() {
        return Err(format!("http {}", resp.status()));
    }
    resp.json::<Value>()
        .await
        .map_err(|e| format!("parse error: {e}"))
}

#[component]
pub fn PodsView() -> impl IntoView {
    let auth = use_context::<AuthToken>().expect("AuthToken context provided by AppRoot");

    let rows: RwSignal<Result<Vec<Value>, String>> = RwSignal::new(Ok(Vec::new()));
    let loading = RwSignal::new(true);
    let filter = RwSignal::new(String::new());
    let now_secs = RwSignal::new((js_sys::Date::now() / 1000.0) as i64);
    let busy_ids: RwSignal<std::collections::HashSet<String>> =
        RwSignal::new(std::collections::HashSet::new());
    let toasts: RwSignal<Vec<Toast>> = RwSignal::new(Vec::new());
    let toast_seq: RwSignal<u64> = RwSignal::new(0);
    let create_open = RwSignal::new(false);
    // (id, name) of the pod pending a remove confirmation, plus its force flag.
    let pending_remove: RwSignal<Option<(String, String)>> = RwSignal::new(None);
    let remove_force = RwSignal::new(false);

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
        now_secs.set((js_sys::Date::now() / 1000.0) as i64);
        spawn_local(async move {
            match fetch_list("pods", &token).await {
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
    // No dedicated `pod` event topic exists (Phase 26) — pod lifecycle
    // changes ride along with container lifecycle events, so this panel
    // refreshes on the same `container` topic the image/volume panels use.
    Effect::new(move |prev: Option<()>| {
        if prev.is_some() {
            return;
        }
        subscribe("container", move |_e| reload());
    });

    let run_action = move |id: String, path_suffix: &'static str, verb: &'static str| {
        let token = match auth.0.get_untracked() {
            Some(t) => t,
            None => {
                push_toast("set a bearer token to act on pods".into(), "error");
                return;
            }
        };
        if busy_ids.get_untracked().contains(&id) {
            return;
        }
        busy_ids.update(|s| {
            s.insert(id.clone());
        });
        let url = format!("/api/v1/pods/{id}/{path_suffix}");
        let id_for_done = id.clone();
        spawn_local(async move {
            match post_json(&url, json!({}), &token).await {
                Ok(_) => push_toast(format!("{verb} sent to {}", short_id(&id)), "success"),
                Err(e) => push_toast(format!("failed to {verb} {}: {e}", short_id(&id)), "error"),
            }
            busy_ids.update(|s| {
                s.remove(&id_for_done);
            });
            reload();
        });
    };

    let confirm_remove = move |_| {
        let (id, _name) = match pending_remove.get_untracked() {
            Some(pair) => pair,
            None => return,
        };
        let force = remove_force.get_untracked();
        let token = match auth.0.get_untracked() {
            Some(t) => t,
            None => {
                push_toast("set a bearer token to act on pods".into(), "error");
                pending_remove.set(None);
                return;
            }
        };
        pending_remove.set(None);
        busy_ids.update(|s| {
            s.insert(id.clone());
        });
        let url = format!("/api/v1/pods/{id}/remove");
        let id_for_done = id.clone();
        spawn_local(async move {
            match post_json(&url, json!({ "force": force }), &token).await {
                Ok(_) => push_toast(format!("removed {}", short_id(&id)), "success"),
                Err(e) => push_toast(format!("failed to remove {}: {e}", short_id(&id)), "error"),
            }
            busy_ids.update(|s| {
                s.remove(&id_for_done);
            });
            reload();
        });
    };

    let body_view = move || {
        if loading.get() {
            return skeleton_rows(6);
        }
        match rows.get() {
            Err(msg) => view! {
                <div class="error-state"><Icon name="approval"/><span>{msg}</span></div>
            }
            .into_any(),
            Ok(items) if items.is_empty() => view! {
                <div class="empty-state empty-state--spot">
                    <span class="empty-state__spot"><EmptySpot motif="containers"/></span>
                    <span class="empty-state__title">"no pods"</span>
                    <span class="empty-state__hint">
                        "Pods group related containers behind a shared network namespace — "
                        "the same concept podman-compose / docker-compose use for a \"stack\". "
                        "Create one with the linpodx CLI (\"linpodx pod create\") or the button above."
                    </span>
                </div>
            }
            .into_any(),
            Ok(items) => {
                let needle = filter.get().trim().to_lowercase();
                let filtered: Vec<Value> = items
                    .into_iter()
                    .filter(|row| {
                        needle.is_empty()
                            || row_name(row).to_lowercase().contains(&needle)
                            || row_id(row).to_lowercase().contains(&needle)
                    })
                    .collect();
                if filtered.is_empty() {
                    return view! {
                        <div class="empty-state">
                            <span class="empty-state__icon"><Icon name="container"/></span>
                            <span class="empty-state__title">"no rows match your filter"</span>
                        </div>
                    }
                    .into_any();
                }
                let count = filtered.len();
                let now = now_secs.get();
                let busy = busy_ids.get();

                let body_rows = filtered
                    .into_iter()
                    .map(|row| {
                        let id = row_id(&row);
                        let name = row_name(&row);
                        let status = row.get("status").and_then(Value::as_str).unwrap_or("");
                        let created_raw = row.get("created").and_then(Value::as_str).unwrap_or("");
                        let created = humanize_timestamp(now, created_raw);
                        let num_containers = row
                            .get("num_containers")
                            .and_then(Value::as_u64)
                            .unwrap_or(0);
                        let infra = row
                            .get("infra_id")
                            .and_then(Value::as_str)
                            .filter(|s| !s.is_empty())
                            .map(short_id);
                        let stack = stack_label(&row);
                        let row_busy = busy.contains(&id);
                        let row_disabled = id.is_empty() || row_busy;

                        let id_for_start = id.clone();
                        let id_for_stop = id.clone();
                        let id_for_remove = id.clone();
                        let name_for_remove = name.clone();

                        let status_view = if status.is_empty() {
                            view! { <span class="cell-muted">"—"</span> }.into_any()
                        } else {
                            let cls = format!("chip {}", status_chip_modifier(status));
                            view! { <span class=cls>{status.to_string()}</span> }.into_any()
                        };

                        view! {
                            <tr>
                                <td>
                                    <span class="cell">{name.clone()}</span>
                                    {(!id.is_empty()).then({
                                        let title_id = id.clone();
                                        move || view! { " "<span class="mono cell-id" title=title_id.clone()>{short_id(&title_id)}</span> }
                                    })}
                                </td>
                                <td>{status_view}</td>
                                <td class="cell-num"><span class="mono">{num_containers.to_string()}</span></td>
                                <td>
                                    {match infra {
                                        Some(short) => view! { <span class="mono cell-id">{short}</span> }.into_any(),
                                        None => view! { <span class="cell-muted">"—"</span> }.into_any(),
                                    }}
                                </td>
                                <td>{created}</td>
                                <td>
                                    {match stack {
                                        Some(s) => view! { <span class="badge badge--neutral">{s}</span> }.into_any(),
                                        None => view! { <span class="cell-muted">"—"</span> }.into_any(),
                                    }}
                                </td>
                                <td class="cell-actions">
                                    <button
                                        type="button"
                                        class="row-action"
                                        prop:disabled=row_disabled
                                        on:click=move |_| run_action(id_for_start.clone(), "start", "start")
                                    >
                                        "Start"
                                    </button>
                                    <button
                                        type="button"
                                        class="row-action"
                                        prop:disabled=row_disabled
                                        on:click=move |_| run_action(id_for_stop.clone(), "stop", "stop")
                                    >
                                        "Stop"
                                    </button>
                                    <button
                                        type="button"
                                        class="row-action danger"
                                        prop:disabled=row_disabled
                                        on:click=move |_| {
                                            remove_force.set(false);
                                            pending_remove.set(Some((id_for_remove.clone(), name_for_remove.clone())));
                                        }
                                    >
                                        "Remove"
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
                                    <th>"Name"</th>
                                    <th>"Status"</th>
                                    <th>"Containers"</th>
                                    <th>"Infra"</th>
                                    <th>"Created"</th>
                                    <th>"Stack"</th>
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

    let refresh_cb: Callback<()> = Callback::new(move |_| reload());

    view! {
        <div class="panel section-scope--workloads">
            <header class="page-head">
                <div class="page-head__lead">
                    <div class="page-head__disc"><Icon name="pod"/></div>
                    <div class="page-head__titles">
                        <div class="page-head__eyebrow">"Workloads"</div>
                        <div class="page-head__title">"Pods"</div>
                        <div class="page-head__sub">"Containers grouped by shared pod namespace."</div>
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
                    class="btn btn--primary btn--sm"
                    on:click=move |_| create_open.set(true)
                >
                    "New pod"
                </button>
            </div>
            {body_view}
            <Show when=move || pending_remove.get().is_some() fallback=|| view! { <></> }>
                <div class="modal-backdrop">
                    <div class="modal-card">
                        <h3>"Confirm removal"</h3>
                        <p class="modal-confirm">
                            {move || match pending_remove.get() {
                                Some((_, name)) => format!(
                                    "Remove pod \"{name}\"? This cannot be undone."
                                ),
                                None => String::new(),
                            }}
                        </p>
                        <label class="modal-inline">
                            <input
                                type="checkbox"
                                class="checkbox"
                                prop:checked=move || remove_force.get()
                                on:change=move |ev| remove_force.set(event_target_checked(&ev))
                            />
                            <span>"Force (remove even if the pod holds running containers)"</span>
                        </label>
                        <div class="modal-actions">
                            <button type="button" class="btn btn--danger" on:click=confirm_remove>"Remove"</button>
                            <button type="button" class="btn" on:click=move |_| pending_remove.set(None)>"Cancel"</button>
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
            <NewPodModal open=create_open refresh=refresh_cb/>
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct PortRow {
    id: u64,
    host_port: String,
    container_port: String,
    protocol: String,
}

fn empty_port_row(id: u64) -> PortRow {
    PortRow {
        id,
        host_port: String::new(),
        container_port: String::new(),
        protocol: String::from("tcp"),
    }
}

/// Parse the form's port rows into the `PortMapping`-shaped JSON array the
/// daemon's `PodCreateParams.ports` expects. Blank rows (both fields empty)
/// are skipped so the default single empty row doesn't need to be deleted by
/// hand before submitting a pod with no published ports.
fn parse_port_rows(rows: &[PortRow]) -> Result<Vec<Value>, String> {
    let mut out = Vec::new();
    for row in rows {
        let host = row.host_port.trim();
        let container = row.container_port.trim();
        if host.is_empty() && container.is_empty() {
            continue;
        }
        if host.is_empty() || container.is_empty() {
            return Err("port rows need both a host and a container port".into());
        }
        let host_port: u16 = host
            .parse()
            .map_err(|_| format!("invalid host port: {host}"))?;
        let container_port: u16 = container
            .parse()
            .map_err(|_| format!("invalid container port: {container}"))?;
        out.push(json!({
            "host_port": host_port,
            "container_port": container_port,
            "protocol": row.protocol,
        }));
    }
    Ok(out)
}

/// "New pod" creation modal — `name` + repeatable port rows, posting
/// `POST /api/v1/pods/create`. Kept as a private submodule-style component
/// (like `images.rs`'s `PullModal`) rather than a sibling file: this lane
/// owns only `pods.rs`.
#[component]
fn NewPodModal(open: RwSignal<bool>, refresh: Callback<()>) -> impl IntoView {
    let auth = use_context::<AuthToken>().expect("AuthToken context provided by AppRoot");

    let name = RwSignal::new(String::new());
    let port_rows = RwSignal::new(vec![empty_port_row(0)]);
    let next_id = RwSignal::new(1_u64);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let busy = RwSignal::new(false);

    Effect::new(move |_| {
        if open.get() {
            name.set(String::new());
            port_rows.set(vec![empty_port_row(0)]);
            next_id.set(1);
            error.set(None);
            busy.set(false);
        }
    });

    let close = move |_| {
        if !busy.get_untracked() {
            open.set(false);
        }
    };

    let add_port = move |_| {
        let id = next_id.get_untracked();
        next_id.set(id + 1);
        port_rows.update(|rows| rows.push(empty_port_row(id)));
    };

    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let token = match auth.0.get_untracked() {
            Some(t) => t,
            None => {
                error.set(Some("set a bearer token before creating a pod".into()));
                return;
            }
        };
        let pod_name = name.get_untracked().trim().to_string();
        if pod_name.is_empty() {
            error.set(Some("pod name is required".into()));
            return;
        }
        let ports = match parse_port_rows(&port_rows.get_untracked()) {
            Ok(p) => p,
            Err(e) => {
                error.set(Some(e));
                return;
            }
        };
        let body = json!({
            "name": pod_name,
            "ports": ports,
            "labels": {},
        });
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            match post_json("/api/v1/pods/create", body, &token).await {
                Ok(_) => {
                    open.set(false);
                    refresh.run(());
                }
                Err(e) => error.set(Some(e)),
            }
            busy.set(false);
        });
    };

    let port_rows_view = move || {
        port_rows
            .get()
            .into_iter()
            .map(|row| {
                let id = row.id;
                let remove_disabled = port_rows.get_untracked().len() <= 1;
                view! {
                    <label class="modal-inline">
                        <input
                            class="input"
                            type="text"
                            placeholder="Host port"
                            prop:value=row.host_port
                            on:input=move |ev| {
                                let value = event_target_value(&ev);
                                port_rows.update(|rows| {
                                    if let Some(r) = rows.iter_mut().find(|r| r.id == id) {
                                        r.host_port = value;
                                    }
                                });
                            }
                        />
                        <input
                            class="input"
                            type="text"
                            placeholder="Container port"
                            prop:value=row.container_port
                            on:input=move |ev| {
                                let value = event_target_value(&ev);
                                port_rows.update(|rows| {
                                    if let Some(r) = rows.iter_mut().find(|r| r.id == id) {
                                        r.container_port = value;
                                    }
                                });
                            }
                        />
                        <select
                            class="select"
                            prop:value=row.protocol
                            on:change=move |ev| {
                                let value = event_target_value(&ev);
                                port_rows.update(|rows| {
                                    if let Some(r) = rows.iter_mut().find(|r| r.id == id) {
                                        r.protocol = value;
                                    }
                                });
                            }
                        >
                            <option value="tcp">"tcp"</option>
                            <option value="udp">"udp"</option>
                        </select>
                        <button
                            type="button"
                            class="btn btn--ghost"
                            prop:disabled=remove_disabled
                            on:click=move |_| {
                                port_rows.update(|rows| {
                                    if rows.len() > 1 {
                                        rows.retain(|r| r.id != id);
                                    }
                                });
                            }
                        >
                            <Icon name="close"/>
                            "Remove"
                        </button>
                    </label>
                }
            })
            .collect_view()
    };

    view! {
        <Show when=move || open.get() fallback=|| view! { <></> }>
            <div class="modal-backdrop">
                <div class="modal-card">
                    <h3>"New pod"</h3>
                    <form on:submit=submit>
                        <div class="modal-form">
                            <div class="field-group">
                                <label class="label">"Name"</label>
                                <input
                                    class="input"
                                    type="text"
                                    placeholder="my-stack"
                                    prop:disabled=move || busy.get()
                                    prop:value=move || name.get()
                                    on:input=move |ev| name.set(event_target_value(&ev))
                                />
                            </div>
                            <div class="field-group">
                                <span class="label">"Ports"</span>
                                {port_rows_view}
                                <button type="button" class="btn" on:click=add_port>"Add port"</button>
                            </div>
                            {move || error.get().map(|msg| view! { <p class="modal-error">{msg}</p> })}
                        </div>
                        <div class="modal-actions">
                            <button type="submit" class="btn btn--primary" prop:disabled=move || busy.get()>
                                {move || if busy.get() { "Creating…" } else { "Create" }}
                            </button>
                            <button type="button" class="btn" on:click=close prop:disabled=move || busy.get()>
                                "Cancel"
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </Show>
    }
}
