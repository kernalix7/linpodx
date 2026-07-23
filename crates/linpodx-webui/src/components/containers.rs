//! Containers panel — Docker Desktop parity upgrade: a bespoke table (not the
//! generic `ListTable`) so we can add live CPU% / Memory columns fed from the
//! shared app-wide metrics poll loop, a humanized "Created" column, and a
//! proper status chip — none of which fit `PanelSpec`'s flat column-name
//! model. Mirrors the pattern `images.rs` already established for the same
//! reason (see its module doc).
//!
//! Wire-shape note: the daemon's `GET /api/v1/containers` returns `names`
//! (an array — podman allows more than one name per container) and `created`
//! (an RFC3339 string), not `name` / `created_at`. Rendering used to bind
//! directly against `PanelSpec::columns = ["id", "name", "image", "status",
//! "created_at"]`, which silently produced a blank Name column and a blank
//! Created column against the real field names. [`crate::helpers::container_display_name`]
//! and [`crate::helpers::humanize_timestamp`] centralize the correct field
//! mapping (+ humanization) so this can't drift again.

use leptos::prelude::*;
use serde_json::Value;
use wasm_bindgen_futures::spawn_local;

use super::create_modal::CreateContainerModal;
use super::exec_modal::ExecModal;
use super::exec_pty_modal::ExecPtyModal;
use super::icons::Icon;
use super::illustrations::EmptySpot;
use super::logs_modal::LogsModal;
use super::{ContainerLiveSample, DashboardShared};
use crate::app::{AuthToken, DensityMode, DrawerState};
use crate::helpers::{
    container_display_name, format_bytes, humanize_timestamp, short_id, status_chip_modifier,
};
use crate::ws::{fetch_list, subscribe};

fn row_id(row: &Value) -> String {
    row.get("id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn row_names(row: &Value) -> Vec<String> {
    row.get("names")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn row_is_running(row: &Value) -> bool {
    row.get("state").and_then(Value::as_str) == Some("running")
}

/// The compose project a container belongs to, from its `labels` map
/// (`com.docker.compose.project`, then `io.podman.compose.project`). `None`
/// for standalone containers. Used to render the Stack badge column — mirrors
/// `stacks.rs::stack_project` so the two views agree on grouping.
fn row_stack_project(row: &Value) -> Option<String> {
    let labels = row.get("labels")?.as_object()?;
    for key in ["com.docker.compose.project", "io.podman.compose.project"] {
        if let Some(v) = labels.get(key).and_then(Value::as_str) {
            let t = v.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    None
}

/// `window.setTimeout`-backed sleep used to periodically nudge the humanized
/// "Created" column forward without needing a full data refetch.
async fn sleep_ms(ms: i32) {
    let promise = js_sys::Promise::new(&mut |resolve, _reject| {
        if let Some(win) = web_sys::window() {
            let _ = win.set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms);
        }
    });
    let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
}

#[component]
pub fn ContainerList() -> impl IntoView {
    let auth = use_context::<AuthToken>().expect("AuthToken context provided by AppRoot");
    let shared = use_context::<DashboardShared>().expect("DashboardShared provided by AppRoot");
    // The detail slide-over is hosted by `AppRoot`; a row's "Details" action
    // sets this shared signal to the container id (deep-links `#container/<id>`).
    let drawer = use_context::<DrawerState>().expect("DrawerState context provided by AppRoot");
    let density = use_context::<DensityMode>().expect("DensityMode context provided by AppRoot");

    let rows: RwSignal<Result<Vec<Value>, String>> = RwSignal::new(Ok(Vec::new()));
    let loading = RwSignal::new(true);
    let filter = RwSignal::new(String::new());
    let now_secs = RwSignal::new((js_sys::Date::now() / 1000.0) as i64);

    let exec_open: RwSignal<Option<String>> = RwSignal::new(None);
    let exec_pty_open: RwSignal<Option<String>> = RwSignal::new(None);
    let logs_open: RwSignal<Option<String>> = RwSignal::new(None);
    let create_open = RwSignal::new(false);

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
            match fetch_list("containers?all=true", &token).await {
                Ok(v) => {
                    let arr = if let Value::Array(a) = v { a } else { vec![v] };
                    rows.set(Ok(arr));
                }
                Err(e) => rows.set(Err(e)),
            }
            loading.set(false);
        });
    };
    let refresh_containers = Callback::new(move |_| reload());

    Effect::new(move |_| {
        let _ = auth.0.get();
        reload();
    });
    Effect::new(move |prev: Option<()>| {
        if prev.is_some() {
            return;
        }
        subscribe("container", move |_event| reload());
    });

    // Nudge the humanized "Created" column forward periodically; the table
    // otherwise only re-renders on data refetch (topic events), so a
    // "3 days ago" label would never advance to "4 days ago" on its own.
    spawn_local(async move {
        loop {
            sleep_ms(30_000).await;
            now_secs.set((js_sys::Date::now() / 1000.0) as i64);
        }
    });

    let body_view = move || {
        if loading.get() {
            return skeleton_rows(8);
        }
        match rows.get() {
            Err(msg) => view! {
                <div class="error-state"><Icon name="approval"/><span>{msg}</span></div>
            }
            .into_any(),
            Ok(items) if items.is_empty() => view! {
                <div class="empty-state empty-state--spot">
                    <span class="empty-state__spot"><EmptySpot motif="containers"/></span>
                    <span class="empty-state__title">"no containers"</span>
                    <span class="empty-state__hint">
                        "Nothing here yet — create one with the linpodx CLI, or adjust your filter."
                    </span>
                </div>
            }
            .into_any(),
            Ok(items) => {
                let needle = filter.get().trim().to_lowercase();
                let filtered: Vec<Value> = items
                    .into_iter()
                    .filter(|row| {
                        if needle.is_empty() {
                            return true;
                        }
                        let name =
                            container_display_name(&row_names(row), &row_id(row)).to_lowercase();
                        let image = row
                            .get("image")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_lowercase();
                        let status = row
                            .get("status")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_lowercase();
                        let id = row_id(row).to_lowercase();
                        let stack = row_stack_project(row).unwrap_or_default().to_lowercase();
                        name.contains(&needle)
                            || image.contains(&needle)
                            || status.contains(&needle)
                            || id.contains(&needle)
                            || stack.contains(&needle)
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
                let latest = shared.latest_metrics.get();
                let body_rows = filtered
                    .into_iter()
                    .map(|row| {
                        render_row(
                            &row,
                            now,
                            &latest,
                            drawer,
                            exec_open,
                            exec_pty_open,
                            logs_open,
                        )
                    })
                    .collect_view();
                view! {
                    <div class="data-table-wrap">
                        <table class=move || density.table_class()>
                            <thead>
                                <tr>
                                    <th>"Name"</th>
                                    <th>"Stack"</th>
                                    <th>"Image"</th>
                                    <th>"Status"</th>
                                    <th>"Created"</th>
                                    <th class="cell-num">"CPU"</th>
                                    <th class="cell-num">"Mem"</th>
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
        <div class="containers-panel section-scope--workloads">
            <header class="page-head">
                <div class="page-head__lead">
                    <div class="page-head__disc"><Icon name="container"/></div>
                    <div class="page-head__titles">
                        <div class="page-head__eyebrow">"Workloads"</div>
                        <div class="page-head__title">"Containers"</div>
                        <div class="page-head__sub">"Create, inspect, and operate local containers."</div>
                    </div>
                </div>
                <div class="page-head__actions">
                    <button
                        type="button"
                        class="btn btn--primary"
                        on:click=move |_| create_open.set(true)
                    >
                        <Icon name="container"/>
                        "New container"
                    </button>
                </div>
            </header>
            <section class="panel">
                <div class="panel-toolbar">
                    <span class="search-box">
                        <span class="search-box__icon"><Icon name="search"/></span>
                        <input
                            class="input"
                            type="search"
                            placeholder="Filter…"
                            on:input=move |ev| filter.set(event_target_value(&ev))
                        />
                    </span>
                </div>
                {body_view}
            </section>
            <ExecModal open=exec_open/>
            <ExecPtyModal open=exec_pty_open/>
            <LogsModal open=logs_open/>
            <CreateContainerModal open=create_open refresh_containers=refresh_containers/>
        </div>
    }
}

/// Render one container row. `latest` is the shared per-container live-metrics
/// snapshot (populated by the app-wide poll loop in `app.rs`); a row shows
/// "—" in the CPU/Mem columns whenever the container isn't `running` or no
/// sample has landed yet (collector warm-up / just-started container).
#[allow(clippy::too_many_arguments)]
fn render_row(
    row: &Value,
    now_secs: i64,
    latest: &std::collections::HashMap<String, ContainerLiveSample>,
    drawer: DrawerState,
    exec_open: RwSignal<Option<String>>,
    exec_pty_open: RwSignal<Option<String>>,
    logs_open: RwSignal<Option<String>>,
) -> AnyView {
    let id = row_id(row);
    let name = container_display_name(&row_names(row), &id);
    // Secondary (muted) line under the container name: image + short id — the
    // Docker Desktop density pattern. Hidden by CSS in compact mode.
    let image_field = row.get("image").and_then(Value::as_str).unwrap_or("");
    let short = if id.is_empty() {
        String::new()
    } else {
        short_id(&id)
    };
    let primary_sub = match (image_field.is_empty(), short.is_empty()) {
        (true, true) => "—".to_string(),
        (true, false) => short.clone(),
        (false, true) => image_field.to_string(),
        (false, false) => format!("{image_field} · {short}"),
    };
    let stack_view = match row_stack_project(row) {
        Some(project) => {
            view! { <span class="badge badge--info" title="Compose project">{project}</span> }
                .into_any()
        }
        None => view! { <span class="cell-muted">"—"</span> }.into_any(),
    };
    let image = row.get("image").and_then(Value::as_str).unwrap_or("");
    let image_view = if image.is_empty() {
        view! { <span class="cell-muted">"—"</span> }.into_any()
    } else {
        view! { <span class="cell mono">{image.to_string()}</span> }.into_any()
    };
    let status = row.get("status").and_then(Value::as_str).unwrap_or("");
    let status_view = if status.is_empty() {
        view! { <span class="cell-muted">"—"</span> }.into_any()
    } else {
        let cls = format!("chip {}", status_chip_modifier(status));
        view! { <span class=cls>{status.to_string()}</span> }.into_any()
    };
    let created_raw = row.get("created").and_then(Value::as_str).unwrap_or("");
    let created = humanize_timestamp(now_secs, created_raw);

    let running = row_is_running(row);
    let sample = if running {
        latest.get(&id).copied()
    } else {
        None
    };
    let (cpu_view, mem_view) = match sample {
        Some(s) => (
            view! { <span class="mono">{format!("{:.1}%", s.cpu_pct * 100.0)}</span> }.into_any(),
            view! { <span class="mono">{format_bytes(s.mem_bytes.max(0.0) as u64)}</span> }
                .into_any(),
        ),
        None => (
            view! { <span class="cell-muted">"—"</span> }.into_any(),
            view! { <span class="cell-muted">"—"</span> }.into_any(),
        ),
    };

    let id_for_details = id.clone();
    let id_for_exec = id.clone();
    let id_for_pty = id.clone();
    let id_for_logs = id.clone();
    let row_disabled = id.is_empty();

    view! {
        <tr>
            <td>
                <span class="cell-primary" title=id.clone()>
                    <span class="cell-primary__main">{name}</span>
                    <span class="cell-primary__sub">{primary_sub}</span>
                </span>
            </td>
            <td>{stack_view}</td>
            <td>{image_view}</td>
            <td>{status_view}</td>
            <td><span class="cell">{created}</span></td>
            <td class="cell-num">{cpu_view}</td>
            <td class="cell-num">{mem_view}</td>
            <td class="cell-actions">
                <button
                    type="button"
                    class="row-action row-action--primary"
                    prop:disabled=row_disabled
                    on:click=move |_| {
                        if !id_for_details.is_empty() {
                            drawer.0.set(Some(id_for_details.clone()));
                        }
                    }
                >
                    "Details"
                </button>
                <button
                    type="button"
                    class="row-action"
                    prop:disabled=row_disabled
                    on:click=move |_| {
                        if !id_for_exec.is_empty() {
                            exec_open.set(Some(id_for_exec.clone()));
                        }
                    }
                >
                    "Exec"
                </button>
                <button
                    type="button"
                    class="row-action"
                    prop:disabled=row_disabled
                    on:click=move |_| {
                        if !id_for_pty.is_empty() {
                            exec_pty_open.set(Some(id_for_pty.clone()));
                        }
                    }
                >
                    "Exec PTY"
                </button>
                <button
                    type="button"
                    class="row-action"
                    prop:disabled=row_disabled
                    on:click=move |_| {
                        if !id_for_logs.is_empty() {
                            logs_open.set(Some(id_for_logs.clone()));
                        }
                    }
                >
                    "Logs"
                </button>
            </td>
        </tr>
    }
    .into_any()
}

/// `n_cols`-wide skeleton table body shown before the first fetch resolves.
fn skeleton_rows(n_cols: usize) -> AnyView {
    let rows = (0..6)
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
