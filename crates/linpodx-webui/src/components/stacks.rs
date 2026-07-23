//! Stacks panel — groups containers into Compose "stacks" by their project
//! label so a multi-container app can be operated as a unit.
//!
//! Grouping key: a container's `labels` map (added to `ContainerSummary` so the
//! daemon now ships it in `GET /api/v1/containers`). We look up
//! `com.docker.compose.project` first, then `io.podman.compose.project`;
//! anything without a project label falls into the synthetic `standalone`
//! bucket (rendered last). Every class used below (`.card-stack`, `.card`,
//! `.card-header`, `.chip`, `.data-table`, `.toast`, …) comes straight from the
//! existing `style.css` contract — no new CSS is introduced here.
//!
//! Mutations reuse the *existing* per-container JSON-RPC methods
//! (`container_start` / `container_stop`) over `send_rpc`; a stack's bulk
//! Start / Stop / Restart buttons are just client-side loops over those calls,
//! so no new daemon surface is required (keeping the "read-only Web UI; CLI
//! mutates" posture — a stack op is only ever a fan-out of single-container
//! ops). Podman exposes no `restart` verb here, so "Restart" is a stop→start
//! sequence per member. Progress + per-member failures surface as toasts.

use std::collections::HashMap;

use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

use super::icons::Icon;
use super::illustrations::EmptySpot;
use crate::app::{AuthToken, DensityMode};
use crate::helpers::{container_display_name, short_id, status_chip_modifier};
use crate::ws::{fetch_list, send_rpc, subscribe};

/// Synthetic bucket name for containers that carry no compose project label.
const STANDALONE: &str = "standalone";

/// A group of containers sharing one compose project label (or the synthetic
/// `standalone` bucket).
struct StackGroup {
    name: String,
    members: Vec<Value>,
}

/// The three bulk operations a stack card exposes.
#[derive(Clone, Copy)]
enum BulkAction {
    Start,
    Stop,
    Restart,
}

impl BulkAction {
    fn verb(self) -> &'static str {
        match self {
            BulkAction::Start => "Start",
            BulkAction::Stop => "Stop",
            BulkAction::Restart => "Restart",
        }
    }
}

/// Read a container row's compose project label, if any. Checks the Docker
/// key first, then the podman-compose key. Empty / whitespace values are
/// treated as absent so they don't create a blank-named stack.
fn stack_project(row: &Value) -> Option<String> {
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

/// Group container rows by compose project. Named stacks come first (sorted
/// case-insensitively); the `standalone` bucket, if present, is always last.
/// Insertion order of members within a stack is preserved.
fn group_stacks(rows: &[Value]) -> Vec<StackGroup> {
    let mut order: Vec<String> = Vec::new();
    let mut map: HashMap<String, Vec<Value>> = HashMap::new();
    for row in rows {
        let name = stack_project(row).unwrap_or_else(|| STANDALONE.to_string());
        if !map.contains_key(&name) {
            order.push(name.clone());
        }
        map.entry(name).or_default().push(row.clone());
    }
    order.sort_by(|a, b| match (a == STANDALONE, b == STANDALONE) {
        (true, true) => std::cmp::Ordering::Equal,
        (true, false) => std::cmp::Ordering::Greater,
        (false, true) => std::cmp::Ordering::Less,
        (false, false) => a.to_lowercase().cmp(&b.to_lowercase()),
    });
    order
        .into_iter()
        .map(|name| {
            let members = map.remove(&name).unwrap_or_default();
            StackGroup { name, members }
        })
        .collect()
}

/// Count of running members in a stack (podman `state == "running"`).
fn member_running(members: &[Value]) -> usize {
    members
        .iter()
        .filter(|m| m.get("state").and_then(Value::as_str) == Some("running"))
        .count()
}

/// Canonical container ids for a stack's members (blank ids skipped).
fn member_ids(members: &[Value]) -> Vec<String> {
    members
        .iter()
        .filter_map(|m| m.get("id").and_then(Value::as_str))
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Chip modifier for the running/total health of a stack.
fn stack_chip_cls(running: usize, total: usize) -> &'static str {
    if total > 0 && running == total {
        "chip chip--running"
    } else if running == 0 {
        "chip chip--stopped"
    } else {
        "chip chip--warn"
    }
}

/// Does any member (or the stack name) match the filter needle?
fn group_matches(group: &StackGroup, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    if group.name.to_lowercase().contains(needle) {
        return true;
    }
    group.members.iter().any(|m| {
        let name = container_display_name(&member_names(m), &member_id(m)).to_lowercase();
        let image = m
            .get("image")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_lowercase();
        name.contains(needle) || image.contains(needle)
    })
}

fn member_id(row: &Value) -> String {
    row.get("id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn member_names(row: &Value) -> Vec<String> {
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

/// Fan a bulk action out across a stack's members via the existing per-container
/// RPCs. Emits a starting toast, a per-failure toast, and a final summary
/// toast; refetches the list when done. "Restart" is a stop→start sequence
/// (podman exposes no single restart verb over this IPC).
fn run_bulk(
    action: BulkAction,
    stack: String,
    ids: Vec<String>,
    busy: RwSignal<bool>,
    push_toast: impl Fn(String, &'static str) + Copy + 'static,
    reload: impl Fn() + Copy + 'static,
) {
    if ids.is_empty() || busy.get_untracked() {
        return;
    }
    busy.set(true);
    push_toast(
        format!("{} “{stack}” — {} container(s)…", action.verb(), ids.len()),
        "info",
    );
    spawn_local(async move {
        let mut ok = 0usize;
        let mut fail = 0usize;
        for id in &ids {
            let short = short_id(id);
            let res = match action {
                BulkAction::Start => send_rpc("container_start", json!({ "id": id })).await,
                BulkAction::Stop => send_rpc("container_stop", json!({ "id": id })).await,
                BulkAction::Restart => {
                    match send_rpc("container_stop", json!({ "id": id })).await {
                        Ok(_) => send_rpc("container_start", json!({ "id": id })).await,
                        Err(e) => Err(e),
                    }
                }
            };
            match res {
                Ok(_) => ok += 1,
                Err(e) => {
                    fail += 1;
                    push_toast(
                        format!("{} failed for {short}: {e}", action.verb()),
                        "error",
                    );
                }
            }
        }
        let kind = if fail == 0 { "success" } else { "warn" };
        push_toast(
            format!("{} “{stack}”: {ok} ok, {fail} failed", action.verb()),
            kind,
        );
        busy.set(false);
        reload();
    });
}

#[component]
pub fn StacksView() -> impl IntoView {
    let auth = use_context::<AuthToken>().expect("AuthToken context provided by AppRoot");
    let density = use_context::<DensityMode>().expect("DensityMode context provided by AppRoot");

    let rows: RwSignal<Result<Vec<Value>, String>> = RwSignal::new(Ok(Vec::new()));
    let loading = RwSignal::new(true);
    let filter = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let toasts: RwSignal<Vec<(u64, String, &'static str)>> = RwSignal::new(Vec::new());
    let toast_seq: RwSignal<u64> = RwSignal::new(0);

    let push_toast = move |text: String, kind: &'static str| {
        let id = toast_seq.get_untracked() + 1;
        toast_seq.set(id);
        toasts.update(|t| {
            t.push((id, text, kind));
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

    let body_view = move || {
        if loading.get() {
            return skeleton_cards();
        }
        match rows.get() {
            Err(msg) => view! {
                <div class="error-state"><Icon name="approval"/><span>{msg}</span></div>
            }
            .into_any(),
            Ok(items) if items.is_empty() => empty_state(),
            Ok(items) => {
                let needle = filter.get().trim().to_lowercase();
                let groups: Vec<StackGroup> = group_stacks(&items)
                    .into_iter()
                    .filter(|g| group_matches(g, &needle))
                    .collect();
                if groups.is_empty() {
                    return empty_state();
                }
                let count = groups.len();
                let cards = groups
                    .into_iter()
                    .map(|g| render_stack_card(g, density, busy, push_toast, reload))
                    .collect_view();
                view! {
                    <div class="card-stack">{cards}</div>
                    <div class="table-footer">
                        <span class="row-count">{format!("{count} stack(s)")}</span>
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
                    <div class="page-head__disc"><Icon name="stack"/></div>
                    <div class="page-head__titles">
                        <div class="page-head__eyebrow">"Workloads"</div>
                        <div class="page-head__title">"Stacks"</div>
                        <div class="page-head__sub">
                            "Containers grouped by Compose project — operate a multi-container app as a unit."
                        </div>
                    </div>
                </div>
            </header>
            <section class="panel">
                <div class="panel-toolbar">
                    <span class="search-box">
                        <span class="search-box__icon"><Icon name="search"/></span>
                        <input
                            class="input"
                            type="search"
                            placeholder="Filter stacks…"
                            on:input=move |ev| filter.set(event_target_value(&ev))
                        />
                    </span>
                </div>
                {body_view}
            </section>
            <div class="toast-stack">
                {move || toasts.get().into_iter().map(|(id, text, kind)| {
                    let cls = format!("toast toast--{kind}");
                    view! {
                        <div class=cls on:click=move |_| toasts.update(|v| v.retain(|x| x.0 != id))>
                            <span>{text}</span>
                        </div>
                    }
                }).collect_view()}
            </div>
        </div>
    }
}

/// Render one stack card: header (name + running/total chip), bulk action row,
/// and a member table (name / status / ports).
fn render_stack_card(
    group: StackGroup,
    density: DensityMode,
    busy: RwSignal<bool>,
    push_toast: impl Fn(String, &'static str) + Copy + 'static,
    reload: impl Fn() + Copy + 'static,
) -> AnyView {
    let total = group.members.len();
    let running = member_running(&group.members);
    let ids = member_ids(&group.members);
    let chip_cls = stack_chip_cls(running, total);
    let name = group.name.clone();
    // Secondary (muted) line under the stack name: member-count summary —
    // hidden by CSS in compact mode.
    let member_summary = format!("{total} container(s)");

    let member_rows = group.members.iter().map(render_member_row).collect_view();
    let no_members = ids.is_empty();

    // One handler factory per action, cloning the shared ids/name into the
    // spawned bulk loop.
    let make_click = move |action: BulkAction| {
        let ids = ids.clone();
        let name = name.clone();
        move |_| run_bulk(action, name.clone(), ids.clone(), busy, push_toast, reload)
    };
    let on_start = make_click(BulkAction::Start);
    let on_stop = make_click(BulkAction::Stop);
    let on_restart = make_click(BulkAction::Restart);

    view! {
        <div class="card">
            <div class="card-header">
                <span class="cell-primary card-header__title">
                    <span class="cell-primary__main">{group.name.clone()}</span>
                    <span class="cell-primary__sub">{member_summary}</span>
                </span>
                <span class="card-header__status">
                    <span class=chip_cls>{format!("{running}/{total} running")}</span>
                </span>
            </div>
            <div class="panel-toolbar">
                <button
                    type="button"
                    class="btn btn--sm btn--secondary"
                    prop:disabled=move || no_members || busy.get()
                    on:click=on_start
                >
                    "Start"
                </button>
                <button
                    type="button"
                    class="btn btn--sm btn--secondary"
                    prop:disabled=move || no_members || busy.get()
                    on:click=on_stop
                >
                    "Stop"
                </button>
                <button
                    type="button"
                    class="btn btn--sm btn--secondary"
                    prop:disabled=move || no_members || busy.get()
                    on:click=on_restart
                >
                    "Restart"
                </button>
            </div>
            <div class="data-table-wrap">
                <table class=move || density.table_class()>
                    <thead>
                        <tr>
                            <th>"Name"</th>
                            <th>"Status"</th>
                            <th>"Ports"</th>
                        </tr>
                    </thead>
                    <tbody>{member_rows}</tbody>
                </table>
            </div>
        </div>
    }
    .into_any()
}

/// One member row inside a stack card.
fn render_member_row(row: &Value) -> AnyView {
    let id = member_id(row);
    let name = container_display_name(&member_names(row), &id);
    let status = row.get("status").and_then(Value::as_str).unwrap_or("");
    let status_view = if status.is_empty() {
        view! { <span class="cell-muted">"—"</span> }.into_any()
    } else {
        let cls = format!("chip {}", status_chip_modifier(status));
        view! { <span class=cls>{status.to_string()}</span> }.into_any()
    };
    let ports: Vec<String> = row
        .get("ports")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let ports_view = if ports.is_empty() {
        view! { <span class="cell-muted">"—"</span> }.into_any()
    } else {
        view! { <span class="mono">{ports.join(", ")}</span> }.into_any()
    };

    view! {
        <tr>
            <td><span class="cell">{name}</span></td>
            <td>{status_view}</td>
            <td>{ports_view}</td>
        </tr>
    }
    .into_any()
}

/// Empty-state shown when there are no containers (or none match the filter).
fn empty_state() -> AnyView {
    view! {
        <div class="empty-state empty-state--spot">
            <span class="empty-state__spot"><EmptySpot motif="containers"/></span>
            <span class="empty-state__title">"no stacks"</span>
            <span class="empty-state__hint">
                "Compose projects appear here once you run containers labelled with a compose project."
            </span>
        </div>
    }
    .into_any()
}

/// Placeholder card skeletons shown before the first fetch resolves.
fn skeleton_cards() -> AnyView {
    let cards = (0..2)
        .map(|_| {
            view! {
                <div class="card">
                    <div class="card-header">
                        <span class="skeleton-line"></span>
                    </div>
                    <div class="data-table-wrap">
                        <table class="data-table">
                            <tbody>
                                {(0..3).map(|_| view! {
                                    <tr>
                                        <td><span class="skeleton-line"></span></td>
                                        <td><span class="skeleton-line"></span></td>
                                        <td><span class="skeleton-line"></span></td>
                                    </tr>
                                }).collect_view()}
                            </tbody>
                        </table>
                    </div>
                </div>
            }
        })
        .collect_view();
    view! { <div class="card-stack">{cards}</div> }.into_any()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn row(id: &str, project: Option<&str>, state: &str) -> Value {
        let mut labels = serde_json::Map::new();
        if let Some(p) = project {
            labels.insert("com.docker.compose.project".to_string(), json!(p));
        }
        json!({
            "id": id,
            "names": [id],
            "image": "alpine:latest",
            "state": state,
            "status": "Up",
            "ports": [],
            "labels": Value::Object(labels),
        })
    }

    #[test]
    fn stack_project_prefers_docker_then_podman_key() {
        let docker = json!({ "labels": { "com.docker.compose.project": "web" } });
        assert_eq!(stack_project(&docker).as_deref(), Some("web"));
        let podman = json!({ "labels": { "io.podman.compose.project": "api" } });
        assert_eq!(stack_project(&podman).as_deref(), Some("api"));
        let both = json!({ "labels": {
            "com.docker.compose.project": "primary",
            "io.podman.compose.project": "secondary",
        }});
        assert_eq!(stack_project(&both).as_deref(), Some("primary"));
    }

    #[test]
    fn stack_project_none_for_missing_or_blank() {
        assert!(stack_project(&json!({ "labels": {} })).is_none());
        assert!(stack_project(&json!({})).is_none());
        assert!(
            stack_project(&json!({ "labels": { "com.docker.compose.project": "  " } })).is_none()
        );
    }

    #[test]
    fn group_stacks_buckets_and_orders_standalone_last() {
        let rows = vec![
            row("z1", None, "running"),
            row("b1", Some("beta"), "running"),
            row("a1", Some("alpha"), "exited"),
            row("b2", Some("beta"), "exited"),
        ];
        let groups = group_stacks(&rows);
        let names: Vec<&str> = groups.iter().map(|g| g.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "beta", STANDALONE]);
        // beta has both members; standalone has the unlabelled one.
        let beta = groups.iter().find(|g| g.name == "beta").unwrap();
        assert_eq!(beta.members.len(), 2);
        assert_eq!(member_running(&beta.members), 1);
        assert_eq!(member_ids(&beta.members), vec!["b1", "b2"]);
    }

    #[test]
    fn stack_chip_reflects_health() {
        assert_eq!(stack_chip_cls(2, 2), "chip chip--running");
        assert_eq!(stack_chip_cls(0, 2), "chip chip--stopped");
        assert_eq!(stack_chip_cls(1, 2), "chip chip--warn");
        assert_eq!(stack_chip_cls(0, 0), "chip chip--stopped");
    }

    #[test]
    fn group_matches_by_name_or_member() {
        let g = StackGroup {
            name: "myapp".to_string(),
            members: vec![row("web-1", Some("myapp"), "running")],
        };
        assert!(group_matches(&g, ""));
        assert!(group_matches(&g, "myapp"));
        assert!(group_matches(&g, "web"));
        assert!(group_matches(&g, "alpine"));
        assert!(!group_matches(&g, "zzz"));
    }
}
