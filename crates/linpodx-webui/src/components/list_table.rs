//! Phase 10 — shared data-table panel renderer (redesigned v4).
//!
//! Each panel declares its API path, event topic, and the column list to render
//! per row. We then:
//!
//! * fetch the seed list from `/api/v1/<api_path>` once at mount,
//! * resubscribe via `/ipc` and refetch the seed whenever a topic event arrives,
//! * render every row into a professional data table — sticky header, hover
//!   rows, sortable columns (click a header), status chips for `status`/`state`
//!   columns, monospace ellipsised IDs, and an optional trailing action cell.
//! * expose a search box (case-insensitive substring across visible columns),
//!   a row-count footer, a loading skeleton, an empty state and an error state.
//!
//! The public API — [`PanelSpec`], [`RowActions`], [`row_actions`],
//! [`ListTable`] — is unchanged so the per-tab view components (containers /
//! images / snapshots / …) keep compiling untouched. Only the internal DOM the
//! table emits changed (cards → `<table>`).
//!
//! Rendering goes through leptos `view!` so interpolated values are escaped —
//! no `set_html` / `inner_html` anywhere.

use std::sync::Arc;

use leptos::prelude::*;
use serde_json::Value;
use wasm_bindgen_futures::spawn_local;

use super::icons::Icon;
use crate::app::{AuthToken, DensityMode};
use crate::helpers::status_chip_modifier;
use crate::ws::{fetch_list, subscribe};

#[derive(Clone)]
pub struct PanelSpec {
    pub api_path: &'static str,
    pub topic: &'static str,
    pub columns: &'static [&'static str],
    pub empty_msg: &'static str,
}

/// Per-row action renderer. Wrap a closure with [`row_actions`] when
/// constructing one; the wrapper makes the closure `Clone` + `Send + Sync` +
/// `'static` so it can live inside leptos signals (which assume `Send + Sync`
/// even on the single-threaded wasm target).
#[derive(Clone)]
pub struct RowActions(Arc<dyn Fn(&Value) -> AnyView + Send + Sync>);

impl RowActions {
    pub fn new<F>(f: F) -> Self
    where
        F: Fn(&Value) -> AnyView + Send + Sync + 'static,
    {
        Self(Arc::new(f))
    }

    fn render(&self, row: &Value) -> AnyView {
        (self.0)(row)
    }
}

/// Convenience constructor mirroring leptos' `Callback::new` ergonomics.
pub fn row_actions<F>(f: F) -> RowActions
where
    F: Fn(&Value) -> AnyView + Send + Sync + 'static,
{
    RowActions::new(f)
}

#[derive(Clone, Copy, PartialEq)]
struct SortState {
    /// Index into `spec.columns`. `None` means "no sort applied".
    column: Option<usize>,
    /// `true` = ascending, `false` = descending.
    ascending: bool,
}

#[component]
pub fn ListTable(
    spec: PanelSpec,
    #[prop(optional)] actions_for_row: Option<RowActions>,
) -> impl IntoView {
    let auth = use_context::<AuthToken>().expect("AuthToken context provided by AppRoot");
    let density = use_context::<DensityMode>().expect("DensityMode context provided by AppRoot");
    let rows: RwSignal<Result<Vec<Value>, String>> = RwSignal::new(Ok(Vec::new()));
    let loading = RwSignal::new(true);
    let filter = RwSignal::new(String::new());
    let sort = RwSignal::new(SortState {
        column: None,
        ascending: true,
    });

    let api_path = spec.api_path;
    let topic = spec.topic;
    let columns = spec.columns;
    let empty_msg = spec.empty_msg;
    let empty_icon = topic_icon(topic);
    let has_actions = actions_for_row.is_some();

    let reload = move || {
        let token = auth.0.get_untracked();
        let token = match token {
            Some(t) => t,
            None => {
                rows.set(Err("set a bearer token to load data".into()));
                loading.set(false);
                return;
            }
        };
        spawn_local(async move {
            match fetch_list(api_path, &token).await {
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
        // Re-fire the seed fetch whenever the token changes.
        let _ = auth.0.get();
        reload();
    });

    Effect::new(move |prev: Option<()>| {
        if prev.is_some() {
            return;
        }
        subscribe(topic, move |_event| {
            reload();
        });
    });

    let n_cols = columns.len() + if has_actions { 1 } else { 0 };

    // Header cells are rebuilt on each reactive render (so the sort arrow
    // tracks state) and live in the SAME `<table>` as the body so column widths
    // stay aligned. Clicking the active column toggles direction; clicking a
    // different column resets to ascending.
    let build_header = move || {
        let cells = columns
            .iter()
            .enumerate()
            .map(|(idx, col)| {
                let label = *col;
                let s = sort.get();
                let arrow = if s.column == Some(idx) {
                    if s.ascending {
                        "\u{25B2}"
                    } else {
                        "\u{25BC}"
                    }
                } else {
                    ""
                };
                view! {
                    <th
                        class="th-sortable"
                        on:click=move |_| {
                            let s = sort.get_untracked();
                            let next = if s.column == Some(idx) {
                                SortState { column: Some(idx), ascending: !s.ascending }
                            } else {
                                SortState { column: Some(idx), ascending: true }
                            };
                            sort.set(next);
                        }
                    >
                        <span class="th-inner">
                            {pretty_header(label)}
                            <span class="sort-ind">{arrow}</span>
                        </span>
                    </th>
                }
            })
            .collect_view();
        let action_header = has_actions.then(|| view! { <th class="cell-actions"></th> });
        view! { <tr>{cells}{action_header}</tr> }
    };

    let actions_for_row_clone = actions_for_row.clone();
    let body_view = move || {
        if loading.get() {
            return skeleton_view(n_cols);
        }
        match rows.get() {
            Err(msg) => view! {
                <div class="error-state">
                    <Icon name="approval"/>
                    <span>{msg}</span>
                </div>
            }
            .into_any(),
            Ok(items) if items.is_empty() => empty_view(empty_icon, empty_msg),
            Ok(items) => {
                let needle = filter.get().trim().to_lowercase();
                let mut filtered: Vec<Value> = if needle.is_empty() {
                    items
                } else {
                    items
                        .into_iter()
                        .filter(|row| row_matches(row, columns, &needle))
                        .collect()
                };
                let s = sort.get();
                if let Some(idx) = s.column {
                    let key = columns[idx];
                    filtered.sort_by(|a, b| {
                        let av = pick_field(a, key).to_lowercase();
                        let bv = pick_field(b, key).to_lowercase();
                        if s.ascending {
                            av.cmp(&bv)
                        } else {
                            bv.cmp(&av)
                        }
                    });
                }
                if filtered.is_empty() {
                    return empty_view(empty_icon, "no rows match your filter");
                }
                let count = filtered.len();
                let actions = actions_for_row_clone.clone();
                let body_rows = filtered
                    .into_iter()
                    .map(|row| {
                        let cells = columns
                            .iter()
                            .map(|col| render_cell(&row, col))
                            .collect_view();
                        let action_cell = actions.as_ref().map(|a| {
                            let rendered = a.render(&row);
                            view! { <td class="cell-actions">{rendered}</td> }
                        });
                        view! { <tr>{cells}{action_cell}</tr> }
                    })
                    .collect_view();
                view! {
                    <div class="data-table-wrap">
                        <table class=move || density.table_class()>
                            <thead>{build_header()}</thead>
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
    }
}

/// Skeleton placeholder shown until the first fetch resolves.
fn skeleton_view(n_cols: usize) -> AnyView {
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
            <table class="data-table">
                <tbody>{rows}</tbody>
            </table>
        </div>
    }
    .into_any()
}

/// Rich empty state — icon disc + title + hint.
fn empty_view(icon: &'static str, msg: &'static str) -> AnyView {
    view! {
        <div class="empty-state">
            <span class="empty-state__icon"><Icon name=icon/></span>
            <span class="empty-state__title">{msg}</span>
            <span class="empty-state__hint">
                "Nothing here yet — create one with the linpodx CLI, or adjust your filter."
            </span>
        </div>
    }
    .into_any()
}

/// Render one `<td>` for a row/column pair. `status`/`state` columns become a
/// status chip, `id`-like columns render in monospace with ellipsis, everything
/// else is plain text with an em-dash placeholder when empty.
fn render_cell(row: &Value, col: &str) -> AnyView {
    let raw = pick_field(row, col);
    let is_status = matches!(col, "status" | "state" | "phase");
    let is_id = col == "id" || col.ends_with("_id") || col == "image_ref";

    if raw.is_empty() {
        return view! { <td><span class="cell-muted">"—"</span></td> }.into_any();
    }
    if is_status {
        let cls = format!("chip {}", status_chip_modifier(&raw));
        return view! { <td><span class=cls>{raw}</span></td> }.into_any();
    }
    if is_id {
        let title = raw.clone();
        return view! {
            <td><span class="cell-id" title=title>{raw}</span></td>
        }
        .into_any();
    }
    view! { <td><span class="cell">{raw}</span></td> }.into_any()
}

/// Turn a snake_case column key into a spaced Title-ish header label.
fn pretty_header(key: &str) -> String {
    key.replace('_', " ")
}

/// Pick the default empty-state / error icon for a topic.
fn topic_icon(topic: &str) -> &'static str {
    match topic {
        "container" => "container",
        "image" => "image",
        "volume" => "volume",
        "network" => "network",
        "snapshot" => "snapshot",
        "session" => "event",
        "sandbox" => "sandbox",
        "audit" => "approval",
        "cluster" => "daemon",
        "pin" | "pinned" => "pin",
        "plugin" => "plugin",
        _ => "container",
    }
}

fn row_matches(row: &Value, columns: &[&str], needle: &str) -> bool {
    columns.iter().any(|c| {
        let v = pick_field(row, c);
        v.to_lowercase().contains(needle)
    })
}

fn pick_field(row: &Value, key: &str) -> String {
    let obj = match row.as_object() {
        Some(o) => o,
        None => return String::new(),
    };
    match obj.get(key) {
        None => String::new(),
        Some(v) => fmt_value(v),
    }
}

fn fmt_value(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        Value::Array(arr) => arr.iter().map(fmt_value).collect::<Vec<_>>().join(", "),
        Value::Object(_) => v.to_string(),
    }
}
