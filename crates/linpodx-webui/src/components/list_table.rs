//! Phase 10 — card-stack panel renderer.
//!
//! Each panel declares its API path, event topic, and the column list to render
//! per row. We then:
//!
//! * fetch the seed list from `/api/v1/<api_path>` once at mount,
//! * resubscribe via `/ipc` and refetch the seed whenever a topic event arrives,
//! * render every row as a hoverable `.card` with one labelled field per column,
//! * expose a sort selector (column toggle, asc/desc) and a per-tab filter
//!   textbox (case-insensitive substring match across visible columns).
//!
//! Phase 12 — added optional per-row action area. Callers pass a `RowActions`
//! closure that receives the row JSON and returns an `AnyView` rendered after
//! the card fields. Used for [Exec]/[Logs] (Containers), [Push] (Images),
//! [Branch]/[Rollback]/[Remove] (Snapshots), [Timeline] (Sessions).
//!
//! Rendering goes through leptos `view!` so interpolated values are escaped —
//! no `set_html` / `inner_html` anywhere.

use std::sync::Arc;

use leptos::prelude::*;
use serde_json::Value;
use wasm_bindgen_futures::spawn_local;

use crate::app::AuthToken;
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
    let rows: RwSignal<Result<Vec<Value>, String>> = RwSignal::new(Ok(Vec::new()));
    let filter = RwSignal::new(String::new());
    let sort = RwSignal::new(SortState {
        column: None,
        ascending: true,
    });

    let api_path = spec.api_path;
    let topic = spec.topic;
    let columns = spec.columns;
    let empty_msg = spec.empty_msg;

    let reload = move || {
        let token = auth.0.get_untracked();
        let token = match token {
            Some(t) => t,
            None => {
                rows.set(Err("set a bearer token to load data".into()));
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

    // Sort buttons live in the toolbar above the card stack. Clicking the active
    // column toggles direction; clicking a different column resets to ascending.
    let sort_buttons = columns
        .iter()
        .enumerate()
        .map(|(idx, col)| {
            let label = *col;
            let cls = move || {
                let s = sort.get();
                if s.column == Some(idx) {
                    "sort-button active"
                } else {
                    "sort-button"
                }
            };
            let arrow = move || {
                let s = sort.get();
                if s.column == Some(idx) {
                    if s.ascending {
                        " \u{25B2}"
                    } else {
                        " \u{25BC}"
                    }
                } else {
                    ""
                }
            };
            view! {
                <button
                    type="button"
                    class=cls
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
                    {label}
                    {arrow}
                </button>
            }
        })
        .collect_view();

    let actions_for_row_clone = actions_for_row.clone();
    let body_view = move || match rows.get() {
        Err(msg) => view! { <div class="error-state">{msg}</div> }.into_any(),
        Ok(items) if items.is_empty() => {
            view! { <div class="empty-state">{empty_msg}</div> }.into_any()
        }
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
                return view! { <div class="empty-state">"no rows match filter"</div> }.into_any();
            }
            let actions = actions_for_row_clone.clone();
            filtered
                .into_iter()
                .map(|row| {
                    let fields = columns
                        .iter()
                        .map(|col| {
                            let raw = pick_field(&row, col);
                            let is_empty = raw.is_empty();
                            let value_cls = if is_empty {
                                "field-value empty"
                            } else {
                                "field-value"
                            };
                            let display = if is_empty { "—".to_string() } else { raw };
                            view! {
                                <div class="field">
                                    <span class="field-label">{*col}</span>
                                    <span class=value_cls>{display}</span>
                                </div>
                            }
                        })
                        .collect_view();
                    let action_view = actions.as_ref().map(|a| {
                        let rendered = a.render(&row);
                        view! { <div class="card-actions">{rendered}</div> }
                    });
                    view! {
                        <div class="card">
                            {fields}
                            {action_view}
                        </div>
                    }
                })
                .collect_view()
                .into_any()
        }
    };

    view! {
        <section class="panel">
            <div class="panel-toolbar">
                <span class="sort-label">"sort:"</span>
                {sort_buttons}
                <input
                    type="search"
                    placeholder="filter…"
                    on:input=move |ev| {
                        let v = event_target_value(&ev);
                        filter.set(v);
                    }
                />
            </div>
            <div class="card-stack">
                {body_view}
            </div>
        </section>
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
