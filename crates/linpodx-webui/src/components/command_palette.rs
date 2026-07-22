//! Global command palette (Ctrl / Cmd-K) — always mounted in `AppRoot`, gated
//! on a shared `RwSignal<bool>`. Fuzzy-searches the loaded resource lists and
//! offers verb actions ("stop <name>", "logs <name>", …). The document-level
//! `Cmd/Ctrl-K` keydown that toggles `open` lives in `app.rs`.
//!
//! Ranking uses [`crate::helpers::fuzzy_score`] (unit-tested on the host).

use leptos::ev::KeyboardEvent;
use leptos::prelude::*;
use serde_json::Value;
use wasm_bindgen_futures::spawn_local;

use crate::app::{AuthToken, DrawerState, Nav, Tab};
use crate::helpers::{fuzzy_score, short_id};
use crate::ws::{fetch_list, send_rpc};

/// One indexed resource in the palette corpus.
#[derive(Clone, PartialEq)]
struct Item {
    kind: &'static str,
    id: String,
    display: String,
}

/// A ranked palette row: either a resource to open or a parsed verb action.
#[derive(Clone, PartialEq)]
enum Entry {
    Resource(Item),
    Action {
        verb: String,
        target: String,
        label: String,
        mutating: bool,
    },
}

/// Best display label for a resource row.
fn display_of(row: &Value) -> String {
    if let Some(n) = row.get("name").and_then(|v| v.as_str()) {
        if !n.is_empty() {
            return n.to_string();
        }
    }
    if let Some(t) = row
        .get("repo_tags")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
    {
        if !t.is_empty() {
            return t.to_string();
        }
    }
    row.get("id")
        .and_then(|v| v.as_str())
        .map(short_id)
        .unwrap_or_else(|| "?".to_string())
}

/// Map a resource list into `Item`s under a fixed kind.
fn index_list(v: &Value, kind: &'static str) -> Vec<Item> {
    v.as_array()
        .map(|arr| {
            arr.iter()
                .map(|row| Item {
                    kind,
                    id: row
                        .get("id")
                        .and_then(|x| x.as_str())
                        .map(str::to_string)
                        .unwrap_or_else(|| display_of(row)),
                    display: display_of(row),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Recognised verbs → (canonical verb, is-mutating).
fn parse_verb(word: &str) -> Option<(&'static str, bool)> {
    match word {
        "stop" => Some(("stop", true)),
        "start" => Some(("start", true)),
        "restart" => Some(("restart", true)),
        "remove" | "rm" => Some(("remove", true)),
        "logs" => Some(("logs", false)),
        "exec" | "terminal" => Some(("terminal", false)),
        "inspect" => Some(("inspect", false)),
        _ => None,
    }
}

/// The `Tab` a resource kind navigates to.
fn tab_of(kind: &str) -> Tab {
    match kind {
        "image" => Tab::Images,
        "volume" => Tab::Volumes,
        "network" => Tab::Networks,
        _ => Tab::Containers,
    }
}

#[component]
pub fn CommandPalette(open: RwSignal<bool>) -> impl IntoView {
    let auth = use_context::<AuthToken>().expect("AuthToken context provided by AppRoot");
    let nav = use_context::<Nav>().expect("Nav context provided by AppRoot");
    let drawer = use_context::<DrawerState>().expect("DrawerState provided by AppRoot");

    let corpus = RwSignal::new(Vec::<Item>::new());
    let loading = RwSignal::new(false);
    let query = RwSignal::new(String::new());
    let active = RwSignal::new(0usize);
    let input_ref = NodeRef::<leptos::html::Input>::new();

    // On open: (re)load the corpus and focus the input.
    Effect::new(move |_| {
        if !open.get() {
            return;
        }
        query.set(String::new());
        active.set(0);
        if let Some(el) = input_ref.get() {
            let _ = el.focus();
        }
        let token = auth.0.get_untracked().unwrap_or_default();
        loading.set(true);
        spawn_local(async move {
            let mut items = Vec::new();
            if let Ok(v) = fetch_list("containers?all=true", &token).await {
                items.extend(index_list(&v, "container"));
            }
            if let Ok(v) = fetch_list("images", &token).await {
                items.extend(index_list(&v, "image"));
            }
            if let Ok(v) = fetch_list("volumes", &token).await {
                items.extend(index_list(&v, "volume"));
            }
            if let Ok(v) = fetch_list("networks", &token).await {
                items.extend(index_list(&v, "network"));
            }
            corpus.set(items);
            loading.set(false);
        });
    });

    // Ranked results: an optional verb action first, then fuzzy resource hits.
    let results = Memo::new(move |_| {
        let q = query.get();
        let items = corpus.get();
        let mut out: Vec<Entry> = Vec::new();

        // Verb parsing: "<verb> <name>".
        let trimmed = q.trim();
        if let Some((verb_word, rest)) = trimmed.split_once(char::is_whitespace) {
            if let Some((verb, mutating)) = parse_verb(verb_word.to_lowercase().as_str()) {
                let name = rest.trim();
                if !name.is_empty() {
                    // Prefer a container whose display fuzzy-matches the name.
                    let target = items
                        .iter()
                        .filter(|i| i.kind == "container")
                        .filter_map(|i| fuzzy_score(name, &i.display).map(|s| (s, i)))
                        .max_by_key(|(s, _)| *s)
                        .map(|(_, i)| i.id.clone())
                        .unwrap_or_else(|| name.to_string());
                    out.push(Entry::Action {
                        verb: verb.to_string(),
                        target: target.clone(),
                        label: format!("▷ {verb} {name}"),
                        mutating,
                    });
                }
            }
        }

        let mut scored: Vec<(i32, Item)> = items
            .into_iter()
            .filter_map(|i| fuzzy_score(trimmed, &i.display).map(|s| (s, i)))
            .collect();
        scored.sort_by_key(|(s, _)| std::cmp::Reverse(*s));
        scored.truncate(20);
        out.extend(scored.into_iter().map(|(_, i)| Entry::Resource(i)));
        out
    });

    let invoke = move |entry: Entry| {
        match entry {
            Entry::Resource(item) => {
                if item.kind == "container" {
                    drawer.0.set(Some(item.id));
                } else {
                    nav.0.set(tab_of(item.kind));
                }
            }
            Entry::Action {
                verb,
                target,
                mutating,
                ..
            } => {
                match verb.as_str() {
                    "logs" | "terminal" | "inspect" => {
                        // Drawer-backed verbs: open the container drawer; the
                        // detail-tab deep-link is handled by the drawer host.
                        drawer.0.set(Some(target));
                    }
                    other => {
                        if mutating {
                            let ok = web_sys::window()
                                .and_then(|w| {
                                    w.confirm_with_message(&format!("{other} container {target}?"))
                                        .ok()
                                })
                                .unwrap_or(false);
                            if !ok {
                                return;
                            }
                        }
                        let method = format!("container_{other}");
                        let params = serde_json::json!({ "container_id": target });
                        spawn_local(async move {
                            let _ = send_rpc(&method, params).await;
                        });
                    }
                }
            }
        }
        open.set(false);
    };

    let on_key = move |ev: KeyboardEvent| {
        let list = results.get();
        match ev.key().as_str() {
            "ArrowDown" => {
                ev.prevent_default();
                active.update(|a| {
                    if !list.is_empty() {
                        *a = (*a + 1).min(list.len() - 1);
                    }
                });
            }
            "ArrowUp" => {
                ev.prevent_default();
                active.update(|a| *a = a.saturating_sub(1));
            }
            "Enter" => {
                ev.prevent_default();
                if let Some(entry) = list.get(active.get_untracked()).cloned() {
                    invoke(entry);
                }
            }
            "Escape" => {
                ev.prevent_default();
                open.set(false);
            }
            _ => {}
        }
    };

    let list_view = move || {
        if loading.get() {
            return view! { <div class="loading-inline">"loading…"</div> }.into_any();
        }
        let list = results.get();
        if list.is_empty() {
            return view! {
                <div class="cmdk-item cmdk-item--disabled">"No matches."</div>
            }
            .into_any();
        }
        let cur = active.get();
        list.into_iter()
            .enumerate()
            .map(|(i, entry)| {
                let (kind, label): (String, String) = match &entry {
                    Entry::Resource(it) => (it.kind.to_string(), it.display.clone()),
                    Entry::Action { verb, label, .. } => (verb.clone(), label.clone()),
                };
                let cls = if i == cur {
                    "cmdk-item active"
                } else {
                    "cmdk-item"
                };
                let entry_click = entry.clone();
                let invoke_click = invoke;
                view! {
                    <div
                        class=cls
                        on:mouseenter=move |_| active.set(i)
                        on:click=move |_| invoke_click(entry_click.clone())
                    >
                        <span class="cmdk-item__kind">{kind}</span>
                        <span class="cmdk-item__label">{label}</span>
                    </div>
                }
            })
            .collect_view()
            .into_any()
    };

    view! {
        <Show when=move || open.get() fallback=|| view! { <></> }>
            <div class="cmdk-backdrop" on:click=move |_| open.set(false)>
                <div
                    class="cmdk-panel"
                    on:click=move |ev| ev.stop_propagation()
                >
                    <input
                        node_ref=input_ref
                        class="cmdk-input"
                        placeholder="Search containers, images, volumes… or type a verb"
                        prop:value=move || query.get()
                        on:input=move |ev| query.set(event_target_value(&ev))
                        on:keydown=on_key
                    />
                    <div class="cmdk-list">{list_view}</div>
                </div>
            </div>
        </Show>
    }
}
