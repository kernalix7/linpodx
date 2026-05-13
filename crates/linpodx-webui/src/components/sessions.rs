use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

use super::list_table::{row_actions, ListTable, PanelSpec};
use crate::ws::send_rpc;

#[component]
pub fn SessionTimeline() -> impl IntoView {
    let spec = PanelSpec {
        api_path: "sessions",
        topic: "session",
        columns: &[
            "id",
            "container_id",
            "container_name",
            "profile_name",
            "started_at",
            "ended_at",
        ],
        empty_msg: "no sessions",
    };
    let timeline_open: RwSignal<Option<i64>> = RwSignal::new(None);
    let timeline: RwSignal<Result<Vec<Value>, String>> = RwSignal::new(Ok(Vec::new()));
    let busy = RwSignal::new(false);

    let actions = row_actions(move |row| {
        let id = row.get("id").and_then(|v| v.as_i64());
        match id {
            Some(i) => view! {
                <button
                    type="button"
                    class="row-action"
                    on:click=move |_| timeline_open.set(Some(i))
                >
                    "Timeline"
                </button>
            }
            .into_any(),
            None => view! { <span class="row-action-empty">"—"</span> }.into_any(),
        }
    });

    Effect::new(move |_| {
        let id = match timeline_open.get() {
            Some(i) => i,
            None => return,
        };
        timeline.set(Ok(Vec::new()));
        busy.set(true);
        let params = json!({ "id": id, "kinds": Vec::<String>::new() });
        spawn_local(async move {
            match send_rpc("session_timeline", params).await {
                Ok(v) => {
                    let arr = if let Value::Array(a) = v { a } else { vec![v] };
                    timeline.set(Ok(arr));
                }
                Err(e) => timeline.set(Err(e)),
            }
            busy.set(false);
        });
    });

    let close = move |_| timeline_open.set(None);

    let body_view = move || match timeline.get() {
        Err(msg) => view! { <p class="modal-error">{msg}</p> }.into_any(),
        Ok(items) if items.is_empty() => {
            if busy.get() {
                view! { <p class="modal-empty">"loading…"</p> }.into_any()
            } else {
                view! { <p class="modal-empty">"no events"</p> }.into_any()
            }
        }
        Ok(items) => {
            let lines: Vec<String> = items
                .iter()
                .map(|row| match row {
                    Value::Object(_) => row.to_string(),
                    other => other.to_string(),
                })
                .collect();
            let joined = lines.join("\n");
            view! { <pre class="modal-result">{joined}</pre> }.into_any()
        }
    };

    let title = move || match timeline_open.get() {
        Some(id) => format!("Session #{id} timeline"),
        None => String::from("Session timeline"),
    };

    view! {
        <div class="sessions-panel">
            <ListTable spec=spec actions_for_row=actions/>
            <Show when=move || timeline_open.get().is_some() fallback=|| view! { <></> }>
                <div class="modal-backdrop">
                    <div class="modal-card modal-card-wide">
                        <h3>{title}</h3>
                        <div class="modal-form">
                            {body_view}
                        </div>
                        <div class="modal-actions">
                            <button type="button" on:click=close>"Close"</button>
                        </div>
                    </div>
                </div>
            </Show>
        </div>
    }
}
