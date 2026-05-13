use leptos::prelude::*;

use super::list_table::{row_actions, ListTable, PanelSpec};
use super::push_modal::PushModal;

#[component]
pub fn ImageList() -> impl IntoView {
    let spec = PanelSpec {
        api_path: "images",
        topic: "image",
        columns: &["id", "repo_tags", "size", "created_at"],
        empty_msg: "no images",
    };
    let push_open: RwSignal<Option<String>> = RwSignal::new(None);

    let actions = row_actions(move |row| {
        // Prefer the first repo_tag (e.g. "docker.io/me/app:1.0") because the
        // bare image id isn't pushable. Fall back to the id so the modal still
        // opens and the operator can edit the reference manually.
        let seed = row
            .get("repo_tags")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| row.get("id").and_then(|v| v.as_str()).map(str::to_string))
            .unwrap_or_default();
        view! {
            <button
                type="button"
                class="row-action"
                on:click=move |_| push_open.set(Some(seed.clone()))
            >
                "Push"
            </button>
        }
        .into_any()
    });

    view! {
        <div class="images-panel">
            <div class="panel-toolbar push-toolbar">
                <button
                    type="button"
                    class="primary"
                    on:click=move |_| push_open.set(Some(String::new()))
                >
                    "Push image"
                </button>
            </div>
            <ListTable spec=spec actions_for_row=actions/>
            <PushModal open=push_open/>
        </div>
    }
}
