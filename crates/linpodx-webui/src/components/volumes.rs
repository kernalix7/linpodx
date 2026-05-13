use leptos::prelude::*;

use super::list_table::{ListTable, PanelSpec};

#[component]
pub fn VolumeList() -> impl IntoView {
    let spec = PanelSpec {
        api_path: "volumes",
        topic: "volume",
        columns: &["name", "driver", "mountpoint", "created_at"],
        empty_msg: "no volumes",
    };
    view! { <ListTable spec=spec/> }
}
