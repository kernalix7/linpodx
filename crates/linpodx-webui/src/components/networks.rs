use leptos::prelude::*;

use super::list_table::{ListTable, PanelSpec};

#[component]
pub fn NetworkList() -> impl IntoView {
    let spec = PanelSpec {
        api_path: "networks",
        topic: "network",
        columns: &["name", "driver", "subnet", "gateway", "internal"],
        empty_msg: "no networks",
    };
    view! { <ListTable spec=spec/> }
}
