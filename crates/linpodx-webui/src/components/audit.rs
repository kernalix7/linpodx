use leptos::prelude::*;

use super::list_table::{ListTable, PanelSpec};

#[component]
pub fn AuditFeed() -> impl IntoView {
    let spec = PanelSpec {
        api_path: "audit?limit=100",
        topic: "audit",
        columns: &["seq", "ts", "kind", "profile_name", "container_id"],
        empty_msg: "no audit entries",
    };
    view! { <ListTable spec=spec/> }
}
