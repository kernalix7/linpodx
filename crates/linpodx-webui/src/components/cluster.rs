use leptos::prelude::*;

use super::list_table::{ListTable, PanelSpec};

#[component]
pub fn ClusterView() -> impl IntoView {
    // Cluster aggregation surface is owned by cluster-team — schema may evolve.
    // We render the fields we know about; missing keys fall through to empty
    // cells rather than failing the whole panel.
    let spec = PanelSpec {
        api_path: "cluster/containers",
        topic: "container",
        columns: &["node", "id", "name", "image", "status"],
        empty_msg: "cluster aggregation unavailable",
    };
    view! { <ListTable spec=spec/> }
}
