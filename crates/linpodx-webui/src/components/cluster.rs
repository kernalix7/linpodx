use leptos::prelude::*;

use super::icons::Icon;
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
    view! {
        <div class="cluster-panel section-scope--system">
            <header class="page-head">
                <div class="page-head__lead">
                    <div class="page-head__disc"><Icon name="daemon"/></div>
                    <div class="page-head__titles">
                        <div class="page-head__eyebrow">"System"</div>
                        <div class="page-head__title">"Cluster"</div>
                        <div class="page-head__sub">"Raft / gossip cluster membership."</div>
                    </div>
                </div>
            </header>
            <ListTable spec=spec/>
        </div>
    }
}
