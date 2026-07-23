use leptos::prelude::*;

use super::icons::Icon;
use super::list_table::{ListTable, PanelSpec};

#[component]
pub fn AuditFeed() -> impl IntoView {
    let spec = PanelSpec {
        api_path: "audit?limit=100",
        topic: "audit",
        columns: &["seq", "ts", "kind", "profile_name", "container_id"],
        empty_msg: "no audit entries",
    };
    view! {
        <div class="audit-panel section-scope--sandbox">
            <header class="page-head">
                <div class="page-head__lead">
                    <div class="page-head__disc"><Icon name="approval"/></div>
                    <div class="page-head__titles">
                        <div class="page-head__eyebrow">"AI Sandbox"</div>
                        <div class="page-head__title">"Audit"</div>
                        <div class="page-head__sub">"Tamper-evident audit event feed."</div>
                    </div>
                </div>
            </header>
            <ListTable spec=spec/>
        </div>
    }
}
