use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use super::icons::Icon;
use super::illustrations::EmptySpot;
use super::list_table::{ListTable, PanelSpec};
use crate::app::AuthToken;
use crate::ws::fetch_list;

/// Availability of the cluster aggregation surface, probed once at mount so
/// we can tell "clustering isn't enabled on this daemon" (a 404 — no route
/// mounted without `--cluster-raft`) apart from a genuine failure (podman
/// unreachable, auth error, …) before deciding whether to mount the full
/// `ListTable`.
#[derive(Clone, PartialEq)]
enum Availability {
    Probing,
    Enabled,
    NotEnabled,
    Error(String),
}

#[component]
pub fn ClusterView() -> impl IntoView {
    let auth = use_context::<AuthToken>().expect("AuthToken context provided by AppRoot");
    let availability = RwSignal::new(Availability::Probing);

    let probe = move || {
        let token = match auth.0.get_untracked() {
            Some(t) => t,
            None => {
                availability.set(Availability::Error(
                    "set a bearer token to load data".into(),
                ));
                return;
            }
        };
        availability.set(Availability::Probing);
        spawn_local(async move {
            match fetch_list("cluster/containers", &token).await {
                Ok(_) => availability.set(Availability::Enabled),
                Err(e) if e == "http 404" => availability.set(Availability::NotEnabled),
                Err(e) => availability.set(Availability::Error(e)),
            }
        });
    };

    Effect::new(move |prev: Option<()>| {
        if prev.is_some() {
            return;
        }
        let _ = auth.0.get();
        probe();
    });

    // Cluster aggregation surface is owned by cluster-team — schema may evolve.
    // We render the fields we know about; missing keys fall through to empty
    // cells rather than failing the whole panel.
    let spec = PanelSpec {
        api_path: "cluster/containers",
        topic: "container",
        columns: &["node", "id", "name", "image", "status"],
        empty_msg: "cluster aggregation unavailable",
    };

    let body_view = move || {
        match availability.get() {
        Availability::Probing => view! {
            <div class="loading-inline"><span class="spinner"></span>"Checking cluster availability…"</div>
        }
        .into_any(),
        Availability::NotEnabled => view! {
            <div class="empty-state empty-state--spot">
                <span class="empty-state__spot"><EmptySpot motif="generic"/></span>
                <span class="empty-state__title">"Clustering is not enabled on this daemon"</span>
                <span class="empty-state__hint">
                    "Start the daemon with "<code>"--cluster-raft"</code>" to turn on Raft leader-election, "
                    "and add "<code>"--cluster-raft-advertise <addr>"</code>" once you're ready to add more nodes. "
                    "See "<code>"docs/architecture.md"</code>" for the full cluster bootstrap walkthrough."
                </span>
            </div>
        }
        .into_any(),
        Availability::Error(msg) => view! {
            <div class="error-state">
                <span class="error-state__icon"><Icon name="daemon"/></span>
                <span>{msg}</span>
            </div>
        }
        .into_any(),
        Availability::Enabled => view! { <ListTable spec=spec.clone()/> }.into_any(),
    }
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
            {body_view}
        </div>
    }
}
