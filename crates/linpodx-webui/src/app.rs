//! Top-level leptos component — tab strip + header + active panel.
//!
//! Tab state lives in a single `RwSignal<Tab>`; each panel component is
//! responsible for its own data fetch + WebSocket subscription. The bearer
//! token is read once from `localStorage` and shared down through a context
//! so child components don't have to re-read it.

use gloo_storage::Storage;
use leptos::prelude::*;

use crate::components::{
    AuditFeed, ClusterView, ContainerList, ImageList, NetworkList, PinnedClientsView, PluginsView,
    SandboxList, SessionTimeline, SnapshotTree, VolumeList,
};

const TOKEN_KEY: &str = "linpodx_token";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    Containers,
    Images,
    Volumes,
    Networks,
    Snapshots,
    Sessions,
    Sandbox,
    Audit,
    Cluster,
    /// Phase 17 — TOFU pin-store status / countdown + "Set expiry" input.
    PinnedClients,
    /// Phase 17 — plugin key registry + cluster-wide revocation.
    Plugins,
}

impl Tab {
    fn label(self) -> &'static str {
        match self {
            Tab::Containers => "Containers",
            Tab::Images => "Images",
            Tab::Volumes => "Volumes",
            Tab::Networks => "Networks",
            Tab::Snapshots => "Snapshots",
            Tab::Sessions => "Sessions",
            Tab::Sandbox => "Sandbox",
            Tab::Audit => "Audit",
            Tab::Cluster => "Cluster",
            Tab::PinnedClients => "Pinned Clients",
            Tab::Plugins => "Plugins",
        }
    }

    const ALL: [Tab; 11] = [
        Tab::Containers,
        Tab::Images,
        Tab::Volumes,
        Tab::Networks,
        Tab::Snapshots,
        Tab::Sessions,
        Tab::Sandbox,
        Tab::Audit,
        Tab::Cluster,
        Tab::PinnedClients,
        Tab::Plugins,
    ];
}

/// Shared bearer token signal — `None` means "no token in localStorage; child
/// fetches will surface an auth-needed message".
#[derive(Clone, Copy)]
pub struct AuthToken(pub RwSignal<Option<String>>);

#[component]
pub fn AppRoot() -> impl IntoView {
    let active = RwSignal::new(Tab::Containers);

    let initial_token = gloo_storage::LocalStorage::get::<String>(TOKEN_KEY)
        .ok()
        .filter(|s| !s.trim().is_empty());
    let token = RwSignal::new(initial_token);
    provide_context(AuthToken(token));

    let prompt_token = move |_| {
        let window = match web_sys::window() {
            Some(w) => w,
            None => return,
        };
        let current = token.get_untracked().unwrap_or_default();
        let prompt = window
            .prompt_with_message_and_default("Enter linpodx remote token:", &current)
            .ok()
            .flatten();
        if let Some(s) = prompt {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                gloo_storage::LocalStorage::delete(TOKEN_KEY);
                token.set(None);
            } else {
                let _ = gloo_storage::LocalStorage::set(TOKEN_KEY, trimmed);
                token.set(Some(trimmed.to_string()));
            }
        }
    };

    view! {
        <header>
            <div class="brand">"linpodx"</div>
            <div class="status">
                <span class="token-indicator">
                    {move || if token.get().is_some() { "token set" } else { "no token" }}
                </span>
                <button type="button" on:click=prompt_token>"Set token"</button>
            </div>
        </header>
        <nav id="tabs">
            {Tab::ALL.iter().copied().map(|t| {
                let cls = move || if active.get() == t { "tab active" } else { "tab" };
                view! {
                    <button
                        type="button"
                        class=cls
                        on:click=move |_| active.set(t)
                    >
                        {t.label()}
                    </button>
                }
            }).collect_view()}
        </nav>
        <main>
            {move || match active.get() {
                Tab::Containers => view! { <ContainerList/> }.into_any(),
                Tab::Images => view! { <ImageList/> }.into_any(),
                Tab::Volumes => view! { <VolumeList/> }.into_any(),
                Tab::Networks => view! { <NetworkList/> }.into_any(),
                Tab::Snapshots => view! { <SnapshotTree/> }.into_any(),
                Tab::Sessions => view! { <SessionTimeline/> }.into_any(),
                Tab::Sandbox => view! { <SandboxList/> }.into_any(),
                Tab::Audit => view! { <AuditFeed/> }.into_any(),
                Tab::Cluster => view! { <ClusterView/> }.into_any(),
                Tab::PinnedClients => view! { <PinnedClientsView/> }.into_any(),
                Tab::Plugins => view! { <PluginsView/> }.into_any(),
            }}
        </main>
        <footer>
            <span>"read-only views — use the CLI for mutations"</span>
            <span>"leptos SPA (Phase 9)"</span>
        </footer>
    }
}
