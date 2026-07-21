//! Top-level leptos component — app shell (sidebar + topbar + content).
//!
//! Tab state lives in a single `RwSignal<Tab>`; each panel component is
//! responsible for its own data fetch + WebSocket subscription. The bearer
//! token is read once from `localStorage` and shared down through a context
//! so child components don't have to re-read it.
//!
//! Shell layout (Docker Desktop / Linear style):
//!   ┌──────────┬─────────────────────────────┐
//!   │ sidebar  │ topbar (title · status · ⚙) │
//!   │ (nav)    ├─────────────────────────────┤
//!   │          │ content (active panel)      │
//!   │          ├─────────────────────────────┤
//!   │          │ statusbar                   │
//!   └──────────┴─────────────────────────────┘

use gloo_storage::Storage;
use leptos::prelude::*;

use crate::components::{
    AuditFeed, ClusterView, ContainerList, Icon, ImageList, NetworkList, PinnedClientsView,
    PluginsView, SandboxList, SessionTimeline, SnapshotTree, VolumeList,
};

const TOKEN_KEY: &str = "linpodx_token";
const THEME_KEY: &str = "linpodx_theme";

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

    /// Icon name understood by [`crate::components::Icon`].
    fn icon(self) -> &'static str {
        match self {
            Tab::Containers => "container",
            Tab::Images => "image",
            Tab::Volumes => "volume",
            Tab::Networks => "network",
            Tab::Snapshots => "snapshot",
            Tab::Sessions => "event",
            Tab::Sandbox => "sandbox",
            Tab::Audit => "approval",
            Tab::Cluster => "daemon",
            Tab::PinnedClients => "pin",
            Tab::Plugins => "plugin",
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

/// Pull a `?token=<t>` bearer token out of the current URL, if present.
///
/// The desktop shell (and `linpodx daemon` operators following the docs) hand
/// the token over in the query string; the SPA otherwise only knows the token
/// via localStorage, so without this ingest a fresh webview would load the
/// page yet fail every API call with 401. Tokens are hex, so a plain split is
/// enough — no percent-decoding needed.
fn token_from_query() -> Option<String> {
    let search = web_sys::window()?.location().search().ok()?;
    search
        .trim_start_matches('?')
        .split('&')
        .find_map(|kv| kv.strip_prefix("token="))
        .map(str::to_string)
        .filter(|t| !t.trim().is_empty())
}

/// Read the current theme from `<html data-theme>`; falls back to `"dark"`
/// (the design system is dark-first) when no explicit choice is stored.
fn current_theme() -> String {
    web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.document_element())
        .and_then(|el| el.get_attribute("data-theme"))
        .filter(|t| t == "dark" || t == "light")
        .unwrap_or_else(|| "dark".to_string())
}

/// Stamp `data-theme` on `<html>` and persist the choice to localStorage so it
/// survives reloads (index.html only honours the `?theme=` query on first hit).
fn apply_theme(theme: &str) {
    if let Some(el) = web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.document_element())
    {
        let _ = el.set_attribute("data-theme", theme);
    }
    let _ = gloo_storage::LocalStorage::set(THEME_KEY, theme);
}

#[component]
pub fn AppRoot() -> impl IntoView {
    let active = RwSignal::new(Tab::Containers);
    let collapsed = RwSignal::new(false);
    let theme = RwSignal::new(current_theme());

    // Restore a previously-toggled theme if the query param didn't force one.
    if let Ok(saved) = gloo_storage::LocalStorage::get::<String>(THEME_KEY) {
        if (saved == "dark" || saved == "light") && saved != theme.get_untracked() {
            apply_theme(&saved);
            theme.set(saved);
        }
    }

    // Query-string token (desktop shell / operator handoff) wins over the
    // stored one and is persisted for future loads.
    let query_token = token_from_query();
    if let Some(t) = &query_token {
        let _ = gloo_storage::LocalStorage::set(TOKEN_KEY, t);
    }
    let initial_token = query_token.or_else(|| {
        gloo_storage::LocalStorage::get::<String>(TOKEN_KEY)
            .ok()
            .filter(|s| !s.trim().is_empty())
    });
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

    let toggle_theme = move |_| {
        let next = if theme.get_untracked() == "dark" {
            "light"
        } else {
            "dark"
        };
        apply_theme(next);
        theme.set(next.to_string());
    };

    let toggle_collapse = move |_| collapsed.update(|c| *c = !*c);

    let shell_cls = move || {
        if collapsed.get() {
            "sidebar sidebar--collapsed"
        } else {
            "sidebar"
        }
    };

    view! {
        <div class="app-shell">
            <aside class=shell_cls>
                <div class="sidebar-head">
                    <div class="sidebar-brand">
                        <span class="sidebar-brand__mark"><Icon name="container"/></span>
                        <span class="sidebar-brand__label">"linpodx"</span>
                    </div>
                    <button
                        type="button"
                        class="sidebar-collapse"
                        title="Collapse sidebar"
                        aria-label="Collapse sidebar"
                        on:click=toggle_collapse
                    >
                        <Icon name="chevron-left"/>
                    </button>
                </div>
                <nav class="sidebar-nav">
                    {Tab::ALL.iter().copied().map(|t| {
                        let cls = move || if active.get() == t { "nav-item active" } else { "nav-item" };
                        view! {
                            <button
                                type="button"
                                class=cls
                                title=t.label()
                                on:click=move |_| active.set(t)
                            >
                                <span class="nav-item__icon"><Icon name=t.icon()/></span>
                                <span class="nav-item__label">{t.label()}</span>
                            </button>
                        }
                    }).collect_view()}
                </nav>
                <div class="sidebar-foot">
                    <span class="sidebar-foot__text">"read-only · use CLI to mutate"</span>
                </div>
            </aside>

            <div class="app-main">
                <header class="topbar">
                    <div class="topbar-title">{move || active.get().label()}</div>
                    <div class="topbar-actions">
                        <span
                            class=move || if token.get().is_some() {
                                "status-pill status-pill--ok"
                            } else {
                                "status-pill status-pill--warn"
                            }
                        >
                            {move || if token.get().is_some() { "daemon · token set" } else { "no token" }}
                        </span>
                        <button
                            type="button"
                            class="btn btn--sm btn--secondary"
                            on:click=prompt_token
                        >
                            "Set token"
                        </button>
                        <button
                            type="button"
                            class="theme-toggle"
                            title="Toggle theme"
                            aria-label="Toggle colour theme"
                            on:click=toggle_theme
                        >
                            {move || if theme.get() == "dark" {
                                view! { <Icon name="theme-light"/> }.into_any()
                            } else {
                                view! { <Icon name="theme-dark"/> }.into_any()
                            }}
                        </button>
                    </div>
                </header>

                <main class="content">
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

                <footer class="statusbar">
                    <span>"linpodx web UI"</span>
                    <span>"leptos SPA"</span>
                </footer>
            </div>
        </div>
    }
}
