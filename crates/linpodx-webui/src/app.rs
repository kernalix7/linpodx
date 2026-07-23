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

use std::collections::HashSet;

use gloo_storage::Storage;
use leptos::prelude::*;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;

use crate::components::{
    AuditFeed, ClusterView, CommandPalette, ContainerDetail, ContainerList, ContainerLiveSample,
    Dashboard, DashboardShared, DiskUsageView, Icon, ImageList, NetworkList, PinnedClientsView,
    PluginsView, PodsView, SandboxList, SecretsView, SessionTimeline, Settings, SnapshotTree,
    Sparkline, StacksView, VolumeList,
};

const TOKEN_KEY: &str = "linpodx_token";
const THEME_KEY: &str = "linpodx_theme";
/// Comma-joined [`Section::key`]s of the *collapsed* nav sections (Spec v6 §1.3).
const NAV_SECTIONS_KEY: &str = "linpodx_nav_sections";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    /// App-shell v5 — the at-a-glance home the SPA opens to (new default).
    Dashboard,
    Containers,
    /// Compose/stack grouping — containers grouped by compose project label.
    Stacks,
    /// Pod grouping — containers grouped by podman pod (sibling `pods.rs`).
    Pods,
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
    /// Phase 26 — podman secret store (list / create / remove).
    Secrets,
    /// Spec v6 §5 — disk management center (`system df` breakdown + per-category
    /// prune behind a confirm gate). Body delivered by Lane C's `DiskCenter`.
    Disk,
    /// Spec v6 addendum — codex-lane disk-usage detail view (`DiskUsageView`).
    DiskUsage,
    /// App-shell v5 — daemon info + doctor diagnostics.
    Settings,
}

impl Tab {
    fn label(self) -> &'static str {
        match self {
            Tab::Dashboard => "Dashboard",
            Tab::Containers => "Containers",
            Tab::Stacks => "Stacks",
            Tab::Pods => "Pods",
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
            Tab::Secrets => "Secrets",
            Tab::Disk => "Disk",
            Tab::DiskUsage => "Disk Usage",
            Tab::Settings => "Settings",
        }
    }

    /// One-line subtitle for the §3 page-head. Kept here (not in each panel) so
    /// the shell breadcrumb and the page identity stay in lockstep.
    pub fn subtitle(self) -> &'static str {
        match self {
            Tab::Dashboard => "Live daemon health, capacity and activity",
            Tab::Containers => "Running and stopped containers",
            Tab::Stacks => "Containers grouped by compose project",
            Tab::Pods => "Containers grouped by shared pod namespace",
            Tab::Images => "Local OCI image store",
            Tab::Volumes => "Named data volumes",
            Tab::Networks => "Container networks",
            Tab::Snapshots => "Commit snapshots and rollback tree",
            Tab::Sessions => "Per-container session timeline",
            Tab::Sandbox => "AI-agent sandbox profiles and policy",
            Tab::Audit => "Tamper-evident audit event feed",
            Tab::Cluster => "Raft / gossip cluster membership",
            Tab::PinnedClients => "TOFU-pinned remote clients",
            Tab::Plugins => "Plugin key registry and revocation",
            Tab::Secrets => "Podman secret store",
            Tab::Disk => "Reclaim space across images, containers and volumes",
            Tab::DiskUsage => "Detailed on-disk usage breakdown",
            Tab::Settings => "Daemon info and doctor diagnostics",
        }
    }

    /// Icon name understood by [`crate::components::Icon`]. Unknown names fall
    /// back to a neutral dot (see `icons.rs`), so `"dashboard"` is safe even
    /// before a bespoke glyph exists.
    fn icon(self) -> &'static str {
        match self {
            Tab::Dashboard => "dashboard",
            Tab::Containers => "container",
            Tab::Stacks => "stack",
            Tab::Pods => "pod",
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
            Tab::Secrets => "secret",
            Tab::Disk => "disk",
            Tab::DiskUsage => "disk",
            Tab::Settings => "settings",
        }
    }

    /// Reverse map: which sidebar [`Section`] this tab belongs to.
    pub fn section(self) -> Section {
        match self {
            Tab::Dashboard => Section::Home,
            Tab::Containers | Tab::Pods | Tab::Stacks => Section::Workloads,
            Tab::Images | Tab::Volumes | Tab::Networks | Tab::Secrets => Section::Resources,
            Tab::Sandbox | Tab::Sessions | Tab::Audit | Tab::Snapshots => Section::Sandbox,
            Tab::Cluster
            | Tab::Plugins
            | Tab::PinnedClients
            | Tab::Disk
            | Tab::DiskUsage
            | Tab::Settings => Section::System,
        }
    }
}

/// Sidebar information-architecture group (Spec v6 §1). Sections order the nav
/// rail and, via the `--sec-*` token ramp, give each area its own accent so an
/// active item's colour signals *where you are*, never a status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Section {
    Home,
    Workloads,
    Resources,
    Sandbox,
    System,
}

impl Section {
    /// Eyebrow label for the section header row. `Home` is unlabelled — its
    /// single item renders bare at the top of the rail.
    pub fn label(self) -> &'static str {
        match self {
            Section::Home => "",
            Section::Workloads => "Workloads",
            Section::Resources => "Resources",
            Section::Sandbox => "AI Sandbox",
            Section::System => "System",
        }
    }

    /// CSS modifier that sets the section-accent trio (`--section-fg/soft/disc`).
    pub fn class(self) -> &'static str {
        match self {
            Section::Home => "nav-section--home",
            Section::Workloads => "nav-section--workloads",
            Section::Resources => "nav-section--resources",
            Section::Sandbox => "nav-section--sandbox",
            Section::System => "nav-section--system",
        }
    }

    /// Stable short id used for the section-token custom props (`--sec-<key>-*`)
    /// and the `localStorage` collapse-state persistence.
    pub fn key(self) -> &'static str {
        match self {
            Section::Home => "home",
            Section::Workloads => "workloads",
            Section::Resources => "resources",
            Section::Sandbox => "sandbox",
            Section::System => "system",
        }
    }

    fn from_key(k: &str) -> Option<Section> {
        match k {
            "home" => Some(Section::Home),
            "workloads" => Some(Section::Workloads),
            "resources" => Some(Section::Resources),
            "sandbox" => Some(Section::Sandbox),
            "system" => Some(Section::System),
            _ => None,
        }
    }

    /// The section's tabs, in display order.
    fn tabs(self) -> &'static [Tab] {
        match self {
            Section::Home => &[Tab::Dashboard],
            Section::Workloads => &[Tab::Containers, Tab::Pods, Tab::Stacks],
            Section::Resources => &[Tab::Images, Tab::Volumes, Tab::Networks, Tab::Secrets],
            Section::Sandbox => &[Tab::Sandbox, Tab::Sessions, Tab::Audit, Tab::Snapshots],
            Section::System => &[
                Tab::Cluster,
                Tab::Plugins,
                Tab::PinnedClients,
                Tab::Disk,
                Tab::DiskUsage,
                Tab::Settings,
            ],
        }
    }

    /// The context-appropriate default "+ Create" kind for this section.
    fn default_create(self) -> CreateKind {
        match self {
            Section::Resources => CreateKind::Volume,
            _ => CreateKind::Container,
        }
    }

    const ORDER: [Section; 5] = [
        Section::Home,
        Section::Workloads,
        Section::Resources,
        Section::Sandbox,
        Section::System,
    ];
}

/// The five resource kinds the topbar "+ Create" split-button can spawn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateKind {
    Container,
    Pod,
    Volume,
    Network,
    Secret,
}

impl CreateKind {
    fn label(self) -> &'static str {
        match self {
            CreateKind::Container => "Container",
            CreateKind::Pod => "Pod",
            CreateKind::Volume => "Volume",
            CreateKind::Network => "Network",
            CreateKind::Secret => "Secret",
        }
    }

    fn icon(self) -> &'static str {
        match self {
            CreateKind::Container => "container",
            CreateKind::Pod => "pod",
            CreateKind::Volume => "volume",
            CreateKind::Network => "network",
            CreateKind::Secret => "secret",
        }
    }

    /// The tab that owns this kind's create modal — selecting a kind first
    /// navigates here, then raises the intent the page listens for.
    fn owning_tab(self) -> Tab {
        match self {
            CreateKind::Container => Tab::Containers,
            CreateKind::Pod => Tab::Pods,
            CreateKind::Volume => Tab::Volumes,
            CreateKind::Network => Tab::Networks,
            CreateKind::Secret => Tab::Secrets,
        }
    }

    const MENU: [CreateKind; 5] = [
        CreateKind::Container,
        CreateKind::Pod,
        CreateKind::Volume,
        CreateKind::Network,
        CreateKind::Secret,
    ];
}

/// Cross-cutting "create" intent bus (Spec v6 §2.3). The topbar sets
/// `Some(kind)`; the owning page's Effect opens its local modal and clears it.
/// Decoupled on purpose — the shell never touches page-local modal signals.
///
/// The inner field is read by the page-side listeners (Lanes B/C) via
/// `use_context::<CreateIntent>()`; until those land in this crate it is
/// write-only from the shell, so silence the interim dead-field lint.
#[derive(Clone, Copy)]
pub struct CreateIntent(#[allow(dead_code)] pub RwSignal<Option<CreateKind>>);

/// Shared bearer token signal — `None` means "no token in localStorage; child
/// fetches will surface an auth-needed message".
#[derive(Clone, Copy)]
pub struct AuthToken(pub RwSignal<Option<String>>);

/// Navigation handle — lets overlay components (command palette, dashboard
/// quick actions) switch the active tab without threading props everywhere.
#[derive(Clone, Copy)]
pub struct Nav(pub RwSignal<Tab>);

/// Detail-drawer host slot. `Some(container_id)` opens the right slide-over;
/// this crate renders the host shell + backdrop and owns the open/close +
/// deep-link `#container/<id>` sync — the drawer *body* (tabs) is filled by the
/// container-drawer component another agent provides, which consumes this
/// context.
#[derive(Clone, Copy)]
pub struct DrawerState(pub RwSignal<Option<String>>);

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

/// Load the persisted set of *collapsed* nav sections. Missing/blank key ⇒
/// empty set (all sections open), matching §1.3's default.
fn load_collapsed_sections() -> HashSet<Section> {
    gloo_storage::LocalStorage::get::<String>(NAV_SECTIONS_KEY)
        .unwrap_or_default()
        .split(',')
        .filter_map(Section::from_key)
        .collect()
}

/// Persist the collapsed set as comma-joined keys (stable [`Section::ORDER`]).
fn save_collapsed_sections(set: &HashSet<Section>) {
    let joined = Section::ORDER
        .iter()
        .filter(|s| set.contains(s))
        .map(|s| s.key())
        .collect::<Vec<_>>()
        .join(",");
    let _ = gloo_storage::LocalStorage::set(NAV_SECTIONS_KEY, joined);
}

/// Resolve after `ms` milliseconds via `window.setTimeout` — a `gloo-timers`-free
/// sleep so the metrics poll loop can `await` between ticks.
async fn sleep_ms(ms: i32) {
    let promise = js_sys::Promise::new(&mut |resolve, _reject| {
        if let Some(win) = web_sys::window() {
            let _ = win.set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms);
        }
    });
    let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
}

/// Push a sample onto a fixed-capacity (60) ring buffer signal.
fn push_ring(sig: RwSignal<Vec<(f64, f64)>>, ts: f64, val: f64) {
    sig.update(|buf| {
        buf.push((ts, val));
        if buf.len() > 60 {
            let excess = buf.len() - 60;
            buf.drain(0..excess);
        }
    });
}

/// A container is "running" if its status string reads like podman's `Up …` /
/// `running`. The metrics endpoint only has samples for running containers, so
/// this keeps us from polling stopped ones.
fn is_running(status: &str) -> bool {
    let s = status.to_lowercase();
    s.contains("up") || s.contains("running")
}

/// The single app-wide metrics poll loop. Every 2 s it lists containers,
/// updates the shared running/total counts, sums `cpu_pct` / `mem_bytes` across
/// running containers and pushes one aggregate sample into each ring. Both the
/// dashboard charts and the status-footer sparkline read these rings, so the
/// poll happens exactly once.
fn start_metrics_loop(shared: DashboardShared, token: RwSignal<Option<String>>) {
    spawn_local(async move {
        loop {
            match token.get_untracked() {
                None => shared.connected.set(false),
                Some(tok) => match crate::ws::fetch_list("containers?all=true", &tok).await {
                    Ok(v) => {
                        shared.connected.set(true);
                        // Fetch the version once (cheap composite endpoint).
                        if shared.version.get_untracked().is_empty() {
                            if let Ok(info) = crate::api_client::fetch_system_info(&tok).await {
                                if let Some(ver) =
                                    info.get("linpodx_version").and_then(|s| s.as_str())
                                {
                                    shared.version.set(ver.to_string());
                                }
                            }
                        }
                        let arr = v.as_array().cloned().unwrap_or_default();
                        shared.total.set(arr.len() as u32);
                        let running_ids: Vec<String> = arr
                            .iter()
                            .filter(|c| {
                                c.get("status")
                                    .and_then(|s| s.as_str())
                                    .map(is_running)
                                    .unwrap_or(false)
                            })
                            .filter_map(|c| {
                                c.get("id").and_then(|x| x.as_str()).map(str::to_string)
                            })
                            .collect();
                        shared.running.set(running_ids.len() as u32);

                        let mut cpu_sum = 0.0_f64;
                        let mut mem_sum = 0.0_f64;
                        // Rebuilt wholesale (not merged into the previous map) so a
                        // container that stops between polls drops out rather than
                        // leaving a stale reading behind for the containers table.
                        let mut per_container = std::collections::HashMap::new();
                        for id in &running_ids {
                            if let Ok(m) = crate::api_client::fetch_metrics_latest(id, &tok).await {
                                let cpu = m.get("cpu_pct").and_then(|x| x.as_f64());
                                let mem = m.get("mem_bytes").and_then(|x| x.as_f64());
                                if let Some(c) = cpu {
                                    cpu_sum += c;
                                }
                                if let Some(mm) = mem {
                                    mem_sum += mm;
                                }
                                // Only surface a per-container sample once both fields
                                // are present — a partial/missing sample means the
                                // collector hasn't warmed up for this container yet,
                                // so the table should show "—" rather than a
                                // half-populated row.
                                if let (Some(c), Some(mm)) = (cpu, mem) {
                                    per_container.insert(
                                        id.clone(),
                                        ContainerLiveSample {
                                            cpu_pct: c,
                                            mem_bytes: mm,
                                        },
                                    );
                                }
                            }
                        }
                        shared.latest_metrics.set(per_container);
                        let now = js_sys::Date::now() / 1000.0;
                        push_ring(shared.agg_cpu, now, cpu_sum * 100.0);
                        push_ring(shared.agg_mem, now, mem_sum);
                    }
                    Err(_) => shared.connected.set(false),
                },
            }
            sleep_ms(2_000).await;
        }
    });
}

/// Parse a `#container/<id>[/<tab>]` deep-link fragment into the drawer target
/// container id. Returns `None` for any other fragment shape.
fn drawer_id_from_hash(hash: &str) -> Option<String> {
    let frag = hash.trim_start_matches('#');
    let mut parts = frag.splitn(3, '/');
    match (parts.next(), parts.next()) {
        (Some("container"), Some(id)) if !id.is_empty() => Some(id.to_string()),
        _ => None,
    }
}

/// Read the current `location.hash`.
fn current_hash() -> String {
    web_sys::window()
        .and_then(|w| w.location().hash().ok())
        .unwrap_or_default()
}

/// Write (or clear) the drawer deep-link fragment without triggering a reload.
fn set_drawer_hash(target: Option<&str>) {
    if let Some(win) = web_sys::window() {
        let next = match target {
            Some(id) => format!("#container/{id}"),
            None => String::new(),
        };
        if current_hash() != next {
            let _ = win.location().set_hash(&next);
        }
    }
}

#[component]
pub fn AppRoot() -> impl IntoView {
    let active = RwSignal::new(Tab::Dashboard);
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

    // Navigation + detail-drawer + shared live-metrics contexts.
    provide_context(Nav(active));
    let drawer = RwSignal::new(None::<String>);
    provide_context(DrawerState(drawer));
    let shared = DashboardShared::new();
    provide_context(shared);

    // "+ Create" intent bus (§2.3) — the topbar raises a kind, the owning page
    // consumes it. Provided here so every panel can `use_context` it.
    let create_intent = RwSignal::new(None::<CreateKind>);
    provide_context(CreateIntent(create_intent));

    // Grouped-sidebar per-section collapse state (§1.3): the set of *collapsed*
    // sections, restored from localStorage and persisted on every change.
    let collapsed_sections = RwSignal::new(load_collapsed_sections());
    Effect::new(move |_| save_collapsed_sections(&collapsed_sections.get()));

    // Pre-open the drawer from a `#container/<id>` deep-link on first load.
    if let Some(id) = drawer_id_from_hash(&current_hash()) {
        drawer.set(Some(id));
    }

    // Keep the URL fragment in sync with the drawer state (deep-linking).
    Effect::new(move |_| {
        set_drawer_hash(drawer.get().as_deref());
    });

    // React to browser back/forward (hashchange) by re-syncing the drawer.
    {
        let cb = Closure::<dyn Fn()>::new(move || {
            let next = drawer_id_from_hash(&current_hash());
            if drawer.get_untracked() != next {
                drawer.set(next);
            }
        });
        if let Some(win) = web_sys::window() {
            let _ = win.add_event_listener_with_callback("hashchange", cb.as_ref().unchecked_ref());
        }
        cb.forget();
    }

    // The single app-wide metrics poll loop feeding dashboard + footer.
    start_metrics_loop(shared, token);

    // "+ Create" popover open-state (§2.3).
    let create_menu_open = RwSignal::new(false);

    // Command palette open-state + global Cmd/Ctrl-K + Escape keydown. Escape
    // dismisses, in priority order: create menu → palette → drawer.
    let palette_open = RwSignal::new(false);
    {
        let cb =
            Closure::<dyn Fn(web_sys::KeyboardEvent)>::new(move |ev: web_sys::KeyboardEvent| {
                let key = ev.key();
                if key == "k" && (ev.meta_key() || ev.ctrl_key()) {
                    ev.prevent_default();
                    palette_open.update(|o| *o = !*o);
                } else if key == "Escape" {
                    if create_menu_open.get_untracked() {
                        create_menu_open.set(false);
                    } else if palette_open.get_untracked() {
                        palette_open.set(false);
                    } else if drawer.get_untracked().is_some() {
                        drawer.set(None);
                    }
                }
            });
        if let Some(win) = web_sys::window() {
            let _ = win.add_event_listener_with_callback("keydown", cb.as_ref().unchecked_ref());
        }
        cb.forget();
    }

    // Raise a create intent: navigate to the owning tab, then set the intent so
    // that page's Effect opens its local modal. Never touches page-local state.
    let fire_create = move |kind: CreateKind| {
        active.set(kind.owning_tab());
        create_intent.set(Some(kind));
        create_menu_open.set(false);
    };
    // Primary segment: the section-appropriate default kind for the active tab.
    let create_default = move |_| fire_create(active.get_untracked().section().default_create());

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

    // Toggle a single section's collapsed state (insert⇄remove).
    let toggle_section = move |sec: Section| {
        collapsed_sections.update(|set| {
            if !set.insert(sec) {
                set.remove(&sec);
            }
        });
    };

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
                    {Section::ORDER.iter().copied().map(|sec| {
                        let items = sec.tabs().iter().copied().map(|t| {
                            let cls = move || if active.get() == t { "nav-item active" } else { "nav-item" };
                            view! {
                                <button
                                    type="button"
                                    class=cls
                                    // Section-qualified so the collapsed 60px rail
                                    // (labels hidden) still tells you where you are.
                                    title=format!("{} · {}", sec.label(), t.label())
                                    on:click=move |_| active.set(t)
                                >
                                    <span class="nav-item__icon"><Icon name=t.icon()/></span>
                                    <span class="nav-item__label">{t.label()}</span>
                                </button>
                            }
                        }).collect_view();
                        // Home renders its single item bare (no header row).
                        if sec == Section::Home {
                            return view! {
                                <div class=move || format!("nav-section {}", sec.class())>
                                    <div class="nav-section__items">{items}</div>
                                </div>
                            }.into_any();
                        }
                        let is_collapsed = move || collapsed_sections.get().contains(&sec);
                        let head_chevron_cls = move || if is_collapsed() {
                            "nav-section__chevron nav-section__chevron--collapsed"
                        } else {
                            "nav-section__chevron"
                        };
                        let items_cls = move || if is_collapsed() {
                            "nav-section__items nav-section__items--collapsed"
                        } else {
                            "nav-section__items"
                        };
                        view! {
                            <div class=move || format!("nav-section {}", sec.class())>
                                <button
                                    type="button"
                                    class="nav-section__head"
                                    aria-expanded=move || (!is_collapsed()).to_string()
                                    on:click=move |_| toggle_section(sec)
                                >
                                    <span class="nav-section__eyebrow">{sec.label()}</span>
                                    <span class=head_chevron_cls><Icon name="chevron-down"/></span>
                                </button>
                                <div class=items_cls>{items}</div>
                            </div>
                        }.into_any()
                    }).collect_view()}
                </nav>
                <div class="sidebar-foot">
                    <span class="sidebar-foot__text">
                        {move || {
                            let v = shared.version.get();
                            if v.is_empty() { "linpodx".to_string() } else { format!("linpodx v{v}") }
                        }}
                    </span>
                </div>
            </aside>

            <div class="app-main">
                <header class="topbar">
                    <div class="topbar-crumb">
                        <Show when=move || active.get().section() != Section::Home fallback=|| ()>
                            <span
                                class="topbar-crumb__section"
                                style=move || format!(
                                    "color: var(--sec-{}-fg)",
                                    active.get().section().key(),
                                )
                            >
                                {move || active.get().section().label()}
                            </span>
                            <span class="topbar-crumb__sep">"›"</span>
                        </Show>
                        <span class="topbar-crumb__page">{move || active.get().label()}</span>
                    </div>
                    <div class="topbar-actions">
                        <div
                            class="topbar-health"
                            title="Daemon connection · running/total containers"
                        >
                            <span class=move || {
                                if token.get().is_none() {
                                    "dot dot--warn"
                                } else if shared.connected.get() {
                                    "dot dot--success"
                                } else {
                                    "dot dot--danger"
                                }
                            }></span>
                            <span class="topbar-health__text">
                                {move || format!("{}/{}", shared.running.get(), shared.total.get())}
                            </span>
                        </div>
                        <div class="create-split">
                            <button
                                type="button"
                                class="create-split__main"
                                on:click=create_default
                            >
                                "+ Create"
                            </button>
                            <button
                                type="button"
                                class="create-split__caret"
                                aria-label="Choose what to create"
                                aria-haspopup="menu"
                                aria-expanded=move || create_menu_open.get().to_string()
                                on:click=move |_| create_menu_open.update(|o| *o = !*o)
                            >
                                <Icon name="chevron-down"/>
                            </button>
                            <Show when=move || create_menu_open.get() fallback=|| ()>
                                <div
                                    class="create-menu-scrim"
                                    on:click=move |_| create_menu_open.set(false)
                                ></div>
                                <div class="create-menu" role="menu">
                                    {CreateKind::MENU.iter().copied().map(|kind| {
                                        let key = kind.owning_tab().section().key();
                                        view! {
                                            <button
                                                type="button"
                                                class="create-menu__item"
                                                role="menuitem"
                                                on:click=move |_| fire_create(kind)
                                            >
                                                <span
                                                    class="create-menu__icon"
                                                    style=format!(
                                                        "background: var(--sec-{key}-disc); color: var(--sec-{key}-fg)",
                                                    )
                                                >
                                                    <Icon name=kind.icon()/>
                                                </span>
                                                <span>{kind.label()}</span>
                                            </button>
                                        }
                                    }).collect_view()}
                                </div>
                            </Show>
                        </div>
                        <button
                            type="button"
                            class="cmdk-chip"
                            aria-label="Open command palette"
                            on:click=move |_| palette_open.set(true)
                        >
                            <span class="cmdk-chip__icon"><Icon name="search"/></span>
                            <span class="cmdk-chip__text">"Search"</span>
                            <kbd class="cmdk-chip__key">"⌘K"</kbd>
                        </button>
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
                    // Keyed on the active tab so leptos remounts the wrapper on
                    // every switch — that mount fires the `.content-fade` entry
                    // animation (§7). Reduced-motion collapses it to a no-op.
                    {move || {
                        let body = match active.get() {
                            Tab::Dashboard => view! { <Dashboard/> }.into_any(),
                            Tab::Containers => view! { <ContainerList/> }.into_any(),
                            Tab::Stacks => view! { <StacksView/> }.into_any(),
                            Tab::Pods => view! { <PodsView/> }.into_any(),
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
                            Tab::Secrets => view! { <SecretsView/> }.into_any(),
                            // Body delivered by Lane C (`DiskCenter`); placeholder
                            // keeps the shell compiling until it lands.
                            Tab::Disk => view! { <DiskCenterPlaceholder/> }.into_any(),
                            Tab::DiskUsage => view! { <DiskUsageView/> }.into_any(),
                            Tab::Settings => view! { <Settings/> }.into_any(),
                        };
                        view! { <div class="content-fade">{body}</div> }
                    }}
                </main>

                <StatusFooter shared=shared token=token/>
            </div>

            // Detail-drawer host — a right-anchored slide-over + backdrop. The
            // body (tabs) is filled by the container-drawer component another
            // agent mounts against the same `DrawerState` context.
            <Show when=move || drawer.get().is_some() fallback=|| view! { <></> }>
                <div class="drawer-backdrop" on:click=move |_| drawer.set(None)></div>
                <aside class="drawer">
                    <div class="drawer-head">
                        <span class="mono">
                            {move || drawer.get().unwrap_or_default()}
                        </span>
                        <button
                            type="button"
                            class="btn btn--icon btn--sm"
                            aria-label="Close drawer"
                            on:click=move |_| drawer.set(None)
                        >
                            <Icon name="close"/>
                        </button>
                    </div>
                    <div class="drawer-body" id="drawer-host-slot">
                        <ContainerDetail/>
                    </div>
                </aside>
            </Show>

            <CommandPalette open=palette_open/>
        </div>
    }
}

/// Live status footer — daemon health dot, version, running/total and an
/// aggregate CPU sparkline. All read-only, sourced from the shared metrics
/// context so nothing here re-polls.
#[component]
fn StatusFooter(shared: DashboardShared, token: RwSignal<Option<String>>) -> impl IntoView {
    let health = move || {
        if token.get().is_none() {
            ("dot dot--warn", "no token".to_string())
        } else if shared.connected.get() {
            ("dot dot--success", "connected".to_string())
        } else {
            ("dot dot--danger", "unreachable".to_string())
        }
    };
    let version = move || {
        let v = shared.version.get();
        if v.is_empty() {
            "—".to_string()
        } else {
            format!("v{v}")
        }
    };
    let counts = move || {
        let r = shared.running.get();
        let t = shared.total.get();
        format!("{r}/{t} running")
    };
    view! {
        <footer class="statusbar">
            <span class="statusbar-metric">
                <span class=move || health().0></span>
                {move || health().1}
            </span>
            <span class="statusbar-metric mono">{version}</span>
            <span class="statusbar-metric mono">{counts}</span>
            <span class="statusbar-metric">
                <Sparkline data=Signal::derive(move || shared.agg_cpu.get())/>
            </span>
        </footer>
    }
}

/// Shell-owned §3 page identity header — used by the two placeholder panels
/// below and available for any panel that wants the shared composition. The
/// section-accent trio resolves from the enclosing `.section-scope--*` wrapper.
#[component]
fn PageHead(tab: Tab) -> impl IntoView {
    view! {
        <header class="page-head">
            <div class="page-head__lead">
                <div class="page-head__disc"><Icon name=tab.icon()/></div>
                <div class="page-head__titles">
                    <div class="page-head__eyebrow">{tab.section().label()}</div>
                    <div class="page-head__title">{tab.label()}</div>
                    <div class="page-head__sub">{tab.subtitle()}</div>
                </div>
            </div>
        </header>
    }
}

/// Placeholder for `Tab::Disk` until Lane C's `DiskCenter` lands (§5). Renders
/// the real §3 identity so the tab is never blank, then a quiet notice.
#[component]
fn DiskCenterPlaceholder() -> impl IntoView {
    view! {
        <div class="dashboard-panel section-scope--system">
            <PageHead tab=Tab::Disk/>
            <div class="surface-card">
                <div class="empty-state empty-state--spot">
                    <div class="empty-state__spot"><Icon name="disk"/></div>
                    <div class="empty-state__title">"Disk center"</div>
                    <div class="empty-state__hint">
                        "Per-category usage and reclaim tools mount here once the disk module loads."
                    </div>
                </div>
            </div>
        </div>
    }
}
