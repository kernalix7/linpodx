//! Settings & Diagnostics (`Tab::Settings`) — App-shell v5 §5.
//!
//! Two independent `.surface-card` sections, each with its own fetch/loading/
//! error state so one failing endpoint never blanks the whole page:
//!   - **Daemon info** — `GET /api/v1/system/info` rendered as a
//!     `.detail-grid`, plus a "Set token" / "Clear token" control mirroring
//!     the topbar prompt flow (same `localStorage` slot as `app.rs`) and a
//!     one-line pointer to the theme toggle.
//!   - **Diagnostics** — `POST /api/v1/doctor/run` rendered as a
//!     `.doctor-list` (pass/warn/fail rows + summary badges). Auto-runs once
//!     on mount and on every token change; a manual re-run button and an `r`
//!     keyboard shortcut (while this tab is mounted and no text input is
//!     focused) re-issue the sweep.
//!
//! A third card links out to Audit / Sessions via the shared [`Nav`] context
//! — no new data fetch, just `active.set(...)`.

use gloo_storage::Storage;
use leptos::ev;
use leptos::prelude::*;
use serde_json::Value;
use wasm_bindgen_futures::spawn_local;

use super::icons::Icon;
use super::illustrations::EmptySpot;
use crate::app::{AuthToken, Nav, Tab};

/// Mirrors `app.rs::TOKEN_KEY`. Kept as a local literal rather than importing
/// a private constant from another agent's mount-point file — both slots must
/// stay in sync (same `localStorage` key the topbar's "Set token" flow uses).
const TOKEN_KEY: &str = "linpodx_token";

#[derive(Clone, Debug)]
struct DoctorCheck {
    label: String,
    outcome: String,
    detail: Option<String>,
    fix_hint: Option<String>,
}

impl DoctorCheck {
    fn from_value(v: &Value) -> Option<Self> {
        let obj = v.as_object()?;
        Some(Self {
            label: obj
                .get("label")
                .and_then(|x| x.as_str())
                .unwrap_or("check")
                .to_string(),
            outcome: obj
                .get("outcome")
                .and_then(|x| x.as_str())
                .unwrap_or("warn")
                .to_string(),
            detail: obj
                .get("detail")
                .and_then(|x| x.as_str())
                .map(str::to_string),
            fix_hint: obj
                .get("fix_hint")
                .and_then(|x| x.as_str())
                .map(str::to_string),
        })
    }

    /// `.doctor-row` plus the outcome modifier — see the style.css contract's
    /// `.doctor-row(.pass|.warn|.fail)` notation (space-joined, not `--`).
    fn row_class(&self) -> String {
        let modifier = match self.outcome.as_str() {
            "pass" => "pass",
            "fail" => "fail",
            _ => "warn",
        };
        format!("doctor-row {modifier}")
    }
}

#[derive(Clone, Debug)]
struct DoctorSummary {
    checks: Vec<DoctorCheck>,
    pass: u64,
    warn: u64,
    fail: u64,
}

impl DoctorSummary {
    fn from_value(v: &Value) -> Option<Self> {
        let obj = v.as_object()?;
        let checks = obj
            .get("checks")?
            .as_array()?
            .iter()
            .filter_map(DoctorCheck::from_value)
            .collect();
        Some(Self {
            checks,
            pass: obj.get("pass_count").and_then(|x| x.as_u64()).unwrap_or(0),
            warn: obj.get("warn_count").and_then(|x| x.as_u64()).unwrap_or(0),
            fail: obj.get("fail_count").and_then(|x| x.as_u64()).unwrap_or(0),
        })
    }
}

/// Display heuristic (not validation): a `fix_hint` that looks like a path or
/// URL renders as a link, everything else as plain text.
fn looks_linkable(s: &str) -> bool {
    s.starts_with('/')
        || s.starts_with("http://")
        || s.starts_with("https://")
        || s.starts_with("docs/")
}

/// `3625` -> `"1h 0m"`, `45` -> `"45s"`. Coarsest-unit-first, two components
/// max so the stat stays glanceable.
fn fmt_uptime(secs: u64) -> String {
    let d = secs / 86_400;
    let h = (secs % 86_400) / 3_600;
    let m = (secs % 3_600) / 60;
    let s = secs % 60;
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

/// True when the currently-focused element is a text-entry control, so the
/// `r` shortcut doesn't hijack typing into a future filter/token field.
fn is_text_input_focused() -> bool {
    web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.active_element())
        .map(|el| {
            let tag = el.tag_name();
            tag.eq_ignore_ascii_case("input") || tag.eq_ignore_ascii_case("textarea")
        })
        .unwrap_or(false)
}

#[component]
pub fn Settings() -> impl IntoView {
    let auth = use_context::<AuthToken>().expect("AuthToken context provided by AppRoot");
    let nav = use_context::<Nav>().expect("Nav context provided by AppRoot");

    let info: RwSignal<Option<Result<Value, String>>> = RwSignal::new(None);
    let doctor: RwSignal<Option<Result<DoctorSummary, String>>> = RwSignal::new(None);
    let doctor_busy = RwSignal::new(false);

    let load_info = move || {
        let token = match auth.0.get_untracked() {
            Some(t) => t,
            None => {
                info.set(Some(Err("set a bearer token to load daemon info".into())));
                return;
            }
        };
        info.set(None);
        spawn_local(async move {
            info.set(Some(crate::api_client::fetch_system_info(&token).await));
        });
    };

    let run_doctor = move || {
        let token = match auth.0.get_untracked() {
            Some(t) => t,
            None => {
                doctor.set(Some(Err("set a bearer token to run diagnostics".into())));
                return;
            }
        };
        doctor_busy.set(true);
        spawn_local(async move {
            let mapped = match crate::api_client::run_doctor(&token).await {
                Ok(v) => DoctorSummary::from_value(&v)
                    .ok_or_else(|| "malformed doctor response".to_string()),
                Err(e) => Err(e),
            };
            doctor.set(Some(mapped));
            doctor_busy.set(false);
        });
    };

    // Fires once on mount, then again on every token change — so an operator
    // who lands on Settings before setting a token sees it retry automatically
    // rather than staring at a stale "set a bearer token" message.
    Effect::new(move |_| {
        let _ = auth.0.get();
        load_info();
        run_doctor();
    });

    // `r` re-runs diagnostics while this tab is mounted (it's only ever
    // mounted when `Tab::Settings` is active — see app.rs) and no text input
    // is focused. `window_event_listener` + `on_cleanup` is leptos' own
    // pattern for this (see its doc example) — it handles the `Send + Sync`
    // wrapping `on_cleanup` requires internally, so the listener is properly
    // removed on unmount without us reaching for raw `wasm_bindgen::Closure`.
    let keydown_handle = window_event_listener(ev::keydown, move |kev: web_sys::KeyboardEvent| {
        if kev.key() == "r" && !is_text_input_focused() {
            run_doctor();
        }
    });
    on_cleanup(move || keydown_handle.remove());

    let prompt_token = move |_| {
        let window = match web_sys::window() {
            Some(w) => w,
            None => return,
        };
        let current = auth.0.get_untracked().unwrap_or_default();
        let prompt = window
            .prompt_with_message_and_default("Enter linpodx remote token:", &current)
            .ok()
            .flatten();
        if let Some(s) = prompt {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                gloo_storage::LocalStorage::delete(TOKEN_KEY);
                auth.0.set(None);
            } else {
                let _ = gloo_storage::LocalStorage::set(TOKEN_KEY, trimmed);
                auth.0.set(Some(trimmed.to_string()));
            }
        }
    };
    let clear_token = move |_| {
        gloo_storage::LocalStorage::delete(TOKEN_KEY);
        auth.0.set(None);
    };

    // ---- daemon info card -----------------------------------------------
    let info_view = move || {
        match info.get() {
        None => view! {
            <div class="detail-grid">
                {(0..6)
                    .map(|_| view! {
                        <span class="detail-grid__key"><span class="skeleton-line" style="width:64px"></span></span>
                        <span class="detail-grid__val"><span class="skeleton-line" style="width:160px"></span></span>
                    })
                    .collect_view()}
            </div>
        }
        .into_any(),
        Some(Err(e)) => view! {
            <div>
                <div class="error-state"><Icon name="daemon"/><span>{e}</span></div>
                <button type="button" class="btn btn--sm btn--secondary" on:click=move |_| load_info()>
                    "Retry"
                </button>
            </div>
        }
        .into_any(),
        Some(Ok(v)) => {
            let get_str = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
            let ipc_version = v.get("ipc_version").and_then(|x| x.as_u64());
            let uptime = v.get("uptime_secs").and_then(|x| x.as_u64());
            let dash = || "—".to_string();
            view! {
                <div class="detail-grid">
                    <span class="detail-grid__key">"Version"</span>
                    <span class="detail-grid__val mono">{get_str("linpodx_version").unwrap_or_else(dash)}</span>
                    <span class="detail-grid__key">"IPC version"</span>
                    <span class="detail-grid__val mono">{ipc_version.map(|n| n.to_string()).unwrap_or_else(dash)}</span>
                    <span class="detail-grid__key">"Podman"</span>
                    <span class="detail-grid__val mono">{get_str("podman_version").unwrap_or_else(dash)}</span>
                    <span class="detail-grid__key">"Socket"</span>
                    <span class="detail-grid__val mono">{get_str("socket_path").unwrap_or_else(dash)}</span>
                    <span class="detail-grid__key">"Web listener"</span>
                    <span class="detail-grid__val mono">{get_str("web_listener_url").unwrap_or_else(dash)}</span>
                    <span class="detail-grid__key">"Uptime"</span>
                    <span class="detail-grid__val mono">{uptime.map(fmt_uptime).unwrap_or_else(dash)}</span>
                </div>
            }
            .into_any()
        }
    }
    };

    // ---- diagnostics card -------------------------------------------------
    let doctor_view = move || {
        match doctor.get() {
        None => view! {
            <div class="doctor-list">
                {(0..5)
                    .map(|_| view! {
                        <div class="doctor-row warn">
                            <span class="doctor-row__icon">
                                <span class="skeleton-line" style="width:14px;height:14px;border-radius:999px"></span>
                            </span>
                            <div>
                                <span class="skeleton-line" style="width:200px;display:block;margin-bottom:4px"></span>
                                <span class="skeleton-line" style="width:280px;display:block"></span>
                            </div>
                        </div>
                    })
                    .collect_view()}
            </div>
        }
        .into_any(),
        Some(Err(e)) => view! {
            <div>
                <div class="error-state"><Icon name="settings"/><span>{e}</span></div>
                <button type="button" class="btn btn--sm btn--secondary" on:click=move |_| run_doctor()>
                    "Retry"
                </button>
            </div>
        }
        .into_any(),
        Some(Ok(summary)) if summary.checks.is_empty() => view! {
            <div class="empty-state empty-state--spot">
                <span class="empty-state__spot"><EmptySpot motif="generic"/></span>
                <span class="empty-state__title">"No checks reported"</span>
                <span class="empty-state__hint">"Run "<span class="mono">"linpodx doctor"</span>" from the CLI for a full report."</span>
            </div>
        }
        .into_any(),
        Some(Ok(summary)) => {
            let rows = summary
                .checks
                .iter()
                .map(|c| {
                    let cls = c.row_class();
                    let label = c.label.clone();
                    let detail = c.detail.clone();
                    let fix = c.fix_hint.clone();
                    view! {
                        <div class=cls>
                            // Deliberately an unmatched icon name — icons.rs's
                            // fallback renders a plain filled dot, which then
                            // inherits the row's pass/warn/fail colour via
                            // `.doctor-row__icon` (see style.css).
                            <span class="doctor-row__icon"><Icon name="doctor-outcome"/></span>
                            <div>
                                <div>{label}</div>
                                {detail.map(|d| view! { <div class="doctor-row__detail">{d}</div> })}
                                {fix.map(|f| {
                                    if looks_linkable(&f) {
                                        let href = f.clone();
                                        view! {
                                            <div class="doctor-row__detail">
                                                <a href=href target="_blank" rel="noopener noreferrer">{f}</a>
                                            </div>
                                        }
                                        .into_any()
                                    } else {
                                        view! { <div class="doctor-row__detail">{f}</div> }.into_any()
                                    }
                                })}
                            </div>
                        </div>
                    }
                })
                .collect_view();
            view! {
                <div>
                    <div class="page-actions" style="margin-bottom:var(--sp-3)">
                        <span class="badge badge--success">{format!("{} pass", summary.pass)}</span>
                        <span class="badge badge--warn">{format!("{} warn", summary.warn)}</span>
                        <span class="badge badge--error">{format!("{} fail", summary.fail)}</span>
                    </div>
                    <div class="doctor-list">{rows}</div>
                </div>
            }
            .into_any()
        }
    }
    };

    let doctor_button_label = move || {
        if doctor_busy.get() {
            "Running…"
        } else if doctor.get().is_some() {
            "Re-run checks"
        } else {
            "Run checks"
        }
    };

    view! {
        <div class="dashboard-panel section-scope--system">
            <header class="page-head">
                <div class="page-head__lead">
                    <div class="page-head__disc"><Icon name="settings"/></div>
                    <div class="page-head__titles">
                        <div class="page-head__eyebrow">"System"</div>
                        <div class="page-head__title">"Settings"</div>
                        <div class="page-head__sub">"Daemon info and doctor diagnostics."</div>
                    </div>
                </div>
            </header>

            <div class="surface-card">
                <div class="section-title">"Daemon"</div>
                {info_view}
                <div class="page-actions" style="margin-top:var(--sp-3)">
                    <button type="button" class="btn btn--sm btn--secondary" on:click=prompt_token>
                        "Set token"
                    </button>
                    <button type="button" class="btn btn--sm btn--ghost" on:click=clear_token>
                        "Clear token"
                    </button>
                    <span class="rest-hint">"theme toggle lives in the topbar"</span>
                </div>
            </div>

            <div class="surface-card">
                <div class="card-header">
                    <span class="card-header__title">"Diagnostics"</span>
                    <button
                        type="button"
                        class="btn btn--sm btn--primary"
                        prop:disabled=move || doctor_busy.get()
                        on:click=move |_| run_doctor()
                    >
                        {doctor_button_label}
                    </button>
                </div>
                {doctor_view}
            </div>

            <div class="surface-card">
                <div class="section-title">"Links"</div>
                <div class="page-actions">
                    <button type="button" class="btn btn--sm btn--secondary" on:click=move |_| nav.0.set(Tab::Audit)>
                        "View audit log"
                    </button>
                    <button type="button" class="btn btn--sm btn--secondary" on:click=move |_| nav.0.set(Tab::Sessions)>
                        "View events / sessions"
                    </button>
                </div>
            </div>
        </div>
    }
}

// NB: no `#[cfg(test)]` module here — like every other file under
// `components/`, this module only compiles on `wasm32-unknown-unknown` (see
// `lib.rs`'s `#[cfg(target_arch = "wasm32")] mod components;`), so host-target
// `cargo test -p linpodx-webui` never even sees this file. The pure parsing /
// formatting helpers above (`DoctorCheck`, `DoctorSummary`, `looks_linkable`,
// `fmt_uptime`) are intentionally small and inspectable inline; anything that
// warrants host-side unit coverage belongs in `helpers.rs` instead.
