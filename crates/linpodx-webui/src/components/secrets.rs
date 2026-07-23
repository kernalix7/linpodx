//! Phase 26 — secrets management panel (issue #9).
//!
//! Table view over `podman secret ls` (name / id-short / created / driver),
//! a create modal (name + value textarea — the value field is cleared the
//! instant the modal closes, win or lose, so it never lingers in a leptos
//! signal longer than the request needs it), and remove-with-confirm.
//!
//! `SecretSummary` never carries a value (see `linpodx-common::ipc::responses`)
//! so there is nothing here to redact on the read path; the only sensitive
//! field in this whole panel is the create-modal's plaintext input, which is
//! never logged, never sent anywhere but the `secret_create` RPC body, and is
//! zeroed out of the signal on every close path (success, error, cancel).
//!
//! Row keyboard nav (j/k/arrows + Enter) and right-click context menu match
//! the pattern the other resource panels use (`context_menu.rs`); Enter opens
//! the same remove-confirm modal as the row button rather than deleting
//! outright, since removal here has no undo.

use leptos::ev;
use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

use super::context_menu;

use super::icons::Icon;
use super::illustrations::EmptySpot;
use crate::app::DensityMode;
use crate::ws::send_rpc;

#[derive(Clone, Debug)]
struct SecretRow {
    id: String,
    name: String,
    created: String,
    driver: String,
}

impl SecretRow {
    fn from_value(v: &Value) -> Option<Self> {
        let obj = v.as_object()?;
        Some(Self {
            id: obj.get("id")?.as_str()?.to_string(),
            name: obj.get("name")?.as_str()?.to_string(),
            created: obj
                .get("created")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            driver: obj
                .get("driver")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
        })
    }

    /// First 12 chars of the id, matching the `podman secret ls` default
    /// column width — full id stays available via the `title` tooltip.
    fn id_short(&self) -> String {
        self.id.chars().take(12).collect()
    }
}

#[component]
pub fn SecretsView() -> impl IntoView {
    let density = use_context::<DensityMode>().expect("DensityMode context provided by AppRoot");
    let rows: RwSignal<Vec<SecretRow>> = RwSignal::new(Vec::new());
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let loading = RwSignal::new(true);

    // Create-modal state.
    let create_open = RwSignal::new(false);
    let create_name = RwSignal::new(String::new());
    let create_value = RwSignal::new(String::new());
    let create_busy = RwSignal::new(false);
    let create_error: RwSignal<Option<String>> = RwSignal::new(None);

    // Remove-confirm state.
    let pending_remove: RwSignal<Option<String>> = RwSignal::new(None);
    let remove_busy = RwSignal::new(false);
    let remove_error: RwSignal<Option<String>> = RwSignal::new(None);
    let focused_row: RwSignal<Option<String>> = RwSignal::new(None);
    let context_menu = context_menu::ContextMenuState::new();

    let reload = move || {
        loading.set(true);
        spawn_local(async move {
            match send_rpc("secret_list", json!({})).await {
                Ok(v) => {
                    let arr = v
                        .get("secrets")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default();
                    let parsed: Vec<SecretRow> =
                        arr.iter().filter_map(SecretRow::from_value).collect();
                    rows.set(parsed);
                    error.set(None);
                }
                Err(e) => error.set(Some(e)),
            }
            loading.set(false);
        });
    };

    Effect::new(move |prev: Option<()>| {
        if prev.is_some() {
            return;
        }
        reload();
    });

    let visible_names = move || {
        rows.get()
            .iter()
            .map(|s| s.name.clone())
            .collect::<Vec<_>>()
    };

    // Clears the plaintext value from the signal on every exit path —
    // success, RPC error, and plain cancel all funnel through this.
    let close_create = move || {
        create_open.set(false);
        create_name.set(String::new());
        create_value.set(String::new());
        create_error.set(None);
    };

    let open_create = move |_| {
        create_open.set(true);
        create_error.set(None);
    };

    let submit_create = move |_| {
        let name = create_name.get_untracked();
        let value = create_value.get_untracked();
        if name.trim().is_empty() {
            create_error.set(Some("name is required".into()));
            return;
        }
        if value.is_empty() {
            create_error.set(Some("value is required".into()));
            return;
        }
        create_busy.set(true);
        create_error.set(None);
        spawn_local(async move {
            let body = json!({ "name": name, "value": value });
            let result = send_rpc("secret_create", body).await;
            // Zero the plaintext value out of the signal immediately after
            // the request resolves, regardless of outcome.
            create_value.set(String::new());
            match result {
                Ok(_) => {
                    create_busy.set(false);
                    close_create();
                    reload();
                }
                Err(e) => {
                    create_busy.set(false);
                    create_error.set(Some(e));
                }
            }
        });
    };

    let open_remove = move |name: String| {
        pending_remove.set(Some(name));
        remove_error.set(None);
    };

    let key_handle = window_event_listener(ev::keydown, move |kev: web_sys::KeyboardEvent| {
        let blocked = pending_remove.get_untracked().is_some()
            || create_open.get_untracked()
            || context_menu.0.get_untracked().is_some();
        context_menu::handle_table_key(&kev, visible_names(), focused_row, blocked, open_remove);
    });
    on_cleanup(move || key_handle.remove());

    let cancel_remove = move |_| {
        pending_remove.set(None);
        remove_error.set(None);
    };

    let confirm_remove = move |_| {
        let name = match pending_remove.get_untracked() {
            Some(n) => n,
            None => return,
        };
        remove_busy.set(true);
        remove_error.set(None);
        spawn_local(async move {
            match send_rpc("secret_remove", json!({ "name": name })).await {
                Ok(_) => {
                    remove_busy.set(false);
                    pending_remove.set(None);
                    reload();
                }
                Err(e) => {
                    remove_busy.set(false);
                    remove_error.set(Some(e));
                }
            }
        });
    };

    let create_modal = move || {
        create_open.get().then(|| {
            view! {
                <div class="modal-backdrop">
                    <div class="modal-card">
                        <h3>"Create secret"</h3>
                        <p class="rest-hint">"REST: POST /api/v1/secrets/create"</p>
                        <div class="modal-form">
                            <label>
                                "Name"
                                <input
                                    class="input"
                                    type="text"
                                    placeholder="my-secret"
                                    prop:value=move || create_name.get()
                                    on:input=move |ev| create_name.set(event_target_value(&ev))
                                />
                            </label>
                            <label>
                                "Value"
                                <textarea
                                    class="input"
                                    rows="4"
                                    placeholder="secret value…"
                                    prop:value=move || create_value.get()
                                    on:input=move |ev| create_value.set(event_target_value(&ev))
                                ></textarea>
                            </label>
                            {move || create_error.get().map(|e| view! {
                                <p class="modal-error">{e}</p>
                            })}
                        </div>
                        <div class="modal-actions">
                            <button
                                type="button"
                                class="btn btn--primary"
                                prop:disabled=move || create_busy.get()
                                on:click=submit_create
                            >
                                {move || if create_busy.get() { "Creating…" } else { "Create" }}
                            </button>
                            <button
                                type="button"
                                class="btn"
                                prop:disabled=move || create_busy.get()
                                on:click=move |_| close_create()
                            >
                                "Cancel"
                            </button>
                        </div>
                    </div>
                </div>
            }
        })
    };

    let remove_modal = move || {
        pending_remove.get().map(|name| {
            let name_for_view = name.clone();
            view! {
                <div class="modal-backdrop">
                    <div class="modal-card">
                        <h3>"Remove secret"</h3>
                        <p class="modal-confirm">{format!("Remove secret \"{}\"? This cannot be undone.", name_for_view)}</p>
                        {move || remove_error.get().map(|e| view! {
                            <p class="modal-error">{e}</p>
                        })}
                        <div class="modal-actions">
                            <button
                                type="button"
                                class="btn btn--danger"
                                prop:disabled=move || remove_busy.get()
                                on:click=confirm_remove
                            >
                                {move || if remove_busy.get() { "Removing…" } else { "Remove" }}
                            </button>
                            <button
                                type="button"
                                class="btn"
                                prop:disabled=move || remove_busy.get()
                                on:click=cancel_remove
                            >
                                "Cancel"
                            </button>
                        </div>
                    </div>
                </div>
            }
        })
    };

    let body_view = move || {
        if loading.get() {
            return view! {
                <div class="loading-inline"><span class="spinner"></span>"Loading secrets…"</div>
            }
            .into_any();
        }
        let items = rows.get();
        if items.is_empty() {
            return view! {
                <div class="empty-state empty-state--spot">
                    <span class="empty-state__spot"><EmptySpot motif="secrets"/></span>
                    <span class="empty-state__title">"No secrets"</span>
                    <span class="empty-state__hint">
                        "linpodx secrets are podman secrets — create one with the button above, or run "
                        <code>"podman secret create <name> -"</code>
                        " on the host."
                    </span>
                </div>
            }
            .into_any();
        }
        let body_rows = items
            .into_iter()
            .map(|s| {
                let name_for_remove = s.name.clone();
                let id_short = s.id_short();
                // Secondary (muted) line under the secret name: the storage
                // driver — hidden by CSS in compact mode.
                let primary_sub = if s.driver.is_empty() {
                    "—".to_string()
                } else {
                    s.driver.clone()
                };
                let row_key = s.name.clone();
                let name_for_click = s.name.clone();
                let name_for_context = s.name.clone();
                view! {
                    <tr
                        class=move || context_menu::focused_row_class(focused_row, &row_key)
                        on:click=move |_| focused_row.set(Some(name_for_click.clone()))
                        on:contextmenu=move |ev| {
                            focused_row.set(Some(name_for_context.clone()));
                            let name_remove = name_for_context.clone();
                            context_menu.open(
                                &ev,
                                vec![context_menu::ContextMenuEntry::item(
                                    "Remove",
                                    None,
                                    true,
                                    false,
                                    Callback::new(move |_| open_remove(name_remove.clone())),
                                )],
                            );
                        }
                    >
                        <td>
                            <span class="cell-primary" title=s.name.clone()>
                                <span class="cell-primary__main">{s.name.clone()}</span>
                                <span class="cell-primary__sub">{primary_sub}</span>
                            </span>
                        </td>
                        <td><span class="cell mono" title=s.id.clone()>{id_short}</span></td>
                        <td><span class="cell">{s.created}</span></td>
                        <td><span class="cell">{s.driver}</span></td>
                        <td>
                            <button
                                type="button"
                                class="btn btn--danger btn--sm"
                                on:click=move |_| open_remove(name_for_remove.clone())
                            >
                                "Remove"
                            </button>
                        </td>
                    </tr>
                }
            })
            .collect_view();
        view! {
            <div class="data-table-wrap">
                <table class=move || density.table_class()>
                    <thead>
                        <tr>
                            <th>"Name"</th>
                            <th>"ID"</th>
                            <th>"Created"</th>
                            <th>"Driver"</th>
                            <th class="cell-actions">"Actions"</th>
                        </tr>
                    </thead>
                    <tbody>{body_rows}</tbody>
                </table>
            </div>
        }
        .into_any()
    };

    view! {
        <div class="secrets-panel section-scope--resources">
            <header class="page-head">
                <div class="page-head__lead">
                    <div class="page-head__disc"><Icon name="secret"/></div>
                    <div class="page-head__titles">
                        <div class="page-head__eyebrow">"Resources"</div>
                        <div class="page-head__title">"Secrets"</div>
                        <div class="page-head__sub">"podman secret store — values are never displayed after creation"</div>
                    </div>
                </div>
                <div class="page-head__actions">
                    <button type="button" class="btn btn--primary btn--sm" on:click=open_create>
                        "Create secret"
                    </button>
                </div>
            </header>
            {move || error.get().map(|e| view! {
                <div class="error-state"><Icon name="secret"/><span>{e}</span></div>
            })}
            {body_view}
            {create_modal}
            {remove_modal}
            <context_menu::ContextMenu state=context_menu/>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_secret_row() {
        let v = json!({
            "id": "63712b6f299dc1ba2dc59b591abcdef",
            "name": "demo-secret",
            "created": "5 seconds ago",
            "driver": "file",
        });
        let row = SecretRow::from_value(&v).unwrap();
        assert_eq!(row.name, "demo-secret");
        assert_eq!(row.id_short(), "63712b6f299d");
        assert_eq!(row.driver, "file");
    }

    #[test]
    fn rejects_row_missing_required_fields() {
        let v = json!({ "id": "abc" });
        assert!(SecretRow::from_value(&v).is_none());
    }
}
