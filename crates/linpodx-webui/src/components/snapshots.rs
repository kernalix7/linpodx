use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

use super::icons::Icon;
use super::list_table::{row_actions, ListTable, PanelSpec};
use crate::api_client::paths;
use crate::helpers::snapshot_kdf_badge;
use crate::ws::send_rpc;

/// Action the operator picked from a snapshot row's button cluster. We hold one
/// `RwSignal<Option<PendingAction>>` for the whole panel and render a single
/// confirm modal that branches on the variant. Phase 17 added the
/// `RotateKey` / `ReEncryptAll` variants.
#[derive(Clone, Debug)]
enum PendingAction {
    Branch { id: i64 },
    Rollback { id: i64 },
    Remove { id: i64 },
    RotateKey { id: i64 },
    ReEncryptAll,
}

impl PendingAction {
    fn rpc_method(&self) -> &'static str {
        match self {
            Self::Branch { .. } => "snapshot_branch",
            Self::Rollback { .. } => "snapshot_rollback",
            Self::Remove { .. } => "snapshot_remove",
            Self::RotateKey { .. } => "snapshot_key_rotate",
            Self::ReEncryptAll => "snapshot_re_encrypt_all",
        }
    }

    fn rpc_params(&self, passphrase: &str) -> Value {
        match self {
            Self::Branch { id } => json!({ "parent_id": id }),
            Self::Rollback { id } => json!({ "id": id }),
            Self::Remove { id } => json!({ "id": id, "force": false }),
            Self::RotateKey { id } => json!({
                "snapshot_id": id,
                "new_key": {
                    "kind": "passphrase",
                    "passphrase": passphrase,
                }
            }),
            Self::ReEncryptAll => json!({
                "new_key": {
                    "kind": "passphrase",
                    "passphrase": passphrase,
                }
            }),
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Branch { .. } => "Branch snapshot",
            Self::Rollback { .. } => "Rollback to snapshot",
            Self::Remove { .. } => "Remove snapshot",
            Self::RotateKey { .. } => "Rotate snapshot key",
            Self::ReEncryptAll => "Re-encrypt every snapshot",
        }
    }

    fn id_label(&self) -> String {
        match self {
            Self::Branch { id } | Self::Rollback { id } | Self::Remove { id } => format!("#{id}"),
            Self::RotateKey { id } => format!("#{id}"),
            Self::ReEncryptAll => "(all encrypted snapshots)".into(),
        }
    }

    fn needs_passphrase(&self) -> bool {
        matches!(self, Self::RotateKey { .. } | Self::ReEncryptAll)
    }
}

#[component]
pub fn SnapshotTree() -> impl IntoView {
    let spec = PanelSpec {
        api_path: "snapshots",
        topic: "snapshot",
        columns: &[
            "id",
            "container_id",
            "label",
            "image_ref",
            "kdf",
            "created_at",
        ],
        empty_msg: "no snapshots",
    };
    let pending: RwSignal<Option<PendingAction>> = RwSignal::new(None);
    let passphrase = RwSignal::new(String::new());
    let status: RwSignal<Option<String>> = RwSignal::new(None);
    let busy = RwSignal::new(false);

    let actions = row_actions(move |row| {
        let id = row.get("id").and_then(|v| v.as_i64());
        let id = match id {
            Some(i) => i,
            None => {
                return view! {
                    <span class="row-action-empty">"—"</span>
                }
                .into_any();
            }
        };
        let kdf = snapshot_kdf_badge(
            row.get("encrypted")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            row.get("algorithm").and_then(|v| v.as_str()),
            row.get("kdf")
                .or_else(|| row.get("key_source"))
                .and_then(|v| v.as_str()),
        );
        let open_branch = move |_| pending.set(Some(PendingAction::Branch { id }));
        let open_rollback = move |_| pending.set(Some(PendingAction::Rollback { id }));
        let open_remove = move |_| pending.set(Some(PendingAction::Remove { id }));
        let open_rotate = move |_| {
            passphrase.set(String::new());
            pending.set(Some(PendingAction::RotateKey { id }));
        };
        view! {
            <span class="kdf-badge">{kdf}</span>
            <button type="button" class="row-action" on:click=open_branch>"Branch"</button>
            <button type="button" class="row-action" on:click=open_rollback>"Rollback"</button>
            <button type="button" class="row-action" on:click=open_rotate>"Rotate Key"</button>
            <button type="button" class="row-action danger" on:click=open_remove>"Remove"</button>
        }
        .into_any()
    });

    let open_re_encrypt = move |_| {
        passphrase.set(String::new());
        pending.set(Some(PendingAction::ReEncryptAll));
    };

    let cancel = move |_| {
        pending.set(None);
        status.set(None);
    };
    let confirm = move |_| {
        let action = match pending.get_untracked() {
            Some(a) => a,
            None => return,
        };
        let method = action.rpc_method();
        let params = action.rpc_params(&passphrase.get_untracked());
        busy.set(true);
        status.set(Some("working…".into()));
        spawn_local(async move {
            match send_rpc(method, params).await {
                Ok(_) => {
                    status.set(Some("done".into()));
                    pending.set(None);
                    passphrase.set(String::new());
                }
                Err(e) => status.set(Some(format!("error: {e}"))),
            }
            busy.set(false);
        });
    };

    let modal_view = move || {
        pending.get().map(|action| {
            let label = action.label();
            let id_label = action.id_label();
            let st = status.get();
            let needs_pass = action.needs_passphrase();
            let rest_path = match action {
                PendingAction::RotateKey { id } => {
                    Some(format!("REST: POST /api/v1/snapshot/{id}/rotate-key"))
                }
                PendingAction::ReEncryptAll => {
                    Some(format!("REST: POST {}", paths::SANDBOX_AUTO_ENCRYPT))
                }
                _ => None,
            };
            view! {
                <div class="modal-backdrop">
                    <div class="modal-card">
                        <h3>{label}</h3>
                        <p class="modal-confirm">
                            {format!("Confirm {} on {}.", label.to_lowercase(), id_label)}
                        </p>
                        {rest_path.map(|p| view! { <p class="rest-hint">{p}</p> })}
                        {needs_pass.then(|| view! {
                            <div class="field-group">
                                <label class="label">"New passphrase"</label>
                                <input
                                    type="password"
                                    class="input modal-input"
                                    placeholder="new passphrase"
                                    prop:value=move || passphrase.get()
                                    on:input=move |ev| passphrase.set(event_target_value(&ev))
                                />
                            </div>
                        })}
                        {st.map(|m| {
                            if let Some(msg) = m.strip_prefix("error: ") {
                                view! { <p class="modal-error">{msg.to_string()}</p> }.into_any()
                            } else if busy.get() {
                                view! { <div class="loading-inline"><span class="spinner"></span>{m}</div> }.into_any()
                            } else {
                                view! { <p class="status">{m}</p> }.into_any()
                            }
                        })}
                        <div class="modal-actions">
                            <button
                                type="button"
                                class="btn btn--primary"
                                prop:disabled=move || busy.get()
                                on:click=confirm
                            >
                                {move || if busy.get() { "Working…" } else { "Confirm" }}
                            </button>
                            <button type="button" class="btn" on:click=cancel>"Cancel"</button>
                        </div>
                    </div>
                </div>
            }
        })
    };

    view! {
        <div class="snapshots-panel">
            <div class="page-header">
                <div class="page-header__titles">
                    <div class="page-title">"Snapshots"</div>
                    <div class="page-subtitle">"branch, rollback, and manage encryption keys"</div>
                </div>
                <div class="page-actions">
                    <button type="button" class="btn btn--primary" on:click=open_re_encrypt>
                        <Icon name="snapshot"/>
                        " Re-encrypt all"
                    </button>
                </div>
            </div>
            <ListTable spec=spec actions_for_row=actions/>
            {modal_view}
        </div>
    }
}
