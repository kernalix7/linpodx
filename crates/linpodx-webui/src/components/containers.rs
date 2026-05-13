use leptos::prelude::*;

use super::exec_modal::ExecModal;
use super::exec_pty_modal::ExecPtyModal;
use super::list_table::{row_actions, ListTable, PanelSpec};
use super::logs_modal::LogsModal;

#[component]
pub fn ContainerList() -> impl IntoView {
    let spec = PanelSpec {
        api_path: "containers",
        topic: "container",
        columns: &["id", "name", "image", "status", "created_at"],
        empty_msg: "no containers",
    };
    let exec_open: RwSignal<Option<String>> = RwSignal::new(None);
    let exec_pty_open: RwSignal<Option<String>> = RwSignal::new(None);
    let logs_open: RwSignal<Option<String>> = RwSignal::new(None);

    let actions = row_actions(move |row| {
        let id = row
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let id_for_exec = id.clone();
        let id_for_pty = id.clone();
        let id_for_logs = id.clone();
        let row_disabled = id.is_empty();
        view! {
            <button
                type="button"
                class="row-action"
                prop:disabled=row_disabled
                on:click=move |_| {
                    if !id_for_exec.is_empty() {
                        exec_open.set(Some(id_for_exec.clone()));
                    }
                }
            >
                "Exec"
            </button>
            <button
                type="button"
                class="row-action"
                prop:disabled=row_disabled
                on:click=move |_| {
                    if !id_for_pty.is_empty() {
                        exec_pty_open.set(Some(id_for_pty.clone()));
                    }
                }
            >
                "Exec PTY"
            </button>
            <button
                type="button"
                class="row-action"
                prop:disabled=row_disabled
                on:click=move |_| {
                    if !id_for_logs.is_empty() {
                        logs_open.set(Some(id_for_logs.clone()));
                    }
                }
            >
                "Logs"
            </button>
        }
        .into_any()
    });

    view! {
        <div class="containers-panel">
            <ListTable spec=spec actions_for_row=actions/>
            <ExecModal open=exec_open/>
            <ExecPtyModal open=exec_pty_open/>
            <LogsModal open=logs_open/>
        </div>
    }
}
