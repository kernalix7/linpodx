//! Exec modal — issues a `container_exec` JSON-RPC call and renders the captured
//! stdout/stderr/exit_code in a dark monospace result panel.
//!
//! Phase 12 Stream B. The modal is mounted from the Containers panel; visibility
//! is controlled by a shared `RwSignal<Option<String>>` whose `Some` payload is
//! the target container id. Closing the modal sets the signal back to `None`.
//!
//! The exec is non-interactive: we send a one-shot command line, await the
//! response, and display the result. Interactive PTY exec is wired separately
//! by exec-pty-team via `/pty/<bridge_id>` (see Phase 12 Stream A).
//!
//! Pure-Rust parsing/formatting (argv split, response rendering) lives in
//! `crate::helpers` so it stays unit-testable on the host target.

use leptos::prelude::*;
use serde_json::json;
use wasm_bindgen_futures::spawn_local;

use crate::helpers::{format_exec_result, parse_command};
use crate::ws::send_rpc;

#[component]
pub fn ExecModal(open: RwSignal<Option<String>>) -> impl IntoView {
    let command = RwSignal::new(String::new());
    let result: RwSignal<Option<Result<String, String>>> = RwSignal::new(None);
    let busy = RwSignal::new(false);

    let target = Signal::derive(move || open.get());

    Effect::new(move |_| {
        // Reset the form whenever a new container is selected.
        if open.get().is_some() {
            command.set(String::new());
            result.set(None);
            busy.set(false);
        }
    });

    let close = move |_| open.set(None);

    let submit = move |_| {
        let id = match target.get_untracked() {
            Some(id) => id,
            None => return,
        };
        let line = command.get_untracked();
        let argv = parse_command(&line);
        if argv.is_empty() {
            result.set(Some(Err("command is required".into())));
            return;
        }
        busy.set(true);
        result.set(None);
        let params = json!({
            "container_id": id,
            "command": argv,
            "interactive": false,
            "tty": false,
            "env": Vec::<(String, String)>::new(),
        });
        spawn_local(async move {
            match send_rpc("container_exec", params).await {
                Ok(v) => result.set(Some(Ok(format_exec_result(&v)))),
                Err(e) => result.set(Some(Err(e))),
            }
            busy.set(false);
        });
    };

    let title = move || match target.get() {
        Some(id) => format!("Exec — {id}"),
        None => String::from("Exec"),
    };

    let result_view = move || {
        result.get().map(|r| match r {
            Ok(text) => view! { <pre class="modal-result">{text}</pre> }.into_any(),
            Err(msg) => view! { <p class="modal-error">{msg}</p> }.into_any(),
        })
    };

    view! {
        <Show when=move || open.get().is_some() fallback=|| view! { <></> }>
            <div class="modal-backdrop">
                <div class="modal-card">
                    <h3>{title}</h3>
                    <div class="modal-form">
                        <label>
                            "Command (argv, space-separated)"
                            <textarea
                                rows="3"
                                placeholder="ls -la /etc"
                                prop:value=move || command.get()
                                on:input=move |ev| command.set(event_target_value(&ev))
                            ></textarea>
                        </label>
                        {result_view}
                    </div>
                    <div class="modal-actions">
                        <button
                            type="button"
                            class="primary"
                            prop:disabled=move || busy.get()
                            on:click=submit
                        >
                            {move || if busy.get() { "Running…" } else { "Run" }}
                        </button>
                        <button type="button" on:click=close>"Close"</button>
                    </div>
                </div>
            </div>
        </Show>
    }
}
