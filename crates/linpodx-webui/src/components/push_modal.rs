//! Push modal — `image_push` JSON-RPC. Phase 11 had the form inlined inside
//! `images.rs`; Phase 12 Stream B extracts it into a reusable component so the
//! Images view can mount it from the per-row [Push] action button.
//!
//! Visibility is controlled by a shared `RwSignal<Option<String>>`. `Some`
//! pre-fills the reference field with the row's image reference; `None`
//! hides the modal. Registry override + base64 auth blob remain optional.

use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

use crate::ws::send_rpc;

#[component]
pub fn PushModal(open: RwSignal<Option<String>>) -> impl IntoView {
    let reference = RwSignal::new(String::new());
    let registry = RwSignal::new(String::new());
    let auth = RwSignal::new(String::new());
    let status: RwSignal<Option<String>> = RwSignal::new(None);
    let busy = RwSignal::new(false);

    Effect::new(move |_| {
        if let Some(seed) = open.get() {
            reference.set(seed);
            registry.set(String::new());
            auth.set(String::new());
            status.set(None);
            busy.set(false);
        }
    });

    let close = move |_| open.set(None);

    let submit = move |_| {
        let r = reference.get_untracked().trim().to_string();
        if r.is_empty() {
            status.set(Some("reference is required".into()));
            return;
        }
        let mut params = json!({ "reference": r });
        let reg = registry.get_untracked().trim().to_string();
        if !reg.is_empty() {
            params["registry"] = Value::String(reg);
        }
        let a = auth.get_untracked().trim().to_string();
        if !a.is_empty() {
            params["auth"] = Value::String(a);
        }
        busy.set(true);
        status.set(Some("pushing…".into()));
        spawn_local(async move {
            match send_rpc("image_push", params).await {
                Ok(v) => status.set(Some(format!("pushed: {v}"))),
                Err(e) => status.set(Some(format!("error: {e}"))),
            }
            busy.set(false);
        });
    };

    view! {
        <Show when=move || open.get().is_some() fallback=|| view! { <></> }>
            <div class="modal-backdrop">
                <div class="modal-card">
                    <h3>"Push image"</h3>
                    <div class="modal-form">
                        <label>
                            "Reference"
                            <input
                                type="text"
                                placeholder="docker.io/me/app:1.0"
                                prop:value=move || reference.get()
                                on:input=move |ev| reference.set(event_target_value(&ev))
                            />
                        </label>
                        <label>
                            "Registry override (optional)"
                            <input
                                type="text"
                                placeholder="registry.example.com"
                                prop:value=move || registry.get()
                                on:input=move |ev| registry.set(event_target_value(&ev))
                            />
                        </label>
                        <label>
                            "base64(user:password) auth (optional)"
                            <input
                                type="password"
                                prop:value=move || auth.get()
                                on:input=move |ev| auth.set(event_target_value(&ev))
                            />
                        </label>
                        {move || status.get().map(|msg| view! { <p class="status">{msg}</p> })}
                    </div>
                    <div class="modal-actions">
                        <button
                            type="button"
                            class="primary"
                            prop:disabled=move || busy.get()
                            on:click=submit
                        >
                            {move || if busy.get() { "Pushing…" } else { "Push" }}
                        </button>
                        <button type="button" on:click=close>"Close"</button>
                    </div>
                </div>
            </div>
        </Show>
    }
}
