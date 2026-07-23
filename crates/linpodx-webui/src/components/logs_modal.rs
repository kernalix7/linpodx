//! Logs modal — streams `container_logs_stream` notifications into an
//! xterm.js terminal pane.
//!
//! Phase 12 shipped a plain `<pre>` scrollback buffer; Phase 13 Stream B
//! replaces it with an xterm.js Terminal so ANSI colour escapes from
//! `podman logs` render natively. The streaming protocol is unchanged:
//!
//!   1. Caller sets `open` to `Some(container_id)`.
//!   2. Effect dispatches `container_logs_stream{follow}` over the WebSocket.
//!   3. We subscribe once to `EventTopic::Container` notifications and filter
//!      down to `kind == "log"` events whose `resource_id` matches the target.
//!   4. Each matched event is written to the xterm.js terminal via the
//!      [`crate::components::xterm::XTerm`] safe wrapper.
//!
//! Pure-Rust filter / append / extract logic stays in `crate::helpers` so it
//! is unit-testable on the host target (xterm.js is wasm-only).
//!
//! XSS posture: the log line text is fed through `XTerm::write_str`, which
//! writes through xterm.js's binary parser — the DOM is never touched with
//! `innerHTML` / `set_html`. Container ids surfaced in the `<h3>` title are
//! interpolated through leptos `view!` (escaped).

use std::cell::RefCell;
use std::rc::Rc;

use leptos::prelude::*;
use leptos::reactive::owner::{LocalStorage, StoredValue};
use serde_json::json;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::spawn_local;
use web_sys::Element;

use crate::components::xterm::XTerm;
use crate::helpers::{
    event_is_log_kind, event_matches_container, extract_log_line, LOGS_MAX_LINES,
};
use crate::ws::{send_rpc, subscribe};

fn download_text_file(filename: &str, text: &str) {
    let Some(win) = web_sys::window() else {
        return;
    };
    let Some(doc) = win.document() else {
        return;
    };
    let parts = js_sys::Array::new();
    parts.push(&JsValue::from_str(text));
    let Ok(blob) = web_sys::Blob::new_with_str_sequence(parts.as_ref()) else {
        return;
    };
    let Ok(url_ctor) = js_sys::Reflect::get(&win, &JsValue::from_str("URL")) else {
        return;
    };
    let Ok(create) = js_sys::Reflect::get(&url_ctor, &JsValue::from_str("createObjectURL")) else {
        return;
    };
    let Ok(create) = create.dyn_into::<js_sys::Function>() else {
        return;
    };
    let Ok(url) = create.call1(&url_ctor, &blob) else {
        return;
    };
    let Some(url) = url.as_string() else {
        return;
    };
    let Ok(anchor) = doc.create_element("a") else {
        revoke_object_url(&url_ctor, &url);
        return;
    };
    let _ = anchor.set_attribute("href", &url);
    let _ = anchor.set_attribute("download", filename);
    if let Some(body) = doc.body() {
        if body.append_child(&anchor).is_ok() {
            if let Ok(anchor) = anchor.dyn_into::<web_sys::HtmlElement>() {
                anchor.click();
                let _ = body.remove_child(&anchor);
            }
        }
    }
    revoke_object_url(&url_ctor, &url);
}

fn revoke_object_url(url_ctor: &JsValue, url: &str) {
    let Ok(revoke) = js_sys::Reflect::get(url_ctor, &JsValue::from_str("revokeObjectURL")) else {
        return;
    };
    if let Ok(revoke) = revoke.dyn_into::<js_sys::Function>() {
        let _ = revoke.call1(url_ctor, &JsValue::from_str(url));
    }
}

#[component]
pub fn LogsModal(open: RwSignal<Option<String>>) -> impl IntoView {
    let follow = RwSignal::new(true);
    let status: RwSignal<Option<String>> = RwSignal::new(None);
    let buffer = RwSignal::new(String::new());

    // Active container id — shared with the subscribe callback so switching
    // containers doesn't leak a second subscription. The `Rc<RefCell>` lives
    // only inside Effect callbacks (which leptos schedules on the local
    // thread), never inside `view!` closures.
    let active_id: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));

    // The xterm.js terminal handle. `XTerm` is not `Send + Sync`, so we hold
    // it in a `StoredValue<_, LocalStorage>` — leptos' arena for non-thread-
    // safe state. `StoredValue` is `Copy`, which lets us capture it inside
    // `view!` event handlers without any Rc dance.
    let term: StoredValue<Option<XTerm>, LocalStorage> = StoredValue::new_local(None);

    // Subscribe once for the lifetime of the component mount.
    let active_for_sub = active_id.clone();
    Effect::new(move |prev: Option<()>| {
        if prev.is_some() {
            return;
        }
        let active = active_for_sub.clone();
        subscribe("container", move |notif| {
            if !event_is_log_kind(&notif) {
                return;
            }
            let current = match active.borrow().clone() {
                Some(id) => id,
                None => return,
            };
            if !event_matches_container(&notif, &current) {
                return;
            }
            let details = notif.pointer("/params/details").cloned();
            let line = match details.as_ref().and_then(extract_log_line) {
                Some(line) => line,
                None => return,
            };
            buffer.update(|buf| {
                if !buf.is_empty() {
                    buf.push('\n');
                }
                buf.push_str(&line);
            });
            // xterm.js handles its own scrollback; the wrapper drops late
            // writes after dispose, so missing-modal reads are safe.
            term.with_value(|t| {
                if let Some(t) = t.as_ref() {
                    t.write_str(&line);
                    t.write_str("\r\n");
                }
            });
        });
    });

    let active_for_open = active_id.clone();
    Effect::new(move |_| {
        let id = open.get();
        match id {
            Some(id) => {
                status.set(None);
                buffer.set(String::new());
                *active_for_open.borrow_mut() = Some(id.clone());
                term.with_value(|t| {
                    if let Some(t) = t.as_ref() {
                        // xterm.js: `\x1b[2J\x1b[H` clears + homes the cursor.
                        t.write_str("\x1b[2J\x1b[H");
                    }
                });
                let follow_now = follow.get_untracked();
                let params = json!({
                    "container_id": id,
                    "follow": follow_now,
                });
                spawn_local(async move {
                    match send_rpc("container_logs_stream", params).await {
                        Ok(_) => status.set(Some(if follow_now {
                            "streaming…".to_string()
                        } else {
                            "snapshot".to_string()
                        })),
                        Err(e) => status.set(Some(format!("error: {e}"))),
                    }
                });
            }
            None => {
                *active_for_open.borrow_mut() = None;
                term.update_value(|slot| {
                    if let Some(mut t) = slot.take() {
                        t.dispose();
                    }
                });
            }
        }
    });

    let close = move |_| {
        term.update_value(|slot| {
            if let Some(mut t) = slot.take() {
                t.dispose();
            }
        });
        open.set(None);
    };
    let clear = move |_| {
        buffer.set(String::new());
        term.with_value(|t| {
            if let Some(t) = t.as_ref() {
                t.write_str("\x1b[2J\x1b[H");
            }
        });
    };
    let toggle_follow = move |_| follow.update(|f| *f = !*f);

    let title = move || match open.get() {
        Some(id) => format!("Logs — {id}"),
        None => String::from("Logs"),
    };

    let download_logs = move |_| {
        let id = open
            .get_untracked()
            .unwrap_or_else(|| "unknown".to_string());
        let filename = format!("container-{}-logs.txt", crate::helpers::short_id(&id));
        download_text_file(&filename, &buffer.get_untracked());
    };

    // Mount callback — leptos `node_ref` fires once when the <div> is attached.
    let host_ref = NodeRef::<leptos::html::Div>::new();
    Effect::new(move |_| {
        if open.get().is_none() {
            return;
        }
        let Some(node) = host_ref.get() else {
            return;
        };
        if term.with_value(|t| t.is_some()) {
            return;
        }
        let elem: &Element = match (*node).dyn_ref::<Element>() {
            Some(e) => e,
            None => return,
        };
        match XTerm::open(elem) {
            Ok(t) => term.update_value(|slot| *slot = Some(t)),
            Err(e) => {
                web_sys::console::warn_1(&format!("xterm open failed: {e:?}").into());
                status.set(Some("xterm.js failed to load — check CDN".into()));
            }
        }
    });

    view! {
        <Show when=move || open.get().is_some() fallback=|| view! { <></> }>
            <div class="modal-backdrop">
                <div class="modal-card modal-card-wide">
                    <h3>{title}</h3>
                    <div class="logs-toolbar">
                        <span class="log-search">
                            <input
                                class="log-search__input"
                                type="search"
                                placeholder="Search logs"
                                prop:disabled=true
                                title="search available in drawer Logs"
                            />
                            <span class="log-search__count">"0/0"</span>
                            <span class="log-search__nav">
                                <button
                                    type="button"
                                    class="btn btn--sm"
                                    prop:disabled=true
                                    title="search available in drawer Logs"
                                >
                                    "Prev"
                                </button>
                                <button
                                    type="button"
                                    class="btn btn--sm"
                                    prop:disabled=true
                                    title="search available in drawer Logs"
                                >
                                    "Next"
                                </button>
                            </span>
                        </span>
                        <button
                            type="button"
                            class="btn btn--sm log-download"
                            prop:disabled=move || buffer.get().is_empty()
                            on:click=download_logs
                        >
                            "Download"
                        </button>
                    </div>
                    <div class="modal-form">
                        <label class="modal-inline">
                            <input
                                class="checkbox"
                                type="checkbox"
                                prop:checked=move || follow.get()
                                on:change=toggle_follow
                            />
                            " follow (live tail)"
                        </label>
                        {move || status.get().map(|m| view! { <p class="status">{m}</p> })}
                        <div class="xterm-container" node_ref=host_ref></div>
                        <p class="modal-hint">
                            {format!("xterm.js scrollback (cap ~{LOGS_MAX_LINES} lines)")}
                        </p>
                    </div>
                    <div class="modal-actions">
                        <button type="button" class="btn" on:click=clear>"Clear"</button>
                        <button type="button" class="btn" on:click=close>"Close"</button>
                    </div>
                </div>
            </div>
        </Show>
    }
}
