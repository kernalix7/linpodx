//! Interactive PTY exec modal — bridges xterm.js ↔ daemon `/pty/<bridge_id>`
//! WebSocket binary stream.
//!
//! Phase 13 Stream B. Flow:
//!
//!   1. Caller sets `open` to `Some(container_id)`.
//!   2. User types a command (and optional cols/rows hint), clicks Open.
//!   3. We call `container_exec_pty` JSON-RPC — it allocates a PTY on the
//!      daemon side and returns `{bridge_id, endpoint}`.
//!   4. We open a *separate* WebSocket to `wss://host<endpoint>?token=<t>` in
//!      `arraybuffer` binary mode.
//!   5. xterm.js `onData` keystrokes are encoded as UTF-8 bytes and sent as
//!      WebSocket binary frames; daemon stdout frames are written back to
//!      xterm.js via `XTerm::write_bytes`.
//!   6. Closing the modal closes the socket (which the daemon side handles by
//!      tearing down the PTY) and disposes the terminal.
//!
//! XSS / safety posture: command argv goes through leptos `view!` (escaped),
//! and we never construct DOM with `innerHTML`. The terminal is fed binary
//! data straight to xterm.js's parser — the DOM update is owned entirely by
//! xterm.js, not by us.

use gloo_storage::Storage;
use leptos::prelude::*;
use leptos::reactive::owner::{LocalStorage, StoredValue};
use serde_json::json;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::spawn_local;
use web_sys::{js_sys, BinaryType, Element, MessageEvent, WebSocket};

use crate::components::xterm::XTerm;
use crate::helpers::{build_pty_url, parse_command, parse_pty_response, parse_pty_size};
use crate::ws::send_rpc;

const TOKEN_KEY: &str = "linpodx_token";

/// Owned holder for the WebSocket + every `Closure` we register on it.
/// Dropping it tears the connection down deterministically (sockets in the
/// browser get GC'd lazily otherwise, which can leak the PTY on the daemon
/// side until the next collection).
struct PtySocket {
    ws: WebSocket,
    // Keep closures alive for as long as the socket is open. Dropping the
    // PtySocket drops them, which detaches the JS-side handlers.
    _on_message: Closure<dyn FnMut(MessageEvent)>,
    _on_close: Closure<dyn FnMut(web_sys::CloseEvent)>,
    _on_error: Closure<dyn FnMut(web_sys::Event)>,
    _on_data: Closure<dyn FnMut(JsValue)>,
}

impl Drop for PtySocket {
    fn drop(&mut self) {
        let _ = self.ws.close();
    }
}

#[component]
pub fn ExecPtyModal(open: RwSignal<Option<String>>) -> impl IntoView {
    let command = RwSignal::new(String::from("/bin/sh"));
    let cols_input = RwSignal::new(String::from("80"));
    let rows_input = RwSignal::new(String::from("24"));
    let status: RwSignal<Option<String>> = RwSignal::new(None);
    let busy = RwSignal::new(false);
    // True once the WebSocket is open and the terminal is wired to it.
    let attached = RwSignal::new(false);

    // Non-thread-safe state lives in `StoredValue<_, LocalStorage>`. It's
    // `Copy`, so handlers in `view!` can freely capture it without
    // `Rc<RefCell<>>` (which would fail leptos' `Send + Sync` view bounds).
    let term: StoredValue<Option<XTerm>, LocalStorage> = StoredValue::new_local(None);
    let socket: StoredValue<Option<PtySocket>, LocalStorage> = StoredValue::new_local(None);

    // Reset form / dispose anything still attached when the target changes.
    Effect::new(move |_| {
        let id = open.get();
        if id.is_some() {
            command.set(String::from("/bin/sh"));
            cols_input.set(String::from("80"));
            rows_input.set(String::from("24"));
            status.set(None);
            busy.set(false);
            attached.set(false);
        } else {
            // Modal closed externally — tear down.
            socket.update_value(|s| {
                s.take();
            });
            term.update_value(|slot| {
                if let Some(mut t) = slot.take() {
                    t.dispose();
                }
            });
            attached.set(false);
        }
    });

    // Mount the xterm.js terminal once the host <div> attaches. We do this
    // even before the user clicks Open so they can see the modal's empty
    // terminal pane (mirrors the LogsModal feel).
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

    let target = Signal::derive(move || open.get());

    // Submit handler — issues `container_exec_pty` and wires the socket.
    let submit = move |_| {
        let id = match target.get_untracked() {
            Some(id) => id,
            None => return,
        };
        if attached.get_untracked() {
            return;
        }
        let argv = parse_command(&command.get_untracked());
        if argv.is_empty() {
            status.set(Some("command is required".into()));
            return;
        }
        let cols = match parse_pty_size(&cols_input.get_untracked(), "cols") {
            Ok(v) => v,
            Err(e) => {
                status.set(Some(e));
                return;
            }
        };
        let rows = match parse_pty_size(&rows_input.get_untracked(), "rows") {
            Ok(v) => v,
            Err(e) => {
                status.set(Some(e));
                return;
            }
        };

        let mut params = json!({
            "container_id": id,
            "command": argv,
            "env": Vec::<(String, String)>::new(),
        });
        if let Some(c) = cols {
            params["cols"] = json!(c);
        }
        if let Some(r) = rows {
            params["rows"] = json!(r);
        }
        busy.set(true);
        status.set(Some("opening pty…".into()));

        spawn_local(async move {
            let resp = match send_rpc("container_exec_pty", params).await {
                Ok(v) => v,
                Err(e) => {
                    busy.set(false);
                    status.set(Some(format!("error: {e}")));
                    return;
                }
            };
            let (_bridge_id, endpoint) = match parse_pty_response(&resp) {
                Ok(p) => p,
                Err(e) => {
                    busy.set(false);
                    status.set(Some(e));
                    return;
                }
            };
            match attach_socket(&endpoint, term, status) {
                Ok(s) => {
                    socket.update_value(|slot| *slot = Some(s));
                    attached.set(true);
                    status.set(Some(format!("attached: {endpoint}")));
                }
                Err(e) => {
                    status.set(Some(format!("ws attach failed: {e}")));
                }
            }
            busy.set(false);
        });
    };

    let close = move |_| {
        socket.update_value(|s| {
            s.take();
        });
        term.update_value(|slot| {
            if let Some(mut t) = slot.take() {
                t.dispose();
            }
        });
        attached.set(false);
        open.set(None);
    };

    let detach = move |_| {
        socket.update_value(|s| {
            s.take();
        });
        attached.set(false);
        status.set(Some("detached".into()));
    };

    let title = move || match target.get() {
        Some(id) => format!("Exec PTY — {id}"),
        None => String::from("Exec PTY"),
    };

    view! {
        <Show when=move || open.get().is_some() fallback=|| view! { <></> }>
            <div class="modal-backdrop">
                <div class="modal-card modal-card-wide">
                    <h3>{title}</h3>
                    <div class="modal-form">
                        <label>
                            "Command (argv, space-separated)"
                            <input
                                type="text"
                                placeholder="/bin/sh"
                                prop:value=move || command.get()
                                prop:disabled=move || attached.get()
                                on:input=move |ev| command.set(event_target_value(&ev))
                            />
                        </label>
                        <label class="modal-inline">
                            "cols "
                            <input
                                type="text"
                                style="width: 5em"
                                prop:value=move || cols_input.get()
                                prop:disabled=move || attached.get()
                                on:input=move |ev| cols_input.set(event_target_value(&ev))
                            />
                            " rows "
                            <input
                                type="text"
                                style="width: 5em"
                                prop:value=move || rows_input.get()
                                prop:disabled=move || attached.get()
                                on:input=move |ev| rows_input.set(event_target_value(&ev))
                            />
                        </label>
                        {move || status.get().map(|m| view! { <p class="status">{m}</p> })}
                        <div class="xterm-container" node_ref=host_ref></div>
                        <p class="modal-hint">
                            "binary stream — UTF-8 in / arbitrary bytes out"
                        </p>
                    </div>
                    <div class="modal-actions">
                        <button
                            type="button"
                            class="primary"
                            prop:disabled=move || busy.get() || attached.get()
                            on:click=submit
                        >
                            {move || if busy.get() { "Opening…" } else { "Open" }}
                        </button>
                        <button
                            type="button"
                            prop:disabled=move || !attached.get()
                            on:click=detach
                        >
                            "Detach"
                        </button>
                        <button type="button" on:click=close>"Close"</button>
                    </div>
                </div>
            </div>
        </Show>
    }
}

/// Open the PTY WebSocket, wire it to the xterm.js terminal, and return a
/// `PtySocket` that owns the lifetimes. `status` is updated as the connection
/// progresses (open → close / error).
fn attach_socket(
    endpoint: &str,
    term: StoredValue<Option<XTerm>, LocalStorage>,
    status: RwSignal<Option<String>>,
) -> Result<PtySocket, String> {
    let location = web_sys::window()
        .and_then(|w| w.location().host().ok())
        .ok_or_else(|| "no window/location".to_string())?;
    let proto = match web_sys::window()
        .and_then(|w| w.location().protocol().ok())
        .as_deref()
    {
        Some("https:") => "wss",
        _ => "ws",
    };
    let token = gloo_storage::LocalStorage::get::<String>(TOKEN_KEY)
        .ok()
        .filter(|s: &String| !s.trim().is_empty());
    let url = build_pty_url(proto, &location, endpoint, token.as_deref());

    let ws = WebSocket::new(&url).map_err(|e| format!("ws new: {e:?}"))?;
    ws.set_binary_type(BinaryType::Arraybuffer);

    // ---- onmessage: forward server bytes into the terminal ---------------
    let on_message = Closure::<dyn FnMut(MessageEvent)>::new(move |e: MessageEvent| {
        let data = e.data();
        if let Ok(buf) = data.dyn_into::<js_sys::ArrayBuffer>() {
            let arr = js_sys::Uint8Array::new(&buf);
            let bytes = arr.to_vec();
            term.with_value(|t| {
                if let Some(t) = t.as_ref() {
                    t.write_bytes(&bytes);
                }
            });
        } else if let Some(s) = e.data().as_string() {
            // Fallback: text frames (shouldn't happen with arraybuffer mode,
            // but be defensive).
            term.with_value(|t| {
                if let Some(t) = t.as_ref() {
                    t.write_str(&s);
                }
            });
        }
    });
    ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

    // ---- onclose / onerror: surface to status line -----------------------
    let on_close = Closure::<dyn FnMut(web_sys::CloseEvent)>::new(move |e: web_sys::CloseEvent| {
        let code = e.code();
        let reason = e.reason();
        let msg = if reason.is_empty() {
            format!("ws closed (code={code})")
        } else {
            format!("ws closed: {reason} (code={code})")
        };
        status.set(Some(msg));
    });
    ws.set_onclose(Some(on_close.as_ref().unchecked_ref()));

    let on_error = Closure::<dyn FnMut(web_sys::Event)>::new(move |_e: web_sys::Event| {
        status.set(Some("ws error".into()));
    });
    ws.set_onerror(Some(on_error.as_ref().unchecked_ref()));

    // ---- terminal onData: forward keystrokes as binary frames ------------
    let ws_for_input = ws.clone();
    let on_data = Closure::<dyn FnMut(JsValue)>::new(move |data: JsValue| {
        let s = match data.as_string() {
            Some(s) => s,
            None => return,
        };
        let bytes = s.as_bytes();
        let arr = js_sys::Uint8Array::new_with_length(bytes.len() as u32);
        arr.copy_from(bytes);
        let buf: js_sys::ArrayBuffer = arr.buffer();
        let _ = ws_for_input.send_with_array_buffer(&buf);
    });

    let res = term.with_value(|t| match t.as_ref() {
        Some(t) => t.on_data(on_data.as_ref().unchecked_ref()),
        None => Err(JsValue::from_str("xterm not mounted")),
    });
    res.map_err(|e| format!("term.onData: {e:?}"))?;

    Ok(PtySocket {
        ws,
        _on_message: on_message,
        _on_close: on_close,
        _on_error: on_error,
        _on_data: on_data,
    })
}
