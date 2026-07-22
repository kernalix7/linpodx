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

/// Reusable exec-PTY terminal pane. Owns the xterm.js mount, the
/// `container_exec_pty` handshake, the `/pty/<bridge_id>` WebSocket and their
/// deterministic teardown — everything except the surrounding chrome. Both
/// [`ExecPtyModal`] (with a command/size form) and the container-detail drawer
/// Terminal tab (fixed `/bin/sh`) embed this, so the machinery lives in exactly
/// one place.
///
/// Lifecycle: when `active` is `true` and `target` is `Some(id)` and the host
/// `<div>` has mounted, the pane opens a `/bin/sh`-style PTY once (using the
/// current `command`/`cols`/`rows` signal values, read untracked). Flipping
/// `active` to `false`, changing `target`, or unmounting tears the socket +
/// terminal down. `attached` and `status` are lifted so the embedding chrome
/// can reflect connection state.
#[component]
pub fn PtyTerminal(
    #[prop(into)] target: Signal<Option<String>>,
    #[prop(into)] active: Signal<bool>,
    #[prop(into)] command: Signal<String>,
    #[prop(into)] cols: Signal<String>,
    #[prop(into)] rows: Signal<String>,
    status: RwSignal<Option<String>>,
    attached: RwSignal<bool>,
) -> impl IntoView {
    let busy = RwSignal::new(false);

    // Non-thread-safe handles live in `StoredValue<_, LocalStorage>` (Copy), so
    // handlers / effects capture them without an `Rc<RefCell>` dance.
    let term: StoredValue<Option<XTerm>, LocalStorage> = StoredValue::new_local(None);
    let socket: StoredValue<Option<PtySocket>, LocalStorage> = StoredValue::new_local(None);
    let host_ref = NodeRef::<leptos::html::Div>::new();

    // Drop the socket (→ daemon PTY teardown) and dispose the terminal.
    let teardown = move || {
        socket.update_value(|s| {
            s.take();
        });
        term.update_value(|slot| {
            if let Some(mut t) = slot.take() {
                t.dispose();
            }
        });
        attached.set(false);
        busy.set(false);
    };

    // Single driving effect: (re)mount + auto-open while active, tear down when
    // inactive / target cleared / container switched. `command`/`cols`/`rows`
    // are read untracked so typing in the modal form never re-triggers a
    // reconnect — only `active`/`target`/the host node do.
    Effect::new(move |prev: Option<Option<String>>| {
        let id = target.get();
        let is_active = active.get();
        let prev_id = prev.flatten();
        if prev_id.is_some() && prev_id != id {
            // Container switched — drop the old session so a fresh one opens.
            teardown();
        }

        if !is_active || id.is_none() {
            if attached.get_untracked() || busy.get_untracked() || term.with_value(|t| t.is_some())
            {
                teardown();
            }
            return id;
        }

        let Some(node) = host_ref.get() else {
            return id;
        };

        // Mount the terminal exactly once.
        if term.with_value(|t| t.is_none()) {
            match (*node).dyn_ref::<Element>() {
                Some(elem) => match XTerm::open(elem) {
                    Ok(t) => term.update_value(|slot| *slot = Some(t)),
                    Err(e) => {
                        web_sys::console::warn_1(&format!("xterm open failed: {e:?}").into());
                        status.set(Some("xterm.js failed to load — check CDN".into()));
                        return id;
                    }
                },
                None => return id,
            }
        }

        // Open the PTY exactly once per session.
        if attached.get_untracked() || busy.get_untracked() {
            return id;
        }
        let Some(container_id) = id.clone() else {
            return id;
        };
        let argv = {
            let parsed = parse_command(&command.get_untracked());
            if parsed.is_empty() {
                vec![String::from("/bin/sh")]
            } else {
                parsed
            }
        };
        let cols_v = parse_pty_size(&cols.get_untracked(), "cols").ok().flatten();
        let rows_v = parse_pty_size(&rows.get_untracked(), "rows").ok().flatten();
        let mut params = json!({
            "container_id": container_id,
            "command": argv,
            "env": Vec::<(String, String)>::new(),
        });
        if let Some(c) = cols_v {
            params["cols"] = json!(c);
        }
        if let Some(r) = rows_v {
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
            let endpoint = match parse_pty_response(&resp) {
                Ok((_bridge_id, endpoint)) => endpoint,
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
                Err(e) => status.set(Some(format!("ws attach failed: {e}"))),
            }
            busy.set(false);
        });

        id
    });

    // Deterministic teardown when the pane leaves the DOM (`teardown` is a
    // `Copy` closure over `Copy` handles, so it can be handed to `on_cleanup`
    // after the driving effect has already captured its own copy).
    on_cleanup(teardown);

    view! { <div class="xterm-container" node_ref=host_ref></div> }
}

#[component]
pub fn ExecPtyModal(open: RwSignal<Option<String>>) -> impl IntoView {
    let command = RwSignal::new(String::from("/bin/sh"));
    let cols_input = RwSignal::new(String::from("80"));
    let rows_input = RwSignal::new(String::from("24"));
    let status: RwSignal<Option<String>> = RwSignal::new(None);
    // True once the WebSocket is open and the terminal is wired to it (owned by
    // the embedded `PtyTerminal`, lifted here so the buttons/inputs react).
    let attached = RwSignal::new(false);
    // Open-request latch: the "Open" button sets it, "Detach"/"Close" clear it.
    // Fed to `PtyTerminal` as `active` so all socket logic lives there.
    let attach_requested = RwSignal::new(false);

    // Reset the form each time a new target opens the modal.
    Effect::new(move |_| {
        if open.get().is_some() {
            command.set(String::from("/bin/sh"));
            cols_input.set(String::from("80"));
            rows_input.set(String::from("24"));
            status.set(None);
            attach_requested.set(false);
        } else {
            attach_requested.set(false);
        }
    });

    let target = Signal::derive(move || open.get());
    let active = Signal::derive(move || open.get().is_some() && attach_requested.get());

    // Validate before latching `attach_requested` so `PtyTerminal` only ever
    // receives well-formed argv / sizes.
    let submit = move |_| {
        if attached.get_untracked() {
            return;
        }
        if parse_command(&command.get_untracked()).is_empty() {
            status.set(Some("command is required".into()));
            return;
        }
        if let Err(e) = parse_pty_size(&cols_input.get_untracked(), "cols") {
            status.set(Some(e));
            return;
        }
        if let Err(e) = parse_pty_size(&rows_input.get_untracked(), "rows") {
            status.set(Some(e));
            return;
        }
        attach_requested.set(true);
    };

    // Detach → drop the session but keep the modal open (Open reconnects).
    let detach = move |_| {
        attach_requested.set(false);
        status.set(Some("detached".into()));
    };

    let close = move |_| {
        attach_requested.set(false);
        open.set(None);
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
                                class="input"
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
                                class="input"
                                type="text"
                                style="width: 5em"
                                prop:value=move || cols_input.get()
                                prop:disabled=move || attached.get()
                                on:input=move |ev| cols_input.set(event_target_value(&ev))
                            />
                            " rows "
                            <input
                                class="input"
                                type="text"
                                style="width: 5em"
                                prop:value=move || rows_input.get()
                                prop:disabled=move || attached.get()
                                on:input=move |ev| rows_input.set(event_target_value(&ev))
                            />
                        </label>
                        {move || status.get().map(|m| view! { <p class="status">{m}</p> })}
                        <PtyTerminal
                            target=target
                            active=active
                            command=command
                            cols=cols_input
                            rows=rows_input
                            status=status
                            attached=attached
                        />
                        <p class="modal-hint">
                            "binary stream — UTF-8 in / arbitrary bytes out"
                        </p>
                    </div>
                    <div class="modal-actions">
                        <button
                            type="button"
                            class="btn btn--primary"
                            prop:disabled=move || active.get() || attached.get()
                            on:click=submit
                        >
                            {move || if attached.get() { "Attached" } else { "Open" }}
                        </button>
                        <button
                            type="button"
                            class="btn"
                            prop:disabled=move || !attached.get()
                            on:click=detach
                        >
                            "Detach"
                        </button>
                        <button type="button" class="btn" on:click=close>"Close"</button>
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
