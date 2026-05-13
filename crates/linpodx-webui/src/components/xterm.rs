//! Thin wasm-bindgen wrapper around the xterm.js Terminal global.
//!
//! Phase 13 Stream B. The xterm.js library is loaded via CDN script tags in
//! `index.html`, which exposes a global `Terminal` constructor and an
//! `addon-fit.js` global `FitAddon` constructor. We don't pull in npm /
//! wasm-bindgen-derive bindings — instead we go through `js_sys::Reflect` to
//! construct the objects and call methods, which keeps the dependency surface
//! to `js-sys` and `web-sys` only.
//!
//! The wrapper deliberately holds raw `JsValue` handles: leptos signals on the
//! single-threaded wasm target are happy to carry non-Send/Sync values inside
//! `RefCell` storage, but we never expose them to the rest of the crate. All
//! lifecycle (open / write / dispose / addon load / fit) lives behind these
//! safe Rust methods so callers can't accidentally double-dispose.

use js_sys::{Array, Function, JsString, Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;
use web_sys::Element;

/// Owned handle to one xterm.js `Terminal` instance plus its loaded `FitAddon`.
///
/// Drop or [`Self::dispose`] tears down the underlying terminal — the caller
/// must guarantee the host `<div>` outlives the dispose call (leptos modal
/// `Show` removes the div on close, so dispose first, then close).
pub struct XTerm {
    term: JsValue,
    fit_addon: Option<JsValue>,
    /// `true` after `dispose()` has been called. Subsequent writes / fits are
    /// no-ops so a late `EventKind::Log` notification from the daemon doesn't
    /// hit a stale terminal.
    disposed: bool,
}

impl XTerm {
    /// Construct a new `Terminal` and `open()` it on the given DOM element.
    /// Loads the FitAddon if available and triggers an initial `fit()`.
    /// All errors fall back to console warnings — the modal stays open.
    pub fn open(target: &Element) -> Result<Self, JsValue> {
        let global = global_this();
        let term_ctor = Reflect::get(&global, &JsString::from("Terminal"))?;
        let term_ctor: Function = term_ctor
            .dyn_into()
            .map_err(|_| JsValue::from_str("xterm.js Terminal constructor missing"))?;

        let opts = default_terminal_options();
        let term = construct1(&term_ctor, &opts)?;

        // Load fit addon if the global is present (CDN may fail to load).
        let fit_addon = match Reflect::get(&global, &JsString::from("FitAddon")) {
            Ok(v) if !v.is_undefined() && !v.is_null() => {
                let ns: Object = v
                    .dyn_into()
                    .map_err(|_| JsValue::from_str("FitAddon namespace not an object"))?;
                let inner = Reflect::get(&ns, &JsString::from("FitAddon"))?;
                if let Ok(ctor) = inner.dyn_into::<Function>() {
                    let addon = construct0(&ctor)?;
                    let load_fn = Reflect::get(&term, &JsString::from("loadAddon"))?;
                    let load_fn: Function = load_fn
                        .dyn_into()
                        .map_err(|_| JsValue::from_str("term.loadAddon not callable"))?;
                    load_fn.call1(&term, &addon)?;
                    Some(addon)
                } else {
                    None
                }
            }
            _ => None,
        };

        let open_fn = Reflect::get(&term, &JsString::from("open"))?;
        let open_fn: Function = open_fn
            .dyn_into()
            .map_err(|_| JsValue::from_str("term.open not callable"))?;
        open_fn.call1(&term, target.as_ref())?;

        let mut x = Self {
            term,
            fit_addon,
            disposed: false,
        };
        x.fit();
        Ok(x)
    }

    /// Append a UTF-8 string to the terminal. ANSI escape sequences pass
    /// through xterm.js verbatim, which gives us coloured `podman logs` output
    /// for free.
    pub fn write_str(&self, s: &str) {
        if self.disposed {
            return;
        }
        if let Ok(write_fn) = Reflect::get(&self.term, &JsString::from("write")) {
            if let Ok(write_fn) = write_fn.dyn_into::<Function>() {
                let _ = write_fn.call1(&self.term, &JsString::from(s));
            }
        }
    }

    /// Append a raw byte slice. Used by the PTY proxy where the daemon ships
    /// arbitrary bytes (potentially a partial multi-byte UTF-8 sequence) — we
    /// hand the underlying Uint8Array to xterm.js, which buffers across calls.
    pub fn write_bytes(&self, bytes: &[u8]) {
        if self.disposed {
            return;
        }
        let arr = Uint8Array::new_with_length(bytes.len() as u32);
        arr.copy_from(bytes);
        if let Ok(write_fn) = Reflect::get(&self.term, &JsString::from("write")) {
            if let Ok(write_fn) = write_fn.dyn_into::<Function>() {
                let _ = write_fn.call1(&self.term, &arr);
            }
        }
    }

    /// Run the FitAddon `fit()` if one is loaded; otherwise no-op.
    pub fn fit(&mut self) {
        if self.disposed {
            return;
        }
        if let Some(addon) = &self.fit_addon {
            if let Ok(fit_fn) = Reflect::get(addon, &JsString::from("fit")) {
                if let Ok(fit_fn) = fit_fn.dyn_into::<Function>() {
                    let _ = fit_fn.call0(addon);
                }
            }
        }
    }

    /// Register a JS callback for terminal `data` events (raw key input).
    /// Used by the PTY modal to forward keystrokes to the WebSocket. Returns
    /// the disposable returned by xterm.js so the caller can detach the
    /// handler; we drop it on dispose so the `Closure` stays alive only as
    /// long as the modal.
    pub fn on_data(&self, cb: &Function) -> Result<JsValue, JsValue> {
        if self.disposed {
            return Ok(JsValue::UNDEFINED);
        }
        let on_data = Reflect::get(&self.term, &JsString::from("onData"))?;
        let on_data: Function = on_data
            .dyn_into()
            .map_err(|_| JsValue::from_str("term.onData not callable"))?;
        on_data.call1(&self.term, cb)
    }

    /// Tear down the underlying Terminal. Idempotent.
    pub fn dispose(&mut self) {
        if self.disposed {
            return;
        }
        self.disposed = true;
        if let Ok(dispose_fn) = Reflect::get(&self.term, &JsString::from("dispose")) {
            if let Ok(dispose_fn) = dispose_fn.dyn_into::<Function>() {
                let _ = dispose_fn.call0(&self.term);
            }
        }
        self.fit_addon = None;
    }
}

impl Drop for XTerm {
    fn drop(&mut self) {
        self.dispose();
    }
}

fn global_this() -> JsValue {
    // js_sys::global() returns the worker/window scope; for our purposes the
    // browser `window` is fine because the CDN scripts attach there.
    js_sys::global().into()
}

fn default_terminal_options() -> JsValue {
    let opts = Object::new();
    let _ = Reflect::set(&opts, &JsString::from("convertEol"), &JsValue::from(true));
    let _ = Reflect::set(&opts, &JsString::from("cursorBlink"), &JsValue::from(true));
    let _ = Reflect::set(&opts, &JsString::from("fontSize"), &JsValue::from(12.0));
    let _ = Reflect::set(
        &opts,
        &JsString::from("fontFamily"),
        &JsString::from("ui-monospace, Menlo, Consolas, monospace"),
    );
    // Match the dark gradient background of the modal.
    let theme = Object::new();
    let _ = Reflect::set(
        &theme,
        &JsString::from("background"),
        &JsString::from("#0a0a0a"),
    );
    let _ = Reflect::set(
        &theme,
        &JsString::from("foreground"),
        &JsString::from("#d4d4d4"),
    );
    let _ = Reflect::set(&opts, &JsString::from("theme"), &theme);
    opts.into()
}

fn construct0(ctor: &Function) -> Result<JsValue, JsValue> {
    let args = Array::new();
    Reflect::construct(ctor, &args)
}

fn construct1(ctor: &Function, arg0: &JsValue) -> Result<JsValue, JsValue> {
    let args = Array::new();
    args.push(arg0);
    Reflect::construct(ctor, &args)
}
