//! linpodx-webui — leptos-based browser SPA replacing the Phase 8 vanilla UI.
//!
//! Phase 9 Stream C entry crate. This crate has two faces:
//!
//! * On `wasm32-unknown-unknown`, it compiles to a `cdylib` consumed by
//!   `wasm-bindgen`. The daemon's `build.rs` (see `linpodx-daemon/build.rs`)
//!   invokes `cargo build --target wasm32-unknown-unknown --release` and bundles
//!   the resulting artifact under `OUT_DIR/linpodx_webui.{wasm,js}`. The browser
//!   loads `index.html` from `/ui/`, which imports the JS shim and calls
//!   [`entry`] — that mounts the leptos `AppRoot` component to `<body>`.
//!
//! * On any other target (incl. host x86_64-linux), the `entry` symbol stays a
//!   no-op so `cargo build --workspace` and `cargo test --workspace` keep
//!   working without a wasm toolchain. All leptos-dependent modules are gated
//!   on `cfg(target_arch = "wasm32")` for the same reason.
//!
//! XSS posture: every render path goes through leptos `view!`, which escapes
//! interpolated values by default. We never reach for `inner_html` / `set_html`.

#![forbid(unsafe_code)]

#[cfg(target_arch = "wasm32")]
mod app;
#[cfg(target_arch = "wasm32")]
mod components;
#[cfg(target_arch = "wasm32")]
mod ws;

// Phase 17 — REST wrappers for the new Stream A/B/C endpoints. Body-building
// helpers compile on every target so the host-side `cargo test` covers them.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
pub mod api_client;

// Pure-Rust helpers used by the modal components. Compiled on every target so
// the host-side `cargo test` can exercise their logic without a wasm toolchain.
// On non-wasm builds the helpers are reachable only from `#[cfg(test)]`, so we
// silence the resulting dead-code warnings there.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
mod helpers;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

/// Browser entry point. Called by the JS bootstrap shim emitted by
/// `wasm-bindgen` (`init().then(() => entry())`).
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn entry() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(app::AppRoot);
}

/// Host build keeps the symbol so downstream code referring to it (e.g. test
/// scaffolding) compiles, but does no work.
#[cfg(not(target_arch = "wasm32"))]
pub fn entry() {}

// ---------------------------------------------------------------------------
// Phase 14 — xterm.js vendoring assets, exposed for daemon consumption.
//
// These embed whatever `build.rs` placed in `OUT_DIR` (real downloaded bytes
// when `LINPODX_VENDOR_XTERM=1`, textual stubs otherwise). The daemon copies
// the same data into its own `OUT_DIR` independently — these constants exist
// so other consumers / tests can introspect the webui crate's own copy.
// ---------------------------------------------------------------------------

/// Vendored xterm.js bytes. Real minified JS when built with
/// `LINPODX_VENDOR_XTERM=1`, otherwise a `// stub: ...` placeholder.
pub const VENDORED_XTERM_JS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/xterm.js"));

/// Vendored xterm.css bytes. Real CSS when vendored, placeholder otherwise.
pub const VENDORED_XTERM_CSS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/xterm.css"));

/// Vendored addon-fit.js bytes. Real JS when vendored, placeholder otherwise.
pub const VENDORED_ADDON_FIT_JS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/addon-fit.js"));

/// True when the embedded bytes are the textual `// stub:` placeholder the
/// build script writes by default. Real downloads never start with this prefix.
pub fn vendored_asset_is_stub(body: &[u8]) -> bool {
    body.starts_with(b"// stub")
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod vendoring_tests {
    use super::*;

    #[test]
    fn build_script_emits_xterm_assets_into_out_dir() {
        // include_bytes! has already proved the files exist; the slices must
        // also be non-empty in either stub or vendored mode.
        assert!(!std::hint::black_box(VENDORED_XTERM_JS).is_empty());
        assert!(!std::hint::black_box(VENDORED_XTERM_CSS).is_empty());
        assert!(!std::hint::black_box(VENDORED_ADDON_FIT_JS).is_empty());
    }

    #[test]
    fn vendored_asset_is_stub_recognises_build_script_prefix() {
        assert!(vendored_asset_is_stub(
            b"// stub: linpodx-webui xterm asset\n"
        ));
        assert!(vendored_asset_is_stub(b"// stub: anything"));
        assert!(!vendored_asset_is_stub(b"!function(){}();"));
        assert!(!vendored_asset_is_stub(b".terminal{color:white}"));
        assert!(!vendored_asset_is_stub(b""));
    }

    #[test]
    fn default_build_emits_stub_bytes_when_env_unset() {
        // CI / `cargo test --workspace` runs without LINPODX_VENDOR_XTERM, so
        // the embedded bytes must be the stub variant. Pin the invariant.
        if std::env::var_os("LINPODX_VENDOR_XTERM").is_none() {
            assert!(
                vendored_asset_is_stub(VENDORED_XTERM_JS),
                "default build must embed the stub for xterm.js"
            );
            assert!(vendored_asset_is_stub(VENDORED_XTERM_CSS));
            assert!(vendored_asset_is_stub(VENDORED_ADDON_FIT_JS));
        }
    }

    #[test]
    fn index_html_references_xterm_loader() {
        // The shipped index.html must keep the jsDelivr URL (default mode);
        // the daemon swaps it to /ui/assets/* at serve time when vendored.
        let html = include_str!("../index.html");
        assert!(
            html.contains("xterm.js"),
            "index.html must load xterm.js from somewhere"
        );
        assert!(
            html.contains("addon-fit.js"),
            "index.html must load the addon-fit shim"
        );
    }
}
