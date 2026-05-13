//! Phase 9 — embed the leptos WASM bundle into the daemon binary.
//!
//! Behavior:
//!
//! * Default (`LINPODX_WASM` unset): write small "// stub" placeholder bytes to
//!   `OUT_DIR/linpodx_webui.{wasm,js}` so the `include_bytes!` calls in
//!   `web_ui.rs` always have a target. The runtime serve path detects the stub
//!   prefix and falls back to the Phase 8 vanilla bundle automatically with a
//!   warning. This keeps `cargo build --workspace` green on hosts without a
//!   `wasm32-unknown-unknown` toolchain or `wasm-bindgen-cli`.
//!
//! * `LINPODX_WASM=1`: invoke `cargo build -p linpodx-webui --release --target
//!   wasm32-unknown-unknown` and then run `wasm-bindgen` to produce the JS
//!   shim. Any failure (missing toolchain, missing tool, build error) is
//!   reported via `cargo:warning=` and we fall back to the stub bytes —
//!   builds never fail just because the wasm pipeline is incomplete.
//!
//! No filesystem writes happen outside of `OUT_DIR`. We `cargo:rerun-if-…`
//! exactly the inputs that affect the output so incremental builds stay quick.

use std::path::{Path, PathBuf};
use std::process::Command;

const STUB_WASM: &[u8] = b"// stub: linpodx-webui wasm bundle was not built (set LINPODX_WASM=1)\n";
const STUB_JS: &str =
    "// stub: linpodx-webui js shim was not built (set LINPODX_WASM=1)\nexport default function init(){return Promise.reject(new Error('webui-wasm-stub'));}export function entry(){}\n";

fn main() {
    println!("cargo:rerun-if-env-changed=LINPODX_WASM");
    // Phase 14: linpodx-webui/build.rs reads this same env var to decide
    // whether to vendor xterm.js. We rerun + emit a cfg flag so web_ui.rs
    // can switch between CDN-loaded and locally-served xterm assets.
    println!("cargo:rerun-if-env-changed=LINPODX_VENDOR_XTERM");
    // Phase 14: declare the cfg name so the compiler doesn't warn
    // ("unexpected_cfgs") when it isn't set.
    println!("cargo:rustc-check-cfg=cfg(linpodx_xterm_vendored)");
    if std::env::var_os("LINPODX_VENDOR_XTERM").is_some() {
        println!("cargo:rustc-cfg=linpodx_xterm_vendored");
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../linpodx-webui/Cargo.toml");
    println!("cargo:rerun-if-changed=../linpodx-webui/src");
    println!("cargo:rerun-if-changed=../linpodx-webui/index.html");
    println!("cargo:rerun-if-changed=../linpodx-webui/build.rs");

    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR set by cargo"));
    let wasm_out = out_dir.join("linpodx_webui.wasm");
    let js_out = out_dir.join("linpodx_webui.js");

    let want_wasm = std::env::var_os("LINPODX_WASM").is_some();
    let mut wrote_real = false;

    if want_wasm {
        match try_build_wasm(&out_dir) {
            Ok((wasm, js)) => {
                if let Err(e) = std::fs::copy(&wasm, &wasm_out) {
                    println!("cargo:warning=failed to copy wasm artifact: {e}");
                } else if let Err(e) = std::fs::copy(&js, &js_out) {
                    println!("cargo:warning=failed to copy wasm-bindgen js: {e}");
                } else {
                    wrote_real = true;
                }
            }
            Err(e) => {
                println!("cargo:warning=LINPODX_WASM set but wasm build failed: {e}");
                println!("cargo:warning=falling back to vanilla Phase 8 Web UI at runtime");
            }
        }
    }

    if !wrote_real {
        if let Err(e) = std::fs::write(&wasm_out, STUB_WASM) {
            println!("cargo:warning=failed to write wasm stub: {e}");
        }
        if let Err(e) = std::fs::write(&js_out, STUB_JS) {
            println!("cargo:warning=failed to write js stub: {e}");
        }
    }

    // Phase 14: emit xterm.js / xterm.css / addon-fit.js into the daemon's
    // OUT_DIR so `web_ui.rs` can `include_bytes!` them unconditionally. The
    // *content* depends on `LINPODX_VENDOR_XTERM`: real bytes downloaded from
    // jsDelivr when set, tiny stubs otherwise. The daemon runtime only serves
    // these assets when the `linpodx_xterm_vendored` cfg is on.
    if let Err(e) = emit_xterm_assets(&out_dir) {
        // Vendoring is opt-in: a hard build failure here would punish the
        // default unset-env path. We surface the error so operators who set
        // LINPODX_VENDOR_XTERM=1 can see why their build degraded to stubs.
        if std::env::var_os("LINPODX_VENDOR_XTERM").is_some() {
            panic!("LINPODX_VENDOR_XTERM=1 but xterm vendoring failed: {e}");
        } else {
            println!("cargo:warning=xterm asset stub write failed: {e}");
        }
    }
}

const XTERM_STUB_PREFIX: &[u8] =
    b"// stub: xterm asset not vendored (set LINPODX_VENDOR_XTERM=1)\n";

const XTERM_ASSETS: &[(&str, &str)] = &[
    (
        "xterm.js",
        "https://cdn.jsdelivr.net/npm/@xterm/xterm@5/lib/xterm.js",
    ),
    (
        "xterm.css",
        "https://cdn.jsdelivr.net/npm/@xterm/xterm@5/css/xterm.css",
    ),
    (
        "addon-fit.js",
        "https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.10/lib/addon-fit.js",
    ),
];

fn emit_xterm_assets(out_dir: &Path) -> Result<(), String> {
    let want_vendor = std::env::var_os("LINPODX_VENDOR_XTERM").is_some();
    for (name, url) in XTERM_ASSETS {
        let dest = out_dir.join(name);
        let body = if want_vendor {
            xterm_download_with_curl(url).map_err(|e| format!("download {name} from {url}: {e}"))?
        } else {
            xterm_stub_for(name)
        };
        std::fs::write(&dest, &body).map_err(|e| format!("write {}: {e}", dest.display()))?;
    }
    Ok(())
}

fn xterm_stub_for(name: &str) -> Vec<u8> {
    let mut v = XTERM_STUB_PREFIX.to_vec();
    v.extend_from_slice(format!("// asset: {name}\n").as_bytes());
    v
}

/// Use the system `curl` binary so we don't need an HTTP build-dep for the
/// daemon (which would compile even when LINPODX_VENDOR_XTERM is unset).
/// linpodx-webui's own build.rs uses `ureq` — between the two, operators
/// without `curl` can still get a vendored bundle by leaning on the webui
/// crate's standalone artifacts in its OUT_DIR.
fn xterm_download_with_curl(url: &str) -> Result<Vec<u8>, String> {
    let output = Command::new("curl")
        .arg("--silent")
        .arg("--show-error")
        .arg("--fail")
        .arg("--location")
        .arg("--max-time")
        .arg("60")
        .arg(url)
        .output()
        .map_err(|e| format!("`curl` not runnable: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "curl exited with {} — stderr: {}",
            output.status,
            stderr.trim()
        ));
    }
    if output.stdout.is_empty() {
        return Err("downloaded asset is empty".into());
    }
    Ok(output.stdout)
}

/// Run `cargo build` for the webui crate against `wasm32-unknown-unknown`, then
/// `wasm-bindgen` to emit the JS shim. Returns `(wasm_path, js_path)` pointing
/// inside `out_dir/wasm-bindgen-out/`.
fn try_build_wasm(out_dir: &Path) -> Result<(PathBuf, PathBuf), String> {
    let manifest_dir =
        PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set"));
    let webui_dir = manifest_dir
        .parent()
        .ok_or("daemon manifest has no parent")?
        .join("linpodx-webui");

    if !webui_dir.exists() {
        return Err(format!("webui crate not found at {}", webui_dir.display()));
    }

    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let target_dir = out_dir.join("wasm-target");
    let status = Command::new(&cargo)
        .args([
            "build",
            "-p",
            "linpodx-webui",
            "--release",
            "--target",
            "wasm32-unknown-unknown",
        ])
        .arg("--target-dir")
        .arg(&target_dir)
        .status()
        .map_err(|e| format!("cargo build invocation failed: {e}"))?;
    if !status.success() {
        return Err(format!("cargo build exited with {status}"));
    }

    let raw_wasm = target_dir
        .join("wasm32-unknown-unknown")
        .join("release")
        .join("linpodx_webui.wasm");
    if !raw_wasm.exists() {
        return Err(format!("expected {} after build", raw_wasm.display()));
    }

    let bindgen_out = out_dir.join("wasm-bindgen-out");
    std::fs::create_dir_all(&bindgen_out).map_err(|e| format!("mkdir bindgen out: {e}"))?;

    let status = Command::new("wasm-bindgen")
        .arg("--target")
        .arg("web")
        .arg("--no-typescript")
        .arg("--out-dir")
        .arg(&bindgen_out)
        .arg("--out-name")
        .arg("linpodx_webui")
        .arg(&raw_wasm)
        .status()
        .map_err(|e| format!("wasm-bindgen not runnable (install wasm-bindgen-cli): {e}"))?;
    if !status.success() {
        return Err(format!("wasm-bindgen exited with {status}"));
    }

    let wasm = bindgen_out.join("linpodx_webui_bg.wasm");
    let js = bindgen_out.join("linpodx_webui.js");
    if !wasm.exists() || !js.exists() {
        return Err(format!(
            "wasm-bindgen did not produce expected outputs in {}",
            bindgen_out.display()
        ));
    }
    Ok((wasm, js))
}
