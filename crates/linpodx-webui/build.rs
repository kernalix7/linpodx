//! Phase 14 — vendor xterm.js + addon-fit so the Web UI works air-gapped.
//!
//! Behavior:
//!
//! * Default (`LINPODX_VENDOR_XTERM` unset): write a tiny "// stub" placeholder
//!   for each of the three xterm assets to `OUT_DIR`, so the daemon's
//!   `include_bytes!` calls (in `web_ui.rs`) always have a target. The leptos
//!   `index.html` ships with jsDelivr `<script>` URLs — the stubs are present
//!   for the build pipeline only, never served.
//!
//! * `LINPODX_VENDOR_XTERM=1`: download the three pinned files from jsDelivr
//!   into `OUT_DIR` so the daemon can embed them and serve them locally at
//!   `/ui/assets/xterm.{js,css}` and `/ui/assets/addon-fit.js`. The daemon's
//!   `build.rs` reads the same env var and emits `cfg=linpodx_xterm_vendored`,
//!   which switches `index.html` to point at the local paths.
//!
//! Pinned versions match the jsDelivr URLs in `index.html`:
//!   - `@xterm/xterm@5/lib/xterm.js`
//!   - `@xterm/xterm@5/css/xterm.css`
//!   - `@xterm/addon-fit@0.10/lib/addon-fit.js`
//!
//! Failure mode: if `LINPODX_VENDOR_XTERM=1` and any download fails, the build
//! fails loudly. Operators opting into vendoring need a working network or a
//! local mirror; silently falling back to a stub would defeat the purpose.

use std::path::PathBuf;

const STUB_PREFIX: &[u8] =
    b"// stub: linpodx-webui xterm asset was not vendored (set LINPODX_VENDOR_XTERM=1)\n";

const XTERM_JS_URL: &str = "https://cdn.jsdelivr.net/npm/@xterm/xterm@5/lib/xterm.js";
const XTERM_CSS_URL: &str = "https://cdn.jsdelivr.net/npm/@xterm/xterm@5/css/xterm.css";
const ADDON_FIT_JS_URL: &str =
    "https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.10/lib/addon-fit.js";

const ASSETS: &[(&str, &str)] = &[
    ("xterm.js", XTERM_JS_URL),
    ("xterm.css", XTERM_CSS_URL),
    ("addon-fit.js", ADDON_FIT_JS_URL),
];

fn main() {
    println!("cargo:rerun-if-env-changed=LINPODX_VENDOR_XTERM");
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR set by cargo"));

    let want_vendor = std::env::var_os("LINPODX_VENDOR_XTERM").is_some();

    if want_vendor {
        for (name, url) in ASSETS {
            let dest = out_dir.join(name);
            if let Err(e) = download_to(url, &dest) {
                panic!(
                    "LINPODX_VENDOR_XTERM=1 but failed to download {name} from {url}: {e}\n\
                     hint: ensure the build host has outbound HTTPS to cdn.jsdelivr.net, \
                     or unset LINPODX_VENDOR_XTERM to ship the CDN-loaded fallback."
                );
            }
        }
    } else {
        // Stub mode — write placeholder bytes so include_bytes! succeeds. The
        // daemon never serves these; index.html keeps its jsDelivr <script> tags.
        for (name, _) in ASSETS {
            let dest = out_dir.join(name);
            let body = make_stub(name);
            std::fs::write(&dest, body)
                .unwrap_or_else(|e| panic!("failed to write stub asset {}: {e}", dest.display()));
        }
    }
}

fn make_stub(name: &str) -> Vec<u8> {
    let mut v = STUB_PREFIX.to_vec();
    v.extend_from_slice(format!("// asset: {name}\n").as_bytes());
    v
}

fn download_to(url: &str, dest: &std::path::Path) -> Result<(), String> {
    let resp = ureq::get(url)
        .call()
        .map_err(|e| format!("HTTP request failed: {e}"))?;
    let mut reader = resp.into_reader();
    let mut body = Vec::new();
    std::io::Read::read_to_end(&mut reader, &mut body)
        .map_err(|e| format!("read response body: {e}"))?;
    if body.is_empty() {
        return Err("downloaded asset is empty".into());
    }
    std::fs::write(dest, &body).map_err(|e| format!("write {}: {e}", dest.display()))?;
    Ok(())
}
