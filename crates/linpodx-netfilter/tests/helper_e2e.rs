//! End-to-end smoke test for `linpodx-netfilter-helper`.
//!
//! Spawns the real helper binary against a tempdir Unix socket, drives an `Apply`
//! followed by a `Clear` round-trip, and asserts the helper acknowledges both. The
//! test is gated behind `LINPODX_TEST_NETFILTER_ROOT=1` and `#[ignore]` because the
//! helper enters its own network namespace via `nsenter` and runs `nft`, both of
//! which require real privileges (root or `CAP_NET_ADMIN` + `CAP_SYS_ADMIN`).
//!
//! Run with:
//! ```text
//! sudo LINPODX_TEST_NETFILTER_ROOT=1 \
//!     cargo test -p linpodx-netfilter --test helper_e2e -- --ignored --test-threads=1
//! ```

#![forbid(unsafe_code)]

use linpodx_netfilter::wire::{HelperRequest, HelperResponse};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Resolve the path to the helper binary built by `cargo test` for this crate.
/// `CARGO_BIN_EXE_<name>` is provided automatically when the bin is part of the same
/// package as the integration test.
fn helper_bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_linpodx-netfilter-helper"))
}

/// Wait until `socket` becomes connectable or the timeout elapses.
async fn wait_for_socket(socket: &std::path::Path) -> bool {
    let deadline = Instant::now() + PROBE_TIMEOUT;
    while Instant::now() < deadline {
        if UnixStream::connect(socket).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// One-shot request/response over a fresh Unix connection. Mirrors the framing used by
/// `EgressEnforcer` in the runtime crate so we don't need to import it here.
async fn round_trip(socket: &std::path::Path, req: HelperRequest) -> HelperResponse {
    let stream = UnixStream::connect(socket).await.expect("connect helper");
    let (read_half, mut write_half) = stream.into_split();
    let mut payload = serde_json::to_vec(&req).expect("encode request");
    payload.push(b'\n');
    write_half.write_all(&payload).await.expect("write request");
    write_half.shutdown().await.ok();
    let mut lines = BufReader::new(read_half).lines();
    let line = lines
        .next_line()
        .await
        .expect("read response")
        .expect("non-empty response");
    serde_json::from_str(&line).expect("decode response")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires LINPODX_TEST_NETFILTER_ROOT=1 and root/CAP_NET_ADMIN privileges"]
async fn helper_apply_clear_round_trip() {
    if std::env::var("LINPODX_TEST_NETFILTER_ROOT").ok().as_deref() != Some("1") {
        // Sentinel for local runs: opt in explicitly so an accidental `--ignored` sweep
        // doesn't try to bind a privileged socket.
        eprintln!(
            "skipping helper_apply_clear_round_trip: LINPODX_TEST_NETFILTER_ROOT!=1 (current: {:?})",
            std::env::var("LINPODX_TEST_NETFILTER_ROOT").ok()
        );
        return;
    }

    let scratch = tempfile::tempdir().expect("scratch tempdir");
    let socket = scratch.path().join("helper.sock");
    let uid = std::fs::metadata("/proc/self")
        .ok()
        .map(|m| {
            use std::os::unix::fs::MetadataExt;
            m.uid()
        })
        .unwrap_or(0);

    let mut child = Command::new(helper_bin_path())
        .arg("--socket")
        .arg(&socket)
        .arg("--daemon-uid")
        .arg(uid.to_string())
        .arg("--log-level")
        .arg("warn")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn helper");

    let socket_ready = wait_for_socket(&socket).await;
    let cleanup = scopeguard_kill(&mut child);

    assert!(socket_ready, "helper socket never became ready");

    // Sanity ping first so a wedged binary fails before we touch nftables.
    let ping = round_trip(&socket, HelperRequest::Ping).await;
    assert!(matches!(ping, HelperResponse::Ok { .. }), "ping ok");

    // Apply with an empty rule list — the helper installs a deny-all linpodx_egress
    // table inside our own netns (we pass our own pid). The nftables side-effect is
    // best-effort; what we assert here is the wire-level Ok response.
    let our_pid = std::process::id();
    let apply = round_trip(
        &socket,
        HelperRequest::Apply {
            container_pid: our_pid,
            rules: Vec::new(),
        },
    )
    .await;
    match &apply {
        HelperResponse::Ok { .. } => {}
        HelperResponse::Err { message } => {
            panic!("apply failed (running as root? CAP_NET_ADMIN?): {message}");
        }
    }

    // `nft list table inet linpodx_egress` should now succeed; capture stderr too so
    // the failure message is useful when the nftables backend is missing.
    let nft = Command::new("nft")
        .args(["list", "table", "inet", "linpodx_egress"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();
    if let Ok(out) = nft {
        assert!(
            out.status.success(),
            "nft list after apply failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let clear = round_trip(
        &socket,
        HelperRequest::Clear {
            container_pid: our_pid,
        },
    )
    .await;
    assert!(matches!(clear, HelperResponse::Ok { .. }), "clear ok");

    drop(cleanup);
}

/// Tiny scope-guard wrapper so the helper child is always killed on test exit, even
/// when an assertion panics partway through.
fn scopeguard_kill(child: &mut std::process::Child) -> ChildKiller<'_> {
    ChildKiller(child)
}

struct ChildKiller<'a>(&'a mut std::process::Child);

impl Drop for ChildKiller<'_> {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
