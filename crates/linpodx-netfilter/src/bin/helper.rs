//! linpodx-netfilter-helper — privileged L4 egress firewall helper.
//!
//! Listens on a Unix socket (default `/run/linpodx/netfilter.sock`), accepts NDJSON
//! `HelperRequest` messages from the daemon, and applies nftables rules inside the
//! target container's network namespace via `nsenter -t <pid> -n nft -f -`.
//!
//! Auth: socket file is created with mode 0600 owned by `--daemon-uid`, and each
//! incoming connection's `peer_cred().uid()` is checked against the same value.
//! Defence-in-depth — either gate alone would be sufficient, but pinning both keeps
//! us safe across future filesystem-permission slips and accidental setuid scenarios.
//!
//! Run as root or with `setcap cap_net_admin,cap_sys_admin+ep` (the latter for
//! `nsenter` to enter another netns).

#![forbid(unsafe_code)]

use clap::Parser;
use linpodx_netfilter::applier;
use linpodx_netfilter::resolver::{resolve_addr, ResolvedAddr};
use linpodx_netfilter::wire::{HelperRequest, HelperResponse};
use linpodx_netfilter::{
    NetfilterError, Result as NetResult, DEFAULT_SOCKET_PATH, HELPER_PROTOCOL_VERSION,
    SOCKET_ENV_VAR,
};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, error, info, warn};

#[derive(Debug, Parser)]
#[command(
    name = "linpodx-netfilter-helper",
    version,
    about = "linpodx privileged L4 egress firewall helper"
)]
struct Args {
    /// Unix socket path. Created (with mode 0600) and removed on exit.
    #[arg(long, env = SOCKET_ENV_VAR, default_value = DEFAULT_SOCKET_PATH)]
    socket: PathBuf,

    /// Allowed peer UID. Connections with `peer_cred().uid()` other than this value are
    /// closed immediately. Defaults to the helper process's own UID — sufficient for
    /// dev/test where helper + daemon run as the same user.
    #[arg(long)]
    daemon_uid: Option<u32>,

    /// `tracing` env-filter, e.g. `info`, `debug`, `linpodx_netfilter=trace`.
    #[arg(long, default_value = "info")]
    log_level: String,
}

fn main() {
    let args = Args::parse();
    init_tracing(&args.log_level);
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("failed to start tokio runtime: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = runtime.block_on(run(args)) {
        error!(error = %e, "helper exited with error");
        std::process::exit(1);
    }
}

fn init_tracing(filter: &str) {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};
    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(filter))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().with_target(true).with_level(true))
        .init();
}

async fn run(args: Args) -> NetResult<()> {
    let allowed_uid = args.daemon_uid.unwrap_or_else(current_uid);
    let listener = bind_socket(&args.socket).await?;
    info!(
        socket = %args.socket.display(),
        allowed_uid,
        version = HELPER_PROTOCOL_VERSION,
        "linpodx-netfilter-helper listening"
    );

    // Best-effort socket cleanup on Ctrl-C.
    let socket_path = Arc::new(args.socket.clone());
    let cleanup_path = Arc::clone(&socket_path);
    let shutdown = tokio::signal::ctrl_c();

    tokio::select! {
        res = accept_loop(listener, allowed_uid) => {
            res?;
        }
        _ = shutdown => {
            info!("shutdown signal received");
        }
    }

    if let Err(e) = std::fs::remove_file(cleanup_path.as_path()) {
        if e.kind() != std::io::ErrorKind::NotFound {
            warn!(error = %e, "could not remove socket on shutdown");
        }
    }
    Ok(())
}

fn current_uid() -> u32 {
    // `std::os::unix::fs::MetadataExt` exposes uid; we synthesise it from `/proc/self`
    // to keep the crate `forbid(unsafe_code)` (libc::getuid would be unsafe).
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self")
        .map(|m| m.uid())
        .unwrap_or(0)
}

async fn bind_socket(path: &std::path::Path) -> NetResult<UnixListener> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                NetfilterError::Io(std::io::Error::new(
                    e.kind(),
                    format!("create_dir_all {}: {e}", parent.display()),
                ))
            })?;
        }
    }
    // Remove a stale socket from a prior run before binding.
    match tokio::fs::remove_file(path).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            warn!(error = %e, path = %path.display(), "stale socket removal failed (continuing)")
        }
    }
    let listener = UnixListener::bind(path)?;
    // Tighten file mode to 0600 so only the owning UID can connect.
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms).map_err(|e| {
        NetfilterError::Io(std::io::Error::new(
            e.kind(),
            format!("chmod 0600 {}: {e}", path.display()),
        ))
    })?;
    Ok(listener)
}

async fn accept_loop(listener: UnixListener, allowed_uid: u32) -> NetResult<()> {
    loop {
        let (stream, _addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!(error = %e, "accept failed; continuing");
                continue;
            }
        };
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, allowed_uid).await {
                warn!(error = %e, "connection handler error");
            }
        });
    }
}

async fn handle_connection(stream: UnixStream, allowed_uid: u32) -> NetResult<()> {
    // Peer-cred check via SO_PEERCRED (tokio's safe wrapper). Defence-in-depth on top of
    // the socket-file 0600 mode set in `bind_socket`.
    let cred = stream.peer_cred().map_err(NetfilterError::Io)?;
    let peer_uid = cred.uid();
    if peer_uid != allowed_uid {
        warn!(peer_uid, allowed_uid, "rejecting peer with mismatched uid");
        return Err(NetfilterError::PermissionDenied { uid: peer_uid });
    }
    debug!(peer_uid, "peer accepted");

    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<HelperRequest>(&line) {
            Ok(req) => dispatch(req).await,
            Err(e) => HelperResponse::Err {
                message: format!("malformed request: {e}"),
            },
        };
        let mut payload = serde_json::to_vec(&response)?;
        payload.push(b'\n');
        write_half.write_all(&payload).await?;
    }
    Ok(())
}

async fn dispatch(req: HelperRequest) -> HelperResponse {
    match req {
        HelperRequest::Ping => HelperResponse::Ok { applied: 0 },
        HelperRequest::Status => HelperResponse::Ok {
            applied: HELPER_PROTOCOL_VERSION as usize,
        },
        HelperRequest::Clear { container_pid } => {
            match applier::clear_in_namespace(container_pid).await {
                Ok(()) => HelperResponse::Ok { applied: 0 },
                Err(e) => HelperResponse::Err {
                    message: format!("clear failed: {e}"),
                },
            }
        }
        HelperRequest::Apply {
            container_pid,
            rules,
        } => match apply(container_pid, rules).await {
            Ok(applied) => HelperResponse::Ok { applied },
            Err(e) => HelperResponse::Err {
                message: format!("apply failed: {e}"),
            },
        },
    }
}

/// Resolve every rule's address, warning (with the full rule + error) and counting any
/// that fail so a caller can surface the drop instead of it vanishing silently. Split
/// out from [`apply`] so the resolution/skip-accounting logic is unit-testable without
/// requiring the privileged `nsenter`/`nft` side effects of `apply_in_namespace`.
async fn resolve_rules(
    container_pid: u32,
    rules: &[linpodx_common::network::EgressRule],
) -> (Vec<applier::ResolvedRule>, usize) {
    let mut resolved = Vec::with_capacity(rules.len());
    let mut skipped = 0usize;
    for rule in rules {
        let addr = match resolve_addr(&rule.addr).await {
            Ok(addr) => addr,
            Err(e) => {
                // Default-drop means a rule that silently fails to resolve narrows
                // connectivity without a trace — always warn with the full rule so an
                // operator can find it in the logs, and roll it into the summary below.
                warn!(
                    container_pid,
                    addr = %rule.addr,
                    proto = ?rule.proto,
                    port = ?rule.port,
                    note = ?rule.note,
                    error = %e,
                    "skipping egress rule: address resolution failed"
                );
                skipped += 1;
                continue;
            }
        };
        // Defensive: resolve_addr's FQDN path returns Err on an empty answer, so this
        // should be unreachable in practice, but guard it the same way in case that
        // contract ever changes upstream.
        if let ResolvedAddr::Ips(ips) = &addr {
            if ips.is_empty() {
                warn!(
                    container_pid,
                    addr = %rule.addr,
                    proto = ?rule.proto,
                    port = ?rule.port,
                    note = ?rule.note,
                    "skipping egress rule: resolved to zero addresses"
                );
                skipped += 1;
                continue;
            }
        }
        resolved.push(applier::ResolvedRule::from_parts(rule, addr));
    }
    (resolved, skipped)
}

async fn apply(
    container_pid: u32,
    rules: Vec<linpodx_common::network::EgressRule>,
) -> NetResult<usize> {
    let requested = rules.len();
    let (resolved, skipped) = resolve_rules(container_pid, &rules).await;
    if skipped > 0 {
        warn!(
            container_pid,
            requested,
            applied = resolved.len(),
            skipped,
            "egress ruleset apply completed with skipped rules (see per-rule warnings above)"
        );
    }
    let ruleset = applier::build_ruleset(&resolved);
    applier::apply_in_namespace(container_pid, &ruleset).await?;
    Ok(resolved.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    #[tokio::test]
    async fn bind_socket_sets_mode_0600() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("nf.sock");
        let _listener = bind_socket(&sock).await.expect("bind");
        let mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "socket must be 0600 (got {mode:o})");
    }

    #[tokio::test]
    async fn bind_socket_replaces_stale_file() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("nf.sock");
        std::fs::write(&sock, b"stale").unwrap();
        let _listener = bind_socket(&sock).await.expect("rebind");
        // Should now be a socket (we can't easily check FileType::is_socket on stable
        // without unsafe; at minimum the bind succeeded and mode is 0600).
        let mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[tokio::test]
    async fn dispatch_ping_returns_ok_zero() {
        let resp = dispatch(HelperRequest::Ping).await;
        assert_eq!(resp, HelperResponse::Ok { applied: 0 });
    }

    #[tokio::test]
    async fn dispatch_status_returns_protocol_version() {
        let resp = dispatch(HelperRequest::Status).await;
        assert_eq!(
            resp,
            HelperResponse::Ok {
                applied: HELPER_PROTOCOL_VERSION as usize
            }
        );
    }

    #[tokio::test]
    async fn resolve_rules_counts_and_skips_unresolvable_addrs() {
        // Deliberately avoids real DNS (flaky in CI): an empty/whitespace `addr` fails
        // resolution synchronously inside `resolve_addr`, so this is deterministic.
        use linpodx_common::network::EgressRule;
        let rules = vec![
            EgressRule {
                proto: Default::default(),
                addr: "127.0.0.1".into(),
                port: None,
                note: None,
            },
            EgressRule {
                proto: Default::default(),
                addr: "   ".into(),
                port: None,
                note: Some("broken-rule".into()),
            },
        ];
        let (resolved, skipped) = resolve_rules(999, &rules).await;
        assert_eq!(resolved.len(), 1, "only the resolvable rule should survive");
        assert_eq!(
            skipped, 1,
            "the unresolvable rule must be counted, not dropped silently"
        );
    }

    #[tokio::test]
    async fn resolve_rules_all_resolvable_reports_zero_skipped() {
        use linpodx_common::network::EgressRule;
        let rules = vec![EgressRule {
            proto: Default::default(),
            addr: "10.0.0.0/8".into(),
            port: None,
            note: None,
        }];
        let (resolved, skipped) = resolve_rules(1, &rules).await;
        assert_eq!(resolved.len(), 1);
        assert_eq!(skipped, 0);
    }

    #[tokio::test]
    async fn malformed_request_yields_err_response() {
        // Roundtrip a malformed line through the same path as handle_connection.
        let response = match serde_json::from_str::<HelperRequest>("{not json") {
            Ok(req) => dispatch(req).await,
            Err(e) => HelperResponse::Err {
                message: format!("malformed request: {e}"),
            },
        };
        match response {
            HelperResponse::Err { message } => assert!(message.contains("malformed request")),
            _ => panic!("expected Err response"),
        }
    }
}
