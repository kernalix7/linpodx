//! linpodx-netfilter — privileged L4 egress firewall helper + daemon-side client.
//!
//! Phase 5 Stage 2-A. The crate ships:
//! * the `linpodx-netfilter-helper` binary (root-or-`CAP_NET_ADMIN` Unix-socket
//!   listener that runs `nsenter -t <pid> -n nft -f -`),
//! * the wire protocol that the daemon-side `EgressEnforcer` (in `linpodx-runtime`)
//!   uses to talk to it,
//! * the nftables ruleset builder + DNS resolver shared between both sides.
//!
//! The crate is `#![forbid(unsafe_code)]`; peer-credential checks rely on the safe
//! `std::os::unix::net::UnixStream::peer_cred` helper.

#![forbid(unsafe_code)]

pub mod applier;
pub mod resolver;
pub mod wire;

use thiserror::Error;

/// Default Unix socket path the helper listens on. Override with `--socket` (helper) or
/// `LINPODX_NETFILTER_SOCKET` (client) so test/CI can use a tempdir.
pub const DEFAULT_SOCKET_PATH: &str = "/run/linpodx/netfilter.sock";

/// Environment variable consulted by `EgressEnforcer::default()` and (for symmetry) the
/// helper's `--socket` flag default.
pub const SOCKET_ENV_VAR: &str = "LINPODX_NETFILTER_SOCKET";

/// Wire / helper protocol revision. Embedded in `Status` responses so the client can
/// refuse to talk to an older helper after a future schema bump.
pub const HELPER_PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum NetfilterError {
    #[error("not yet implemented (Stage 2-A): {0}")]
    NotImplemented(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("helper unavailable: {0}")]
    HelperUnavailable(String),
    #[error("permission denied: helper rejected peer (uid {uid})")]
    PermissionDenied { uid: u32 },
    #[error("nft invocation failed: {0}")]
    NftInvocation(String),
    #[error("namespace error: {0}")]
    Namespace(String),
    #[error("dns resolution failed for {addr}: {source}")]
    DnsResolution { addr: String, source: anyhow::Error },
    #[error("helper returned error: {0}")]
    HelperRejected(String),
    #[error("malformed helper response: {0}")]
    MalformedResponse(String),
}

pub type Result<T> = std::result::Result<T, NetfilterError>;
