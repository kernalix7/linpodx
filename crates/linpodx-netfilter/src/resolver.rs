//! One-shot DNS resolution for egress allowlist entries.
//!
//! `EgressRule.addr` may be:
//! * an IP literal (`"127.0.0.1"`, `"::1"`),
//! * an IPv4/IPv6 CIDR (`"10.0.0.0/8"`),
//! * an FQDN (`"api.openai.com"`).
//!
//! Literal and CIDR strings are returned verbatim so the nftables rule builder can
//! pass them through to `nft` (which accepts both single addrs and CIDR ranges).
//! FQDNs are resolved once via [`hickory_resolver::TokioAsyncResolver`] using the
//! system `/etc/resolv.conf`. The L4 filter is intentionally a snapshot; long-lived
//! DNS rotation is the upstream DNS-only filter's job (see
//! `linpodx-runtime::network_filter`).

use crate::{NetfilterError, Result};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use std::net::IpAddr;
use std::str::FromStr;

/// What `resolve_addr` produced for one input addr.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedAddr {
    /// `"10.0.0.0/8"` style — pass through to nft as-is.
    Cidr(String),
    /// One or more concrete IPs (a literal contributes a single entry; an FQDN may
    /// contribute several).
    Ips(Vec<IpAddr>),
}

impl ResolvedAddr {
    /// All addr-strings in the form `nft` accepts in `ip daddr` / `ip6 daddr` exprs.
    pub fn as_nft_strings(&self) -> Vec<String> {
        match self {
            Self::Cidr(s) => vec![s.clone()],
            Self::Ips(ips) => ips.iter().map(|ip| ip.to_string()).collect(),
        }
    }

    pub fn first_family(&self) -> AddrFamily {
        match self {
            Self::Cidr(s) => {
                if s.contains(':') {
                    AddrFamily::V6
                } else {
                    AddrFamily::V4
                }
            }
            Self::Ips(ips) => match ips.first() {
                Some(IpAddr::V6(_)) => AddrFamily::V6,
                _ => AddrFamily::V4,
            },
        }
    }
}

/// IP family hint so the rule builder can pick the right `ip` vs `ip6` keyword.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrFamily {
    V4,
    V6,
}

/// Resolve one allowlist addr. CIDR / literal returns immediately; FQDN goes through
/// the system resolver. Errors carry the original input so the caller can surface a
/// useful audit log line.
pub async fn resolve_addr(addr: &str) -> Result<ResolvedAddr> {
    let trimmed = addr.trim();
    if trimmed.is_empty() {
        return Err(NetfilterError::DnsResolution {
            addr: addr.to_string(),
            source: anyhow::anyhow!("empty addr"),
        });
    }
    if trimmed.contains('/') {
        // CIDR — pass through.
        return Ok(ResolvedAddr::Cidr(trimmed.to_string()));
    }
    if let Ok(ip) = IpAddr::from_str(trimmed) {
        return Ok(ResolvedAddr::Ips(vec![ip]));
    }
    // FQDN — DNS lookup.
    let resolver = system_resolver().map_err(|e| NetfilterError::DnsResolution {
        addr: addr.to_string(),
        source: anyhow::anyhow!("could not build resolver: {e}"),
    })?;
    let lookup = resolver
        .lookup_ip(trimmed)
        .await
        .map_err(|e| NetfilterError::DnsResolution {
            addr: addr.to_string(),
            source: anyhow::anyhow!(e),
        })?;
    let ips: Vec<IpAddr> = lookup.iter().collect();
    if ips.is_empty() {
        return Err(NetfilterError::DnsResolution {
            addr: addr.to_string(),
            source: anyhow::anyhow!("no A/AAAA records returned"),
        });
    }
    Ok(ResolvedAddr::Ips(ips))
}

fn system_resolver(
) -> std::result::Result<TokioAsyncResolver, hickory_resolver::error::ResolveError> {
    match TokioAsyncResolver::tokio_from_system_conf() {
        Ok(r) => Ok(r),
        Err(_) => Ok(TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ipv4_literal_returns_single_ip() {
        let r = resolve_addr("127.0.0.1").await.unwrap();
        assert_eq!(r, ResolvedAddr::Ips(vec!["127.0.0.1".parse().unwrap()]));
        assert_eq!(r.as_nft_strings(), vec!["127.0.0.1".to_string()]);
        assert_eq!(r.first_family(), AddrFamily::V4);
    }

    #[tokio::test]
    async fn ipv6_literal_returns_single_ip() {
        let r = resolve_addr("::1").await.unwrap();
        assert_eq!(r, ResolvedAddr::Ips(vec!["::1".parse().unwrap()]));
        assert_eq!(r.first_family(), AddrFamily::V6);
    }

    #[tokio::test]
    async fn cidr_passes_through() {
        let r = resolve_addr("10.0.0.0/8").await.unwrap();
        assert_eq!(r, ResolvedAddr::Cidr("10.0.0.0/8".to_string()));
        assert_eq!(r.as_nft_strings(), vec!["10.0.0.0/8".to_string()]);
    }

    #[tokio::test]
    async fn ipv6_cidr_family() {
        let r = resolve_addr("fe80::/10").await.unwrap();
        assert_eq!(r.first_family(), AddrFamily::V6);
    }

    #[tokio::test]
    async fn empty_addr_rejected() {
        assert!(resolve_addr("   ").await.is_err());
    }

    #[tokio::test]
    #[ignore = "requires working DNS"]
    async fn fqdn_resolves() {
        // `localhost` is the only FQDN we can rely on across all CI envs, but even that
        // depends on /etc/hosts. Marked #[ignore] so CI without resolv.conf doesn't
        // break.
        let r = resolve_addr("localhost").await.unwrap();
        if let ResolvedAddr::Ips(ips) = r {
            assert!(!ips.is_empty());
        } else {
            panic!("expected Ips");
        }
    }
}
