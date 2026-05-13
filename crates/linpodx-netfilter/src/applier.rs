//! nftables ruleset builder + namespace-aware `nft` invoker.
//!
//! The builder emits a stable, line-by-line ruleset string so unit tests can pin
//! exact output. The resulting string is fed to `nft -f -` inside the container's
//! network namespace via `nsenter -t <pid> -n`, which is invoked by the privileged
//! helper.
//!
//! Table layout (single inet table, two chains):
//! * `table inet linpodx_egress`
//!   * `chain output { type filter hook output priority 0; policy drop; ... accept; }`
//!   * `chain forward { type filter hook forward priority 0; policy drop; }` (defence-in-depth)
//!
//! An empty allowlist still installs the table — output policy `drop` then blocks
//! everything except established / loopback (which we explicitly accept).

use crate::resolver::{AddrFamily, ResolvedAddr};
use crate::{NetfilterError, Result};
use linpodx_common::network::{EgressProto, EgressRule};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/// Table name reserved for linpodx-managed egress rules. Stable so `Clear` can find
/// and drop it without consulting any state.
pub const TABLE_NAME: &str = "linpodx_egress";

/// One fully-resolved allow row ready to be rendered into nft syntax.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRule {
    pub proto: EgressProto,
    pub addr: ResolvedAddr,
    pub port: Option<u16>,
}

impl ResolvedRule {
    pub fn from_parts(rule: &EgressRule, addr: ResolvedAddr) -> Self {
        Self {
            proto: rule.proto,
            addr,
            port: rule.port,
        }
    }
}

/// Build the full `nft -f -` script for the supplied resolved allowlist. Output is
/// deterministic: rules are emitted in input order, and each rule emits one accept
/// line per concrete IP/CIDR it resolved to. Used by both the privileged helper and
/// the unit tests.
pub fn build_ruleset(rules: &[ResolvedRule]) -> String {
    let mut out = String::new();
    // Always start by removing any prior table so `nft -f -` is idempotent.
    out.push_str(&format!("table inet {TABLE_NAME} {{}}\n"));
    out.push_str(&format!("delete table inet {TABLE_NAME}\n"));
    out.push_str(&format!("table inet {TABLE_NAME} {{\n"));
    out.push_str("\tchain output {\n");
    out.push_str("\t\ttype filter hook output priority 0; policy drop;\n");
    // Always-on plumbing: loopback + already-established connections.
    out.push_str("\t\tmeta oif \"lo\" accept\n");
    out.push_str("\t\tct state established,related accept\n");
    for rule in rules {
        for line in render_rule_lines(rule) {
            out.push_str("\t\t");
            out.push_str(&line);
            out.push('\n');
        }
    }
    out.push_str("\t}\n");
    // Defense-in-depth: deny forward by default (containers shouldn't be routers).
    out.push_str("\tchain forward {\n");
    out.push_str("\t\ttype filter hook forward priority 0; policy drop;\n");
    out.push_str("\t}\n");
    out.push_str("}\n");
    out
}

fn render_rule_lines(rule: &ResolvedRule) -> Vec<String> {
    let family = rule.addr.first_family();
    let daddr_keyword = match family {
        AddrFamily::V4 => "ip daddr",
        AddrFamily::V6 => "ip6 daddr",
    };
    let mut lines = Vec::new();
    for addr in rule.addr.as_nft_strings() {
        match (rule.proto, rule.port) {
            (EgressProto::Any, None) => {
                lines.push(format!("{daddr_keyword} {addr} accept"));
            }
            (EgressProto::Any, Some(port)) => {
                lines.push(format!("{daddr_keyword} {addr} tcp dport {port} accept"));
                lines.push(format!("{daddr_keyword} {addr} udp dport {port} accept"));
            }
            (EgressProto::Tcp, None) => {
                lines.push(format!("{daddr_keyword} {addr} tcp accept"));
            }
            (EgressProto::Tcp, Some(port)) => {
                lines.push(format!("{daddr_keyword} {addr} tcp dport {port} accept"));
            }
            (EgressProto::Udp, None) => {
                lines.push(format!("{daddr_keyword} {addr} udp accept"));
            }
            (EgressProto::Udp, Some(port)) => {
                lines.push(format!("{daddr_keyword} {addr} udp dport {port} accept"));
            }
        }
    }
    lines
}

/// Apply `ruleset` inside the network namespace identified by `pid` using
/// `nsenter -t <pid> -n nft -f -`. Returns the stderr-encoded `nft` failure verbatim
/// when nft exits non-zero.
pub async fn apply_in_namespace(pid: u32, ruleset: &str) -> Result<()> {
    let mut child = Command::new("nsenter")
        .arg("-t")
        .arg(pid.to_string())
        .arg("-n")
        .arg("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| NetfilterError::NftInvocation(format!("spawn nsenter/nft: {e}")))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(ruleset.as_bytes())
            .await
            .map_err(|e| NetfilterError::NftInvocation(format!("write ruleset: {e}")))?;
        stdin.shutdown().await.ok();
    }
    let out = child
        .wait_with_output()
        .await
        .map_err(|e| NetfilterError::NftInvocation(format!("wait nsenter/nft: {e}")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        return Err(NetfilterError::NftInvocation(format!(
            "nft exited with status {}: {}",
            out.status, stderr
        )));
    }
    Ok(())
}

/// Drop the linpodx egress table from the container's network namespace. Idempotent —
/// missing table is treated as success (nft prints to stderr, we tolerate it).
pub async fn clear_in_namespace(pid: u32) -> Result<()> {
    // Use a script that defines + deletes so absence isn't fatal.
    let script = format!("table inet {TABLE_NAME} {{}}\ndelete table inet {TABLE_NAME}\n");
    apply_in_namespace(pid, &script).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn empty_ruleset_still_emits_table_with_drop_policy() {
        let s = build_ruleset(&[]);
        assert!(s.contains("table inet linpodx_egress"));
        assert!(s.contains("policy drop"));
        assert!(s.contains("ct state established,related accept"));
        assert!(s.contains("meta oif \"lo\" accept"));
        // No accept lines beyond the always-on plumbing.
        let accept_count = s.matches(" accept").count();
        assert_eq!(accept_count, 2, "only loopback + established expected");
    }

    #[test]
    fn tcp_with_port_emits_single_line() {
        let r = ResolvedRule {
            proto: EgressProto::Tcp,
            addr: ResolvedAddr::Ips(vec![ip("1.1.1.1")]),
            port: Some(443),
        };
        let s = build_ruleset(&[r]);
        assert!(s.contains("ip daddr 1.1.1.1 tcp dport 443 accept"));
    }

    #[test]
    fn udp_no_port_emits_proto_clause() {
        let r = ResolvedRule {
            proto: EgressProto::Udp,
            addr: ResolvedAddr::Ips(vec![ip("8.8.8.8")]),
            port: None,
        };
        let s = build_ruleset(&[r]);
        assert!(s.contains("ip daddr 8.8.8.8 udp accept"));
    }

    #[test]
    fn any_proto_with_cidr_emits_one_line_no_proto() {
        let r = ResolvedRule {
            proto: EgressProto::Any,
            addr: ResolvedAddr::Cidr("10.0.0.0/8".into()),
            port: None,
        };
        let s = build_ruleset(&[r]);
        assert!(s.contains("ip daddr 10.0.0.0/8 accept"));
    }

    #[test]
    fn any_proto_with_port_emits_tcp_and_udp_lines() {
        let r = ResolvedRule {
            proto: EgressProto::Any,
            addr: ResolvedAddr::Ips(vec![ip("9.9.9.9")]),
            port: Some(53),
        };
        let s = build_ruleset(&[r]);
        assert!(s.contains("ip daddr 9.9.9.9 tcp dport 53 accept"));
        assert!(s.contains("ip daddr 9.9.9.9 udp dport 53 accept"));
    }

    #[test]
    fn ipv6_address_uses_ip6_keyword() {
        let r = ResolvedRule {
            proto: EgressProto::Tcp,
            addr: ResolvedAddr::Ips(vec![ip("2606:4700:4700::1111")]),
            port: Some(443),
        };
        let s = build_ruleset(&[r]);
        assert!(s.contains("ip6 daddr 2606:4700:4700::1111 tcp dport 443 accept"));
    }

    #[test]
    fn fqdn_with_multiple_ips_emits_one_accept_per_ip() {
        let r = ResolvedRule {
            proto: EgressProto::Tcp,
            addr: ResolvedAddr::Ips(vec![ip("1.1.1.1"), ip("1.0.0.1")]),
            port: Some(443),
        };
        let s = build_ruleset(&[r]);
        assert!(s.contains("ip daddr 1.1.1.1 tcp dport 443 accept"));
        assert!(s.contains("ip daddr 1.0.0.1 tcp dport 443 accept"));
    }

    #[test]
    fn ruleset_starts_with_idempotent_delete() {
        let s = build_ruleset(&[]);
        let header_end = s
            .find("table inet linpodx_egress {\n\tchain output")
            .unwrap();
        let header = &s[..header_end];
        assert!(header.contains("delete table inet linpodx_egress"));
    }

    #[test]
    fn forward_chain_drop_policy_present() {
        let s = build_ruleset(&[]);
        assert!(s.contains("chain forward"));
        // Two `policy drop` lines: output + forward.
        assert_eq!(s.matches("policy drop;").count(), 2);
    }

    #[test]
    fn rules_render_in_input_order() {
        let r1 = ResolvedRule {
            proto: EgressProto::Tcp,
            addr: ResolvedAddr::Ips(vec![ip("1.1.1.1")]),
            port: Some(80),
        };
        let r2 = ResolvedRule {
            proto: EgressProto::Tcp,
            addr: ResolvedAddr::Ips(vec![ip("2.2.2.2")]),
            port: Some(443),
        };
        let s = build_ruleset(&[r1, r2]);
        let p1 = s.find("1.1.1.1").unwrap();
        let p2 = s.find("2.2.2.2").unwrap();
        assert!(p1 < p2);
    }
}
