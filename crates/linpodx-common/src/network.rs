//! Cross-crate network egress rule definitions.
//!
//! Lives in `linpodx-common` so the sandbox profile schema, the runtime helper client,
//! and the privileged `linpodx-netfilter-helper` binary all speak the same vocabulary.

use serde::{Deserialize, Serialize};

/// One row in the L4 egress allowlist that the privileged netfilter helper enforces
/// inside the container's network namespace.
///
/// Matched on (proto, addr, port). When `port` is `None` the rule covers all ports for
/// the protocol. When `proto` is `Any` the rule covers tcp + udp + icmp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressRule {
    #[serde(default)]
    pub proto: EgressProto,
    /// IP literal, CIDR (e.g. `10.0.0.0/8`), or FQDN. Helper resolves FQDNs once at
    /// `Apply` time; later DNS changes are not picked up — the DNS-only filter sits
    /// upstream of this layer for that.
    pub addr: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressProto {
    #[default]
    Any,
    Tcp,
    Udp,
}

impl EgressProto {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_round_trips() {
        let rule = EgressRule {
            proto: EgressProto::Tcp,
            addr: "1.1.1.1/32".into(),
            port: Some(443),
            note: Some("dns over https".into()),
        };
        let s = serde_json::to_string(&rule).unwrap();
        let back: EgressRule = serde_json::from_str(&s).unwrap();
        assert_eq!(rule, back);
    }

    #[test]
    fn defaults_to_any_proto_no_port() {
        let s = r#"{"addr": "10.0.0.0/8"}"#;
        let parsed: EgressRule = serde_json::from_str(s).unwrap();
        assert_eq!(parsed.proto, EgressProto::Any);
        assert_eq!(parsed.port, None);
        assert_eq!(parsed.addr, "10.0.0.0/8");
    }

    #[test]
    fn proto_serializes_snake_case() {
        let s = serde_json::to_string(&EgressProto::Tcp).unwrap();
        assert_eq!(s, "\"tcp\"");
        let parsed: EgressProto = serde_json::from_str("\"any\"").unwrap();
        assert_eq!(parsed, EgressProto::Any);
    }
}
