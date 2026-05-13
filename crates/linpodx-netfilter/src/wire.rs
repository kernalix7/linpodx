//! JSON wire protocol between the daemon-side `EgressEnforcer` client and the
//! privileged `linpodx-netfilter-helper` binary.
//!
//! Framing: NDJSON (one JSON object per line) over a Unix stream socket. The client
//! writes a `HelperRequest`, the helper writes back exactly one `HelperResponse`, and
//! the connection is closed by the client.
//!
//! Tagged enums use `#[serde(tag = "op", rename_all = "snake_case")]` so the wire form
//! reads naturally — `{"op":"apply","container_pid":1234,"rules":[...]}` rather than
//! the default `{"Apply":{...}}` shape.

use linpodx_common::network::EgressRule;
use serde::{Deserialize, Serialize};

/// Commands the daemon may issue to the helper.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum HelperRequest {
    /// Replace the egress ruleset for a container's network namespace with `rules`.
    /// An empty `rules` list installs a deny-all table (drop policy on the output chain).
    Apply {
        container_pid: u32,
        rules: Vec<EgressRule>,
    },
    /// Remove the linpodx egress table from the container's network namespace.
    Clear { container_pid: u32 },
    /// Ask the helper to confirm it's alive and report its version. Used by the daemon
    /// to decide whether to invoke the helper at all (graceful degradation).
    Status,
    /// No-op liveness probe; helper replies with `Ok { applied: 0 }`.
    Ping,
}

/// Responses the helper may return.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum HelperResponse {
    /// Successful apply / clear. `applied` carries the rule count for `Apply`, the
    /// helper version (squashed to `usize`) for `Status`, or `0` otherwise.
    Ok {
        applied: usize,
    },
    Err {
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use linpodx_common::network::EgressProto;

    #[test]
    fn apply_round_trips() {
        let req = HelperRequest::Apply {
            container_pid: 4242,
            rules: vec![EgressRule {
                proto: EgressProto::Tcp,
                addr: "1.1.1.1".into(),
                port: Some(443),
                note: None,
            }],
        };
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains("\"op\":\"apply\""));
        assert!(s.contains("\"container_pid\":4242"));
        let back: HelperRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn clear_round_trips() {
        let req = HelperRequest::Clear { container_pid: 7 };
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains("\"op\":\"clear\""));
        let back: HelperRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn status_and_ping_round_trip() {
        for req in [HelperRequest::Status, HelperRequest::Ping] {
            let s = serde_json::to_string(&req).unwrap();
            let back: HelperRequest = serde_json::from_str(&s).unwrap();
            assert_eq!(req, back);
        }
    }

    #[test]
    fn ok_response_round_trips() {
        let resp = HelperResponse::Ok { applied: 12 };
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains("\"result\":\"ok\""));
        assert!(s.contains("\"applied\":12"));
        let back: HelperResponse = serde_json::from_str(&s).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn err_response_round_trips() {
        let resp = HelperResponse::Err {
            message: "nft refused".into(),
        };
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains("\"result\":\"err\""));
        let back: HelperResponse = serde_json::from_str(&s).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn unknown_op_rejected() {
        let bad = r#"{"op":"explode","container_pid":1}"#;
        let parsed: std::result::Result<HelperRequest, _> = serde_json::from_str(bad);
        assert!(parsed.is_err());
    }
}
