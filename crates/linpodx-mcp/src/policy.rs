//! Per-method MCP policy evaluation.
//!
//! The bridge consults the policy engine for every parsed message. Rules live in the
//! `mcp_policies` SQLite table and are mirrored into a process-local `Vec` (refreshed by
//! `mcp_policy_set`). Matching prefers the more specific rule:
//!
//! 1. For `tools/call` with a tool name, look for a rule with `(method, Some(tool))`.
//! 2. Fall back to `(method, None)`.
//! 3. If still no match, return [`McpPolicyDecision::AuditOnly`].

use crate::protocol::{McpMessage, METHOD_TOOLS_CALL};
use linpodx_common::ipc::{McpPolicyDecision, McpPolicyRule};

pub struct PolicyEngine;

impl PolicyEngine {
    /// Run the matching algorithm described in the module docs.
    pub fn evaluate(rules: &[McpPolicyRule], msg: &McpMessage) -> McpPolicyDecision {
        let method = msg.method_str();

        if method == METHOD_TOOLS_CALL {
            if let Some(tool) = msg.tool_name() {
                if let Some(r) = rules
                    .iter()
                    .find(|r| r.method == method && r.tool_name.as_deref() == Some(tool))
                {
                    return r.decision;
                }
            }
        }

        if let Some(r) = rules
            .iter()
            .find(|r| r.method == method && r.tool_name.is_none())
        {
            return r.decision;
        }

        McpPolicyDecision::AuditOnly
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn rule(method: &str, tool: Option<&str>, decision: McpPolicyDecision) -> McpPolicyRule {
        McpPolicyRule {
            method: method.to_string(),
            tool_name: tool.map(|s| s.to_string()),
            decision,
            note: None,
        }
    }

    #[test]
    fn empty_rules_yields_audit_only() {
        let m = McpMessage::ToolsList;
        assert_eq!(
            PolicyEngine::evaluate(&[], &m),
            McpPolicyDecision::AuditOnly
        );
    }

    #[test]
    fn tools_call_prefers_specific_tool_rule() {
        let rules = vec![
            rule("tools/call", None, McpPolicyDecision::Prompt),
            rule(
                "tools/call",
                Some("read_file"),
                McpPolicyDecision::AutoAllow,
            ),
        ];
        let m = McpMessage::ToolsCall {
            name: "read_file".into(),
            arguments: Value::Null,
        };
        assert_eq!(
            PolicyEngine::evaluate(&rules, &m),
            McpPolicyDecision::AutoAllow
        );
    }

    #[test]
    fn tools_call_falls_back_to_method_rule_when_tool_misses() {
        let rules = vec![
            rule("tools/call", None, McpPolicyDecision::Prompt),
            rule("tools/call", Some("write_file"), McpPolicyDecision::Deny),
        ];
        let m = McpMessage::ToolsCall {
            name: "read_file".into(),
            arguments: Value::Null,
        };
        assert_eq!(
            PolicyEngine::evaluate(&rules, &m),
            McpPolicyDecision::Prompt
        );
    }

    #[test]
    fn other_methods_only_match_method_rule() {
        let rules = vec![rule("resources/read", None, McpPolicyDecision::Deny)];
        let m = McpMessage::ResourcesRead {
            uri: "file:///x".into(),
        };
        assert_eq!(PolicyEngine::evaluate(&rules, &m), McpPolicyDecision::Deny);
    }

    #[test]
    fn other_methods_ignore_tool_qualified_rules() {
        // tool_name on a non-tools/call rule should not match anything.
        let rules = vec![rule(
            "resources/read",
            Some("ignored"),
            McpPolicyDecision::AutoAllow,
        )];
        let m = McpMessage::ResourcesRead {
            uri: "file:///x".into(),
        };
        assert_eq!(
            PolicyEngine::evaluate(&rules, &m),
            McpPolicyDecision::AuditOnly
        );
    }

    #[test]
    fn unknown_method_in_other_variant_matches_by_method_string() {
        let rules = vec![rule("custom/thing", None, McpPolicyDecision::Deny)];
        let m = McpMessage::Other {
            method: "custom/thing".into(),
            params: Value::Null,
        };
        assert_eq!(PolicyEngine::evaluate(&rules, &m), McpPolicyDecision::Deny);
    }

    #[test]
    fn no_matching_rule_defaults_to_audit_only() {
        let rules = vec![rule("tools/list", None, McpPolicyDecision::AutoAllow)];
        let m = McpMessage::Initialize {
            params: Value::Null,
        };
        assert_eq!(
            PolicyEngine::evaluate(&rules, &m),
            McpPolicyDecision::AuditOnly
        );
    }
}
