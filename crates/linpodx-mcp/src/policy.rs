//! Per-method MCP policy evaluation.
//!
//! The bridge consults the policy engine for every parsed message. Rules live in the
//! `mcp_policies` SQLite table and are mirrored into a process-local `Vec` (refreshed by
//! `mcp_policy_set`). Matching prefers the more specific rule:
//!
//! 1. For `tools/call` with a tool name, look for a rule with `(method, Some(tool))`.
//! 2. Fall back to `(method, None)`.
//! 3. If still no match, return the profile's *default action* (see below).
//!
//! ## Default action for unmatched messages
//!
//! The shared IPC schema ([`McpPolicyRule`]) has no dedicated `default_action` column, so
//! rather than default fail-open in every case we *derive* the default from the rule set —
//! a simple, explicit scheme that needs no schema change:
//!
//! - **Zero rules** → [`McpPolicyDecision::AuditOnly`]. An empty policy table means the
//!   profile author has expressed no intent; the bridge stays backward-compatible and
//!   forwards (this is also the regime the legacy static-allowlist path serves).
//! - **Any `Deny` rule present** → [`McpPolicyDecision::Deny`]. The presence of *any*
//!   explicit deny signals the author is thinking in denylist terms, so an unmatched
//!   (or parser-differential) message must fail *closed* rather than slip through. This is
//!   what closes the old fail-open hole where a method the author never wrote a rule for
//!   defaulted to forward even under a hardened profile.
//! - **Rules present, none `Deny`** (pure allow/prompt/audit profile) →
//!   [`McpPolicyDecision::AuditOnly`], preserving the prior behavior for allowlist-style
//!   profiles that never intended to block anything.
//!
//! See [`PolicyEngine::default_action`].

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

        Self::default_action(rules)
    }

    /// Decision applied to a message that matches no explicit rule.
    ///
    /// Derived from the rule set per the module-level "Default action" docs: `Deny` when
    /// the profile contains any `Deny` rule (denylist intent → fail closed), otherwise
    /// `AuditOnly` (empty or pure-allow profile → forward, backward-compatible).
    pub fn default_action(rules: &[McpPolicyRule]) -> McpPolicyDecision {
        if rules.iter().any(|r| r.decision == McpPolicyDecision::Deny) {
            McpPolicyDecision::Deny
        } else {
            McpPolicyDecision::AuditOnly
        }
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

    #[test]
    fn default_action_is_audit_only_for_empty_rules() {
        assert_eq!(
            PolicyEngine::default_action(&[]),
            McpPolicyDecision::AuditOnly
        );
    }

    #[test]
    fn default_action_is_audit_only_without_any_deny_rule() {
        let rules = vec![
            rule("tools/list", None, McpPolicyDecision::AutoAllow),
            rule("tools/call", Some("read"), McpPolicyDecision::Prompt),
        ];
        assert_eq!(
            PolicyEngine::default_action(&rules),
            McpPolicyDecision::AuditOnly
        );
    }

    #[test]
    fn default_action_is_deny_when_any_deny_rule_present() {
        let rules = vec![
            rule("tools/list", None, McpPolicyDecision::AutoAllow),
            rule("tools/call", Some("write_file"), McpPolicyDecision::Deny),
        ];
        assert_eq!(
            PolicyEngine::default_action(&rules),
            McpPolicyDecision::Deny
        );
    }

    #[test]
    fn unmatched_message_denied_under_denylist_profile() {
        // A profile that denies one tool must not fail *open* for a method the author
        // never wrote a rule for — the derived default action is Deny.
        let rules = vec![rule(
            "tools/call",
            Some("write_file"),
            McpPolicyDecision::Deny,
        )];
        let m = McpMessage::Initialize {
            params: Value::Null,
        };
        assert_eq!(PolicyEngine::evaluate(&rules, &m), McpPolicyDecision::Deny);
    }

    #[test]
    fn unmatched_message_audit_only_under_pure_allow_profile() {
        let rules = vec![rule(
            "tools/call",
            Some("read"),
            McpPolicyDecision::AutoAllow,
        )];
        let m = McpMessage::Initialize {
            params: Value::Null,
        };
        assert_eq!(
            PolicyEngine::evaluate(&rules, &m),
            McpPolicyDecision::AuditOnly
        );
    }
}
