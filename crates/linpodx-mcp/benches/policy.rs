//! Bench: [`PolicyEngine::evaluate`] across a representative rule set.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use linpodx_common::ipc::{McpPolicyDecision, McpPolicyRule};
use linpodx_mcp::{McpMessage, PolicyEngine};
use serde_json::Value;

fn rules() -> Vec<McpPolicyRule> {
    vec![
        McpPolicyRule {
            method: "tools/call".into(),
            tool_name: None,
            decision: McpPolicyDecision::Prompt,
            note: None,
        },
        McpPolicyRule {
            method: "tools/call".into(),
            tool_name: Some("read_file".into()),
            decision: McpPolicyDecision::AutoAllow,
            note: None,
        },
        McpPolicyRule {
            method: "tools/call".into(),
            tool_name: Some("write_file".into()),
            decision: McpPolicyDecision::Deny,
            note: None,
        },
        McpPolicyRule {
            method: "resources/read".into(),
            tool_name: None,
            decision: McpPolicyDecision::AuditOnly,
            note: None,
        },
        McpPolicyRule {
            method: "tools/list".into(),
            tool_name: None,
            decision: McpPolicyDecision::AutoAllow,
            note: None,
        },
    ]
}

fn bench_policy(c: &mut Criterion) {
    let rules = rules();
    let allow = McpMessage::ToolsCall {
        name: "read_file".into(),
        arguments: Value::Null,
    };
    let deny = McpMessage::ToolsCall {
        name: "write_file".into(),
        arguments: Value::Null,
    };
    let fallback = McpMessage::ToolsCall {
        name: "unknown_tool".into(),
        arguments: Value::Null,
    };

    c.bench_function("mcp/policy/evaluate/allow", |b| {
        b.iter(|| PolicyEngine::evaluate(black_box(&rules), black_box(&allow)))
    });
    c.bench_function("mcp/policy/evaluate/deny", |b| {
        b.iter(|| PolicyEngine::evaluate(black_box(&rules), black_box(&deny)))
    });
    c.bench_function("mcp/policy/evaluate/fallback", |b| {
        b.iter(|| PolicyEngine::evaluate(black_box(&rules), black_box(&fallback)))
    });
}

criterion_group!(benches, bench_policy);
criterion_main!(benches);
