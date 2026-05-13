//! Best-effort MCP / JSON-RPC 2.0 message recognition.
//!
//! The bridge sees raw stdio lines and only needs enough structure to evaluate the
//! per-method policy: which `method` the line carries and (for `tools/call`) which tool
//! is being invoked. Anything we cannot parse to JSON is dropped at the call site;
//! anything that parses but doesn't match a known method falls into [`McpMessage::Other`]
//! so the policy engine can still match by `method`.

use linpodx_common::ipc::McpCapabilities;
use serde_json::Value;

/// JSON-RPC 2.0 method names recognized by the bridge.
pub const METHOD_INITIALIZE: &str = "initialize";
pub const METHOD_TOOLS_LIST: &str = "tools/list";
pub const METHOD_TOOLS_CALL: &str = "tools/call";
pub const METHOD_RESOURCES_LIST: &str = "resources/list";
pub const METHOD_RESOURCES_READ: &str = "resources/read";
pub const METHOD_RESOURCES_SUBSCRIBE: &str = "resources/subscribe";
pub const METHOD_RESOURCES_UNSUBSCRIBE: &str = "resources/unsubscribe";
pub const METHOD_PROMPTS_LIST: &str = "prompts/list";

// Phase 2F notifications.
pub const METHOD_NOTIFICATIONS_INITIALIZED: &str = "notifications/initialized";
pub const METHOD_NOTIFICATIONS_TOOLS_LIST_CHANGED: &str = "notifications/tools/list_changed";
pub const METHOD_NOTIFICATIONS_RESOURCES_LIST_CHANGED: &str =
    "notifications/resources/list_changed";
pub const METHOD_NOTIFICATIONS_PROMPTS_LIST_CHANGED: &str = "notifications/prompts/list_changed";
pub const METHOD_NOTIFICATIONS_RESOURCES_UPDATED: &str = "notifications/resources/updated";

/// Structured view over one stdio line. Variants carry only the fields the policy
/// engine + audit pipeline actually use; the original `serde_json::Value` is preserved
/// for `Other` and `Notification` so the catch-all path can still log payloads.
#[derive(Debug, Clone, PartialEq)]
pub enum McpMessage {
    Initialize {
        params: Value,
    },
    ToolsList,
    ToolsCall {
        name: String,
        arguments: Value,
    },
    ResourcesList,
    ResourcesRead {
        uri: String,
    },
    /// Phase 2F: client-side subscription registration. The bridge tracks the URI in its
    /// per-bridge subscription set so that subsequent `notifications/resources/updated`
    /// can be filtered.
    ResourcesSubscribe {
        uri: String,
    },
    /// Phase 2F: client-side subscription removal. The bridge drops the URI from its
    /// per-bridge subscription set.
    ResourcesUnsubscribe {
        uri: String,
    },
    PromptsList,
    /// Phase 2F: `notifications/initialized` — the client signals it is ready after the
    /// initialize handshake completes.
    Initialized,
    /// Phase 2F: server announces tool list changed.
    ToolsListChanged,
    /// Phase 2F: server announces resource list changed.
    ResourcesListChanged,
    /// Phase 2F: server announces prompt list changed.
    PromptsListChanged,
    /// Phase 2F: server pushes a resource update for a specific URI. Filtered against
    /// the per-bridge subscription set.
    ResourcesUpdated {
        uri: String,
    },
    /// JSON-RPC notification (no `id` field). `method` is still meaningful for policy
    /// matching, but we never block notifications via approval (they have no caller to
    /// answer to) — the bridge just audits and forwards.
    Notification {
        method: String,
        params: Value,
    },
    /// Any parsable JSON object with a `method` field that we don't model explicitly.
    Other {
        method: String,
        params: Value,
    },
}

impl McpMessage {
    /// Parse one stdio line. Returns `None` if the line is not valid JSON or doesn't
    /// carry a string `method` field.
    pub fn parse(line: &str) -> Option<Self> {
        let value: Value = serde_json::from_str(line.trim()).ok()?;
        let method = value.get("method")?.as_str()?.to_string();
        let params = value.get("params").cloned().unwrap_or(Value::Null);
        let is_notification = value.get("id").is_none();

        Some(match method.as_str() {
            METHOD_INITIALIZE => Self::Initialize { params },
            METHOD_TOOLS_LIST => Self::ToolsList,
            METHOD_TOOLS_CALL => {
                let name = params
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);
                Self::ToolsCall { name, arguments }
            }
            METHOD_RESOURCES_LIST => Self::ResourcesList,
            METHOD_RESOURCES_READ => {
                let uri = params
                    .get("uri")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                Self::ResourcesRead { uri }
            }
            METHOD_RESOURCES_SUBSCRIBE => {
                let uri = params
                    .get("uri")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                Self::ResourcesSubscribe { uri }
            }
            METHOD_RESOURCES_UNSUBSCRIBE => {
                let uri = params
                    .get("uri")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                Self::ResourcesUnsubscribe { uri }
            }
            METHOD_PROMPTS_LIST => Self::PromptsList,
            METHOD_NOTIFICATIONS_INITIALIZED => Self::Initialized,
            METHOD_NOTIFICATIONS_TOOLS_LIST_CHANGED => Self::ToolsListChanged,
            METHOD_NOTIFICATIONS_RESOURCES_LIST_CHANGED => Self::ResourcesListChanged,
            METHOD_NOTIFICATIONS_PROMPTS_LIST_CHANGED => Self::PromptsListChanged,
            METHOD_NOTIFICATIONS_RESOURCES_UPDATED => {
                let uri = params
                    .get("uri")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                Self::ResourcesUpdated { uri }
            }
            _ if is_notification => Self::Notification { method, params },
            _ => Self::Other { method, params },
        })
    }

    /// Stable string for the JSON-RPC `method` field. Used for policy lookup + audit.
    pub fn method_str(&self) -> &str {
        match self {
            Self::Initialize { .. } => METHOD_INITIALIZE,
            Self::ToolsList => METHOD_TOOLS_LIST,
            Self::ToolsCall { .. } => METHOD_TOOLS_CALL,
            Self::ResourcesList => METHOD_RESOURCES_LIST,
            Self::ResourcesRead { .. } => METHOD_RESOURCES_READ,
            Self::ResourcesSubscribe { .. } => METHOD_RESOURCES_SUBSCRIBE,
            Self::ResourcesUnsubscribe { .. } => METHOD_RESOURCES_UNSUBSCRIBE,
            Self::PromptsList => METHOD_PROMPTS_LIST,
            Self::Initialized => METHOD_NOTIFICATIONS_INITIALIZED,
            Self::ToolsListChanged => METHOD_NOTIFICATIONS_TOOLS_LIST_CHANGED,
            Self::ResourcesListChanged => METHOD_NOTIFICATIONS_RESOURCES_LIST_CHANGED,
            Self::PromptsListChanged => METHOD_NOTIFICATIONS_PROMPTS_LIST_CHANGED,
            Self::ResourcesUpdated { .. } => METHOD_NOTIFICATIONS_RESOURCES_UPDATED,
            Self::Notification { method, .. } | Self::Other { method, .. } => method.as_str(),
        }
    }

    /// Tool name, only set for `tools/call`. The policy engine prefers a
    /// `(method, Some(tool))` rule over `(method, None)` when this is `Some`.
    pub fn tool_name(&self) -> Option<&str> {
        match self {
            Self::ToolsCall { name, .. } if !name.is_empty() => Some(name.as_str()),
            _ => None,
        }
    }
}

/// Best-effort: detect a JSON-RPC `initialize` *response* and pull out the
/// `result.capabilities` shape. Returns `None` if the line is not a JSON-RPC response,
/// the id does not match the expected one, or no capabilities object is present.
///
/// The caller is responsible for filtering by `id` before persisting; this helper just
/// parses the capability fields it understands and leaves anything else under
/// `experimental`.
pub fn parse_initialize_response(line: &str, expected_id: i64) -> Option<McpCapabilities> {
    let value: Value = serde_json::from_str(line.trim()).ok()?;
    // Must be a response (no `method`, has `id` matching expected).
    if value.get("method").is_some() {
        return None;
    }
    let id = value.get("id")?.as_i64()?;
    if id != expected_id {
        return None;
    }
    let caps = value.get("result")?.get("capabilities")?;
    Some(parse_capabilities_object(caps))
}

/// Translate a `capabilities` JSON object into the typed [`McpCapabilities`] shape.
/// Unknown keys are dumped under `experimental` so the daemon can still surface them.
pub fn parse_capabilities_object(caps: &Value) -> McpCapabilities {
    let tools = caps.get("tools").is_some();
    let resources = caps.get("resources").is_some();
    let prompts = caps.get("prompts").is_some();
    let logging = caps.get("logging").is_some();
    let experimental = caps.get("experimental").cloned().unwrap_or(Value::Null);
    McpCapabilities {
        tools,
        resources,
        prompts,
        logging,
        experimental,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_initialize() {
        let m = McpMessage::parse(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1.0"}}"#,
        )
        .unwrap();
        assert_eq!(m.method_str(), "initialize");
        assert!(matches!(m, McpMessage::Initialize { .. }));
        assert!(m.tool_name().is_none());
    }

    #[test]
    fn parse_tools_list() {
        let m = McpMessage::parse(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#).unwrap();
        assert!(matches!(m, McpMessage::ToolsList));
        assert_eq!(m.method_str(), "tools/list");
    }

    #[test]
    fn parse_tools_call_extracts_name_and_args() {
        let m = McpMessage::parse(
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/hosts"}}}"#,
        )
        .unwrap();
        match &m {
            McpMessage::ToolsCall { name, arguments } => {
                assert_eq!(name, "read_file");
                assert_eq!(arguments.get("path").unwrap().as_str(), Some("/etc/hosts"));
            }
            other => panic!("expected ToolsCall, got {other:?}"),
        }
        assert_eq!(m.tool_name(), Some("read_file"));
    }

    #[test]
    fn parse_resources_list() {
        let m = McpMessage::parse(r#"{"jsonrpc":"2.0","id":4,"method":"resources/list"}"#).unwrap();
        assert!(matches!(m, McpMessage::ResourcesList));
    }

    #[test]
    fn parse_resources_read_extracts_uri() {
        let m = McpMessage::parse(
            r#"{"jsonrpc":"2.0","id":5,"method":"resources/read","params":{"uri":"file:///x"}}"#,
        )
        .unwrap();
        match &m {
            McpMessage::ResourcesRead { uri } => assert_eq!(uri, "file:///x"),
            other => panic!("expected ResourcesRead, got {other:?}"),
        }
    }

    #[test]
    fn parse_prompts_list() {
        let m = McpMessage::parse(r#"{"jsonrpc":"2.0","id":6,"method":"prompts/list"}"#).unwrap();
        assert!(matches!(m, McpMessage::PromptsList));
    }

    #[test]
    fn parse_notification_when_no_id() {
        let m = McpMessage::parse(
            r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"ratio":0.5}}"#,
        )
        .unwrap();
        match m {
            McpMessage::Notification { method, params } => {
                assert_eq!(method, "notifications/progress");
                assert_eq!(params.get("ratio").and_then(|v| v.as_f64()), Some(0.5));
            }
            other => panic!("expected Notification, got {other:?}"),
        }
    }

    #[test]
    fn parse_other_for_unknown_method_with_id() {
        let m =
            McpMessage::parse(r#"{"jsonrpc":"2.0","id":9,"method":"custom/thing","params":{}}"#)
                .unwrap();
        match m {
            McpMessage::Other { method, .. } => assert_eq!(method, "custom/thing"),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn parse_returns_none_for_invalid_json() {
        assert!(McpMessage::parse("not json").is_none());
    }

    #[test]
    fn parse_returns_none_when_method_missing() {
        assert!(McpMessage::parse(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#).is_none());
    }

    #[test]
    fn parse_returns_none_when_method_not_string() {
        assert!(McpMessage::parse(r#"{"method": 42}"#).is_none());
    }

    #[test]
    fn tools_call_with_empty_name_yields_none_tool_name() {
        let m = McpMessage::parse(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{}}}"#,
        )
        .unwrap();
        assert_eq!(m.tool_name(), None);
    }

    // ----- Phase 2F: new variants -----

    #[test]
    fn parse_initialized_notification() {
        let m =
            McpMessage::parse(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).unwrap();
        assert!(matches!(m, McpMessage::Initialized));
        assert_eq!(m.method_str(), "notifications/initialized");
    }

    #[test]
    fn parse_tools_list_changed() {
        let m =
            McpMessage::parse(r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#)
                .unwrap();
        assert!(matches!(m, McpMessage::ToolsListChanged));
    }

    #[test]
    fn parse_resources_list_changed() {
        let m = McpMessage::parse(
            r#"{"jsonrpc":"2.0","method":"notifications/resources/list_changed"}"#,
        )
        .unwrap();
        assert!(matches!(m, McpMessage::ResourcesListChanged));
    }

    #[test]
    fn parse_prompts_list_changed() {
        let m =
            McpMessage::parse(r#"{"jsonrpc":"2.0","method":"notifications/prompts/list_changed"}"#)
                .unwrap();
        assert!(matches!(m, McpMessage::PromptsListChanged));
    }

    #[test]
    fn parse_resources_updated_extracts_uri() {
        let m = McpMessage::parse(
            r#"{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"file:///watched"}}"#,
        )
        .unwrap();
        match m {
            McpMessage::ResourcesUpdated { uri } => assert_eq!(uri, "file:///watched"),
            other => panic!("expected ResourcesUpdated, got {other:?}"),
        }
    }

    #[test]
    fn parse_resources_subscribe_extracts_uri() {
        let m = McpMessage::parse(
            r#"{"jsonrpc":"2.0","id":11,"method":"resources/subscribe","params":{"uri":"file:///x"}}"#,
        )
        .unwrap();
        match m {
            McpMessage::ResourcesSubscribe { uri } => assert_eq!(uri, "file:///x"),
            other => panic!("expected ResourcesSubscribe, got {other:?}"),
        }
    }

    #[test]
    fn parse_resources_unsubscribe_extracts_uri() {
        let m = McpMessage::parse(
            r#"{"jsonrpc":"2.0","id":12,"method":"resources/unsubscribe","params":{"uri":"file:///x"}}"#,
        )
        .unwrap();
        match m {
            McpMessage::ResourcesUnsubscribe { uri } => assert_eq!(uri, "file:///x"),
            other => panic!("expected ResourcesUnsubscribe, got {other:?}"),
        }
    }

    #[test]
    fn parse_initialize_response_full_capabilities() {
        let line = r#"{"jsonrpc":"2.0","id":42,"result":{"capabilities":{"tools":{},"resources":{"subscribe":true},"prompts":{},"logging":{},"experimental":{"foo":1}}}}"#;
        let caps = parse_initialize_response(line, 42).expect("parsed");
        assert!(caps.tools);
        assert!(caps.resources);
        assert!(caps.prompts);
        assert!(caps.logging);
        assert_eq!(
            caps.experimental.get("foo").and_then(|v| v.as_i64()),
            Some(1)
        );
    }

    #[test]
    fn parse_initialize_response_partial_capabilities() {
        let line = r#"{"jsonrpc":"2.0","id":7,"result":{"capabilities":{"tools":{}}}}"#;
        let caps = parse_initialize_response(line, 7).expect("parsed");
        assert!(caps.tools);
        assert!(!caps.resources);
        assert!(!caps.prompts);
        assert!(!caps.logging);
        assert!(caps.experimental.is_null());
    }

    #[test]
    fn parse_initialize_response_id_mismatch_returns_none() {
        let line = r#"{"jsonrpc":"2.0","id":1,"result":{"capabilities":{"tools":{}}}}"#;
        assert!(parse_initialize_response(line, 99).is_none());
    }

    #[test]
    fn parse_initialize_response_rejects_messages_with_method() {
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        assert!(parse_initialize_response(line, 1).is_none());
    }

    #[test]
    fn parse_initialize_response_rejects_invalid_json() {
        assert!(parse_initialize_response("not json", 1).is_none());
    }

    #[test]
    fn parse_initialize_response_missing_capabilities_returns_none() {
        let line = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
        assert!(parse_initialize_response(line, 1).is_none());
    }
}
