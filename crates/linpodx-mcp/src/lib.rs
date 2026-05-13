#![forbid(unsafe_code)]

//! MCP bridge subsystem for linpodx (Phase 2D + 2E).
//!
//! Spawns a host-side MCP server process and pipes its stdio through
//! `podman exec -i <container_id>`. Each line is best-effort parsed as a JSON-RPC
//! envelope so the bridge can extract the `method` field for audit + per-method policy
//! enforcement. Phase 2E adds:
//!   - `protocol`: typed `McpMessage` view over each stdio line
//!   - `policy`: rule-table → `McpPolicyDecision` evaluation
//!   - `bridge`: `Prompt` decisions delegate to an `ApprovalGateway`
//!
//! Bridges are tracked in a `BridgeRegistry`; the daemon dispatcher drives `start` /
//! `stop` / `status`.

pub mod bridge;
pub mod policy;
pub mod protocol;

pub use bridge::{empty_policy_store, Bridge, BridgeRegistry, BridgeStartHandle, PolicyStore};
pub use policy::PolicyEngine;
pub use protocol::{parse_capabilities_object, parse_initialize_response, McpMessage};
