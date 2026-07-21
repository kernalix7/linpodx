//! `linpodx mcp <...>` — host-stdio MCP bridges (Phase 2D) and per-method
//! policy table (Phase 2E).
#![forbid(unsafe_code)]

use crate::client::Client;
use crate::output::{print_mcp_policy_list, print_mcp_status, OutputFormat};
use anyhow::Result;
use clap::Subcommand;
use linpodx_common::ipc::{
    McpBridgeStartParams, McpBridgeStatusParams, McpBridgeStopParams, McpPolicyDecision,
    McpPolicyRule, McpPolicySetParams, Method,
};

#[derive(Subcommand, Debug)]
pub(crate) enum McpCmd {
    /// Start a host-stdio MCP bridge for a container.
    Start {
        /// Allow only these MCP method names. Repeat the flag. Empty = audit-only.
        #[arg(long = "allow")]
        allowlist: Vec<String>,
        /// Container id or name to attach to.
        container: String,
        /// Host command to run as the MCP server (e.g. `/usr/bin/cat`).
        host_command: String,
        /// Trailing arguments forwarded to the host command.
        #[arg(trailing_var_arg = true)]
        host_args: Vec<String>,
    },
    /// Stop a running bridge by id.
    Stop { bridge_id: String },
    /// List currently running bridges.
    Status {
        /// Limit to a single bridge id.
        #[arg(long)]
        bridge_id: Option<String>,
    },
    /// Per-method MCP policy table (Phase 2E).
    #[command(subcommand)]
    Policy(McpPolicyCmd),
}

#[derive(Subcommand, Debug)]
pub(crate) enum McpPolicyCmd {
    /// Upsert one rule (method [+ tool]) → decision.
    Set {
        /// JSON-RPC method name (e.g. `tools/call`, `prompts/list`).
        #[arg(long)]
        method: String,
        /// Optional tool name (only meaningful with `tools/call`).
        #[arg(long)]
        tool: Option<String>,
        /// Decision: auto_allow | prompt | deny | audit_only.
        #[arg(long, value_parser = parse_mcp_decision)]
        decision: McpPolicyDecision,
        /// Optional free-form note recorded alongside the rule.
        #[arg(long)]
        note: Option<String>,
    },
    /// Print the current rule table.
    List,
}

fn parse_mcp_decision(raw: &str) -> std::result::Result<McpPolicyDecision, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "auto_allow" | "auto-allow" | "allow" => Ok(McpPolicyDecision::AutoAllow),
        "prompt" | "ask" => Ok(McpPolicyDecision::Prompt),
        "deny" => Ok(McpPolicyDecision::Deny),
        "audit_only" | "audit-only" | "audit" => Ok(McpPolicyDecision::AuditOnly),
        other => Err(format!(
            "unknown decision '{other}' (expected: auto_allow | prompt | deny | audit_only)"
        )),
    }
}

pub(crate) async fn handle_mcp(client: &mut Client, fmt: OutputFormat, cmd: McpCmd) -> Result<()> {
    use linpodx_common::ipc::responses::{
        McpBridgeStartResponse, McpBridgeStatusResponse, McpBridgeStopResponse,
        McpPolicyListResponse, McpPolicySetResponse,
    };
    match cmd {
        McpCmd::Start {
            allowlist,
            container,
            host_command,
            host_args,
        } => {
            let resp: McpBridgeStartResponse = client
                .call(Method::McpBridgeStart(McpBridgeStartParams {
                    container_id: container,
                    host_command,
                    host_args,
                    allowlist,
                }))
                .await?;
            println!("{}", resp.bridge_id);
        }
        McpCmd::Stop { bridge_id } => {
            let resp: McpBridgeStopResponse = client
                .call(Method::McpBridgeStop(McpBridgeStopParams {
                    bridge_id: bridge_id.clone(),
                }))
                .await?;
            if resp.stopped {
                println!("{}", resp.bridge_id);
            } else {
                eprintln!("bridge {} not found (already stopped?)", resp.bridge_id);
                std::process::exit(1);
            }
        }
        McpCmd::Status { bridge_id } => {
            let entries: McpBridgeStatusResponse = client
                .call(Method::McpBridgeStatus(McpBridgeStatusParams { bridge_id }))
                .await?;
            print_mcp_status(&entries, fmt)?;
        }
        McpCmd::Policy(McpPolicyCmd::Set {
            method,
            tool,
            decision,
            note,
        }) => {
            let rule = McpPolicyRule {
                method,
                tool_name: tool,
                decision,
                note,
            };
            let resp: McpPolicySetResponse = client
                .call(Method::McpPolicySet(McpPolicySetParams {
                    rules: vec![rule],
                    replace_all: false,
                }))
                .await?;
            println!("upserted={} deleted={}", resp.upserted, resp.deleted);
        }
        McpCmd::Policy(McpPolicyCmd::List) => {
            let rules: McpPolicyListResponse = client.call(Method::McpPolicyList).await?;
            print_mcp_policy_list(&rules, fmt)?;
        }
    }
    Ok(())
}
