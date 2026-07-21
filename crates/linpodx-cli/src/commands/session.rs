//! `linpodx session <...>` — agent sessions (Phase 2C): one row per container
//! lifetime, plus the merged audit + MCP timeline view.
#![forbid(unsafe_code)]

use crate::client::Client;
use crate::output::{print_inspect, print_session_list, print_session_timeline, OutputFormat};
use anyhow::Result;
use clap::Subcommand;
use linpodx_common::ipc::{Method, SessionIdParams, SessionListParams, SessionTimelineParams};

#[derive(Subcommand, Debug)]
pub(crate) enum SessionCmd {
    /// List sessions (one row per container lifetime).
    List {
        /// Filter by container id or name.
        #[arg(long)]
        container: Option<String>,
        /// Cap the number of rows returned.
        #[arg(long)]
        limit: Option<u32>,
    },
    /// Show one session row as pretty JSON.
    Inspect { id: i64 },
    /// Print the merged audit + MCP timeline for a session.
    Timeline {
        /// Filter to specific entry kinds. Repeatable.
        #[arg(long = "kind")]
        kinds: Vec<String>,
        id: i64,
    },
}

pub(crate) async fn handle_session(
    client: &mut Client,
    fmt: OutputFormat,
    cmd: SessionCmd,
) -> Result<()> {
    use linpodx_common::ipc::responses::{
        SessionListResponse, SessionSummary, SessionTimelineResponse,
    };
    match cmd {
        SessionCmd::List { container, limit } => {
            let sessions: SessionListResponse = client
                .call(Method::SessionList(SessionListParams {
                    container_id: container,
                    limit,
                }))
                .await?;
            print_session_list(&sessions, fmt)?;
        }
        SessionCmd::Inspect { id } => {
            let summary: SessionSummary = client
                .call(Method::SessionInspect(SessionIdParams { id }))
                .await?;
            print_inspect(&summary, fmt)?;
        }
        SessionCmd::Timeline { kinds, id } => {
            let entries: SessionTimelineResponse = client
                .call(Method::SessionTimeline(SessionTimelineParams { id, kinds }))
                .await?;
            print_session_timeline(&entries)?;
        }
    }
    Ok(())
}
