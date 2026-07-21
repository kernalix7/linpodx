//! `linpodx cluster <...>` — Raft leader-elect queries (Phase 14) and
//! replicated container state-machine queries (Phase 16 Stream A).
#![forbid(unsafe_code)]

use crate::client::Client;
use crate::output::OutputFormat;
use anyhow::Result;
use clap::Subcommand;
use linpodx_common::ipc::{ClusterRaftPromoteParams, ClusterStateProposeContainerParams, Method};

#[derive(Subcommand, Debug)]
pub(crate) enum ClusterCmd {
    /// Print the current Raft leader's node label (or `none` if no leader is
    /// known yet).
    Leader,
    /// Print this node's current Raft role (leader / follower / candidate /
    /// learner / unknown) plus the node label and any visible leader.
    Role,
    /// Print the cluster Raft membership table (voters + learners + term).
    /// Phase 15 — only meaningful when the daemon was started with
    /// `--cluster-raft`.
    Status,
    /// Promote a previously-added learner to a voter. The argument is the
    /// gossip node label / friendly id (the daemon hashes it the same way as
    /// `linpodx_cluster::node_id_from_string`). Phase 15.
    Promote {
        /// String node id (gossip label) of the learner to promote.
        node_id: String,
    },
    /// Phase 16 Stream A — replicated state machine queries. Requires the
    /// daemon to have been started with `--cluster-raft`.
    #[command(subcommand)]
    State(ClusterStateCmd),
}

#[derive(Debug, clap::Subcommand)]
pub(crate) enum ClusterStateCmd {
    /// Print the replicated container state machine (last_applied + entries).
    Get,
    /// Propose a synthetic container summary into the replicated state
    /// machine. Useful for end-to-end / integration testing without driving
    /// a real podman lifecycle.
    Propose {
        /// Source node label (the `node_id` field of the resulting entry).
        #[arg(long)]
        node_id: String,
        /// Container id to propose. A minimal `ContainerSummary` is built
        /// around it on the client side.
        #[arg(long)]
        container_id: String,
        /// Optional image tag to embed in the proposed summary.
        #[arg(long, default_value = "linpodx-test:latest")]
        image: String,
    },
}

pub(crate) async fn handle_cluster(
    client: &mut Client,
    fmt: OutputFormat,
    cmd: ClusterCmd,
) -> Result<()> {
    use linpodx_common::ipc::responses::{
        ClusterLeaderGetResponse, ClusterRaftPromoteResponse, ClusterRaftStatusResponse,
        ClusterRoleGetResponse,
    };
    match cmd {
        ClusterCmd::Leader => {
            let resp: ClusterLeaderGetResponse = client.call(Method::ClusterLeaderGet).await?;
            match fmt {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&resp)?),
                OutputFormat::Table => match resp.leader.as_deref() {
                    Some(l) => println!("{l}"),
                    None => println!("none"),
                },
            }
        }
        ClusterCmd::Role => {
            let resp: ClusterRoleGetResponse = client.call(Method::ClusterRoleGet).await?;
            match fmt {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&resp)?),
                OutputFormat::Table => {
                    let role = cluster_role_str(resp.role);
                    let leader = resp.leader.as_deref().unwrap_or("none");
                    println!("node:   {}", resp.node_id);
                    println!("role:   {role}");
                    println!("leader: {leader}");
                }
            }
        }
        ClusterCmd::Status => {
            let resp: ClusterRaftStatusResponse = client.call(Method::ClusterRaftStatus).await?;
            match fmt {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&resp)?),
                OutputFormat::Table => {
                    let role = cluster_role_str(resp.local_role);
                    let leader = resp.leader.as_deref().unwrap_or("none");
                    println!("local node:  {}", resp.local_node_id);
                    println!("local role:  {role}");
                    println!("leader:      {leader}");
                    println!("term:        {}", resp.current_term);
                    println!();
                    println!("MEMBERSHIP");
                    println!("{:<10}  {:<24}  {:<6}", "NODE_ID", "LABEL/ADDR", "ROLE");
                    for v in &resp.voters {
                        println!(
                            "{:<10}  {:<24}  {:<6}",
                            v.node_id,
                            v.label.as_deref().unwrap_or("-"),
                            v.role
                        );
                    }
                    for l in &resp.learners {
                        println!(
                            "{:<10}  {:<24}  {:<6}",
                            l.node_id,
                            l.label.as_deref().unwrap_or("-"),
                            l.role
                        );
                    }
                    if resp.voters.is_empty() && resp.learners.is_empty() {
                        println!("(no members)");
                    }
                }
            }
        }
        ClusterCmd::Promote { node_id } => {
            let params = ClusterRaftPromoteParams {
                node_id: node_id.clone(),
            };
            let resp: ClusterRaftPromoteResponse =
                client.call(Method::ClusterRaftPromote(params)).await?;
            match fmt {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&resp)?),
                OutputFormat::Table => {
                    println!("promoted: {} -> {}", resp.node_id, resp.new_role);
                }
            }
        }
        ClusterCmd::State(state) => handle_cluster_state(client, fmt, state).await?,
    }
    Ok(())
}

async fn handle_cluster_state(
    client: &mut Client,
    fmt: OutputFormat,
    cmd: ClusterStateCmd,
) -> Result<()> {
    use linpodx_common::ipc::responses::{
        ClusterStateGetResponse, ClusterStateProposeContainerResponse,
    };
    use linpodx_common::state::{ContainerState, ContainerSummary};
    use linpodx_common::types::ContainerId;

    match cmd {
        ClusterStateCmd::Get => {
            let resp: ClusterStateGetResponse = client.call(Method::ClusterStateGet).await?;
            match fmt {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&resp)?),
                OutputFormat::Table => {
                    println!("last_applied: {}", resp.last_applied);
                    println!("state_bytes:  {}", resp.state_bytes);
                    println!("entries:      {}", resp.containers.len());
                    println!();
                    println!(
                        "{:<14}  {:<14}  {:<24}  {:<10}",
                        "NODE", "CONTAINER", "IMAGE", "STATE"
                    );
                    for e in &resp.containers {
                        println!(
                            "{:<14}  {:<14}  {:<24}  {:<10}",
                            e.node_id, e.container.id.0, e.container.image, e.container.state
                        );
                    }
                    if resp.containers.is_empty() {
                        println!("(no entries)");
                    }
                }
            }
        }
        ClusterStateCmd::Propose {
            node_id,
            container_id,
            image,
        } => {
            let summary = ContainerSummary {
                id: ContainerId(container_id.clone()),
                names: vec![format!("synthetic-{container_id}")],
                image: image.clone(),
                state: ContainerState::Running,
                status: "Up (proposed)".into(),
                created: chrono::Utc::now(),
                command: None,
                ports: vec![],
            };
            let params = ClusterStateProposeContainerParams {
                node_id: node_id.clone(),
                container: summary,
            };
            let resp: ClusterStateProposeContainerResponse = client
                .call(Method::ClusterStateProposeContainer(params))
                .await?;
            match fmt {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&resp)?),
                OutputFormat::Table => {
                    println!(
                        "proposed: node={node_id} container={container_id} \
                         log_index={} committed={}",
                        resp.log_index, resp.committed
                    );
                }
            }
        }
    }
    Ok(())
}

fn cluster_role_str(role: linpodx_common::ipc::responses::ClusterRole) -> &'static str {
    use linpodx_common::ipc::responses::ClusterRole;
    match role {
        ClusterRole::Leader => "leader",
        ClusterRole::Follower => "follower",
        ClusterRole::Candidate => "candidate",
        ClusterRole::Learner => "learner",
        ClusterRole::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cli, Cmd};
    use clap::Parser;

    #[test]
    fn parse_cluster_leader_subcommand() {
        let cli = Cli::parse_from(["linpodx", "cluster", "leader"]);
        match cli.cmd {
            Cmd::Cluster(ClusterCmd::Leader) => {}
            other => panic!("expected Cluster Leader subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_cluster_role_subcommand() {
        let cli = Cli::parse_from(["linpodx", "cluster", "role"]);
        match cli.cmd {
            Cmd::Cluster(ClusterCmd::Role) => {}
            other => panic!("expected Cluster Role subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_cluster_status_subcommand() {
        let cli = Cli::parse_from(["linpodx", "cluster", "status"]);
        match cli.cmd {
            Cmd::Cluster(ClusterCmd::Status) => {}
            other => panic!("expected Cluster Status subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_cluster_promote_subcommand() {
        let cli = Cli::parse_from(["linpodx", "cluster", "promote", "node-b"]);
        match cli.cmd {
            Cmd::Cluster(ClusterCmd::Promote { node_id }) => {
                assert_eq!(node_id, "node-b");
            }
            other => panic!("expected Cluster Promote subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_cluster_state_get_subcommand() {
        let cli = Cli::parse_from(["linpodx", "cluster", "state", "get"]);
        match cli.cmd {
            Cmd::Cluster(ClusterCmd::State(ClusterStateCmd::Get)) => {}
            other => panic!("expected Cluster State Get subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_cluster_state_propose_subcommand() {
        let cli = Cli::parse_from([
            "linpodx",
            "cluster",
            "state",
            "propose",
            "--node-id",
            "alpha",
            "--container-id",
            "c1",
        ]);
        match cli.cmd {
            Cmd::Cluster(ClusterCmd::State(ClusterStateCmd::Propose {
                node_id,
                container_id,
                image,
            })) => {
                assert_eq!(node_id, "alpha");
                assert_eq!(container_id, "c1");
                assert_eq!(image, "linpodx-test:latest");
            }
            other => panic!("expected Cluster State Propose subcommand, got {other:?}"),
        }
    }

    #[test]
    fn cluster_raft_status_response_round_trips_via_serde() {
        use linpodx_common::ipc::responses::{
            ClusterRaftStatusResponse, ClusterRole, RaftMembershipNode,
        };
        let resp = ClusterRaftStatusResponse {
            local_node_id: "alpha".into(),
            local_role: ClusterRole::Leader,
            leader: Some("alpha".into()),
            voters: vec![RaftMembershipNode {
                node_id: "1".into(),
                label: Some("alpha".into()),
                role: "voter".into(),
            }],
            learners: vec![RaftMembershipNode {
                node_id: "1234567890".into(),
                label: Some("beta".into()),
                role: "learner".into(),
            }],
            current_term: 4,
        };
        let s = serde_json::to_string(&resp).unwrap();
        let back: ClusterRaftStatusResponse = serde_json::from_str(&s).unwrap();
        assert_eq!(back.local_node_id, "alpha");
        assert_eq!(back.voters.len(), 1);
        assert_eq!(back.learners.len(), 1);
        assert_eq!(back.current_term, 4);
        assert!(matches!(back.local_role, ClusterRole::Leader));
    }
}
