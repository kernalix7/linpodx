//! Phase 14 Stream C — integration tests for the openraft 0.9 leader-elect
//! engine. The first two are unit-style (single node, no real network) and
//! always run; the `#[ignore]` tests spin up real axum servers + reqwest
//! clients on loopback ports and exercise the Raft HTTP transport end-to-end.
//! Run with `cargo test -p linpodx-cluster --test raft_election -- --ignored
//! --test-threads=1` once the loopback ports `17820..17830` are free.

use std::sync::Arc;
use std::time::Duration;

use linpodx_cluster::{LeaderState, RaftNode, RaftStartConfig};

fn fast_cfg(node_id: u64, label: &str, port: u16) -> RaftStartConfig {
    RaftStartConfig {
        node_id,
        node_label: label.into(),
        advertise_addr: format!("127.0.0.1:{port}"),
        heartbeat_ms: 50,
        election_timeout_min_ms: 200,
        election_timeout_max_ms: 400,
        bootstrap_single_node: true,
    }
}

async fn wait_for<F>(timeout: Duration, mut pred: F)
where
    F: FnMut() -> bool,
{
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if pred() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn loopback_port_available(port: u16) -> bool {
    match tokio::net::TcpListener::bind(format!("127.0.0.1:{port}")).await {
        Ok(listener) => {
            drop(listener);
            true
        }
        Err(err) => {
            eprintln!("skipping: loopback TCP port {port} unavailable ({err})");
            false
        }
    }
}

#[tokio::test]
async fn single_node_leader_elect_via_public_api() {
    let node = RaftNode::start(fast_cfg(1, "alpha", 17820), None, None)
        .await
        .expect("start");
    wait_for(Duration::from_secs(2), || {
        node.current_role() == LeaderState::Leader
    })
    .await;
    assert_eq!(node.current_role(), LeaderState::Leader);
    assert_eq!(node.current_leader(), Some("alpha".to_string()));
    assert_eq!(node.node_label(), "alpha");
    node.shutdown().await;
}

#[tokio::test]
async fn role_get_response_shape_compiles() {
    // Compile-time guard: the public response types are constructible from
    // the engine accessors without extra glue. Catches accidental field
    // renames in `linpodx-common::ipc::responses`.
    use linpodx_common::ipc::responses::{ClusterRole, ClusterRoleGetResponse};
    let node = RaftNode::start(fast_cfg(1, "alpha", 17821), None, None)
        .await
        .expect("start");
    wait_for(Duration::from_secs(2), || {
        node.current_role() == LeaderState::Leader
    })
    .await;
    let role = match node.current_role() {
        LeaderState::Leader => ClusterRole::Leader,
        LeaderState::Follower => ClusterRole::Follower,
        LeaderState::Candidate => ClusterRole::Candidate,
        LeaderState::Learner => ClusterRole::Learner,
        LeaderState::Unknown => ClusterRole::Unknown,
    };
    let resp = ClusterRoleGetResponse {
        node_id: node.node_label().to_string(),
        role,
        leader: node.current_leader(),
    };
    assert_eq!(resp.node_id, "alpha");
    assert!(matches!(resp.role, ClusterRole::Leader));
    node.shutdown().await;
}

#[tokio::test]
#[ignore = "spins up an axum listener; run with -- --ignored --test-threads=1"]
async fn raft_http_router_serves_against_real_listener() {
    use axum::Router;

    if !loopback_port_available(17826).await {
        return;
    }

    let node = Arc::new(
        RaftNode::start(fast_cfg(1, "alpha", 17825), None, None)
            .await
            .expect("start"),
    );
    wait_for(Duration::from_secs(2), || {
        node.current_role() == LeaderState::Leader
    })
    .await;

    let router: Router = Router::new().nest(
        "/cluster/raft",
        linpodx_cluster::raft_router(Arc::clone(&node)),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:17826")
        .await
        .expect("bind");
    let serve = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    // The vote endpoint expects a JSON-encoded VoteRequest; an empty POST
    // returns 4xx but proves the route is mounted (and not 404).
    let client = reqwest::Client::new();
    let resp = client
        .post("http://127.0.0.1:17826/cluster/raft/vote")
        .body("{}")
        .header("content-type", "application/json")
        .send()
        .await
        .expect("send");
    assert!(
        resp.status().as_u16() != 404,
        "vote endpoint should be mounted, got {}",
        resp.status()
    );

    serve.abort();
    Arc::try_unwrap(node)
        .unwrap_or_else(|n| (*n).clone())
        .shutdown()
        .await;
}

#[tokio::test]
#[ignore = "exercises a 3-node mock — long election timeouts; run with -- --ignored"]
async fn three_node_membership_change_via_add_learner() {
    // Bootstraps node A only. B/C start blank, matching daemon flow when
    // `--cluster-raft` is enabled without the explicit bootstrapper bit.
    let a = RaftNode::start(fast_cfg(1, "alpha", 17828), None, None)
        .await
        .expect("start a");
    let b_cfg = RaftStartConfig {
        bootstrap_single_node: false,
        ..fast_cfg(2, "beta", 17829)
    };
    let c_cfg = RaftStartConfig {
        bootstrap_single_node: false,
        ..fast_cfg(3, "gamma", 17830)
    };
    let b = RaftNode::start(b_cfg, None, None).await.expect("start b");
    let c = RaftNode::start(c_cfg, None, None).await.expect("start c");
    wait_for(Duration::from_secs(2), || {
        a.current_role() == LeaderState::Leader
    })
    .await;
    assert_ne!(b.current_role(), LeaderState::Leader);
    assert_ne!(c.current_role(), LeaderState::Leader);

    tokio::time::timeout(
        Duration::from_secs(8),
        linpodx_cluster::gossip::raft_on_peer_added(Some(&a), "beta", "127.0.0.1:17829"),
    )
    .await
    .expect("join beta timed out");
    tokio::time::timeout(
        Duration::from_secs(8),
        linpodx_cluster::gossip::raft_on_peer_added(Some(&a), "gamma", "127.0.0.1:17830"),
    )
    .await
    .expect("join gamma timed out");
    let labels = a.known_labels();
    assert!(labels.contains(&"alpha".to_string()));
    assert!(labels.contains(&"beta".to_string()));
    assert!(labels.contains(&"gamma".to_string()));
    a.shutdown().await;
    b.shutdown().await;
    c.shutdown().await;
}

// ---- Phase 15 Stream A — real HTTP multi-node bring-up ----

#[tokio::test]
#[ignore = "Phase 15 — spins up 3 axum listeners + RaftHttpFactory; \
            run with -- --ignored --test-threads=1 (free ports 17840..17850)"]
async fn three_node_bringup_via_real_http_factory() {
    use axum::Router;
    use chrono::Utc;
    use linpodx_cluster::{node_id_from_string, PeerInfo, PeerStatus, RaftHttpFactory};

    for port in 17840..=17842 {
        if !loopback_port_available(port).await {
            return;
        }
    }

    // Three nodes on adjacent loopback ports. Each runs:
    //   1. A RaftNode constructed with the production HTTP network factory.
    //   2. An axum listener mounting `/cluster/raft/{append,vote,snapshot}`
    //      via `linpodx_cluster::raft_router`.
    // Only node A has the explicit bootstrapper bit; B/C start blank and join
    // through the same hook daemon `ClusterJoin` uses.
    let id_a = node_id_from_string("phase15-alpha");
    let id_b = node_id_from_string("phase15-beta");
    let id_c = node_id_from_string("phase15-gamma");

    let mk_cfg = |id: u64, label: &str, port: u16, bootstrap: bool| RaftStartConfig {
        node_id: id,
        node_label: label.into(),
        advertise_addr: format!("127.0.0.1:{port}"),
        heartbeat_ms: 100,
        election_timeout_min_ms: 400,
        election_timeout_max_ms: 800,
        bootstrap_single_node: bootstrap,
    };

    let a = Arc::new(
        RaftNode::start_with_network(
            mk_cfg(id_a, "phase15-alpha", 17840, true),
            None,
            None,
            RaftHttpFactory::new(),
        )
        .await
        .expect("start a"),
    );
    let b = Arc::new(
        RaftNode::start_with_network(
            mk_cfg(id_b, "phase15-beta", 17841, false),
            None,
            None,
            RaftHttpFactory::new(),
        )
        .await
        .expect("start b"),
    );
    let c = Arc::new(
        RaftNode::start_with_network(
            mk_cfg(id_c, "phase15-gamma", 17842, false),
            None,
            None,
            RaftHttpFactory::new(),
        )
        .await
        .expect("start c"),
    );

    let serve = |node: Arc<RaftNode>, port: u16| async move {
        let router: Router = Router::new().nest(
            "/cluster/raft",
            linpodx_cluster::raft_router(Arc::clone(&node)),
        );
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
            .await
            .expect("bind");
        let _ = axum::serve(listener, router).await;
    };
    let h_a = tokio::spawn(serve(Arc::clone(&a), 17840));
    let h_b = tokio::spawn(serve(Arc::clone(&b), 17841));
    let h_c = tokio::spawn(serve(Arc::clone(&c), 17842));

    // Allow the listeners to come up.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Wait for A to elect itself as leader (single-node bootstrap).
    wait_for(Duration::from_secs(3), || {
        a.current_role() == LeaderState::Leader
    })
    .await;
    assert_eq!(a.current_role(), LeaderState::Leader);

    // Add B and C as learners via the daemon join hook, then promote through
    // the existing gossip -> Raft membership sync round.
    tokio::time::timeout(
        Duration::from_secs(8),
        linpodx_cluster::gossip::raft_on_peer_added(
            Some(a.as_ref()),
            "phase15-beta",
            "127.0.0.1:17841",
        ),
    )
    .await
    .expect("join beta timed out");
    tokio::time::timeout(
        Duration::from_secs(8),
        linpodx_cluster::gossip::raft_on_peer_added(
            Some(a.as_ref()),
            "phase15-gamma",
            "127.0.0.1:17842",
        ),
    )
    .await
    .expect("join gamma timed out");

    let now = Utc::now();
    let peers = vec![
        PeerInfo {
            node_id: "phase15-beta".into(),
            addr: "127.0.0.1:17841".into(),
            status: PeerStatus::Alive,
            last_seen: now,
            joined_at: now - chrono::Duration::seconds(10),
        },
        PeerInfo {
            node_id: "phase15-gamma".into(),
            addr: "127.0.0.1:17842".into(),
            status: PeerStatus::Alive,
            last_seen: now,
            joined_at: now - chrono::Duration::seconds(10),
        },
    ];
    let (promoted, removed) = linpodx_cluster::gossip::raft_membership_sync_round(
        a.as_ref(),
        &peers,
        now,
        chrono::Duration::seconds(5),
    )
    .await;
    assert!(removed.is_empty(), "no nodes should be removed");
    assert!(
        promoted.contains(&"phase15-beta".to_string()),
        "beta should be promoted, got {promoted:?}"
    );
    assert!(
        promoted.contains(&"phase15-gamma".to_string()),
        "gamma should be promoted, got {promoted:?}"
    );

    // After promotion the membership snapshot on the leader has 3 voters.
    let snap = a.membership_snapshot();
    assert_eq!(snap.voters.len(), 3, "got voters: {:?}", snap.voters);

    // Cleanup.
    h_a.abort();
    h_b.abort();
    h_c.abort();
    Arc::try_unwrap(a)
        .unwrap_or_else(|n| (*n).clone())
        .shutdown()
        .await;
    Arc::try_unwrap(b)
        .unwrap_or_else(|n| (*n).clone())
        .shutdown()
        .await;
    Arc::try_unwrap(c)
        .unwrap_or_else(|n| (*n).clone())
        .shutdown()
        .await;
}
