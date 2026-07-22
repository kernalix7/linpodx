//! Cluster gossip + Raft (leader-elect, multi-node membership, state
//! replication) and the K8s read/write adapter dispatch handlers.

use super::*;

impl Dispatcher {
    pub(crate) async fn cluster_join(
        &self,
        p: linpodx_common::ipc::ClusterJoinParams,
    ) -> Result<serde_json::Value> {
        let store = self.cluster_store();
        let info = store
            .upsert(p.node_id.clone(), p.addr.clone())
            .await
            .map_err(cluster_to_err)?;
        // Register the freshly-joined peer with the Raft engine as a learner so
        // leader-election / replication traffic can flow to it. Best-effort:
        // the hook short-circuits when no Raft node is wired, logs + audits on
        // success, and swallows errors (e.g. this node is not the leader — a
        // documented v0.2 multi-node bootstrap concern). SQLite upsert above
        // remains the source of truth for the gossip peer view.
        linpodx_cluster::gossip::raft_on_peer_added(self.raft.as_deref(), &p.node_id, &p.addr)
            .await;
        let resp = responses::ClusterJoinResponse {
            node_id: info.node_id,
            joined: true,
        };
        Ok(serde_json::to_value(resp)?)
    }

    pub(crate) async fn cluster_leave(
        &self,
        p: linpodx_common::ipc::ClusterLeaveParams,
    ) -> Result<serde_json::Value> {
        let store = self.cluster_store();
        let removed = store
            .remove(p.node_id.clone())
            .await
            .map_err(cluster_to_err)?;
        // Drop the peer from the Raft membership set too. Best-effort counterpart
        // to the learner registration in `cluster_join`: no-op when no Raft node
        // is wired, audited on success, errors swallowed (best-effort membership).
        linpodx_cluster::gossip::raft_on_peer_removed(self.raft.as_deref(), &p.node_id).await;
        let resp = responses::ClusterLeaveResponse {
            node_id: p.node_id,
            removed,
        };
        Ok(serde_json::to_value(resp)?)
    }

    pub(crate) async fn cluster_peers(&self) -> Result<serde_json::Value> {
        let store = self.cluster_store();
        let peers = store.list().await.map_err(cluster_to_err)?;
        let summaries: Vec<responses::ClusterPeerSummary> = peers
            .into_iter()
            .map(|p| responses::ClusterPeerSummary {
                node_id: p.node_id,
                addr: p.addr,
                status: p.status.as_str().to_string(),
                last_seen: p.last_seen,
            })
            .collect();
        Ok(serde_json::to_value::<responses::ClusterPeersResponse>(
            summaries,
        )?)
    }

    pub(crate) async fn cluster_container_view(&self) -> Result<serde_json::Value> {
        // Phase 16 Stream A — prefer the Raft-replicated state when a
        // Raft node is wired and has at least one applied entry. Fall
        // back to the Phase 9 gossip aggregation when Raft is absent
        // or has not seen any container proposals yet, so single-node
        // and pre-Phase-16 deployments keep behaving the same.
        if let Some(node) = self.raft.as_ref() {
            let snap = node.state_snapshot().await;
            if snap.last_applied > 0 && !snap.containers.is_empty() {
                let entries: Vec<responses::ClusterContainerEntry> = snap
                    .containers
                    .into_iter()
                    .map(|(node_id, container)| responses::ClusterContainerEntry {
                        node_id,
                        container,
                    })
                    .collect();
                let db = Arc::clone(self.snapshot.database());
                record_cluster_view_served(&db, self.audit.as_ref(), 0, entries.len()).await;
                return Ok(serde_json::to_value::<
                    responses::ClusterContainerViewResponse,
                >(entries)?);
            }
        }
        let store = self.cluster_store();
        let peers = store.list().await.map_err(cluster_to_err)?;
        let local = self.podman.list(true).await?;
        let http = linpodx_cluster::gossip::default_client();
        let local_node_id =
            std::env::var("LINPODX_NODE_ID").unwrap_or_else(|_| "local".to_string());
        let entries = linpodx_cluster::view::aggregate_containers(
            &local_node_id,
            &local,
            &peers,
            &http,
            None,
        )
        .await;
        let db = Arc::clone(self.snapshot.database());
        record_cluster_view_served(&db, self.audit.as_ref(), peers.len(), entries.len()).await;
        Ok(serde_json::to_value::<
            responses::ClusterContainerViewResponse,
        >(entries)?)
    }

    pub(crate) async fn cluster_leader_get(&self) -> Result<serde_json::Value> {
        let leader = match self.raft.as_ref() {
            Some(node) => node.current_leader(),
            None => None,
        };
        let resp = responses::ClusterLeaderGetResponse { leader };
        Ok(serde_json::to_value(resp)?)
    }

    pub(crate) async fn cluster_role_get(&self) -> Result<serde_json::Value> {
        use linpodx_cluster::LeaderState;
        let (node_id, role, leader) = match self.raft.as_ref() {
            Some(node) => {
                let role = match node.current_role() {
                    LeaderState::Leader => responses::ClusterRole::Leader,
                    LeaderState::Follower => responses::ClusterRole::Follower,
                    LeaderState::Candidate => responses::ClusterRole::Candidate,
                    LeaderState::Learner => responses::ClusterRole::Learner,
                    LeaderState::Unknown => responses::ClusterRole::Unknown,
                };
                (node.node_label().to_string(), role, node.current_leader())
            }
            None => {
                let label =
                    std::env::var("LINPODX_NODE_ID").unwrap_or_else(|_| "local".to_string());
                (label, responses::ClusterRole::Unknown, None)
            }
        };
        let resp = responses::ClusterRoleGetResponse {
            node_id,
            role,
            leader,
        };
        Ok(serde_json::to_value(resp)?)
    }

    pub(crate) async fn cluster_raft_status(&self) -> Result<serde_json::Value> {
        use linpodx_cluster::LeaderState;
        let Some(node) = self.raft.as_ref() else {
            return Err(Error::Unsupported(
                "raft leader-elect not enabled on this daemon \
                 (start with --cluster-raft to enable cluster.raft_status)"
                    .into(),
            ));
        };
        let role = match node.current_role() {
            LeaderState::Leader => responses::ClusterRole::Leader,
            LeaderState::Follower => responses::ClusterRole::Follower,
            LeaderState::Candidate => responses::ClusterRole::Candidate,
            LeaderState::Learner => responses::ClusterRole::Learner,
            LeaderState::Unknown => responses::ClusterRole::Unknown,
        };
        let snap = node.membership_snapshot();
        let to_membership_node = |row: &linpodx_cluster::MembershipNodeView,
                                  role: &str|
         -> responses::RaftMembershipNode {
            responses::RaftMembershipNode {
                node_id: row.node_id.to_string(),
                // Prefer the friendly label; fall back to the
                // advertised host:port so the UI never shows a bare
                // numeric id.
                label: row.label.clone().or_else(|| row.addr.clone()),
                role: role.to_string(),
            }
        };
        let voters: Vec<responses::RaftMembershipNode> = snap
            .voters
            .iter()
            .map(|r| to_membership_node(r, "voter"))
            .collect();
        let learners: Vec<responses::RaftMembershipNode> = snap
            .learners
            .iter()
            .map(|r| to_membership_node(r, "learner"))
            .collect();
        let resp = responses::ClusterRaftStatusResponse {
            local_node_id: node.node_label().to_string(),
            local_role: role,
            leader: node.current_leader(),
            voters,
            learners,
            current_term: snap.current_term,
        };
        Ok(serde_json::to_value(resp)?)
    }

    pub(crate) async fn cluster_raft_promote(
        &self,
        p: linpodx_common::ipc::ClusterRaftPromoteParams,
    ) -> Result<serde_json::Value> {
        let Some(node) = self.raft.as_ref() else {
            return Err(Error::Unsupported(
                "raft leader-elect not enabled on this daemon \
                 (start with --cluster-raft to enable cluster.raft_promote)"
                    .into(),
            ));
        };
        let label = p.node_id.clone();
        node.promote_with_audit(std::slice::from_ref(&label))
            .await
            .map_err(|e| Error::Runtime {
                message: format!("cluster.raft_promote({label}) failed: {e}"),
            })?;
        let resp = responses::ClusterRaftPromoteResponse {
            node_id: p.node_id,
            new_role: "voter".to_string(),
        };
        Ok(serde_json::to_value(resp)?)
    }

    pub(crate) async fn cluster_state_get(&self) -> Result<serde_json::Value> {
        let Some(node) = self.raft.as_ref() else {
            return Err(Error::Unsupported(
                "cluster.state_get unavailable: daemon was started \
                 without --cluster-raft (no replicated state machine)"
                    .into(),
            ));
        };
        let snap = node.state_snapshot().await;
        let containers: Vec<responses::ClusterContainerEntry> = snap
            .containers
            .into_iter()
            .map(|(node_id, container)| responses::ClusterContainerEntry { node_id, container })
            .collect();
        // `state_bytes` is best-effort: serialize the current container
        // map so callers have a usable size hint without forcing the
        // store to expose its on-disk byte count (which is not a thing
        // for the in-memory MemStore yet).
        let state_bytes = serde_json::to_vec(&containers)
            .map(|v| v.len() as u64)
            .unwrap_or(0);
        let resp = responses::ClusterStateGetResponse {
            last_applied: snap.last_applied,
            containers,
            state_bytes,
        };
        Ok(serde_json::to_value(resp)?)
    }

    pub(crate) async fn cluster_state_propose_container(
        &self,
        p: linpodx_common::ipc::ClusterStateProposeContainerParams,
    ) -> Result<serde_json::Value> {
        let Some(node) = self.raft.as_ref() else {
            return Err(Error::Unsupported(
                "cluster.state_propose_container unavailable: daemon \
                 was started without --cluster-raft"
                    .into(),
            ));
        };
        let log_index = node
            .propose_container(p.node_id.clone(), p.container.clone())
            .await
            .map_err(cluster_to_err)?;
        let resp = responses::ClusterStateProposeContainerResponse {
            log_index,
            committed: true,
        };
        Ok(serde_json::to_value(resp)?)
    }

    /// Lazily construct the K8s adapter once and cache it on `self.k8s`
    /// (kubeconfig parse + TLS handshake are expensive to redo per request —
    /// all six `k8s_*` arms below funnel through this). Only a *successful*
    /// init is cached: a broken kubeconfig must not permanently poison later
    /// retries once the environment is fixed (e.g. `KUBECONFIG` gets set
    /// after the daemon has already served one failed request).
    async fn k8s_adapter(&self) -> Result<linpodx_cluster::K8sAdapter> {
        cache_or_init(&self.k8s, || async {
            linpodx_cluster::K8sAdapter::try_default()
                .await
                .map_err(k8s_unavailable_err)
        })
        .await
    }

    // ----- Phase 10: K8s read-only adapter (Stream C) -----
    pub(crate) async fn k8s_pod_list(
        &self,
        p: linpodx_common::ipc::K8sNamespaceParams,
    ) -> Result<serde_json::Value> {
        let adapter = self.k8s_adapter().await?;
        let pods = adapter
            .list_pods(p.namespace.as_deref())
            .await
            .map_err(cluster_to_err)?;
        record_k8s_query_served(
            self.audit.as_ref(),
            "pod_list",
            p.namespace.as_deref(),
            pods.len(),
        )
        .await;
        Ok(serde_json::to_value::<responses::K8sPodListResponse>(pods)?)
    }

    pub(crate) async fn k8s_service_list(
        &self,
        p: linpodx_common::ipc::K8sNamespaceParams,
    ) -> Result<serde_json::Value> {
        let adapter = self.k8s_adapter().await?;
        let svcs = adapter
            .list_services(p.namespace.as_deref())
            .await
            .map_err(cluster_to_err)?;
        record_k8s_query_served(
            self.audit.as_ref(),
            "service_list",
            p.namespace.as_deref(),
            svcs.len(),
        )
        .await;
        Ok(serde_json::to_value::<responses::K8sServiceListResponse>(
            svcs,
        )?)
    }

    // ----- Phase 13 Stream A: K8s write-side -----
    pub(crate) async fn k8s_pod_create(
        &self,
        p: linpodx_common::ipc::K8sPodCreateParams,
    ) -> Result<serde_json::Value> {
        let adapter = self.k8s_adapter().await?;
        let resp = adapter
            .create_pod(&p.namespace, &p.pod_spec_yaml)
            .await
            .map_err(cluster_to_err)?;
        self.audit
            .record(
                AuditSinkKind::K8sPodCreated,
                None,
                None,
                serde_json::json!({
                    "namespace": resp.namespace,
                    "name": resp.name,
                    "uid": resp.uid,
                }),
            )
            .await;
        Ok(serde_json::to_value::<responses::K8sPodCreateResponse>(
            resp,
        )?)
    }

    pub(crate) async fn k8s_pod_delete(
        &self,
        p: linpodx_common::ipc::K8sPodDeleteParams,
    ) -> Result<serde_json::Value> {
        let adapter = self.k8s_adapter().await?;
        let resp = adapter
            .delete_pod(&p.namespace, &p.name)
            .await
            .map_err(cluster_to_err)?;
        self.audit
            .record(
                AuditSinkKind::K8sPodDeleted,
                None,
                None,
                serde_json::json!({
                    "namespace": resp.namespace,
                    "name": resp.name,
                    "deleted": resp.deleted,
                }),
            )
            .await;
        Ok(serde_json::to_value::<responses::K8sPodDeleteResponse>(
            resp,
        )?)
    }

    pub(crate) async fn k8s_namespace_create(
        &self,
        p: linpodx_common::ipc::K8sNamespaceCreateParams,
    ) -> Result<serde_json::Value> {
        let adapter = self.k8s_adapter().await?;
        let resp = adapter
            .create_namespace(&p.name)
            .await
            .map_err(cluster_to_err)?;
        self.audit
            .record(
                AuditSinkKind::K8sNamespaceCreated,
                None,
                None,
                serde_json::json!({
                    "name": resp.name,
                    "uid": resp.uid,
                }),
            )
            .await;
        Ok(serde_json::to_value::<responses::K8sNamespaceCreateResponse>(resp)?)
    }

    pub(crate) async fn k8s_deployment_scale(
        &self,
        p: linpodx_common::ipc::K8sDeploymentScaleParams,
    ) -> Result<serde_json::Value> {
        let adapter = self.k8s_adapter().await?;
        let resp = adapter
            .scale_deployment(&p.namespace, &p.name, p.replicas)
            .await
            .map_err(cluster_to_err)?;
        self.audit
            .record(
                AuditSinkKind::K8sDeploymentScaled,
                None,
                None,
                serde_json::json!({
                    "namespace": resp.namespace,
                    "name": resp.name,
                    "replicas": resp.replicas,
                }),
            )
            .await;
        Ok(serde_json::to_value::<responses::K8sDeploymentScaleResponse>(resp)?)
    }
}
