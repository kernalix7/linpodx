//! Phase 14 Stream C — openraft 0.9 leader-elect.
//!
//! Wraps openraft 0.9 in a thin facade so the rest of the daemon can ask
//! "who is the leader right now?" / "what role am I in?" without touching
//! openraft types directly. v0.1 is intentionally minimal:
//!
//! * **No application state machine.** Entries are opaque blobs — the only
//!   thing this module cares about is the leader-election outcome (vote +
//!   membership). Container-view consensus arrives in a later phase.
//! * **In-memory log + state machine** with opportunistic SQLite persistence
//!   of the **vote only** (key/value rows in `raft_state`). A daemon restart
//!   resets the cluster to bootstrap; that is acceptable for v0.1 because the
//!   audit log already records `ClusterLeaderElected` on every fresh round.
//! * **HTTP transport** — see [`crate::raft_http`]. The peer endpoints live
//!   under `/cluster/raft/{append,vote,snapshot}` and reuse the existing axum
//!   listener spawned by the daemon.
//!
//! The public surface is deliberately small: build a [`RaftNode`] via
//! [`RaftNode::start`], then call [`RaftNode::current_leader`] and
//! [`RaftNode::current_role`]. Membership is updated via
//! [`RaftNode::add_learner`] / [`RaftNode::remove_node`] — both wired from a
//! narrow hook in [`crate::gossip`].

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::io::Cursor;
use std::ops::RangeBounds;
use std::sync::Arc;

use crate::ClusterError;
use chrono::Utc;
use linpodx_common::audit_sink::{AuditSink, AuditSinkKind};
use openraft::error::{InitializeError, RaftError};
use openraft::network::RaftNetworkFactory;
use openraft::storage::Adaptor;
use openraft::storage::RaftStorage;
use openraft::storage::Snapshot;
use openraft::BasicNode;
use openraft::Config;
use openraft::Entry;
use openraft::EntryPayload;
use openraft::LogId;
use openraft::LogState;
use openraft::RaftLogReader;
use openraft::RaftMetrics;
use openraft::RaftSnapshotBuilder;
use openraft::ServerState;
use openraft::SnapshotMeta;
use openraft::StorageError;
use openraft::StorageIOError;
use openraft::StoredMembership;
use openraft::TokioRuntime;
use openraft::Vote;
use serde::{Deserialize, Serialize};
use std::sync::Mutex as StdMutex;
use tokio::sync::watch;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// `NodeId` used by [`LinpodxRaft`]. Aliased so callers don't need to import
/// `BasicNode` directly.
pub type NodeId = u64;

/// Address the HTTP transport will reach a peer at. Stored as `BasicNode` for
/// openraft compatibility; the `addr` field is a host:port (no scheme — the
/// transport adds `http://`).
pub type Node = BasicNode;

/// Cluster role surfaced through [`RaftNode::current_role`]. Mirrors openraft's
/// [`ServerState`] but adds an `Unknown` sentinel for the brief window between
/// `Raft::new` and the first metric emission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaderState {
    Leader,
    Follower,
    Candidate,
    Learner,
    Unknown,
}

impl From<ServerState> for LeaderState {
    fn from(s: ServerState) -> Self {
        match s {
            ServerState::Leader => LeaderState::Leader,
            ServerState::Follower => LeaderState::Follower,
            ServerState::Candidate => LeaderState::Candidate,
            ServerState::Learner => LeaderState::Learner,
            ServerState::Shutdown => LeaderState::Unknown,
        }
    }
}

/// Application payload appended to the Raft log. Phase 16 Stream A grew the
/// surface from "opaque heartbeat blob" to two real container-view mutations;
/// Phase 17 Stream C adds a third for cluster-wide plugin-key revocation:
///
/// * [`AppData::ProposeContainer`] — upsert a container summary into the
///   replicated `(node_id, container_id) -> ContainerSummary` map.
/// * [`AppData::RemoveContainer`] — drop the entry for a `(node_id, container_id)`
///   pair (no-op when the key is missing).
/// * [`AppData::RevokePluginKey`] — propagate a publisher-key revocation so
///   every node writes its local `<publisher>.revoked` marker through the
///   sandbox `KeyRegistry::apply_remote_revocation` hook (idempotent — applying
///   the same revocation twice is a no-op).
///
/// The previous `Noop { bytes }` variant is preserved with `serde(other)` so a
/// daemon rolled back to an older binary can still drain its in-memory log
/// without panicking on an unknown discriminant.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AppData {
    ProposeContainer {
        node_id: String,
        container: linpodx_common::state::ContainerSummary,
    },
    RemoveContainer {
        node_id: String,
        container_id: String,
    },
    /// Phase 17 Stream C — replicated plugin-key revocation. `revoked_at` is
    /// the proposer's Unix-seconds timestamp; followers apply it verbatim so
    /// audit timestamps stay consistent across the cluster.
    RevokePluginKey {
        publisher: String,
        fingerprint: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        revoked_at: i64,
    },
    /// Backwards-compat sentinel for the Phase 14/15 placeholder payload. Apply
    /// is a no-op — the entry only contributes to `last_applied_index`.
    #[serde(other)]
    #[default]
    Noop,
}

/// Phase 17 Stream C — callback the daemon supplies so the Raft state-machine
/// apply path can drive `KeyRegistry::apply_remote_revocation` without
/// `linpodx-cluster` depending on `linpodx-sandbox` / `linpodx-plugin`.
///
/// Implementations MUST be idempotent (re-applying the same `(publisher,
/// fingerprint, revoked_at)` triple is a no-op). The state-machine apply
/// path holds no Raft locks while invoking this sink, so blocking I/O
/// (writing the `.revoked` marker) is acceptable here.
pub trait PluginRevocationSink: Send + Sync + Debug {
    fn apply_remote_revocation(
        &self,
        publisher: &str,
        fingerprint: &str,
        reason: Option<&str>,
        revoked_at: i64,
    );
}

/// State machine response. Reports the new `last_applied_index` and the total
/// container count after the entry was applied so callers (and tests) can
/// assert monotonic progress without re-reading the snapshot.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppResponse {
    pub ok: bool,
    pub last_applied_index: u64,
    pub container_count: u64,
}

openraft::declare_raft_types!(
    /// Type configuration for the linpodx leader-elect Raft cluster.
    pub LinpodxRaft:
        D = AppData,
        R = AppResponse,
        NodeId = NodeId,
        Node = BasicNode,
        Entry = openraft::Entry<Self>,
        SnapshotData = Cursor<Vec<u8>>,
        AsyncRuntime = TokioRuntime,
);

/// Configuration for [`RaftNode::start`]. All fields have sensible single-node
/// defaults so unit tests can call `Default::default()` and get a working
/// bootstrap.
#[derive(Debug, Clone)]
pub struct RaftStartConfig {
    /// Stable numeric id for this node. Bound to the gossip `node_id` string
    /// via a deterministic hash (see [`node_id_from_string`]).
    pub node_id: NodeId,
    /// Friendly string id surfaced to IPC (the same value the gossip layer
    /// uses). Stored alongside the numeric id in `raft_state`.
    pub node_label: String,
    /// `host:port` this node's HTTP transport is reachable at. Persisted in
    /// the membership entry so peers know where to dial.
    pub advertise_addr: String,
    /// Raft heartbeat / election tick. Defaults to 250 ms / 1500 ms — fast
    /// enough for a snappy single-node bootstrap and slow enough to avoid
    /// thrashing on a busy laptop.
    pub heartbeat_ms: u64,
    pub election_timeout_min_ms: u64,
    pub election_timeout_max_ms: u64,
    /// When `true`, [`RaftNode::start`] calls `Raft::initialize` with a
    /// single-node membership of `{node_id}` so the node becomes leader
    /// immediately. Disable for tests that want to drive election manually.
    pub bootstrap_single_node: bool,
}

impl Default for RaftStartConfig {
    fn default() -> Self {
        Self {
            node_id: 1,
            node_label: "local".into(),
            advertise_addr: "127.0.0.1:7878".into(),
            heartbeat_ms: 250,
            election_timeout_min_ms: 1500,
            election_timeout_max_ms: 3000,
            bootstrap_single_node: true,
        }
    }
}

/// Hash a free-form node label (gossip `node_id` string) into a stable u64.
/// Used so the same label always maps to the same openraft NodeId across
/// restarts, without requiring a separate provisioning step.
pub fn node_id_from_string(label: &str) -> NodeId {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    if label == "local" {
        // The single-node bootstrap path always uses id=1 so the daemon's
        // metrics stream is human-readable on the common path.
        return 1;
    }
    let mut h = DefaultHasher::new();
    label.hash(&mut h);
    // Reserve ids 0/1 for sentinel/bootstrap use.
    let v = h.finish();
    if v < 2 {
        v + 2
    } else {
        v
    }
}

// ---------------------------------------------------------------------------
// In-memory storage — implements the legacy `RaftStorage` (v1) trait, then
// adapted to `RaftLogStorage + RaftStateMachine` via openraft's `Adaptor`.
// SQLite persistence is opportunistic and only covers `vote`.
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct StoreInner {
    log: BTreeMap<u64, Entry<LinpodxRaft>>,
    last_purged_log_id: Option<LogId<NodeId>>,
    vote: Option<Vote<NodeId>>,
    last_applied_log_id: Option<LogId<NodeId>>,
    last_membership: StoredMembership<NodeId, BasicNode>,
    snapshot_idx: u64,
    current_snapshot: Option<StoredSnapshot>,
    /// Phase 16 Stream A — replicated container view. Keyed by
    /// `(source_node_label, container_id)` so two nodes reporting the same
    /// container id stay distinct (a deliberate choice — collisions across
    /// nodes are a podman bug, not a state-machine bug).
    containers: BTreeMap<(String, String), linpodx_common::state::ContainerSummary>,
}

#[derive(Debug, Clone)]
struct StoredSnapshot {
    meta: SnapshotMeta<NodeId, BasicNode>,
    data: Vec<u8>,
}

/// In-memory Raft storage. Vote writes are mirrored to the optional `vote_sink`
/// so SQLite-backed deployments survive a restart without losing the term.
#[derive(Clone)]
pub struct MemStore {
    inner: Arc<RwLock<StoreInner>>,
    vote_sink: Option<Arc<dyn VoteSink>>,
    /// Phase 17 Stream C — invoked by `apply_to_state_machine` whenever a
    /// `RevokePluginKey` entry is applied. Wrapped in `StdMutex<Option<_>>`
    /// so the daemon can install it after `MemStore::new` (the openraft
    /// `Raft` engine takes ownership of the store before the plugin
    /// subsystem is wired up).
    revocation_sink: Arc<StdMutex<Option<Arc<dyn PluginRevocationSink>>>>,
}

impl Debug for MemStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemStore").finish_non_exhaustive()
    }
}

impl MemStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(StoreInner::default())),
            vote_sink: None,
            revocation_sink: Arc::new(StdMutex::new(None)),
        }
    }

    pub fn with_vote_sink(sink: Arc<dyn VoteSink>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(StoreInner::default())),
            vote_sink: Some(sink),
            revocation_sink: Arc::new(StdMutex::new(None)),
        }
    }

    /// Phase 17 Stream C — install (or replace) the callback driving local
    /// plugin-key revocation on every applied `RevokePluginKey` entry.
    pub fn set_plugin_revocation_sink(&self, sink: Arc<dyn PluginRevocationSink>) {
        if let Ok(mut guard) = self.revocation_sink.lock() {
            *guard = Some(sink);
        }
    }

    fn invoke_revocation_sink(
        &self,
        publisher: &str,
        fingerprint: &str,
        reason: Option<&str>,
        revoked_at: i64,
    ) {
        let sink = match self.revocation_sink.lock() {
            Ok(g) => g.clone(),
            Err(_) => None,
        };
        if let Some(s) = sink {
            s.apply_remote_revocation(publisher, fingerprint, reason, revoked_at);
        } else {
            debug!(
                publisher,
                fingerprint, "raft applied RevokePluginKey but no local sink is installed"
            );
        }
    }

    /// Phase 16 Stream A — snapshot the replicated container state machine.
    /// Cheap O(n) clone of an in-memory `BTreeMap`; callers that need to hold
    /// the result across an `await` should not hold the inner lock themselves.
    pub async fn state_snapshot(&self) -> ClusterStateSnapshot {
        let guard = self.inner.read().await;
        let last_applied = guard.last_applied_log_id.map(|l| l.index).unwrap_or(0);
        let mut containers = Vec::with_capacity(guard.containers.len());
        for ((node_id, _cid), summary) in guard.containers.iter() {
            containers.push((node_id.clone(), summary.clone()));
        }
        ClusterStateSnapshot {
            last_applied,
            containers,
        }
    }

    /// Restore the persisted vote (if any) into the in-memory store. Called by
    /// [`RaftNode::start`] before constructing the openraft engine so a fresh
    /// election does not clobber a previously-elected term.
    pub async fn load_persisted_vote(&self) {
        let Some(sink) = self.vote_sink.as_ref() else {
            return;
        };
        match sink.load_vote().await {
            Ok(Some(v)) => {
                let mut guard = self.inner.write().await;
                guard.vote = Some(v);
            }
            Ok(None) => {}
            Err(e) => {
                warn!(error = %e, "raft: load_persisted_vote failed (continuing with empty vote)")
            }
        }
    }
}

impl Default for MemStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Hook used by [`MemStore`] to persist `vote` writes to a long-lived backing
/// store (in production: a row in `raft_state`).
#[async_trait::async_trait]
pub trait VoteSink: Send + Sync + Debug {
    async fn save_vote(&self, vote: &Vote<NodeId>) -> std::result::Result<(), String>;
    async fn load_vote(&self) -> std::result::Result<Option<Vote<NodeId>>, String>;
}

/// No-op sink useful for tests.
#[derive(Debug, Default)]
pub struct NoopVoteSink;

#[async_trait::async_trait]
impl VoteSink for NoopVoteSink {
    async fn save_vote(&self, _vote: &Vote<NodeId>) -> std::result::Result<(), String> {
        Ok(())
    }
    async fn load_vote(&self) -> std::result::Result<Option<Vote<NodeId>>, String> {
        Ok(None)
    }
}

/// SQLite-backed [`VoteSink`] persisting the vote into the `raft_state`
/// key/value table (migration 0014). Stores the vote as a JSON-encoded
/// string under `key='vote'` so the schema is stable across openraft
/// minor-version bumps.
pub struct SqliteVoteSink {
    db: Arc<linpodx_common::db::Database>,
}

impl Debug for SqliteVoteSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteVoteSink").finish_non_exhaustive()
    }
}

impl SqliteVoteSink {
    pub fn new(db: Arc<linpodx_common::db::Database>) -> Self {
        Self { db }
    }
}

#[async_trait::async_trait]
impl VoteSink for SqliteVoteSink {
    async fn save_vote(&self, vote: &Vote<NodeId>) -> std::result::Result<(), String> {
        let encoded = serde_json::to_string(vote).map_err(|e| format!("serialize vote: {e}"))?;
        sqlx::query(
            "INSERT INTO raft_state(key, value, updated_at) VALUES('vote', ?1, \
             strftime('%Y-%m-%dT%H:%M:%fZ','now')) \
             ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        )
        .bind(encoded)
        .execute(self.db.pool())
        .await
        .map_err(|e| format!("save vote: {e}"))?;
        Ok(())
    }

    async fn load_vote(&self) -> std::result::Result<Option<Vote<NodeId>>, String> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT value FROM raft_state WHERE key = 'vote'")
                .fetch_optional(self.db.pool())
                .await
                .map_err(|e| format!("load vote: {e}"))?;
        match row {
            None => Ok(None),
            Some((s,)) => {
                let v: Vote<NodeId> =
                    serde_json::from_str(&s).map_err(|e| format!("decode vote: {e}"))?;
                Ok(Some(v))
            }
        }
    }
}

impl RaftLogReader<LinpodxRaft> for MemStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + Send>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<LinpodxRaft>>, StorageError<NodeId>> {
        let guard = self.inner.read().await;
        let entries = guard
            .log
            .range(range)
            .map(|(_, v)| v.clone())
            .collect::<Vec<_>>();
        Ok(entries)
    }
}

/// On-disk shape for a state-machine snapshot. Phase 14/15 only persisted
/// `last_membership` opaquely; Phase 16 extends it to include the replicated
/// container map so a fresh follower catches up by `install_snapshot` instead
/// of re-applying every log entry.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SnapshotPayload {
    last_membership: StoredMembership<NodeId, BasicNode>,
    #[serde(default)]
    containers: BTreeMap<String, linpodx_common::state::ContainerSummary>,
}

fn key_to_str(node_id: &str, container_id: &str) -> String {
    format!("{node_id}\u{0}{container_id}")
}

fn key_from_str(s: &str) -> Option<(String, String)> {
    let mut parts = s.splitn(2, '\u{0}');
    let n = parts.next()?.to_string();
    let c = parts.next()?.to_string();
    Some((n, c))
}

impl RaftSnapshotBuilder<LinpodxRaft> for MemStore {
    async fn build_snapshot(&mut self) -> Result<Snapshot<LinpodxRaft>, StorageError<NodeId>> {
        let (data, last_applied_log, last_membership);
        {
            let guard = self.inner.read().await;
            let payload = SnapshotPayload {
                last_membership: guard.last_membership.clone(),
                containers: guard
                    .containers
                    .iter()
                    .map(|((n, c), v)| (key_to_str(n, c), v.clone()))
                    .collect(),
            };
            data = serde_json::to_vec(&payload)
                .map_err(|e| StorageIOError::read_state_machine(&e).into_storage_error())?;
            last_applied_log = guard.last_applied_log_id;
            last_membership = guard.last_membership.clone();
        }
        let mut guard = self.inner.write().await;
        guard.snapshot_idx += 1;
        let snapshot_id = match last_applied_log {
            Some(id) => format!("{}-{}-{}", id.leader_id, id.index, guard.snapshot_idx),
            None => format!("--{}", guard.snapshot_idx),
        };
        let meta = SnapshotMeta {
            last_log_id: last_applied_log,
            last_membership,
            snapshot_id,
        };
        let snapshot = StoredSnapshot {
            meta: meta.clone(),
            data: data.clone(),
        };
        guard.current_snapshot = Some(snapshot);
        Ok(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(data)),
        })
    }
}

impl RaftStorage<LinpodxRaft> for MemStore {
    type LogReader = Self;
    type SnapshotBuilder = Self;

    async fn save_vote(&mut self, vote: &Vote<NodeId>) -> Result<(), StorageError<NodeId>> {
        {
            let mut guard = self.inner.write().await;
            guard.vote = Some(*vote);
        }
        if let Some(sink) = self.vote_sink.as_ref() {
            if let Err(e) = sink.save_vote(vote).await {
                warn!(error = %e, "raft: persist vote failed (in-memory state still updated)");
            }
        }
        Ok(())
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<NodeId>>, StorageError<NodeId>> {
        let guard = self.inner.read().await;
        Ok(guard.vote)
    }

    async fn get_log_state(&mut self) -> Result<LogState<LinpodxRaft>, StorageError<NodeId>> {
        use openraft::RaftLogId;
        let guard = self.inner.read().await;
        let last = guard.log.iter().next_back().map(|(_, e)| *e.get_log_id());
        let last_purged = guard.last_purged_log_id;
        Ok(LogState {
            last_purged_log_id: last_purged,
            last_log_id: last.or(last_purged),
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn append_to_log<I>(&mut self, entries: I) -> Result<(), StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<LinpodxRaft>> + Send,
    {
        let mut guard = self.inner.write().await;
        for e in entries {
            guard.log.insert(e.log_id.index, e);
        }
        Ok(())
    }

    async fn delete_conflict_logs_since(
        &mut self,
        log_id: LogId<NodeId>,
    ) -> Result<(), StorageError<NodeId>> {
        let mut guard = self.inner.write().await;
        let keys: Vec<_> = guard.log.range(log_id.index..).map(|(k, _)| *k).collect();
        for k in keys {
            guard.log.remove(&k);
        }
        Ok(())
    }

    async fn purge_logs_upto(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        let mut guard = self.inner.write().await;
        let keys: Vec<_> = guard.log.range(..=log_id.index).map(|(k, _)| *k).collect();
        for k in keys {
            guard.log.remove(&k);
        }
        if guard
            .last_purged_log_id
            .map(|p| p.index < log_id.index)
            .unwrap_or(true)
        {
            guard.last_purged_log_id = Some(log_id);
        }
        Ok(())
    }

    async fn last_applied_state(
        &mut self,
    ) -> Result<(Option<LogId<NodeId>>, StoredMembership<NodeId, BasicNode>), StorageError<NodeId>>
    {
        let guard = self.inner.read().await;
        Ok((guard.last_applied_log_id, guard.last_membership.clone()))
    }

    async fn apply_to_state_machine(
        &mut self,
        entries: &[Entry<LinpodxRaft>],
    ) -> Result<Vec<AppResponse>, StorageError<NodeId>> {
        let mut out = Vec::with_capacity(entries.len());
        // Collect revocation hooks to fire after dropping the write lock; the
        // sink may want to take its own locks (and we keep the Raft path
        // free of unrelated I/O while holding the state-machine guard).
        let mut deferred_revocations: Vec<(String, String, Option<String>, i64)> = Vec::new();
        {
            let mut guard = self.inner.write().await;
            for entry in entries {
                guard.last_applied_log_id = Some(entry.log_id);
                match &entry.payload {
                    EntryPayload::Blank => {}
                    EntryPayload::Normal(data) => match data {
                        AppData::ProposeContainer { node_id, container } => {
                            let key = (node_id.clone(), container.id.0.clone());
                            guard.containers.insert(key, container.clone());
                        }
                        AppData::RemoveContainer {
                            node_id,
                            container_id,
                        } => {
                            let key = (node_id.clone(), container_id.clone());
                            guard.containers.remove(&key);
                        }
                        AppData::RevokePluginKey {
                            publisher,
                            fingerprint,
                            reason,
                            revoked_at,
                        } => {
                            deferred_revocations.push((
                                publisher.clone(),
                                fingerprint.clone(),
                                reason.clone(),
                                *revoked_at,
                            ));
                        }
                        AppData::Noop => {}
                    },
                    EntryPayload::Membership(m) => {
                        guard.last_membership =
                            StoredMembership::new(Some(entry.log_id), m.clone());
                    }
                }
                out.push(AppResponse {
                    ok: true,
                    last_applied_index: entry.log_id.index,
                    container_count: guard.containers.len() as u64,
                });
            }
        }
        for (publisher, fingerprint, reason, revoked_at) in deferred_revocations {
            self.invoke_revocation_sink(&publisher, &fingerprint, reason.as_deref(), revoked_at);
        }
        Ok(out)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<Cursor<Vec<u8>>>, StorageError<NodeId>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<NodeId, BasicNode>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<NodeId>> {
        let data = snapshot.into_inner();
        let mut guard = self.inner.write().await;
        guard.last_applied_log_id = meta.last_log_id;
        guard.last_membership = meta.last_membership.clone();
        // Phase 16 — rehydrate the container map from the new snapshot payload
        // shape. A snapshot written by an older daemon (no `containers` field)
        // deserializes with `containers` defaulting to empty, which is the
        // safe fallback.
        if !data.is_empty() {
            if let Ok(payload) = serde_json::from_slice::<SnapshotPayload>(&data) {
                let mut rebuilt = BTreeMap::new();
                for (k, v) in payload.containers {
                    if let Some(parsed) = key_from_str(&k) {
                        rebuilt.insert(parsed, v);
                    }
                }
                guard.containers = rebuilt;
            } else {
                debug!("install_snapshot: payload not in Phase 16 shape, leaving containers as-is");
            }
        }
        guard.current_snapshot = Some(StoredSnapshot {
            meta: meta.clone(),
            data,
        });
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<LinpodxRaft>>, StorageError<NodeId>> {
        let guard = self.inner.read().await;
        Ok(guard.current_snapshot.as_ref().map(|s| Snapshot {
            meta: s.meta.clone(),
            snapshot: Box::new(Cursor::new(s.data.clone())),
        }))
    }
}

// Defensive helpers — openraft's StorageIOError builders need a concrete cause.
trait IntoStorageError {
    fn into_storage_error(self) -> StorageError<NodeId>;
}

impl IntoStorageError for StorageIOError<NodeId> {
    fn into_storage_error(self) -> StorageError<NodeId> {
        self.into()
    }
}

// ---------------------------------------------------------------------------
// RaftNode — the public facade.
// ---------------------------------------------------------------------------

type RaftEngine = openraft::Raft<LinpodxRaft>;

/// Lightweight handle to the openraft engine plus the metric watcher used by
/// [`Self::current_leader`] / [`Self::current_role`].
#[derive(Clone)]
pub struct RaftNode {
    inner: Arc<RaftNodeInner>,
}

struct RaftNodeInner {
    raft: RaftEngine,
    config: RaftStartConfig,
    label_map: StdMutex<BTreeMap<NodeId, String>>,
    /// Last-known `host:port` for each NodeId we have ever added as a learner
    /// (or that we self-bootstrapped with). Used by [`RaftNode::membership_snapshot`]
    /// since openraft's `BasicNode.addr` is reachable through the metrics borrow but
    /// requires holding it across an await boundary; mirroring it locally lets the
    /// IPC arm return without taking the watch lock.
    addr_map: StdMutex<BTreeMap<NodeId, String>>,
    /// Last metric snapshot — refreshed by the background `metric_pump` task.
    /// Held in a watch channel so accessors are non-blocking.
    metrics_rx: watch::Receiver<MetricSnapshot>,
    /// Audit sink shared with the membership-mutation helpers
    /// ([`RaftNode::add_learner_with_audit`] / [`RaftNode::promote_with_audit`])
    /// so promotions/demotions surface in the daemon audit log.
    audit: Option<Arc<dyn AuditSink>>,
    /// Provides access to the underlying `MemStore` for tests / membership
    /// queries that the openraft API doesn't surface directly.
    store: MemStore,
}

#[derive(Debug, Clone, Default)]
pub struct MetricSnapshot {
    pub current_leader: Option<NodeId>,
    pub server_state: Option<ServerState>,
    pub current_term: u64,
    pub last_log_index: Option<u64>,
}

/// Phase 16 Stream A — replicated container view as observed by the local
/// state machine. The IPC `cluster.state_get` and `cluster.container_view`
/// arms map this into wire types (`ClusterStateGetResponse` /
/// `ClusterContainerViewResponse`).
#[derive(Debug, Clone, Default)]
pub struct ClusterStateSnapshot {
    /// `last_applied_log_id.index` — monotonically non-decreasing; reset to 0
    /// only by snapshot install.
    pub last_applied: u64,
    /// `(source_node_label, container_summary)` pairs in deterministic
    /// `(node_id, container_id)` order.
    pub containers: Vec<(String, linpodx_common::state::ContainerSummary)>,
}

impl From<&RaftMetrics<NodeId, BasicNode>> for MetricSnapshot {
    fn from(m: &RaftMetrics<NodeId, BasicNode>) -> Self {
        Self {
            current_leader: m.current_leader,
            server_state: Some(m.state),
            current_term: m.current_term,
            last_log_index: m.last_log_index,
        }
    }
}

/// One row of a [`MembershipSnapshot`]. Wire-friendly — no openraft types
/// leak through.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipNodeView {
    pub node_id: NodeId,
    pub label: Option<String>,
    pub addr: Option<String>,
}

/// Returned by [`RaftNode::membership_snapshot`]. Used by the daemon's
/// `cluster.raft_status` IPC arm to describe the current cluster topology
/// without exposing openraft types to the wire schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipSnapshot {
    pub voters: Vec<MembershipNodeView>,
    pub learners: Vec<MembershipNodeView>,
    pub current_term: u64,
}

impl RaftNode {
    /// Build a `RaftNode` with the placeholder `NoopNetworkFactory` (single-node
    /// path). Equivalent to `start_with_network(cfg, vote_sink, audit, NoopNetworkFactory)`.
    pub async fn start(
        cfg: RaftStartConfig,
        vote_sink: Option<Arc<dyn VoteSink>>,
        audit: Option<Arc<dyn AuditSink>>,
    ) -> std::result::Result<Self, ClusterError> {
        Self::start_with_network(cfg, vote_sink, audit, NoopNetworkFactory).await
    }

    /// Build a `RaftNode` with a caller-provided
    /// [`openraft::network::RaftNetworkFactory`]. The Phase 15 daemon plugs in
    /// [`crate::raft_http::RaftHttpFactory`] here so multi-node replication actually
    /// flows over HTTP; tests / single-node deployments keep using
    /// `NoopNetworkFactory` via [`Self::start`].
    pub async fn start_with_network<F>(
        cfg: RaftStartConfig,
        vote_sink: Option<Arc<dyn VoteSink>>,
        audit: Option<Arc<dyn AuditSink>>,
        network: F,
    ) -> std::result::Result<Self, ClusterError>
    where
        F: RaftNetworkFactory<LinpodxRaft>,
    {
        let store = match vote_sink {
            Some(s) => MemStore::with_vote_sink(s),
            None => MemStore::new(),
        };
        store.load_persisted_vote().await;

        let raft_config = Config {
            cluster_name: "linpodx-cluster".into(),
            heartbeat_interval: cfg.heartbeat_ms,
            election_timeout_min: cfg.election_timeout_min_ms,
            election_timeout_max: cfg.election_timeout_max_ms,
            ..Default::default()
        }
        .validate()
        .map_err(|e| ClusterError::Storage(format!("openraft config invalid: {e}")))?;

        let (log_store, state_machine) = Adaptor::new(store.clone());
        let raft = openraft::Raft::<LinpodxRaft>::new(
            cfg.node_id,
            Arc::new(raft_config),
            network,
            log_store,
            state_machine,
        )
        .await
        .map_err(|e| ClusterError::Storage(format!("openraft init failed: {e}")))?;

        if cfg.bootstrap_single_node {
            let mut members = BTreeMap::new();
            members.insert(cfg.node_id, BasicNode::new(cfg.advertise_addr.clone()));
            match raft.initialize(members).await {
                Ok(()) => info!(
                    node_id = cfg.node_id,
                    addr = %cfg.advertise_addr,
                    "raft: single-node bootstrap done"
                ),
                Err(RaftError::APIError(InitializeError::NotAllowed(_))) => {
                    debug!(
                        "raft: initialize() skipped — node already initialized from persisted state"
                    );
                }
                Err(e) => {
                    return Err(ClusterError::Storage(format!(
                        "raft initialize failed: {e}"
                    )));
                }
            }
        }

        let metrics_rx = raft.metrics();
        let (snap_tx, snap_rx) = watch::channel(MetricSnapshot::default());
        let mut label_map = BTreeMap::new();
        label_map.insert(cfg.node_id, cfg.node_label.clone());
        let mut addr_map = BTreeMap::new();
        addr_map.insert(cfg.node_id, cfg.advertise_addr.clone());
        let inner = Arc::new(RaftNodeInner {
            raft,
            config: cfg.clone(),
            label_map: StdMutex::new(label_map),
            addr_map: StdMutex::new(addr_map),
            metrics_rx: snap_rx,
            audit: audit.clone(),
            store,
        });

        // Spawn the metric-pump task that translates openraft watch updates
        // into MetricSnapshot + audit events for leader transitions.
        let inner_clone = Arc::clone(&inner);
        tokio::spawn(metric_pump(inner_clone, metrics_rx, snap_tx, audit));

        Ok(Self { inner })
    }

    /// Best-effort current leader as a friendly string label. Returns `None`
    /// when the cluster is in an election or this node has just started.
    pub fn current_leader(&self) -> Option<String> {
        let snap = self.inner.metrics_rx.borrow();
        snap.current_leader.and_then(|id| {
            let map = self.inner.label_map.lock().ok()?;
            map.get(&id).cloned().or(Some(id.to_string()))
        })
    }

    pub fn current_role(&self) -> LeaderState {
        let snap = self.inner.metrics_rx.borrow();
        snap.server_state
            .map(LeaderState::from)
            .unwrap_or(LeaderState::Unknown)
    }

    pub fn node_label(&self) -> &str {
        &self.inner.config.node_label
    }

    pub fn node_id(&self) -> NodeId {
        self.inner.config.node_id
    }

    pub fn snapshot(&self) -> MetricSnapshot {
        self.inner.metrics_rx.borrow().clone()
    }

    /// Add a peer as a learner (non-voting). `node_id` is the deterministic
    /// numeric id derived from the gossip label; `addr` is `host:port`.
    pub async fn add_learner(
        &self,
        label: String,
        addr: String,
    ) -> std::result::Result<(), ClusterError> {
        let id = node_id_from_string(&label);
        if let Ok(mut map) = self.inner.label_map.lock() {
            map.insert(id, label.clone());
        }
        if let Ok(mut map) = self.inner.addr_map.lock() {
            map.insert(id, addr.clone());
        }
        match self
            .inner
            .raft
            .add_learner(id, BasicNode::new(addr.clone()), true)
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => Err(ClusterError::Storage(format!(
                "raft.add_learner({label}, {addr}) failed: {e}"
            ))),
        }
    }

    /// Phase 15 — counterpart to [`Self::add_learner`] that also records the
    /// learner-add into the audit sink (when one was wired at startup). Adding
    /// a learner is *not* a promotion, so it emits no `ClusterRaftPromoted`
    /// event — but having an audit trail of the membership change is useful
    /// for debugging multi-node bring-up.
    pub async fn add_learner_with_audit(
        &self,
        label: String,
        addr: String,
    ) -> std::result::Result<(), ClusterError> {
        let id = node_id_from_string(&label);
        let res = self.add_learner(label.clone(), addr.clone()).await;
        if res.is_ok() {
            if let Some(sink) = self.inner.audit.as_ref() {
                let payload = serde_json::json!({
                    "event": "raft_learner_added",
                    "node_id": id,
                    "node_label": label,
                    "addr": addr,
                    "ts": Utc::now().to_rfc3339(),
                });
                sink.record(AuditSinkKind::ClusterRaftPromoted, None, None, payload)
                    .await;
            }
        }
        res
    }

    /// Promote a previously-added learner into the voting set. Calls
    /// `change_membership` with `retain=false` so removed nodes are dropped.
    pub async fn promote_to_voter(
        &self,
        labels: &[String],
    ) -> std::result::Result<(), ClusterError> {
        let mut ids = BTreeSet::new();
        ids.insert(self.inner.config.node_id);
        for l in labels {
            ids.insert(node_id_from_string(l));
        }
        self.inner
            .raft
            .change_membership(ids, false)
            .await
            .map_err(|e| ClusterError::Storage(format!("raft.change_membership failed: {e}")))?;
        Ok(())
    }

    /// Phase 15 — promote one or more labels to voter and emit
    /// [`AuditSinkKind::ClusterRaftPromoted`] for each label that was *not*
    /// already a voter before the call (so repeated promotion calls are quiet).
    /// Returns the labels that were newly promoted.
    pub async fn promote_with_audit(
        &self,
        labels: &[String],
    ) -> std::result::Result<Vec<String>, ClusterError> {
        let metrics = self.inner.raft.metrics().borrow().clone();
        let prior_voters: BTreeSet<NodeId> =
            metrics.membership_config.membership().voter_ids().collect();
        let mut newly_promoted: Vec<String> = Vec::new();
        for l in labels {
            let id = node_id_from_string(l);
            if !prior_voters.contains(&id) {
                newly_promoted.push(l.clone());
            }
        }
        self.promote_to_voter(labels).await?;
        if let Some(sink) = self.inner.audit.as_ref() {
            for l in &newly_promoted {
                let id = node_id_from_string(l);
                let payload = serde_json::json!({
                    "event": "raft_promoted_to_voter",
                    "node_id": id,
                    "node_label": l,
                    "term": metrics.current_term,
                    "ts": Utc::now().to_rfc3339(),
                });
                sink.record(AuditSinkKind::ClusterRaftPromoted, None, None, payload)
                    .await;
            }
        }
        Ok(newly_promoted)
    }

    /// Remove a peer from the cluster. Best-effort — if the node was never
    /// added the call is silently ignored.
    pub async fn remove_node(&self, label: &str) -> std::result::Result<(), ClusterError> {
        let id = node_id_from_string(label);
        // Compute the new voter set by fetching current membership from
        // metrics, then dropping the removed id.
        let metrics = self.inner.raft.metrics().borrow().clone();
        let current = metrics.membership_config.membership().voter_ids();
        let mut new_ids: BTreeSet<NodeId> = current.collect();
        let was_voter = new_ids.remove(&id);
        if new_ids.is_empty() {
            // Refuse to leave the cluster empty — that would prevent any
            // future election.
            return Err(ClusterError::Storage(
                "refusing to remove the last voter".into(),
            ));
        }
        self.inner
            .raft
            .change_membership(new_ids, false)
            .await
            .map_err(|e| {
                ClusterError::Storage(format!("raft.change_membership remove failed: {e}"))
            })?;
        if let Ok(mut map) = self.inner.label_map.lock() {
            map.remove(&id);
        }
        if let Ok(mut map) = self.inner.addr_map.lock() {
            map.remove(&id);
        }
        // Only emit the demotion audit when the node was actually a voter
        // before this call — removing a learner is not a demotion.
        if was_voter {
            if let Some(sink) = self.inner.audit.as_ref() {
                let payload = serde_json::json!({
                    "event": "raft_voter_removed",
                    "node_id": id,
                    "node_label": label,
                    "term": metrics.current_term,
                    "ts": Utc::now().to_rfc3339(),
                });
                sink.record(AuditSinkKind::ClusterRaftDemoted, None, None, payload)
                    .await;
            }
        }
        Ok(())
    }

    /// Phase 16 Stream A — Raft state machine snapshot accessor. Returns the
    /// last-applied index plus the replicated container map. Cheap clone of
    /// an in-memory `BTreeMap` so callers can render IPC responses without
    /// holding any Raft locks.
    pub async fn state_snapshot(&self) -> ClusterStateSnapshot {
        self.inner.store.state_snapshot().await
    }

    /// Phase 16 Stream A — true when this node currently believes itself the
    /// Raft leader. Used by [`Self::propose_container`] (and the dispatch
    /// layer) to short-circuit a `client_write` that would only return
    /// `ForwardToLeader`.
    pub fn is_leader(&self) -> bool {
        matches!(self.current_role(), LeaderState::Leader)
    }

    /// Phase 16 Stream A — submit a container summary into the replicated
    /// state machine. Returns the assigned Raft log index on success.
    ///
    /// Callers MUST be the current leader; non-leader callers receive a
    /// [`ClusterError::Storage`] with a message starting with `"not_leader"`
    /// so the dispatch layer can surface a precise error to the client.
    /// Errors emit an [`AuditSinkKind::ClusterStateProposeFailed`] audit row;
    /// success emits [`AuditSinkKind::ClusterStateApplied`].
    pub async fn propose_container(
        &self,
        node_id: String,
        container: linpodx_common::state::ContainerSummary,
    ) -> std::result::Result<u64, ClusterError> {
        if !self.is_leader() {
            self.audit_propose_failed("not_leader", &node_id, Some(&container.id.0))
                .await;
            return Err(ClusterError::Storage(format!(
                "not_leader (current role = {:?}, current leader = {:?})",
                self.current_role(),
                self.current_leader()
            )));
        }
        let payload = AppData::ProposeContainer {
            node_id: node_id.clone(),
            container: container.clone(),
        };
        match self.inner.raft.client_write(payload).await {
            Ok(resp) => {
                let idx = resp.log_id.index;
                self.audit_propose_applied("upsert", &node_id, &container.id.0, idx)
                    .await;
                Ok(idx)
            }
            Err(e) => {
                self.audit_propose_failed(
                    &format!("client_write_failed: {e}"),
                    &node_id,
                    Some(&container.id.0),
                )
                .await;
                Err(ClusterError::Storage(format!(
                    "raft.client_write(ProposeContainer) failed: {e}"
                )))
            }
        }
    }

    /// Phase 16 Stream A — drop a `(node_id, container_id)` entry from the
    /// replicated state machine. Returns the assigned log index on success.
    /// Same leader-only rule as [`Self::propose_container`].
    pub async fn propose_container_remove(
        &self,
        node_id: String,
        container_id: String,
    ) -> std::result::Result<u64, ClusterError> {
        if !self.is_leader() {
            self.audit_propose_failed("not_leader", &node_id, Some(&container_id))
                .await;
            return Err(ClusterError::Storage(format!(
                "not_leader (current role = {:?}, current leader = {:?})",
                self.current_role(),
                self.current_leader()
            )));
        }
        let payload = AppData::RemoveContainer {
            node_id: node_id.clone(),
            container_id: container_id.clone(),
        };
        match self.inner.raft.client_write(payload).await {
            Ok(resp) => {
                let idx = resp.log_id.index;
                self.audit_propose_applied("remove", &node_id, &container_id, idx)
                    .await;
                Ok(idx)
            }
            Err(e) => {
                self.audit_propose_failed(
                    &format!("client_write_failed: {e}"),
                    &node_id,
                    Some(&container_id),
                )
                .await;
                Err(ClusterError::Storage(format!(
                    "raft.client_write(RemoveContainer) failed: {e}"
                )))
            }
        }
    }

    /// Phase 17 Stream C — install the plugin-key revocation sink on the
    /// underlying `MemStore`. The daemon calls this after constructing both
    /// the Raft node and the sandbox `KeyRegistry` so every applied
    /// `RevokePluginKey` entry hits the local registry.
    pub fn set_plugin_revocation_sink(&self, sink: Arc<dyn PluginRevocationSink>) {
        self.inner.store.set_plugin_revocation_sink(sink);
    }

    /// Phase 17 Stream C — propose a cluster-wide plugin-key revocation. Same
    /// leader-only rule as the container-view proposers. The caller has
    /// already verified leadership via [`Self::is_leader`] in the dispatch
    /// layer, but we re-check here so direct callers (tests, future helpers)
    /// stay safe. Returns the assigned Raft log index on success.
    pub async fn propose_plugin_key_revocation(
        &self,
        publisher: String,
        fingerprint: String,
        reason: Option<String>,
        revoked_at: i64,
    ) -> std::result::Result<u64, ClusterError> {
        if !self.is_leader() {
            return Err(ClusterError::Storage(format!(
                "not_leader (current role = {:?}, current leader = {:?})",
                self.current_role(),
                self.current_leader()
            )));
        }
        let payload = AppData::RevokePluginKey {
            publisher: publisher.clone(),
            fingerprint: fingerprint.clone(),
            reason: reason.clone(),
            revoked_at,
        };
        match self.inner.raft.client_write(payload).await {
            Ok(resp) => Ok(resp.log_id.index),
            Err(e) => Err(ClusterError::Storage(format!(
                "raft.client_write(RevokePluginKey) failed: {e}"
            ))),
        }
    }

    async fn audit_propose_applied(
        &self,
        op: &str,
        node_id: &str,
        container_id: &str,
        log_index: u64,
    ) {
        let Some(sink) = self.inner.audit.as_ref() else {
            return;
        };
        let payload = serde_json::json!({
            "op": op,
            "node_id": node_id,
            "container_id": container_id,
            "log_index": log_index,
            "ts": Utc::now().to_rfc3339(),
        });
        sink.record(
            AuditSinkKind::ClusterStateApplied,
            None,
            Some(container_id.to_string()),
            payload,
        )
        .await;
    }

    async fn audit_propose_failed(&self, reason: &str, node_id: &str, container_id: Option<&str>) {
        let Some(sink) = self.inner.audit.as_ref() else {
            return;
        };
        let payload = serde_json::json!({
            "reason": reason,
            "node_id": node_id,
            "container_id": container_id,
            "ts": Utc::now().to_rfc3339(),
        });
        sink.record(
            AuditSinkKind::ClusterStateProposeFailed,
            None,
            container_id.map(|s| s.to_string()),
            payload,
        )
        .await;
    }

    /// Phase 15 — return the current membership broken down into voter and
    /// learner sets, each with the friendly label / advertised `host:port` we
    /// have on file. Used by the `cluster.raft_status` IPC arm.
    pub fn membership_snapshot(&self) -> MembershipSnapshot {
        let metrics = self.inner.raft.metrics().borrow().clone();
        let mem = metrics.membership_config.membership();
        let voter_ids: BTreeSet<NodeId> = mem.voter_ids().collect();
        let learner_ids: BTreeSet<NodeId> = mem.learner_ids().collect();
        let label_map = self
            .inner
            .label_map
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();
        let addr_map = self
            .inner
            .addr_map
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();
        let collect = |ids: &BTreeSet<NodeId>| -> Vec<MembershipNodeView> {
            ids.iter()
                .map(|id| MembershipNodeView {
                    node_id: *id,
                    label: label_map.get(id).cloned(),
                    addr: addr_map
                        .get(id)
                        .cloned()
                        .or_else(|| mem.get_node(id).map(|n| n.addr.clone())),
                })
                .collect()
        };
        MembershipSnapshot {
            voters: collect(&voter_ids),
            learners: collect(&learner_ids),
            current_term: metrics.current_term,
        }
    }

    /// Used by [`crate::raft_http`] to dispatch incoming RPCs to the engine.
    pub fn raft(&self) -> &RaftEngine {
        &self.inner.raft
    }

    /// Used by tests + the audit pump for direct membership inspection.
    pub fn known_labels(&self) -> Vec<String> {
        self.inner
            .label_map
            .lock()
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Best-effort shutdown for tests. Production callers usually let the
    /// daemon's `Drop` propagate.
    pub async fn shutdown(self) {
        let _ = self.inner.raft.shutdown().await;
    }

    pub fn store(&self) -> &MemStore {
        &self.inner.store
    }
}

async fn metric_pump(
    inner: Arc<RaftNodeInner>,
    mut rx: watch::Receiver<RaftMetrics<NodeId, BasicNode>>,
    tx: watch::Sender<MetricSnapshot>,
    audit: Option<Arc<dyn AuditSink>>,
) {
    let me = inner.config.node_id;
    let mut prev_state: Option<ServerState> = None;
    loop {
        let snap = MetricSnapshot::from(&*rx.borrow());
        let new_leader = snap.current_leader;
        let new_state = snap.server_state;
        if let Some(audit_sink) = audit.as_ref() {
            let was_leader = prev_state == Some(ServerState::Leader);
            let is_leader = new_state == Some(ServerState::Leader);
            if !was_leader && is_leader {
                let payload = serde_json::json!({
                    "node_id": me,
                    "node_label": inner.config.node_label,
                    "term": snap.current_term,
                    "ts": Utc::now().to_rfc3339(),
                });
                audit_sink
                    .record(AuditSinkKind::ClusterLeaderElected, None, None, payload)
                    .await;
            } else if was_leader && !is_leader {
                let payload = serde_json::json!({
                    "node_id": me,
                    "node_label": inner.config.node_label,
                    "term": snap.current_term,
                    "new_leader": new_leader,
                    "ts": Utc::now().to_rfc3339(),
                });
                audit_sink
                    .record(AuditSinkKind::ClusterLeaderLost, None, None, payload)
                    .await;
            }
        }
        prev_state = new_state;
        let _ = tx.send(snap);
        if rx.changed().await.is_err() {
            break;
        }
    }
    debug!("raft metric_pump exited");
}

// ---------------------------------------------------------------------------
// NoopNetworkFactory — placeholder used until raft_http wires real RPC.
//
// In single-node bootstrap mode the engine never tries to call the network so
// the empty impl is correct. For multi-node the daemon swaps a real factory
// via `RaftNode::start_with_network` (added when raft_http lands).
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
struct NoopNetworkFactory;

impl openraft::network::RaftNetworkFactory<LinpodxRaft> for NoopNetworkFactory {
    type Network = NoopNetwork;
    async fn new_client(&mut self, target: NodeId, _node: &BasicNode) -> Self::Network {
        NoopNetwork { target }
    }
}

#[derive(Debug)]
struct NoopNetwork {
    target: NodeId,
}

impl openraft::network::RaftNetwork<LinpodxRaft> for NoopNetwork {
    async fn append_entries(
        &mut self,
        _rpc: openraft::raft::AppendEntriesRequest<LinpodxRaft>,
        _option: openraft::network::RPCOption,
    ) -> Result<
        openraft::raft::AppendEntriesResponse<NodeId>,
        openraft::error::RPCError<NodeId, BasicNode, openraft::error::RaftError<NodeId>>,
    > {
        warn!(
            target = self.target,
            "raft: append_entries to placeholder network"
        );
        Err(openraft::error::RPCError::Unreachable(
            openraft::error::Unreachable::new(&std::io::Error::other("noop network")),
        ))
    }

    async fn install_snapshot(
        &mut self,
        _rpc: openraft::raft::InstallSnapshotRequest<LinpodxRaft>,
        _option: openraft::network::RPCOption,
    ) -> Result<
        openraft::raft::InstallSnapshotResponse<NodeId>,
        openraft::error::RPCError<
            NodeId,
            BasicNode,
            openraft::error::RaftError<NodeId, openraft::error::InstallSnapshotError>,
        >,
    > {
        Err(openraft::error::RPCError::Unreachable(
            openraft::error::Unreachable::new(&std::io::Error::other("noop network")),
        ))
    }

    async fn vote(
        &mut self,
        _rpc: openraft::raft::VoteRequest<NodeId>,
        _option: openraft::network::RPCOption,
    ) -> Result<
        openraft::raft::VoteResponse<NodeId>,
        openraft::error::RPCError<NodeId, BasicNode, openraft::error::RaftError<NodeId>>,
    > {
        Err(openraft::error::RPCError::Unreachable(
            openraft::error::Unreachable::new(&std::io::Error::other("noop network")),
        ))
    }
}

// Make `Membership` available to crate users (re-export so `gossip.rs`
// doesn't need to import openraft directly).
pub use openraft::Membership as RaftMembership;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn fast_cfg(node_id: NodeId, label: &str) -> RaftStartConfig {
        RaftStartConfig {
            node_id,
            node_label: label.into(),
            advertise_addr: format!("127.0.0.1:{}", 17878 + node_id as u16),
            heartbeat_ms: 50,
            election_timeout_min_ms: 200,
            election_timeout_max_ms: 400,
            bootstrap_single_node: true,
        }
    }

    /// Wait up to `Duration` for `pred` to return true. Avoids racy
    /// fixed-sleep assertions.
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

    #[tokio::test]
    async fn node_id_from_string_is_stable() {
        let a = node_id_from_string("node-a");
        let b = node_id_from_string("node-a");
        let c = node_id_from_string("node-b");
        assert_eq!(a, b, "same label maps to same id");
        assert_ne!(a, c, "different labels diverge");
        assert_eq!(node_id_from_string("local"), 1);
    }

    #[tokio::test]
    async fn node_id_avoids_reserved_low_values() {
        // Synthesize a label whose hash collides into the 0/1 reserved
        // range — the helper bumps it to >=2.
        for label in ["x", "yz", "abcd", "foo-bar", "node-99"] {
            let id = node_id_from_string(label);
            assert!(id >= 2, "label {label} -> {id} must be >=2");
        }
    }

    #[tokio::test]
    async fn single_node_becomes_leader() {
        let node = RaftNode::start(fast_cfg(1, "alpha"), None, None)
            .await
            .expect("start");
        wait_for(Duration::from_secs(2), || {
            node.current_role() == LeaderState::Leader
        })
        .await;
        assert_eq!(node.current_role(), LeaderState::Leader);
        assert_eq!(node.current_leader(), Some("alpha".to_string()));
        node.shutdown().await;
    }

    #[tokio::test]
    async fn current_role_is_unknown_before_metrics() {
        // Bootstrap disabled so no election runs immediately.
        let cfg = RaftStartConfig {
            bootstrap_single_node: false,
            ..fast_cfg(1, "alpha")
        };
        let node = RaftNode::start(cfg, None, None).await.expect("start");
        // Role may be Unknown OR transition into Follower/Candidate quickly;
        // accept either, but reject Leader (no quorum).
        let role = node.current_role();
        assert_ne!(role, LeaderState::Leader);
        node.shutdown().await;
    }

    #[tokio::test]
    async fn leader_state_round_trips_via_serde() {
        for v in [
            LeaderState::Leader,
            LeaderState::Follower,
            LeaderState::Candidate,
            LeaderState::Learner,
            LeaderState::Unknown,
        ] {
            let s = serde_json::to_string(&v).unwrap();
            let back: LeaderState = serde_json::from_str(&s).unwrap();
            assert_eq!(v, back);
        }
    }

    #[tokio::test]
    async fn metric_snapshot_default_is_unknown_role() {
        let s = MetricSnapshot::default();
        assert!(s.current_leader.is_none());
        assert_eq!(s.current_term, 0);
    }

    #[tokio::test]
    async fn server_state_to_leader_state_mapping() {
        assert_eq!(LeaderState::from(ServerState::Leader), LeaderState::Leader);
        assert_eq!(
            LeaderState::from(ServerState::Follower),
            LeaderState::Follower
        );
        assert_eq!(
            LeaderState::from(ServerState::Candidate),
            LeaderState::Candidate
        );
        assert_eq!(
            LeaderState::from(ServerState::Learner),
            LeaderState::Learner
        );
    }

    #[derive(Debug, Default)]
    struct CountingSink {
        saved: tokio::sync::Mutex<Vec<Vote<NodeId>>>,
    }

    #[async_trait::async_trait]
    impl VoteSink for CountingSink {
        async fn save_vote(&self, vote: &Vote<NodeId>) -> std::result::Result<(), String> {
            self.saved.lock().await.push(*vote);
            Ok(())
        }
        async fn load_vote(&self) -> std::result::Result<Option<Vote<NodeId>>, String> {
            Ok(self.saved.lock().await.last().copied())
        }
    }

    #[tokio::test]
    async fn vote_sink_receives_writes() {
        let sink = Arc::new(CountingSink::default());
        let node = RaftNode::start(fast_cfg(1, "alpha"), Some(sink.clone()), None)
            .await
            .expect("start");
        wait_for(Duration::from_secs(2), || {
            node.current_role() == LeaderState::Leader
        })
        .await;
        let saved = sink.saved.lock().await;
        assert!(!saved.is_empty(), "leader bootstrap must persist a vote");
        drop(saved);
        node.shutdown().await;
    }

    #[tokio::test]
    async fn noop_vote_sink_returns_none() {
        let s = NoopVoteSink;
        assert!(s.load_vote().await.unwrap().is_none());
        let v = Vote::new(1, 1);
        assert!(s.save_vote(&v).await.is_ok());
    }

    #[tokio::test]
    async fn known_labels_includes_self() {
        let node = RaftNode::start(fast_cfg(1, "alpha"), None, None)
            .await
            .expect("start");
        let labels = node.known_labels();
        assert!(labels.iter().any(|l| l == "alpha"));
        node.shutdown().await;
    }

    #[derive(Debug, Default)]
    struct CountingAudit {
        records: tokio::sync::Mutex<Vec<AuditSinkKind>>,
    }

    impl AuditSink for CountingAudit {
        fn record(
            &self,
            kind: AuditSinkKind,
            _profile_name: Option<String>,
            _container_id: Option<String>,
            _payload: serde_json::Value,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
            Box::pin(async move {
                self.records.lock().await.push(kind);
            })
        }
    }

    #[tokio::test]
    async fn audit_sink_records_leader_elected_event() {
        let audit = Arc::new(CountingAudit::default());
        let node = RaftNode::start(
            fast_cfg(1, "alpha"),
            None,
            Some(audit.clone() as Arc<dyn AuditSink>),
        )
        .await
        .expect("start");
        wait_for(Duration::from_secs(3), || {
            node.current_role() == LeaderState::Leader
        })
        .await;
        // Give the metric_pump a beat to fire its audit record.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let recs = audit.records.lock().await;
        assert!(
            recs.contains(&AuditSinkKind::ClusterLeaderElected),
            "expected ClusterLeaderElected, got {:?}",
            *recs
        );
        drop(recs);
        node.shutdown().await;
    }

    #[tokio::test]
    async fn current_leader_returns_label_not_numeric_id() {
        let node = RaftNode::start(fast_cfg(1, "alpha"), None, None)
            .await
            .expect("start");
        wait_for(Duration::from_secs(2), || {
            node.current_role() == LeaderState::Leader
        })
        .await;
        let leader = node.current_leader().expect("leader");
        assert_eq!(leader, "alpha");
        node.shutdown().await;
    }

    #[tokio::test]
    async fn add_learner_records_label_mapping() {
        let node = RaftNode::start(fast_cfg(1, "alpha"), None, None)
            .await
            .expect("start");
        wait_for(Duration::from_secs(2), || {
            node.current_role() == LeaderState::Leader
        })
        .await;
        // Add a learner — the network is noop so the actual replication
        // will fail, but the label map and the openraft membership change
        // entry must still be processed.
        let _ = node
            .add_learner("beta".into(), "127.0.0.1:17999".into())
            .await;
        let labels = node.known_labels();
        assert!(labels.contains(&"alpha".to_string()));
        assert!(labels.contains(&"beta".to_string()));
        node.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_is_idempotent_in_drop_path() {
        let node = RaftNode::start(fast_cfg(1, "alpha"), None, None)
            .await
            .expect("start");
        node.shutdown().await;
    }

    #[tokio::test]
    async fn sqlite_vote_sink_round_trips_vote() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("raft.db");
        let db = linpodx_common::db::Database::open(&path).await.unwrap();
        db.migrate().await.unwrap();
        let sink = SqliteVoteSink::new(Arc::new(db));
        assert!(sink.load_vote().await.unwrap().is_none());
        let v = Vote::new(7, 42);
        sink.save_vote(&v).await.unwrap();
        let back = sink.load_vote().await.unwrap().unwrap();
        assert_eq!(back, v);
        // Overwrite — value is upserted, not appended.
        let v2 = Vote::new(8, 42);
        sink.save_vote(&v2).await.unwrap();
        let back2 = sink.load_vote().await.unwrap().unwrap();
        assert_eq!(back2, v2);
    }

    // ---- Phase 15 Stream A — multi-node membership tests ----

    #[tokio::test]
    async fn membership_snapshot_single_node_lists_only_self() {
        let node = RaftNode::start(fast_cfg(1, "alpha"), None, None)
            .await
            .expect("start");
        wait_for(Duration::from_secs(2), || {
            node.current_role() == LeaderState::Leader
        })
        .await;
        let snap = node.membership_snapshot();
        assert_eq!(snap.voters.len(), 1, "single-node membership has one voter");
        assert!(snap.learners.is_empty(), "no learners on bootstrap");
        let me = &snap.voters[0];
        assert_eq!(me.node_id, 1);
        assert_eq!(me.label.as_deref(), Some("alpha"));
        assert!(me.addr.as_deref().unwrap_or("").contains("127.0.0.1:"));
        node.shutdown().await;
    }

    #[tokio::test]
    async fn add_learner_records_addr_in_snapshot() {
        let node = RaftNode::start(fast_cfg(1, "alpha"), None, None)
            .await
            .expect("start");
        wait_for(Duration::from_secs(2), || {
            node.current_role() == LeaderState::Leader
        })
        .await;
        // Best-effort — the noop network will fail to actually replicate, but
        // the local label/addr maps update synchronously before the openraft
        // call is made, so the snapshot picks up the entry regardless.
        let _ = node
            .add_learner("beta".into(), "127.0.0.1:18999".into())
            .await;
        let snap = node.membership_snapshot();
        let labels: Vec<_> = snap
            .voters
            .iter()
            .chain(snap.learners.iter())
            .filter_map(|v| v.label.clone())
            .collect();
        assert!(labels.contains(&"beta".to_string()));
        node.shutdown().await;
    }

    #[tokio::test]
    async fn add_learner_with_audit_emits_event() {
        let audit = Arc::new(CountingAudit::default());
        let node = RaftNode::start(
            fast_cfg(1, "alpha"),
            None,
            Some(audit.clone() as Arc<dyn AuditSink>),
        )
        .await
        .expect("start");
        wait_for(Duration::from_secs(2), || {
            node.current_role() == LeaderState::Leader
        })
        .await;
        let _ = node
            .add_learner_with_audit("beta".into(), "127.0.0.1:18001".into())
            .await;
        // Election event always fires; the learner-add event must also be
        // present in the audit sink record list.
        let recs = audit.records.lock().await;
        assert!(
            recs.iter()
                .any(|k| matches!(k, AuditSinkKind::ClusterRaftPromoted)),
            "expected ClusterRaftPromoted, got {:?}",
            *recs
        );
        drop(recs);
        node.shutdown().await;
    }

    #[tokio::test]
    async fn promote_with_audit_no_op_for_empty_label_list() {
        // promote_with_audit with no labels still re-asserts the local voter
        // set (== {self}), which is a no-op. No new ClusterRaftPromoted
        // records should be emitted; the prior_voters set already includes
        // every id we'd try to add.
        let audit = Arc::new(CountingAudit::default());
        let node = RaftNode::start(
            fast_cfg(1, "alpha"),
            None,
            Some(audit.clone() as Arc<dyn AuditSink>),
        )
        .await
        .expect("start");
        wait_for(Duration::from_secs(2), || {
            node.current_role() == LeaderState::Leader
        })
        .await;
        let recs_before = audit.records.lock().await.len();
        let newly = node.promote_with_audit(&[]).await.expect("promote");
        assert!(newly.is_empty(), "no labels => no newly promoted");
        let recs_after = audit.records.lock().await.len();
        // Filter to only ClusterRaftPromoted to stay robust to other audit
        // chatter.
        let promoted_count = audit
            .records
            .lock()
            .await
            .iter()
            .filter(|k| matches!(k, AuditSinkKind::ClusterRaftPromoted))
            .count();
        assert_eq!(promoted_count, 0, "no promotion records on empty input");
        let _ = (recs_before, recs_after);
        node.shutdown().await;
    }

    #[tokio::test]
    async fn membership_snapshot_serializes_to_json_round_trip() {
        // The status response uses MembershipNodeView via responses::; verify
        // the bare type at this layer round-trips so the IPC wire path can rely
        // on it.
        let s = MembershipSnapshot {
            voters: vec![MembershipNodeView {
                node_id: 1,
                label: Some("alpha".into()),
                addr: Some("127.0.0.1:7878".into()),
            }],
            learners: vec![MembershipNodeView {
                node_id: 99,
                label: None,
                addr: Some("10.0.0.5:7878".into()),
            }],
            current_term: 4,
        };
        let j = serde_json::to_string(&s).unwrap();
        let back: MembershipSnapshot = serde_json::from_str(&j).unwrap();
        assert_eq!(back.voters.len(), 1);
        assert_eq!(back.learners.len(), 1);
        assert_eq!(back.current_term, 4);
        assert_eq!(back.voters[0].label.as_deref(), Some("alpha"));
        assert_eq!(back.learners[0].node_id, 99);
    }

    #[tokio::test]
    async fn start_with_network_uses_explicit_factory() {
        // Pass an explicit NoopNetworkFactory to verify the generic path
        // compiles and the bootstrap still elects.
        let node =
            RaftNode::start_with_network(fast_cfg(1, "alpha"), None, None, NoopNetworkFactory)
                .await
                .expect("start_with_network");
        wait_for(Duration::from_secs(2), || {
            node.current_role() == LeaderState::Leader
        })
        .await;
        assert_eq!(node.current_role(), LeaderState::Leader);
        node.shutdown().await;
    }

    #[tokio::test]
    async fn start_with_real_http_factory_compiles() {
        // RaftHttpFactory is the production multi-node factory. We can't drive
        // a full election here without a live HTTP listener, but feeding it
        // into start_with_network proves the generic bound holds and the
        // single-node bootstrap still happens locally (replication never
        // tries to dial since voters == {self}).
        let factory = crate::raft_http::RaftHttpFactory::new();
        let node = RaftNode::start_with_network(fast_cfg(1, "alpha"), None, None, factory)
            .await
            .expect("start_with_network http");
        wait_for(Duration::from_secs(2), || {
            node.current_role() == LeaderState::Leader
        })
        .await;
        assert_eq!(node.current_role(), LeaderState::Leader);
        node.shutdown().await;
    }

    // ---- Phase 16 Stream A — replicated state machine tests ----

    fn sample_summary(id: &str, image: &str) -> linpodx_common::state::ContainerSummary {
        use linpodx_common::state::{ContainerState, ContainerSummary};
        use linpodx_common::types::ContainerId;
        ContainerSummary {
            id: ContainerId(id.into()),
            names: vec![format!("name-{id}")],
            image: image.into(),
            state: ContainerState::Running,
            status: "Up".into(),
            created: Utc::now(),
            command: None,
            ports: vec![],
            labels: Default::default(),
        }
    }

    /// Wait up to `timeout` for the leader to *be* leader. Single-node
    /// bootstrap usually wins within ~250ms; we give a generous deadline so
    /// CI under load doesn't flake.
    async fn wait_until_leader(node: &RaftNode) {
        wait_for(Duration::from_secs(3), || {
            node.current_role() == LeaderState::Leader
        })
        .await;
        assert_eq!(node.current_role(), LeaderState::Leader);
    }

    #[tokio::test]
    async fn propose_container_appends_entry_and_state_grows() {
        let node = RaftNode::start(fast_cfg(1, "alpha"), None, None)
            .await
            .expect("start");
        wait_until_leader(&node).await;

        let before = node.state_snapshot().await;
        let idx = node
            .propose_container("alpha".into(), sample_summary("c1", "alpine:3.20"))
            .await
            .expect("propose ok");
        assert!(idx > 0, "log index from a real Raft entry must be > 0");

        let after = node.state_snapshot().await;
        assert!(
            after.last_applied >= idx,
            "last_applied ({}) must be >= returned idx ({idx})",
            after.last_applied
        );
        assert!(
            after.last_applied >= before.last_applied,
            "last_applied is monotonic non-decreasing"
        );
        assert_eq!(after.containers.len(), 1, "one entry in state map");
        assert_eq!(after.containers[0].0, "alpha");
        assert_eq!(after.containers[0].1.id.0, "c1");
        node.shutdown().await;
    }

    #[tokio::test]
    async fn two_proposes_have_strictly_increasing_log_index() {
        let node = RaftNode::start(fast_cfg(1, "alpha"), None, None)
            .await
            .expect("start");
        wait_until_leader(&node).await;

        let i1 = node
            .propose_container("alpha".into(), sample_summary("c1", "alpine:3.20"))
            .await
            .expect("propose 1");
        let i2 = node
            .propose_container("alpha".into(), sample_summary("c2", "ubuntu:22.04"))
            .await
            .expect("propose 2");
        assert!(
            i2 > i1,
            "consecutive proposes must produce strictly increasing log indices: i1={i1}, i2={i2}"
        );
        let snap = node.state_snapshot().await;
        assert_eq!(snap.containers.len(), 2);
        node.shutdown().await;
    }

    #[tokio::test]
    async fn remove_container_drops_entry_from_state_map() {
        let node = RaftNode::start(fast_cfg(1, "alpha"), None, None)
            .await
            .expect("start");
        wait_until_leader(&node).await;

        node.propose_container("alpha".into(), sample_summary("c1", "alpine:3.20"))
            .await
            .expect("propose");
        node.propose_container("alpha".into(), sample_summary("c2", "ubuntu:22.04"))
            .await
            .expect("propose");
        let mid = node.state_snapshot().await;
        assert_eq!(mid.containers.len(), 2);

        let _ = node
            .propose_container_remove("alpha".into(), "c1".into())
            .await
            .expect("remove");
        let after = node.state_snapshot().await;
        assert_eq!(after.containers.len(), 1, "one entry remains after remove");
        assert_eq!(after.containers[0].1.id.0, "c2");
        // Removing a missing entry must still succeed (idempotent) and bump
        // last_applied.
        let pre_idx = after.last_applied;
        let _ = node
            .propose_container_remove("alpha".into(), "missing".into())
            .await
            .expect("remove of missing entry is a successful no-op");
        let after2 = node.state_snapshot().await;
        assert!(after2.last_applied > pre_idx);
        assert_eq!(after2.containers.len(), 1);
        node.shutdown().await;
    }

    #[tokio::test]
    async fn propose_when_not_leader_returns_not_leader_error() {
        // Bootstrap disabled — node never wins an election so it can't ever
        // be leader. propose_container must reject with a precise error.
        let cfg = RaftStartConfig {
            bootstrap_single_node: false,
            ..fast_cfg(1, "alpha")
        };
        let node = RaftNode::start(cfg, None, None).await.expect("start");
        // Give the engine a moment to settle; it should remain non-Leader.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_ne!(node.current_role(), LeaderState::Leader);

        let err = node
            .propose_container("alpha".into(), sample_summary("c1", "alpine:3.20"))
            .await
            .expect_err("non-leader must reject");
        let msg = format!("{err}");
        assert!(
            msg.contains("not_leader"),
            "expected 'not_leader' in error message, got: {msg}"
        );
        node.shutdown().await;
    }

    #[tokio::test]
    async fn audit_sink_records_state_applied_on_success() {
        let audit = Arc::new(CountingAudit::default());
        let node = RaftNode::start(
            fast_cfg(1, "alpha"),
            None,
            Some(audit.clone() as Arc<dyn AuditSink>),
        )
        .await
        .expect("start");
        wait_until_leader(&node).await;

        node.propose_container("alpha".into(), sample_summary("c1", "alpine:3.20"))
            .await
            .expect("propose");
        // metric_pump may fire ClusterLeaderElected too; we filter to the
        // ClusterStateApplied kind to keep this assertion precise.
        let recs = audit.records.lock().await;
        let applied_count = recs
            .iter()
            .filter(|k| matches!(k, AuditSinkKind::ClusterStateApplied))
            .count();
        assert_eq!(
            applied_count, 1,
            "exactly one ClusterStateApplied row per successful propose, got: {:?}",
            *recs
        );
        drop(recs);
        node.shutdown().await;
    }

    #[tokio::test]
    async fn audit_sink_records_state_propose_failed_on_not_leader() {
        let audit = Arc::new(CountingAudit::default());
        // bootstrap disabled => never leader => propose fails => audit row.
        let cfg = RaftStartConfig {
            bootstrap_single_node: false,
            ..fast_cfg(1, "alpha")
        };
        let node = RaftNode::start(cfg, None, Some(audit.clone() as Arc<dyn AuditSink>))
            .await
            .expect("start");
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = node
            .propose_container("alpha".into(), sample_summary("c1", "alpine:3.20"))
            .await
            .expect_err("must reject");
        let recs = audit.records.lock().await;
        let failed_count = recs
            .iter()
            .filter(|k| matches!(k, AuditSinkKind::ClusterStateProposeFailed))
            .count();
        assert!(
            failed_count >= 1,
            "expected ClusterStateProposeFailed audit, got: {:?}",
            *recs
        );
        drop(recs);
        node.shutdown().await;
    }

    #[tokio::test]
    async fn app_data_serializes_with_kind_tag() {
        // The ProposeContainer / RemoveContainer variants land in the Raft log
        // as serde_json (see openraft Entry serialization). Round-trip them
        // through serde to catch accidental rename / tag-strategy changes.
        let p = AppData::ProposeContainer {
            node_id: "alpha".into(),
            container: sample_summary("cx", "img:1"),
        };
        let s = serde_json::to_string(&p).unwrap();
        assert!(s.contains("\"kind\":\"propose_container\""), "tag: {s}");
        let back: AppData = serde_json::from_str(&s).unwrap();
        match back {
            AppData::ProposeContainer { node_id, container } => {
                assert_eq!(node_id, "alpha");
                assert_eq!(container.id.0, "cx");
            }
            other => panic!("wrong variant: {other:?}"),
        }
        let r = AppData::RemoveContainer {
            node_id: "alpha".into(),
            container_id: "cx".into(),
        };
        let s2 = serde_json::to_string(&r).unwrap();
        assert!(s2.contains("\"kind\":\"remove_container\""), "tag: {s2}");
        // Default is the Noop sentinel.
        let n = AppData::default();
        match n {
            AppData::Noop => {}
            other => panic!("default should be Noop, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn state_snapshot_is_empty_before_any_propose() {
        // ClusterContainerView dispatch arm uses last_applied + non-empty as
        // its "raft has data" signal. Newly-bootstrapped single-node clusters
        // must have an empty state map even after the leader is elected, so
        // the IPC layer falls back to gossip aggregation.
        let node = RaftNode::start(fast_cfg(1, "alpha"), None, None)
            .await
            .expect("start");
        wait_until_leader(&node).await;
        let snap = node.state_snapshot().await;
        assert!(
            snap.containers.is_empty(),
            "no proposes => empty state snapshot"
        );
        node.shutdown().await;
    }

    // ----- Phase 17 Stream C — RevokePluginKey -----

    #[derive(Debug, Clone)]
    struct RevocationRecord {
        publisher: String,
        fingerprint: String,
        reason: Option<String>,
        revoked_at: i64,
    }

    #[derive(Debug, Default)]
    struct RecordingRevocationSink {
        applied: tokio::sync::Mutex<Vec<RevocationRecord>>,
    }

    impl PluginRevocationSink for RecordingRevocationSink {
        fn apply_remote_revocation(
            &self,
            publisher: &str,
            fingerprint: &str,
            reason: Option<&str>,
            revoked_at: i64,
        ) {
            // try_lock is enough — apply is called outside the Raft engine
            // lock and tests serialize their proposes.
            if let Ok(mut guard) = self.applied.try_lock() {
                guard.push(RevocationRecord {
                    publisher: publisher.to_string(),
                    fingerprint: fingerprint.to_string(),
                    reason: reason.map(|s| s.to_string()),
                    revoked_at,
                });
            }
        }
    }

    #[tokio::test]
    async fn app_data_revoke_plugin_key_round_trips_via_serde() {
        let p = AppData::RevokePluginKey {
            publisher: "acme".into(),
            fingerprint: "abc123".into(),
            reason: Some("compromised".into()),
            revoked_at: 1_700_000_000,
        };
        let s = serde_json::to_string(&p).unwrap();
        assert!(s.contains("\"kind\":\"revoke_plugin_key\""), "tag: {s}");
        let back: AppData = serde_json::from_str(&s).unwrap();
        match back {
            AppData::RevokePluginKey {
                publisher,
                fingerprint,
                reason,
                revoked_at,
            } => {
                assert_eq!(publisher, "acme");
                assert_eq!(fingerprint, "abc123");
                assert_eq!(reason.as_deref(), Some("compromised"));
                assert_eq!(revoked_at, 1_700_000_000);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn propose_plugin_key_revocation_when_not_leader_returns_not_leader() {
        let cfg = RaftStartConfig {
            bootstrap_single_node: false,
            ..fast_cfg(1, "alpha")
        };
        let node = RaftNode::start(cfg, None, None).await.expect("start");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_ne!(node.current_role(), LeaderState::Leader);
        let err = node
            .propose_plugin_key_revocation(
                "acme".into(),
                "fp1".into(),
                Some("test".into()),
                1_700_000_000,
            )
            .await
            .expect_err("non-leader must reject");
        let msg = format!("{err}");
        assert!(
            msg.contains("not_leader"),
            "expected not_leader in error, got: {msg}"
        );
        node.shutdown().await;
    }

    #[tokio::test]
    async fn propose_plugin_key_revocation_invokes_sink_on_leader_apply() {
        let node = RaftNode::start(fast_cfg(1, "alpha"), None, None)
            .await
            .expect("start");
        wait_until_leader(&node).await;

        let sink = Arc::new(RecordingRevocationSink::default());
        node.set_plugin_revocation_sink(Arc::clone(&sink) as Arc<dyn PluginRevocationSink>);

        let log_idx = node
            .propose_plugin_key_revocation(
                "acme".into(),
                "abc".into(),
                Some("rotation".into()),
                1_700_000_000,
            )
            .await
            .expect("propose");
        assert!(log_idx > 0);

        // Give Raft a moment to deliver the apply (single-node bootstrap is
        // synchronous in practice but openraft's apply is async).
        let mut found = false;
        for _ in 0..50 {
            {
                let g = sink.applied.lock().await;
                if !g.is_empty() {
                    assert_eq!(g[0].publisher, "acme");
                    assert_eq!(g[0].fingerprint, "abc");
                    assert_eq!(g[0].reason.as_deref(), Some("rotation"));
                    assert_eq!(g[0].revoked_at, 1_700_000_000);
                    found = true;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(found, "revocation sink was never invoked");
        node.shutdown().await;
    }

    #[tokio::test]
    async fn revoke_plugin_key_apply_without_sink_advances_last_applied() {
        // Defensive: the apply path must not blow up when no sink is wired.
        // The Raft entry should still bump last_applied_index — operators may
        // intentionally run without a sink (e.g., a daemon built without the
        // sandbox feature).
        let node = RaftNode::start(fast_cfg(1, "alpha"), None, None)
            .await
            .expect("start");
        wait_until_leader(&node).await;

        let before = node.state_snapshot().await.last_applied;
        let _ = node
            .propose_plugin_key_revocation("ghost".into(), "fp".into(), None, 1_700_000_000)
            .await
            .expect("propose");
        // Wait briefly for apply.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let after = node.state_snapshot().await.last_applied;
        assert!(after > before, "last_applied must grow even without a sink");
        node.shutdown().await;
    }

    #[tokio::test]
    async fn propose_plugin_key_revocation_audit_records_zero_state_propose_failed_when_leader() {
        // The propose_plugin_key_revocation path intentionally does NOT emit
        // ClusterStateProposeFailed audit rows on the happy path — those rows
        // are reserved for container-view mutations (existing semantics).
        // This test guards against an accidental cross-wire.
        let audit = Arc::new(CountingAudit::default());
        let node = RaftNode::start(
            fast_cfg(1, "alpha"),
            None,
            Some(audit.clone() as Arc<dyn AuditSink>),
        )
        .await
        .expect("start");
        wait_until_leader(&node).await;

        let _ = node
            .propose_plugin_key_revocation("acme".into(), "fp".into(), None, 1_700_000_000)
            .await
            .expect("propose");
        tokio::time::sleep(Duration::from_millis(30)).await;
        let recs = audit.records.lock().await;
        let propose_failed = recs
            .iter()
            .filter(|k| matches!(k, AuditSinkKind::ClusterStateProposeFailed))
            .count();
        assert_eq!(propose_failed, 0);
        node.shutdown().await;
    }
}
