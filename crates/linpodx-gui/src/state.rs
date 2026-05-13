use linpodx_common::approval::{ApprovalRequest, ApprovalResolved};
use linpodx_common::ipc::responses::{
    AuditEntrySummary, DaemonPinClientTofuExpiryStatusResponse, PluginKeyEntry,
    SandboxProfileSummary, SandboxSnapshotAutoTriggerStatusResponse, SessionSummary,
    SessionTimelineEntry, SnapshotDiffResponse, SnapshotEncryptionStatusResponse, SnapshotSummary,
};
use linpodx_common::ipc::{Event, EventKind, EventTopic, MetricsSample};
use linpodx_common::state::{ContainerSummary, ImageSummary, NetworkSummary, VolumeSummary};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Tab {
    #[default]
    Containers,
    Images,
    Volumes,
    Networks,
    Sandbox,
    Audit,
    Snapshot,
    Session,
    Metrics,
    /// Phase 17 Stream C — TOFU pin-store status / countdown.
    PinnedClients,
    /// Phase 17 Stream C — plugin key revocation propagation.
    Plugins,
}

impl Tab {
    pub const ALL: [Tab; 11] = [
        Tab::Containers,
        Tab::Images,
        Tab::Volumes,
        Tab::Networks,
        Tab::Sandbox,
        Tab::Audit,
        Tab::Snapshot,
        Tab::Session,
        Tab::Metrics,
        Tab::PinnedClients,
        Tab::Plugins,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            Tab::Containers => "Containers",
            Tab::Images => "Images",
            Tab::Volumes => "Volumes",
            Tab::Networks => "Networks",
            Tab::Sandbox => "Sandbox",
            Tab::Audit => "Audit",
            Tab::Snapshot => "Snapshots",
            Tab::Session => "Sessions",
            Tab::Metrics => "Metrics",
            Tab::PinnedClients => "Pinned Clients",
            Tab::Plugins => "Plugins",
        }
    }
}

impl std::fmt::Display for Tab {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Default)]
pub enum ConnectionState {
    #[default]
    Connecting,
    Connected,
    Disconnected(String),
}

/// A snapshot from a daemon `*List` call. Carried in `Message::SnapshotLoaded`.
#[derive(Debug, Clone)]
pub enum Snapshot {
    Containers(Vec<ContainerSummary>),
    Images(Vec<ImageSummary>),
    Volumes(Vec<VolumeSummary>),
    Networks(Vec<NetworkSummary>),
}

/// Which side of the snapshot-diff selection a row maps to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffSlot {
    A,
    B,
}

/// One node in a depth-first snapshot tree built from a flat list with `parent_id` links.
/// `depth` is precomputed at build time so the renderer can indent without recursion.
#[derive(Debug, Clone)]
pub struct SnapshotTreeNode {
    pub snapshot: SnapshotSummary,
    pub depth: usize,
}

/// Build a flat depth-indexed traversal of snapshots ordered as roots → children
/// (depth-first). Roots are snapshots whose `parent_id` is `None` *or* points outside
/// the input list (so an orphaned child still renders as a root rather than vanishing).
pub fn build_snapshot_tree(snapshots: &[SnapshotSummary]) -> Vec<SnapshotTreeNode> {
    use std::collections::{BTreeMap, HashSet};

    let known: HashSet<i64> = snapshots.iter().map(|s| s.id).collect();
    let mut children: BTreeMap<i64, Vec<&SnapshotSummary>> = BTreeMap::new();
    let mut roots: Vec<&SnapshotSummary> = Vec::new();
    for s in snapshots {
        match s.parent_id {
            Some(p) if known.contains(&p) => {
                children.entry(p).or_default().push(s);
            }
            _ => roots.push(s),
        }
    }
    // Stable order by id so the GUI doesn't reshuffle on refresh.
    roots.sort_by_key(|s| s.id);
    for v in children.values_mut() {
        v.sort_by_key(|s| s.id);
    }

    let mut out = Vec::with_capacity(snapshots.len());
    let mut stack: Vec<(&SnapshotSummary, usize)> =
        roots.into_iter().rev().map(|r| (r, 0)).collect();
    while let Some((node, depth)) = stack.pop() {
        out.push(SnapshotTreeNode {
            snapshot: node.clone(),
            depth,
        });
        if let Some(kids) = children.get(&node.id) {
            for k in kids.iter().rev() {
                stack.push((*k, depth + 1));
            }
        }
    }
    out
}

#[derive(Debug, Clone)]
pub enum Message {
    TabSelected(Tab),
    ConnectionStateChanged(ConnectionState),
    SnapshotLoaded(Snapshot),
    EventReceived(Event),
    // Phase 3 additions
    SandboxLoaded(Vec<SandboxProfileSummary>),
    AuditLoaded(Vec<AuditEntrySummary>),
    SnapshotsLoaded(Vec<SnapshotSummary>),
    SessionsLoaded(Vec<SessionSummary>),
    SessionTimelineLoaded {
        session_id: i64,
        entries: Vec<SessionTimelineEntry>,
    },
    SandboxProfileSelected(String),
    SnapshotRollback(i64),
    SnapshotRemove(i64),
    /// User clicked "select A" / "select B" on a snapshot row in the tree view. The slot
    /// indicates which side of the diff selection the row should occupy.
    SnapshotSelectForDiff {
        slot: DiffSlot,
        id: i64,
    },
    /// User clicked the "Diff" button after selecting both A and B.
    SnapshotDiffRequest {
        id_a: i64,
        id_b: i64,
    },
    /// Server returned diff content for the currently selected pair.
    SnapshotDiffLoaded(SnapshotDiffResponse),
    /// User clicked "Branch" on a snapshot row.
    SnapshotBranch(i64),
    SessionSelected(i64),
    AuditFilterChanged(Option<String>),
    ApprovalReceived(ApprovalRequest),
    ApprovalResolved(ApprovalResolved),
    ApprovalReasonChanged(String),
    ApprovalDecision {
        request_id: String,
        allow: bool,
        reason: Option<String>,
    },
    /// User picked a container in the Metrics tab. The iced layer fires a one-shot
    /// `MetricsLatest` and the result lands as `MetricsLoaded`.
    MetricsContainerSelected(String),
    /// Server returned a metrics sample (or the latest from the ring) for `container_id`.
    MetricsLoaded {
        container_id: String,
        samples: Vec<MetricsSample>,
    },
    /// User clicked the Images-tab "Push" button on a row → open the push modal pre-populated
    /// with the row's reference (first repo tag, or empty if none).
    ImagePushOpen(String),
    /// User typed a registry override in the push modal.
    ImagePushRegistryChanged(String),
    /// User typed a base64(`user:pass`) auth blob in the push modal.
    ImagePushAuthChanged(String),
    /// User cancelled the push modal — reset state.
    ImagePushCancel,
    /// User submitted the push modal — fire `ImagePush` IPC. Refresh comes via Image event.
    ImagePushSubmit,
    /// Phase 11 — user clicked the `Exec` button on a container row. The iced layer
    /// turns this into a `ContainerExec` IPC; the reducer flips `exec_target` so the
    /// modal can render. Argument is the container id.
    ExecRequested(String),
    /// Phase 11 — user clicked the `Logs` button on a container row. The iced layer
    /// triggers a `ContainerLogsStream` subscription; the reducer flips `logs_target`.
    LogsRequested(String),
    /// Phase 11 — daemon delivered a log line for a container the GUI is following.
    LogLineReceived {
        container_id: String,
        stream: String,
        line: String,
    },
    /// Phase 11 — close the Exec/Logs modal target so the GUI returns to the table.
    ExecModalDismissed,
    LogsModalDismissed,
    // ----- Phase 17: snapshot key rotation / re-encryption -----
    /// User clicked "Rotate Key" on a snapshot row. Opens the key-rotation modal.
    SnapshotKeyRotateOpen(i64),
    /// User typed into the passphrase field of the key-rotation modal.
    SnapshotKeyRotatePassphraseChanged(String),
    /// User clicked the modal's Cancel button.
    SnapshotKeyRotateCancel,
    /// User clicked Confirm on the rotation modal — fires the IPC.
    SnapshotKeyRotateSubmit,
    /// Server returned the rotation result; carries the snapshot id + new algo/kdf.
    SnapshotKeyRotated {
        snapshot_id: i64,
        algorithm: String,
        kdf: String,
    },
    /// User clicked "Re-encrypt all" in the Snapshots toolbar.
    SnapshotReEncryptAllOpen,
    /// User typed into the bulk-passphrase field.
    SnapshotReEncryptAllPassphraseChanged(String),
    SnapshotReEncryptAllCancel,
    SnapshotReEncryptAllSubmit,
    SnapshotReEncryptAllDone {
        total_seen: u32,
        re_encrypted: u32,
        skipped: u32,
        failed: u32,
    },
    /// Server returned encryption metadata (algo / kdf) for a single snapshot —
    /// the badge cache absorbs it.
    SnapshotEncryptionLoaded(SnapshotEncryptionStatusResponse),
    // ----- Phase 17: TOFU expiry -----
    /// Server returned current TOFU expiry status.
    TofuExpiryLoaded(DaemonPinClientTofuExpiryStatusResponse),
    /// User typed into the "Set expiry" input on the PinnedClients tab.
    TofuExpiryInputChanged(String),
    /// User clicked Apply on the expiry input — fires the IPC with the typed seconds.
    TofuExpirySubmit,
    /// Server confirmed a new expiry value (clears the input).
    TofuExpiryUpdated(Option<u64>),
    // ----- Phase 17: plugin key revocation propagation -----
    /// Server returned the plugin key list (used to render the Plugins tab).
    PluginKeysLoaded(Vec<PluginKeyEntry>),
    /// User clicked "Revoke cluster-wide" on a row → opens the confirm modal.
    PluginKeyRevokeOpen {
        publisher: String,
        fingerprint: String,
    },
    PluginKeyRevokeCancel,
    PluginKeyRevokeSubmit,
    /// Server confirmed a cluster-wide revocation propagation.
    PluginKeyRevokePropagated {
        publisher: String,
        fingerprint: String,
        log_index: Option<u64>,
    },
    // ----- Phase 17: sandbox auto-encrypt -----
    /// Server returned the sandbox snapshot auto-trigger status.
    SandboxAutoTriggerLoaded(SandboxSnapshotAutoTriggerStatusResponse),
    /// User clicked the toggle button on the Sandbox tab.
    SandboxAutoTriggerToggle,
    NoOp,
}

#[derive(Debug, Default, Clone)]
pub struct App {
    pub socket_path: PathBuf,
    pub tab: Tab,
    pub conn: ConnectionState,
    pub containers: Vec<ContainerSummary>,
    pub images: Vec<ImageSummary>,
    pub volumes: Vec<VolumeSummary>,
    pub networks: Vec<NetworkSummary>,
    // Phase 3 fields
    pub sandbox_profiles: Vec<SandboxProfileSummary>,
    pub selected_sandbox_profile: Option<String>,
    pub audit_entries: Vec<AuditEntrySummary>,
    pub audit_filter_kind: Option<String>,
    pub snapshots: Vec<SnapshotSummary>,
    pub snapshot_diff_a: Option<i64>,
    pub snapshot_diff_b: Option<i64>,
    pub snapshot_diff: Option<SnapshotDiffResponse>,
    pub sessions: Vec<SessionSummary>,
    pub selected_session: Option<i64>,
    pub session_timeline: Vec<SessionTimelineEntry>,
    pub pending_approvals: VecDeque<ApprovalRequest>,
    pub approval_reason: String,
    /// Per-container metrics history. Keyed by container id (as the server sends it on
    /// `EventTopic::Metrics`). Capped on the daemon side (ring of 600); the GUI replaces
    /// the vec wholesale on each `MetricsLoaded`.
    pub metrics_samples: HashMap<String, Vec<MetricsSample>>,
    /// Container the Metrics tab is currently viewing. `None` falls back to the first
    /// container in the list when rendering.
    pub metrics_selected: Option<String>,
    /// In-flight image-push form state. `Some` means the modal is open.
    pub image_push_form: Option<ImagePushForm>,
    /// Phase 11 — container id whose `Exec` modal is currently open. `None` means no modal.
    pub exec_target: Option<String>,
    /// Phase 11 — container id whose `Logs` modal is currently open.
    pub logs_target: Option<String>,
    /// Phase 11 — per-container ring of streamed log lines (capped at 1000 lines per
    /// container). Pushed by `LogLineReceived`. Cleared on `LogsModalDismissed`.
    pub logs_buffer: HashMap<String, Vec<(String, String)>>,
    // ----- Phase 17 fields -----
    /// `Some(form)` while the snapshot-key rotation modal is open.
    pub snapshot_key_rotate_form: Option<SnapshotKeyRotateForm>,
    /// `Some(form)` while the "Re-encrypt all" modal is open.
    pub snapshot_re_encrypt_form: Option<SnapshotReEncryptForm>,
    /// Per-snapshot encryption metadata cache — keyed by snapshot id, populated by
    /// background `SnapshotEncryptionStatus` calls. Used to render the kdf/algo
    /// badge in the Snapshot tab without an extra round-trip on every render.
    pub snapshot_encryption_badges: HashMap<i64, SnapshotEncryptionBadge>,
    /// Last seen TOFU expiry status (from `DaemonPinClientTofuExpiryStatus`).
    pub tofu_expiry: Option<DaemonPinClientTofuExpiryStatusResponse>,
    /// Inline input for the "Set expiry" field on the PinnedClients tab.
    pub tofu_expiry_input: String,
    /// Plugin key registry — rendered by the Plugins tab.
    pub plugin_keys: Vec<PluginKeyEntry>,
    /// `Some(form)` while the cluster-wide revocation confirm modal is open.
    pub plugin_key_revoke_form: Option<PluginKeyRevokeForm>,
    /// Per-(publisher, fingerprint) propagation state: tracks recent successful
    /// cluster propagations so the Plugins tab can show "cluster-wide / pending /
    /// this node only" without polling.
    pub plugin_key_revoke_state: HashMap<(String, String), PluginRevokePropagation>,
    /// Last seen sandbox snapshot auto-trigger status.
    pub sandbox_auto_trigger: Option<SandboxSnapshotAutoTriggerStatusResponse>,
}

/// Phase 11: max log lines retained per container in the GUI's `logs_buffer`. Past
/// this cap, the oldest line is evicted on each push so a long-running follow doesn't
/// grow without bound.
pub const LOGS_BUFFER_CAP: usize = 1000;

#[derive(Debug, Default, Clone)]
pub struct ImagePushForm {
    pub reference: String,
    pub registry: String,
    pub auth: String,
}

/// State for the per-snapshot key-rotation modal (Phase 17 Stream A).
#[derive(Debug, Default, Clone)]
pub struct SnapshotKeyRotateForm {
    pub snapshot_id: i64,
    pub new_passphrase: String,
}

/// State for the bulk "re-encrypt all snapshots" modal (Phase 17 Stream A).
#[derive(Debug, Default, Clone)]
pub struct SnapshotReEncryptForm {
    pub new_passphrase: String,
}

/// Cached subset of `SnapshotEncryptionStatusResponse` — enough to render the kdf
/// / algorithm badge per row.
#[derive(Debug, Default, Clone)]
pub struct SnapshotEncryptionBadge {
    pub encrypted: bool,
    pub algorithm: Option<String>,
    /// Phase 17 — surfaced as a separate column in `SnapshotEncryptionStatusResponse.key_source`.
    /// For Phase 17 Stream A the daemon returns the KDF identifier ("argon2id" /
    /// "sha256-1k") in this field; we mirror it here for the badge cell.
    pub kdf: Option<String>,
}

/// State for the "Revoke cluster-wide" confirm modal (Phase 17 Stream C).
#[derive(Debug, Default, Clone)]
pub struct PluginKeyRevokeForm {
    pub publisher: String,
    pub fingerprint: String,
}

/// Three-state machine for cluster-wide revocation propagation status. Each
/// `PluginKeyRevokePropagateSubmit` flips the state to `Pending`; the matching
/// `PluginKeyRevokePropagated` reply flips it to `Cluster`. Local revokes that
/// never went through Raft stay at `ThisNode`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum PluginRevokePropagation {
    /// Local-only revoke (no Raft propagation issued).
    #[default]
    ThisNode,
    /// User requested cluster propagation; waiting on the leader's commit.
    Pending,
    /// Raft committed the revocation entry; `log_index` carries the index.
    Cluster { log_index: Option<u64> },
}

impl App {
    pub fn new(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            ..Default::default()
        }
    }

    /// Apply a Message and return the next state. Pure reducer — used in unit tests.
    /// `update` in the iced layer wraps this and additionally returns `Task::none()` etc.
    pub fn apply(&mut self, msg: &Message) {
        match msg {
            Message::TabSelected(tab) => self.tab = *tab,
            Message::ConnectionStateChanged(s) => self.conn = s.clone(),
            Message::SnapshotLoaded(s) => self.apply_snapshot(s.clone()),
            Message::EventReceived(e) => self.apply_event(e),
            Message::SandboxLoaded(v) => self.sandbox_profiles = v.clone(),
            Message::AuditLoaded(v) => self.audit_entries = v.clone(),
            Message::SnapshotsLoaded(v) => {
                self.snapshots = v.clone();
                let known: std::collections::HashSet<i64> =
                    self.snapshots.iter().map(|s| s.id).collect();
                if self.snapshot_diff_a.is_some_and(|id| !known.contains(&id)) {
                    self.snapshot_diff_a = None;
                    self.snapshot_diff = None;
                }
                if self.snapshot_diff_b.is_some_and(|id| !known.contains(&id)) {
                    self.snapshot_diff_b = None;
                    self.snapshot_diff = None;
                }
            }
            Message::SessionsLoaded(v) => self.sessions = v.clone(),
            Message::SessionTimelineLoaded {
                session_id,
                entries,
            } => {
                if self.selected_session == Some(*session_id) {
                    self.session_timeline = entries.clone();
                }
            }
            Message::SandboxProfileSelected(name) => {
                self.selected_sandbox_profile = Some(name.clone());
            }
            Message::SessionSelected(id) => {
                self.selected_session = Some(*id);
                self.session_timeline.clear();
            }
            Message::AuditFilterChanged(kind) => {
                self.audit_filter_kind = kind.clone();
            }
            Message::ApprovalReceived(req) => {
                if !self
                    .pending_approvals
                    .iter()
                    .any(|p| p.request_id == req.request_id)
                {
                    self.pending_approvals.push_back(req.clone());
                }
            }
            Message::ApprovalResolved(res) => {
                self.pending_approvals
                    .retain(|p| p.request_id != res.request_id);
                // Clear the reason text if the resolved request was the one being viewed.
                if self.pending_approvals.is_empty() {
                    self.approval_reason.clear();
                }
            }
            Message::ApprovalReasonChanged(s) => {
                self.approval_reason = s.clone();
            }
            Message::ApprovalDecision { request_id, .. } => {
                // Optimistically pop the request from the queue; the server will also fan out
                // an `ApprovalResolved` shortly which is a no-op once it's already gone.
                self.pending_approvals
                    .retain(|p| &p.request_id != request_id);
                if self.pending_approvals.is_empty() {
                    self.approval_reason.clear();
                }
            }
            // SnapshotRollback / SnapshotRemove / SnapshotBranch / SnapshotDiffRequest are
            // forwarded by the iced update layer to connection.rs (one-shot RPC). The reducer
            // itself doesn't mutate for these.
            Message::SnapshotRollback(_)
            | Message::SnapshotRemove(_)
            | Message::SnapshotBranch(_)
            | Message::SnapshotDiffRequest { .. } => {}
            Message::SnapshotSelectForDiff { slot, id } => match slot {
                DiffSlot::A => {
                    self.snapshot_diff_a = Some(*id);
                    self.snapshot_diff = None;
                }
                DiffSlot::B => {
                    self.snapshot_diff_b = Some(*id);
                    self.snapshot_diff = None;
                }
            },
            Message::SnapshotDiffLoaded(resp) => {
                if self.snapshot_diff_a == Some(resp.id_a)
                    && self.snapshot_diff_b == Some(resp.id_b)
                {
                    self.snapshot_diff = Some(resp.clone());
                }
            }
            Message::MetricsContainerSelected(id) => {
                self.metrics_selected = Some(id.clone());
            }
            Message::MetricsLoaded {
                container_id,
                samples,
            } => {
                self.metrics_samples
                    .insert(container_id.clone(), samples.clone());
            }
            Message::ImagePushOpen(reference) => {
                self.image_push_form = Some(ImagePushForm {
                    reference: reference.clone(),
                    registry: String::new(),
                    auth: String::new(),
                });
            }
            Message::ImagePushRegistryChanged(s) => {
                if let Some(form) = self.image_push_form.as_mut() {
                    form.registry = s.clone();
                }
            }
            Message::ImagePushAuthChanged(s) => {
                if let Some(form) = self.image_push_form.as_mut() {
                    form.auth = s.clone();
                }
            }
            Message::ImagePushCancel => {
                self.image_push_form = None;
            }
            Message::ImagePushSubmit => {
                // Form is consumed by the iced layer (which fires the IPC). Drop the
                // modal here so the reducer alone is enough for unit-test coverage.
                self.image_push_form = None;
            }
            Message::ExecRequested(id) => {
                self.exec_target = Some(id.clone());
            }
            Message::LogsRequested(id) => {
                self.logs_target = Some(id.clone());
                // Reset any prior follow buffer for this container so the modal opens clean.
                self.logs_buffer.entry(id.clone()).or_default().clear();
            }
            Message::LogLineReceived {
                container_id,
                stream,
                line,
            } => {
                let buf = self.logs_buffer.entry(container_id.clone()).or_default();
                buf.push((stream.clone(), line.clone()));
                if buf.len() > LOGS_BUFFER_CAP {
                    let drop = buf.len() - LOGS_BUFFER_CAP;
                    buf.drain(0..drop);
                }
            }
            Message::ExecModalDismissed => {
                self.exec_target = None;
            }
            Message::LogsModalDismissed => {
                if let Some(id) = self.logs_target.take() {
                    self.logs_buffer.remove(&id);
                }
            }
            // ----- Phase 17 reducer branches -----
            Message::SnapshotKeyRotateOpen(id) => {
                self.snapshot_key_rotate_form = Some(SnapshotKeyRotateForm {
                    snapshot_id: *id,
                    new_passphrase: String::new(),
                });
            }
            Message::SnapshotKeyRotatePassphraseChanged(s) => {
                if let Some(form) = self.snapshot_key_rotate_form.as_mut() {
                    form.new_passphrase = s.clone();
                }
            }
            Message::SnapshotKeyRotateCancel => {
                self.snapshot_key_rotate_form = None;
            }
            Message::SnapshotKeyRotateSubmit => {
                // The iced layer captures the form before mutation; reducer just clears it.
                self.snapshot_key_rotate_form = None;
            }
            Message::SnapshotKeyRotated {
                snapshot_id,
                algorithm,
                kdf,
            } => {
                let entry = self
                    .snapshot_encryption_badges
                    .entry(*snapshot_id)
                    .or_default();
                entry.encrypted = true;
                entry.algorithm = Some(algorithm.clone());
                entry.kdf = Some(kdf.clone());
            }
            Message::SnapshotReEncryptAllOpen => {
                self.snapshot_re_encrypt_form = Some(SnapshotReEncryptForm::default());
            }
            Message::SnapshotReEncryptAllPassphraseChanged(s) => {
                if let Some(form) = self.snapshot_re_encrypt_form.as_mut() {
                    form.new_passphrase = s.clone();
                }
            }
            Message::SnapshotReEncryptAllCancel => {
                self.snapshot_re_encrypt_form = None;
            }
            Message::SnapshotReEncryptAllSubmit => {
                self.snapshot_re_encrypt_form = None;
            }
            Message::SnapshotReEncryptAllDone { .. } => {
                // The toast banner is rendered transiently by the iced layer; the reducer
                // itself has no persistent flag (Phase 17 keeps the surface minimal).
            }
            Message::SnapshotEncryptionLoaded(resp) => {
                self.snapshot_encryption_badges.insert(
                    resp.snapshot_id,
                    SnapshotEncryptionBadge {
                        encrypted: resp.encrypted,
                        algorithm: resp.algorithm.clone(),
                        kdf: resp.key_source.clone(),
                    },
                );
            }
            Message::TofuExpiryLoaded(resp) => {
                self.tofu_expiry = Some(resp.clone());
            }
            Message::TofuExpiryInputChanged(s) => {
                self.tofu_expiry_input = s.clone();
            }
            Message::TofuExpirySubmit => {
                // Form value is captured by the iced layer beforehand. Reducer clears
                // the input so the user gets a clean text box after submission.
                self.tofu_expiry_input.clear();
            }
            Message::TofuExpiryUpdated(max_age) => {
                if let Some(status) = self.tofu_expiry.as_mut() {
                    status.max_age_secs = *max_age;
                }
            }
            Message::PluginKeysLoaded(keys) => {
                self.plugin_keys = keys.clone();
            }
            Message::PluginKeyRevokeOpen {
                publisher,
                fingerprint,
            } => {
                self.plugin_key_revoke_form = Some(PluginKeyRevokeForm {
                    publisher: publisher.clone(),
                    fingerprint: fingerprint.clone(),
                });
            }
            Message::PluginKeyRevokeCancel => {
                self.plugin_key_revoke_form = None;
            }
            Message::PluginKeyRevokeSubmit => {
                if let Some(form) = self.plugin_key_revoke_form.as_ref() {
                    self.plugin_key_revoke_state.insert(
                        (form.publisher.clone(), form.fingerprint.clone()),
                        PluginRevokePropagation::Pending,
                    );
                }
                self.plugin_key_revoke_form = None;
            }
            Message::PluginKeyRevokePropagated {
                publisher,
                fingerprint,
                log_index,
            } => {
                self.plugin_key_revoke_state.insert(
                    (publisher.clone(), fingerprint.clone()),
                    PluginRevokePropagation::Cluster {
                        log_index: *log_index,
                    },
                );
            }
            Message::SandboxAutoTriggerLoaded(resp) => {
                self.sandbox_auto_trigger = Some(resp.clone());
            }
            Message::SandboxAutoTriggerToggle => {
                if let Some(status) = self.sandbox_auto_trigger.as_mut() {
                    status.enabled = !status.enabled;
                }
            }
            Message::NoOp => {}
        }
    }

    fn apply_snapshot(&mut self, s: Snapshot) {
        match s {
            Snapshot::Containers(v) => self.containers = v,
            Snapshot::Images(v) => self.images = v,
            Snapshot::Volumes(v) => self.volumes = v,
            Snapshot::Networks(v) => self.networks = v,
        }
    }

    /// React to a server-pushed event. v1 strategy is intentionally simple: any change to a
    /// resource type triggers nothing but a small in-place mutation when straightforward
    /// (Removed → drop the row), and otherwise leaves it to the next snapshot refresh.
    fn apply_event(&mut self, event: &Event) {
        let id = event.resource_id.as_str();
        match (event.topic, &event.kind) {
            (EventTopic::Container, EventKind::Removed) => {
                self.containers
                    .retain(|c| c.id.as_str() != id && !c.names.iter().any(|n| n == id));
            }
            (EventTopic::Image, EventKind::Removed) => {
                self.images.retain(|i| i.id.as_str() != id);
            }
            (EventTopic::Volume, EventKind::Removed) => {
                self.volumes.retain(|v| v.name.as_str() != id);
            }
            (EventTopic::Network, EventKind::Removed) => {
                self.networks
                    .retain(|n| n.id.as_str() != id && n.name != id);
            }
            // Created / Started / Stopped / Pulled / Tagged / Renamed: snapshot will catch up.
            // The connection task triggers a refresh (re-call *List) on each event in v1 to keep
            // it simple. (Optimization for Phase 2: maintain an LRU of recent IDs and skip
            // unnecessary refreshes.)
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use linpodx_common::approval::ApprovalCategory;
    use linpodx_common::approval::ApprovalOutcome;
    use linpodx_common::state::ContainerState;
    use linpodx_common::types::{ContainerId, ImageId, NetworkId, VolumeId};

    fn container(id: &str, name: &str) -> ContainerSummary {
        ContainerSummary {
            id: ContainerId::from(id),
            names: vec![name.to_string()],
            image: "alpine".into(),
            state: ContainerState::Running,
            status: "Up".into(),
            created: Utc::now(),
            command: None,
            ports: vec![],
        }
    }

    fn approval(id: &str) -> ApprovalRequest {
        ApprovalRequest {
            request_id: id.into(),
            category: ApprovalCategory::MountHostPath,
            profile_name: "demo".into(),
            timeout_secs: 30,
            created_at: Utc::now(),
            payload: serde_json::Value::Null,
            container_hint: None,
        }
    }

    #[test]
    fn tab_selection_changes_tab() {
        let mut app = App::default();
        app.apply(&Message::TabSelected(Tab::Images));
        assert_eq!(app.tab, Tab::Images);
    }

    #[test]
    fn snapshot_load_replaces_list() {
        let mut app = App::default();
        let s = Snapshot::Containers(vec![container("a", "alpha"), container("b", "beta")]);
        app.apply(&Message::SnapshotLoaded(s));
        assert_eq!(app.containers.len(), 2);
    }

    #[test]
    fn container_removed_event_drops_row_by_id() {
        let mut app = App {
            containers: vec![container("aaa", "alpha"), container("bbb", "beta")],
            ..App::default()
        };
        let event = Event {
            topic: EventTopic::Container,
            kind: EventKind::Removed,
            resource_id: "aaa".to_string(),
            timestamp: Utc::now(),
            details: serde_json::Value::Null,
        };
        app.apply(&Message::EventReceived(event));
        assert_eq!(app.containers.len(), 1);
        assert_eq!(app.containers[0].id, ContainerId::from("bbb"));
    }

    #[test]
    fn container_removed_event_drops_row_by_name() {
        // The CLI lets the user `rm` by name; the daemon emits an event with the name as
        // resource_id (since podman returned the name). The reducer should still match.
        let mut app = App {
            containers: vec![container("xyz", "probe")],
            ..App::default()
        };
        let event = Event {
            topic: EventTopic::Container,
            kind: EventKind::Removed,
            resource_id: "probe".to_string(),
            timestamp: Utc::now(),
            details: serde_json::Value::Null,
        };
        app.apply(&Message::EventReceived(event));
        assert!(app.containers.is_empty());
    }

    #[test]
    fn unknown_event_kind_does_not_panic() {
        // Created events don't mutate directly — they wait for the next snapshot.
        let mut app = App::default();
        let event = Event {
            topic: EventTopic::Image,
            kind: EventKind::Pulled,
            resource_id: "sha256:zzz".into(),
            timestamp: Utc::now(),
            details: serde_json::Value::Null,
        };
        app.apply(&Message::EventReceived(event));
        // No assertion — just verify no panic / divergence.
    }

    #[test]
    fn tab_all_has_eleven_entries() {
        assert_eq!(Tab::ALL.len(), 11);
        // Display matches label.
        assert_eq!(Tab::Sandbox.to_string(), "Sandbox");
        assert_eq!(Tab::Metrics.to_string(), "Metrics");
        assert_eq!(Tab::PinnedClients.to_string(), "Pinned Clients");
        assert_eq!(Tab::Plugins.to_string(), "Plugins");
    }

    #[test]
    fn sandbox_loaded_replaces_profiles() {
        let mut app = App::default();
        let v = vec![SandboxProfileSummary {
            name: "p1".into(),
            description: "d".into(),
            version: 1,
            yaml_hash: "h".into(),
            last_updated: Utc::now(),
        }];
        app.apply(&Message::SandboxLoaded(v));
        assert_eq!(app.sandbox_profiles.len(), 1);
    }

    #[test]
    fn audit_loaded_and_filter_changed() {
        let mut app = App::default();
        app.apply(&Message::AuditLoaded(vec![AuditEntrySummary {
            seq: 1,
            ts: Utc::now(),
            kind: "denied".into(),
            profile_name: None,
            container_id: None,
            payload: serde_json::Value::Null,
            prev_hash: "0".into(),
            this_hash: "1".into(),
        }]));
        assert_eq!(app.audit_entries.len(), 1);
        app.apply(&Message::AuditFilterChanged(Some("denied".into())));
        assert_eq!(app.audit_filter_kind.as_deref(), Some("denied"));
    }

    #[test]
    fn approval_received_pushes_to_back_and_dedupes() {
        let mut app = App::default();
        app.apply(&Message::ApprovalReceived(approval("req-1")));
        app.apply(&Message::ApprovalReceived(approval("req-2")));
        // Duplicate request_id should be ignored.
        app.apply(&Message::ApprovalReceived(approval("req-1")));
        assert_eq!(app.pending_approvals.len(), 2);
        assert_eq!(app.pending_approvals.front().unwrap().request_id, "req-1");
    }

    #[test]
    fn approval_resolved_removes_matching_id() {
        let mut app = App::default();
        app.apply(&Message::ApprovalReceived(approval("req-1")));
        app.apply(&Message::ApprovalReceived(approval("req-2")));
        app.apply(&Message::ApprovalResolved(ApprovalResolved {
            request_id: "req-2".into(),
            outcome: ApprovalOutcome::TimedOut,
        }));
        assert_eq!(app.pending_approvals.len(), 1);
        assert_eq!(app.pending_approvals.front().unwrap().request_id, "req-1");
    }

    #[test]
    fn approval_decision_optimistically_pops() {
        let mut app = App::default();
        app.apply(&Message::ApprovalReceived(approval("req-1")));
        app.approval_reason = "looks ok".into();
        app.apply(&Message::ApprovalDecision {
            request_id: "req-1".into(),
            allow: true,
            reason: Some("looks ok".into()),
        });
        assert!(app.pending_approvals.is_empty());
        assert!(app.approval_reason.is_empty());
    }

    #[test]
    fn session_selection_clears_old_timeline() {
        let mut app = App {
            session_timeline: vec![SessionTimelineEntry {
                source: "audit".into(),
                ts: Utc::now(),
                kind: "denied".into(),
                payload: serde_json::Value::Null,
            }],
            ..App::default()
        };
        app.apply(&Message::SessionSelected(42));
        assert_eq!(app.selected_session, Some(42));
        assert!(app.session_timeline.is_empty());
    }

    #[test]
    fn session_timeline_only_loads_for_selected() {
        let mut app = App::default();
        app.apply(&Message::SessionSelected(1));
        app.apply(&Message::SessionTimelineLoaded {
            session_id: 2,
            entries: vec![SessionTimelineEntry {
                source: "audit".into(),
                ts: Utc::now(),
                kind: "x".into(),
                payload: serde_json::Value::Null,
            }],
        });
        // Stale (different session) — ignored.
        assert!(app.session_timeline.is_empty());
        app.apply(&Message::SessionTimelineLoaded {
            session_id: 1,
            entries: vec![SessionTimelineEntry {
                source: "audit".into(),
                ts: Utc::now(),
                kind: "y".into(),
                payload: serde_json::Value::Null,
            }],
        });
        assert_eq!(app.session_timeline.len(), 1);
    }

    #[test]
    fn approval_reason_changed_updates_field() {
        let mut app = App::default();
        app.apply(&Message::ApprovalReasonChanged("nope".into()));
        assert_eq!(app.approval_reason, "nope");
    }

    fn snap(id: i64, parent: Option<i64>) -> SnapshotSummary {
        SnapshotSummary {
            id,
            container_id: format!("c{id}"),
            label: None,
            image_ref: format!("linpodx-snap-{id}"),
            parent_id: parent,
            created_at: Utc::now(),
            size_bytes: None,
        }
    }

    #[test]
    fn build_snapshot_tree_orders_roots_then_children_depth_first() {
        // Tree:
        //   1 (root)
        //     ├─ 2
        //     │    └─ 3
        //     └─ 4
        //   5 (root, parent_id pointing nowhere)
        let flat = vec![
            snap(2, Some(1)),
            snap(1, None),
            snap(4, Some(1)),
            snap(3, Some(2)),
            snap(5, Some(99)),
        ];
        let nodes = build_snapshot_tree(&flat);
        let order: Vec<(i64, usize)> = nodes.iter().map(|n| (n.snapshot.id, n.depth)).collect();
        assert_eq!(order, vec![(1, 0), (2, 1), (3, 2), (4, 1), (5, 0)]);
    }

    #[test]
    fn build_snapshot_tree_handles_empty_input() {
        let nodes = build_snapshot_tree(&[]);
        assert!(nodes.is_empty());
    }

    #[test]
    fn select_for_diff_updates_slot_and_clears_old_diff() {
        let mut app = App {
            snapshot_diff: Some(SnapshotDiffResponse {
                id_a: 1,
                id_b: 2,
                added: vec![],
                modified: vec![],
                deleted: vec![],
                size_delta_bytes: 0,
            }),
            ..App::default()
        };
        app.apply(&Message::SnapshotSelectForDiff {
            slot: DiffSlot::A,
            id: 7,
        });
        assert_eq!(app.snapshot_diff_a, Some(7));
        assert!(app.snapshot_diff.is_none());

        app.apply(&Message::SnapshotSelectForDiff {
            slot: DiffSlot::B,
            id: 8,
        });
        assert_eq!(app.snapshot_diff_b, Some(8));
    }

    #[test]
    fn diff_loaded_only_applies_when_selection_matches() {
        let mut app = App {
            snapshot_diff_a: Some(3),
            snapshot_diff_b: Some(4),
            ..App::default()
        };
        // Stale response (different ids) — should be ignored.
        app.apply(&Message::SnapshotDiffLoaded(SnapshotDiffResponse {
            id_a: 1,
            id_b: 2,
            added: vec![],
            modified: vec![],
            deleted: vec![],
            size_delta_bytes: 0,
        }));
        assert!(app.snapshot_diff.is_none());

        app.apply(&Message::SnapshotDiffLoaded(SnapshotDiffResponse {
            id_a: 3,
            id_b: 4,
            added: vec!["/etc/hosts".into()],
            modified: vec![],
            deleted: vec![],
            size_delta_bytes: 12,
        }));
        let d = app.snapshot_diff.as_ref().unwrap();
        assert_eq!(d.added, vec!["/etc/hosts".to_string()]);
        assert_eq!(d.size_delta_bytes, 12);
    }

    #[test]
    fn snapshots_refresh_drops_diff_selection_for_missing_rows() {
        let mut app = App {
            snapshot_diff_a: Some(1),
            snapshot_diff_b: Some(2),
            snapshot_diff: Some(SnapshotDiffResponse {
                id_a: 1,
                id_b: 2,
                added: vec![],
                modified: vec![],
                deleted: vec![],
                size_delta_bytes: 0,
            }),
            ..App::default()
        };
        // New list contains only id 1 → b becomes stale, diff cleared.
        app.apply(&Message::SnapshotsLoaded(vec![snap(1, None)]));
        assert_eq!(app.snapshot_diff_a, Some(1));
        assert!(app.snapshot_diff_b.is_none());
        assert!(app.snapshot_diff.is_none());
    }

    fn metrics_sample(cid: &str, cpu: f64) -> MetricsSample {
        MetricsSample {
            container_id: cid.into(),
            ts: Utc::now(),
            cpu_pct: cpu,
            mem_bytes: 0,
            mem_limit: None,
            net_rx: 0,
            net_tx: 0,
            block_in: 0,
            block_out: 0,
        }
    }

    #[test]
    fn metrics_container_selected_updates_state() {
        let mut app = App::default();
        app.apply(&Message::MetricsContainerSelected("abc".into()));
        assert_eq!(app.metrics_selected.as_deref(), Some("abc"));
    }

    #[test]
    fn metrics_loaded_replaces_samples_for_container() {
        let mut app = App::default();
        app.apply(&Message::MetricsLoaded {
            container_id: "c1".into(),
            samples: vec![metrics_sample("c1", 0.1), metrics_sample("c1", 0.2)],
        });
        assert_eq!(app.metrics_samples.get("c1").map(Vec::len), Some(2));
        // Subsequent load fully replaces (not appends) so the GUI mirrors the daemon ring.
        app.apply(&Message::MetricsLoaded {
            container_id: "c1".into(),
            samples: vec![metrics_sample("c1", 0.5)],
        });
        assert_eq!(app.metrics_samples.get("c1").map(Vec::len), Some(1));
    }

    // Suppress unused-import warnings on these helper imports until volume / network reducer
    // tests get added in Phase 1C.
    #[allow(dead_code)]
    fn _unused_imports() {
        let _: ImageId;
        let _: VolumeId;
        let _: NetworkId;
    }

    // ---- Phase 11: exec / logs modal reducer branches ----

    #[test]
    fn exec_requested_sets_target_and_dismiss_clears_it() {
        let mut app = App::default();
        app.apply(&Message::ExecRequested("c1".into()));
        assert_eq!(app.exec_target.as_deref(), Some("c1"));
        app.apply(&Message::ExecModalDismissed);
        assert!(app.exec_target.is_none());
    }

    #[test]
    fn logs_requested_sets_target_and_clears_buffer() {
        let mut app = App::default();
        // Pre-seed an old buffer so we can verify the request resets it.
        app.logs_buffer
            .insert("c1".into(), vec![("stdout".into(), "old line".into())]);
        app.apply(&Message::LogsRequested("c1".into()));
        assert_eq!(app.logs_target.as_deref(), Some("c1"));
        assert_eq!(app.logs_buffer.get("c1").map(Vec::len), Some(0));
    }

    #[test]
    fn log_line_received_appends_to_buffer() {
        let mut app = App::default();
        app.apply(&Message::LogLineReceived {
            container_id: "c1".into(),
            stream: "stdout".into(),
            line: "hello".into(),
        });
        app.apply(&Message::LogLineReceived {
            container_id: "c1".into(),
            stream: "stderr".into(),
            line: "warn!".into(),
        });
        let buf = app.logs_buffer.get("c1").expect("buffer present");
        assert_eq!(buf.len(), 2);
        assert_eq!(buf[0], ("stdout".to_string(), "hello".to_string()));
        assert_eq!(buf[1], ("stderr".to_string(), "warn!".to_string()));
    }

    #[test]
    fn log_buffer_caps_at_one_thousand_lines() {
        let mut app = App::default();
        for i in 0..(LOGS_BUFFER_CAP + 5) {
            app.apply(&Message::LogLineReceived {
                container_id: "c1".into(),
                stream: "stdout".into(),
                line: format!("line {i}"),
            });
        }
        let buf = app.logs_buffer.get("c1").expect("buffer present");
        assert_eq!(buf.len(), LOGS_BUFFER_CAP);
        // First retained line should be index 5 (oldest 5 evicted).
        assert_eq!(buf.first().unwrap().1, "line 5");
        assert_eq!(
            buf.last().unwrap().1,
            format!("line {}", LOGS_BUFFER_CAP + 4)
        );
    }

    #[test]
    fn logs_modal_dismissed_drops_target_and_buffer() {
        let mut app = App::default();
        app.apply(&Message::LogsRequested("c1".into()));
        app.apply(&Message::LogLineReceived {
            container_id: "c1".into(),
            stream: "stdout".into(),
            line: "x".into(),
        });
        app.apply(&Message::LogsModalDismissed);
        assert!(app.logs_target.is_none());
        assert!(!app.logs_buffer.contains_key("c1"));
    }

    #[test]
    fn dismiss_with_no_modal_is_a_noop() {
        let mut app = App::default();
        app.apply(&Message::ExecModalDismissed);
        app.apply(&Message::LogsModalDismissed);
        assert!(app.exec_target.is_none());
        assert!(app.logs_target.is_none());
    }

    // ---- Phase 17 reducer branches ----

    #[test]
    fn snapshot_key_rotate_open_seeds_form_with_id() {
        let mut app = App::default();
        app.apply(&Message::SnapshotKeyRotateOpen(42));
        let f = app.snapshot_key_rotate_form.as_ref().expect("form present");
        assert_eq!(f.snapshot_id, 42);
        assert!(f.new_passphrase.is_empty());
    }

    #[test]
    fn snapshot_key_rotate_passphrase_persists_until_submit() {
        let mut app = App::default();
        app.apply(&Message::SnapshotKeyRotateOpen(7));
        app.apply(&Message::SnapshotKeyRotatePassphraseChanged(
            "hunter2".into(),
        ));
        assert_eq!(
            app.snapshot_key_rotate_form
                .as_ref()
                .unwrap()
                .new_passphrase,
            "hunter2"
        );
        app.apply(&Message::SnapshotKeyRotateSubmit);
        assert!(app.snapshot_key_rotate_form.is_none());
    }

    #[test]
    fn snapshot_key_rotated_caches_badge() {
        let mut app = App::default();
        app.apply(&Message::SnapshotKeyRotated {
            snapshot_id: 11,
            algorithm: "aes-256-gcm".into(),
            kdf: "argon2id".into(),
        });
        let badge = app
            .snapshot_encryption_badges
            .get(&11)
            .expect("badge cached");
        assert!(badge.encrypted);
        assert_eq!(badge.algorithm.as_deref(), Some("aes-256-gcm"));
        assert_eq!(badge.kdf.as_deref(), Some("argon2id"));
    }

    #[test]
    fn snapshot_encryption_loaded_populates_badge_cache() {
        let mut app = App::default();
        app.apply(&Message::SnapshotEncryptionLoaded(
            SnapshotEncryptionStatusResponse {
                snapshot_id: 9,
                encrypted: true,
                algorithm: Some("aes-256-gcm".into()),
                key_source: Some("sha256-1k".into()),
                ciphertext_sha256: None,
            },
        ));
        let badge = app
            .snapshot_encryption_badges
            .get(&9)
            .expect("badge cached");
        assert!(badge.encrypted);
        assert_eq!(badge.kdf.as_deref(), Some("sha256-1k"));
    }

    #[test]
    fn snapshot_re_encrypt_form_opens_and_cancels() {
        let mut app = App::default();
        app.apply(&Message::SnapshotReEncryptAllOpen);
        assert!(app.snapshot_re_encrypt_form.is_some());
        app.apply(&Message::SnapshotReEncryptAllPassphraseChanged("p".into()));
        assert_eq!(
            app.snapshot_re_encrypt_form
                .as_ref()
                .unwrap()
                .new_passphrase,
            "p"
        );
        app.apply(&Message::SnapshotReEncryptAllCancel);
        assert!(app.snapshot_re_encrypt_form.is_none());
    }

    #[test]
    fn tofu_expiry_input_changed_persists() {
        let mut app = App::default();
        app.apply(&Message::TofuExpiryInputChanged("3600".into()));
        assert_eq!(app.tofu_expiry_input, "3600");
        app.apply(&Message::TofuExpirySubmit);
        assert!(app.tofu_expiry_input.is_empty());
    }

    #[test]
    fn tofu_expiry_loaded_and_updated() {
        let mut app = App::default();
        app.apply(&Message::TofuExpiryLoaded(
            DaemonPinClientTofuExpiryStatusResponse {
                enabled: true,
                max_age_secs: Some(7_200),
                enabled_at: Some(1_700_000_000),
            },
        ));
        assert_eq!(app.tofu_expiry.as_ref().unwrap().max_age_secs, Some(7_200));
        app.apply(&Message::TofuExpiryUpdated(Some(1_800)));
        assert_eq!(app.tofu_expiry.as_ref().unwrap().max_age_secs, Some(1_800));
        app.apply(&Message::TofuExpiryUpdated(None));
        assert_eq!(app.tofu_expiry.as_ref().unwrap().max_age_secs, None);
    }

    #[test]
    fn plugin_keys_loaded_replaces_list() {
        let mut app = App::default();
        app.apply(&Message::PluginKeysLoaded(vec![PluginKeyEntry {
            publisher: "alice".into(),
            fingerprint: "ff00".into(),
            status: "active".into(),
            revoked_at: None,
            reason: None,
        }]));
        assert_eq!(app.plugin_keys.len(), 1);
    }

    #[test]
    fn plugin_key_revoke_flow_submits_to_pending_then_cluster() {
        let mut app = App::default();
        app.apply(&Message::PluginKeyRevokeOpen {
            publisher: "alice".into(),
            fingerprint: "ff00".into(),
        });
        assert!(app.plugin_key_revoke_form.is_some());
        app.apply(&Message::PluginKeyRevokeSubmit);
        assert!(app.plugin_key_revoke_form.is_none());
        let st = app
            .plugin_key_revoke_state
            .get(&("alice".to_string(), "ff00".to_string()))
            .copied()
            .expect("state seeded");
        assert_eq!(st, PluginRevokePropagation::Pending);
        app.apply(&Message::PluginKeyRevokePropagated {
            publisher: "alice".into(),
            fingerprint: "ff00".into(),
            log_index: Some(42),
        });
        let st = app
            .plugin_key_revoke_state
            .get(&("alice".to_string(), "ff00".to_string()))
            .copied()
            .expect("state updated");
        match st {
            PluginRevokePropagation::Cluster { log_index } => assert_eq!(log_index, Some(42)),
            _ => panic!("expected Cluster"),
        }
    }

    #[test]
    fn plugin_key_revoke_cancel_clears_form_without_state() {
        let mut app = App::default();
        app.apply(&Message::PluginKeyRevokeOpen {
            publisher: "alice".into(),
            fingerprint: "ff00".into(),
        });
        app.apply(&Message::PluginKeyRevokeCancel);
        assert!(app.plugin_key_revoke_form.is_none());
        assert!(!app
            .plugin_key_revoke_state
            .contains_key(&("alice".to_string(), "ff00".to_string())));
    }

    #[test]
    fn sandbox_auto_trigger_loaded_and_toggle() {
        let mut app = App::default();
        app.apply(&Message::SandboxAutoTriggerLoaded(
            SandboxSnapshotAutoTriggerStatusResponse {
                enabled: false,
                last_image_ref: None,
                trigger_count: 0,
            },
        ));
        assert!(!app.sandbox_auto_trigger.as_ref().unwrap().enabled);
        app.apply(&Message::SandboxAutoTriggerToggle);
        assert!(app.sandbox_auto_trigger.as_ref().unwrap().enabled);
        app.apply(&Message::SandboxAutoTriggerToggle);
        assert!(!app.sandbox_auto_trigger.as_ref().unwrap().enabled);
    }
}
