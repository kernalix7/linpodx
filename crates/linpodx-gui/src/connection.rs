use crate::state::{ConnectionState, Message, Snapshot};
use anyhow::{anyhow, Context, Result};
use iced::futures::channel::mpsc;
use iced::futures::SinkExt;
use linpodx_common::approval::{ApprovalRequest, ApprovalResolved};
use linpodx_common::ipc::{
    responses, AuditQueryParams, ContainerListParams, EventTopic, ImageListParams, ImagePushParams,
    JsonRpcVersion, Method, MetricsHistoryParams, MetricsLatestParams, Notification, RpcRequest,
    RpcResponse, ServerMessage, SessionListParams, SessionTimelineParams, SnapshotBranchParams,
    SnapshotDiffParams, SnapshotListParams, SnapshotRemoveParams, SnapshotRollbackParams,
    SubscribeParams,
};
use linpodx_common::state::{ContainerSummary, ImageSummary, NetworkSummary, VolumeSummary};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tracing::{debug, warn};

static NEXT_ID: AtomicI64 = AtomicI64::new(1);

/// Subscription that maintains a connection to the daemon, seeds the GUI with initial state,
/// then streams events. Reconnects with exponential backoff (1s → 30s).
pub fn daemon_subscription(socket: PathBuf) -> iced::Subscription<Message> {
    let id = format!("daemon-connection-{}", socket.display());
    iced::Subscription::run_with_id(
        id,
        iced::stream::channel(256, move |mut output| {
            let socket = socket.clone();
            async move {
                let mut backoff = Duration::from_secs(1);
                loop {
                    let _ = output
                        .send(Message::ConnectionStateChanged(ConnectionState::Connecting))
                        .await;

                    let result = run_session(&socket, &mut output).await;
                    let reason = match result {
                        Ok(()) => "daemon closed the connection".to_string(),
                        Err(e) => format!("{e:#}"),
                    };
                    let _ = output
                        .send(Message::ConnectionStateChanged(
                            ConnectionState::Disconnected(reason),
                        ))
                        .await;

                    tokio::time::sleep(backoff).await;
                    backoff = std::cmp::min(backoff * 2, Duration::from_secs(30));
                }
            }
        }),
    )
}

async fn run_session(socket: &Path, output: &mut mpsc::Sender<Message>) -> Result<()> {
    let stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!("connect {}", socket.display()))?;
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);

    // Initial seed: existing 4 lists.
    let containers: Vec<ContainerSummary> = call(
        &mut reader,
        &mut write,
        Method::ContainerList(ContainerListParams { all: true }),
    )
    .await
    .context("ContainerList")?;
    let _ = output
        .send(Message::SnapshotLoaded(Snapshot::Containers(containers)))
        .await;

    let images: Vec<ImageSummary> = call(
        &mut reader,
        &mut write,
        Method::ImageList(ImageListParams::default()),
    )
    .await
    .context("ImageList")?;
    let _ = output
        .send(Message::SnapshotLoaded(Snapshot::Images(images)))
        .await;

    let volumes: Vec<VolumeSummary> = call(&mut reader, &mut write, Method::VolumeList)
        .await
        .context("VolumeList")?;
    let _ = output
        .send(Message::SnapshotLoaded(Snapshot::Volumes(volumes)))
        .await;

    let networks: Vec<NetworkSummary> = call(&mut reader, &mut write, Method::NetworkList)
        .await
        .context("NetworkList")?;
    let _ = output
        .send(Message::SnapshotLoaded(Snapshot::Networks(networks)))
        .await;

    // Phase 3 seed: sandbox / audit / snapshot / session lists. Each call is best-effort —
    // the daemon may not have any data yet; failures here are logged and skipped so the
    // event subscription still comes online.
    if let Ok(profiles) = call::<Vec<responses::SandboxProfileSummary>>(
        &mut reader,
        &mut write,
        Method::SandboxProfileList,
    )
    .await
    {
        let _ = output.send(Message::SandboxLoaded(profiles)).await;
    } else {
        warn!("SandboxProfileList seed failed");
    }

    let audit_params = AuditQueryParams {
        limit: Some(200),
        ..AuditQueryParams::default()
    };
    if let Ok(entries) = call::<Vec<responses::AuditEntrySummary>>(
        &mut reader,
        &mut write,
        Method::AuditLogQuery(audit_params),
    )
    .await
    {
        let _ = output.send(Message::AuditLoaded(entries)).await;
    } else {
        warn!("AuditLogQuery seed failed");
    }

    if let Ok(snaps) = call::<Vec<responses::SnapshotSummary>>(
        &mut reader,
        &mut write,
        Method::SnapshotList(SnapshotListParams::default()),
    )
    .await
    {
        let _ = output.send(Message::SnapshotsLoaded(snaps)).await;
    } else {
        warn!("SnapshotList seed failed");
    }

    if let Ok(sessions) = call::<Vec<responses::SessionSummary>>(
        &mut reader,
        &mut write,
        Method::SessionList(SessionListParams::default()),
    )
    .await
    {
        let _ = output.send(Message::SessionsLoaded(sessions)).await;
    } else {
        warn!("SessionList seed failed");
    }

    // Subscribe to all topics. Server-side this also opts the connection in for
    // approval_request / approval_resolved notifications (see daemon/server.rs).
    let _ack: responses::SubscribeResponse = call(
        &mut reader,
        &mut write,
        Method::Subscribe(SubscribeParams {
            topics: EventTopic::ALL.to_vec(),
        }),
    )
    .await
    .context("Subscribe")?;

    let _ = output
        .send(Message::ConnectionStateChanged(ConnectionState::Connected))
        .await;

    // Stream notifications. After each event, refresh the affected list.
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await.context("event read")?;
        if n == 0 {
            return Ok(());
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            continue;
        }
        let msg: ServerMessage = match serde_json::from_str(trimmed) {
            Ok(m) => m,
            Err(e) => {
                warn!(error = %e, line = trimmed, "invalid server message; skipping");
                continue;
            }
        };
        match msg {
            ServerMessage::Notification(Notification { method, params, .. }) => {
                match method.as_str() {
                    "event" => {
                        let event: linpodx_common::ipc::Event = serde_json::from_value(params)
                            .map_err(|e| anyhow!("decode event: {e}"))?;
                        let topic = event.topic;
                        let resource_id = event.resource_id.clone();
                        let _ = output.send(Message::EventReceived(event)).await;
                        if topic == EventTopic::Metrics {
                            if let Err(e) = refresh_metrics(socket, &resource_id, output).await {
                                warn!(error = %e, container = %resource_id, "metrics refresh failed");
                            }
                        } else if let Err(e) = refresh_topic(socket, topic, output).await {
                            warn!(error = %e, ?topic, "tab refresh failed");
                        }
                    }
                    "approval_request" => match serde_json::from_value::<ApprovalRequest>(params) {
                        Ok(req) => {
                            let _ = output.send(Message::ApprovalReceived(req)).await;
                        }
                        Err(e) => warn!(error = %e, "decode approval_request"),
                    },
                    "approval_resolved" => {
                        match serde_json::from_value::<ApprovalResolved>(params) {
                            Ok(res) => {
                                let _ = output.send(Message::ApprovalResolved(res)).await;
                            }
                            Err(e) => warn!(error = %e, "decode approval_resolved"),
                        }
                    }
                    other => debug!(method = other, "unknown notification ignored"),
                }
            }
            ServerMessage::Response(_) => debug!("unexpected response after subscribe; ignoring"),
        }
    }
}

/// Open a one-shot connection and re-fetch the list for `topic`. Pushes a fresh `Snapshot`
/// or one of the Phase 3 `*Loaded` messages.
async fn refresh_topic(
    socket: &Path,
    topic: EventTopic,
    output: &mut mpsc::Sender<Message>,
) -> Result<()> {
    let stream = UnixStream::connect(socket)
        .await
        .context("refresh connect")?;
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    match topic {
        EventTopic::Container => {
            let v: Vec<ContainerSummary> = call(
                &mut reader,
                &mut write,
                Method::ContainerList(ContainerListParams { all: true }),
            )
            .await?;
            let _ = output
                .send(Message::SnapshotLoaded(Snapshot::Containers(v)))
                .await;
        }
        EventTopic::Image => {
            let v: Vec<ImageSummary> = call(
                &mut reader,
                &mut write,
                Method::ImageList(ImageListParams::default()),
            )
            .await?;
            let _ = output
                .send(Message::SnapshotLoaded(Snapshot::Images(v)))
                .await;
        }
        EventTopic::Volume => {
            let v: Vec<VolumeSummary> = call(&mut reader, &mut write, Method::VolumeList).await?;
            let _ = output
                .send(Message::SnapshotLoaded(Snapshot::Volumes(v)))
                .await;
        }
        EventTopic::Network => {
            let v: Vec<NetworkSummary> = call(&mut reader, &mut write, Method::NetworkList).await?;
            let _ = output
                .send(Message::SnapshotLoaded(Snapshot::Networks(v)))
                .await;
        }
        EventTopic::Sandbox => {
            let v: Vec<responses::SandboxProfileSummary> =
                call(&mut reader, &mut write, Method::SandboxProfileList).await?;
            let _ = output.send(Message::SandboxLoaded(v)).await;
        }
        EventTopic::Audit => {
            let v: Vec<responses::AuditEntrySummary> = call(
                &mut reader,
                &mut write,
                Method::AuditLogQuery(AuditQueryParams {
                    limit: Some(200),
                    ..AuditQueryParams::default()
                }),
            )
            .await?;
            let _ = output.send(Message::AuditLoaded(v)).await;
        }
        EventTopic::Snapshot => {
            let v: Vec<responses::SnapshotSummary> = call(
                &mut reader,
                &mut write,
                Method::SnapshotList(SnapshotListParams::default()),
            )
            .await?;
            let _ = output.send(Message::SnapshotsLoaded(v)).await;
        }
        EventTopic::Session => {
            let v: Vec<responses::SessionSummary> = call(
                &mut reader,
                &mut write,
                Method::SessionList(SessionListParams::default()),
            )
            .await?;
            let _ = output.send(Message::SessionsLoaded(v)).await;
        }
        // No GUI surface for these yet; the event was already pushed up via EventReceived.
        EventTopic::Mcp | EventTopic::Distro => {}
        // Metrics events take a different code path (`refresh_metrics`) since the refresh
        // is per-container, not per-topic.
        EventTopic::Metrics => {}
    }
    Ok(())
}

/// Pull the full metrics history for a single container and push it as a `MetricsLoaded`
/// message. Called whenever the daemon emits a `Progress` event on the Metrics topic so
/// the GUI's local series stays in sync without paying for a fan-out poll.
async fn refresh_metrics(
    socket: &Path,
    container_id: &str,
    output: &mut mpsc::Sender<Message>,
) -> Result<()> {
    let stream = UnixStream::connect(socket)
        .await
        .context("metrics refresh connect")?;
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    let samples: Vec<linpodx_common::ipc::MetricsSample> = call(
        &mut reader,
        &mut write,
        Method::MetricsHistory(MetricsHistoryParams {
            container_id: container_id.to_string(),
            since: None,
        }),
    )
    .await?;
    // History is the source of truth — when the daemon's collector hasn't been wired yet
    // (Stage 2), this returns an empty vec and the GUI shows the "no samples yet" hint.
    let _ = output
        .send(Message::MetricsLoaded {
            container_id: container_id.to_string(),
            samples,
        })
        .await;
    Ok(())
}

async fn call<T: serde::de::DeserializeOwned>(
    reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
    write: &mut tokio::net::unix::OwnedWriteHalf,
    method: Method,
) -> Result<T> {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let req = RpcRequest {
        jsonrpc: JsonRpcVersion::V2,
        id: Some(linpodx_common::ipc::RequestId::Number(id)),
        method,
    };
    let mut payload = serde_json::to_vec(&req)?;
    payload.push(b'\n');
    write.write_all(&payload).await?;
    write.flush().await.ok();

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Err(anyhow!("daemon closed during request"));
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            continue;
        }
        // The server may interleave a notification before our response (rare for one-shot
        // calls but theoretically possible). Skip non-Response messages while waiting for
        // our specific id.
        let msg: ServerMessage = serde_json::from_str(trimmed)
            .map_err(|e| anyhow!("parse server message: {e}: {trimmed}"))?;
        match msg {
            ServerMessage::Response(RpcResponse { payload, .. }) => match payload {
                linpodx_common::ipc::ResponsePayload::Success { result } => {
                    return serde_json::from_value(result)
                        .map_err(|e| anyhow!("decode result: {e}"));
                }
                linpodx_common::ipc::ResponsePayload::Error { error } => {
                    return Err(anyhow!(
                        "daemon error (code {}): {}",
                        error.code,
                        error.message
                    ));
                }
            },
            ServerMessage::Notification(_) => continue,
        }
    }
}

// ----- One-shot RPC helpers used by the iced `update` layer (Task::perform). -----

/// Fire-and-forget approval decision. Result is reported back via the existing
/// `approval_resolved` notification stream, so this returns `Message::NoOp`.
pub async fn send_approval_decision(
    socket: PathBuf,
    request_id: String,
    allow: bool,
    reason: Option<String>,
) -> Message {
    if let Err(e) = one_shot::<responses::ApprovalDecisionResponse>(
        &socket,
        Method::ApprovalDecision(linpodx_common::ipc::ApprovalDecisionParams {
            request_id,
            allow,
            by: Some("gui".to_string()),
            reason,
        }),
    )
    .await
    {
        warn!(error = %e, "approval decision rpc failed");
    }
    Message::NoOp
}

/// Fire-and-forget snapshot rollback. Refresh comes via Snapshot/Container event.
pub async fn send_snapshot_rollback(socket: PathBuf, id: i64) -> Message {
    if let Err(e) = one_shot::<responses::SnapshotRollbackResponse>(
        &socket,
        Method::SnapshotRollback(SnapshotRollbackParams {
            id,
            new_name: None,
            keep_original: false,
        }),
    )
    .await
    {
        warn!(error = %e, snapshot_id = id, "snapshot rollback rpc failed");
    }
    Message::NoOp
}

/// One-shot snapshot diff RPC. Returns a `SnapshotDiffLoaded` message on success.
pub async fn send_snapshot_diff(socket: PathBuf, id_a: i64, id_b: i64) -> Message {
    match one_shot::<responses::SnapshotDiffResponse>(
        &socket,
        Method::SnapshotDiff(SnapshotDiffParams { id_a, id_b }),
    )
    .await
    {
        Ok(resp) => Message::SnapshotDiffLoaded(resp),
        Err(e) => {
            warn!(error = %e, id_a, id_b, "snapshot diff rpc failed");
            Message::NoOp
        }
    }
}

/// Fire-and-forget snapshot branch. Refresh comes via Snapshot event.
pub async fn send_snapshot_branch(socket: PathBuf, parent_id: i64) -> Message {
    if let Err(e) = one_shot::<responses::SnapshotBranchResponse>(
        &socket,
        Method::SnapshotBranch(SnapshotBranchParams {
            parent_id,
            label: None,
            fork: false,
        }),
    )
    .await
    {
        warn!(error = %e, parent_id, "snapshot branch rpc failed");
    }
    Message::NoOp
}

/// Fire-and-forget image push. Refresh / completion lands as an Image event
/// (`Succeeded` topic). The IPC response is logged at warn level on failure.
pub async fn send_image_push(
    socket: PathBuf,
    reference: String,
    registry: Option<String>,
    auth: Option<String>,
) -> Message {
    if let Err(e) = one_shot::<responses::ImagePushResponse>(
        &socket,
        Method::ImagePush(ImagePushParams {
            reference: reference.clone(),
            registry,
            auth,
            cert_dir: None,
        }),
    )
    .await
    {
        warn!(error = %e, %reference, "image push rpc failed");
    }
    Message::NoOp
}

/// Fire-and-forget snapshot remove. Refresh comes via Snapshot event.
pub async fn send_snapshot_remove(socket: PathBuf, id: i64) -> Message {
    if let Err(e) = one_shot::<serde_json::Value>(
        &socket,
        Method::SnapshotRemove(SnapshotRemoveParams { id, force: false }),
    )
    .await
    {
        warn!(error = %e, snapshot_id = id, "snapshot remove rpc failed");
    }
    Message::NoOp
}

/// Load the metrics history for a container (called when the user picks one in the
/// Metrics tab). The MetricsLatest path is also called once so we have at least one row
/// to show even when the ring buffer is still empty server-side.
pub async fn load_metrics_for_container(socket: PathBuf, container_id: String) -> Message {
    let history = match one_shot::<Vec<linpodx_common::ipc::MetricsSample>>(
        &socket,
        Method::MetricsHistory(MetricsHistoryParams {
            container_id: container_id.clone(),
            since: None,
        }),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, container = %container_id, "metrics history load failed");
            Vec::new()
        }
    };

    if !history.is_empty() {
        return Message::MetricsLoaded {
            container_id,
            samples: history,
        };
    }

    // Fall back to MetricsLatest when history is empty (the ring may have just one entry).
    match one_shot::<Option<linpodx_common::ipc::MetricsSample>>(
        &socket,
        Method::MetricsLatest(MetricsLatestParams {
            container_id: container_id.clone(),
        }),
    )
    .await
    {
        Ok(Some(s)) => Message::MetricsLoaded {
            container_id,
            samples: vec![s],
        },
        Ok(None) => Message::MetricsLoaded {
            container_id,
            samples: Vec::new(),
        },
        Err(e) => {
            warn!(error = %e, container = %container_id, "metrics latest load failed");
            Message::NoOp
        }
    }
}

/// Load a session timeline. Returns the result wrapped in a Message so the iced layer can
/// route it via `Task::perform`.
pub async fn load_session_timeline(socket: PathBuf, session_id: i64) -> Message {
    match one_shot::<Vec<responses::SessionTimelineEntry>>(
        &socket,
        Method::SessionTimeline(SessionTimelineParams {
            id: session_id,
            kinds: Vec::new(),
        }),
    )
    .await
    {
        Ok(entries) => Message::SessionTimelineLoaded {
            session_id,
            entries,
        },
        Err(e) => {
            warn!(error = %e, session_id, "session timeline load failed");
            Message::NoOp
        }
    }
}

/// Open a one-shot connection, send a single request, and decode the response.
pub async fn one_shot<T: serde::de::DeserializeOwned>(socket: &Path, method: Method) -> Result<T> {
    let stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!("connect {}", socket.display()))?;
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    call(&mut reader, &mut write, method).await
}
