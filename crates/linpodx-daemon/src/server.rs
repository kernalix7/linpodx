use crate::dispatch::Dispatcher;
use linpodx_common::approval::{ApprovalRequest, ApprovalResolved};
use linpodx_common::ipc::{
    error_codes, responses, EventTopic, JsonRpcVersion, Method, Notification, RpcError, RpcRequest,
    RpcResponse, ServerMessage,
};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, instrument, warn};

/// Run the accept loop until `shutdown` is fired. Each connection is handled in its own task.
#[instrument(skip(listener, dispatcher, shutdown))]
pub async fn run(listener: UnixListener, dispatcher: Arc<Dispatcher>, shutdown: CancellationToken) {
    info!("accepting connections");
    let mut conn_id: u64 = 0;
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                info!("shutdown signal received, stopping accept loop");
                break;
            }
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _addr)) => {
                        conn_id += 1;
                        let d = Arc::clone(&dispatcher);
                        let shutdown = shutdown.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(conn_id, stream, d, shutdown).await {
                                error!(conn_id, error = %e, "connection handler errored");
                            }
                        });
                    }
                    Err(e) => {
                        error!(error = %e, "accept failed");
                    }
                }
            }
        }
    }
}

#[instrument(skip(stream, dispatcher, shutdown))]
async fn handle_connection(
    conn_id: u64,
    stream: tokio::net::UnixStream,
    dispatcher: Arc<Dispatcher>,
    shutdown: CancellationToken,
) -> std::io::Result<()> {
    debug!(conn_id, "connection accepted");
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half).lines();

    // Per-connection subscription state. `subscribed_topics.is_empty()` means no active subscription.
    let mut subscribed_topics: HashSet<EventTopic> = HashSet::new();
    let mut subscription: Option<broadcast::Receiver<linpodx_common::ipc::Event>> = None;
    // Phase 2A: Subscribe to approval requests at the same time as the event subscription.
    // Each connection that calls `Subscribe` becomes a candidate listener for approvals.
    let mut approval_subscription: Option<broadcast::Receiver<ApprovalRequest>> = None;
    // Phase 2A follow-up: also subscribe to resolved-notifications so listeners can
    // dismiss their prompt UI when another listener answered first.
    let mut approval_resolved_subscription: Option<broadcast::Receiver<ApprovalResolved>> = None;

    loop {
        tokio::select! {
            biased;

            _ = shutdown.cancelled() => {
                debug!(conn_id, "shutdown — closing connection");
                break;
            }

            line = reader.next_line() => {
                match line {
                    Ok(Some(raw)) => {
                        if raw.trim().is_empty() {
                            continue;
                        }
                        if let Err(e) = handle_request(
                            &raw,
                            &dispatcher,
                            &mut write_half,
                            &mut subscription,
                            &mut subscribed_topics,
                            &mut approval_subscription,
                            &mut approval_resolved_subscription,
                        ).await {
                            warn!(conn_id, error = %e, "request handling errored");
                            break;
                        }
                    }
                    Ok(None) => {
                        debug!(conn_id, "client closed connection");
                        break;
                    }
                    Err(e) => {
                        warn!(conn_id, error = %e, "read error");
                        break;
                    }
                }
            }

            event = recv_event(subscription.as_mut()) => {
                if let Some(event) = event {
                    if subscribed_topics.contains(&event.topic) {
                        let notif = ServerMessage::Notification(Notification::event(&event));
                        if let Err(e) = write_message(&mut write_half, &notif).await {
                            warn!(conn_id, error = %e, "event write error");
                            break;
                        }
                    }
                }
                // None = subscription was None or returned RecvError; ignore and loop.
            }

            approval = recv_approval(approval_subscription.as_mut()) => {
                if let Some(req) = approval {
                    let notif = ServerMessage::Notification(Notification {
                        jsonrpc: JsonRpcVersion::V2,
                        method: "approval_request".into(),
                        params: serde_json::to_value(&req).unwrap_or(serde_json::Value::Null),
                    });
                    if let Err(e) = write_message(&mut write_half, &notif).await {
                        warn!(conn_id, error = %e, "approval write error");
                        break;
                    }
                }
            }

            resolved = recv_resolved(approval_resolved_subscription.as_mut()) => {
                if let Some(res) = resolved {
                    let notif = ServerMessage::Notification(Notification {
                        jsonrpc: JsonRpcVersion::V2,
                        method: "approval_resolved".into(),
                        params: serde_json::to_value(&res).unwrap_or(serde_json::Value::Null),
                    });
                    if let Err(e) = write_message(&mut write_half, &notif).await {
                        warn!(conn_id, error = %e, "approval_resolved write error");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

async fn recv_resolved(
    rx: Option<&mut broadcast::Receiver<ApprovalResolved>>,
) -> Option<ApprovalResolved> {
    match rx {
        Some(rx) => match rx.recv().await {
            Ok(res) => Some(res),
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                warn!(skipped, "approval_resolved subscriber lagged");
                None
            }
            Err(broadcast::error::RecvError::Closed) => None,
        },
        None => std::future::pending().await,
    }
}

async fn recv_approval(
    rx: Option<&mut broadcast::Receiver<ApprovalRequest>>,
) -> Option<ApprovalRequest> {
    match rx {
        Some(rx) => match rx.recv().await {
            Ok(req) => Some(req),
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                warn!(skipped, "approval subscriber lagged");
                None
            }
            Err(broadcast::error::RecvError::Closed) => None,
        },
        None => std::future::pending().await,
    }
}

/// Wait for the next event from the subscription, if any. When `rx` is `None`
/// (no active subscription on this connection) this future never resolves —
/// otherwise the surrounding `tokio::select!` would busy-loop.
async fn recv_event(
    rx: Option<&mut broadcast::Receiver<linpodx_common::ipc::Event>>,
) -> Option<linpodx_common::ipc::Event> {
    match rx {
        Some(rx) => match rx.recv().await {
            Ok(event) => Some(event),
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                warn!(skipped, "event subscriber lagged");
                None
            }
            Err(broadcast::error::RecvError::Closed) => None,
        },
        None => std::future::pending().await,
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_request(
    raw: &str,
    dispatcher: &Arc<Dispatcher>,
    write_half: &mut tokio::net::unix::OwnedWriteHalf,
    subscription: &mut Option<broadcast::Receiver<linpodx_common::ipc::Event>>,
    subscribed_topics: &mut HashSet<EventTopic>,
    approval_subscription: &mut Option<broadcast::Receiver<ApprovalRequest>>,
    approval_resolved_subscription: &mut Option<broadcast::Receiver<ApprovalResolved>>,
) -> std::io::Result<()> {
    let req: RpcRequest = match serde_json::from_str(raw) {
        Ok(r) => r,
        Err(e) => {
            let resp = RpcResponse::error(
                None,
                RpcError {
                    code: error_codes::PARSE_ERROR,
                    message: format!("parse error: {e}"),
                    data: None,
                },
            );
            return write_message(write_half, &ServerMessage::Response(resp)).await;
        }
    };

    let response = match &req.method {
        Method::Subscribe(params) => {
            let topics = if params.topics.is_empty() {
                EventTopic::ALL.iter().copied().collect::<HashSet<_>>()
            } else {
                params.topics.iter().copied().collect::<HashSet<_>>()
            };
            *subscribed_topics = topics.clone();
            // Drain any backlog by re-subscribing — subscriber starts seeing events from now on.
            *subscription = Some(dispatcher.event_bus.subscribe());
            // Phase 2A: same Subscribe call also opts the connection in for approvals.
            *approval_subscription = Some(dispatcher.approvals.subscribe());
            *approval_resolved_subscription = Some(dispatcher.approvals.subscribe_resolved());
            let ack = responses::SubscribeResponse {
                topics: topics.into_iter().collect(),
                since: chrono::Utc::now(),
            };
            RpcResponse {
                jsonrpc: JsonRpcVersion::V2,
                id: req.id.clone(),
                payload: linpodx_common::ipc::ResponsePayload::Success {
                    result: serde_json::to_value(ack).unwrap_or(serde_json::Value::Null),
                },
            }
        }
        // Phase 3: approvals-only subscription. Lets a listener (e.g. a dedicated GUI
        // modal stream) opt in without subscribing to the event firehose.
        Method::ApprovalsSubscribe => {
            *approval_subscription = Some(dispatcher.approvals.subscribe());
            *approval_resolved_subscription = Some(dispatcher.approvals.subscribe_resolved());
            let ack = responses::ApprovalsSubscribeResponse {
                since: chrono::Utc::now(),
            };
            RpcResponse {
                jsonrpc: JsonRpcVersion::V2,
                id: req.id.clone(),
                payload: linpodx_common::ipc::ResponsePayload::Success {
                    result: serde_json::to_value(ack).unwrap_or(serde_json::Value::Null),
                },
            }
        }
        _ => dispatcher.dispatch(req).await,
    };

    write_message(write_half, &ServerMessage::Response(response)).await
}

async fn write_message(
    write_half: &mut tokio::net::unix::OwnedWriteHalf,
    msg: &ServerMessage,
) -> std::io::Result<()> {
    let mut payload = serde_json::to_vec(msg).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("serialize: {e}"))
    })?;
    payload.push(b'\n');
    write_half.write_all(&payload).await
}
