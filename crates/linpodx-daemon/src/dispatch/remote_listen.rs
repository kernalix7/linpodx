//! Remote daemon (WebSocket transport) dispatch handlers — auth probe plus
//! runtime start/stop/status of the `--remote-listen` listener.

use super::*;

impl Dispatcher {
    pub(crate) async fn remote_auth(
        &self,
        p: linpodx_common::ipc::RemoteAuthParams,
    ) -> Result<serde_json::Value> {
        let slot = self.remote.lock().await;
        let accepted = match slot.as_ref() {
            Some(handle) => constant_eq(&p.token, &handle.state.token),
            None => false,
        };
        Ok(serde_json::to_value(responses::RemoteAuthResponse {
            accepted,
            since: chrono::Utc::now(),
        })?)
    }

    pub(crate) async fn remote_listen_start(
        &self,
        p: linpodx_common::ipc::RemoteListenStartParams,
    ) -> Result<serde_json::Value> {
        let addr: std::net::SocketAddr = p
            .addr
            .parse()
            .map_err(|e| Error::InvalidArgument(format!("bad addr '{}': {e}", p.addr)))?;
        if p.token.trim().is_empty() {
            return Err(Error::InvalidArgument("empty remote token".into()));
        }
        let dispatcher = Arc::new(self.clone());
        // Runtime-spawned listener via IPC currently always plain (no TLS).
        // mTLS is opt-in only via daemon startup flags; the IPC schema would
        // need a TLS variant to support it at runtime.
        let handle = remote::spawn(
            addr,
            p.token.clone(),
            dispatcher,
            Arc::clone(&self.audit),
            None,
            false,
        )
        .map_err(|e| Error::Runtime {
            message: format!("remote bind failed: {e}"),
        })?;
        let actual_addr = handle.state.addr.to_string();
        {
            let mut slot = self.remote.lock().await;
            if let Some(prev) = slot.take() {
                prev.shutdown().await;
            }
            *slot = Some(handle);
        }
        Ok(serde_json::to_value(
            responses::RemoteListenStartResponse { addr: actual_addr },
        )?)
    }

    pub(crate) async fn remote_listen_stop(&self) -> Result<serde_json::Value> {
        let stopped = {
            let mut slot = self.remote.lock().await;
            slot.take()
        };
        let was_running = stopped.is_some();
        if let Some(handle) = stopped {
            handle.shutdown().await;
        }
        Ok(serde_json::to_value(responses::RemoteListenStopResponse {
            stopped: was_running,
        })?)
    }

    pub(crate) async fn remote_listen_status(&self) -> Result<serde_json::Value> {
        let slot = self.remote.lock().await;
        let resp = match slot.as_ref() {
            Some(handle) => responses::RemoteListenStatusResponse {
                addr: Some(handle.state.addr.to_string()),
                running: !handle.task.is_finished(),
                sessions: handle
                    .state
                    .sessions
                    .load(std::sync::atomic::Ordering::SeqCst),
            },
            None => responses::RemoteListenStatusResponse {
                addr: None,
                running: false,
                sessions: 0,
            },
        };
        Ok(serde_json::to_value(resp)?)
    }
}
