//! Daemon lifecycle + first-run diagnostics + Web UI ensure dispatch handlers.

use super::*;

impl Dispatcher {
    // ----- Phase 18 Stream C: first-run readiness diagnostics -----
    pub(crate) async fn doctor_run(
        &self,
        _params: linpodx_common::ipc::DoctorRunParams,
    ) -> Result<serde_json::Value> {
        let report = self.run_doctor().await;
        Ok(serde_json::to_value(report)?)
    }

    // ----- Phase 18 Stream D: daemon-side daemon-mgmt arms -----
    //
    // Design: the *primary* surface for `linpodx daemon
    // {start,stop,status,logs}` lives on the CLI
    // (`crates/linpodx-cli/src/commands/daemon_mgmt.rs`). The CLI
    // spawns/signals/probes the daemon process directly via the
    // pid-file + /proc — no IPC required. These IPC arms exist so
    // that:
    //   - a *remote* CLI session over the WebSocket transport can
    //     ask the running daemon about its own state; and
    //   - tooling that only speaks JSON-RPC has a clean way to get
    //     the same answer.
    //
    // `Start` / `Stop` are informational: a daemon cannot
    // meaningfully start itself, and shutting itself down over IPC
    // would require a graceful-stop path we have not built. Both
    // return `Running` with a message pointing the caller at the
    // CLI.
    pub(crate) async fn daemon_mgmt_start(
        &self,
        _params: linpodx_common::ipc::DaemonMgmtStartParams,
    ) -> Result<serde_json::Value> {
        let resp = responses::DaemonMgmtStartResponse {
            state: responses::DaemonMgmtState::Running,
            pid: Some(std::process::id()),
            pid_file: None,
            message: Some(
                "daemon is already running; use the CLI on the host (`linpodx daemon start`) to spawn a new instance"
                    .to_string(),
            ),
        };
        Ok(serde_json::to_value(resp)?)
    }

    pub(crate) async fn daemon_mgmt_stop(&self) -> Result<serde_json::Value> {
        let resp = responses::DaemonMgmtStopResponse {
            state: responses::DaemonMgmtState::Running,
            message: Some(
                "stop over IPC is not supported; signal the daemon directly (`linpodx daemon stop` or `kill -TERM <pid>`)"
                    .to_string(),
            ),
        };
        Ok(serde_json::to_value(resp)?)
    }

    pub(crate) async fn daemon_mgmt_status(&self) -> Result<serde_json::Value> {
        let pid_file = crate::config::default_pid_file_path();
        let resp = responses::DaemonMgmtStatusResponse {
            state: responses::DaemonMgmtState::Running,
            pid: Some(std::process::id()),
            pid_file: if pid_file.exists() {
                Some(pid_file)
            } else {
                None
            },
            socket_path: self.socket_path.clone(),
            uptime_secs: Some(self.start_time.elapsed().as_secs()),
        };
        Ok(serde_json::to_value(resp)?)
    }

    pub(crate) async fn web_ui_ensure(
        &self,
        _: linpodx_common::ipc::WebUiEnsureParams,
    ) -> Result<serde_json::Value> {
        let resp = crate::web_ui_local::ensure(self).await?;
        Ok(serde_json::to_value(resp)?)
    }
}
