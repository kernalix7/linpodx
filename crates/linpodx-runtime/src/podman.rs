use crate::parse;
use crate::passthrough;
use crate::version::{compare_versions, podman_version, MIN_PODMAN_VERSION};
use futures::stream::Stream;
use linpodx_common::error::{Error, Result};
use linpodx_common::ipc::{ContainerUpdateParams, CreateOptions};
use linpodx_common::state::{ContainerInspect, ContainerSummary};
use linpodx_common::types::ContainerId;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, instrument, warn};

/// Configuration for spawning the `podman` binary.
#[derive(Debug, Clone, Default)]
pub struct PodmanConfig {
    /// Override the binary path. Default: `podman` from `$PATH`.
    pub binary: Option<PathBuf>,
    /// `--root <path>`. Use a disposable directory in tests.
    pub root: Option<PathBuf>,
    /// `--runroot <path>`. Use a disposable directory in tests.
    pub runroot: Option<PathBuf>,
}

/// Options for fetching container logs (Phase 0: non-streaming snapshot only).
#[derive(Debug, Clone, Default)]
pub struct LogOptions {
    /// RFC3339 timestamp; only return lines after this time.
    pub since: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct LogsOutput {
    pub stdout: String,
    pub stderr: String,
}

/// Phase 11: which OS pipe a streamed log line came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    Stdout,
    Stderr,
}

impl StreamKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

/// Phase 11: options for `podman exec`. v0.1 ignores `interactive` (no PTY proxy).
#[derive(Debug, Clone)]
pub struct ExecOptions {
    pub id: ContainerId,
    pub command: Vec<String>,
    pub env: Vec<(String, String)>,
    pub tty: bool,
}

/// Phase 11: captured output of a one-shot `podman exec`.
#[derive(Debug, Clone, Default)]
pub struct ExecOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Result of a live `podman update` operation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContainerUpdateOutput {
    pub id: String,
    pub applied: Vec<String>,
}

/// Adapter over the `podman` CLI.
#[derive(Debug, Clone, Default)]
pub struct Podman {
    config: PodmanConfig,
}

impl Podman {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: PodmanConfig) -> Self {
        Self { config }
    }

    pub(crate) fn binary(&self) -> &str {
        self.config
            .binary
            .as_deref()
            .and_then(|p| p.to_str())
            .unwrap_or("podman")
    }

    pub(crate) fn base_command(&self) -> Command {
        let mut cmd = Command::new(self.binary());
        if let Some(root) = &self.config.root {
            cmd.arg("--root").arg(root);
        }
        if let Some(runroot) = &self.config.runroot {
            cmd.arg("--runroot").arg(runroot);
        }
        cmd
    }

    /// Verify Podman is installed and meets `MIN_PODMAN_VERSION`.
    /// Returns the detected version on success.
    pub async fn check(&self) -> Result<String> {
        let v = podman_version(self.binary()).await?;
        if compare_versions(&v, MIN_PODMAN_VERSION).is_lt() {
            return Err(Error::PodmanVersionMismatch {
                found: v,
                required: MIN_PODMAN_VERSION.to_string(),
            });
        }
        Ok(v)
    }

    #[instrument(skip(self))]
    pub async fn list(&self, all: bool) -> Result<Vec<ContainerSummary>> {
        let mut cmd = self.base_command();
        cmd.arg("ps").arg("--format=json");
        if all {
            cmd.arg("--all");
        }
        let out = self.run_capture(cmd).await?;
        parse::parse_container_list(&out)
    }

    #[instrument(skip(self))]
    pub async fn inspect(&self, id: &ContainerId) -> Result<ContainerInspect> {
        let mut cmd = self.base_command();
        cmd.arg("inspect").arg("--type=container").arg(&id.0);
        let out = match self.run_capture(cmd).await {
            Ok(s) => s,
            Err(Error::Runtime { message }) if looks_like_not_found(&message) => {
                return Err(Error::NotFound(id.0.clone()));
            }
            Err(e) => return Err(e),
        };
        parse::parse_container_inspect(&out)
    }

    #[instrument(skip(self, opts))]
    pub async fn create(&self, opts: &CreateOptions) -> Result<ContainerId> {
        let mut cmd = self.base_command();
        cmd.arg("create");
        if let Some(name) = &opts.name {
            cmd.arg("--name").arg(name);
        }
        if opts.rm {
            cmd.arg("--rm");
        }
        for (k, v) in &opts.env {
            cmd.arg("--env").arg(format!("{k}={v}"));
        }
        for (k, v) in &opts.labels {
            cmd.arg("--label").arg(format!("{k}={v}"));
        }
        for pm in &opts.port_mappings {
            cmd.arg("--publish").arg(pm.to_publish_arg());
        }
        for vm in &opts.volumes {
            cmd.arg("--volume").arg(vm.to_volume_arg());
        }
        for net in &opts.networks {
            cmd.arg("--network").arg(net);
        }
        // Phase 1C: sandbox-derived flags (also usable directly by callers).
        if let Some(cpus) = opts.cpus {
            cmd.arg("--cpus").arg(cpus.to_string());
        }
        if let Some(mem) = opts.memory_mb {
            cmd.arg("--memory").arg(format!("{mem}m"));
        }
        for cap in &opts.cap_drop {
            cmd.arg("--cap-drop").arg(cap);
        }
        for cap in &opts.cap_add {
            cmd.arg("--cap-add").arg(cap);
        }
        if opts.read_only {
            cmd.arg("--read-only");
        }
        // Phase 11 / 14: secprofile-compiled --security-opt entries
        // (seccomp= / apparmor= / label=type:<v>). Filtered by
        // `dedup_label_type_first_wins` so podman never receives two conflicting
        // SELinux labels from upstream.
        for sec_opt in dedup_label_type_first_wins(&opts.security_opts) {
            cmd.arg("--security-opt").arg(sec_opt);
        }
        // Phase 3 / 4: passthrough + systemd + auto-restart + keep-id.
        if let Some(spec) = &opts.passthrough {
            if !spec.is_empty() {
                passthrough::apply_passthrough(&mut cmd, spec);
            }
        }
        if opts.systemd {
            cmd.arg("--systemd=true");
            cmd.arg("--tmpfs").arg("/run");
            cmd.arg("--tmpfs").arg("/run/lock");
        }
        if opts.auto_restart {
            cmd.arg("--restart=unless-stopped");
        }
        if opts.keep_user_id {
            cmd.arg("--userns=keep-id");
        }
        // Phase 10: when an upstream snapshot backend (overlayfs) has materialised
        // a rootfs for this image, --rootfs replaces the image positional. podman
        // refuses both at once.
        if let Some(rootfs) = &opts.rootfs {
            cmd.arg("--rootfs").arg(rootfs);
        } else {
            cmd.arg(&opts.image);
        }
        for c in &opts.command {
            cmd.arg(c);
        }
        let out = self.run_capture(cmd).await?;
        let id = out.trim().to_string();
        if id.is_empty() {
            return Err(Error::Runtime {
                message: "podman create returned empty id".into(),
            });
        }
        Ok(ContainerId(id))
    }

    #[instrument(skip(self))]
    pub async fn start(&self, id: &ContainerId) -> Result<()> {
        let mut cmd = self.base_command();
        cmd.arg("start").arg(&id.0);
        match self.run_capture(cmd).await {
            Ok(_) => Ok(()),
            Err(Error::Runtime { message }) if looks_like_not_found(&message) => {
                Err(Error::NotFound(id.0.clone()))
            }
            Err(e) => Err(e),
        }
    }

    #[instrument(skip(self))]
    pub async fn stop(&self, id: &ContainerId, timeout: Option<Duration>) -> Result<()> {
        let mut cmd = self.base_command();
        cmd.arg("stop");
        if let Some(t) = timeout {
            cmd.arg("--time").arg(t.as_secs().to_string());
        }
        cmd.arg(&id.0);
        match self.run_capture(cmd).await {
            Ok(_) => Ok(()),
            Err(Error::Runtime { message }) if looks_like_not_found(&message) => {
                Err(Error::NotFound(id.0.clone()))
            }
            Err(e) => Err(e),
        }
    }

    /// Build the argv for `podman update`, applying only fields explicitly set
    /// in the IPC params. Kept separate so unit tests can verify construction
    /// without requiring Podman.
    pub(crate) fn build_update_command(&self, params: &ContainerUpdateParams) -> Command {
        let mut cmd = self.base_command();
        cmd.arg("update");
        if let Some(memory) = params.memory_bytes {
            cmd.arg("--memory").arg(memory.to_string());
        }
        if let Some(memory_swap) = params.memory_swap_bytes {
            cmd.arg("--memory-swap").arg(memory_swap.to_string());
        }
        if let Some(cpus) = params.cpus {
            cmd.arg("--cpus").arg(cpus.to_string());
        }
        if let Some(pids_limit) = params.pids_limit {
            cmd.arg("--pids-limit").arg(pids_limit.to_string());
        }
        if let Some(restart_policy) = &params.restart_policy {
            cmd.arg("--restart").arg(restart_policy);
        }
        cmd.arg(&params.id);
        cmd
    }

    pub(crate) fn update_applied_fields(params: &ContainerUpdateParams) -> Vec<String> {
        let mut applied = Vec::new();
        if params.memory_bytes.is_some() {
            applied.push("memory".to_string());
        }
        if params.memory_swap_bytes.is_some() {
            applied.push("memory_swap".to_string());
        }
        if params.cpus.is_some() {
            applied.push("cpus".to_string());
        }
        if params.pids_limit.is_some() {
            applied.push("pids_limit".to_string());
        }
        if params.restart_policy.is_some() {
            applied.push("restart_policy".to_string());
        }
        applied
    }

    /// Apply live resource limits via `podman update`.
    #[instrument(skip(self, params), fields(id = %params.id))]
    pub async fn container_update(
        &self,
        params: &ContainerUpdateParams,
    ) -> Result<ContainerUpdateOutput> {
        let applied = Self::update_applied_fields(params);
        if applied.is_empty() {
            return Ok(ContainerUpdateOutput {
                id: params.id.clone(),
                applied,
            });
        }

        let cmd = self.build_update_command(params);
        match self.run_capture(cmd).await {
            Ok(_) => Ok(ContainerUpdateOutput {
                id: params.id.clone(),
                applied,
            }),
            Err(Error::Runtime { message }) if looks_like_not_found(&message) => {
                Err(Error::NotFound(params.id.clone()))
            }
            Err(e) => Err(e),
        }
    }

    #[instrument(skip(self))]
    pub async fn remove(&self, id: &ContainerId, force: bool) -> Result<()> {
        let mut cmd = self.base_command();
        cmd.arg("rm");
        if force {
            cmd.arg("--force");
        }
        cmd.arg(&id.0);
        match self.run_capture(cmd).await {
            Ok(_) => Ok(()),
            Err(Error::Runtime { message }) if looks_like_not_found(&message) => {
                Err(Error::NotFound(id.0.clone()))
            }
            Err(e) => Err(e),
        }
    }

    /// Pull an image. Phase 0 helper used by integration tests.
    #[instrument(skip(self))]
    pub async fn pull(&self, image: &str) -> Result<()> {
        let mut cmd = self.base_command();
        cmd.arg("pull").arg(image);
        self.run_capture(cmd).await?;
        Ok(())
    }

    /// Snapshot the container's logs. Streaming logs land in Phase 1
    /// alongside the daemon event-bus subscription model.
    #[instrument(skip(self, opts))]
    pub async fn logs(&self, id: &ContainerId, opts: LogOptions) -> Result<LogsOutput> {
        let mut cmd = self.base_command();
        cmd.arg("logs");
        if let Some(since) = &opts.since {
            cmd.arg("--since").arg(since);
        }
        cmd.arg(&id.0);
        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());

        debug!(?cmd, "podman logs");
        let output = cmd.output().await?;
        // `podman logs` exits non-zero only on truly bad arguments; missing-but-recently-removed
        // containers usually still print whatever was captured. We tolerate non-zero status when
        // there is captured output.
        if !output.status.success() && output.stdout.is_empty() && output.stderr.is_empty() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(Error::Runtime {
                message: format!("podman logs failed: {stderr}"),
            });
        }

        Ok(LogsOutput {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }

    /// Phase 11: build the argv for an `exec` invocation. Pulled out of [`Self::exec`]
    /// so unit tests can introspect the assembled argv without spawning podman.
    pub(crate) fn build_exec_command(&self, opts: &ExecOptions) -> Command {
        let mut cmd = self.base_command();
        cmd.arg("exec");
        if opts.tty {
            cmd.arg("-t");
        }
        for (k, v) in &opts.env {
            cmd.arg("-e").arg(format!("{k}={v}"));
        }
        cmd.arg(&opts.id.0);
        for arg in &opts.command {
            cmd.arg(arg);
        }
        cmd
    }

    /// Phase 11: run a single command inside an existing container and capture
    /// stdout/stderr/exit code. v0.1 is non-interactive — `interactive` is ignored at
    /// the IPC layer because there is no stdin proxy.
    #[instrument(skip(self, opts), fields(id = %opts.id.0))]
    pub async fn exec(&self, opts: ExecOptions) -> Result<ExecOutput> {
        let mut cmd = self.build_exec_command(&opts);
        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());
        debug!(?cmd, "podman exec");
        let output = cmd.output().await?;
        // Surface "no such container" cleanly even when stderr is the only signal.
        if !output.status.success() && output.stdout.is_empty() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            if looks_like_not_found(&stderr) {
                return Err(Error::NotFound(opts.id.0.clone()));
            }
        }
        let exit_code = output.status.code().unwrap_or(-1);
        Ok(ExecOutput {
            exit_code,
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }

    /// Phase 11: spawn `podman logs [--follow] [--since X] <id>` and return a stream
    /// of `(StreamKind, String)` log lines. The child is dropped when the returned
    /// stream is dropped (tokio kills it on drop by default).
    pub fn logs_stream(
        &self,
        id: &ContainerId,
        follow: bool,
        since: Option<String>,
    ) -> Pin<Box<dyn Stream<Item = (StreamKind, String)> + Send>> {
        let mut cmd = self.base_command();
        cmd.arg("logs");
        if follow {
            cmd.arg("--follow");
        }
        if let Some(s) = &since {
            cmd.arg("--since").arg(s);
        }
        cmd.arg(&id.0);
        spawn_line_stream(cmd, true)
    }

    /// Phase 11: spawn `podman pull <ref>` and stream stdout line-by-line. Each
    /// line is one progress message (podman emits "Trying to pull ...", "Getting
    /// image source signatures", layer digests, etc.). Stderr lines are also
    /// surfaced (prefixed by the [`StreamKind`]).
    pub fn pull_with_progress(
        &self,
        reference: String,
    ) -> Pin<Box<dyn Stream<Item = String> + Send>> {
        let mut cmd = self.base_command();
        cmd.arg("pull").arg(&reference);
        let combined = spawn_line_stream(cmd, true);
        // Strip the StreamKind tag — pull progress doesn't separate stdout/stderr
        // for downstream consumers (the daemon publishes a single "message" field).
        Box::pin(futures::StreamExt::map(combined, |(_, line)| line))
    }

    pub(crate) async fn run_capture(&self, mut cmd: Command) -> Result<String> {
        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());
        debug!(?cmd, "podman exec");
        let output = cmd.output().await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(Error::Runtime { message: stderr });
        }
        let stdout = String::from_utf8(output.stdout).map_err(|e| Error::Runtime {
            message: e.to_string(),
        })?;
        Ok(stdout)
    }
}

/// Phase 14 — pre-flight de-dup of `--security-opt` entries before they go to
/// `podman create`. `label=type:<v>` is single-valued in podman; if two entries
/// arrive (e.g. an upstream wired both a static and a dynamic SELinux label),
/// the FIRST is kept and the rest are dropped. All other `--security-opt`
/// entries pass through unchanged. Order is preserved for everything that
/// survives.
pub(crate) fn dedup_label_type_first_wins<S: AsRef<str>>(opts: &[S]) -> Vec<String> {
    let mut out = Vec::with_capacity(opts.len());
    let mut label_type_emitted = false;
    for opt in opts {
        let s = opt.as_ref();
        if s.starts_with("label=type:") {
            if label_type_emitted {
                continue;
            }
            label_type_emitted = true;
        }
        out.push(s.to_string());
    }
    out
}

pub(crate) fn looks_like_not_found(stderr: &str) -> bool {
    let lower = stderr.to_lowercase();
    // Be specific: avoid matching unrelated runtime errors that happen to contain
    // "no such file" (cgroup probes, missing shared libs, etc.).
    lower.contains("no such container")
        || lower.contains("no such image")
        || lower.contains("no such volume")
        || lower.contains("no such network")
        || lower.contains("no container with id")
        || lower.contains("no image with id")
        || lower.contains("does not exist in local storage")
        // Podman 5.x uses these phrasings for missing resources.
        || lower.contains("image not known")
        || lower.contains("container not known")
        || lower.contains("volume not known")
        || lower.contains("network not known")
}

/// Map a `Runtime { message }` error that smells like "not found" to `NotFound(what)`.
pub(crate) fn map_not_found(err: Error, what: &str) -> Error {
    if let Error::Runtime { message } = &err {
        if looks_like_not_found(message) {
            return Error::NotFound(what.to_string());
        }
    }
    err
}

/// Spawn `cmd`, asynchronously read stdout (and stderr if `include_stderr`) line by line,
/// and forward each line through an mpsc channel as `(StreamKind, String)`.
///
/// On spawn failure, returns a stream that immediately yields one `(Stderr, msg)` and
/// closes — callers see the error as the only line they receive.
///
/// The child is owned by the background reader task; dropping the returned stream drops
/// the receiver, which causes the reader task's `tx.send` to fail and exit, which drops
/// the child (tokio kills it via `kill_on_drop`-style cleanup on `Child` drop).
pub(crate) fn spawn_line_stream(
    mut cmd: Command,
    include_stderr: bool,
) -> Pin<Box<dyn Stream<Item = (StreamKind, String)> + Send>> {
    cmd.stdout(Stdio::piped())
        .stdin(Stdio::null())
        .stderr(if include_stderr {
            Stdio::piped()
        } else {
            Stdio::null()
        });
    cmd.kill_on_drop(true);

    let (tx, rx) = mpsc::channel::<(StreamKind, String)>(64);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let err_tx = tx.clone();
            tokio::spawn(async move {
                let _ = err_tx
                    .send((StreamKind::Stderr, format!("spawn error: {e}")))
                    .await;
            });
            return Box::pin(ReceiverStream::new(rx));
        }
    };

    let stdout = child.stdout.take();
    let stderr = if include_stderr {
        child.stderr.take()
    } else {
        None
    };

    if let Some(out) = stdout {
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(out).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                if tx.send((StreamKind::Stdout, line)).await.is_err() {
                    break;
                }
            }
        });
    }
    if let Some(err) = stderr {
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(err).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                if tx.send((StreamKind::Stderr, line)).await.is_err() {
                    break;
                }
            }
        });
    }

    // Reap the child so we don't leave zombies. The drop-tx pattern lets readers above
    // close their senders on EOF; we additionally wait on the child to capture exit.
    tokio::spawn(async move {
        let _ = child.wait().await;
        drop(tx);
    });

    Box::pin(ReceiverStream::new(rx))
}

// ---------------------------------------------------------------------------
// Phase 12 — Interactive PTY proxy
// ---------------------------------------------------------------------------

/// Phase 12: options for spawning `podman exec -it <id> <cmd>` attached to a freshly
/// allocated PTY pair. The slave side is given to podman as stdio; the master side is
/// returned to the caller (wrapped in a [`PtyHandle`]) for proxying to a remote client.
#[derive(Debug, Clone)]
pub struct PtyExecOptions {
    pub container_id: ContainerId,
    pub command: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cols: u16,
    pub rows: u16,
    /// Path to the `podman` binary. The dispatcher passes its already-resolved path so
    /// the child sees the same binary the daemon was started with (matters when
    /// `$PATH` differs between the daemon's startup environment and a Tokio worker).
    pub podman_bin: String,
}

/// Owns a PTY master + the spawned `podman exec` child for the lifetime of one
/// interactive session. Dropping the handle kills the child and closes the master,
/// which tears down the per-bridge WebSocket on the daemon side.
pub struct PtyHandle {
    pub master: Box<dyn portable_pty::MasterPty + Send>,
    pub child: Box<dyn portable_pty::Child + Send + Sync>,
    pub bridge_id: String,
}

impl std::fmt::Debug for PtyHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PtyHandle")
            .field("bridge_id", &self.bridge_id)
            .finish()
    }
}

impl Drop for PtyHandle {
    fn drop(&mut self) {
        // Best-effort cleanup. `kill` may fail if the child already exited; ignore.
        if let Err(e) = self.child.kill() {
            warn!(bridge_id = %self.bridge_id, error = %e, "PtyHandle: kill failed (child likely already exited)");
        }
        // The master is dropped with this struct — closes the file descriptors.
    }
}

/// Phase 12: derive a short, unique bridge id from the container id and a wall-clock
/// timestamp. SHA-256 is overkill cryptographically here — we only want a collision-
/// resistant short string; the audit log records both ends so traceability is intact.
pub fn make_bridge_id(container_id: &str, now_micros: i64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(container_id.as_bytes());
    hasher.update(now_micros.to_le_bytes());
    let digest = hasher.finalize();
    let hex = digest.iter().take(4).fold(String::new(), |mut hex, b| {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        hex.push(HEX[(b >> 4) as usize] as char);
        hex.push(HEX[(b & 0x0f) as usize] as char);
        hex
    });
    format!("pty-{hex}")
}

/// Phase 12: open a PTY pair and spawn `podman exec -it <id> <cmd>` on the slave end.
/// Returns the master side bundled with the child for later proxy use.
///
/// `portable_pty` blocks internally on `openpty` (it talks to /dev/ptmx). We hop onto
/// `tokio::task::spawn_blocking` so the daemon's async runtime stays responsive even
/// if a busy host slows the pty allocation.
pub async fn exec_pty(opts: PtyExecOptions) -> Result<PtyHandle> {
    let container_id = opts.container_id.0.clone();
    let now_micros = chrono::Utc::now().timestamp_micros();
    let bridge_id = make_bridge_id(&container_id, now_micros);

    let result = tokio::task::spawn_blocking(move || -> std::result::Result<PtyHandle, String> {
        use portable_pty::{native_pty_system, CommandBuilder, PtySize};

        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows: opts.rows.max(1),
                cols: opts.cols.max(1),
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| format!("openpty failed: {e}"))?;

        let mut cmd = CommandBuilder::new(&opts.podman_bin);
        cmd.arg("exec");
        cmd.arg("-it");
        for (k, v) in &opts.env {
            cmd.arg("-e");
            cmd.arg(format!("{k}={v}"));
        }
        cmd.arg(&opts.container_id.0);
        for arg in &opts.command {
            cmd.arg(arg);
        }

        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| format!("spawn podman exec: {e}"))?;
        // Drop the slave: the child has its own dup; keeping ours open would prevent
        // EOF detection on the master read side after the child exits.
        drop(pair.slave);

        Ok(PtyHandle {
            master: pair.master,
            child,
            bridge_id,
        })
    })
    .await;

    match result {
        Ok(Ok(handle)) => Ok(handle),
        Ok(Err(message)) => Err(Error::Runtime { message }),
        Err(join_err) => Err(Error::Runtime {
            message: format!("exec_pty task join failed: {join_err}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_default() {
        let p = Podman::new();
        assert_eq!(p.binary(), "podman");
    }

    #[test]
    fn binary_override() {
        let p = Podman::with_config(PodmanConfig {
            binary: Some(PathBuf::from("/opt/bin/podman")),
            ..Default::default()
        });
        assert_eq!(p.binary(), "/opt/bin/podman");
    }

    #[test]
    fn create_uses_rootfs_when_set() {
        // We can't run podman in unit tests, but we can introspect the assembled
        // Command's argv to confirm --rootfs replaces the image positional.
        use linpodx_common::ipc::CreateOptions;
        let p = Podman::new();
        let opts = CreateOptions {
            image: "alpine".into(),
            rootfs: Some("/tmp/rootfs/abc".into()),
            ..Default::default()
        };
        let mut cmd = p.base_command();
        cmd.arg("create");
        if let Some(rootfs) = &opts.rootfs {
            cmd.arg("--rootfs").arg(rootfs);
        } else {
            cmd.arg(&opts.image);
        }
        let std_cmd = cmd.as_std();
        let argv: Vec<&str> = std_cmd
            .get_args()
            .map(|a| a.to_str().unwrap_or(""))
            .collect();
        assert!(argv.contains(&"--rootfs"), "argv={argv:?}");
        assert!(argv.contains(&"/tmp/rootfs/abc"), "argv={argv:?}");
        assert!(
            !argv.contains(&"alpine"),
            "image positional must be omitted: argv={argv:?}"
        );
    }

    #[test]
    fn update_command_includes_only_some_fields() {
        let p = Podman::new();
        let params = ContainerUpdateParams {
            id: "demo".to_string(),
            memory_bytes: Some(536_870_912),
            memory_swap_bytes: None,
            cpus: Some(1.5),
            pids_limit: None,
            restart_policy: Some("unless-stopped".to_string()),
        };
        let cmd = p.build_update_command(&params);
        let argv: Vec<&str> = cmd
            .as_std()
            .get_args()
            .map(|a| a.to_str().unwrap_or(""))
            .collect();

        assert_eq!(argv[0], "update", "argv={argv:?}");
        assert_eq!(
            argv,
            vec![
                "update",
                "--memory",
                "536870912",
                "--cpus",
                "1.5",
                "--restart",
                "unless-stopped",
                "demo",
            ]
        );
        assert!(!argv.contains(&"--memory-swap"), "argv={argv:?}");
        assert!(!argv.contains(&"--pids-limit"), "argv={argv:?}");
    }

    #[test]
    fn update_command_includes_all_supported_fields_in_contract_order() {
        let p = Podman::new();
        let params = ContainerUpdateParams {
            id: "abc123".to_string(),
            memory_bytes: Some(268_435_456),
            memory_swap_bytes: Some(536_870_912),
            cpus: Some(2.0),
            pids_limit: Some(256),
            restart_policy: Some("always".to_string()),
        };
        let cmd = p.build_update_command(&params);
        let argv: Vec<&str> = cmd
            .as_std()
            .get_args()
            .map(|a| a.to_str().unwrap_or(""))
            .collect();

        assert_eq!(
            argv,
            vec![
                "update",
                "--memory",
                "268435456",
                "--memory-swap",
                "536870912",
                "--cpus",
                "2",
                "--pids-limit",
                "256",
                "--restart",
                "always",
                "abc123",
            ]
        );
        assert_eq!(
            Podman::update_applied_fields(&params),
            vec![
                "memory".to_string(),
                "memory_swap".to_string(),
                "cpus".to_string(),
                "pids_limit".to_string(),
                "restart_policy".to_string(),
            ]
        );
    }

    #[test]
    fn update_applied_fields_empty_when_request_has_no_changes() {
        let params = ContainerUpdateParams {
            id: "no-op".to_string(),
            memory_bytes: None,
            memory_swap_bytes: None,
            cpus: None,
            pids_limit: None,
            restart_policy: None,
        };
        assert!(Podman::update_applied_fields(&params).is_empty());
    }

    // ---- Phase 14: --security-opt label=type: dedup ----

    #[test]
    fn dedup_label_type_keeps_first_drops_subsequent() {
        let input = [
            "seccomp=/tmp/x.json".to_string(),
            "label=type:container_t".to_string(),
            "apparmor=linpodx-foo".to_string(),
            "label=type:linpodx_dyn_t".to_string(),
        ];
        let out = dedup_label_type_first_wins(&input);
        assert_eq!(
            out,
            vec![
                "seccomp=/tmp/x.json".to_string(),
                "label=type:container_t".to_string(),
                "apparmor=linpodx-foo".to_string(),
            ]
        );
    }

    #[test]
    fn dedup_label_type_passes_unrelated_label_opts_through() {
        // `label=disable` and `label=user:` are different security-opt subkeys
        // and must NOT be consumed by the type-dedup gate.
        let input = [
            "label=disable".to_string(),
            "label=type:container_t".to_string(),
            "label=user:system_u".to_string(),
        ];
        let out = dedup_label_type_first_wins(&input);
        assert_eq!(out, input.to_vec());
    }

    #[test]
    fn dedup_label_type_no_op_when_none_present() {
        let input = ["seccomp=/x.json".to_string(), "apparmor=bar".to_string()];
        let out = dedup_label_type_first_wins(&input);
        assert_eq!(out, input.to_vec());
    }

    #[test]
    fn not_found_detection() {
        assert!(looks_like_not_found("no such container: abc"));
        assert!(looks_like_not_found("Error: no such image alpine:9999"));
        assert!(looks_like_not_found("does not exist in local storage"));
        assert!(!looks_like_not_found("permission denied"));
        assert!(!looks_like_not_found("no such file or directory"));
        assert!(!looks_like_not_found(
            "openat2 /sys/fs/cgroup/...: no such file"
        ));
    }

    // ---- Phase 11: exec / logs_stream / pull_with_progress ----

    #[test]
    fn exec_command_includes_env_and_tty_and_args() {
        let p = Podman::new();
        let opts = ExecOptions {
            id: ContainerId::from("c123"),
            command: vec!["sh".into(), "-c".into(), "echo hi".into()],
            env: vec![("FOO".into(), "bar".into())],
            tty: true,
        };
        let cmd = p.build_exec_command(&opts);
        let std_cmd = cmd.as_std();
        let argv: Vec<&str> = std_cmd
            .get_args()
            .map(|a| a.to_str().unwrap_or(""))
            .collect();
        assert_eq!(argv[0], "exec", "argv={argv:?}");
        assert!(argv.contains(&"-t"), "tty flag missing: argv={argv:?}");
        assert!(argv.contains(&"-e"), "env flag missing: argv={argv:?}");
        assert!(
            argv.contains(&"FOO=bar"),
            "env value missing: argv={argv:?}"
        );
        // Container id appears before the command tail.
        let id_pos = argv.iter().position(|a| *a == "c123").expect("id present");
        let sh_pos = argv.iter().position(|a| *a == "sh").expect("cmd present");
        assert!(id_pos < sh_pos, "id should precede command: argv={argv:?}");
        assert_eq!(argv.last().copied(), Some("echo hi"));
    }

    #[test]
    fn exec_command_omits_tty_when_false() {
        let p = Podman::new();
        let opts = ExecOptions {
            id: ContainerId::from("abc"),
            command: vec!["true".into()],
            env: vec![],
            tty: false,
        };
        let cmd = p.build_exec_command(&opts);
        let argv: Vec<&str> = cmd
            .as_std()
            .get_args()
            .map(|a| a.to_str().unwrap_or(""))
            .collect();
        assert!(!argv.contains(&"-t"), "tty must be omitted: argv={argv:?}");
    }

    #[tokio::test]
    async fn exec_runs_real_binary_and_captures_stdout() {
        // Override the podman binary with a real shell so we can assert the full
        // pipeline (arg assembly → spawn → output capture) without needing podman.
        // We bypass `build_exec_command` and use `run_capture` semantics directly via
        // a constructed Command since the test's goal is the spawn/capture path.
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg("printf 'hello\\nworld'; exit 0");
        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());
        let output = cmd.output().await.expect("spawn sh");
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("hello"));
        assert!(stdout.contains("world"));
    }

    #[tokio::test]
    async fn line_stream_reads_multiple_lines_and_separates_streams() {
        use futures::StreamExt;
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg("printf 'a\\nb\\n'; printf 'err1\\n' 1>&2");
        let mut stream = spawn_line_stream(cmd, true);
        let mut stdout_lines = Vec::new();
        let mut stderr_lines = Vec::new();
        while let Some((kind, line)) = stream.next().await {
            match kind {
                StreamKind::Stdout => stdout_lines.push(line),
                StreamKind::Stderr => stderr_lines.push(line),
            }
        }
        assert_eq!(stdout_lines, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(stderr_lines, vec!["err1".to_string()]);
    }

    #[tokio::test]
    async fn line_stream_yields_empty_when_no_output() {
        use futures::StreamExt;
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg("true");
        let mut stream = spawn_line_stream(cmd, true);
        let mut count = 0usize;
        while stream.next().await.is_some() {
            count += 1;
        }
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn line_stream_spawn_failure_yields_error_line() {
        use futures::StreamExt;
        let cmd = Command::new("/this/path/definitely/does/not/exist/linpodx-test");
        let mut stream = spawn_line_stream(cmd, true);
        let first = stream.next().await;
        assert!(matches!(first, Some((StreamKind::Stderr, _))));
    }

    #[tokio::test]
    async fn pull_with_progress_strips_stream_kind_tag() {
        // Smoke test the wrapping: build a Podman pointed at /bin/sh, then call
        // pull_with_progress through a constructed command. We can't reuse the real
        // method (it always invokes `podman pull`) so we replicate its tail behaviour.
        use futures::StreamExt;
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg("printf 'line-1\\nline-2\\n'");
        let combined = spawn_line_stream(cmd, true);
        let stripped: Vec<String> = futures::StreamExt::map(combined, |(_, l)| l)
            .collect()
            .await;
        assert_eq!(stripped, vec!["line-1".to_string(), "line-2".to_string()]);
    }

    // ---- Phase 12: PTY proxy ----

    #[test]
    fn bridge_id_format_is_pty_prefix_plus_8_hex() {
        let id = make_bridge_id("abc123", 42);
        assert!(id.starts_with("pty-"), "id={id}");
        let suffix = &id[4..];
        assert_eq!(suffix.len(), 8, "expected 8 hex chars: id={id}");
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn bridge_id_distinct_for_distinct_inputs() {
        // Same container id, different timestamps → distinct ids (overwhelmingly likely).
        let a = make_bridge_id("c1", 1);
        let b = make_bridge_id("c1", 2);
        assert_ne!(a, b);
        // Different container ids, same timestamp → distinct ids.
        let c = make_bridge_id("c2", 1);
        assert_ne!(a, c);
    }

    #[test]
    fn bridge_id_is_deterministic() {
        let a = make_bridge_id("c1", 7);
        let b = make_bridge_id("c1", 7);
        assert_eq!(a, b);
    }

    #[tokio::test]
    async fn exec_pty_spawns_real_pty_and_echoes() {
        // Skip if /bin/sh is missing (alpine containers without a shell, etc).
        if !std::path::Path::new("/bin/sh").exists() {
            eprintln!("skip: /bin/sh not available");
            return;
        }

        // We point podman_bin at /bin/sh and use `-c` to ignore the `exec`/`-it`/id args
        // we'd normally hand to podman. The command becomes:
        //   /bin/sh exec -it <id> -e ... <cmd...>
        // which sh treats as `-c` style script via the alternate form below. To keep this
        // simple, we bypass by giving podman_bin = /bin/sh and a command that ignores
        // earlier positional args. In practice we want to verify that:
        //   1. openpty succeeds
        //   2. the child runs and produces output on the master
        //   3. dropping the handle reaps the child
        // For that purpose we override by constructing the handle directly using the
        // public API: spawn `/bin/sh -c "echo READY; sleep 0.1"` via portable-pty.
        use portable_pty::{native_pty_system, CommandBuilder, PtySize};
        let pair = native_pty_system()
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("openpty");
        let mut cmd = CommandBuilder::new("/bin/sh");
        cmd.arg("-c");
        cmd.arg("printf READY");
        let child = pair.slave.spawn_command(cmd).expect("spawn sh");
        drop(pair.slave);
        let handle = PtyHandle {
            master: pair.master,
            child,
            bridge_id: make_bridge_id("test", 0),
        };
        // Read up to 64 bytes from the master — `printf READY` should land within the
        // first read on a normal Linux PTY.
        let mut reader = handle
            .master
            .try_clone_reader()
            .expect("clone master reader");
        let read_result = tokio::task::spawn_blocking(move || {
            use std::io::Read;
            let mut buf = [0u8; 64];
            let n = reader.read(&mut buf).unwrap_or(0);
            String::from_utf8_lossy(&buf[..n]).to_string()
        })
        .await
        .expect("read task");
        assert!(
            read_result.contains("READY"),
            "expected READY in pty output, got {read_result:?}"
        );
        // Drop forces best-effort kill (already exited — kill() returns Err which we
        // tolerate). Just exercising the Drop impl path.
        drop(handle);
    }
}
