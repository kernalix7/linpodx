//! Per-container metrics collector (Phase 6).
//!
//! Spawns one tokio task per active container that calls
//! `podman stats --no-stream --format json <id>` once per second, parses the result, pushes
//! it into a bounded ring buffer, and broadcasts a `Progress` event on the
//! [`EventTopic::Metrics`](linpodx_common::ipc::EventTopic) topic.
//!
//! Ring capacity is fixed at [`RING_CAPACITY`] samples per container (~10 minutes of
//! 1-second samples). Stage 3 wires this into the daemon's container start / stop hooks.

use chrono::{DateTime, Utc};
use linpodx_common::audit_sink::{AuditSink, AuditSinkKind};
use linpodx_common::events::EventPublisher;
use linpodx_common::ipc::{Event, EventKind, EventTopic, MetricsSample};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::debug;

/// Number of samples retained per container in the ring buffer.
pub const RING_CAPACITY: usize = 600;

/// Polling interval between successive `podman stats --no-stream` invocations.
pub const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

/// Bounded ring buffer; pushes past capacity drop the oldest element.
#[derive(Debug, Clone)]
pub struct RingBuffer<T> {
    capacity: usize,
    items: VecDeque<T>,
}

impl<T> RingBuffer<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            items: VecDeque::with_capacity(capacity.max(1)),
        }
    }

    pub fn push(&mut self, item: T) {
        if self.items.len() == self.capacity {
            self.items.pop_front();
        }
        self.items.push_back(item);
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.items.iter()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

type RingMap = HashMap<String, RingBuffer<MetricsSample>>;

/// Owner of the per-container collector tasks and their ring buffers.
#[derive(Clone)]
pub struct MetricsCollector {
    inner: Arc<CollectorInner>,
}

struct CollectorInner {
    handles: Mutex<HashMap<String, JoinHandle<()>>>,
    rings: Arc<Mutex<RingMap>>,
    podman_bin: String,
    publisher: Arc<dyn EventPublisher>,
    audit: Arc<dyn AuditSink>,
}

impl MetricsCollector {
    pub fn new(
        podman_bin: String,
        publisher: Arc<dyn EventPublisher>,
        audit: Arc<dyn AuditSink>,
    ) -> Self {
        Self {
            inner: Arc::new(CollectorInner {
                handles: Mutex::new(HashMap::new()),
                rings: Arc::new(Mutex::new(HashMap::new())),
                podman_bin,
                publisher,
                audit,
            }),
        }
    }

    /// Start collection for `container_id`. Idempotent — re-spawning for the same id
    /// silently no-ops while a task is already running.
    pub async fn spawn_for(&self, container_id: String) {
        let mut handles = self.inner.handles.lock().await;
        if handles
            .get(&container_id)
            .map(|h| !h.is_finished())
            .unwrap_or(false)
        {
            return;
        }
        // Reset any prior ring entry so callers see a clean buffer for the new lifetime.
        {
            let mut rings = self.inner.rings.lock().await;
            rings.insert(container_id.clone(), RingBuffer::new(RING_CAPACITY));
        }

        self.inner
            .audit
            .record(
                AuditSinkKind::MetricsCollectorStarted,
                None,
                Some(container_id.clone()),
                serde_json::json!({}),
            )
            .await;

        let podman_bin = self.inner.podman_bin.clone();
        let rings = Arc::clone(&self.inner.rings);
        let publisher = Arc::clone(&self.inner.publisher);
        let cid = container_id.clone();
        let handle = tokio::spawn(async move {
            collector_loop(podman_bin, cid, rings, publisher).await;
        });
        handles.insert(container_id, handle);
    }

    /// Stop collection for `container_id`. Aborts the task if running, drops the ring
    /// buffer, and emits a `MetricsCollectorStopped` audit entry.
    pub async fn stop_for(&self, container_id: &str) {
        let removed = {
            let mut handles = self.inner.handles.lock().await;
            handles.remove(container_id)
        };
        if let Some(handle) = removed {
            handle.abort();
        }
        {
            let mut rings = self.inner.rings.lock().await;
            rings.remove(container_id);
        }
        self.inner
            .audit
            .record(
                AuditSinkKind::MetricsCollectorStopped,
                None,
                Some(container_id.to_string()),
                serde_json::json!({}),
            )
            .await;
    }

    /// Reconcile the live collector set against the set of currently-running
    /// container ids. Spawns a collector for every running id that is not yet
    /// tracked (covers containers started directly via podman and those already
    /// running when the daemon booted) and stops collectors whose container is
    /// no longer running (their `podman stats` loop would otherwise poll a dead
    /// container forever, since a direct `podman stop` never routes through
    /// [`stop_for`]). Idempotent — safe to call on a fixed interval.
    ///
    /// Matching is prefix-tolerant in both directions so a collector keyed by a
    /// short id (or name) is not spuriously pruned when the list surface returns
    /// full ids.
    pub async fn reconcile_running(&self, running_ids: &[String]) {
        for id in running_ids {
            self.spawn_for(id.clone()).await;
        }
        let tracked: Vec<String> = {
            let handles = self.inner.handles.lock().await;
            handles.keys().cloned().collect()
        };
        for id in tracked {
            let still_running = running_ids
                .iter()
                .any(|r| r == &id || r.starts_with(&id) || id.starts_with(r.as_str()));
            if !still_running {
                self.stop_for(&id).await;
            }
        }
    }

    /// Return the most recent sample for `container_id`, if any.
    pub async fn latest(&self, container_id: &str) -> Option<MetricsSample> {
        let rings = self.inner.rings.lock().await;
        rings
            .get(container_id)
            .and_then(|r| r.iter().last().cloned())
    }

    /// Return all samples for `container_id` whose `ts >= since` (inclusive). When `since`
    /// is `None`, returns the full ring buffer.
    pub async fn history(
        &self,
        container_id: &str,
        since: Option<DateTime<Utc>>,
    ) -> Vec<MetricsSample> {
        let rings = self.inner.rings.lock().await;
        match rings.get(container_id) {
            None => Vec::new(),
            Some(r) => match since {
                None => r.iter().cloned().collect(),
                Some(cutoff) => r.iter().filter(|s| s.ts >= cutoff).cloned().collect(),
            },
        }
    }

    /// Test-only helper: directly insert a sample into the ring (bypasses podman). Used by
    /// the unit tests that don't run a real podman binary.
    #[cfg(test)]
    pub(crate) async fn push_sample_for_test(&self, container_id: &str, sample: MetricsSample) {
        let mut rings = self.inner.rings.lock().await;
        rings
            .entry(container_id.to_string())
            .or_insert_with(|| RingBuffer::new(RING_CAPACITY))
            .push(sample);
    }

    /// Test-only helper: returns whether a task is registered for `container_id`.
    #[cfg(test)]
    pub(crate) async fn has_handle(&self, container_id: &str) -> bool {
        let handles = self.inner.handles.lock().await;
        handles.contains_key(container_id)
    }
}

async fn collector_loop(
    podman_bin: String,
    container_id: String,
    rings: Arc<Mutex<RingMap>>,
    publisher: Arc<dyn EventPublisher>,
) {
    // cgroup v2 fast path state — resolved lazily on the first sample so we don't
    // pay an inspect call when cgroup v2 isn't even present.
    let cgroup_v2 = cgroup_v2_check();
    let mut cgroup_pid: Option<u32> = None;
    let mut prev_cpu_usec: Option<u64> = None;
    let mut prev_ts: Option<DateTime<Utc>> = None;

    loop {
        tokio::time::sleep(SAMPLE_INTERVAL).await;

        let mut sample: Option<MetricsSample> = None;

        if cgroup_v2 {
            if cgroup_pid.is_none() {
                cgroup_pid = inspect_pid(&podman_bin, &container_id).await;
            }
            if let Some(pid) = cgroup_pid {
                if let Some(mut s) = cgroup_sample(pid, &container_id) {
                    let now_us = read_cpu_usec_for_pid(pid).unwrap_or(0);
                    if let (Some(prev_us), Some(prev)) = (prev_cpu_usec, prev_ts) {
                        let dt_secs = (s.ts - prev).num_milliseconds() as f64 / 1000.0;
                        let cpu_delta = now_us.saturating_sub(prev_us) as f64 / 1_000_000.0;
                        s.cpu_pct = if dt_secs > 0.0 {
                            cpu_delta / dt_secs
                        } else {
                            0.0
                        };
                    } else {
                        s.cpu_pct = 0.0;
                    }
                    prev_cpu_usec = Some(now_us);
                    prev_ts = Some(s.ts);
                    sample = Some(s);
                }
            }
        }

        let sample = match sample {
            Some(s) => s,
            None => {
                let raw = match run_podman_stats(&podman_bin, &container_id).await {
                    Ok(s) => s,
                    Err(e) => {
                        debug!(error = %e, container = %container_id, "podman stats invocation failed");
                        continue;
                    }
                };
                match parse_podman_stats(&container_id, &raw) {
                    Some(s) => s,
                    None => {
                        debug!(container = %container_id, "no parseable sample in podman stats output");
                        continue;
                    }
                }
            }
        };
        {
            let mut guard = rings.lock().await;
            guard
                .entry(container_id.clone())
                .or_insert_with(|| RingBuffer::new(RING_CAPACITY))
                .push(sample.clone());
        }
        publisher.publish(Event {
            topic: EventTopic::Metrics,
            kind: EventKind::Progress,
            resource_id: container_id.clone(),
            timestamp: sample.ts,
            details: serde_json::to_value(&sample).unwrap_or(serde_json::Value::Null),
        });
    }
}

/// Look up the container's main process PID via `podman inspect`. Returns None on
/// failure — caller falls back to podman-stats.
async fn inspect_pid(podman_bin: &str, container_id: &str) -> Option<u32> {
    let mut cmd = Command::new(podman_bin);
    cmd.arg("inspect")
        .arg("--format")
        .arg("{{.State.Pid}}")
        .arg(container_id)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    let output = cmd.output().await.ok()?;
    if !output.status.success() {
        return None;
    }
    let s = String::from_utf8(output.stdout).ok()?;
    let trimmed = s.trim();
    let pid: u32 = trimmed.parse().ok()?;
    if pid == 0 {
        None
    } else {
        Some(pid)
    }
}

fn read_cpu_usec_for_pid(pid: u32) -> Option<u64> {
    let path = cgroup_v2_path_for_pid(Path::new("/proc"), pid)?;
    let cpu_stat_path = PathBuf::from("/sys/fs/cgroup").join(strip_leading_slash(&path));
    let cpu_stat = std::fs::read_to_string(cpu_stat_path.join("cpu.stat")).ok()?;
    parse_usage_usec(&cpu_stat)
}

/// Returns true when the host is running cgroup v2 (unified hierarchy). Best-effort —
/// false on read failure or when the path is missing.
pub fn cgroup_v2_check() -> bool {
    std::fs::read_to_string("/sys/fs/cgroup/cgroup.controllers").is_ok()
}

/// Sample container metrics directly from cgroup v2 + /proc — avoids the cost of
/// spawning `podman stats`. Returns `None` when any required file is missing or
/// unreadable (caller should fall back to podman-stats).
///
/// Note: `cpu_pct` is returned as 0.0 here; the caller is responsible for computing
/// a delta against the previous sample's `usage_usec`.
pub fn cgroup_sample(pid: u32, container_id: &str) -> Option<MetricsSample> {
    sample_from_roots(
        Path::new("/proc"),
        Path::new("/sys/fs/cgroup"),
        pid,
        container_id,
    )
}

fn sample_from_roots(
    proc_root: &Path,
    cgroup_root: &Path,
    pid: u32,
    container_id: &str,
) -> Option<MetricsSample> {
    let path = cgroup_v2_path_for_pid(proc_root, pid)?;
    let cgroup_dir = cgroup_root.join(strip_leading_slash(&path));

    let cpu_stat = std::fs::read_to_string(cgroup_dir.join("cpu.stat")).ok();
    let _cpu_usec = cpu_stat.as_deref().and_then(parse_usage_usec).unwrap_or(0);

    let mem_bytes = match std::fs::read_to_string(cgroup_dir.join("memory.current")) {
        Ok(s) => s.trim().parse::<u64>().unwrap_or(0),
        // The memory controller isn't delegated (common rootless default is
        // `Delegate=pids` only), so `memory.current` does not exist anywhere in
        // the container's subtree. Approximate from the pids controller we DO
        // have: sum PSS (fallback RSS) over every process in the container's
        // scope. PSS prorates shared pages, so the sum stays honest.
        Err(_) => procfs_mem_fallback(proc_root, &cgroup_dir).unwrap_or(0),
    };

    let mem_limit = std::fs::read_to_string(cgroup_dir.join("memory.max"))
        .ok()
        .and_then(|s| {
            let t = s.trim();
            if t == "max" {
                None
            } else {
                t.parse::<u64>().ok()
            }
        });

    let net = std::fs::read_to_string(proc_root.join(format!("{pid}/net/dev"))).ok();
    let (net_rx, net_tx) = net.as_deref().map(parse_proc_net_dev).unwrap_or((0, 0));

    Some(MetricsSample {
        container_id: container_id.to_string(),
        ts: Utc::now(),
        cpu_pct: 0.0,
        mem_bytes,
        mem_limit,
        net_rx,
        net_tx,
        block_in: 0,
        block_out: 0,
    })
}

/// Userspace memory approximation for hosts without memory-controller
/// delegation. Walks the container's scope subtree (starting from the
/// `libpod-*.scope` ancestor of the sampled cgroup when present, else the
/// sampled cgroup itself), collects every pid from `cgroup.procs`, and sums
/// per-process PSS from `smaps_rollup` (falling back to `VmRSS` from `status`
/// when `smaps_rollup` is unreadable). Returns `None` when no process could be
/// measured, so callers can distinguish "no data" from a genuine 0.
fn procfs_mem_fallback(proc_root: &Path, cgroup_dir: &Path) -> Option<u64> {
    let walk_root = libpod_scope_ancestor(cgroup_dir).unwrap_or_else(|| cgroup_dir.to_path_buf());
    let mut total: u64 = 0;
    let mut counted = false;
    for dir in walk_cgroup_dirs(&walk_root, 6) {
        let Ok(procs) = std::fs::read_to_string(dir.join("cgroup.procs")) else {
            continue;
        };
        for pid in procs.lines().filter_map(|l| l.trim().parse::<u32>().ok()) {
            if let Some(bytes) = mem_bytes_for_pid(proc_root, pid) {
                total = total.saturating_add(bytes);
                counted = true;
            }
        }
    }
    counted.then_some(total)
}

/// Nearest ancestor path component named `libpod-*.scope` (podman's per-container
/// systemd scope), so the walk covers sibling cgroups of the sampled leaf (e.g.
/// systemd-in-container splits processes across `init.scope`/`system.slice`).
fn libpod_scope_ancestor(cgroup_dir: &Path) -> Option<PathBuf> {
    let mut current = cgroup_dir;
    loop {
        let name = current.file_name()?.to_string_lossy();
        if name.starts_with("libpod-") && name.ends_with(".scope") {
            return Some(current.to_path_buf());
        }
        current = current.parent()?;
    }
}

/// Depth-limited recursive listing of a cgroup directory and its sub-cgroups.
fn walk_cgroup_dirs(root: &Path, depth_left: u32) -> Vec<PathBuf> {
    let mut out = vec![root.to_path_buf()];
    if depth_left == 0 {
        return out;
    }
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                out.extend(walk_cgroup_dirs(&p, depth_left - 1));
            }
        }
    }
    out
}

/// Per-process memory: PSS (shared pages prorated) when `smaps_rollup` is
/// readable, else VmRSS. Values in the source files are kB.
fn mem_bytes_for_pid(proc_root: &Path, pid: u32) -> Option<u64> {
    let base = proc_root.join(pid.to_string());
    if let Ok(rollup) = std::fs::read_to_string(base.join("smaps_rollup")) {
        if let Some(kb) = parse_kb_field(&rollup, "Pss:") {
            return Some(kb.saturating_mul(1024));
        }
    }
    let status = std::fs::read_to_string(base.join("status")).ok()?;
    parse_kb_field(&status, "VmRSS:").map(|kb| kb.saturating_mul(1024))
}

/// Extract the numeric kB value from a `Key:   1234 kB` procfs line.
fn parse_kb_field(text: &str, key: &str) -> Option<u64> {
    text.lines()
        .find(|l| l.starts_with(key))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse::<u64>().ok())
}

/// Read `<proc_root>/<pid>/cgroup` and return the v2 unified cgroup path (the line
/// starting with `0::`). Returns `None` if the file is missing or doesn't include a
/// v2 entry.
fn cgroup_v2_path_for_pid(proc_root: &Path, pid: u32) -> Option<String> {
    let raw = std::fs::read_to_string(proc_root.join(format!("{pid}/cgroup"))).ok()?;
    parse_cgroup_v2_path(&raw)
}

fn parse_cgroup_v2_path(raw: &str) -> Option<String> {
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("0::") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

fn strip_leading_slash(p: &str) -> &str {
    p.strip_prefix('/').unwrap_or(p)
}

fn parse_usage_usec(cpu_stat: &str) -> Option<u64> {
    for line in cpu_stat.lines() {
        if let Some(rest) = line.strip_prefix("usage_usec ") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// Sum `rx_bytes` (column 1) + `tx_bytes` (column 9) across every interface listed in
/// the file (excluding the two header rows).
fn parse_proc_net_dev(raw: &str) -> (u64, u64) {
    let mut rx_total: u64 = 0;
    let mut tx_total: u64 = 0;
    for line in raw.lines().skip(2) {
        let mut parts = line.split_whitespace();
        let _iface = match parts.next() {
            Some(s) => s,
            None => continue,
        };
        let rx: u64 = parts.next().and_then(|n| n.parse().ok()).unwrap_or(0);
        // Skip rx_packets..rx_compressed,multicast (7 fields) before tx_bytes.
        for _ in 0..7 {
            if parts.next().is_none() {
                break;
            }
        }
        let tx: u64 = parts.next().and_then(|n| n.parse().ok()).unwrap_or(0);
        rx_total = rx_total.saturating_add(rx);
        tx_total = tx_total.saturating_add(tx);
    }
    (rx_total, tx_total)
}

async fn run_podman_stats(
    podman_bin: &str,
    container_id: &str,
) -> std::result::Result<String, String> {
    let mut cmd = Command::new(podman_bin);
    cmd.arg("stats")
        .arg("--no-stream")
        .arg("--format")
        .arg("json")
        .arg(container_id)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    let output = cmd.output().await.map_err(|e| e.to_string())?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(stderr);
    }
    String::from_utf8(output.stdout).map_err(|e| e.to_string())
}

/// Parse the JSON output of `podman stats --no-stream --format json`. Best-effort — any
/// missing field falls back to 0. Returns the first row that matches `container_id` (by id
/// prefix) or, when the output is a single-element array, the only row.
pub fn parse_podman_stats(container_id: &str, raw: &str) -> Option<MetricsSample> {
    let value: serde_json::Value = serde_json::from_str(raw.trim()).ok()?;
    let rows = match &value {
        serde_json::Value::Array(rows) => rows.clone(),
        serde_json::Value::Object(_) => vec![value.clone()],
        _ => return None,
    };
    if rows.is_empty() {
        return None;
    }
    let row = rows
        .iter()
        .find(|r| {
            r.get("ContainerID")
                .or_else(|| r.get("Id"))
                .or_else(|| r.get("ID"))
                .and_then(|v| v.as_str())
                .map(|id| id.starts_with(container_id) || container_id.starts_with(id))
                .unwrap_or(false)
        })
        .cloned()
        .unwrap_or_else(|| rows[0].clone());

    let cpu_pct = row
        .get("CPU")
        .and_then(read_percent_string_or_number)
        .unwrap_or(0.0);
    let (mem_bytes, mem_limit) = row
        .get("MemUsage")
        .and_then(|v| v.as_str())
        .map(parse_pair_with_limit)
        .or_else(|| {
            row.get("MemUsageBytes")
                .and_then(|v| v.as_u64())
                .map(|n| (n, row.get("MemLimitBytes").and_then(|v| v.as_u64())))
        })
        .unwrap_or((0, None));
    let (net_rx, net_tx) = row
        .get("NetIO")
        .and_then(|v| v.as_str())
        .map(parse_pair_two)
        .or_else(|| {
            let rx = row.get("NetInputBytes").and_then(|v| v.as_u64());
            let tx = row.get("NetOutputBytes").and_then(|v| v.as_u64());
            match (rx, tx) {
                (Some(r), Some(t)) => Some((r, t)),
                _ => None,
            }
        })
        .unwrap_or((0, 0));
    let (block_in, block_out) = row
        .get("BlockIO")
        .and_then(|v| v.as_str())
        .map(parse_pair_two)
        .or_else(|| {
            let rd = row.get("BlockInput").and_then(|v| v.as_u64());
            let wr = row.get("BlockOutput").and_then(|v| v.as_u64());
            match (rd, wr) {
                (Some(r), Some(w)) => Some((r, w)),
                _ => None,
            }
        })
        .unwrap_or((0, 0));

    Some(MetricsSample {
        container_id: container_id.to_string(),
        ts: Utc::now(),
        cpu_pct,
        mem_bytes,
        mem_limit,
        net_rx,
        net_tx,
        block_in,
        block_out,
    })
}

/// Convert podman's CPU% reading (string `"12.50%"` or already a number) into a fraction of
/// one core (0.125 ≡ 12.5%).
fn read_percent_string_or_number(v: &serde_json::Value) -> Option<f64> {
    match v {
        serde_json::Value::String(s) => {
            let trimmed = s.trim().trim_end_matches('%').trim();
            trimmed.parse::<f64>().ok().map(|n| n / 100.0)
        }
        serde_json::Value::Number(n) => n.as_f64().map(|n| n / 100.0),
        _ => None,
    }
}

/// Parse `"<used> / <limit>"` (e.g. `"10MB / 1GB"`) — used for the memory column where the
/// limit is meaningful.
fn parse_pair_with_limit(s: &str) -> (u64, Option<u64>) {
    let mut parts = s.split('/').map(str::trim);
    let lhs = parts.next().map(parse_size_string).unwrap_or(0);
    let rhs = parts.next().and_then(|p| {
        let n = parse_size_string(p);
        if n == 0 {
            None
        } else {
            Some(n)
        }
    });
    (lhs, rhs)
}

/// Parse `"<a> / <b>"` for net/block IO columns where both values are deltas, not limits.
fn parse_pair_two(s: &str) -> (u64, u64) {
    let mut parts = s.split('/').map(str::trim);
    let a = parts.next().map(parse_size_string).unwrap_or(0);
    let b = parts.next().map(parse_size_string).unwrap_or(0);
    (a, b)
}

/// Parse podman's human-readable size strings — `"10MB"`, `"1.5GiB"`, `"512kB"`, `"42"`.
/// Returns 0 on parse failure (best-effort).
fn parse_size_string(s: &str) -> u64 {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return 0;
    }
    let split_at = trimmed
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(trimmed.len());
    let (num_part, suffix_part) = trimmed.split_at(split_at);
    let num: f64 = match num_part.parse() {
        Ok(n) => n,
        Err(_) => return 0,
    };
    let suffix = suffix_part.trim().to_ascii_lowercase();
    let multiplier: f64 = match suffix.as_str() {
        "" | "b" => 1.0,
        "k" | "kb" => 1_000.0,
        "kib" => 1_024.0,
        "m" | "mb" => 1_000_000.0,
        "mib" => 1_048_576.0,
        "g" | "gb" => 1_000_000_000.0,
        "gib" => 1_073_741_824.0,
        "t" | "tb" => 1_000_000_000_000.0,
        "tib" => 1_099_511_627_776.0,
        _ => 1.0,
    };
    let result = num * multiplier;
    if result < 0.0 {
        0
    } else {
        result as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linpodx_common::audit_sink::NoopAuditSink;
    use linpodx_common::events::NoopEventPublisher;

    #[test]
    fn ring_buffer_drops_oldest_at_capacity() {
        let mut r = RingBuffer::new(3);
        r.push(1);
        r.push(2);
        r.push(3);
        assert_eq!(r.len(), 3);
        r.push(4);
        let collected: Vec<_> = r.iter().copied().collect();
        assert_eq!(collected, vec![2, 3, 4]);
        assert_eq!(r.len(), 3);
    }

    #[test]
    fn ring_buffer_iter_preserves_insertion_order() {
        let mut r = RingBuffer::new(5);
        for i in 1..=4 {
            r.push(i);
        }
        let collected: Vec<_> = r.iter().copied().collect();
        assert_eq!(collected, vec![1, 2, 3, 4]);
        assert!(!r.is_empty());
        assert_eq!(r.capacity(), 5);
    }

    #[test]
    fn parse_size_string_handles_common_suffixes() {
        assert_eq!(parse_size_string("0"), 0);
        assert_eq!(parse_size_string("100"), 100);
        assert_eq!(parse_size_string("1kB"), 1_000);
        assert_eq!(parse_size_string("1KiB"), 1_024);
        assert_eq!(parse_size_string("2MB"), 2_000_000);
        assert_eq!(
            parse_size_string("1.5GiB"),
            (1.5_f64 * 1_073_741_824.0) as u64
        );
        assert_eq!(parse_size_string(""), 0);
        assert_eq!(parse_size_string("garbage"), 0);
    }

    #[test]
    fn parse_pair_with_limit_basic() {
        let (used, limit) = parse_pair_with_limit("10MB / 1GB");
        assert_eq!(used, 10_000_000);
        assert_eq!(limit, Some(1_000_000_000));
        let (used, limit) = parse_pair_with_limit("512kB / --");
        assert_eq!(used, 512_000);
        assert_eq!(limit, None);
    }

    #[test]
    fn parse_pair_two_basic() {
        assert_eq!(parse_pair_two("1kB / 2kB"), (1_000, 2_000));
        assert_eq!(parse_pair_two("1MB / 2MB"), (1_000_000, 2_000_000));
    }

    #[test]
    fn parse_podman_stats_full_row() {
        let raw = r#"[{"ContainerID":"abc123","CPU":"12.50%","MemUsage":"10MB / 1GB","NetIO":"1kB / 2kB","BlockIO":"3MB / 4MB"}]"#;
        let s = parse_podman_stats("abc123", raw).expect("sample");
        assert_eq!(s.container_id, "abc123");
        assert!((s.cpu_pct - 0.125).abs() < 1e-9);
        assert_eq!(s.mem_bytes, 10_000_000);
        assert_eq!(s.mem_limit, Some(1_000_000_000));
        assert_eq!(s.net_rx, 1_000);
        assert_eq!(s.net_tx, 2_000);
        assert_eq!(s.block_in, 3_000_000);
        assert_eq!(s.block_out, 4_000_000);
    }

    #[test]
    fn parse_podman_stats_missing_fields_default_to_zero() {
        let raw = r#"[{"ContainerID":"abc"}]"#;
        let s = parse_podman_stats("abc", raw).expect("sample");
        assert_eq!(s.cpu_pct, 0.0);
        assert_eq!(s.mem_bytes, 0);
        assert_eq!(s.mem_limit, None);
        assert_eq!(s.net_rx, 0);
        assert_eq!(s.net_tx, 0);
        assert_eq!(s.block_in, 0);
        assert_eq!(s.block_out, 0);
    }

    #[test]
    fn parse_podman_stats_single_object_form() {
        // Some podman versions emit a bare object instead of a single-element array.
        let raw = r#"{"ContainerID":"deadbeef","CPU":50,"MemUsage":"5MiB / 0B","NetIO":"0B / 0B","BlockIO":"0B / 0B"}"#;
        let s = parse_podman_stats("deadbeef", raw).expect("sample");
        assert!((s.cpu_pct - 0.5).abs() < 1e-9);
        assert_eq!(s.mem_bytes, 5 * 1_048_576);
        assert_eq!(s.mem_limit, None);
    }

    #[test]
    fn parse_podman_stats_invalid_json_returns_none() {
        assert!(parse_podman_stats("abc", "not json").is_none());
        assert!(parse_podman_stats("abc", "[]").is_none());
    }

    #[tokio::test]
    async fn collector_lifecycle_inserts_and_removes_state() {
        let collector = MetricsCollector::new(
            "/nonexistent/podman".to_string(),
            Arc::new(NoopEventPublisher),
            Arc::new(NoopAuditSink),
        );
        collector.spawn_for("c1".to_string()).await;
        assert!(collector.has_handle("c1").await);
        // Push a synthetic sample so latest/history have something to return without
        // depending on the (intentionally broken) podman binary path.
        let sample = MetricsSample {
            container_id: "c1".into(),
            ts: Utc::now(),
            cpu_pct: 0.25,
            mem_bytes: 4096,
            mem_limit: Some(8192),
            net_rx: 0,
            net_tx: 0,
            block_in: 0,
            block_out: 0,
        };
        collector.push_sample_for_test("c1", sample.clone()).await;
        let latest = collector.latest("c1").await.expect("latest");
        assert!((latest.cpu_pct - 0.25).abs() < 1e-9);
        assert_eq!(collector.history("c1", None).await.len(), 1);

        collector.stop_for("c1").await;
        assert!(!collector.has_handle("c1").await);
        assert!(collector.latest("c1").await.is_none());
        assert!(collector.history("c1", None).await.is_empty());
    }

    #[tokio::test]
    async fn reconcile_running_spawns_and_prunes() {
        let collector = MetricsCollector::new(
            "/nonexistent/podman".to_string(),
            Arc::new(NoopEventPublisher),
            Arc::new(NoopAuditSink),
        );
        // First reconcile: two running containers -> both get collectors.
        collector
            .reconcile_running(&["aaa".to_string(), "bbb".to_string()])
            .await;
        assert!(collector.has_handle("aaa").await);
        assert!(collector.has_handle("bbb").await);

        // Second reconcile: only "aaa" still running -> "bbb" pruned.
        collector.reconcile_running(&["aaa".to_string()]).await;
        assert!(collector.has_handle("aaa").await);
        assert!(!collector.has_handle("bbb").await);

        // Empty reconcile prunes everything.
        collector.reconcile_running(&[]).await;
        assert!(!collector.has_handle("aaa").await);
    }

    #[tokio::test]
    async fn reconcile_running_prefix_tolerant() {
        let collector = MetricsCollector::new(
            "/nonexistent/podman".to_string(),
            Arc::new(NoopEventPublisher),
            Arc::new(NoopAuditSink),
        );
        // Collector keyed by a short id (as a lazy UI request might spawn).
        collector.spawn_for("abc123".to_string()).await;
        // List surface returns the full id — must NOT prune the short-id handle.
        collector
            .reconcile_running(&["abc123def456".to_string()])
            .await;
        assert!(collector.has_handle("abc123").await);
    }

    #[test]
    fn parse_cgroup_v2_path_basic() {
        let raw = "0::/user.slice/user-1000.slice/session-2.scope\n";
        assert_eq!(
            parse_cgroup_v2_path(raw),
            Some("/user.slice/user-1000.slice/session-2.scope".to_string())
        );
    }

    #[test]
    fn parse_cgroup_v2_path_skips_v1_lines() {
        let raw = "12:devices:/user.slice\n11:cpuset:/\n0::/podman/abc123\n";
        assert_eq!(
            parse_cgroup_v2_path(raw),
            Some("/podman/abc123".to_string())
        );
    }

    #[test]
    fn parse_cgroup_v2_path_returns_none_when_v2_missing() {
        let raw = "12:devices:/user.slice\n11:cpuset:/\n";
        assert_eq!(parse_cgroup_v2_path(raw), None);
    }

    #[test]
    fn parse_usage_usec_extracts_field() {
        let raw = "usage_usec 12345\nuser_usec 5000\nsystem_usec 7345\n";
        assert_eq!(parse_usage_usec(raw), Some(12345));
    }

    #[test]
    fn parse_usage_usec_returns_none_when_field_missing() {
        let raw = "user_usec 5000\nsystem_usec 7345\n";
        assert_eq!(parse_usage_usec(raw), None);
    }

    #[test]
    fn parse_proc_net_dev_sums_interfaces() {
        // Real-world `/proc/<pid>/net/dev` layout — two header lines, then iface stats.
        // Columns: Inter-|   Receive (bytes pkts errs drop fifo frame compressed multicast) | Transmit (bytes pkts errs drop fifo colls carrier compressed)
        let raw = "Inter-|   Receive                                                |  Transmit\n\
                   face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n\
                   lo:    100 1 0 0 0 0 0 0   200 1 0 0 0 0 0 0\n\
                   eth0:  1000 5 0 0 0 0 0 0   2000 5 0 0 0 0 0 0\n";
        let (rx, tx) = parse_proc_net_dev(raw);
        assert_eq!(rx, 1100);
        assert_eq!(tx, 2200);
    }

    #[test]
    fn parse_proc_net_dev_handles_empty() {
        assert_eq!(parse_proc_net_dev(""), (0, 0));
        assert_eq!(parse_proc_net_dev("Inter-|...\nface |...\n"), (0, 0));
    }

    #[test]
    fn cgroup_sample_reads_mocked_files() {
        let proc_dir = tempfile::tempdir().expect("proc tempdir");
        let cgroup_dir = tempfile::tempdir().expect("cgroup tempdir");
        let pid: u32 = 4242;

        // /proc/<pid>/cgroup + /proc/<pid>/net/dev
        let pid_dir = proc_dir.path().join(format!("{pid}"));
        std::fs::create_dir_all(pid_dir.join("net")).unwrap();
        std::fs::write(pid_dir.join("cgroup"), "0::/podman/test\n").unwrap();
        std::fs::write(
            pid_dir.join("net/dev"),
            "Inter-|...\nface |...\nlo: 100 0 0 0 0 0 0 0 200 0 0 0 0 0 0 0\n",
        )
        .unwrap();

        // cgroup root: <root>/podman/test/{cpu.stat, memory.current, memory.max}
        let cdir = cgroup_dir.path().join("podman").join("test");
        std::fs::create_dir_all(&cdir).unwrap();
        std::fs::write(cdir.join("cpu.stat"), "usage_usec 999\n").unwrap();
        std::fs::write(cdir.join("memory.current"), "4096\n").unwrap();
        std::fs::write(cdir.join("memory.max"), "8192\n").unwrap();

        let sample = sample_from_roots(proc_dir.path(), cgroup_dir.path(), pid, "container-x")
            .expect("sample");
        assert_eq!(sample.container_id, "container-x");
        assert_eq!(sample.mem_bytes, 4096);
        assert_eq!(sample.mem_limit, Some(8192));
        assert_eq!(sample.net_rx, 100);
        assert_eq!(sample.net_tx, 200);
        // cpu_pct is left at 0.0 here — the collector loop computes the delta.
        assert_eq!(sample.cpu_pct, 0.0);
    }

    #[test]
    fn cgroup_sample_treats_memory_max_string_as_unlimited() {
        let proc_dir = tempfile::tempdir().unwrap();
        let cgroup_dir = tempfile::tempdir().unwrap();
        let pid: u32 = 7;
        let pid_dir = proc_dir.path().join(format!("{pid}"));
        std::fs::create_dir_all(&pid_dir).unwrap();
        std::fs::write(pid_dir.join("cgroup"), "0::/sys.slice\n").unwrap();
        std::fs::create_dir_all(pid_dir.join("net")).unwrap();
        std::fs::write(pid_dir.join("net/dev"), "Inter-|\nface |\n").unwrap();

        let cdir = cgroup_dir.path().join("sys.slice");
        std::fs::create_dir_all(&cdir).unwrap();
        std::fs::write(cdir.join("cpu.stat"), "usage_usec 0\n").unwrap();
        std::fs::write(cdir.join("memory.current"), "0\n").unwrap();
        std::fs::write(cdir.join("memory.max"), "max\n").unwrap();

        let s = sample_from_roots(proc_dir.path(), cgroup_dir.path(), pid, "c").expect("sample");
        assert_eq!(s.mem_limit, None);
    }

    #[test]
    fn procfs_fallback_sums_pss_when_memory_controller_missing() {
        let proc_dir = tempfile::tempdir().unwrap();
        let cgroup_dir = tempfile::tempdir().unwrap();
        let pid: u32 = 11;
        let pid_dir = proc_dir.path().join(format!("{pid}"));
        std::fs::create_dir_all(pid_dir.join("net")).unwrap();
        std::fs::write(pid_dir.join("cgroup"), "0::/libpod-abc.scope/container\n").unwrap();
        std::fs::write(pid_dir.join("net/dev"), "Inter-|\nface |\n").unwrap();
        // Two processes in the scope: pid 11 (smaps_rollup Pss) + pid 12
        // (no smaps_rollup -> VmRSS fallback), pid 12 in a SIBLING cgroup so
        // the libpod-scope ancestor walk is exercised.
        std::fs::write(pid_dir.join("smaps_rollup"), "Pss:      10 kB\n").unwrap();
        let pid12_dir = proc_dir.path().join("12");
        std::fs::create_dir_all(&pid12_dir).unwrap();
        std::fs::write(pid12_dir.join("status"), "Name:\tx\nVmRSS:\t     5 kB\n").unwrap();

        // cgroup tree WITHOUT memory.current anywhere (pids-only delegation).
        let scope = cgroup_dir.path().join("libpod-abc.scope");
        let leaf = scope.join("container");
        let sibling = scope.join("init.scope");
        std::fs::create_dir_all(&leaf).unwrap();
        std::fs::create_dir_all(&sibling).unwrap();
        std::fs::write(leaf.join("cpu.stat"), "usage_usec 1\n").unwrap();
        std::fs::write(leaf.join("cgroup.procs"), "11\n").unwrap();
        std::fs::write(sibling.join("cgroup.procs"), "12\n").unwrap();

        let s = sample_from_roots(proc_dir.path(), cgroup_dir.path(), pid, "c").expect("sample");
        assert_eq!(s.mem_bytes, 15 * 1024, "10kB Pss + 5kB VmRSS");
        assert_eq!(s.mem_limit, None);
    }

    #[test]
    fn parse_kb_field_extracts_value() {
        assert_eq!(
            parse_kb_field("Pss:            1234 kB\n", "Pss:"),
            Some(1234)
        );
        assert_eq!(parse_kb_field("VmRSS:\t  77 kB\n", "VmRSS:"), Some(77));
        assert_eq!(parse_kb_field("nothing here\n", "Pss:"), None);
    }

    #[test]
    fn libpod_scope_ancestor_finds_scope() {
        let p = Path::new("/sys/fs/cgroup/user.slice/libpod-deadbeef.scope/container");
        assert_eq!(
            libpod_scope_ancestor(p).unwrap().file_name().unwrap(),
            "libpod-deadbeef.scope"
        );
        assert!(libpod_scope_ancestor(Path::new("/sys/fs/cgroup/user.slice")).is_none());
    }

    #[test]
    fn cgroup_v2_check_does_not_panic() {
        // Best-effort — true on hosts running cgroup v2 (most modern Linux), false
        // elsewhere. We just assert the call doesn't panic.
        let _ = cgroup_v2_check();
    }

    #[tokio::test]
    async fn history_filters_by_since() {
        let collector = MetricsCollector::new(
            "/nonexistent/podman".to_string(),
            Arc::new(NoopEventPublisher),
            Arc::new(NoopAuditSink),
        );
        let now = Utc::now();
        let older = MetricsSample {
            container_id: "c2".into(),
            ts: now - chrono::Duration::seconds(60),
            cpu_pct: 0.1,
            mem_bytes: 0,
            mem_limit: None,
            net_rx: 0,
            net_tx: 0,
            block_in: 0,
            block_out: 0,
        };
        let newer = MetricsSample {
            container_id: "c2".into(),
            ts: now,
            cpu_pct: 0.5,
            mem_bytes: 0,
            mem_limit: None,
            net_rx: 0,
            net_tx: 0,
            block_in: 0,
            block_out: 0,
        };
        collector.push_sample_for_test("c2", older).await;
        collector.push_sample_for_test("c2", newer).await;
        let cutoff = now - chrono::Duration::seconds(10);
        let filtered = collector.history("c2", Some(cutoff)).await;
        assert_eq!(filtered.len(), 1);
        assert!((filtered[0].cpu_pct - 0.5).abs() < 1e-9);
        let all = collector.history("c2", None).await;
        assert_eq!(all.len(), 2);
    }
}
