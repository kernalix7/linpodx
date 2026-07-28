//! Fake-podman dispatch-arm coverage (podman-free, CI-safe).
//!
//! # Why this exists
//!
//! The 113 dispatch arms are otherwise exercised only behind podman-gated
//! `#[ignore]` integration tests (`tests/e2e_*.rs`), so CI never runs the arm
//! bodies at all — argv assembly, JSON parsing, event publication and audit
//! payloads all go unverified until someone runs the ignored suite by hand on a
//! host with Podman installed.
//!
//! The volume lane (`linpodx-runtime/src/volume.rs` tests) proved a pattern: a
//! tiny shell script standing in for the `podman` binary (`PodmanConfig{binary:
//! script}`) drives the *real* runtime wrapper with canned, real-shaped JSON.
//! This module generalises that pattern up to the daemon: it builds a **real
//! [`Dispatcher`]** (via [`DispatcherBuilder`]) whose podman handle — and the
//! raw `podman_bin` path the `SystemDf` overlay shells out to — both point at
//! the fake script, then drives arms end-to-end through the public
//! [`Dispatcher::dispatch`] entry point.
//!
//! Nothing here needs Podman, so none of these tests are `#[ignore]`d — the
//! shell script *is* podman. The script inspects `$1`/`$2` and emits fixtures
//! whose shapes were captured from live `podman` (5.8.2) on the dev host.
//!
//! # Structure note
//!
//! `linpodx-daemon` is a binary-only crate (no `lib` target), so an integration
//! test under `tests/` cannot name [`Dispatcher`]. This harness therefore lives
//! as an in-crate `#[cfg(test)]` module (declared from `dispatch/containers.rs`)
//! and runs under `cargo test -p linpodx-daemon` alongside the existing dispatch
//! unit tests. It is a test-only seam: zero production behaviour changes.

use crate::approval::ApprovalRegistry;
use crate::dispatch::DispatcherBuilder;
use crate::event_bus::EventBus;
use crate::pin_store::PinnedClientStore;
use linpodx_common::approval::ApprovalGateway;
use linpodx_common::audit_sink::{AuditSink, AuditSinkKind};
use linpodx_common::db::Database;
use linpodx_common::events::EventPublisher;
use linpodx_common::ipc::{
    responses, ContainerListParams, ContainerUpdateParams, CreateOptions, Event, EventKind,
    ImagePullJobParams, Method, PodActionParams, PodCreateParams, PodRemoveParams, ResponsePayload,
    RpcResponse, SecretCreateParams, SecretRemoveParams, VolumeNameParams,
};
use linpodx_common::types::VolumeId;
use linpodx_mcp::BridgeRegistry;
use linpodx_runtime::{MetricsCollector, Podman, PodmanConfig};
use linpodx_sandbox::{SandboxManager, SessionManager, SnapshotManager};
use std::future::Future;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::broadcast;

// ---------------------------------------------------------------------------
// Fake podman
// ---------------------------------------------------------------------------

/// Shared script body. Dispatches on the podman subcommand (`$1`, and `$2` for
/// the `pod`/`secret`/`volume`/`system` families) and prints real-shaped JSON
/// fixtures. Every invocation's argv is appended to the log file by the wrapper
/// prologue written in [`write_fake_podman`], so tests can assert argv assembly.
///
/// All fixture shapes were captured from live `podman` 5.8.2:
/// * `ps --format=json` — array of container objects (`Id`/`Names`/`State`/…).
/// * `pod ps --format json` — array of pod objects.
/// * `secret ls --format '{{json .}}'` — one JSON object per line.
/// * `system df --format json` — 3-entry array with `RawSize`/`RawReclaimable`.
/// * `volume inspect <name>` — single-element array.
const FAKE_BODY: &str = r#"
case "$1" in
  ps)
    cat <<'JSON'
[{"Id":"c1","Names":["web"],"Image":"docker.io/library/nginx:latest","State":"running","Status":"Up 2 hours","Created":"2026-05-20T10:05:00Z","Command":["nginx","-g","daemon off;"],"Ports":null,"Labels":{"com.docker.compose.project":"demo-stack"}},{"Id":"c2","Names":["worker"],"Image":"docker.io/library/alpine:latest","State":"exited","Status":"Exited (0) 3 minutes ago","Created":"2026-05-20T10:06:00Z","Command":["sleep","999"],"Ports":null,"Labels":{}}]
JSON
    ;;
  create)
    echo "ctr-abc123def456abc123def456abc123def456abc123def456abc123def456"
    ;;
  update)
    echo "ctr-abc123def456"
    ;;
  images)
    cat <<'JSON'
[{"Id":"img0000000001","Names":["docker.io/library/alpine:latest"],"Size":7340032,"Created":1710000000,"Labels":{}}]
JSON
    ;;
  pull)
    echo "Trying to pull docker.io/library/alpine:latest..."
    echo "Getting image source signatures"
    echo "Copying blob sha256:abcd1234"
    echo "Writing manifest to image destination"
    ;;
  volume)
    case "$2" in
      inspect)
        cat <<'JSON'
[{"Name":"data-vol","Driver":"local","Mountpoint":"/var/lib/containers/storage/volumes/data-vol/_data","CreatedAt":"2026-05-20T10:00:00Z","Labels":{"role":"db"},"Options":{}}]
JSON
        ;;
      *)
        echo "[]"
        ;;
    esac
    ;;
  system)
    # $2 == df. volume_size_bytes uses `system df -v`; the SystemDf overlay uses
    # `system df --format json` (no -v). Distinguish on the presence of -v.
    case "$*" in
      *" -v "*|*" -v")
        cat <<'JSON'
{"Volumes":[{"VolumeName":"data-vol","Links":2,"Size":104857600,"ReclaimableSize":0},{"VolumeName":"other-vol","Size":10}]}
JSON
        ;;
      *)
        cat <<'JSON'
[{"Type":"Images","Total":1,"Active":0,"RawSize":4509715660,"RawReclaimable":1181116006,"Size":"4.5GB","Reclaimable":"1.1GB (26%)"},{"Type":"Containers","Total":2,"Active":1,"RawSize":32768,"RawReclaimable":0,"Size":"32kB","Reclaimable":"0B (0%)"},{"Type":"Local Volumes","Total":1,"Active":0,"RawSize":335544320,"RawReclaimable":0,"Size":"320MB","Reclaimable":"0B (0%)"}]
JSON
        ;;
    esac
    ;;
  pod)
    case "$2" in
      ps)
        cat <<'JSON'
[{"Id":"pod123456789","Name":"web-pod","Status":"Running","Created":"2026-05-20T10:00:00Z","NumContainers":2,"InfraId":"infra999888","Labels":{"env":"test"}}]
JSON
        ;;
      create)
        echo "pod123456789abcdef"
        ;;
      start|stop)
        echo "pod123456789"
        ;;
      rm)
        echo "pod123456789"
        ;;
      *)
        echo ""
        ;;
    esac
    ;;
  secret)
    case "$2" in
      ls)
        printf '%s\n' '{"ID":"63712b6f299dc1ba2dc59b591","Name":"db-password","Driver":"file","CreatedAt":"5 seconds ago","UpdatedAt":"5 seconds ago"}'
        ;;
      create)
        # The value arrives on stdin (never argv). Consume + discard it so it is
        # provably never echoed, then emit the new secret id.
        cat >/dev/null
        echo "secretid00112233445566778899aabbcc"
        ;;
      rm)
        echo "db-password"
        ;;
      *)
        echo ""
        ;;
    esac
    ;;
  inspect)
    echo "[]"
    ;;
  *)
    echo "fake-podman: unhandled subcommand: $1" 1>&2
    exit 1
    ;;
esac
"#;

/// Write an executable `/bin/sh` fake-podman script that (1) appends its full
/// argv to `log_path` on every invocation and (2) runs `body`.
fn write_fake_podman(script_path: &Path, log_path: &Path, body: &str) {
    // The prologue logs argv; the value piped to `secret create` on stdin is
    // never touched here, so it can never leak into the log.
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{log}'\n{body}\nexit 0\n",
        log = log_path.display(),
    );
    let mut f = std::fs::File::create(script_path).expect("create fake podman script");
    f.write_all(script.as_bytes())
        .expect("write fake podman script");
    let mut perms = f.metadata().expect("script metadata").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(script_path, perms).expect("chmod fake podman script");
}

// ---------------------------------------------------------------------------
// Capturing audit sink
// ---------------------------------------------------------------------------

/// [`AuditSink`] that records every `(kind, payload)` into memory so tests can
/// assert exactly what the arm handed the tamper-evident log — most importantly
/// that `SecretCreate` audits the name only, never the value.
struct CapturingAuditSink {
    records: Mutex<Vec<(AuditSinkKind, serde_json::Value)>>,
}

impl CapturingAuditSink {
    fn new() -> Self {
        Self {
            records: Mutex::new(Vec::new()),
        }
    }

    fn records(&self) -> Vec<(AuditSinkKind, serde_json::Value)> {
        self.records.lock().expect("audit lock").clone()
    }

    fn payload_for(&self, kind: AuditSinkKind) -> Option<serde_json::Value> {
        self.records()
            .into_iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, p)| p)
    }
}

impl AuditSink for CapturingAuditSink {
    fn record(
        &self,
        kind: AuditSinkKind,
        _profile_name: Option<String>,
        _container_id: Option<String>,
        payload: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        self.records
            .lock()
            .expect("audit lock")
            .push((kind, payload));
        Box::pin(async {})
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct Harness {
    dispatcher: crate::dispatch::Dispatcher,
    event_bus: Arc<EventBus>,
    audit: Arc<CapturingAuditSink>,
    log_path: std::path::PathBuf,
    // Keep the tempdir alive for the harness lifetime (dropping it deletes the
    // fake script + db).
    _tmp: tempfile::TempDir,
}

impl Harness {
    /// Build a real `Dispatcher` wired to the fake podman script.
    async fn build() -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let log_path = tmp.path().join("podman-argv.log");
        let script_path = tmp.path().join("podman");
        write_fake_podman(&script_path, &log_path, FAKE_BODY);

        let db = Database::open(tmp.path().join("state.db"))
            .await
            .expect("open db");
        db.migrate().await.expect("migrate db");
        let db = Arc::new(db);

        let event_bus = Arc::new(EventBus::new(1024));
        let publisher: Arc<dyn EventPublisher> = event_bus.clone();

        let podman = Podman::with_config(PodmanConfig {
            binary: Some(script_path.clone()),
            root: None,
            runroot: None,
        });
        let podman_bin = script_path.to_string_lossy().into_owned();

        let approvals = Arc::new(ApprovalRegistry::new());
        let snapshot = Arc::new(SnapshotManager::new(
            Arc::clone(&db),
            Arc::clone(&publisher),
        ));
        let session = Arc::new(SessionManager::new(Arc::clone(&db), Arc::clone(&publisher)));

        let profiles_dir = tmp.path().join("profiles");
        std::fs::create_dir_all(&profiles_dir).expect("profiles dir");
        let gateway: Arc<dyn ApprovalGateway> = approvals.clone();
        let sandbox = Arc::new(SandboxManager::new(
            Arc::clone(&db),
            profiles_dir,
            Arc::clone(&publisher),
            gateway,
            Duration::from_secs(30),
            Arc::clone(&snapshot),
            Arc::clone(&session),
        ));

        let audit_capture = Arc::new(CapturingAuditSink::new());
        let audit: Arc<dyn AuditSink> = audit_capture.clone();
        let bridges = Arc::new(BridgeRegistry::new(Arc::clone(&audit)));
        let metrics = Arc::new(MetricsCollector::new(
            podman_bin.clone(),
            Arc::clone(&publisher),
            Arc::clone(&audit),
        ));
        let pin_store = PinnedClientStore::new(Arc::clone(&db));

        let dispatcher = DispatcherBuilder::new()
            .podman(podman)
            .podman_bin(podman_bin)
            .podman_version("5.8.2".to_string())
            .event_bus(Arc::clone(&event_bus))
            .sandbox(sandbox)
            .approvals(approvals)
            .snapshot(snapshot)
            .session(session)
            .bridges(bridges)
            .metrics(metrics)
            .audit(audit)
            .pin_store(pin_store)
            .build()
            .expect("build dispatcher");

        Self {
            dispatcher,
            event_bus,
            audit: audit_capture,
            log_path,
            _tmp: tmp,
        }
    }

    /// Drive one method through the public dispatch entry point.
    async fn dispatch(&self, method: Method) -> RpcResponse {
        self.dispatcher
            .dispatch(linpodx_common::ipc::RpcRequest::new(1i64, method))
            .await
    }

    /// Dispatch and unwrap a successful result, panicking on an error payload.
    async fn ok(&self, method: Method) -> serde_json::Value {
        match self.dispatch(method).await.payload {
            ResponsePayload::Success { result } => result,
            ResponsePayload::Error { error } => {
                panic!("expected success, got error: {error:?}")
            }
        }
    }

    /// Full contents of the fake podman argv log.
    fn argv_log(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }
}

/// Collect up to `max` events off a broadcast receiver, bailing out after
/// `timeout` idle time (or on lag/close). Used for arms whose observable effect
/// is asynchronous (e.g. the spawned pull-progress task).
async fn collect_events(
    rx: &mut broadcast::Receiver<Event>,
    max: usize,
    timeout: Duration,
) -> Vec<Event> {
    let mut out = Vec::new();
    while out.len() < max {
        match tokio::time::timeout(timeout, rx.recv()).await {
            Ok(Ok(ev)) => out.push(ev),
            Ok(Err(_)) | Err(_) => break,
        }
    }
    out
}

// ===========================================================================
// Container arms
// ===========================================================================

#[tokio::test]
async fn container_list_parses_rows_and_preserves_labels() {
    let h = Harness::build().await;
    let result = h
        .ok(Method::ContainerList(ContainerListParams { all: true }))
        .await;
    let rows = result.as_array().expect("array");
    assert_eq!(rows.len(), 2, "expected 2 containers: {result}");
    assert_eq!(rows[0]["names"][0], "web");
    assert_eq!(rows[0]["state"], "running");
    // Stack-grouping label must survive the serialize round the arm performs.
    assert_eq!(
        rows[0]["labels"]["com.docker.compose.project"],
        "demo-stack"
    );
    // `--all` must reach podman's argv.
    assert!(h.argv_log().contains("ps"), "log={}", h.argv_log());
    assert!(h.argv_log().contains("--all"), "log={}", h.argv_log());
}

#[tokio::test]
async fn container_create_assembles_argv_and_publishes_created() {
    let h = Harness::build().await;
    let mut rx = h.event_bus.subscribe();

    let opts = CreateOptions {
        image: "docker.io/library/alpine:latest".to_string(),
        name: Some("mock-ctr".to_string()),
        env: vec![("FOO".to_string(), "bar".to_string())],
        labels: vec![("role".to_string(), "test".to_string())],
        ..Default::default()
    };
    let result = h.ok(Method::ContainerCreate(opts)).await;
    let id = result.as_str().expect("container id string");
    assert!(id.starts_with("ctr-"), "got {id}");

    // argv construction landed in the script log.
    let log = h.argv_log();
    assert!(log.contains("create"), "log={log}");
    assert!(log.contains("--name mock-ctr"), "log={log}");
    assert!(log.contains("--env FOO=bar"), "log={log}");
    assert!(log.contains("--label role=test"), "log={log}");
    assert!(
        log.contains("docker.io/library/alpine:latest"),
        "image positional missing: log={log}"
    );

    // A Created event was published with the create details. `session.start`
    // also publishes a Session event first, so collect a few and search rather
    // than assuming ordering.
    let events = collect_events(&mut rx, 4, Duration::from_secs(2)).await;
    let created = events
        .iter()
        .find(|e| matches!(e.kind, EventKind::Created))
        .expect("Created event");
    assert_eq!(created.details["image"], "docker.io/library/alpine:latest");
    assert_eq!(created.details["name"], "mock-ctr");
}

#[tokio::test]
async fn container_update_applies_fields_and_audits() {
    let h = Harness::build().await;
    let result = h
        .ok(Method::ContainerUpdate(ContainerUpdateParams {
            id: "ctr-abc123def456".to_string(),
            memory_bytes: Some(536_870_912),
            memory_swap_bytes: None,
            cpus: Some(1.5),
            pids_limit: None,
            restart_policy: Some("unless-stopped".to_string()),
        }))
        .await;
    let applied = result["applied"].as_array().expect("applied array");
    let applied: Vec<&str> = applied.iter().filter_map(|v| v.as_str()).collect();
    assert_eq!(applied, vec!["memory", "cpus", "restart_policy"]);

    // Only the set fields reach podman's argv.
    let log = h.argv_log();
    assert!(log.contains("update"), "log={log}");
    assert!(log.contains("--memory 536870912"), "log={log}");
    assert!(log.contains("--cpus 1.5"), "log={log}");
    assert!(log.contains("--restart unless-stopped"), "log={log}");
    assert!(!log.contains("--pids-limit"), "log={log}");

    // A ContainerUpdated audit row records the applied field list.
    let payload = h
        .audit
        .payload_for(AuditSinkKind::ContainerUpdated)
        .expect("ContainerUpdated audit");
    assert_eq!(payload["container_id"], "ctr-abc123def456");
}

// ===========================================================================
// Pod arms
// ===========================================================================

#[tokio::test]
async fn pod_list_parses_summary() {
    let h = Harness::build().await;
    let result = h.ok(Method::PodList).await;
    let pods = result["pods"].as_array().expect("pods array");
    assert_eq!(pods.len(), 1);
    assert_eq!(pods[0]["id"], "pod123456789");
    assert_eq!(pods[0]["name"], "web-pod");
    assert_eq!(pods[0]["num_containers"], 2);
    assert_eq!(pods[0]["infra_id"], "infra999888");
}

#[tokio::test]
async fn pod_create_assembles_argv_and_publishes() {
    let h = Harness::build().await;
    let mut rx = h.event_bus.subscribe();
    let mut labels = std::collections::HashMap::new();
    labels.insert("env".to_string(), "test".to_string());

    let result = h
        .ok(Method::PodCreate(PodCreateParams {
            name: "web-pod".to_string(),
            ports: vec![],
            labels,
        }))
        .await;
    assert_eq!(result["name"], "web-pod");
    assert!(result["id"].as_str().unwrap().starts_with("pod123"));

    let log = h.argv_log();
    assert!(log.contains("pod create"), "log={log}");
    assert!(log.contains("--name web-pod"), "log={log}");
    assert!(log.contains("--label env=test"), "log={log}");

    let events = collect_events(&mut rx, 1, Duration::from_secs(2)).await;
    assert!(events.iter().any(|e| matches!(e.kind, EventKind::Created)));
}

#[tokio::test]
async fn pod_start_stop_refresh_status_from_ps() {
    let h = Harness::build().await;

    let started = h
        .ok(Method::PodStart(PodActionParams {
            id_or_name: "web-pod".to_string(),
        }))
        .await;
    assert_eq!(started["id"], "pod123456789");
    assert_eq!(started["status"], "Running");
    assert!(h.argv_log().contains("pod start web-pod"));

    let stopped = h
        .ok(Method::PodStop(PodActionParams {
            id_or_name: "web-pod".to_string(),
        }))
        .await;
    assert_eq!(stopped["id"], "pod123456789");
    assert!(h.argv_log().contains("pod stop web-pod"));
}

#[tokio::test]
async fn pod_remove_forwards_force_flag() {
    let h = Harness::build().await;
    let result = h
        .ok(Method::PodRemove(PodRemoveParams {
            id_or_name: "web-pod".to_string(),
            force: true,
        }))
        .await;
    assert_eq!(result["id"], "pod123456789");
    assert_eq!(result["status"], "Removed");
    let log = h.argv_log();
    assert!(log.contains("pod rm"), "log={log}");
    assert!(log.contains("--force"), "log={log}");
    assert!(log.contains("web-pod"), "log={log}");
}

// ===========================================================================
// Secret arms — the value must never reach argv, audit, or the log
// ===========================================================================

#[tokio::test]
async fn secret_list_parses_json_lines() {
    let h = Harness::build().await;
    let result = h.ok(Method::SecretList).await;
    let secrets = result["secrets"].as_array().expect("secrets array");
    assert_eq!(secrets.len(), 1);
    assert_eq!(secrets[0]["name"], "db-password");
    assert_eq!(secrets[0]["driver"], "file");
}

#[tokio::test]
async fn secret_create_audits_name_only_and_never_leaks_value() {
    let h = Harness::build().await;
    let secret_value = "s3cr3t-value-do-not-leak-xyz";

    let result = h
        .ok(Method::SecretCreate(SecretCreateParams {
            name: "db-password".to_string(),
            value: secret_value.to_string(),
        }))
        .await;
    assert_eq!(result["name"], "db-password");
    assert!(result["id"].as_str().unwrap().starts_with("secretid"));

    // Audit payload carries the name and nothing else — no value, no extra keys.
    let payload = h
        .audit
        .payload_for(AuditSinkKind::SecretCreated)
        .expect("SecretCreated audit row");
    assert_eq!(payload, serde_json::json!({ "name": "db-password" }));

    // The value is passed to podman over stdin, so it must not appear in argv…
    assert!(
        !h.argv_log().contains(secret_value),
        "secret value leaked into podman argv"
    );
    // …nor in any captured audit payload.
    for (_, p) in h.audit.records() {
        assert!(
            !p.to_string().contains(secret_value),
            "secret value leaked into an audit payload"
        );
    }
}

#[tokio::test]
async fn secret_remove_reports_removed_and_audits_name_only() {
    let h = Harness::build().await;
    let result = h
        .ok(Method::SecretRemove(SecretRemoveParams {
            name: "db-password".to_string(),
        }))
        .await;
    assert_eq!(result["name"], "db-password");
    assert_eq!(result["removed"], true);
    let payload = h
        .audit
        .payload_for(AuditSinkKind::SecretRemoved)
        .expect("SecretRemoved audit row");
    assert_eq!(payload, serde_json::json!({ "name": "db-password" }));
}

// ===========================================================================
// System / image / volume arms
// ===========================================================================

#[tokio::test]
async fn system_df_overlays_podman_raw_sizes() {
    let h = Harness::build().await;
    let result = h.ok(Method::SystemDf).await;

    // List-derived counts (from `ps` / `images` / `volume ls`).
    assert_eq!(result["containers"]["total"], 2);
    assert_eq!(result["containers"]["running"], 1);
    assert_eq!(result["images"]["total"], 1);

    // Overlay path: `system df --format json` RawSize/RawReclaimable win over the
    // list-derived approximation.
    assert_eq!(result["images"]["size_bytes"], 4_509_715_660u64);
    assert_eq!(result["images"]["reclaimable_bytes"], 1_181_116_006u64);
    assert_eq!(result["containers"]["size_bytes"], 32_768u64);
    assert_eq!(result["volumes"]["size_bytes"], 335_544_320u64);

    assert!(h.argv_log().contains("system df"), "log={}", h.argv_log());
}

#[tokio::test]
async fn image_pull_job_starts_and_streams_progress_events() {
    let h = Harness::build().await;
    let mut rx = h.event_bus.subscribe();

    let result = h
        .ok(Method::ImagePullJob(ImagePullJobParams {
            reference: "docker.io/library/alpine:latest".to_string(),
        }))
        .await;
    assert_eq!(result["status"], "started");
    let job_id = result["job_id"].as_str().expect("job_id");
    assert!(job_id.starts_with("pull-"), "got {job_id}");

    // The spawned task streams one Progress event per fake pull line, then a
    // terminal Succeeded (the fake emits output, so it is not Failed).
    let events = collect_events(&mut rx, 8, Duration::from_secs(5)).await;
    let progress = events
        .iter()
        .filter(|e| matches!(e.kind, EventKind::Progress))
        .count();
    assert!(progress >= 1, "expected progress events, got {events:?}");
    assert!(
        events
            .iter()
            .any(|e| matches!(e.kind, EventKind::Succeeded)),
        "expected a terminal Succeeded event, got {events:?}"
    );

    // ImagePullStarted audit carries the reference + job_id (never a secret).
    let payload = h
        .audit
        .payload_for(AuditSinkKind::ImagePullStarted)
        .expect("ImagePullStarted audit row");
    assert_eq!(payload["reference"], "docker.io/library/alpine:latest");
    assert_eq!(payload["job_id"], job_id);
}

#[tokio::test]
async fn volume_inspect_detail_composes_size_and_in_use_by() {
    let h = Harness::build().await;
    let result = h
        .ok(Method::VolumeInspectDetail(VolumeNameParams {
            name: VolumeId::from("data-vol"),
        }))
        .await;
    let detail: responses::VolumeInspectDetailResponse =
        serde_json::from_value(result).expect("VolumeInspectDetailResponse");
    assert_eq!(detail.name, "data-vol");
    assert_eq!(detail.driver, "local");
    assert_eq!(
        detail.mountpoint,
        "/var/lib/containers/storage/volumes/data-vol/_data"
    );
    // Size comes from `system df -v`; in-use-by from `ps -a --filter volume=`.
    assert_eq!(detail.size_bytes, Some(104_857_600));
    assert_eq!(
        detail.in_use_by,
        vec!["web".to_string(), "worker".to_string()]
    );

    let log = h.argv_log();
    assert!(log.contains("volume inspect data-vol"), "log={log}");
    assert!(log.contains("--filter volume=data-vol"), "log={log}");
}
