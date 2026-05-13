use anyhow::Result;
use comfy_table::{presets::UTF8_FULL, Cell, ContentArrangement, Table};
use linpodx_common::ipc::responses;
use linpodx_common::ipc::responses::{
    AuditEntrySummary, DistroInstanceSummary, DistroTemplateSummary, McpBridgeStatusEntry,
    PluginSummary, SandboxProfileSummary, SessionSummary, SessionTimelineEntry,
    SnapshotBackendListResponse, SnapshotDiffResponse, SnapshotDiffV2Response,
    SnapshotJobStatusResponse, SnapshotSummary,
};
use linpodx_common::ipc::McpPolicyRule;
use linpodx_common::passthrough::PassthroughSpec;
use linpodx_common::state::{ContainerSummary, ImageSummary, NetworkSummary, VolumeSummary};
use serde::Serialize;

#[derive(Debug, Clone, Copy, clap::ValueEnum, PartialEq, Eq)]
#[value(rename_all = "lower")]
pub enum OutputFormat {
    Table,
    Json,
}

pub fn print_container_list(containers: &[ContainerSummary], fmt: OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_json(containers),
        OutputFormat::Table => {
            if containers.is_empty() {
                println!("No containers.");
                return Ok(());
            }
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec![
                    "CONTAINER ID",
                    "NAME",
                    "IMAGE",
                    "STATE",
                    "STATUS",
                    "CREATED",
                ]);
            for c in containers {
                let id_short = if c.id.as_str().len() > 12 {
                    &c.id.as_str()[..12]
                } else {
                    c.id.as_str()
                };
                let name = c.names.first().map(String::as_str).unwrap_or("");
                table.add_row(vec![
                    Cell::new(id_short),
                    Cell::new(name),
                    Cell::new(&c.image),
                    Cell::new(c.state.to_string()),
                    Cell::new(&c.status),
                    Cell::new(c.created.format("%Y-%m-%d %H:%M:%S").to_string()),
                ]);
            }
            println!("{table}");
            Ok(())
        }
    }
}

pub fn print_inspect<T: Serialize>(value: &T, _fmt: OutputFormat) -> Result<()> {
    // `inspect` always renders pretty JSON regardless of --output (matches docker/podman UX).
    print_json(value)
}

pub fn print_version_response(v: &responses::VersionResponse, fmt: OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_json(v),
        OutputFormat::Table => {
            let cli = linpodx_common::version::LINPODX_VERSION;
            println!("Client:");
            println!("  linpodx version: {cli}");
            println!(
                "  IPC version:     {}",
                linpodx_common::version::IPC_VERSION
            );
            println!("Daemon:");
            println!("  linpodx version: {}", v.linpodx_version);
            println!("  IPC version:     {}", v.ipc_version);
            println!("  podman version:  {}", v.podman_version);
            Ok(())
        }
    }
}

pub fn print_logs(logs: &responses::LogsResponse) -> Result<()> {
    use std::io::Write;
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    if !logs.stdout.is_empty() {
        let mut h = stdout.lock();
        h.write_all(logs.stdout.as_bytes())?;
        if !logs.stdout.ends_with('\n') {
            h.write_all(b"\n")?;
        }
    }
    if !logs.stderr.is_empty() {
        let mut h = stderr.lock();
        h.write_all(logs.stderr.as_bytes())?;
        if !logs.stderr.ends_with('\n') {
            h.write_all(b"\n")?;
        }
    }
    Ok(())
}

fn print_json<T: Serialize + ?Sized>(value: &T) -> Result<()> {
    let s = serde_json::to_string_pretty(value)?;
    println!("{s}");
    Ok(())
}

pub fn print_image_list(images: &[ImageSummary], fmt: OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_json(images),
        OutputFormat::Table => {
            if images.is_empty() {
                println!("No images.");
                return Ok(());
            }
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec!["IMAGE ID", "TAGS", "SIZE", "CREATED"]);
            for img in images {
                let id_short = if img.id.as_str().len() > 16 {
                    &img.id.as_str()[..16]
                } else {
                    img.id.as_str()
                };
                let tags = if img.repo_tags.is_empty() {
                    "<none>".to_string()
                } else {
                    img.repo_tags.join(", ")
                };
                table.add_row(vec![
                    Cell::new(id_short),
                    Cell::new(tags),
                    Cell::new(human_size(img.size_bytes)),
                    Cell::new(img.created.format("%Y-%m-%d %H:%M:%S").to_string()),
                ]);
            }
            println!("{table}");
            Ok(())
        }
    }
}

pub fn print_image_push(resp: &responses::ImagePushResponse, fmt: OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_json(resp),
        OutputFormat::Table => {
            println!("Pushed: {}", resp.reference);
            if let Some(d) = &resp.digest {
                println!("Digest:  {d}");
            }
            Ok(())
        }
    }
}

pub fn print_image_manifest_create(
    resp: &responses::ImageManifestCreateResponse,
    fmt: OutputFormat,
) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_json(resp),
        OutputFormat::Table => {
            println!("Manifest: {}", resp.manifest);
            if resp.added.is_empty() {
                println!("Added:    <none>");
            } else {
                println!("Added:");
                for r in &resp.added {
                    println!("  - {r}");
                }
            }
            Ok(())
        }
    }
}

pub fn print_image_manifest_push(
    resp: &responses::ImageManifestPushResponse,
    fmt: OutputFormat,
) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_json(resp),
        OutputFormat::Table => {
            println!("Manifest pushed: {}", resp.manifest);
            if let Some(reg) = &resp.registry {
                println!("Registry:        {reg}");
            }
            Ok(())
        }
    }
}

pub fn print_volume_list(volumes: &[VolumeSummary], fmt: OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_json(volumes),
        OutputFormat::Table => {
            if volumes.is_empty() {
                println!("No volumes.");
                return Ok(());
            }
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec!["NAME", "DRIVER", "MOUNTPOINT", "CREATED"]);
            for v in volumes {
                table.add_row(vec![
                    Cell::new(v.name.as_str()),
                    Cell::new(&v.driver),
                    Cell::new(&v.mountpoint),
                    Cell::new(v.created.format("%Y-%m-%d %H:%M:%S").to_string()),
                ]);
            }
            println!("{table}");
            Ok(())
        }
    }
}

pub fn print_network_list(networks: &[NetworkSummary], fmt: OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_json(networks),
        OutputFormat::Table => {
            if networks.is_empty() {
                println!("No networks.");
                return Ok(());
            }
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec!["NETWORK ID", "NAME", "DRIVER", "SUBNET", "CREATED"]);
            for n in networks {
                let id_short = if n.id.as_str().len() > 16 {
                    &n.id.as_str()[..16]
                } else {
                    n.id.as_str()
                };
                table.add_row(vec![
                    Cell::new(id_short),
                    Cell::new(&n.name),
                    Cell::new(&n.driver),
                    Cell::new(n.subnet.as_deref().unwrap_or("-")),
                    Cell::new(n.created.format("%Y-%m-%d %H:%M:%S").to_string()),
                ]);
            }
            println!("{table}");
            Ok(())
        }
    }
}

pub fn print_prune_result(kind: &str, removed: &[String]) -> Result<()> {
    if removed.is_empty() {
        println!("No {kind} to prune.");
    } else {
        println!("Removed {} {kind}:", removed.len());
        for r in removed {
            println!("  {r}");
        }
    }
    Ok(())
}

pub fn print_sandbox_profile_list(
    profiles: &[SandboxProfileSummary],
    fmt: OutputFormat,
) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_json(profiles),
        OutputFormat::Table => {
            if profiles.is_empty() {
                println!("No sandbox profiles loaded. Drop YAML files into ~/.config/linpodx/profiles/ and run `linpodx sandbox reload`.");
                return Ok(());
            }
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec![
                    "NAME",
                    "VERSION",
                    "DESCRIPTION",
                    "YAML HASH",
                    "UPDATED",
                ]);
            for p in profiles {
                let hash_short = if p.yaml_hash.len() > 12 {
                    &p.yaml_hash[..12]
                } else {
                    p.yaml_hash.as_str()
                };
                table.add_row(vec![
                    Cell::new(&p.name),
                    Cell::new(p.version.to_string()),
                    Cell::new(&p.description),
                    Cell::new(hash_short),
                    Cell::new(p.last_updated.format("%Y-%m-%d %H:%M:%S").to_string()),
                ]);
            }
            println!("{table}");
            Ok(())
        }
    }
}

pub fn print_audit_table(entries: &[AuditEntrySummary]) -> Result<()> {
    if entries.is_empty() {
        println!("No audit entries.");
        return Ok(());
    }
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec!["SEQ", "TS", "KIND", "PROFILE", "CONTAINER", "PAYLOAD"]);
    for e in entries {
        let payload_summary = match &e.payload {
            serde_json::Value::Object(_) => {
                let s = serde_json::to_string(&e.payload).unwrap_or_default();
                if s.len() > 60 {
                    format!("{}…", &s[..60])
                } else {
                    s
                }
            }
            other => other.to_string(),
        };
        table.add_row(vec![
            Cell::new(e.seq),
            Cell::new(e.ts.format("%Y-%m-%d %H:%M:%S").to_string()),
            Cell::new(&e.kind),
            Cell::new(e.profile_name.clone().unwrap_or_else(|| "-".into())),
            Cell::new(e.container_id.clone().unwrap_or_else(|| "-".into())),
            Cell::new(payload_summary),
        ]);
    }
    println!("{table}");
    Ok(())
}

pub fn print_snapshot_list(snapshots: &[SnapshotSummary], fmt: OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_json(snapshots),
        OutputFormat::Table => {
            if snapshots.is_empty() {
                println!("No snapshots.");
                return Ok(());
            }
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec!["ID", "CONTAINER", "LABEL", "IMAGE", "CREATED"]);
            for s in snapshots {
                let cid_short = if s.container_id.len() > 12 {
                    &s.container_id[..12]
                } else {
                    s.container_id.as_str()
                };
                table.add_row(vec![
                    Cell::new(s.id),
                    Cell::new(cid_short),
                    Cell::new(s.label.clone().unwrap_or_else(|| "-".into())),
                    Cell::new(&s.image_ref),
                    Cell::new(s.created_at.format("%Y-%m-%d %H:%M:%S").to_string()),
                ]);
            }
            println!("{table}");
            Ok(())
        }
    }
}

pub fn print_snapshot_diff_v2(resp: &SnapshotDiffV2Response, fmt: OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_json(resp),
        OutputFormat::Table => {
            println!(
                "Layer-aware diff snapshots {} → {} (size delta: {} bytes)",
                resp.id_a, resp.id_b, resp.size_delta_bytes
            );
            let mut summary = Table::new();
            summary
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec!["COMMON-LAYERS", "A-ONLY", "B-ONLY", "SIZE-DELTA"]);
            summary.add_row(vec![
                Cell::new(resp.common_layer_count),
                Cell::new(resp.a_only_layers.len()),
                Cell::new(resp.b_only_layers.len()),
                Cell::new(resp.size_delta_bytes),
            ]);
            println!("{summary}");

            if !resp.a_only_layers.is_empty() || !resp.b_only_layers.is_empty() {
                let mut layers = Table::new();
                layers
                    .load_preset(UTF8_FULL)
                    .set_content_arrangement(ContentArrangement::Dynamic)
                    .set_header(vec!["SIDE", "LAYER", "SIZE"]);
                for l in &resp.a_only_layers {
                    layers.add_row(vec![
                        Cell::new("A"),
                        Cell::new(short_layer(&l.layer_id)),
                        Cell::new(l.size_bytes),
                    ]);
                }
                for l in &resp.b_only_layers {
                    layers.add_row(vec![
                        Cell::new("B"),
                        Cell::new(short_layer(&l.layer_id)),
                        Cell::new(l.size_bytes),
                    ]);
                }
                println!("{layers}");
            }

            if !resp.file_changes.is_empty() {
                let mut files = Table::new();
                files
                    .load_preset(UTF8_FULL)
                    .set_content_arrangement(ContentArrangement::Dynamic)
                    .set_header(vec!["CHANGE", "PATH", "LAYER"]);
                for c in &resp.file_changes {
                    files.add_row(vec![
                        Cell::new(c.kind.to_uppercase()),
                        Cell::new(&c.path),
                        Cell::new(short_layer(&c.layer_id)),
                    ]);
                }
                println!("{files}");
            } else {
                // v0.1 limitation: per-layer file-change extraction is not implemented.
                println!(
                    "(no per-layer file changes; layer-level diff only in v0.1 — used_layer_path={})",
                    resp.used_layer_path
                );
            }
            Ok(())
        }
    }
}

pub fn print_snapshot_backend_list(
    backends: &SnapshotBackendListResponse,
    fmt: OutputFormat,
) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_json(backends),
        OutputFormat::Table => {
            if backends.is_empty() {
                println!("No snapshot backends registered.");
                return Ok(());
            }
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec!["KIND", "AVAILABLE", "NOTE"]);
            for b in backends {
                table.add_row(vec![
                    Cell::new(b.kind.as_str()),
                    Cell::new(if b.available { "yes" } else { "no" }),
                    Cell::new(&b.note),
                ]);
            }
            println!("{table}");
            Ok(())
        }
    }
}

fn short_layer(digest: &str) -> String {
    let trimmed = digest.strip_prefix("sha256:").unwrap_or(digest);
    if trimmed.len() > 12 {
        format!("{}…", &trimmed[..12])
    } else {
        trimmed.to_string()
    }
}

pub fn print_snapshot_diff(diff: &SnapshotDiffResponse, fmt: OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_json(diff),
        OutputFormat::Table => {
            println!(
                "Diff snapshots {} → {} (size delta: {} bytes)",
                diff.id_a, diff.id_b, diff.size_delta_bytes
            );
            if diff.added.is_empty() && diff.modified.is_empty() && diff.deleted.is_empty() {
                println!("No changes.");
                return Ok(());
            }
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec!["CHANGE", "PATH"]);
            for p in &diff.added {
                table.add_row(vec![Cell::new("ADDED"), Cell::new(p)]);
            }
            for p in &diff.modified {
                table.add_row(vec![Cell::new("MODIFIED"), Cell::new(p)]);
            }
            for p in &diff.deleted {
                table.add_row(vec![Cell::new("DELETED"), Cell::new(p)]);
            }
            println!("{table}");
            Ok(())
        }
    }
}

pub fn print_session_list(sessions: &[SessionSummary], fmt: OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_json(sessions),
        OutputFormat::Table => {
            if sessions.is_empty() {
                println!("No sessions.");
                return Ok(());
            }
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec![
                    "ID",
                    "CONTAINER",
                    "NAME",
                    "PROFILE",
                    "STATUS",
                    "STARTED",
                    "ENDED",
                ]);
            for s in sessions {
                let cid_short = if s.container_id.len() > 12 {
                    &s.container_id[..12]
                } else {
                    s.container_id.as_str()
                };
                let ended = s
                    .ended_at
                    .map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_else(|| "-".into());
                table.add_row(vec![
                    Cell::new(s.id),
                    Cell::new(cid_short),
                    Cell::new(&s.container_name),
                    Cell::new(s.profile_name.clone().unwrap_or_else(|| "-".into())),
                    Cell::new(&s.status),
                    Cell::new(s.started_at.format("%Y-%m-%d %H:%M:%S").to_string()),
                    Cell::new(ended),
                ]);
            }
            println!("{table}");
            Ok(())
        }
    }
}

pub fn print_session_timeline(entries: &[SessionTimelineEntry]) -> Result<()> {
    if entries.is_empty() {
        println!("No timeline entries.");
        return Ok(());
    }
    for e in entries {
        let ts = e.ts.format("%Y-%m-%d %H:%M:%S%.3f");
        let payload = match &e.payload {
            serde_json::Value::Null => String::new(),
            other => {
                let s = serde_json::to_string(other).unwrap_or_default();
                if s.len() > 120 {
                    format!(" {}…", &s[..120])
                } else {
                    format!(" {s}")
                }
            }
        };
        println!("[{ts}] {}.{}{payload}", e.source, e.kind);
    }
    Ok(())
}

pub fn print_mcp_status(entries: &[McpBridgeStatusEntry], fmt: OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_json(entries),
        OutputFormat::Table => {
            if entries.is_empty() {
                println!("No active MCP bridges.");
                return Ok(());
            }
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec![
                    "BRIDGE_ID",
                    "CONTAINER",
                    "HOST_CMD",
                    "MESSAGES",
                    "STARTED",
                ]);
            for e in entries {
                let cid_short = if e.container_id.len() > 12 {
                    &e.container_id[..12]
                } else {
                    e.container_id.as_str()
                };
                table.add_row(vec![
                    Cell::new(&e.bridge_id),
                    Cell::new(cid_short),
                    Cell::new(&e.host_command),
                    Cell::new(e.messages_seen),
                    Cell::new(e.started_at.format("%Y-%m-%d %H:%M:%S").to_string()),
                ]);
            }
            println!("{table}");
            Ok(())
        }
    }
}

pub fn print_distro_template_list(
    entries: &[DistroTemplateSummary],
    fmt: OutputFormat,
) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_json(entries),
        OutputFormat::Table => {
            if entries.is_empty() {
                println!("No distro templates registered.");
                return Ok(());
            }
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec!["KIND", "DISPLAY", "IMAGE", "INIT", "PACKAGES"]);
            for e in entries {
                let pkgs = if e.default_packages.is_empty() {
                    "-".to_string()
                } else {
                    e.default_packages.join(", ")
                };
                table.add_row(vec![
                    Cell::new(e.kind.to_string()),
                    Cell::new(&e.display_name),
                    Cell::new(&e.default_image),
                    Cell::new(&e.init_kind),
                    Cell::new(pkgs),
                ]);
            }
            println!("{table}");
            Ok(())
        }
    }
}

pub fn print_distro_instance(inst: &DistroInstanceSummary, fmt: OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_json(inst),
        OutputFormat::Table => {
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec![
                    "ID",
                    "NAME",
                    "KIND",
                    "CONTAINER",
                    "IMAGE",
                    "VM_MODE",
                    "HOME_VOLUME",
                    "AUTO_RESTART",
                    "CREATED",
                ]);
            let cid_short = if inst.container_id.len() > 12 {
                &inst.container_id[..12]
            } else {
                inst.container_id.as_str()
            };
            table.add_row(vec![
                Cell::new(inst.id),
                Cell::new(&inst.name),
                Cell::new(inst.kind.to_string()),
                Cell::new(cid_short),
                Cell::new(&inst.image_ref),
                Cell::new(check(inst.vm_mode)),
                Cell::new(inst.home_volume.clone().unwrap_or_else(|| "-".into())),
                Cell::new(check(inst.auto_restart)),
                Cell::new(inst.created_at.format("%Y-%m-%d %H:%M:%S").to_string()),
            ]);
            println!("{table}");
            Ok(())
        }
    }
}

pub fn print_mcp_policy_list(rules: &[McpPolicyRule], fmt: OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_json(rules),
        OutputFormat::Table => {
            if rules.is_empty() {
                println!("No MCP policy rules.");
                return Ok(());
            }
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec!["METHOD", "TOOL", "DECISION", "NOTE"]);
            for r in rules {
                table.add_row(vec![
                    Cell::new(&r.method),
                    Cell::new(r.tool_name.clone().unwrap_or_else(|| "-".into())),
                    Cell::new(format!("{:?}", r.decision)),
                    Cell::new(r.note.clone().unwrap_or_else(|| "-".into())),
                ]);
            }
            println!("{table}");
            Ok(())
        }
    }
}

pub fn print_snapshot_job_status(
    resp: &SnapshotJobStatusResponse,
    fmt: OutputFormat,
) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_json(resp),
        OutputFormat::Table => {
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec![
                    "JOB_ID",
                    "CONTAINER",
                    "STATUS",
                    "SNAPSHOT_ID",
                    "IMAGE",
                    "PROGRESS",
                    "STARTED",
                    "ENDED",
                ]);
            let cid_short = if resp.container_id.len() > 12 {
                &resp.container_id[..12]
            } else {
                resp.container_id.as_str()
            };
            let snap_id = resp
                .snapshot_id
                .map(|n| n.to_string())
                .unwrap_or_else(|| "-".into());
            let image = resp.image_ref.clone().unwrap_or_else(|| "-".into());
            let progress = resp.last_progress.clone().unwrap_or_else(|| "-".into());
            let ended = resp
                .ended_at
                .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| "-".into());
            table.add_row(vec![
                Cell::new(&resp.job_id),
                Cell::new(cid_short),
                Cell::new(&resp.status),
                Cell::new(snap_id),
                Cell::new(image),
                Cell::new(progress),
                Cell::new(resp.started_at.format("%Y-%m-%d %H:%M:%S").to_string()),
                Cell::new(ended),
            ]);
            println!("{table}");
            if let Some(err) = &resp.error_message {
                println!("error: {err}");
            }
            Ok(())
        }
    }
}

pub fn print_passthrough_status(
    profile: &str,
    spec: &PassthroughSpec,
    fmt: OutputFormat,
) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_json(spec),
        OutputFormat::Table => {
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec!["FIELD", "VALUE"]);
            table.add_row(vec![Cell::new("profile"), Cell::new(profile)]);
            table.add_row(vec![Cell::new("wayland"), Cell::new(check(spec.wayland))]);
            table.add_row(vec![Cell::new("x11"), Cell::new(check(spec.x11))]);
            table.add_row(vec![
                Cell::new("audio"),
                Cell::new(format!("{:?}", spec.audio)),
            ]);
            table.add_row(vec![Cell::new("gpu"), Cell::new(check(spec.gpu))]);
            table.add_row(vec![
                Cell::new("dbus_session"),
                Cell::new(check(spec.dbus_session)),
            ]);
            table.add_row(vec![
                Cell::new("clipboard"),
                Cell::new(check(spec.clipboard)),
            ]);
            table.add_row(vec![
                Cell::new("hidpi_inherit"),
                Cell::new(check(spec.hidpi_inherit)),
            ]);
            table.add_row(vec![
                Cell::new("register_app_menu"),
                Cell::new(spec.register_app_menu.clone().unwrap_or_else(|| "-".into())),
            ]);
            println!("{table}");
            Ok(())
        }
    }
}

fn check(b: bool) -> &'static str {
    if b {
        "[x]"
    } else {
        "[ ]"
    }
}

fn human_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if bytes >= GIB {
        format!("{:.2} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.2} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.2} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// Render a Phase 11/12 secprofile compile result. JSON form prints the artefact paths;
/// table form prints them human-readably along with the cache directory.
pub fn print_compile_result(
    profile_name: &str,
    cache_dir: &std::path::Path,
    compiled: &linpodx_sandbox::CompiledProfile,
    fmt: OutputFormat,
) -> Result<()> {
    match fmt {
        OutputFormat::Json => {
            let value = serde_json::json!({
                "profile": profile_name,
                "cache_dir": cache_dir.display().to_string(),
                "seccomp_path": compiled.seccomp_path.as_ref().map(|p| p.display().to_string()),
                "apparmor_name": compiled.apparmor_name.as_ref().map(|p| p.display().to_string()),
                "selinux_module_name": compiled.selinux_module_name.as_ref(),
                "security_opts": compiled.to_security_opts(),
            });
            print_json(&value)
        }
        OutputFormat::Table => {
            println!("Compiled sandbox profile '{profile_name}':");
            println!("  cache dir: {}", cache_dir.display());
            match &compiled.seccomp_path {
                Some(p) => println!("  seccomp:  {}", p.display()),
                None => println!("  seccomp:  (not requested)"),
            }
            match &compiled.apparmor_name {
                Some(name) => println!(
                    "  apparmor: {} (loaded via apparmor_parser -r)",
                    name.display()
                ),
                None => println!("  apparmor: (not requested or apparmor_parser unavailable)"),
            }
            match &compiled.selinux_module_name {
                Some(name) => println!("  selinux:  {name} (installed via semodule -i)"),
                None => println!("  selinux:  (not requested or SELinux toolchain unavailable)"),
            }
            let opts = compiled.to_security_opts();
            if opts.is_empty() {
                println!("  --security-opt: (none)");
            } else {
                println!("  --security-opt:");
                for o in opts {
                    println!("    {o}");
                }
            }
            Ok(())
        }
    }
}

pub fn print_k8s_pod_created(
    resp: &responses::K8sPodCreateResponse,
    fmt: OutputFormat,
) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_json(resp),
        OutputFormat::Table => {
            println!(
                "pod created\tnamespace={}\tname={}\tuid={}",
                resp.namespace,
                resp.name,
                resp.uid.as_deref().unwrap_or("-"),
            );
            Ok(())
        }
    }
}

pub fn print_k8s_pod_deleted(
    resp: &responses::K8sPodDeleteResponse,
    fmt: OutputFormat,
) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_json(resp),
        OutputFormat::Table => {
            println!(
                "pod deleted\tnamespace={}\tname={}\tdeleted={}",
                resp.namespace, resp.name, resp.deleted,
            );
            Ok(())
        }
    }
}

pub fn print_k8s_namespace_created(
    resp: &responses::K8sNamespaceCreateResponse,
    fmt: OutputFormat,
) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_json(resp),
        OutputFormat::Table => {
            println!(
                "namespace created\tname={}\tuid={}",
                resp.name,
                resp.uid.as_deref().unwrap_or("-"),
            );
            Ok(())
        }
    }
}

pub fn print_k8s_deployment_scaled(
    resp: &responses::K8sDeploymentScaleResponse,
    fmt: OutputFormat,
) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_json(resp),
        OutputFormat::Table => {
            println!(
                "deployment scaled\tnamespace={}\tname={}\treplicas={}",
                resp.namespace, resp.name, resp.replicas,
            );
            Ok(())
        }
    }
}

pub fn print_plugin_list(plugins: &[PluginSummary], fmt: OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Json => print_json(plugins),
        OutputFormat::Table => {
            if plugins.is_empty() {
                println!("No plugins installed. Use `linpodx plugin install <dir>` to add one.");
                return Ok(());
            }
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec!["NAME", "VERSION", "HOOKS", "ENABLED", "INSTALLED"]);
            for p in plugins {
                table.add_row(vec![
                    Cell::new(&p.name),
                    Cell::new(&p.version),
                    Cell::new(p.hooks.join(",")),
                    Cell::new(if p.enabled { "yes" } else { "no" }),
                    Cell::new(p.installed_at.format("%Y-%m-%d %H:%M:%S").to_string()),
                ]);
            }
            println!("{table}");
            Ok(())
        }
    }
}
