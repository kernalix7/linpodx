//! Disk management center for the Spec v6 Disk Usage lane.
//!
//! Mounted at `Tab::DiskUsage` by `app.rs` as `DiskUsageView`.

use std::collections::HashSet;

use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::spawn_local;

use crate::api_client::{fetch_container_inspect, fetch_system_df};
use crate::app::AuthToken;
use crate::helpers::{format_bytes, short_id};
use crate::ws::{fetch_list, send_rpc, subscribe};

#[derive(Clone, Copy, PartialEq, Eq)]
enum PruneCategory {
    Images,
    Containers,
    Volumes,
    BuildCache,
    Everything,
}

#[derive(Clone)]
struct CategoryStats {
    category: PruneCategory,
    label: &'static str,
    count: String,
    size_bytes: Option<u64>,
    reclaimable_bytes: Option<u64>,
}

#[derive(Clone)]
struct Toast {
    id: u64,
    text: String,
    kind: &'static str,
}

fn copy_to_clipboard(text: &str) {
    let Some(win) = web_sys::window() else {
        return;
    };
    let win_val: JsValue = win.into();
    let Ok(nav) = js_sys::Reflect::get(&win_val, &JsValue::from_str("navigator")) else {
        return;
    };
    let Ok(clip) = js_sys::Reflect::get(&nav, &JsValue::from_str("clipboard")) else {
        return;
    };
    if clip.is_undefined() || clip.is_null() {
        return;
    }
    let Ok(write) = js_sys::Reflect::get(&clip, &JsValue::from_str("writeText")) else {
        return;
    };
    if let Ok(func) = write.dyn_into::<js_sys::Function>() {
        let _ = func.call1(&clip, &JsValue::from_str(text));
    }
}

fn value_u64(v: Option<&Value>) -> Option<u64> {
    v.and_then(Value::as_u64).or_else(|| {
        v.and_then(Value::as_i64)
            .and_then(|n| u64::try_from(n).ok())
    })
}

fn row_id(row: &Value) -> String {
    row.get("id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn image_in_use(row: &Value, containers: &[Value]) -> bool {
    let id = row_id(row);
    if id.is_empty() {
        return false;
    }
    let short = short_id(&id);
    let repo_tags: Vec<&str> = row
        .get("repo_tags")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    containers.iter().any(|c| {
        let cimg = c.get("image").and_then(Value::as_str).unwrap_or("");
        !cimg.is_empty() && (cimg == id || cimg == short || repo_tags.contains(&cimg))
    })
}

fn unused_image_ids(images: &[Value], containers: &[Value]) -> Vec<String> {
    images
        .iter()
        .filter(|row| !image_in_use(row, containers))
        .map(row_id)
        .filter(|id| !id.is_empty())
        .collect()
}

fn container_is_running(row: &Value) -> bool {
    row.get("state")
        .and_then(Value::as_str)
        .is_some_and(|s| s.eq_ignore_ascii_case("running"))
}

fn unused_container_ids(containers: &[Value]) -> Vec<String> {
    containers
        .iter()
        .filter(|row| !container_is_running(row))
        .map(row_id)
        .filter(|id| !id.is_empty())
        .collect()
}

fn volume_name(row: &Value) -> String {
    row.get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn unused_volume_names(volumes: &[Value], in_use: &HashSet<String>) -> Vec<String> {
    volumes
        .iter()
        .map(volume_name)
        .filter(|name| !name.is_empty() && !in_use.contains(name))
        .collect()
}

fn extract_volume_names(inspect: &Value) -> Vec<String> {
    if let Some(raw_mounts) = inspect.pointer("/raw/Mounts").and_then(Value::as_array) {
        let names: Vec<String> = raw_mounts
            .iter()
            .filter_map(|m| m.get("Name").and_then(Value::as_str))
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        if !names.is_empty() {
            return names;
        }
    }
    inspect
        .get("mounts")
        .and_then(Value::as_array)
        .map(|mounts| {
            mounts
                .iter()
                .filter(|m| {
                    m.get("type")
                        .and_then(Value::as_str)
                        .is_some_and(|k| k.eq_ignore_ascii_case("volume"))
                })
                .filter_map(|m| m.get("source").and_then(Value::as_str))
                .filter_map(|source| {
                    let trimmed = source.trim_end_matches('/');
                    let mut segs = trimmed.rsplit('/');
                    let last = segs.next()?;
                    if last.eq_ignore_ascii_case("_data") {
                        segs.next().map(str::to_string)
                    } else {
                        Some(last.to_string())
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

fn cli_hint(category: PruneCategory) -> &'static str {
    match category {
        PruneCategory::Images => "linpodx system prune --type images",
        PruneCategory::Containers => "linpodx system prune --type containers",
        PruneCategory::Volumes => "linpodx system prune --type volumes",
        PruneCategory::BuildCache => "linpodx system prune --type build-cache",
        PruneCategory::Everything => "linpodx system prune --all",
    }
}

fn category_action_name(category: PruneCategory) -> &'static str {
    match category {
        PruneCategory::Images => "images",
        PruneCategory::Containers => "containers",
        PruneCategory::Volumes => "volumes",
        PruneCategory::BuildCache => "build cache",
        PruneCategory::Everything => "everything",
    }
}

fn category_prune_count(
    category: PruneCategory,
    images: &[Value],
    containers: &[Value],
    volumes: &[Value],
    volume_in_use: &HashSet<String>,
    volume_usage_ready: bool,
) -> Option<usize> {
    match category {
        PruneCategory::Images => Some(unused_image_ids(images, containers).len()),
        PruneCategory::Containers => Some(unused_container_ids(containers).len()),
        PruneCategory::Volumes if volume_usage_ready => {
            Some(unused_volume_names(volumes, volume_in_use).len())
        }
        PruneCategory::Volumes | PruneCategory::BuildCache | PruneCategory::Everything => None,
    }
}

fn build_stats(
    df: Option<&Value>,
    containers_len: usize,
    images_len: usize,
    volumes_len: usize,
) -> Vec<CategoryStats> {
    let images_size = df
        .and_then(|d| value_u64(d.pointer("/images/size_bytes")))
        .or_else(|| df.and_then(|d| value_u64(d.pointer("/images/SizeBytes"))));
    let images_reclaim = df.and_then(|d| value_u64(d.pointer("/images/reclaimable_bytes")));
    let images_total = df
        .and_then(|d| value_u64(d.pointer("/images/total")))
        .unwrap_or(images_len as u64);

    let containers_size = df.and_then(|d| value_u64(d.pointer("/containers/size_bytes")));
    let containers_reclaim = df.and_then(|d| value_u64(d.pointer("/containers/reclaimable_bytes")));
    let containers_total = df
        .and_then(|d| value_u64(d.pointer("/containers/total")))
        .unwrap_or(containers_len as u64);
    let containers_running = df
        .and_then(|d| value_u64(d.pointer("/containers/running")))
        .unwrap_or(0);

    let volumes_size = df.and_then(|d| value_u64(d.pointer("/volumes/size_bytes")));
    let volumes_reclaim = df.and_then(|d| value_u64(d.pointer("/volumes/reclaimable_bytes")));
    let volumes_total = df
        .and_then(|d| value_u64(d.pointer("/volumes/total")))
        .unwrap_or(volumes_len as u64);

    let build_cache_size = df
        .and_then(|d| value_u64(d.pointer("/build_cache/size_bytes")))
        .or_else(|| df.and_then(|d| value_u64(d.get("build_cache_bytes"))));
    let build_cache_reclaim = df
        .and_then(|d| value_u64(d.pointer("/build_cache/reclaimable_bytes")))
        .or(build_cache_size);

    vec![
        CategoryStats {
            category: PruneCategory::Images,
            label: "Images",
            count: format!("{images_total} total"),
            size_bytes: images_size,
            reclaimable_bytes: images_reclaim,
        },
        CategoryStats {
            category: PruneCategory::Containers,
            label: "Containers",
            count: format!("{containers_total} total · {containers_running} active"),
            size_bytes: containers_size,
            reclaimable_bytes: containers_reclaim,
        },
        CategoryStats {
            category: PruneCategory::Volumes,
            label: "Volumes",
            count: format!("{volumes_total} total"),
            size_bytes: volumes_size,
            reclaimable_bytes: volumes_reclaim,
        },
        CategoryStats {
            category: PruneCategory::BuildCache,
            label: "Build cache",
            count: "count unavailable".to_string(),
            size_bytes: build_cache_size,
            reclaimable_bytes: build_cache_reclaim,
        },
    ]
}

#[component]
pub fn DiskUsageView() -> impl IntoView {
    let Some(auth) = use_context::<AuthToken>() else {
        return view! {
            <div class="disk-center">
                <div class="error-state"><span>"Auth context unavailable"</span></div>
            </div>
        }
        .into_any();
    };

    let df: RwSignal<Option<Result<Value, String>>> = RwSignal::new(None);
    let images = RwSignal::new(Vec::<Value>::new());
    let containers = RwSignal::new(Vec::<Value>::new());
    let volumes = RwSignal::new(Vec::<Value>::new());
    let volume_in_use = RwSignal::new(HashSet::<String>::new());
    let volume_usage_ready = RwSignal::new(false);
    let pending: RwSignal<Option<PruneCategory>> = RwSignal::new(None);
    let danger_text = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let toasts = RwSignal::new(Vec::<Toast>::new());
    let toast_seq = RwSignal::new(0u64);

    let push_toast = move |text: String, kind: &'static str| {
        let id = toast_seq.get_untracked() + 1;
        toast_seq.set(id);
        toasts.update(|items| {
            items.push(Toast { id, text, kind });
            let overflow = items.len().saturating_sub(6);
            if overflow > 0 {
                items.drain(0..overflow);
            }
        });
    };

    let reload = move || {
        let Some(token) = auth.0.get_untracked() else {
            df.set(Some(Err("set a bearer token to load disk usage".into())));
            return;
        };
        df.set(None);
        volume_usage_ready.set(false);
        let token_df = token.clone();
        let token_images = token.clone();
        let token_containers = token.clone();
        let token_volumes = token.clone();
        let token_volume_usage = token;

        spawn_local(async move {
            df.set(Some(fetch_system_df(&token_df).await));
        });
        spawn_local(async move {
            if let Ok(v) = fetch_list("images", &token_images).await {
                images.set(v.as_array().cloned().unwrap_or_default());
            }
        });
        spawn_local(async move {
            match fetch_list("containers?all=true", &token_containers).await {
                Ok(v) => containers.set(v.as_array().cloned().unwrap_or_default()),
                Err(_) => containers.set(Vec::new()),
            }
        });
        spawn_local(async move {
            if let Ok(v) = fetch_list("volumes", &token_volumes).await {
                volumes.set(v.as_array().cloned().unwrap_or_default());
            }
        });
        spawn_local(async move {
            let container_rows = fetch_list("containers?all=true", &token_volume_usage)
                .await
                .map(|v| v.as_array().cloned().unwrap_or_default())
                .unwrap_or_default();
            let mut used = HashSet::new();
            for c in &container_rows {
                let id = row_id(c);
                if id.is_empty() {
                    continue;
                }
                if let Ok(inspect) = fetch_container_inspect(&id, &token_volume_usage).await {
                    used.extend(extract_volume_names(&inspect));
                }
            }
            volume_in_use.set(used);
            volume_usage_ready.set(true);
        });
    };

    Effect::new(move |_| {
        let _ = auth.0.get();
        reload();
    });
    Effect::new(move |prev: Option<()>| {
        if prev.is_some() {
            return;
        }
        subscribe("image", move |_| reload());
    });
    Effect::new(move |prev: Option<()>| {
        if prev.is_some() {
            return;
        }
        subscribe("container", move |_| reload());
    });
    Effect::new(move |prev: Option<()>| {
        if prev.is_some() {
            return;
        }
        subscribe("volume", move |_| reload());
    });

    let copy_cli_fallback = move |category: PruneCategory| {
        let hint = cli_hint(category);
        copy_to_clipboard(hint);
        push_toast(format!("copied CLI fallback: {hint}"), "info");
    };

    let run_confirmed = move |_| {
        let Some(category) = pending.get_untracked() else {
            return;
        };
        if category == PruneCategory::Everything {
            if danger_text.get_untracked().trim() != "prune" {
                push_toast("type prune to confirm".to_string(), "error");
                return;
            }
            copy_cli_fallback(category);
            danger_text.set(String::new());
            pending.set(None);
            return;
        }
        if category == PruneCategory::BuildCache {
            copy_cli_fallback(category);
            pending.set(None);
            return;
        }

        let image_ids = unused_image_ids(&images.get_untracked(), &containers.get_untracked());
        let container_ids = unused_container_ids(&containers.get_untracked());
        let volume_names = if volume_usage_ready.get_untracked() {
            unused_volume_names(&volumes.get_untracked(), &volume_in_use.get_untracked())
        } else {
            Vec::new()
        };
        let volume_ready = volume_usage_ready.get_untracked();
        let needs_cli = match category {
            PruneCategory::Images => image_ids.is_empty(),
            PruneCategory::Containers => container_ids.is_empty(),
            PruneCategory::Volumes => !volume_ready || volume_names.is_empty(),
            PruneCategory::BuildCache | PruneCategory::Everything => true,
        };
        if needs_cli {
            copy_cli_fallback(category);
            pending.set(None);
            return;
        }

        busy.set(true);
        pending.set(None);
        spawn_local(async move {
            let mut removed = 0usize;
            let mut failed = 0usize;
            match category {
                PruneCategory::Images => {
                    for id in image_ids {
                        if send_rpc("image_remove", json!({ "id": id, "force": false }))
                            .await
                            .is_ok()
                        {
                            removed += 1;
                        } else {
                            failed += 1;
                        }
                    }
                }
                PruneCategory::Containers => {
                    for id in container_ids {
                        if send_rpc("container_remove", json!({ "id": id, "force": false }))
                            .await
                            .is_ok()
                        {
                            removed += 1;
                        } else {
                            failed += 1;
                        }
                    }
                }
                PruneCategory::Volumes => {
                    for name in volume_names {
                        if send_rpc("volume_remove", json!({ "name": name, "force": false }))
                            .await
                            .is_ok()
                        {
                            removed += 1;
                        } else {
                            failed += 1;
                        }
                    }
                }
                PruneCategory::BuildCache | PruneCategory::Everything => {}
            }
            if failed == 0 {
                push_toast(
                    format!("pruned {removed} {}", category_action_name(category)),
                    "success",
                );
            } else {
                push_toast(
                    format!(
                        "pruned {removed} {}, {failed} failed",
                        category_action_name(category)
                    ),
                    "error",
                );
            }
            busy.set(false);
            reload();
        });
    };

    let summary = move || {
        let stats = build_stats(
            df.get().and_then(Result::ok).as_ref(),
            containers.get().len(),
            images.get().len(),
            volumes.get().len(),
        );
        let used = stats.iter().filter_map(|s| s.size_bytes).sum::<u64>();
        let reclaim = stats
            .iter()
            .filter_map(|s| s.reclaimable_bytes)
            .sum::<u64>();
        view! {
            <div class="disk-cap">
                <span><strong>"Total used"</strong> " " <span class="mono">{format_bytes(used)}</span></span>
                <span><strong>"Known reclaimable"</strong> " " <span class="mono">{format_bytes(reclaim)}</span></span>
            </div>
        }
    };

    let category_rows = move || match df.get() {
        None => view! { <div class="loading-inline">"Loading disk usage…"</div> }.into_any(),
        Some(Err(msg)) => view! { <div class="error-state"><span>{msg}</span></div> }.into_any(),
        Some(Ok(v)) => {
            let stats = build_stats(
                Some(&v),
                containers.get().len(),
                images.get().len(),
                volumes.get().len(),
            );
            let total = stats
                .iter()
                .filter_map(|s| s.size_bytes)
                .sum::<u64>()
                .max(1);
            stats
                .into_iter()
                .map(|stat| {
                    let size_width = stat
                        .size_bytes
                        .map(|size| (size as f64 / total as f64 * 100.0).clamp(0.0, 100.0))
                        .unwrap_or(0.0);
                    let reclaim_width = stat
                        .reclaimable_bytes
                        .map(|size| (size as f64 / total as f64 * 100.0).clamp(0.0, 100.0))
                        .unwrap_or(0.0);
                    let meta = match (stat.size_bytes, stat.reclaimable_bytes) {
                        (Some(size), Some(reclaim)) => {
                            format!(
                                "{} · {} reclaimable",
                                format_bytes(size),
                                format_bytes(reclaim)
                            )
                        }
                        (Some(size), None) => {
                            format!("{} · reclaimable unknown", format_bytes(size))
                        }
                        (None, Some(reclaim)) => {
                            format!("size unknown · {} reclaimable", format_bytes(reclaim))
                        }
                        (None, None) => "size unknown · reclaimable unknown".to_string(),
                    };
                    let category = stat.category;
                    let count = category_prune_count(
                        category,
                        &images.get(),
                        &containers.get(),
                        &volumes.get(),
                        &volume_in_use.get(),
                        volume_usage_ready.get(),
                    );
                    view! {
                        <div class="disk-cat">
                            <div class="disk-cat__head">
                                <span>{stat.label}</span>
                                <span class="mono">{stat.count}</span>
                            </div>
                            <div class="disk-cat__bar">
                                <span
                                    class="disk-cat__fill"
                                    style=format!("width: {size_width:.2}%;")
                                ></span>
                                <span
                                    class="disk-cat__fill disk-cat__fill--reclaim"
                                    style=format!("width: {reclaim_width:.2}%;")
                                ></span>
                            </div>
                            <div class="disk-cat__meta">{meta}</div>
                            {stat.reclaimable_bytes.filter(|bytes| *bytes > 0).map(|bytes| {
                                let label = match count {
                                    Some(n) => format!("{} unused item(s)", n),
                                    None => "CLI fallback required".to_string(),
                                };
                                view! {
                                    <div class="disk-reclaim">
                                        <span>{label}</span>
                                        <button
                                            type="button"
                                            class="btn btn--secondary btn--sm"
                                            prop:disabled=move || busy.get()
                                            on:click=move |_| pending.set(Some(category))
                                        >
                                            {format!("Reclaim {}", format_bytes(bytes))}
                                        </button>
                                    </div>
                                }
                            })}
                        </div>
                    }
                })
                .collect_view()
                .into_any()
        }
    };

    let confirm_modal = move || {
        pending.get().map(|category| {
            let stats = build_stats(
                df.get().and_then(Result::ok).as_ref(),
                containers.get().len(),
                images.get().len(),
                volumes.get().len(),
            );
            let bytes = stats
                .iter()
                .find(|s| s.category == category)
                .and_then(|s| s.reclaimable_bytes)
                .unwrap_or(0);
            let count = category_prune_count(
                category,
                &images.get(),
                &containers.get(),
                &volumes.get(),
                &volume_in_use.get(),
                volume_usage_ready.get(),
            )
            .map(|n| n.to_string())
            .unwrap_or_else(|| "matching".to_string());
            let body = if category == PruneCategory::Everything {
                "Prune everything (all unused)? Type prune to copy the CLI fallback command."
                    .to_string()
            } else if category == PruneCategory::BuildCache {
                format!(
                    "Prune unused build cache? No Web UI endpoint exists; confirming copies `{}`.",
                    cli_hint(category)
                )
            } else {
                format!(
                    "Prune unused {}? This removes {count} item(s) freeing {}.",
                    category_action_name(category),
                    format_bytes(bytes)
                )
            };
            view! {
                <div class="modal-backdrop">
                    <div class="modal-card">
                        <h3>"Confirm prune"</h3>
                        <p class="modal-confirm">{body}</p>
                        <Show when=move || category == PruneCategory::Everything fallback=|| view! { <></> }>
                            <div class="field-group">
                                <label class="label">"Confirmation"</label>
                                <input
                                    class="input"
                                    type="text"
                                    placeholder="prune"
                                    prop:value=move || danger_text.get()
                                    on:input=move |ev| danger_text.set(event_target_value(&ev))
                                />
                            </div>
                        </Show>
                        <div class="modal-actions">
                            <button
                                type="button"
                                class="btn btn--danger"
                                prop:disabled=move || busy.get()
                                on:click=run_confirmed
                            >
                                {move || if busy.get() { "Pruning…" } else { "Confirm" }}
                            </button>
                            <button
                                type="button"
                                class="btn"
                                prop:disabled=move || busy.get()
                                on:click=move |_| {
                                    pending.set(None);
                                    danger_text.set(String::new());
                                }
                            >
                                "Cancel"
                            </button>
                        </div>
                    </div>
                </div>
            }
        })
    };

    view! {
        <div class="disk-center">
            <div class="toolbar page-actions">
                <span class="toolbar__spacer"></span>
                <button
                    type="button"
                    class="btn btn--secondary btn--sm"
                    prop:disabled=move || busy.get()
                    on:click=move |_| reload()
                >
                    "Refresh"
                </button>
            </div>
            {summary}
            <section class="panel">{category_rows}</section>
            <section class="danger-zone">
                <div class="danger-zone__head">"Danger zone"</div>
                <div class="danger-zone__row">
                    <span>
                        <strong>"Prune everything (all unused)"</strong>
                        <span class="modal-hint">" Copies a CLI fallback because no complete Web UI prune endpoint exists."</span>
                    </span>
                    <button
                        type="button"
                        class="btn btn--danger btn--sm"
                        prop:disabled=move || busy.get()
                        on:click=move |_| pending.set(Some(PruneCategory::Everything))
                    >
                        "Prune everything"
                    </button>
                </div>
            </section>
            {confirm_modal}
            <div class="toast-stack">
                {move || toasts.get().into_iter().map(|toast| {
                    let cls = format!("toast toast--{}", toast.kind);
                    let id = toast.id;
                    view! {
                        <div class=cls on:click=move |_| toasts.update(|items| items.retain(|t| t.id != id))>
                            <span>{toast.text}</span>
                        </div>
                    }
                }).collect_view()}
            </div>
        </div>
    }
    .into_any()
}
