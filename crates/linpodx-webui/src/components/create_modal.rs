//! Container create modal — browser-side form that POSTs a `CreateOptions`
//! shaped JSON body to the daemon REST bridge.

use leptos::prelude::*;
use serde_json::{json, Map, Value};
use wasm_bindgen_futures::spawn_local;

use super::icons::Icon;
use crate::api_client::create_container;
use crate::app::AuthToken;

#[derive(Clone, Debug, PartialEq, Eq)]
struct PortRow {
    id: u64,
    host_port: String,
    container_port: String,
    protocol: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TextRow {
    id: u64,
    value: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VolumeRow {
    id: u64,
    source: String,
    destination: String,
    read_only: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PairRow {
    id: u64,
    key: String,
    value: String,
}

#[component]
pub fn CreateContainerModal(
    open: RwSignal<bool>,
    refresh_containers: Callback<()>,
) -> impl IntoView {
    let auth = use_context::<AuthToken>();
    let image = RwSignal::new(String::new());
    let name = RwSignal::new(String::new());
    let command = RwSignal::new(String::new());
    let network = RwSignal::new(String::new());
    let restart_policy = RwSignal::new(String::from("no"));
    let port_rows = RwSignal::new(vec![PortRow {
        id: 0,
        host_port: String::new(),
        container_port: String::new(),
        protocol: String::from("tcp"),
    }]);
    let env_rows = RwSignal::new(vec![TextRow {
        id: 0,
        value: String::new(),
    }]);
    let volume_rows = RwSignal::new(vec![VolumeRow {
        id: 0,
        source: String::new(),
        destination: String::new(),
        read_only: false,
    }]);
    let label_rows = RwSignal::new(vec![PairRow {
        id: 0,
        key: String::new(),
        value: String::new(),
    }]);
    let next_id = RwSignal::new(1_u64);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let busy = RwSignal::new(false);

    Effect::new(move |_| {
        if open.get() {
            image.set(String::new());
            name.set(String::new());
            command.set(String::new());
            network.set(String::new());
            restart_policy.set(String::from("no"));
            port_rows.set(vec![PortRow {
                id: 0,
                host_port: String::new(),
                container_port: String::new(),
                protocol: String::from("tcp"),
            }]);
            env_rows.set(vec![TextRow {
                id: 0,
                value: String::new(),
            }]);
            volume_rows.set(vec![VolumeRow {
                id: 0,
                source: String::new(),
                destination: String::new(),
                read_only: false,
            }]);
            label_rows.set(vec![PairRow {
                id: 0,
                key: String::new(),
                value: String::new(),
            }]);
            next_id.set(1);
            error.set(None);
            busy.set(false);
        }
    });

    let close = move |_| {
        if !busy.get_untracked() {
            open.set(false);
        }
    };

    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let token = match auth.and_then(|ctx| ctx.0.get_untracked()) {
            Some(token) => token,
            None => {
                error.set(Some(
                    "set a bearer token before creating a container".into(),
                ));
                return;
            }
        };
        let body = match build_create_body(
            &image.get_untracked(),
            &name.get_untracked(),
            &command.get_untracked(),
            &network.get_untracked(),
            &restart_policy.get_untracked(),
            &port_rows.get_untracked(),
            &env_rows.get_untracked(),
            &volume_rows.get_untracked(),
            &label_rows.get_untracked(),
        ) {
            Ok(body) => body,
            Err(msg) => {
                error.set(Some(msg));
                return;
            }
        };

        busy.set(true);
        error.set(None);
        spawn_local(async move {
            match create_container(body, &token).await {
                Ok(_) => {
                    open.set(false);
                    refresh_containers.run(());
                }
                Err(msg) => error.set(Some(msg)),
            }
            busy.set(false);
        });
    };

    let add_port = move |_| {
        let id = take_next_id(next_id);
        port_rows.update(|rows| {
            rows.push(PortRow {
                id,
                host_port: String::new(),
                container_port: String::new(),
                protocol: String::from("tcp"),
            });
        });
    };
    let add_env = move |_| {
        let id = take_next_id(next_id);
        env_rows.update(|rows| {
            rows.push(TextRow {
                id,
                value: String::new(),
            });
        });
    };
    let add_volume = move |_| {
        let id = take_next_id(next_id);
        volume_rows.update(|rows| {
            rows.push(VolumeRow {
                id,
                source: String::new(),
                destination: String::new(),
                read_only: false,
            });
        });
    };
    let add_label = move |_| {
        let id = take_next_id(next_id);
        label_rows.update(|rows| {
            rows.push(PairRow {
                id,
                key: String::new(),
                value: String::new(),
            });
        });
    };

    let port_rows_view = move || {
        port_rows
            .get()
            .into_iter()
            .map(|row| {
                let id = row.id;
                let remove_disabled = port_rows.get_untracked().len() <= 1;
                view! {
                    <label class="modal-inline">
                        <input
                            class="input"
                            type="text"
                            placeholder="Host port"
                            prop:value=row.host_port
                            on:input=move |ev| {
                                let value = event_target_value(&ev);
                                port_rows.update(|rows| {
                                    if let Some(row) = rows.iter_mut().find(|row| row.id == id) {
                                        row.host_port = value;
                                    }
                                });
                            }
                        />
                        <input
                            class="input"
                            type="text"
                            placeholder="Container port"
                            prop:value=row.container_port
                            on:input=move |ev| {
                                let value = event_target_value(&ev);
                                port_rows.update(|rows| {
                                    if let Some(row) = rows.iter_mut().find(|row| row.id == id) {
                                        row.container_port = value;
                                    }
                                });
                            }
                        />
                        <select
                            class="select"
                            prop:value=row.protocol
                            on:change=move |ev| {
                                let value = event_target_value(&ev);
                                port_rows.update(|rows| {
                                    if let Some(row) = rows.iter_mut().find(|row| row.id == id) {
                                        row.protocol = value;
                                    }
                                });
                            }
                        >
                            <option value="tcp">"tcp"</option>
                            <option value="udp">"udp"</option>
                            <option value="sctp">"sctp"</option>
                        </select>
                        <button
                            type="button"
                            class="btn btn--ghost"
                            prop:disabled=remove_disabled
                            on:click=move |_| remove_row(port_rows, id)
                        >
                            <Icon name="close"/>
                            "Remove"
                        </button>
                    </label>
                }
            })
            .collect_view()
    };

    let env_rows_view = move || {
        env_rows
            .get()
            .into_iter()
            .map(|row| {
                let id = row.id;
                let remove_disabled = env_rows.get_untracked().len() <= 1;
                view! {
                    <label class="modal-inline">
                        <input
                            class="input"
                            type="text"
                            placeholder="KEY=VALUE"
                            prop:value=row.value
                            on:input=move |ev| {
                                let value = event_target_value(&ev);
                                env_rows.update(|rows| {
                                    if let Some(row) = rows.iter_mut().find(|row| row.id == id) {
                                        row.value = value;
                                    }
                                });
                            }
                        />
                        <button
                            type="button"
                            class="btn btn--ghost"
                            prop:disabled=remove_disabled
                            on:click=move |_| remove_row(env_rows, id)
                        >
                            <Icon name="close"/>
                            "Remove"
                        </button>
                    </label>
                }
            })
            .collect_view()
    };

    let volume_rows_view = move || {
        volume_rows
            .get()
            .into_iter()
            .map(|row| {
                let id = row.id;
                let remove_disabled = volume_rows.get_untracked().len() <= 1;
                view! {
                    <label class="modal-inline">
                        <input
                            class="input"
                            type="text"
                            placeholder="Host path or volume"
                            prop:value=row.source
                            on:input=move |ev| {
                                let value = event_target_value(&ev);
                                volume_rows.update(|rows| {
                                    if let Some(row) = rows.iter_mut().find(|row| row.id == id) {
                                        row.source = value;
                                    }
                                });
                            }
                        />
                        <input
                            class="input"
                            type="text"
                            placeholder="/container/path"
                            prop:value=row.destination
                            on:input=move |ev| {
                                let value = event_target_value(&ev);
                                volume_rows.update(|rows| {
                                    if let Some(row) = rows.iter_mut().find(|row| row.id == id) {
                                        row.destination = value;
                                    }
                                });
                            }
                        />
                        <span class="modal-inline">
                            <input
                                class="checkbox"
                                type="checkbox"
                                prop:checked=row.read_only
                                on:change=move |ev| {
                                    let checked = event_target_checked(&ev);
                                    volume_rows.update(|rows| {
                                        if let Some(row) = rows.iter_mut().find(|row| row.id == id) {
                                            row.read_only = checked;
                                        }
                                    });
                                }
                            />
                            "ro"
                        </span>
                        <button
                            type="button"
                            class="btn btn--ghost"
                            prop:disabled=remove_disabled
                            on:click=move |_| remove_row(volume_rows, id)
                        >
                            <Icon name="close"/>
                            "Remove"
                        </button>
                    </label>
                }
            })
            .collect_view()
    };

    let label_rows_view = move || {
        label_rows
            .get()
            .into_iter()
            .map(|row| {
                let id = row.id;
                let remove_disabled = label_rows.get_untracked().len() <= 1;
                view! {
                    <label class="modal-inline">
                        <input
                            class="input"
                            type="text"
                            placeholder="Key"
                            prop:value=row.key
                            on:input=move |ev| {
                                let value = event_target_value(&ev);
                                label_rows.update(|rows| {
                                    if let Some(row) = rows.iter_mut().find(|row| row.id == id) {
                                        row.key = value;
                                    }
                                });
                            }
                        />
                        <input
                            class="input"
                            type="text"
                            placeholder="Value"
                            prop:value=row.value
                            on:input=move |ev| {
                                let value = event_target_value(&ev);
                                label_rows.update(|rows| {
                                    if let Some(row) = rows.iter_mut().find(|row| row.id == id) {
                                        row.value = value;
                                    }
                                });
                            }
                        />
                        <button
                            type="button"
                            class="btn btn--ghost"
                            prop:disabled=remove_disabled
                            on:click=move |_| remove_row(label_rows, id)
                        >
                            <Icon name="close"/>
                            "Remove"
                        </button>
                    </label>
                }
            })
            .collect_view()
    };

    view! {
        <Show when=move || open.get() fallback=|| view! { <></> }>
            <div class="modal-backdrop">
                <div class="modal-card modal-card-wide">
                    <div class="modal-header">"New container"</div>
                    <form class="modal-form" on:submit=submit>
                        <div class="field-group">
                            <label>
                                "Image"
                                <input
                                    class="input"
                                    type="text"
                                    placeholder="docker.io/library/nginx:latest"
                                    prop:value=move || image.get()
                                    on:input=move |ev| image.set(event_target_value(&ev))
                                />
                            </label>
                        </div>
                        <div class="field-group">
                            <label>
                                "Name"
                                <input
                                    class="input"
                                    type="text"
                                    placeholder="web"
                                    prop:value=move || name.get()
                                    on:input=move |ev| name.set(event_target_value(&ev))
                                />
                            </label>
                        </div>
                        <div class="field-group">
                            <label>
                                "Command"
                                <input
                                    class="input"
                                    type="text"
                                    placeholder="sleep infinity"
                                    prop:value=move || command.get()
                                    on:input=move |ev| command.set(event_target_value(&ev))
                                />
                            </label>
                        </div>
                        <div class="field-group">
                            <span class="label">"Ports"</span>
                            {port_rows_view}
                            <button type="button" class="btn" on:click=add_port>"Add port"</button>
                        </div>
                        <div class="field-group">
                            <span class="label">"Env"</span>
                            {env_rows_view}
                            <button type="button" class="btn" on:click=add_env>"Add env"</button>
                        </div>
                        <div class="field-group">
                            <span class="label">"Volumes"</span>
                            {volume_rows_view}
                            <button type="button" class="btn" on:click=add_volume>"Add volume"</button>
                        </div>
                        <div class="field-group">
                            <label>
                                "Network"
                                <select
                                    class="select"
                                    prop:value=move || network.get()
                                    on:change=move |ev| network.set(event_target_value(&ev))
                                >
                                    <option value="">"Default"</option>
                                    <option value="bridge">"bridge"</option>
                                    <option value="host">"host"</option>
                                    <option value="none">"none"</option>
                                </select>
                            </label>
                        </div>
                        <div class="field-group">
                            <span class="label">"Labels"</span>
                            {label_rows_view}
                            <button type="button" class="btn" on:click=add_label>"Add label"</button>
                        </div>
                        <div class="field-group">
                            <label>
                                "Restart policy"
                                <select
                                    class="select"
                                    prop:value=move || restart_policy.get()
                                    on:change=move |ev| restart_policy.set(event_target_value(&ev))
                                >
                                    <option value="no">"No"</option>
                                    <option value="unless-stopped">"Unless stopped"</option>
                                </select>
                            </label>
                        </div>
                        {move || {
                            error
                                .get()
                                .map(|msg| view! { <p class="modal-error">{msg}</p> })
                        }}
                        <div class="modal-actions">
                            <button
                                type="submit"
                                class="btn btn--primary"
                                prop:disabled=move || busy.get()
                            >
                                <Icon name="container"/>
                                {move || if busy.get() { "Creating..." } else { "Create" }}
                            </button>
                            <button type="button" class="btn" on:click=close>"Close"</button>
                        </div>
                    </form>
                </div>
            </div>
        </Show>
    }
}

fn take_next_id(next_id: RwSignal<u64>) -> u64 {
    let id = next_id.get_untracked();
    next_id.set(id.saturating_add(1));
    id
}

fn remove_row<T>(rows: RwSignal<Vec<T>>, id: u64)
where
    T: HasRowId + Send + Sync + 'static,
{
    rows.update(|rows| {
        if rows.len() > 1 {
            rows.retain(|row| row.row_id() != id);
        }
    });
}

trait HasRowId {
    fn row_id(&self) -> u64;
}

impl HasRowId for PortRow {
    fn row_id(&self) -> u64 {
        self.id
    }
}

impl HasRowId for TextRow {
    fn row_id(&self) -> u64 {
        self.id
    }
}

impl HasRowId for VolumeRow {
    fn row_id(&self) -> u64 {
        self.id
    }
}

impl HasRowId for PairRow {
    fn row_id(&self) -> u64 {
        self.id
    }
}

#[allow(clippy::too_many_arguments)]
fn build_create_body(
    image: &str,
    name: &str,
    command: &str,
    network: &str,
    restart_policy: &str,
    ports: &[PortRow],
    env: &[TextRow],
    volumes: &[VolumeRow],
    labels: &[PairRow],
) -> Result<Value, String> {
    let image = image.trim();
    if image.is_empty() {
        return Err("Image required".into());
    }

    let mut body = Map::new();
    body.insert("image".into(), Value::String(image.to_string()));
    body.insert("rm".into(), Value::Bool(false));
    body.insert("detach".into(), Value::Bool(true));
    body.insert(
        "auto_restart".into(),
        Value::Bool(restart_policy == "unless-stopped"),
    );

    let name = name.trim();
    if !name.is_empty() {
        body.insert("name".into(), Value::String(name.to_string()));
    }

    let command: Vec<Value> = command
        .split_whitespace()
        .map(|part| Value::String(part.to_string()))
        .collect();
    if !command.is_empty() {
        body.insert("command".into(), Value::Array(command));
    }

    let port_mappings = parse_ports(ports)?;
    if !port_mappings.is_empty() {
        body.insert("port_mappings".into(), Value::Array(port_mappings));
    }

    let env = parse_text_pairs(env, "env")?;
    if !env.is_empty() {
        body.insert("env".into(), Value::Array(env));
    }

    let volumes = parse_volumes(volumes)?;
    if !volumes.is_empty() {
        body.insert("volumes".into(), Value::Array(volumes));
    }

    let network = network.trim();
    if !network.is_empty() {
        body.insert(
            "networks".into(),
            Value::Array(vec![Value::String(network.to_string())]),
        );
    }

    let labels = parse_label_pairs(labels)?;
    if !labels.is_empty() {
        body.insert("labels".into(), Value::Array(labels));
    }

    Ok(Value::Object(body))
}

fn parse_ports(rows: &[PortRow]) -> Result<Vec<Value>, String> {
    let mut out = Vec::new();
    for row in rows {
        let host = row.host_port.trim();
        let container = row.container_port.trim();
        if host.is_empty() && container.is_empty() {
            continue;
        }
        if host.is_empty() || container.is_empty() {
            return Err("Port rows need both host and container ports".into());
        }
        let host_port = parse_u16(host, "host port")?;
        let container_port = parse_u16(container, "container port")?;
        out.push(json!({
            "host_port": host_port,
            "container_port": container_port,
            "protocol": row.protocol,
        }));
    }
    Ok(out)
}

fn parse_text_pairs(rows: &[TextRow], label: &str) -> Result<Vec<Value>, String> {
    let mut out = Vec::new();
    for row in rows {
        let raw = row.value.trim();
        if raw.is_empty() {
            continue;
        }
        let Some((key, value)) = raw.split_once('=') else {
            return Err(format!("{label} rows must use KEY=VALUE"));
        };
        let key = key.trim();
        if key.is_empty() {
            return Err(format!("{label} key is required"));
        }
        out.push(json!([key, value]));
    }
    Ok(out)
}

fn parse_volumes(rows: &[VolumeRow]) -> Result<Vec<Value>, String> {
    let mut out = Vec::new();
    for row in rows {
        let source = row.source.trim();
        let destination = row.destination.trim();
        if source.is_empty() && destination.is_empty() {
            continue;
        }
        if source.is_empty() || destination.is_empty() {
            return Err("Volume rows need both host and container paths".into());
        }
        out.push(json!({
            "source": source,
            "destination": destination,
            "read_only": row.read_only,
        }));
    }
    Ok(out)
}

fn parse_label_pairs(rows: &[PairRow]) -> Result<Vec<Value>, String> {
    let mut out = Vec::new();
    for row in rows {
        let key = row.key.trim();
        let value = row.value.trim();
        if key.is_empty() && value.is_empty() {
            continue;
        }
        if key.is_empty() {
            return Err("Label key is required".into());
        }
        out.push(json!([key, value]));
    }
    Ok(out)
}

fn parse_u16(raw: &str, label: &str) -> Result<u16, String> {
    raw.parse::<u16>()
        .map_err(|_| format!("{label} must be between 0 and 65535"))
}
