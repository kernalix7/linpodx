use crate::podman::Podman;
use linpodx_common::error::{Error, Result};
use linpodx_common::ipc::responses::{PodActionResponse, PodCreateResponse, PodSummary};
use linpodx_common::ipc::{PodActionParams, PodCreateParams, PodRemoveParams};
use serde_json::Value;
use std::collections::HashMap;
use tracing::{instrument, warn};

const DOCKER_COMPOSE_PROJECT_LABEL: &str = "com.docker.compose.project";
const PODMAN_COMPOSE_PROJECT_LABEL: &str = "io.podman.compose.project";

#[instrument(skip(podman))]
pub async fn pod_list(podman: &Podman) -> Result<Vec<PodSummary>> {
    let mut cmd = podman.base_command();
    cmd.arg("pod").arg("ps").arg("--format").arg("json");
    let out = podman.run_capture(cmd).await?;
    parse_pod_list(&out)
}

#[instrument(skip(podman, params), fields(name = %params.name))]
pub async fn pod_create(podman: &Podman, params: &PodCreateParams) -> Result<PodCreateResponse> {
    if params.name.trim().is_empty() {
        return Err(Error::InvalidArgument("pod name must not be empty".into()));
    }

    let mut cmd = podman.base_command();
    cmd.arg("pod").arg("create").arg("--name").arg(&params.name);
    for port in &params.ports {
        cmd.arg("--publish").arg(port.to_publish_arg());
    }
    for (key, value) in &params.labels {
        cmd.arg("--label").arg(format!("{key}={value}"));
    }

    let out = podman.run_capture(cmd).await?;
    let id = out.trim().to_string();
    if id.is_empty() {
        return Err(Error::Runtime {
            message: "podman pod create returned empty id".into(),
        });
    }

    Ok(PodCreateResponse {
        id,
        name: params.name.clone(),
    })
}

#[instrument(skip(podman), fields(id_or_name = %params.id_or_name))]
pub async fn pod_start(podman: &Podman, params: &PodActionParams) -> Result<PodActionResponse> {
    let mut cmd = podman.base_command();
    cmd.arg("pod").arg("start").arg(&params.id_or_name);
    podman
        .run_capture(cmd)
        .await
        .map_err(|e| map_pod_not_found(e, &params.id_or_name))?;
    pod_status_response(podman, &params.id_or_name, "Running").await
}

#[instrument(skip(podman), fields(id_or_name = %params.id_or_name))]
pub async fn pod_stop(podman: &Podman, params: &PodActionParams) -> Result<PodActionResponse> {
    let mut cmd = podman.base_command();
    cmd.arg("pod").arg("stop").arg(&params.id_or_name);
    podman
        .run_capture(cmd)
        .await
        .map_err(|e| map_pod_not_found(e, &params.id_or_name))?;
    pod_status_response(podman, &params.id_or_name, "Stopped").await
}

#[instrument(skip(podman), fields(id_or_name = %params.id_or_name, force = params.force))]
pub async fn pod_remove(podman: &Podman, params: &PodRemoveParams) -> Result<PodActionResponse> {
    let mut cmd = podman.base_command();
    cmd.arg("pod").arg("rm");
    if params.force {
        cmd.arg("--force");
    }
    cmd.arg(&params.id_or_name);
    let out = podman
        .run_capture(cmd)
        .await
        .map_err(|e| map_pod_not_found(e, &params.id_or_name))?;
    let id = out
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or(&params.id_or_name)
        .to_string();
    Ok(PodActionResponse {
        id,
        status: "Removed".to_string(),
    })
}

async fn pod_status_response(
    podman: &Podman,
    id_or_name: &str,
    fallback_status: &str,
) -> Result<PodActionResponse> {
    match pod_list(podman).await {
        Ok(pods) => pods
            .into_iter()
            .find(|pod| pod_matches(pod, id_or_name))
            .map(|pod| PodActionResponse {
                id: pod.id,
                status: pod.status,
            })
            .ok_or_else(|| Error::NotFound(id_or_name.to_string())),
        Err(err) => {
            warn!(
                error = %err,
                id_or_name,
                "pod status refresh failed after successful pod action"
            );
            Ok(PodActionResponse {
                id: id_or_name.to_string(),
                status: fallback_status.to_string(),
            })
        }
    }
}

fn pod_matches(pod: &PodSummary, id_or_name: &str) -> bool {
    pod.id == id_or_name || pod.id.starts_with(id_or_name) || pod.name == id_or_name
}

fn parse_pod_list(json: &str) -> Result<Vec<PodSummary>> {
    let value: Value = serde_json::from_str(json)?;
    let arr = value.as_array().ok_or_else(|| Error::Runtime {
        message: "podman pod ps did not return an array".into(),
    })?;
    arr.iter().map(parse_pod_summary).collect()
}

fn parse_pod_summary(v: &Value) -> Result<PodSummary> {
    let id = string_field(v, &["Id", "ID", "id"]).ok_or_else(|| Error::Runtime {
        message: "pod missing Id".into(),
    })?;
    let name = string_field(v, &["Name", "name"]).ok_or_else(|| Error::Runtime {
        message: "pod missing Name".into(),
    })?;
    let status = string_field(v, &["Status", "State", "status", "state"]).unwrap_or_default();
    let created = created_rfc3339(v.get("Created").or_else(|| v.get("CreatedAt")))?;
    let mut labels = string_map(v.get("Labels").or_else(|| v.get("labels")));
    if !labels.contains_key(DOCKER_COMPOSE_PROJECT_LABEL)
        && !labels.contains_key(PODMAN_COMPOSE_PROJECT_LABEL)
    {
        if let Some((key, value)) = stack_label_from_container_rows(v) {
            labels.insert(key.to_string(), value);
        }
    }
    let num_containers = v
        .get("NumContainers")
        .or_else(|| v.get("NumberOfContainers"))
        .or_else(|| v.get("num_containers"))
        .and_then(Value::as_u64)
        .or_else(|| {
            v.get("Containers")
                .and_then(Value::as_array)
                .map(|containers| containers.len() as u64)
        })
        .unwrap_or(0) as u32;
    let infra_id = string_field(
        v,
        &[
            "InfraId",
            "InfraID",
            "InfraContainerID",
            "infra_id",
            "infraId",
        ],
    )
    .filter(|s| !s.is_empty());

    Ok(PodSummary {
        id,
        name,
        status,
        created,
        num_containers,
        infra_id,
        labels,
    })
}

fn stack_label_from_container_rows(v: &Value) -> Option<(&'static str, String)> {
    let containers = v.get("Containers").and_then(Value::as_array)?;
    for key in [DOCKER_COMPOSE_PROJECT_LABEL, PODMAN_COMPOSE_PROJECT_LABEL] {
        if let Some(value) = containers
            .iter()
            .filter_map(|container| {
                container
                    .get("Labels")
                    .or_else(|| container.get("labels"))
                    .and_then(|labels| labels.get(key))
                    .and_then(Value::as_str)
            })
            .find(|value| !value.is_empty())
        {
            return Some((key, value.to_string()));
        }
    }
    None
}

fn string_field(v: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| v.get(*key).and_then(Value::as_str))
        .map(ToString::to_string)
}

fn string_map(v: Option<&Value>) -> HashMap<String, String> {
    v.and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(key, value)| {
                    value.as_str().map(|value| (key.clone(), value.to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn created_rfc3339(v: Option<&Value>) -> Result<String> {
    match v {
        Some(Value::String(s)) => chrono::DateTime::parse_from_rfc3339(s)
            .map(|dt| dt.with_timezone(&chrono::Utc).to_rfc3339())
            .map_err(|e| Error::Runtime {
                message: format!("invalid pod created timestamp '{s}': {e}"),
            }),
        Some(Value::Number(n)) => {
            let secs = n.as_i64().ok_or_else(|| Error::Runtime {
                message: format!("pod created field is non-integer number: {n}"),
            })?;
            chrono::DateTime::from_timestamp(secs, 0)
                .map(|dt| dt.to_rfc3339())
                .ok_or_else(|| Error::Runtime {
                    message: format!("invalid pod unix timestamp {secs}"),
                })
        }
        _ => Ok(chrono::Utc::now().to_rfc3339()),
    }
}

fn map_pod_not_found(err: Error, what: &str) -> Error {
    if let Error::Runtime { message } = &err {
        let lower = message.to_lowercase();
        if lower.contains("no such pod")
            || lower.contains("pod not known")
            || lower.contains("no pod with id")
            || lower.contains("no pod with name")
            || lower.contains("unable to find pod")
            || lower.contains("does not exist in local storage")
        {
            return Error::NotFound(what.to_string());
        }
    }
    err
}

#[cfg(test)]
mod tests {
    use super::*;

    const FALLBACK_POD_PS_JSON: &str = r#"[
  {
    "Cgroup": "user.slice",
    "Containers": [
      {
        "Id": "f0b58f3be8e4",
        "Names": "linpodx-pod-fixture-infra",
        "Status": "running"
      }
    ],
    "Created": "2026-07-22T16:52:18.123456789+09:00",
    "Id": "6a4e1db9f6a0d4c322b92eec82a28b72bfcd851de3b969bc6fb7c1ef7a6a9e67",
    "InfraId": "f0b58f3be8e4b20d8f7683f1692c942cc0ab3ac5f63325b6689341d258dc1567",
    "Labels": {
      "com.docker.compose.project": "linpodx-fixture",
      "io.podman.compose.project": "shadowed"
    },
    "Name": "linpodx-pod-fixture",
    "Namespace": "",
    "Networks": [
      "podman"
    ],
    "Status": "Running"
  }
]"#;

    #[test]
    fn parses_pod_ps_json_fixture() {
        let pods = parse_pod_list(FALLBACK_POD_PS_JSON).expect("fixture parses");

        assert_eq!(pods.len(), 1);
        assert_eq!(
            pods[0].id,
            "6a4e1db9f6a0d4c322b92eec82a28b72bfcd851de3b969bc6fb7c1ef7a6a9e67"
        );
        assert_eq!(pods[0].name, "linpodx-pod-fixture");
        assert_eq!(pods[0].status, "Running");
        assert_eq!(pods[0].created, "2026-07-22T07:52:18.123456789+00:00");
        assert_eq!(pods[0].num_containers, 1);
        assert_eq!(
            pods[0].infra_id.as_deref(),
            Some("f0b58f3be8e4b20d8f7683f1692c942cc0ab3ac5f63325b6689341d258dc1567")
        );
        assert_eq!(
            pods[0].labels.get(DOCKER_COMPOSE_PROJECT_LABEL),
            Some(&"linpodx-fixture".to_string())
        );
        assert_eq!(
            pods[0].labels.get(PODMAN_COMPOSE_PROJECT_LABEL),
            Some(&"shadowed".to_string())
        );
    }

    #[test]
    fn parses_numeric_created_and_num_containers_field() {
        let pods = parse_pod_list(
            r#"[{"Id":"abc","Name":"demo","State":"Created","Created":1780000000,"NumContainers":2}]"#,
        )
        .expect("fixture parses");

        assert_eq!(pods[0].status, "Created");
        assert_eq!(pods[0].created, "2026-05-28T20:26:40+00:00");
        assert_eq!(pods[0].num_containers, 2);
        assert!(pods[0].labels.is_empty());
    }

    #[test]
    fn prefers_docker_compose_stack_label_from_container_rows() {
        let pods = parse_pod_list(
            r#"[{
                "Id":"abc",
                "Name":"demo",
                "Status":"Running",
                "Created":"2026-07-22T00:00:00Z",
                "Containers":[
                    {"Labels":{"io.podman.compose.project":"podman-stack"}},
                    {"Labels":{"com.docker.compose.project":"docker-stack"}}
                ]
            }]"#,
        )
        .expect("fixture parses");

        assert_eq!(
            pods[0].labels.get(DOCKER_COMPOSE_PROJECT_LABEL),
            Some(&"docker-stack".to_string())
        );
        assert!(!pods[0].labels.contains_key(PODMAN_COMPOSE_PROJECT_LABEL));
    }
}
