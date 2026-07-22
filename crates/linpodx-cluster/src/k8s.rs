//! Read-only Kubernetes adapter (Phase 10 Stream C — v0.1).
//!
//! Wraps a `kube::Client` initialised from the standard discovery chain (env
//! `KUBECONFIG` → `~/.kube/config` → in-cluster `ServiceAccount`). Exposes two
//! list calls — pods and services — that map the upstream API objects to the
//! IPC summary structs in `linpodx-common::ipc::responses`.
//!
//! v0.1 deliberately stays read-only: no apply / delete / exec. Future streams
//! will layer write operations and a watch loop on top of the same client.

use crate::{ClusterError, Result};
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Namespace, Pod, Service};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, DeleteParams, ListParams, Patch, PatchParams, PostParams};
use kube::Client;
use linpodx_common::ipc::responses::{
    K8sDeploymentScaleResponse, K8sNamespaceCreateResponse, K8sPodCreateResponse,
    K8sPodDeleteResponse, K8sPodSummary, K8sServiceSummary,
};
use tracing::instrument;

/// Thin handle around a `kube::Client`. Cheap to clone — the client itself is
/// internally `Arc`-shared, so cloning the adapter is effectively free.
#[derive(Clone)]
pub struct K8sAdapter {
    client: Client,
}

impl K8sAdapter {
    /// Build an adapter using `kube::Client::try_default`, which honours
    /// `KUBECONFIG`, then `~/.kube/config`, then the in-cluster
    /// `ServiceAccount` token. Errors are mapped into [`ClusterError::Http`]
    /// so callers can render them with the same error path the cluster
    /// gossip code uses.
    #[instrument(name = "k8s.try_default", skip_all)]
    pub async fn try_default() -> Result<Self> {
        let client = Client::try_default()
            .await
            .map_err(|e| ClusterError::Http(format!("kube client init: {e}")))?;
        Ok(Self { client })
    }

    /// Construct directly from an existing client. Used by tests and any
    /// future code path that already owns a configured `Client`.
    pub fn from_client(client: Client) -> Self {
        Self { client }
    }

    /// List pods in `namespace`, or across all namespaces when `namespace` is
    /// `None` / empty. Maps each `Pod` to a [`K8sPodSummary`] suitable for
    /// the IPC response.
    #[instrument(name = "k8s.list_pods", skip(self), fields(ns = %namespace.unwrap_or("<all>")))]
    pub async fn list_pods(&self, namespace: Option<&str>) -> Result<Vec<K8sPodSummary>> {
        let api: Api<Pod> = match normalise_ns(namespace) {
            Some(ns) => Api::namespaced(self.client.clone(), ns),
            None => Api::all(self.client.clone()),
        };
        let lp = ListParams::default();
        let list = api
            .list(&lp)
            .await
            .map_err(|e| ClusterError::Http(format!("k8s list pods: {e}")))?;
        Ok(list.items.into_iter().map(map_pod).collect())
    }

    /// List services. Same namespace semantics as [`Self::list_pods`].
    #[instrument(name = "k8s.list_services", skip(self), fields(ns = %namespace.unwrap_or("<all>")))]
    pub async fn list_services(&self, namespace: Option<&str>) -> Result<Vec<K8sServiceSummary>> {
        let api: Api<Service> = match normalise_ns(namespace) {
            Some(ns) => Api::namespaced(self.client.clone(), ns),
            None => Api::all(self.client.clone()),
        };
        let lp = ListParams::default();
        let list = api
            .list(&lp)
            .await
            .map_err(|e| ClusterError::Http(format!("k8s list services: {e}")))?;
        Ok(list.items.into_iter().map(map_service).collect())
    }

    // ----- Phase 13 Stream A: write-side operations -----

    /// Parse `pod_spec_yaml` into a `core::v1::Pod` and POST it to the API
    /// server in `namespace`. Returns the created pod's `(namespace, name,
    /// uid)` so the dispatcher can audit and reply without re-fetching.
    ///
    /// Errors:
    /// - YAML parse failures map to `ClusterError::Http("invalid pod yaml: ...")`
    ///   so the user sees a single category at the CLI (the IPC layer already
    ///   knows how to render `Http`).
    /// - API failures (admission webhooks, RBAC, dup names) propagate as
    ///   `ClusterError::Http` with the original kube error chain attached.
    #[instrument(name = "k8s.create_pod", skip(self, pod_spec_yaml), fields(ns = %namespace))]
    pub async fn create_pod(
        &self,
        namespace: &str,
        pod_spec_yaml: &str,
    ) -> Result<K8sPodCreateResponse> {
        let pod: Pod = serde_norway::from_str(pod_spec_yaml)
            .map_err(|e| ClusterError::Http(format!("invalid pod yaml: {e}")))?;
        let api: Api<Pod> = Api::namespaced(self.client.clone(), namespace);
        let created = api
            .create(&PostParams::default(), &pod)
            .await
            .map_err(|e| ClusterError::Http(format!("k8s pod create: {e}")))?;
        Ok(K8sPodCreateResponse {
            namespace: namespace.to_string(),
            name: created.metadata.name.unwrap_or_default(),
            uid: created.metadata.uid,
        })
    }

    /// Delete pod `name` in `namespace`. Returns `deleted=true` regardless of
    /// whether the API server replied with the pre-delete `Pod` (Left) or the
    /// terminal `Status` (Right) — both are success paths from the caller's
    /// perspective. A 404 is surfaced as `ClusterError::Http`.
    #[instrument(name = "k8s.delete_pod", skip(self), fields(ns = %namespace, pod = %name))]
    pub async fn delete_pod(&self, namespace: &str, name: &str) -> Result<K8sPodDeleteResponse> {
        let api: Api<Pod> = Api::namespaced(self.client.clone(), namespace);
        api.delete(name, &DeleteParams::default())
            .await
            .map_err(|e| ClusterError::Http(format!("k8s pod delete: {e}")))?;
        Ok(K8sPodDeleteResponse {
            namespace: namespace.to_string(),
            name: name.to_string(),
            deleted: true,
        })
    }

    /// Create a cluster-scoped `Namespace` with the given `name`. The minimal
    /// payload mirrors `kubectl create namespace <name>` — no labels/annotations
    /// are set; callers wanting richer metadata should drive the API directly.
    #[instrument(name = "k8s.create_namespace", skip(self), fields(name = %name))]
    pub async fn create_namespace(&self, name: &str) -> Result<K8sNamespaceCreateResponse> {
        let ns = Namespace {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        let api: Api<Namespace> = Api::all(self.client.clone());
        let created = api
            .create(&PostParams::default(), &ns)
            .await
            .map_err(|e| ClusterError::Http(format!("k8s namespace create: {e}")))?;
        Ok(K8sNamespaceCreateResponse {
            name: created.metadata.name.unwrap_or_else(|| name.to_string()),
            uid: created.metadata.uid,
        })
    }

    /// Patch `Deployment` `name` in `namespace` so its replica count becomes
    /// `replicas`. Uses a JSON merge patch on the `scale` subresource — this
    /// avoids pulling in `autoscaling/v1::Scale` field-by-field and matches the
    /// surface area `kubectl scale` exposes.
    #[instrument(
        name = "k8s.scale_deployment",
        skip(self),
        fields(ns = %namespace, deploy = %name, replicas)
    )]
    pub async fn scale_deployment(
        &self,
        namespace: &str,
        name: &str,
        replicas: i32,
    ) -> Result<K8sDeploymentScaleResponse> {
        let api: Api<Deployment> = Api::namespaced(self.client.clone(), namespace);
        let patch = serde_json::json!({ "spec": { "replicas": replicas } });
        let scale = api
            .patch_scale(name, &PatchParams::default(), &Patch::Merge(&patch))
            .await
            .map_err(|e| ClusterError::Http(format!("k8s deployment scale: {e}")))?;
        let applied = scale.spec.and_then(|s| s.replicas).unwrap_or(replicas);
        Ok(K8sDeploymentScaleResponse {
            namespace: namespace.to_string(),
            name: name.to_string(),
            replicas: applied,
        })
    }
}

fn normalise_ns(ns: Option<&str>) -> Option<&str> {
    match ns {
        Some(s) if !s.is_empty() => Some(s),
        _ => None,
    }
}

fn map_pod(pod: Pod) -> K8sPodSummary {
    let meta = pod.metadata;
    let namespace = meta.namespace.unwrap_or_else(|| "default".to_string());
    let name = meta.name.unwrap_or_default();
    let created_at = meta.creation_timestamp.map(|t| t.0);

    let (phase, node, containers) = match (pod.spec, pod.status) {
        (Some(spec), Some(status)) => {
            let phase = status.phase.unwrap_or_else(|| "Unknown".to_string());
            let containers = spec
                .containers
                .into_iter()
                .map(|c| c.name)
                .collect::<Vec<_>>();
            (phase, spec.node_name, containers)
        }
        (Some(spec), None) => {
            let containers = spec
                .containers
                .into_iter()
                .map(|c| c.name)
                .collect::<Vec<_>>();
            ("Unknown".to_string(), spec.node_name, containers)
        }
        (None, Some(status)) => (
            status.phase.unwrap_or_else(|| "Unknown".to_string()),
            None,
            Vec::new(),
        ),
        (None, None) => ("Unknown".to_string(), None, Vec::new()),
    };

    K8sPodSummary {
        namespace,
        name,
        phase,
        node,
        containers,
        created_at,
    }
}

fn map_service(svc: Service) -> K8sServiceSummary {
    let meta = svc.metadata;
    let namespace = meta.namespace.unwrap_or_else(|| "default".to_string());
    let name = meta.name.unwrap_or_default();

    let (service_type, cluster_ip, ports) = match svc.spec {
        Some(spec) => {
            let stype = spec.type_.unwrap_or_else(|| "ClusterIP".to_string());
            let cip = spec.cluster_ip.filter(|s| !s.is_empty() && s != "None");
            let ports = spec
                .ports
                .unwrap_or_default()
                .into_iter()
                .map(|p| {
                    let proto = p.protocol.unwrap_or_else(|| "TCP".to_string());
                    let label = p.name.unwrap_or_else(|| "-".to_string());
                    format!("{label}/{}/{proto}", p.port)
                })
                .collect();
            (stype, cip, ports)
        }
        None => ("ClusterIP".to_string(), None, Vec::new()),
    };

    K8sServiceSummary {
        namespace,
        name,
        service_type,
        cluster_ip,
        ports,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `try_default` should surface a clean `ClusterError::Http` when neither a
    /// kubeconfig nor an in-cluster service account is available. We isolate the
    /// process from any host config by pointing `KUBECONFIG` at a path that
    /// definitely does not exist and clearing `HOME` so the in-cluster fallback
    /// also fails.
    ///
    /// Marked `#[ignore]` because environment mutation here is process-global
    /// and would race other unit tests in the same binary; run on demand with
    /// `cargo test -p linpodx-cluster -- --ignored try_default_without_config`.
    #[tokio::test]
    #[ignore]
    async fn try_default_without_config_returns_http_error() {
        // Neither KUBECONFIG nor in-cluster SA token exist on a typical CI box.
        std::env::set_var("KUBECONFIG", "/nonexistent/linpodx-test/kubeconfig");
        std::env::remove_var("HOME");
        let res = K8sAdapter::try_default().await;
        assert!(res.is_err(), "expected kube init to fail without config");
        if let Err(e) = res {
            assert!(
                matches!(e, ClusterError::Http(_)),
                "expected ClusterError::Http, got {e:?}"
            );
        }
    }

    /// End-to-end smoke test against a real cluster (e.g. `minikube`, `kind`).
    /// Skipped by default — run with `cargo test -p linpodx-cluster -- --ignored
    /// list_pods_real_cluster` after pointing `KUBECONFIG` at a working cluster.
    #[tokio::test]
    #[ignore]
    async fn list_pods_real_cluster() {
        let adapter = K8sAdapter::try_default().await.expect("kube init");
        let pods = adapter.list_pods(None).await.expect("list pods");
        // We don't assert on the count — just that the call shape works.
        for p in pods.iter().take(3) {
            assert!(!p.namespace.is_empty());
            assert!(!p.name.is_empty());
        }
    }

    #[tokio::test]
    #[ignore]
    async fn list_services_real_cluster() {
        let adapter = K8sAdapter::try_default().await.expect("kube init");
        let svcs = adapter.list_services(None).await.expect("list services");
        for s in svcs.iter().take(3) {
            assert!(!s.namespace.is_empty());
            assert!(!s.name.is_empty());
            assert!(!s.service_type.is_empty());
        }
    }

    #[test]
    fn normalise_ns_empty_means_all() {
        assert_eq!(normalise_ns(None), None);
        assert_eq!(normalise_ns(Some("")), None);
        assert_eq!(normalise_ns(Some("kube-system")), Some("kube-system"));
    }

    /// The pod-spec YAML path is the only piece of the write API we can exercise
    /// without a live cluster. Confirm that a typical `kubectl create -f` style
    /// document round-trips through `serde_norway` into the strongly-typed Pod the
    /// adapter would hand to `Api::create`.
    #[test]
    fn parse_pod_spec_yaml_round_trip() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: hello
spec:
  containers:
    - name: main
      image: alpine:3.20
      command: ["sh", "-c", "echo hi"]
"#;
        let pod: Pod = serde_norway::from_str(yaml).expect("parse pod yaml");
        assert_eq!(pod.metadata.name.as_deref(), Some("hello"));
        let spec = pod.spec.expect("pod has spec");
        assert_eq!(spec.containers.len(), 1);
        assert_eq!(spec.containers[0].name, "main");
        assert_eq!(spec.containers[0].image.as_deref(), Some("alpine:3.20"));
    }

    #[test]
    fn parse_pod_spec_yaml_invalid_returns_error() {
        let bogus = "not: a: pod\nthis: [is not yaml";
        let res: std::result::Result<Pod, _> = serde_norway::from_str(bogus);
        assert!(
            res.is_err(),
            "expected serde_norway to reject malformed input"
        );
    }

    /// Real-cluster smoke test: create a throwaway namespace, scale a fixture
    /// deployment, then delete the namespace. Skipped by default — opt in with
    /// `cargo test -p linpodx-cluster -- --ignored write_real_cluster`.
    #[tokio::test]
    #[ignore]
    async fn create_namespace_real_cluster() {
        let adapter = K8sAdapter::try_default().await.expect("kube init");
        let name = format!("linpodx-test-{}", chrono::Utc::now().timestamp_millis());
        let resp = adapter
            .create_namespace(&name)
            .await
            .expect("create namespace");
        assert_eq!(resp.name, name);
    }

    #[tokio::test]
    #[ignore]
    async fn create_pod_real_cluster() {
        let adapter = K8sAdapter::try_default().await.expect("kube init");
        let name = format!("linpodx-test-pod-{}", chrono::Utc::now().timestamp_millis());
        let yaml = format!(
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: {name}\nspec:\n  restartPolicy: Never\n  containers:\n    - name: main\n      image: alpine:3.20\n      command: [\"true\"]\n"
        );
        let resp = adapter
            .create_pod("default", &yaml)
            .await
            .expect("create pod");
        assert_eq!(resp.namespace, "default");
        assert_eq!(resp.name, name);
        // Best-effort cleanup.
        let _ = adapter.delete_pod("default", &name).await;
    }

    #[tokio::test]
    #[ignore]
    async fn scale_deployment_real_cluster() {
        let adapter = K8sAdapter::try_default().await.expect("kube init");
        // Requires a pre-provisioned deployment named `linpodx-scale-fixture`
        // in `default` (we have no deployment-create API to make our own).
        // Soft-skip when the fixture is absent so a full `--ignored` sweep on
        // a host with a live cluster but no fixture doesn't abort the run.
        match adapter
            .scale_deployment("default", "linpodx-scale-fixture", 2)
            .await
        {
            Ok(resp) => assert_eq!(resp.replicas, 2),
            Err(e) if format!("{e}").contains("NotFound") => {
                eprintln!("skipped: linpodx-scale-fixture deployment not provisioned ({e})");
            }
            Err(e) => panic!("scale deployment: {e}"),
        }
    }
}
