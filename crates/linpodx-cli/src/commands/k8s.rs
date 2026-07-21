//! `linpodx k8s <...>` — Kubernetes operations (read-only list in Phase 10,
//! write-side in Phase 13).
#![forbid(unsafe_code)]

use crate::client::Client;
use crate::output::OutputFormat;
use crate::output::{
    print_k8s_deployment_scaled, print_k8s_namespace_created, print_k8s_pod_created,
    print_k8s_pod_deleted,
};
use anyhow::{Context, Result};
use clap::Subcommand;
use linpodx_common::ipc::{
    K8sDeploymentScaleParams, K8sNamespaceCreateParams, K8sPodCreateParams, K8sPodDeleteParams,
    Method,
};
use std::path::{Path, PathBuf};

#[derive(Subcommand, Debug)]
pub(crate) enum K8sCmd {
    /// Pod operations.
    #[command(subcommand)]
    Pod(K8sPodCmd),
    /// Namespace operations.
    #[command(subcommand)]
    Ns(K8sNsCmd),
    /// Scale a deployment to N replicas.
    Scale {
        /// Deployment name.
        deployment: String,
        /// Namespace. Defaults to `default`.
        #[arg(short = 'n', long, default_value = "default")]
        namespace: String,
        /// New replica count.
        #[arg(long)]
        replicas: i32,
    },
}

#[derive(Subcommand, Debug)]
pub(crate) enum K8sPodCmd {
    /// Submit a pod manifest YAML to the cluster.
    Create {
        /// Path to a pod-spec YAML file (use `-` to read from stdin).
        yaml: PathBuf,
        /// Namespace. Defaults to `default`.
        #[arg(short = 'n', long, default_value = "default")]
        namespace: String,
    },
    /// Delete a pod by name.
    Delete {
        /// Pod name.
        name: String,
        /// Namespace. Defaults to `default`.
        #[arg(short = 'n', long, default_value = "default")]
        namespace: String,
    },
}

#[derive(Subcommand, Debug)]
pub(crate) enum K8sNsCmd {
    /// Create a namespace.
    Create {
        /// Namespace name.
        name: String,
    },
}

pub(crate) async fn handle_k8s(client: &mut Client, fmt: OutputFormat, cmd: K8sCmd) -> Result<()> {
    use linpodx_common::ipc::responses::{
        K8sDeploymentScaleResponse, K8sNamespaceCreateResponse, K8sPodCreateResponse,
        K8sPodDeleteResponse,
    };
    match cmd {
        K8sCmd::Pod(K8sPodCmd::Create { yaml, namespace }) => {
            let pod_spec_yaml = read_yaml_input(&yaml)?;
            let resp: K8sPodCreateResponse = client
                .call(Method::K8sPodCreate(K8sPodCreateParams {
                    namespace,
                    pod_spec_yaml,
                }))
                .await?;
            print_k8s_pod_created(&resp, fmt)?;
        }
        K8sCmd::Pod(K8sPodCmd::Delete { name, namespace }) => {
            let resp: K8sPodDeleteResponse = client
                .call(Method::K8sPodDelete(K8sPodDeleteParams { namespace, name }))
                .await?;
            print_k8s_pod_deleted(&resp, fmt)?;
        }
        K8sCmd::Ns(K8sNsCmd::Create { name }) => {
            let resp: K8sNamespaceCreateResponse = client
                .call(Method::K8sNamespaceCreate(K8sNamespaceCreateParams {
                    name,
                }))
                .await?;
            print_k8s_namespace_created(&resp, fmt)?;
        }
        K8sCmd::Scale {
            deployment,
            namespace,
            replicas,
        } => {
            let resp: K8sDeploymentScaleResponse = client
                .call(Method::K8sDeploymentScale(K8sDeploymentScaleParams {
                    namespace,
                    name: deployment,
                    replicas,
                }))
                .await?;
            print_k8s_deployment_scaled(&resp, fmt)?;
        }
    }
    Ok(())
}

/// Read a pod-spec YAML payload from `path`, or from stdin when the path is `-`.
fn read_yaml_input(path: &Path) -> Result<String> {
    use std::io::Read;
    if path.as_os_str() == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("read pod spec yaml from stdin")?;
        Ok(buf)
    } else {
        std::fs::read_to_string(path)
            .with_context(|| format!("read pod spec yaml from '{}'", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cli, Cmd};
    use clap::Parser;

    #[test]
    fn parse_k8s_pod_create_with_namespace() {
        let cli = Cli::parse_from([
            "linpodx",
            "k8s",
            "pod",
            "create",
            "/tmp/pod.yaml",
            "-n",
            "ci",
        ]);
        match cli.cmd {
            Cmd::K8s(K8sCmd::Pod(K8sPodCmd::Create { yaml, namespace })) => {
                assert_eq!(yaml, PathBuf::from("/tmp/pod.yaml"));
                assert_eq!(namespace, "ci");
            }
            other => panic!("expected K8s Pod Create subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_k8s_pod_delete_default_namespace() {
        let cli = Cli::parse_from(["linpodx", "k8s", "pod", "delete", "hello"]);
        match cli.cmd {
            Cmd::K8s(K8sCmd::Pod(K8sPodCmd::Delete { name, namespace })) => {
                assert_eq!(name, "hello");
                assert_eq!(namespace, "default");
            }
            other => panic!("expected K8s Pod Delete subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_k8s_namespace_create() {
        let cli = Cli::parse_from(["linpodx", "k8s", "ns", "create", "my-ns"]);
        match cli.cmd {
            Cmd::K8s(K8sCmd::Ns(K8sNsCmd::Create { name })) => {
                assert_eq!(name, "my-ns");
            }
            other => panic!("expected K8s Ns Create subcommand, got {other:?}"),
        }
    }

    #[test]
    fn parse_k8s_scale_with_replicas() {
        let cli = Cli::parse_from([
            "linpodx",
            "k8s",
            "scale",
            "web",
            "--replicas",
            "3",
            "-n",
            "prod",
        ]);
        match cli.cmd {
            Cmd::K8s(K8sCmd::Scale {
                deployment,
                namespace,
                replicas,
            }) => {
                assert_eq!(deployment, "web");
                assert_eq!(namespace, "prod");
                assert_eq!(replicas, 3);
            }
            other => panic!("expected K8s Scale subcommand, got {other:?}"),
        }
    }
}
