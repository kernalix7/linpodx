//! Multi-distro provisioning dispatch handlers — thin bridges into
//! `linpodx_distro::dispatch` via [`super::Dispatcher::run_distro`].

use super::*;

impl Dispatcher {
    pub(crate) async fn distro_template_list(&self) -> Result<serde_json::Value> {
        self.run_distro(DistroAction::TemplateList).await
    }

    pub(crate) async fn distro_template_inspect(
        &self,
        p: linpodx_common::ipc::DistroTemplateInspectParams,
    ) -> Result<serde_json::Value> {
        self.run_distro(DistroAction::TemplateInspect(p)).await
    }

    pub(crate) async fn distro_create(
        &self,
        p: linpodx_common::ipc::DistroCreateParams,
    ) -> Result<serde_json::Value> {
        self.run_distro(DistroAction::Create(p)).await
    }

    pub(crate) async fn distro_build(
        &self,
        p: linpodx_common::ipc::DistroBuildParams,
    ) -> Result<serde_json::Value> {
        self.run_distro(DistroAction::Build(p)).await
    }

    pub(crate) async fn distro_enter(
        &self,
        p: linpodx_common::ipc::DistroEnterParams,
    ) -> Result<serde_json::Value> {
        self.run_distro(DistroAction::Enter(p)).await
    }

    pub(crate) async fn distro_remove(
        &self,
        p: linpodx_common::ipc::DistroRemoveParams,
    ) -> Result<serde_json::Value> {
        self.run_distro(DistroAction::Remove(p)).await
    }
}
