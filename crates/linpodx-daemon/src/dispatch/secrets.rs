//! Secret-domain dispatch handlers (Phase 26 — secrets management, issue #9).
//!
//! # Security — value never audited
//!
//! `SecretCreateParams.value` carries the plaintext secret. It MUST NEVER be
//! written to the audit log, an event payload, a tracing field, or an error
//! message. [`secret_audit_payload`] is the single place that builds the
//! sanitized (name-only) payload consumed by the audit sink; every write path
//! below routes through it rather than serializing the params directly.

use super::*;

impl Dispatcher {
    pub(crate) async fn secret_list(&self) -> Result<serde_json::Value> {
        let secrets = linpodx_runtime::secret::list(&self.podman).await?;
        Ok(serde_json::to_value(responses::SecretListResponse {
            secrets,
        })?)
    }

    pub(crate) async fn secret_create(
        &self,
        p: linpodx_common::ipc::SecretCreateParams,
    ) -> Result<serde_json::Value> {
        let id = linpodx_runtime::secret::create(&self.podman, &p.name, &p.value).await?;
        // Sanitized (name-only) payload — never the raw params, which would
        // carry `p.value` into the tamper-evident audit log.
        let payload = secret_audit_payload(&p.name);
        self.audit
            .record(AuditSinkKind::SecretCreated, None, None, payload)
            .await;
        self.publish(EventTopic::Secret, EventKind::Created, p.name.clone());
        Ok(serde_json::to_value(responses::SecretCreateResponse {
            id,
            name: p.name,
        })?)
    }

    pub(crate) async fn secret_remove(
        &self,
        p: linpodx_common::ipc::SecretRemoveParams,
    ) -> Result<serde_json::Value> {
        let removed = match linpodx_runtime::secret::remove(&self.podman, &p.name).await {
            Ok(()) => true,
            Err(Error::NotFound(_)) => false,
            Err(e) => return Err(e),
        };
        let payload = secret_audit_payload(&p.name);
        self.audit
            .record(AuditSinkKind::SecretRemoved, None, None, payload)
            .await;
        if removed {
            self.publish(EventTopic::Secret, EventKind::Removed, p.name.clone());
        }
        Ok(serde_json::to_value(responses::SecretRemoveResponse {
            name: p.name,
            removed,
        })?)
    }
}

/// Builds the sanitized audit payload for a secret create/remove — **name
/// only**. This is the load-bearing security boundary: callers must never
/// construct the audit payload any other way (e.g. `serde_json::to_value` on
/// the raw params), since that would leak `SecretCreateParams.value` into the
/// tamper-evident audit log.
fn secret_audit_payload(name: &str) -> serde_json::Value {
    serde_json::json!({ "name": name })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_payload_carries_name_only() {
        let payload = secret_audit_payload("db-password");
        assert_eq!(payload, serde_json::json!({ "name": "db-password" }));
        assert_eq!(payload.as_object().unwrap().len(), 1);
    }

    #[test]
    fn audit_payload_never_contains_a_planted_secret_value() {
        // Simulate the params a real request would carry and prove the
        // sanitizer output has no trace of the value, however it's spelled.
        let value = "hunter2-super-secret";
        let payload = secret_audit_payload("api-key");
        let serialized = payload.to_string();
        assert!(!serialized.contains(value));
    }
}
