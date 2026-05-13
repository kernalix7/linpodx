//! Phase 2E MCP per-method policy store.
//!
//! Persists `McpPolicyRule` rows in the `mcp_policies` SQLite table (migration 0009)
//! and emits `McpPolicyChanged` audit entries on every write. The daemon loads the table
//! into the in-memory `linpodx_mcp::PolicyStore` at boot and re-syncs after each
//! `mcp_policy_set` IPC call.

use crate::audit::{self, AuditKind};
use linpodx_common::audit_sink::{AuditSink, AuditSinkKind};
use linpodx_common::db::Database;
use linpodx_common::error::{Error, Result};
use linpodx_common::ipc::{McpPolicyDecision, McpPolicyRule};
use std::sync::Arc;
use tracing::instrument;

pub struct McpPolicyStore {
    db: Arc<Database>,
}

impl McpPolicyStore {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Read every rule. Used at daemon boot to seed the in-memory `PolicyStore`.
    #[instrument(skip(self))]
    pub async fn load_all(&self) -> Result<Vec<McpPolicyRule>> {
        let rows: Vec<PolicyRow> = sqlx::query_as::<_, PolicyRow>(
            "SELECT method, tool_name, decision, note FROM mcp_policies ORDER BY id ASC",
        )
        .fetch_all(self.db.pool())
        .await
        .map_err(Error::Sqlx)?;
        rows.into_iter().map(PolicyRow::into_rule).collect()
    }

    /// Same as `load_all`. Exposed under the alias `list` to match the IPC verb.
    pub async fn list(&self) -> Result<Vec<McpPolicyRule>> {
        self.load_all().await
    }

    /// Insert / update each rule by `(method, tool_name)`. Audits one
    /// `McpPolicyChanged` entry summarizing the change. Returns rows touched.
    #[instrument(skip(self, sink, rules))]
    pub async fn upsert(&self, sink: &dyn AuditSink, rules: Vec<McpPolicyRule>) -> Result<usize> {
        let mut count = 0usize;
        for r in &rules {
            sqlx::query(
                "INSERT INTO mcp_policies (method, tool_name, decision, note) \
                 VALUES (?, ?, ?, ?) \
                 ON CONFLICT(method, tool_name) DO UPDATE SET \
                    decision = excluded.decision, \
                    note = excluded.note, \
                    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
            )
            .bind(&r.method)
            .bind(&r.tool_name)
            .bind(decision_str(r.decision))
            .bind(&r.note)
            .execute(self.db.pool())
            .await
            .map_err(Error::Sqlx)?;
            count += 1;
        }
        sink.record(
            AuditSinkKind::McpPolicyChanged,
            None,
            None,
            serde_json::json!({
                "op": "upsert",
                "count": count,
                "rules": rules,
            }),
        )
        .await;
        Ok(count)
    }

    /// Remove every row. Returns the count of rows deleted.
    #[instrument(skip(self))]
    pub async fn delete_all(&self) -> Result<usize> {
        let res = sqlx::query("DELETE FROM mcp_policies")
            .execute(self.db.pool())
            .await
            .map_err(Error::Sqlx)?;
        Ok(res.rows_affected() as usize)
    }
}

/// Apply a `McpPolicySetParams`-shaped batch in one go: delete-all if asked, then upsert.
/// Audits a single summary entry. Returned tuple is `(upserted, deleted)`.
pub async fn apply_set(
    db: &Arc<Database>,
    sink: &dyn AuditSink,
    rules: Vec<McpPolicyRule>,
    replace_all: bool,
) -> Result<(usize, usize)> {
    let store = McpPolicyStore::new(Arc::clone(db));
    let deleted = if replace_all {
        store.delete_all().await?
    } else {
        0
    };
    let upserted = store.upsert(sink, rules).await?;
    // The upsert path already wrote one audit entry; if we cleared the table, log a
    // separate one so the audit chain reflects the destructive op.
    if replace_all {
        // Re-using the audit module directly avoids depending on the sink mapping.
        audit::append(
            db,
            AuditKind::McpPolicyChanged,
            None,
            None,
            serde_json::json!({"op": "delete_all", "count": deleted}),
        )
        .await?;
    }
    Ok((upserted, deleted))
}

fn decision_str(d: McpPolicyDecision) -> &'static str {
    match d {
        McpPolicyDecision::AutoAllow => "auto_allow",
        McpPolicyDecision::Prompt => "prompt",
        McpPolicyDecision::Deny => "deny",
        McpPolicyDecision::AuditOnly => "audit_only",
    }
}

fn parse_decision(raw: &str) -> Result<McpPolicyDecision> {
    match raw {
        "auto_allow" => Ok(McpPolicyDecision::AutoAllow),
        "prompt" => Ok(McpPolicyDecision::Prompt),
        "deny" => Ok(McpPolicyDecision::Deny),
        "audit_only" => Ok(McpPolicyDecision::AuditOnly),
        other => Err(Error::Runtime {
            message: format!("invalid mcp policy decision in DB: '{other}'"),
        }),
    }
}

#[derive(sqlx::FromRow)]
struct PolicyRow {
    method: String,
    tool_name: Option<String>,
    decision: String,
    note: Option<String>,
}

impl PolicyRow {
    fn into_rule(self) -> Result<McpPolicyRule> {
        Ok(McpPolicyRule {
            method: self.method,
            tool_name: self.tool_name,
            decision: parse_decision(&self.decision)?,
            note: self.note,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linpodx_common::audit_sink::NoopAuditSink;

    async fn fresh_db() -> Database {
        let dir = Box::leak(Box::new(tempfile::tempdir().expect("tempdir")));
        let path = dir.path().join("mcp-policy-test.db");
        let db = Database::open(&path).await.expect("open");
        db.migrate().await.expect("migrate");
        db
    }

    fn rule(method: &str, tool: Option<&str>, decision: McpPolicyDecision) -> McpPolicyRule {
        McpPolicyRule {
            method: method.to_string(),
            tool_name: tool.map(|s| s.to_string()),
            decision,
            note: None,
        }
    }

    #[tokio::test]
    async fn empty_store_lists_nothing() {
        let db = Arc::new(fresh_db().await);
        let store = McpPolicyStore::new(Arc::clone(&db));
        assert!(store.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn upsert_inserts_and_lists_back() {
        let db = Arc::new(fresh_db().await);
        let store = McpPolicyStore::new(Arc::clone(&db));
        let sink = NoopAuditSink;
        let rules = vec![
            rule("tools/list", None, McpPolicyDecision::AutoAllow),
            rule("tools/call", Some("read"), McpPolicyDecision::Prompt),
        ];
        let n = store.upsert(&sink, rules.clone()).await.unwrap();
        assert_eq!(n, 2);
        let listed = store.list().await.unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.contains(&rules[0]));
        assert!(listed.contains(&rules[1]));
    }

    #[tokio::test]
    async fn upsert_updates_existing_unique_pair() {
        let db = Arc::new(fresh_db().await);
        let store = McpPolicyStore::new(Arc::clone(&db));
        let sink = NoopAuditSink;
        store
            .upsert(
                &sink,
                vec![rule("tools/call", Some("x"), McpPolicyDecision::Prompt)],
            )
            .await
            .unwrap();
        store
            .upsert(
                &sink,
                vec![rule("tools/call", Some("x"), McpPolicyDecision::Deny)],
            )
            .await
            .unwrap();
        let listed = store.list().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].decision, McpPolicyDecision::Deny);
    }

    #[tokio::test]
    async fn delete_all_empties_table_and_returns_count() {
        let db = Arc::new(fresh_db().await);
        let store = McpPolicyStore::new(Arc::clone(&db));
        let sink = NoopAuditSink;
        store
            .upsert(
                &sink,
                vec![
                    rule("a", None, McpPolicyDecision::AutoAllow),
                    rule("b", None, McpPolicyDecision::Deny),
                ],
            )
            .await
            .unwrap();
        let deleted = store.delete_all().await.unwrap();
        assert_eq!(deleted, 2);
        assert!(store.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn apply_set_with_replace_all_clears_then_inserts() {
        let db = Arc::new(fresh_db().await);
        let sink = NoopAuditSink;
        let store = McpPolicyStore::new(Arc::clone(&db));
        store
            .upsert(&sink, vec![rule("a", None, McpPolicyDecision::AutoAllow)])
            .await
            .unwrap();
        let (upserted, deleted) = apply_set(
            &db,
            &sink,
            vec![rule("b", None, McpPolicyDecision::Deny)],
            true,
        )
        .await
        .unwrap();
        assert_eq!(upserted, 1);
        assert_eq!(deleted, 1);
        let listed = store.list().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].method, "b");
    }

    #[tokio::test]
    async fn apply_set_without_replace_all_merges() {
        let db = Arc::new(fresh_db().await);
        let sink = NoopAuditSink;
        let store = McpPolicyStore::new(Arc::clone(&db));
        store
            .upsert(&sink, vec![rule("a", None, McpPolicyDecision::AutoAllow)])
            .await
            .unwrap();
        let (upserted, deleted) = apply_set(
            &db,
            &sink,
            vec![rule("b", None, McpPolicyDecision::Deny)],
            false,
        )
        .await
        .unwrap();
        assert_eq!(upserted, 1);
        assert_eq!(deleted, 0);
        assert_eq!(store.list().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn upsert_writes_audit_entry() {
        let db = Arc::new(fresh_db().await);
        let store = McpPolicyStore::new(Arc::clone(&db));
        let sink = crate::mcp_audit::SandboxAuditSink::new(Arc::clone(&db));
        store
            .upsert(&sink, vec![rule("x", None, McpPolicyDecision::Deny)])
            .await
            .unwrap();
        let row: (String,) = sqlx::query_as("SELECT kind FROM audit_log ORDER BY seq DESC LIMIT 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(row.0, "mcp_policy_changed");
    }
}
