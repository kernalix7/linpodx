//! Phase 2C session manager.
//!
//! A session represents the lifetime of one container. The manager opens a row in
//! `mcp_sessions` on container start and closes it on container removal. The
//! `timeline` query merges the session's audit_log entries with mcp_events so the UI
//! can render the full agent activity stream chronologically.

use crate::audit::{self, AuditKind};
use chrono::{DateTime, Utc};
use linpodx_common::db::Database;
use linpodx_common::error::{Error, Result};
use linpodx_common::events::EventPublisher;
use linpodx_common::ipc::{
    responses::{SessionSummary, SessionTimelineEntry},
    Event, EventKind, EventTopic,
};
use std::sync::Arc;
use tracing::{info, instrument, warn};

pub struct SessionManager {
    db: Arc<Database>,
    publisher: Arc<dyn EventPublisher>,
}

impl SessionManager {
    pub fn new(db: Arc<Database>, publisher: Arc<dyn EventPublisher>) -> Self {
        Self { db, publisher }
    }

    /// Shared `Arc<Database>` so cross-module helpers (mcp_policy admin from the daemon
    /// dispatcher) can hit the same pool without holding an extra handle.
    pub fn db(&self) -> Arc<Database> {
        Arc::clone(&self.db)
    }

    /// Open a new session for a freshly created container.
    #[instrument(skip(self))]
    pub async fn start(
        &self,
        container_id: &str,
        container_name: &str,
        profile_name: Option<&str>,
    ) -> Result<i64> {
        let now_str = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO mcp_sessions (container_id, container_name, profile_name, started_at, status) \
             VALUES (?, ?, ?, ?, 'active') RETURNING id",
        )
        .bind(container_id)
        .bind(container_name)
        .bind(profile_name)
        .bind(&now_str)
        .fetch_one(self.db.pool())
        .await
        .map_err(Error::Sqlx)?;
        let id = row.0;
        audit::append(
            &self.db,
            AuditKind::SessionStarted,
            profile_name.map(|s| s.to_string()),
            Some(container_id.to_string()),
            serde_json::json!({
                "session_id": id,
                "container_id": container_id,
                "container_name": container_name,
                "profile_name": profile_name,
            }),
        )
        .await?;
        self.publisher.publish(Event {
            topic: EventTopic::Session,
            kind: EventKind::Started,
            resource_id: container_id.to_string(),
            timestamp: Utc::now(),
            details: serde_json::json!({
                "session_id": id,
                "container_name": container_name,
                "profile_name": profile_name,
            }),
        });
        info!(session_id = id, container = %container_id, "session started");
        Ok(id)
    }

    /// Close the most-recent active session for a container. No-op if none is active.
    #[instrument(skip(self))]
    pub async fn end(&self, container_id: &str) -> Result<()> {
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT id FROM mcp_sessions \
             WHERE container_id = ? AND status = 'active' \
             ORDER BY id DESC LIMIT 1",
        )
        .bind(container_id)
        .fetch_optional(self.db.pool())
        .await
        .map_err(Error::Sqlx)?;
        let Some((id,)) = row else {
            warn!(container = %container_id, "session::end called but no active session");
            return Ok(());
        };
        // Audit FIRST so the SessionEnded entry's `ts` falls inside the session window;
        // then write `ended_at` from "now" — guaranteed to be ≥ audit ts so the timeline
        // query (`audit_log.ts <= ended_at`) includes the closing entry.
        audit::append(
            &self.db,
            AuditKind::SessionEnded,
            None,
            Some(container_id.to_string()),
            serde_json::json!({"session_id": id, "container_id": container_id}),
        )
        .await?;
        let now_str = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        sqlx::query("UPDATE mcp_sessions SET ended_at = ?, status = 'ended' WHERE id = ?")
            .bind(&now_str)
            .bind(id)
            .execute(self.db.pool())
            .await
            .map_err(Error::Sqlx)?;
        self.publisher.publish(Event {
            topic: EventTopic::Session,
            kind: EventKind::Stopped,
            resource_id: container_id.to_string(),
            timestamp: Utc::now(),
            details: serde_json::json!({"session_id": id}),
        });
        Ok(())
    }

    /// Look up the sandbox profile name attached to the most recent session of a given
    /// container_id. Returns `None` when the container has no session row or its
    /// `profile_name` is NULL. Used by Phase 5 `NetworkEgressApply` to find the L4
    /// allowlist that was associated with a running container at create time.
    #[instrument(skip(self))]
    pub async fn profile_for_container(&self, container_id: &str) -> Result<Option<String>> {
        let row: Option<(Option<String>,)> = sqlx::query_as(
            "SELECT profile_name FROM mcp_sessions \
             WHERE container_id = ? ORDER BY id DESC LIMIT 1",
        )
        .bind(container_id)
        .fetch_optional(self.db.pool())
        .await
        .map_err(Error::Sqlx)?;
        Ok(row.and_then(|(p,)| p))
    }

    #[instrument(skip(self))]
    pub async fn list(
        &self,
        container_id: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Vec<SessionSummary>> {
        let limit = limit.unwrap_or(100).min(1000);
        let rows: Vec<SessionRow> = match container_id {
            Some(cid) => sqlx::query_as::<_, SessionRow>(
                "SELECT id, container_id, container_name, profile_name, started_at, ended_at, status \
                 FROM mcp_sessions WHERE container_id = ? ORDER BY id DESC LIMIT ?",
            )
            .bind(cid)
            .bind(limit as i64)
            .fetch_all(self.db.pool())
            .await
            .map_err(Error::Sqlx)?,
            None => sqlx::query_as::<_, SessionRow>(
                "SELECT id, container_id, container_name, profile_name, started_at, ended_at, status \
                 FROM mcp_sessions ORDER BY id DESC LIMIT ?",
            )
            .bind(limit as i64)
            .fetch_all(self.db.pool())
            .await
            .map_err(Error::Sqlx)?,
        };
        rows.into_iter().map(SessionRow::into_summary).collect()
    }

    #[instrument(skip(self))]
    pub async fn inspect(&self, id: i64) -> Result<SessionSummary> {
        let row = sqlx::query_as::<_, SessionRow>(
            "SELECT id, container_id, container_name, profile_name, started_at, ended_at, status \
             FROM mcp_sessions WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(self.db.pool())
        .await
        .map_err(Error::Sqlx)?
        .ok_or_else(|| Error::NotFound(format!("session {id}")))?;
        row.into_summary()
    }

    /// Merged audit_log + mcp_events stream for the session's container scoped to its
    /// time range. Optional `kinds` filter applies to both sources.
    #[instrument(skip(self))]
    pub async fn timeline(&self, id: i64, kinds: &[String]) -> Result<Vec<SessionTimelineEntry>> {
        let session = self.inspect(id).await?;
        let started = session
            .started_at
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();
        let ended = session
            .ended_at
            .map(|t| t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
            // Use a far-future sentinel so an active session collects ongoing events.
            .unwrap_or_else(|| "9999-12-31T23:59:59.999Z".to_string());

        // Audit entries for this container in the session window.
        let audit_rows = sqlx::query_as::<_, AuditRow>(
            "SELECT ts, kind, payload FROM audit_log \
             WHERE container_id = ? AND ts >= ? AND ts < ?",
        )
        .bind(&session.container_id)
        .bind(&started)
        .bind(&ended)
        .fetch_all(self.db.pool())
        .await
        .map_err(Error::Sqlx)?;

        // MCP events explicitly tagged with this session id.
        let mcp_rows = sqlx::query_as::<_, McpRow>(
            "SELECT ts, direction, tool_name, payload, decision \
             FROM mcp_events WHERE session_id = ?",
        )
        .bind(id)
        .fetch_all(self.db.pool())
        .await
        .map_err(Error::Sqlx)?;

        let mut entries: Vec<SessionTimelineEntry> = Vec::new();
        for row in audit_rows {
            if !kinds.is_empty() && !kinds.iter().any(|k| k == &row.kind) {
                continue;
            }
            let ts = parse_ts(&row.ts)?;
            let payload: serde_json::Value =
                serde_json::from_str(&row.payload).unwrap_or(serde_json::Value::Null);
            entries.push(SessionTimelineEntry {
                source: "audit".into(),
                ts,
                kind: row.kind,
                payload,
            });
        }
        for row in mcp_rows {
            // MCP entries use direction as the kind so callers can filter by direction.
            if !kinds.is_empty() && !kinds.iter().any(|k| k == &row.direction) {
                continue;
            }
            let ts = parse_ts(&row.ts)?;
            entries.push(SessionTimelineEntry {
                source: "mcp".into(),
                ts,
                kind: row.direction,
                payload: serde_json::json!({
                    "tool_name": row.tool_name,
                    "payload": row.payload,
                    "decision": row.decision,
                }),
            });
        }
        entries.sort_by_key(|entry| entry.ts);
        Ok(entries)
    }
}

#[derive(sqlx::FromRow)]
struct SessionRow {
    id: i64,
    container_id: String,
    container_name: String,
    profile_name: Option<String>,
    started_at: String,
    ended_at: Option<String>,
    status: String,
}

impl SessionRow {
    fn into_summary(self) -> Result<SessionSummary> {
        let started_at = parse_ts(&self.started_at)?;
        let ended_at = self.ended_at.as_deref().map(parse_ts).transpose()?;
        Ok(SessionSummary {
            id: self.id,
            container_id: self.container_id,
            container_name: self.container_name,
            profile_name: self.profile_name,
            started_at,
            ended_at,
            status: self.status,
        })
    }
}

#[derive(sqlx::FromRow)]
struct AuditRow {
    ts: String,
    kind: String,
    payload: String,
}

#[derive(sqlx::FromRow)]
struct McpRow {
    ts: String,
    direction: String,
    tool_name: Option<String>,
    payload: String,
    decision: Option<String>,
}

fn parse_ts(raw: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| Error::Runtime {
            message: format!("invalid session ts '{raw}': {e}"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use linpodx_common::events::NoopEventPublisher;

    async fn fresh_db() -> Database {
        let dir = Box::leak(Box::new(tempfile::tempdir().expect("tempdir")));
        let path = dir.path().join("session-test.db");
        let db = Database::open(&path).await.expect("open");
        db.migrate().await.expect("migrate");
        db
    }

    #[tokio::test]
    async fn start_then_end_marks_status_ended() {
        let db = Arc::new(fresh_db().await);
        let mgr = SessionManager::new(Arc::clone(&db), Arc::new(NoopEventPublisher));
        let id = mgr
            .start("cabc", "container-abc", Some("p1"))
            .await
            .unwrap();
        let s = mgr.inspect(id).await.unwrap();
        assert_eq!(s.status, "active");
        assert!(s.ended_at.is_none());

        mgr.end("cabc").await.unwrap();
        let s = mgr.inspect(id).await.unwrap();
        assert_eq!(s.status, "ended");
        assert!(s.ended_at.is_some());
    }

    #[tokio::test]
    async fn end_without_active_session_is_noop() {
        let db = Arc::new(fresh_db().await);
        let mgr = SessionManager::new(Arc::clone(&db), Arc::new(NoopEventPublisher));
        mgr.end("never-existed").await.expect("noop");
    }

    #[tokio::test]
    async fn list_filters_by_container_and_limit() {
        let db = Arc::new(fresh_db().await);
        let mgr = SessionManager::new(Arc::clone(&db), Arc::new(NoopEventPublisher));
        for i in 0..3 {
            mgr.start(&format!("c{i}"), &format!("name-{i}"), None)
                .await
                .unwrap();
        }
        let only_c1 = mgr.list(Some("c1"), None).await.unwrap();
        assert_eq!(only_c1.len(), 1);
        assert_eq!(only_c1[0].container_id, "c1");

        let limited = mgr.list(None, Some(2)).await.unwrap();
        assert_eq!(limited.len(), 2);
    }

    #[tokio::test]
    async fn timeline_merges_audit_and_mcp_in_order() {
        let db = Arc::new(fresh_db().await);
        let mgr = SessionManager::new(Arc::clone(&db), Arc::new(NoopEventPublisher));
        let session_id = mgr.start("cmix", "name-mix", None).await.unwrap();

        // Insert one mcp_event after the session started.
        sqlx::query(
            "INSERT INTO mcp_events (session_id, direction, tool_name, payload, decision) \
             VALUES (?, 'host_to_container', 'list_dirs', '{}', 'allowed')",
        )
        .bind(session_id)
        .execute(db.pool())
        .await
        .unwrap();

        let entries = mgr.timeline(session_id, &[]).await.unwrap();
        // Expect at least the SessionStarted audit + the mcp_event.
        let sources: Vec<&str> = entries.iter().map(|e| e.source.as_str()).collect();
        assert!(sources.contains(&"audit"));
        assert!(sources.contains(&"mcp"));
        // Timestamps must be non-decreasing.
        for w in entries.windows(2) {
            assert!(w[0].ts <= w[1].ts, "timeline not sorted by ts");
        }
    }

    #[tokio::test]
    async fn timeline_kinds_filter_applies_to_both_sources() {
        let db = Arc::new(fresh_db().await);
        let mgr = SessionManager::new(Arc::clone(&db), Arc::new(NoopEventPublisher));
        let session_id = mgr.start("cfilt", "name-filt", None).await.unwrap();
        sqlx::query(
            "INSERT INTO mcp_events (session_id, direction, tool_name, payload, decision) \
             VALUES (?, 'host_to_container', 't', '{}', 'allowed')",
        )
        .bind(session_id)
        .execute(db.pool())
        .await
        .unwrap();
        let only_mcp = mgr
            .timeline(session_id, &["host_to_container".to_string()])
            .await
            .unwrap();
        assert!(only_mcp.iter().all(|e| e.source == "mcp"));
        assert_eq!(only_mcp.len(), 1);
    }
}
