use crate::error::{Error, Result};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::SqlitePool;
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Clone)]
pub struct Database {
    pool: SqlitePool,
    path: PathBuf,
}

impl Database {
    /// Open a database at the given path. Creates the parent directory and the
    /// database file if missing. Enables WAL mode and foreign keys.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent).await?;
            }
        }

        let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", path.display()))
            .map_err(|e| Error::Runtime {
                message: format!("invalid sqlite url: {e}"),
            })?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .foreign_keys(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(opts)
            .await?;

        Ok(Self { pool, path })
    }

    /// Run all pending migrations (compiled into the binary at build time).
    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!("./migrations").run(&self.pool).await?;
        Ok(())
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn close(self) {
        self.pool.close().await;
    }

    /// Default DB path: `$XDG_DATA_HOME/linpodx/state.db` or `~/.local/share/linpodx/state.db`.
    pub fn default_path() -> PathBuf {
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            return PathBuf::from(xdg).join("linpodx").join("state.db");
        }
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(".local/share/linpodx/state.db");
        }
        PathBuf::from("./linpodx-state.db")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn open_and_migrate_creates_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let db = Database::open(&path).await.expect("open");
        db.migrate().await.expect("migrate");

        let row: (String, String) =
            sqlx::query_as("SELECT key, value FROM _schema_meta WHERE key = 'initialized_at'")
                .fetch_one(db.pool())
                .await
                .expect("select");
        assert_eq!(row.0, "initialized_at");
        assert!(!row.1.is_empty());
    }

    #[tokio::test]
    async fn migrate_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let db = Database::open(&path).await.expect("open");
        db.migrate().await.expect("migrate first");
        db.migrate().await.expect("migrate second (idempotent)");
    }
}
