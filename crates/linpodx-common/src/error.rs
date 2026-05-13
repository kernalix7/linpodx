use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("runtime error: {message}")]
    Runtime { message: String },

    #[error("podman not found: {0}")]
    PodmanNotFound(String),

    #[error("podman version {found} is below minimum required {required}")]
    PodmanVersionMismatch { found: String, required: String },

    #[error("IPC error: {0}")]
    Ipc(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),

    #[error(transparent)]
    Migrate(#[from] sqlx::migrate::MigrateError),
}

pub type Result<T> = std::result::Result<T, Error>;
