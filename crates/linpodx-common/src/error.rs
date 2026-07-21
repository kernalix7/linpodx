use thiserror::Error;

/// Library-wide error type.
///
/// Each variant maps to exactly one stable IPC error code (see
/// [`crate::ipc::error_codes`] and the daemon's `error_to_code`). The classified
/// variants below (`PermissionDenied`, `Conflict`, `Timeout`, `Unsupported`,
/// `Unavailable`, `Internal`) exist so dispatch sites can promote a failure out
/// of the stringly-typed [`Error::Runtime`] catch-all into a wire-stable code
/// clients can branch on. Prefer a classified variant whenever the failure is
/// unambiguous; leave genuinely opaque wrapped failures on `Runtime`.
#[derive(Debug, Error)]
pub enum Error {
    /// Catch-all for classifiable-but-unclassified failures. Maps to
    /// `RUNTIME_ERROR`. New code should reach for a typed variant first.
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

    /// The caller is authenticated but not authorized, or the daemon lacks the
    /// host privileges/capabilities required for the operation. Maps to
    /// `PERMISSION_DENIED`.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// The request conflicts with the current state (duplicate, already-exists,
    /// wrong lifecycle state, etc.). Maps to `CONFLICT`.
    #[error("conflict: {0}")]
    Conflict(String),

    /// The operation did not complete within its deadline. Maps to `TIMEOUT`.
    #[error("timeout: {0}")]
    Timeout(String),

    /// The operation is not supported by this build or the daemon's current
    /// configuration (e.g. a feature gated behind a startup flag that was not
    /// passed). Maps to `UNSUPPORTED`.
    #[error("unsupported: {0}")]
    Unsupported(String),

    /// A required subsystem or external dependency is temporarily unavailable
    /// (not wired, not the leader, backend offline). Often retryable. Maps to
    /// `UNAVAILABLE`.
    #[error("unavailable: {0}")]
    Unavailable(String),

    /// An internal invariant was violated (poisoned lock, unreachable dispatch
    /// path, corrupt state). Not the caller's fault. Maps to `INTERNAL`.
    #[error("internal error: {0}")]
    Internal(String),

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
