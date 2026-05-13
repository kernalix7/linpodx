/// linpodx crate version (cargo package version).
pub const LINPODX_VERSION: &str = env!("CARGO_PKG_VERSION");

/// IPC schema version. Bump (and set up migration paths) on breaking change.
pub const IPC_VERSION: u32 = 1;
