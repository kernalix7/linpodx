#![forbid(unsafe_code)]

pub mod approval;
pub mod audit_sink;
pub mod db;
pub mod error;
pub mod events;
pub mod ipc;
pub mod network;
pub mod passthrough;
pub mod state;
pub mod types;
pub mod version;

pub use approval::{
    ApprovalCategory, ApprovalGateway, ApprovalOutcome, ApprovalRequest, ApprovalResolved,
};
pub use audit_sink::{AuditSink, AuditSinkKind, NoopAuditSink};
pub use error::{Error, Result};
pub use events::EventPublisher;
pub use network::{EgressProto, EgressRule};
pub use passthrough::{AudioMode, DistroKind, PassthroughSpec, SnapshotBackendKind};
