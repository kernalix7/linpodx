use crate::ipc::Event;

/// Object-safe trait that lets sub-systems (sandbox, etc.) emit events without depending
/// on the daemon-internal `EventBus`. The daemon implements this trait on its broadcast
/// bus; tests and other adapters can implement it as a no-op or a recorder.
pub trait EventPublisher: Send + Sync {
    fn publish(&self, event: Event);
}

/// No-op publisher useful in unit tests where event side-effects are out of scope.
#[derive(Debug, Default)]
pub struct NoopEventPublisher;

impl EventPublisher for NoopEventPublisher {
    fn publish(&self, _event: Event) {}
}
