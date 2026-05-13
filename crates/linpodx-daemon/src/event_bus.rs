use linpodx_common::events::EventPublisher;
use linpodx_common::ipc::Event;
use tokio::sync::broadcast;
use tracing::trace;

/// Process-wide event bus. Wraps a `tokio::sync::broadcast` channel.
///
/// `publish` is fire-and-forget: if there are no active subscribers the event is dropped.
/// Subscribers see all events; per-topic filtering happens at the connection layer
/// (`server.rs`) so the wire format and the bus stay decoupled.
#[derive(Debug, Clone)]
pub struct EventBus {
    sender: broadcast::Sender<Event>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    pub fn publish(&self, event: Event) {
        // Ok if there are subscribers, Err(SendError) if none — both are normal.
        match self.sender.send(event) {
            Ok(n) => trace!(subscribers = n, "event published"),
            Err(_) => trace!("event dropped (no subscribers)"),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.sender.subscribe()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(1024)
    }
}

impl EventPublisher for EventBus {
    fn publish(&self, event: Event) {
        EventBus::publish(self, event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linpodx_common::ipc::{EventKind, EventTopic};

    fn ev(topic: EventTopic, kind: EventKind) -> Event {
        Event {
            topic,
            kind,
            resource_id: "test".into(),
            timestamp: chrono::Utc::now(),
            details: serde_json::Value::Null,
        }
    }

    #[tokio::test]
    async fn publish_with_no_subscribers_is_no_op() {
        let bus = EventBus::new(8);
        bus.publish(ev(EventTopic::Container, EventKind::Created));
        // No assertion needed — should not panic.
    }

    #[tokio::test]
    async fn subscribers_receive_published_events() {
        let bus = EventBus::new(8);
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();
        bus.publish(ev(EventTopic::Container, EventKind::Started));
        let r1 = rx1.recv().await.unwrap();
        let r2 = rx2.recv().await.unwrap();
        assert_eq!(r1.kind, EventKind::Started);
        assert_eq!(r2.kind, EventKind::Started);
    }

    #[tokio::test]
    async fn subscriber_can_filter_by_topic() {
        let bus = EventBus::new(8);
        let mut rx = bus.subscribe();
        bus.publish(ev(EventTopic::Container, EventKind::Created));
        bus.publish(ev(EventTopic::Image, EventKind::Pulled));
        bus.publish(ev(EventTopic::Container, EventKind::Removed));

        let mut got = Vec::new();
        for _ in 0..3 {
            let event = rx.recv().await.unwrap();
            if event.topic == EventTopic::Container {
                got.push(event.kind);
            }
        }
        assert_eq!(got, vec![EventKind::Created, EventKind::Removed]);
    }
}
