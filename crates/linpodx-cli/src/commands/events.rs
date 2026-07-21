//! `linpodx events` — stream daemon events (container / image / volume /
//! network lifecycle) over the subscribed event bus.
#![forbid(unsafe_code)]

use crate::client::Client;
use anyhow::Result;
use linpodx_common::ipc::{EventTopic, Method, SubscribeParams};

pub(crate) async fn handle_events(
    client: &mut Client,
    topics: Vec<EventTopic>,
    json: bool,
) -> Result<()> {
    use linpodx_common::ipc::responses::SubscribeResponse;

    let _ack: SubscribeResponse = client
        .call(Method::Subscribe(SubscribeParams {
            topics: topics.clone(),
        }))
        .await?;

    let topics_human = if topics.is_empty() {
        "all".to_string()
    } else {
        topics
            .iter()
            .map(|t| t.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    eprintln!("subscribed to events ({topics_human}) — press Ctrl+C to stop");

    while let Some(event) = client.next_event().await? {
        if json {
            println!("{}", serde_json::to_string(&event)?);
        } else {
            let ts = event.timestamp.format("%H:%M:%S");
            let id_short = if event.resource_id.len() > 12 {
                &event.resource_id[..12]
            } else {
                &event.resource_id
            };
            let details = if event.details.is_null() {
                String::new()
            } else {
                format!(
                    " details={}",
                    serde_json::to_string(&event.details).unwrap_or_default()
                )
            };
            println!(
                "[{ts}] {}.{} id={id_short}{details}",
                event.topic, event.kind
            );
        }
    }
    eprintln!("daemon closed the event stream");
    Ok(())
}
