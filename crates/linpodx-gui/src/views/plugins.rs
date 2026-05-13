//! Phase 17 Stream C — plugin key revocation propagation surface.
//!
//! Each row shows the publisher / fingerprint / status, plus a "Revoke
//! cluster-wide" button when the key is still active. Once the user submits a
//! revocation we store a per-row propagation state in `App.plugin_key_revoke_state`
//! and display it (this-node / pending / cluster-wide).

use crate::state::{Message, PluginKeyRevokeForm, PluginRevokePropagation};
use iced::widget::{button, column, container, row, scrollable, text, Column};
use iced::{Element, Length};
use linpodx_common::ipc::responses::PluginKeyEntry;
use std::collections::HashMap;

pub fn view<'a>(
    keys: &'a [PluginKeyEntry],
    propagation: &'a HashMap<(String, String), PluginRevokePropagation>,
    revoke_form: Option<&'a PluginKeyRevokeForm>,
) -> Element<'a, Message> {
    if keys.is_empty() {
        let mut empty = column![text("No plugin keys registered.")].spacing(8);
        if let Some(form) = revoke_form {
            empty = empty.push(revoke_modal(form));
        }
        return empty.into();
    }

    let header = row![
        text("PUBLISHER").width(Length::FillPortion(2)),
        text("FINGERPRINT").width(Length::FillPortion(3)),
        text("STATUS").width(Length::FillPortion(1)),
        text("PROPAGATION").width(Length::FillPortion(2)),
        text("ACTIONS").width(Length::FillPortion(2)),
    ]
    .spacing(8);

    let mut col: Column<'_, Message> = column![header].spacing(4);
    for k in keys {
        let fp_short = if k.fingerprint.len() > 18 {
            format!("{}…", &k.fingerprint[..18])
        } else {
            k.fingerprint.clone()
        };
        let prop = propagation
            .get(&(k.publisher.clone(), k.fingerprint.clone()))
            .copied()
            .unwrap_or_default();
        let prop_label = propagation_label(prop);
        let mut actions = row![].spacing(4);
        if k.status == "active" {
            actions = actions.push(
                button(text("Revoke cluster-wide"))
                    .on_press(Message::PluginKeyRevokeOpen {
                        publisher: k.publisher.clone(),
                        fingerprint: k.fingerprint.clone(),
                    })
                    .style(button::danger),
            );
        }
        col = col.push(
            row![
                text(k.publisher.clone()).width(Length::FillPortion(2)),
                text(fp_short).width(Length::FillPortion(3)),
                text(k.status.clone()).width(Length::FillPortion(1)),
                text(prop_label).width(Length::FillPortion(2)),
                container(actions).width(Length::FillPortion(2)),
            ]
            .spacing(8),
        );
    }

    let mut body = column![scrollable(col).height(Length::FillPortion(2))].spacing(10);
    if let Some(form) = revoke_form {
        body = body.push(revoke_modal(form));
    }
    body.into()
}

fn revoke_modal(form: &PluginKeyRevokeForm) -> Element<'_, Message> {
    container(
        column![
            text(format!("Revoke key for {} (cluster-wide)", form.publisher)).size(16),
            text(format!("fingerprint: {}", form.fingerprint)),
            text(
                "Submitting will propagate the revocation through Raft. Other cluster nodes \
                 stop accepting this publisher within the next replication round."
            ),
            row![
                button(text("Confirm"))
                    .on_press(Message::PluginKeyRevokeSubmit)
                    .style(button::danger),
                button(text("Cancel"))
                    .on_press(Message::PluginKeyRevokeCancel)
                    .style(button::secondary),
            ]
            .spacing(8),
        ]
        .spacing(6)
        .padding(10),
    )
    .style(|_t: &iced::Theme| iced::widget::container::Style {
        background: Some(iced::Color::from_rgb(0.18, 0.06, 0.06).into()),
        border: iced::Border {
            radius: 6.0.into(),
            width: 1.0,
            color: iced::Color::from_rgb(0.6, 0.2, 0.2),
        },
        ..iced::widget::container::Style::default()
    })
    .width(Length::Fill)
    .into()
}

/// Pure helper: render the three propagation states as a human-readable label.
pub fn propagation_label(state: PluginRevokePropagation) -> String {
    match state {
        PluginRevokePropagation::ThisNode => "this node".to_string(),
        PluginRevokePropagation::Pending => "pending (raft)".to_string(),
        PluginRevokePropagation::Cluster { log_index } => match log_index {
            Some(idx) => format!("cluster-wide (idx {idx})"),
            None => "cluster-wide".to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn propagation_label_covers_all_states() {
        assert_eq!(
            propagation_label(PluginRevokePropagation::ThisNode),
            "this node"
        );
        assert_eq!(
            propagation_label(PluginRevokePropagation::Pending),
            "pending (raft)"
        );
        assert_eq!(
            propagation_label(PluginRevokePropagation::Cluster { log_index: None }),
            "cluster-wide"
        );
        assert_eq!(
            propagation_label(PluginRevokePropagation::Cluster { log_index: Some(7) }),
            "cluster-wide (idx 7)"
        );
    }
}
