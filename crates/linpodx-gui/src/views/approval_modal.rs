use crate::state::Message;
use iced::widget::{button, column, container, row, text, text_input};
use iced::{Element, Length};
use linpodx_common::approval::ApprovalRequest;

/// Render an approval request as a modal-style card. iced 0.13 has no built-in modal, so the
/// caller composes this with `iced::widget::stack` to overlay it on the body.
pub fn modal<'a>(req: &'a ApprovalRequest, reason: &'a str) -> Element<'a, Message> {
    let title = text(format!("Approval required — {}", req.category)).size(18);
    let profile_line = text(format!("Profile: {}", req.profile_name));
    let timeout_line = text(format!("Times out in: {}s", req.timeout_secs));
    let payload_line = text(format!("Payload: {}", payload_summary(&req.payload)));
    let hint_line = text(req.container_hint.clone().unwrap_or_default()).size(12);

    let request_id = req.request_id.clone();
    let allow_id = request_id.clone();
    let deny_id = request_id;

    let reason_input =
        text_input("Optional reason…", reason).on_input(Message::ApprovalReasonChanged);
    let reason_owned = reason.to_string();
    let reason_for_allow = reason_owned.clone();
    let reason_for_deny = reason_owned;

    let actions = row![
        button(text("Allow"))
            .style(button::success)
            .on_press(Message::ApprovalDecision {
                request_id: allow_id,
                allow: true,
                reason: opt_reason(&reason_for_allow),
            }),
        button(text("Deny"))
            .style(button::danger)
            .on_press(Message::ApprovalDecision {
                request_id: deny_id,
                allow: false,
                reason: opt_reason(&reason_for_deny),
            }),
    ]
    .spacing(8);

    let card = container(
        column![
            title,
            profile_line,
            timeout_line,
            payload_line,
            hint_line,
            reason_input,
            actions,
        ]
        .spacing(8)
        .padding(16),
    )
    .style(|_theme: &iced::Theme| iced::widget::container::Style {
        background: Some(iced::Color::from_rgb(0.10, 0.10, 0.14).into()),
        text_color: Some(iced::Color::WHITE),
        border: iced::Border {
            radius: 6.0.into(),
            width: 2.0,
            color: iced::Color::from_rgb(0.85, 0.55, 0.10),
        },
        ..iced::widget::container::Style::default()
    })
    .width(Length::Fixed(560.0))
    .padding(8);

    // Center the card on a translucent dim. iced 0.13 has no opacity for backgrounds, so
    // simulate dim with a darker container fill.
    container(card)
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .style(|_theme: &iced::Theme| iced::widget::container::Style {
            background: Some(iced::Color::from_rgba(0.0, 0.0, 0.0, 0.55).into()),
            ..iced::widget::container::Style::default()
        })
        .into()
}

fn opt_reason(s: &str) -> Option<String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn payload_summary(value: &serde_json::Value) -> String {
    let s = value.to_string();
    if s.len() > 220 {
        format!("{}…", &s[..220])
    } else {
        s
    }
}
