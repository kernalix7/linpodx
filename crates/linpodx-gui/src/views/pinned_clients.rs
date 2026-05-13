//! Phase 17 Stream C — TOFU pin-store expiry surface.
//!
//! Renders the daemon's `DaemonPinClientTofuExpiryStatus` payload as a status
//! card with a countdown to auto-disable and a "Set expiry" input. The
//! countdown text and red-indicator styling are computed by pure-Rust helpers
//! at the bottom of the module so they remain unit-testable on host.

use crate::state::Message;
use iced::widget::{button, column, container, row, text, text_input};
use iced::{Element, Length};
use linpodx_common::ipc::responses::DaemonPinClientTofuExpiryStatusResponse;

pub fn view<'a>(
    status: Option<&'a DaemonPinClientTofuExpiryStatusResponse>,
    input: &'a str,
) -> Element<'a, Message> {
    let body: Element<'_, Message> = match status {
        None => column![
            text("TOFU pin-store status").size(16),
            text("status not yet available — daemon will populate on next event"),
            input_row(input),
        ]
        .spacing(6)
        .into(),
        Some(s) => {
            let now_secs = chrono::Utc::now().timestamp();
            let countdown_text = countdown_label(s, now_secs);
            let expired = is_expired(s, now_secs);
            let countdown_widget: Element<'_, Message> = if expired {
                container(text(countdown_text).size(15))
                    .padding(6)
                    .style(|_t: &iced::Theme| iced::widget::container::Style {
                        background: Some(iced::Color::from_rgb(0.55, 0.10, 0.10).into()),
                        text_color: Some(iced::Color::WHITE),
                        border: iced::Border {
                            radius: 4.0.into(),
                            ..Default::default()
                        },
                        ..iced::widget::container::Style::default()
                    })
                    .into()
            } else {
                text(countdown_text).size(15).into()
            };
            column![
                text("TOFU pin-store status").size(16),
                text(format!("enabled: {}", s.enabled)),
                text(format!(
                    "max_age_secs: {}",
                    s.max_age_secs
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "(unset)".into())
                )),
                text(format!(
                    "enabled_at: {}",
                    s.enabled_at
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "(never)".into())
                )),
                countdown_widget,
                input_row(input),
            ]
            .spacing(6)
            .into()
        }
    };
    container(body)
        .padding(10)
        .style(|_t: &iced::Theme| iced::widget::container::Style {
            background: Some(iced::Color::from_rgb(0.10, 0.10, 0.16).into()),
            border: iced::Border {
                radius: 6.0.into(),
                width: 1.0,
                color: iced::Color::from_rgb(0.3, 0.3, 0.5),
            },
            ..iced::widget::container::Style::default()
        })
        .width(Length::Fill)
        .into()
}

fn input_row(input: &str) -> Element<'_, Message> {
    row![
        text_input("e.g. 3600s, 5m, 2h, clear", input)
            .on_input(Message::TofuExpiryInputChanged)
            .padding(6),
        button(text("Apply"))
            .on_press(Message::TofuExpirySubmit)
            .style(button::primary),
    ]
    .spacing(8)
    .into()
}

/// Pure helper: compute the remaining-seconds countdown / expired message for a
/// TOFU expiry status snapshot, given a "now" timestamp in unix seconds.
pub fn countdown_label(s: &DaemonPinClientTofuExpiryStatusResponse, now_secs: i64) -> String {
    let Some(max_age) = s.max_age_secs else {
        return "no expiry set — TOFU stays on until manually disabled".to_string();
    };
    let Some(enabled_at) = s.enabled_at else {
        return format!("expiry: {max_age}s (will start when TOFU is enabled)");
    };
    let elapsed = now_secs.saturating_sub(enabled_at);
    if elapsed < 0 {
        return format!("expiry: {max_age}s (clock skew detected)");
    }
    let remaining = max_age as i64 - elapsed;
    if remaining <= 0 {
        format!(
            "EXPIRED ({} seconds past max_age={max_age}s) — TOFU is auto-disabled",
            (-remaining) as u64
        )
    } else {
        format!("expires in {remaining}s (max_age={max_age}s)")
    }
}

/// Pure helper: did the TOFU enrollment window already elapse?
pub fn is_expired(s: &DaemonPinClientTofuExpiryStatusResponse, now_secs: i64) -> bool {
    let (Some(max_age), Some(enabled_at)) = (s.max_age_secs, s.enabled_at) else {
        return false;
    };
    let elapsed = now_secs.saturating_sub(enabled_at);
    elapsed >= 0 && (elapsed as u64) >= max_age
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st(max: Option<u64>, enabled_at: Option<i64>) -> DaemonPinClientTofuExpiryStatusResponse {
        DaemonPinClientTofuExpiryStatusResponse {
            enabled: true,
            max_age_secs: max,
            enabled_at,
        }
    }

    #[test]
    fn countdown_label_says_no_expiry_when_unset() {
        let s = st(None, Some(1_000));
        assert!(countdown_label(&s, 2_000).contains("no expiry set"));
    }

    #[test]
    fn countdown_label_handles_not_yet_started() {
        let s = st(Some(3_600), None);
        let msg = countdown_label(&s, 1_000);
        assert!(msg.contains("will start when TOFU is enabled"));
    }

    #[test]
    fn countdown_label_reports_remaining_seconds() {
        let s = st(Some(3_600), Some(1_000));
        // enabled_at=1000, now=2000 → elapsed=1000 → remaining=2600.
        let msg = countdown_label(&s, 2_000);
        assert!(msg.contains("expires in 2600s"));
        assert!(msg.contains("max_age=3600s"));
    }

    #[test]
    fn countdown_label_flags_expiry_when_window_elapsed() {
        let s = st(Some(60), Some(1_000));
        let msg = countdown_label(&s, 2_000);
        assert!(msg.starts_with("EXPIRED"));
        assert!(msg.contains("max_age=60s"));
    }

    #[test]
    fn is_expired_returns_true_only_when_elapsed_exceeds_max_age() {
        let s = st(Some(60), Some(1_000));
        assert!(!is_expired(&s, 1_030));
        assert!(is_expired(&s, 1_060));
        assert!(is_expired(&s, 9_000));
    }

    #[test]
    fn is_expired_returns_false_when_either_field_unset() {
        assert!(!is_expired(&st(None, Some(1_000)), 9_999));
        assert!(!is_expired(&st(Some(60), None), 9_999));
    }
}
