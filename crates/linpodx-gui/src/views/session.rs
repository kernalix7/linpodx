use crate::state::Message;
use iced::widget::{button, column, container, row, scrollable, text, Column};
use iced::{Element, Length};
use linpodx_common::ipc::responses::{SessionSummary, SessionTimelineEntry};

pub fn view<'a>(
    sessions: &'a [SessionSummary],
    selected: Option<i64>,
    timeline: &'a [SessionTimelineEntry],
) -> Element<'a, Message> {
    let list = session_list(sessions, selected);
    let detail: Element<'_, Message> = if let Some(id) = selected {
        timeline_view(id, timeline)
    } else {
        container(text("Select a session to view its timeline."))
            .padding(8)
            .into()
    };

    column![list, detail].spacing(8).into()
}

fn session_list(sessions: &[SessionSummary], selected: Option<i64>) -> Element<'_, Message> {
    if sessions.is_empty() {
        return text("No sessions recorded.").into();
    }

    let header = row![
        text("ID").width(Length::FillPortion(1)),
        text("CONTAINER").width(Length::FillPortion(2)),
        text("PROFILE").width(Length::FillPortion(2)),
        text("STARTED").width(Length::FillPortion(3)),
        text("ENDED").width(Length::FillPortion(3)),
        text("STATUS").width(Length::FillPortion(1)),
        text("").width(Length::FillPortion(1)),
    ]
    .spacing(8);

    let mut col: Column<'_, Message> = column![header].spacing(4);
    for s in sessions {
        let mut btn = button(text(if Some(s.id) == selected {
            "Selected"
        } else {
            "View"
        }));
        if Some(s.id) == selected {
            btn = btn.style(button::primary);
        } else {
            btn = btn.style(button::secondary);
        }
        col = col.push(
            row![
                text(s.id.to_string()).width(Length::FillPortion(1)),
                text(s.container_name.clone()).width(Length::FillPortion(2)),
                text(s.profile_name.clone().unwrap_or_default()).width(Length::FillPortion(2)),
                text(s.started_at.to_rfc3339()).width(Length::FillPortion(3)),
                text(
                    s.ended_at
                        .map(|t| t.to_rfc3339())
                        .unwrap_or_else(|| "—".into()),
                )
                .width(Length::FillPortion(3)),
                text(s.status.clone()).width(Length::FillPortion(1)),
                btn.on_press(Message::SessionSelected(s.id))
                    .width(Length::FillPortion(1)),
            ]
            .spacing(8),
        );
    }

    scrollable(col).height(Length::FillPortion(2)).into()
}

fn timeline_view(session_id: i64, entries: &[SessionTimelineEntry]) -> Element<'_, Message> {
    let header = text(format!(
        "Session #{session_id} — timeline ({} events)",
        entries.len()
    ))
    .size(14);
    if entries.is_empty() {
        return column![header, text("Loading or no events.")]
            .spacing(4)
            .into();
    }
    let row_header = row![
        text("SOURCE").width(Length::FillPortion(1)),
        text("TIMESTAMP").width(Length::FillPortion(3)),
        text("KIND").width(Length::FillPortion(2)),
        text("PAYLOAD").width(Length::FillPortion(6)),
    ]
    .spacing(8);
    let mut col: Column<'_, Message> = column![row_header].spacing(4);
    for e in entries {
        col = col.push(
            row![
                text(e.source.clone()).width(Length::FillPortion(1)),
                text(e.ts.to_rfc3339()).width(Length::FillPortion(3)),
                text(e.kind.clone()).width(Length::FillPortion(2)),
                text(payload_summary(&e.payload)).width(Length::FillPortion(6)),
            ]
            .spacing(8),
        );
    }
    column![header, scrollable(col).height(Length::Fill)]
        .spacing(4)
        .into()
}

fn payload_summary(value: &serde_json::Value) -> String {
    let s = value.to_string();
    if s.len() > 160 {
        format!("{}…", &s[..160])
    } else {
        s
    }
}
