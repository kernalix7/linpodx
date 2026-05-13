use crate::state::Message;
use iced::widget::{button, column, container, row, scrollable, text, Column};
use iced::{Element, Length};
use linpodx_common::ipc::responses::{
    SandboxProfileSummary, SandboxSnapshotAutoTriggerStatusResponse,
};

pub fn view<'a>(
    profiles: &'a [SandboxProfileSummary],
    selected: Option<&'a str>,
    auto_trigger: Option<&'a SandboxSnapshotAutoTriggerStatusResponse>,
) -> Element<'a, Message> {
    let mut layout: Column<'_, Message> = column![auto_trigger_panel(auto_trigger)].spacing(10);

    if profiles.is_empty() {
        layout = layout.push(text(
            "No sandbox profiles. Drop a YAML in the daemon's profile dir and reload.",
        ));
        return layout.into();
    }

    let header = row![
        text("NAME").width(Length::FillPortion(2)),
        text("VERSION").width(Length::FillPortion(1)),
        text("YAML HASH").width(Length::FillPortion(3)),
        text("DESCRIPTION").width(Length::FillPortion(4)),
        text("").width(Length::FillPortion(1)),
    ]
    .spacing(8);

    let mut col: Column<'_, Message> = column![header].spacing(4);
    for p in profiles {
        let hash_short = if p.yaml_hash.len() > 16 {
            &p.yaml_hash[..16]
        } else {
            p.yaml_hash.as_str()
        };
        let mut select_btn = button(text("View"));
        let is_selected = selected == Some(p.name.as_str());
        if is_selected {
            select_btn = select_btn.style(button::primary);
        } else {
            select_btn = select_btn.style(button::secondary);
        }
        col = col.push(
            row![
                text(p.name.clone()).width(Length::FillPortion(2)),
                text(p.version.to_string()).width(Length::FillPortion(1)),
                text(hash_short.to_string()).width(Length::FillPortion(3)),
                text(p.description.clone()).width(Length::FillPortion(4)),
                select_btn
                    .on_press(Message::SandboxProfileSelected(p.name.clone()))
                    .width(Length::FillPortion(1)),
            ]
            .spacing(8),
        );
    }

    layout = layout.push(scrollable(col).height(Length::FillPortion(2)));
    if let Some(name) = selected {
        if let Some(profile) = profiles.iter().find(|p| p.name == name) {
            layout = layout.push(profile_detail(profile));
        }
    }
    layout.into()
}

/// Phase 17 Stream B — top-of-tab card with the auto-encrypt toggle + last
/// auto-trigger counter. When the daemon hasn't replied yet (Stream B
/// placeholder) we show an unobtrusive hint instead.
fn auto_trigger_panel(
    status: Option<&SandboxSnapshotAutoTriggerStatusResponse>,
) -> Element<'_, Message> {
    let body: Element<'_, Message> = match status {
        None => column![
            text("Sandbox snapshot auto-trigger").size(16),
            text("status not yet available — open the tab to refresh"),
        ]
        .spacing(4)
        .into(),
        Some(s) => {
            let label = if s.enabled {
                "Disable auto-encrypt"
            } else {
                "Enable auto-encrypt"
            };
            let trigger_line = format!("trigger count: {}", s.trigger_count);
            let last_line = match &s.last_image_ref {
                Some(r) => format!("last trigger: {r}"),
                None => "last trigger: (none yet)".to_string(),
            };
            column![
                text("Sandbox snapshot auto-trigger").size(16),
                text(format!("enabled: {}", s.enabled)),
                text(trigger_line),
                text(last_line),
                row![button(text(label))
                    .on_press(Message::SandboxAutoTriggerToggle)
                    .style(if s.enabled {
                        button::secondary
                    } else {
                        button::primary
                    })]
                .spacing(8),
            ]
            .spacing(4)
            .into()
        }
    };
    container(body)
        .padding(8)
        .style(|_theme: &iced::Theme| iced::widget::container::Style {
            background: Some(iced::Color::from_rgb(0.10, 0.14, 0.16).into()),
            border: iced::Border {
                radius: 4.0.into(),
                width: 1.0,
                color: iced::Color::from_rgb(0.3, 0.4, 0.4),
            },
            ..iced::widget::container::Style::default()
        })
        .width(Length::Fill)
        .into()
}

fn profile_detail(p: &SandboxProfileSummary) -> Element<'_, Message> {
    container(
        column![
            text(format!("Profile: {}", p.name)).size(16),
            text(format!("Version: {}", p.version)),
            text(format!("Hash: {}", p.yaml_hash)),
            text(format!("Last updated: {}", p.last_updated)),
            text(p.description.clone()),
            text("Use the CLI to inspect the YAML body: linpodx sandbox profile get <name>")
                .size(12),
        ]
        .spacing(4)
        .padding(8),
    )
    .style(|_theme: &iced::Theme| iced::widget::container::Style {
        background: Some(iced::Color::from_rgb(0.12, 0.12, 0.16).into()),
        border: iced::Border {
            radius: 4.0.into(),
            width: 1.0,
            color: iced::Color::from_rgb(0.3, 0.3, 0.4),
        },
        ..iced::widget::container::Style::default()
    })
    .width(Length::Fill)
    .into()
}
