use crate::state::{ImagePushForm, Message};
use iced::widget::{button, column, container, row, text, text_input};
use iced::{Element, Length};
use linpodx_common::state::ImageSummary;

pub fn view<'a>(
    images: &'a [ImageSummary],
    push_form: Option<&'a ImagePushForm>,
) -> Element<'a, Message> {
    let body: Element<'_, Message> = if images.is_empty() {
        text("No images. Pull one with: linpodx images pull docker.io/library/alpine:latest").into()
    } else {
        let header = row![
            text("ID").width(Length::FillPortion(2)),
            text("TAGS").width(Length::FillPortion(4)),
            text("SIZE").width(Length::FillPortion(1)),
            text("ACTIONS").width(Length::FillPortion(2)),
        ]
        .spacing(8);

        let mut col = column![header].spacing(4);
        for img in images {
            let id_short = if img.id.as_str().len() > 16 {
                &img.id.as_str()[..16]
            } else {
                img.id.as_str()
            };
            let tags = if img.repo_tags.is_empty() {
                "<none>".to_string()
            } else {
                img.repo_tags.join(", ")
            };
            // Pre-fill the push modal with the first repo tag (most users push by
            // tag, not by digest). Empty string is fine — the user can edit it.
            let push_ref = img
                .repo_tags
                .first()
                .cloned()
                .unwrap_or_else(|| img.id.as_str().to_string());
            let actions = row![button(text("Push"))
                .on_press(Message::ImagePushOpen(push_ref))
                .style(button::primary)]
            .spacing(4);
            col = col.push(
                row![
                    text(id_short.to_string()).width(Length::FillPortion(2)),
                    text(tags).width(Length::FillPortion(4)),
                    text(human_size(img.size_bytes)).width(Length::FillPortion(1)),
                    container(actions).width(Length::FillPortion(2)),
                ]
                .spacing(8),
            );
        }
        col.into()
    };

    if let Some(form) = push_form {
        // iced 0.13 has no built-in modal; mimic the approval modal pattern by
        // composing the form below the table. Callers that need a true overlay
        // can switch to `iced::widget::stack` later.
        let form_el = push_modal(form);
        column![body, form_el].spacing(12).into()
    } else {
        body
    }
}

fn push_modal(form: &ImagePushForm) -> Element<'_, Message> {
    let title = text(format!("Push image: {}", form.reference)).size(16);
    let registry_input = text_input("Registry override (optional)", &form.registry)
        .on_input(Message::ImagePushRegistryChanged);
    let auth_input = text_input("base64(user:password) auth (optional)", &form.auth)
        .on_input(Message::ImagePushAuthChanged)
        .secure(true);
    let actions = row![
        button(text("Push"))
            .on_press(Message::ImagePushSubmit)
            .style(button::success),
        button(text("Cancel"))
            .on_press(Message::ImagePushCancel)
            .style(button::secondary),
    ]
    .spacing(8);
    container(
        column![title, registry_input, auth_input, actions]
            .spacing(8)
            .padding(12),
    )
    .style(|_theme: &iced::Theme| iced::widget::container::Style {
        background: Some(iced::Color::from_rgb(0.10, 0.10, 0.14).into()),
        text_color: Some(iced::Color::WHITE),
        border: iced::Border {
            radius: 6.0.into(),
            width: 2.0,
            color: iced::Color::from_rgb(0.30, 0.55, 0.85),
        },
        ..iced::widget::container::Style::default()
    })
    .width(Length::Fixed(560.0))
    .padding(8)
    .into()
}

fn human_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if bytes >= GIB {
        format!("{:.2} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.2} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.2} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}
