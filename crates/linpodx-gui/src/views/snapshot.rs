use crate::state::{
    build_snapshot_tree, DiffSlot, Message, SnapshotEncryptionBadge, SnapshotKeyRotateForm,
    SnapshotReEncryptForm,
};
use iced::widget::{button, column, container, row, scrollable, text, text_input, Column};
use iced::{Element, Length};
use linpodx_common::ipc::responses::{SnapshotDiffResponse, SnapshotSummary};
use std::collections::HashMap;

#[allow(clippy::too_many_arguments)]
pub fn view<'a>(
    snapshots: &'a [SnapshotSummary],
    diff_a: Option<i64>,
    diff_b: Option<i64>,
    diff: Option<&'a SnapshotDiffResponse>,
    badges: &'a HashMap<i64, SnapshotEncryptionBadge>,
    rotate_form: Option<&'a SnapshotKeyRotateForm>,
    re_encrypt_form: Option<&'a SnapshotReEncryptForm>,
) -> Element<'a, Message> {
    if snapshots.is_empty() {
        let mut empty = column![text(
            "No snapshots. Create one with: linpodx snapshot create <container>"
        )]
        .spacing(8);
        empty = empty.push(re_encrypt_button(re_encrypt_form));
        if let Some(form) = re_encrypt_form {
            empty = empty.push(re_encrypt_modal(form));
        }
        return empty.into();
    }

    let header = row![
        text("ID").width(Length::FillPortion(1)),
        text("CONTAINER").width(Length::FillPortion(2)),
        text("LABEL").width(Length::FillPortion(2)),
        text("IMAGE REF").width(Length::FillPortion(3)),
        text("KDF").width(Length::FillPortion(2)),
        text("CREATED").width(Length::FillPortion(2)),
        text("SIZE").width(Length::FillPortion(1)),
        text("ACTIONS").width(Length::FillPortion(5)),
    ]
    .spacing(8);

    let mut col: Column<'_, Message> = column![header].spacing(4);
    let nodes = build_snapshot_tree(snapshots);
    for node in &nodes {
        let s = &node.snapshot;
        let cid_short = if s.container_id.len() > 12 {
            &s.container_id[..12]
        } else {
            s.container_id.as_str()
        };
        let prefix = if node.depth == 0 {
            String::new()
        } else {
            format!("{}└─ ", "    ".repeat(node.depth - 1))
        };
        let id_label = format!("{}{}", prefix, s.id);

        let select_a_style = if diff_a == Some(s.id) {
            button::primary
        } else {
            button::secondary
        };
        let select_b_style = if diff_b == Some(s.id) {
            button::primary
        } else {
            button::secondary
        };

        let badge = badges.get(&s.id);
        let badge_text = kdf_badge_label(badge);

        let actions = row![
            button(text("A"))
                .on_press(Message::SnapshotSelectForDiff {
                    slot: DiffSlot::A,
                    id: s.id,
                })
                .style(select_a_style),
            button(text("B"))
                .on_press(Message::SnapshotSelectForDiff {
                    slot: DiffSlot::B,
                    id: s.id,
                })
                .style(select_b_style),
            button(text("Branch"))
                .on_press(Message::SnapshotBranch(s.id))
                .style(button::secondary),
            button(text("Rollback"))
                .on_press(Message::SnapshotRollback(s.id))
                .style(button::primary),
            button(text("Rotate Key"))
                .on_press(Message::SnapshotKeyRotateOpen(s.id))
                .style(button::secondary),
            button(text("Remove"))
                .on_press(Message::SnapshotRemove(s.id))
                .style(button::danger),
        ]
        .spacing(4);
        col = col.push(
            row![
                text(id_label).width(Length::FillPortion(1)),
                text(cid_short.to_string()).width(Length::FillPortion(2)),
                text(s.label.clone().unwrap_or_default()).width(Length::FillPortion(2)),
                text(s.image_ref.clone()).width(Length::FillPortion(3)),
                container(text(badge_text)).width(Length::FillPortion(2)),
                text(s.created_at.to_rfc3339()).width(Length::FillPortion(2)),
                text(human_size_opt(s.size_bytes)).width(Length::FillPortion(1)),
                container(actions).width(Length::FillPortion(5)),
            ]
            .spacing(8),
        );
    }

    let diff_panel = diff_panel_view(diff_a, diff_b, diff);
    let mut body = column![
        re_encrypt_button(re_encrypt_form),
        scrollable(col).height(Length::FillPortion(2)),
        diff_panel
    ]
    .spacing(12);
    if let Some(form) = rotate_form {
        body = body.push(rotate_modal(form));
    }
    if let Some(form) = re_encrypt_form {
        body = body.push(re_encrypt_modal(form));
    }
    body.into()
}

fn re_encrypt_button(form: Option<&SnapshotReEncryptForm>) -> Element<'_, Message> {
    let label = if form.is_some() {
        "Re-encrypt All (open)"
    } else {
        "Re-encrypt All"
    };
    button(text(label))
        .on_press(Message::SnapshotReEncryptAllOpen)
        .style(button::primary)
        .into()
}

fn rotate_modal(form: &SnapshotKeyRotateForm) -> Element<'_, Message> {
    let id = form.snapshot_id;
    container(
        column![
            text(format!("Rotate key for snapshot #{id}")).size(16),
            text("Type a new passphrase. The daemon re-encrypts the side-car with the new key."),
            text_input("new passphrase", &form.new_passphrase)
                .on_input(Message::SnapshotKeyRotatePassphraseChanged)
                .secure(true)
                .padding(6),
            row![
                button(text("Confirm"))
                    .on_press(Message::SnapshotKeyRotateSubmit)
                    .style(button::primary),
                button(text("Cancel"))
                    .on_press(Message::SnapshotKeyRotateCancel)
                    .style(button::secondary),
            ]
            .spacing(8),
        ]
        .spacing(6)
        .padding(10),
    )
    .style(|_theme: &iced::Theme| iced::widget::container::Style {
        background: Some(iced::Color::from_rgb(0.08, 0.08, 0.16).into()),
        border: iced::Border {
            radius: 6.0.into(),
            width: 1.0,
            color: iced::Color::from_rgb(0.4, 0.4, 0.6),
        },
        ..iced::widget::container::Style::default()
    })
    .width(Length::Fill)
    .into()
}

fn re_encrypt_modal(form: &SnapshotReEncryptForm) -> Element<'_, Message> {
    container(
        column![
            text("Re-encrypt every snapshot").size(16),
            text("The daemon iterates all encrypted snapshots and rewraps each side-car."),
            text_input("new passphrase", &form.new_passphrase)
                .on_input(Message::SnapshotReEncryptAllPassphraseChanged)
                .secure(true)
                .padding(6),
            row![
                button(text("Confirm"))
                    .on_press(Message::SnapshotReEncryptAllSubmit)
                    .style(button::primary),
                button(text("Cancel"))
                    .on_press(Message::SnapshotReEncryptAllCancel)
                    .style(button::secondary),
            ]
            .spacing(8),
        ]
        .spacing(6)
        .padding(10),
    )
    .style(|_theme: &iced::Theme| iced::widget::container::Style {
        background: Some(iced::Color::from_rgb(0.08, 0.12, 0.08).into()),
        border: iced::Border {
            radius: 6.0.into(),
            width: 1.0,
            color: iced::Color::from_rgb(0.4, 0.6, 0.4),
        },
        ..iced::widget::container::Style::default()
    })
    .width(Length::Fill)
    .into()
}

/// Render a human-readable KDF label for the per-row badge. Returns "—" when no
/// encryption metadata is cached yet; the GUI fills the cache lazily via
/// `daemon_client::load_snapshot_encryption`.
pub fn kdf_badge_label(badge: Option<&SnapshotEncryptionBadge>) -> String {
    let Some(b) = badge else {
        return "—".to_string();
    };
    if !b.encrypted {
        return "plaintext".to_string();
    }
    match (&b.algorithm, &b.kdf) {
        (Some(algo), Some(kdf)) => format!("{algo} / {kdf}"),
        (Some(algo), None) => algo.clone(),
        (None, Some(kdf)) => kdf.clone(),
        (None, None) => "encrypted".to_string(),
    }
}

fn diff_panel_view(
    diff_a: Option<i64>,
    diff_b: Option<i64>,
    diff: Option<&SnapshotDiffResponse>,
) -> Element<'_, Message> {
    let header_text = match (diff_a, diff_b) {
        (Some(a), Some(b)) => format!("Diff selection: A = #{a}  →  B = #{b}"),
        (Some(a), None) => format!("Diff selection: A = #{a}  (select B to compare)"),
        (None, Some(b)) => format!("Diff selection: B = #{b}  (select A to compare)"),
        (None, None) => "Select two snapshots above to diff their content.".to_string(),
    };

    let mut header_row = row![text(header_text).width(Length::Fill)].spacing(8);
    if let (Some(a), Some(b)) = (diff_a, diff_b) {
        header_row = header_row.push(
            button(text("Run diff"))
                .on_press(Message::SnapshotDiffRequest { id_a: a, id_b: b })
                .style(button::primary),
        );
    }

    let body: Element<'_, Message> = match diff {
        None => text("(no diff loaded)").into(),
        Some(d) => {
            let summary = format!(
                "+{} added   ~{} modified   -{} deleted   ({} byte size delta)",
                d.added.len(),
                d.modified.len(),
                d.deleted.len(),
                d.size_delta_bytes,
            );
            let mut diff_col = column![text(summary)].spacing(2);
            for p in &d.added {
                diff_col = diff_col.push(text(format!("+ {p}")));
            }
            for p in &d.modified {
                diff_col = diff_col.push(text(format!("~ {p}")));
            }
            for p in &d.deleted {
                diff_col = diff_col.push(text(format!("- {p}")));
            }
            scrollable(diff_col).height(Length::Fill).into()
        }
    };

    container(column![header_row, body].spacing(6))
        .padding(8)
        .width(Length::Fill)
        .height(Length::FillPortion(1))
        .into()
}

fn human_size_opt(bytes: Option<u64>) -> String {
    match bytes {
        None => "—".into(),
        Some(b) => human_size(b),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_badge_label_returns_dash_for_missing_badge() {
        assert_eq!(kdf_badge_label(None), "—");
    }

    #[test]
    fn kdf_badge_label_shows_plaintext_for_unencrypted() {
        let b = SnapshotEncryptionBadge {
            encrypted: false,
            algorithm: None,
            kdf: None,
        };
        assert_eq!(kdf_badge_label(Some(&b)), "plaintext");
    }

    #[test]
    fn kdf_badge_label_combines_algo_and_kdf_when_both_present() {
        let b = SnapshotEncryptionBadge {
            encrypted: true,
            algorithm: Some("aes-256-gcm".into()),
            kdf: Some("argon2id".into()),
        };
        assert_eq!(kdf_badge_label(Some(&b)), "aes-256-gcm / argon2id");
    }

    #[test]
    fn kdf_badge_label_falls_back_to_either_field() {
        let only_kdf = SnapshotEncryptionBadge {
            encrypted: true,
            algorithm: None,
            kdf: Some("sha256-1k".into()),
        };
        assert_eq!(kdf_badge_label(Some(&only_kdf)), "sha256-1k");
        let only_algo = SnapshotEncryptionBadge {
            encrypted: true,
            algorithm: Some("aes-256-gcm".into()),
            kdf: None,
        };
        assert_eq!(kdf_badge_label(Some(&only_algo)), "aes-256-gcm");
        let bare = SnapshotEncryptionBadge {
            encrypted: true,
            algorithm: None,
            kdf: None,
        };
        assert_eq!(kdf_badge_label(Some(&bare)), "encrypted");
    }
}
