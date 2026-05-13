use crate::state::Message;
use iced::widget::{column, pick_list, row, scrollable, text, Column};
use iced::{Element, Length};
use linpodx_common::ipc::responses::AuditEntrySummary;
use std::collections::BTreeSet;

pub fn view<'a>(
    entries: &'a [AuditEntrySummary],
    filter_kind: Option<&'a str>,
) -> Element<'a, Message> {
    let kinds: BTreeSet<String> = entries.iter().map(|e| e.kind.clone()).collect();
    let mut options: Vec<FilterOption> = vec![FilterOption::All];
    options.extend(kinds.into_iter().map(FilterOption::Kind));

    let selected = match filter_kind {
        None => FilterOption::All,
        Some(k) => FilterOption::Kind(k.to_string()),
    };

    let filter_row = row![
        text("Filter kind:"),
        pick_list(options, Some(selected), |opt| match opt {
            FilterOption::All => Message::AuditFilterChanged(None),
            FilterOption::Kind(k) => Message::AuditFilterChanged(Some(k)),
        }),
    ]
    .spacing(8);

    if entries.is_empty() {
        return column![filter_row, text("No audit entries.")]
            .spacing(8)
            .into();
    }

    let header = row![
        text("SEQ").width(Length::FillPortion(1)),
        text("TIMESTAMP").width(Length::FillPortion(3)),
        text("KIND").width(Length::FillPortion(2)),
        text("PROFILE").width(Length::FillPortion(2)),
        text("CONTAINER").width(Length::FillPortion(2)),
        text("PAYLOAD").width(Length::FillPortion(5)),
    ]
    .spacing(8);

    let mut col: Column<'_, Message> = column![header].spacing(4);
    for e in entries {
        if let Some(k) = filter_kind {
            if e.kind != k {
                continue;
            }
        }
        col = col.push(
            row![
                text(e.seq.to_string()).width(Length::FillPortion(1)),
                text(e.ts.to_rfc3339()).width(Length::FillPortion(3)),
                text(e.kind.clone()).width(Length::FillPortion(2)),
                text(e.profile_name.clone().unwrap_or_default()).width(Length::FillPortion(2)),
                text(short_id(e.container_id.as_deref())).width(Length::FillPortion(2)),
                text(payload_summary(&e.payload)).width(Length::FillPortion(5)),
            ]
            .spacing(8),
        );
    }

    column![filter_row, scrollable(col).height(Length::Fill)]
        .spacing(8)
        .into()
}

fn short_id(id: Option<&str>) -> String {
    match id {
        None => "".into(),
        Some(s) if s.len() > 12 => s[..12].to_string(),
        Some(s) => s.to_string(),
    }
}

fn payload_summary(value: &serde_json::Value) -> String {
    let s = value.to_string();
    if s.len() > 120 {
        format!("{}…", &s[..120])
    } else {
        s
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FilterOption {
    All,
    Kind(String),
}

impl std::fmt::Display for FilterOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FilterOption::All => f.write_str("(all)"),
            FilterOption::Kind(k) => f.write_str(k),
        }
    }
}
