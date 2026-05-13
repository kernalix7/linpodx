use crate::state::Message;
use iced::widget::{button, column, row, text};
use iced::{Element, Length};
use linpodx_common::state::ContainerSummary;

pub fn view(containers: &[ContainerSummary]) -> Element<'_, Message> {
    if containers.is_empty() {
        return text("No containers. Run one with: linpodx run --name demo alpine sleep 30").into();
    }

    let header = row![
        text("ID").width(Length::FillPortion(2)),
        text("NAME").width(Length::FillPortion(2)),
        text("IMAGE").width(Length::FillPortion(3)),
        text("STATE").width(Length::FillPortion(1)),
        text("STATUS").width(Length::FillPortion(2)),
        text("ACTIONS").width(Length::FillPortion(2)),
    ]
    .spacing(8);

    let mut col = column![header].spacing(4);
    for c in containers {
        let id_short = if c.id.as_str().len() > 12 {
            &c.id.as_str()[..12]
        } else {
            c.id.as_str()
        };
        let name = c.names.first().map(String::as_str).unwrap_or("");
        let id_owned = c.id.as_str().to_string();
        let exec_id = id_owned.clone();
        let logs_id = id_owned.clone();
        let actions = row![
            button(text("Exec")).on_press(Message::ExecRequested(exec_id)),
            button(text("Logs")).on_press(Message::LogsRequested(logs_id)),
        ]
        .spacing(4)
        .width(Length::FillPortion(2));
        col = col.push(
            row![
                text(id_short.to_string()).width(Length::FillPortion(2)),
                text(name.to_string()).width(Length::FillPortion(2)),
                text(c.image.clone()).width(Length::FillPortion(3)),
                text(c.state.to_string()).width(Length::FillPortion(1)),
                text(c.status.clone()).width(Length::FillPortion(2)),
                actions,
            ]
            .spacing(8),
        );
    }
    col.into()
}
