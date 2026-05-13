use crate::state::Message;
use iced::widget::{column, row, text};
use iced::{Element, Length};
use linpodx_common::state::NetworkSummary;

pub fn view(networks: &[NetworkSummary]) -> Element<'_, Message> {
    if networks.is_empty() {
        return text("No networks. Create one with: linpodx network create my-net").into();
    }

    let header = row![
        text("ID").width(Length::FillPortion(2)),
        text("NAME").width(Length::FillPortion(2)),
        text("DRIVER").width(Length::FillPortion(1)),
        text("SUBNET").width(Length::FillPortion(2)),
    ]
    .spacing(8);

    let mut col = column![header].spacing(4);
    for n in networks {
        let id_short = if n.id.as_str().len() > 16 {
            &n.id.as_str()[..16]
        } else {
            n.id.as_str()
        };
        col = col.push(
            row![
                text(id_short.to_string()).width(Length::FillPortion(2)),
                text(n.name.clone()).width(Length::FillPortion(2)),
                text(n.driver.clone()).width(Length::FillPortion(1)),
                text(n.subnet.clone().unwrap_or_else(|| "-".to_string()))
                    .width(Length::FillPortion(2)),
            ]
            .spacing(8),
        );
    }
    col.into()
}
