use crate::state::Message;
use iced::widget::{column, row, text};
use iced::{Element, Length};
use linpodx_common::state::VolumeSummary;

pub fn view(volumes: &[VolumeSummary]) -> Element<'_, Message> {
    if volumes.is_empty() {
        return text("No volumes. Create one with: linpodx volume create my-data").into();
    }

    let header = row![
        text("NAME").width(Length::FillPortion(2)),
        text("DRIVER").width(Length::FillPortion(1)),
        text("MOUNTPOINT").width(Length::FillPortion(5)),
    ]
    .spacing(8);

    let mut col = column![header].spacing(4);
    for v in volumes {
        col = col.push(
            row![
                text(v.name.as_str().to_string()).width(Length::FillPortion(2)),
                text(v.driver.clone()).width(Length::FillPortion(1)),
                text(v.mountpoint.clone()).width(Length::FillPortion(5)),
            ]
            .spacing(8),
        );
    }
    col.into()
}
