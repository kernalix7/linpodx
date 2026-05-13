use crate::state::Message;
use iced::widget::{button, column, container, row, scrollable, text, Column};
use iced::{Element, Length};
use linpodx_common::ipc::MetricsSample;
use linpodx_common::state::ContainerSummary;
use std::collections::HashMap;

const SPARK_GLYPHS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
const SPARK_WIDTH: usize = 60;

pub fn view<'a>(
    containers: &'a [ContainerSummary],
    selected: Option<&'a str>,
    samples: &'a HashMap<String, Vec<MetricsSample>>,
) -> Element<'a, Message> {
    if containers.is_empty() {
        return text("No containers. Start one with: linpodx container start <name>").into();
    }

    let mut picker: Column<'_, Message> =
        column![text("Containers").size(16)].spacing(4).padding(4);
    for c in containers {
        let label = c
            .names
            .first()
            .cloned()
            .unwrap_or_else(|| c.id.as_str().to_string());
        let id = c.id.as_str().to_string();
        let active = selected == Some(id.as_str());
        let style = if active {
            button::primary
        } else {
            button::secondary
        };
        picker = picker.push(
            button(text(label))
                .on_press(Message::MetricsContainerSelected(id.clone()))
                .style(style)
                .width(Length::Fill),
        );
    }

    let active_id: Option<String> = selected
        .map(str::to_string)
        .or_else(|| containers.first().map(|c| c.id.as_str().to_string()));

    let detail: Element<'_, Message> = match active_id {
        None => text("Pick a container.").into(),
        Some(id) => {
            let series = samples.get(&id).cloned().unwrap_or_default();
            sample_panel(id, series)
        }
    };

    row![
        container(scrollable(picker))
            .width(Length::FillPortion(1))
            .height(Length::Fill),
        container(detail)
            .padding(8)
            .width(Length::FillPortion(3))
            .height(Length::Fill),
    ]
    .spacing(8)
    .into()
}

fn sample_panel(container_id: String, samples: Vec<MetricsSample>) -> Element<'static, Message> {
    if samples.is_empty() {
        return column![
            text(format!("Container: {container_id}")).size(16),
            text("(no samples yet — waiting for the collector to publish)"),
        ]
        .spacing(6)
        .into();
    }
    let last = samples.last().expect("non-empty").clone();
    let cpu_values: Vec<f64> = samples.iter().map(|s| s.cpu_pct).collect();
    let mem_values: Vec<f64> = samples.iter().map(|s| s.mem_bytes as f64).collect();

    let cpu_line = format!(
        "CPU      {:>6.2}% of one core   {}",
        last.cpu_pct * 100.0,
        sparkline(&cpu_values, SPARK_WIDTH),
    );
    let mem_line = format!(
        "Memory   {:>10}    {}",
        format_bytes(last.mem_bytes),
        sparkline(&mem_values, SPARK_WIDTH),
    );
    let net_line = format!(
        "Net      rx {:>10}    tx {:>10}",
        format_bytes(last.net_rx),
        format_bytes(last.net_tx),
    );
    let block_line = format!(
        "Block    in {:>10}    out {:>10}",
        format_bytes(last.block_in),
        format_bytes(last.block_out),
    );

    column![
        text(format!("Container: {container_id}")).size(16),
        text(format!(
            "{} samples | last @ {}",
            samples.len(),
            last.ts.to_rfc3339()
        )),
        text(cpu_line),
        text(mem_line),
        text(net_line),
        text(block_line),
    ]
    .spacing(6)
    .into()
}

/// Render a series of values as a unicode bar sparkline of fixed character `width`. Last
/// `width` values are shown; missing leading samples render as the lowest glyph.
fn sparkline(values: &[f64], width: usize) -> String {
    if values.is_empty() || width == 0 {
        return String::new();
    }
    let take = values.len().min(width);
    let slice = &values[values.len() - take..];
    let max = slice.iter().cloned().fold(0.0_f64, f64::max);
    if max <= 0.0 {
        return SPARK_GLYPHS[0].to_string().repeat(take);
    }
    let bins = (SPARK_GLYPHS.len() - 1) as f64;
    slice
        .iter()
        .map(|v| {
            let scaled = (v / max).clamp(0.0, 1.0);
            let idx = (scaled * bins).round() as usize;
            SPARK_GLYPHS[idx]
        })
        .collect()
}

fn format_bytes(b: u64) -> String {
    const KB: u64 = 1_000;
    const MB: u64 = 1_000_000;
    const GB: u64 = 1_000_000_000;
    if b >= GB {
        format!("{:.2} GB", b as f64 / GB as f64)
    } else if b >= MB {
        format!("{:.2} MB", b as f64 / MB as f64)
    } else if b >= KB {
        format!("{:.2} kB", b as f64 / KB as f64)
    } else {
        format!("{b} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparkline_handles_empty_and_zero() {
        assert_eq!(sparkline(&[], 10), "");
        assert_eq!(sparkline(&[0.0, 0.0, 0.0], 3), "▁▁▁");
    }

    #[test]
    fn sparkline_scales_to_max() {
        let s = sparkline(&[0.0, 0.5, 1.0], 3);
        let chars: Vec<char> = s.chars().collect();
        assert_eq!(chars.len(), 3);
        assert_eq!(chars[0], SPARK_GLYPHS[0]);
        assert_eq!(chars[2], SPARK_GLYPHS[SPARK_GLYPHS.len() - 1]);
    }

    #[test]
    fn sparkline_caps_to_width() {
        let values: Vec<f64> = (0..100).map(|i| i as f64).collect();
        let s = sparkline(&values, 10);
        assert_eq!(s.chars().count(), 10);
    }

    #[test]
    fn format_bytes_basic() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(900), "900 B");
        assert_eq!(format_bytes(1_500), "1.50 kB");
        assert_eq!(format_bytes(2_500_000), "2.50 MB");
        assert_eq!(format_bytes(3_500_000_000), "3.50 GB");
    }
}
