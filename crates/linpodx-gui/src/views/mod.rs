use crate::state::{App, ConnectionState, Message, Tab};
use iced::widget::{button, column, container, row, scrollable, stack, text};
use iced::{Element, Length};

pub mod approval_modal;
pub mod audit;
pub mod containers;
pub mod images;
pub mod metrics;
pub mod networks;
pub mod pinned_clients;
pub mod plugins;
pub mod sandbox;
pub mod session;
pub mod snapshot;
pub mod volumes;

pub fn view(app: &App) -> Element<'_, Message> {
    let header = tab_bar(app.tab);
    let banner = connection_banner(&app.conn);
    let body: Element<'_, Message> = match app.tab {
        Tab::Containers => containers::view(&app.containers),
        Tab::Images => images::view(&app.images, app.image_push_form.as_ref()),
        Tab::Volumes => volumes::view(&app.volumes),
        Tab::Networks => networks::view(&app.networks),
        Tab::Sandbox => sandbox::view(
            &app.sandbox_profiles,
            app.selected_sandbox_profile.as_deref(),
            app.sandbox_auto_trigger.as_ref(),
        ),
        Tab::Audit => audit::view(&app.audit_entries, app.audit_filter_kind.as_deref()),
        Tab::Snapshot => snapshot::view(
            &app.snapshots,
            app.snapshot_diff_a,
            app.snapshot_diff_b,
            app.snapshot_diff.as_ref(),
            &app.snapshot_encryption_badges,
            app.snapshot_key_rotate_form.as_ref(),
            app.snapshot_re_encrypt_form.as_ref(),
        ),
        Tab::Session => session::view(&app.sessions, app.selected_session, &app.session_timeline),
        Tab::Metrics => metrics::view(
            &app.containers,
            app.metrics_selected.as_deref(),
            &app.metrics_samples,
        ),
        Tab::PinnedClients => {
            pinned_clients::view(app.tofu_expiry.as_ref(), &app.tofu_expiry_input)
        }
        Tab::Plugins => plugins::view(
            &app.plugin_keys,
            &app.plugin_key_revoke_state,
            app.plugin_key_revoke_form.as_ref(),
        ),
    };

    let content = column![header, banner, scrollable(body).height(Length::Fill)]
        .spacing(8)
        .padding(12);

    let base: Element<'_, Message> = container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .into();

    if let Some(req) = app.pending_approvals.front() {
        // Overlay the modal above the rest of the app.
        let overlay = approval_modal::modal(req, &app.approval_reason);
        stack![base, overlay].into()
    } else {
        base
    }
}

fn tab_bar(active: Tab) -> Element<'static, Message> {
    let mut bar = row![].spacing(6);
    for &tab in &Tab::ALL {
        let label = tab.label();
        let mut btn = button(text(label));
        if tab == active {
            btn = btn.style(button::primary);
        } else {
            btn = btn.style(button::secondary);
        }
        bar = bar.push(btn.on_press(Message::TabSelected(tab)));
    }
    bar.into()
}

fn connection_banner(conn: &ConnectionState) -> Element<'static, Message> {
    let label = match conn {
        ConnectionState::Connected => return container(text("")).height(Length::Fixed(0.0)).into(),
        ConnectionState::Connecting => "Connecting to daemon…".to_string(),
        ConnectionState::Disconnected(reason) => format!("Disconnected: {reason} — retrying…"),
    };
    container(text(label).size(14))
        .padding(8)
        .style(|_theme: &iced::Theme| iced::widget::container::Style {
            background: Some(iced::Color::from_rgb(0.85, 0.25, 0.25).into()),
            text_color: Some(iced::Color::WHITE),
            border: iced::Border {
                radius: 4.0.into(),
                ..Default::default()
            },
            ..iced::widget::container::Style::default()
        })
        .width(Length::Fill)
        .into()
}
