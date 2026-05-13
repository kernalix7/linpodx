#![forbid(unsafe_code)]

use linpodx_gui::connection::{
    daemon_subscription, load_metrics_for_container, load_session_timeline, send_approval_decision,
    send_image_push, send_snapshot_branch, send_snapshot_diff, send_snapshot_remove,
    send_snapshot_rollback,
};
use linpodx_gui::daemon_client::{
    parse_expiry_input, send_plugin_key_revoke_propagate, send_snapshot_key_rotate,
    send_snapshot_re_encrypt_all, set_sandbox_auto_trigger, set_tofu_expiry,
};
use linpodx_gui::state::{App, Message};
use linpodx_gui::views;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

fn main() -> iced::Result {
    init_tracing();

    let socket = resolve_socket();
    let initial = App::new(socket.clone());

    iced::application("linpodx", update, view)
        .subscription(move |_| daemon_subscription(socket.clone()))
        .run_with(move || (initial.clone(), iced::Task::none()))
}

fn update(app: &mut App, message: Message) -> iced::Task<Message> {
    // Capture intent before mutating: the reducer pops the approval queue on
    // ApprovalDecision, so we need the request_id beforehand.
    let socket = app.socket_path.clone();
    let task = match &message {
        Message::ApprovalDecision {
            request_id,
            allow,
            reason,
        } => iced::Task::perform(
            send_approval_decision(socket.clone(), request_id.clone(), *allow, reason.clone()),
            |m| m,
        ),
        Message::SnapshotRollback(id) => {
            iced::Task::perform(send_snapshot_rollback(socket.clone(), *id), |m| m)
        }
        Message::SnapshotRemove(id) => {
            iced::Task::perform(send_snapshot_remove(socket.clone(), *id), |m| m)
        }
        Message::SnapshotBranch(id) => {
            iced::Task::perform(send_snapshot_branch(socket.clone(), *id), |m| m)
        }
        Message::SnapshotDiffRequest { id_a, id_b } => {
            iced::Task::perform(send_snapshot_diff(socket.clone(), *id_a, *id_b), |m| m)
        }
        Message::SessionSelected(id) => {
            iced::Task::perform(load_session_timeline(socket.clone(), *id), |m| m)
        }
        Message::MetricsContainerSelected(id) => iced::Task::perform(
            load_metrics_for_container(socket.clone(), id.clone()),
            |m| m,
        ),
        Message::ImagePushSubmit => {
            // Snapshot the form before `apply` clears it. If the modal isn't open
            // (shouldn't happen — view only renders Submit when it is) fall through
            // to the no-op task.
            if let Some(form) = app.image_push_form.as_ref() {
                let reference = form.reference.clone();
                let registry = if form.registry.trim().is_empty() {
                    None
                } else {
                    Some(form.registry.trim().to_string())
                };
                let auth = if form.auth.trim().is_empty() {
                    None
                } else {
                    Some(form.auth.trim().to_string())
                };
                iced::Task::perform(
                    send_image_push(socket.clone(), reference, registry, auth),
                    |m| m,
                )
            } else {
                iced::Task::none()
            }
        }
        Message::SnapshotKeyRotateSubmit => {
            if let Some(form) = app.snapshot_key_rotate_form.as_ref() {
                iced::Task::perform(
                    send_snapshot_key_rotate(
                        socket.clone(),
                        form.snapshot_id,
                        form.new_passphrase.clone(),
                    ),
                    |m| m,
                )
            } else {
                iced::Task::none()
            }
        }
        Message::SnapshotReEncryptAllSubmit => {
            if let Some(form) = app.snapshot_re_encrypt_form.as_ref() {
                iced::Task::perform(
                    send_snapshot_re_encrypt_all(socket.clone(), form.new_passphrase.clone()),
                    |m| m,
                )
            } else {
                iced::Task::none()
            }
        }
        Message::TofuExpirySubmit => {
            // Parse the typed input into a normalised seconds value (or `None`
            // to clear). Garbage input is logged and dropped — the modal will
            // re-render on the next status refresh, so the user sees no
            // mysterious silent failure.
            match parse_expiry_input(&app.tofu_expiry_input) {
                Ok(max_age) => iced::Task::perform(set_tofu_expiry(socket.clone(), max_age), |m| m),
                Err(e) => {
                    tracing::warn!(input = %app.tofu_expiry_input, error = %e, "ignored bad tofu expiry input");
                    iced::Task::none()
                }
            }
        }
        Message::PluginKeyRevokeSubmit => {
            if let Some(form) = app.plugin_key_revoke_form.as_ref() {
                iced::Task::perform(
                    send_plugin_key_revoke_propagate(
                        socket.clone(),
                        form.publisher.clone(),
                        form.fingerprint.clone(),
                        None,
                    ),
                    |m| m,
                )
            } else {
                iced::Task::none()
            }
        }
        Message::SandboxAutoTriggerToggle => {
            // The reducer optimistically flips `enabled`; fire the matching IPC
            // with the *new* desired state. Status reloads on the daemon's
            // Sandbox event.
            let next = app
                .sandbox_auto_trigger
                .as_ref()
                .map(|s| !s.enabled)
                .unwrap_or(true);
            iced::Task::perform(set_sandbox_auto_trigger(socket.clone(), next), |m| m)
        }
        _ => iced::Task::none(),
    };
    app.apply(&message);
    task
}

fn view(app: &App) -> iced::Element<'_, Message> {
    views::view(app)
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("warn,linpodx_gui=info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

fn resolve_socket() -> PathBuf {
    if let Ok(s) = std::env::var("LINPODX_SOCKET") {
        return PathBuf::from(s);
    }
    if let Ok(rt) = std::env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(rt).join("linpodx.sock");
    }
    let uid = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| {
                l.strip_prefix("Uid:")
                    .and_then(|rest| rest.split_whitespace().next())
                    .and_then(|n| n.parse::<u32>().ok())
            })
        })
        .unwrap_or(1000);
    PathBuf::from(format!("/tmp/linpodx-{uid}.sock"))
}
