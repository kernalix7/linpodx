// Shared test-support module compiled independently into each `tests/e2e_*.rs`
// integration-test binary; not every binary uses every helper here, so a
// per-binary `dead_code` lint would false-positive depending on which test
// file happens to call which helper.
#![allow(dead_code)]

use assert_cmd::Command as AssertCommand;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::time::Duration;

pub const TEST_IMAGE: &str = "docker.io/library/alpine:latest";

const IMAGE_PULL_TIMEOUT: Duration = Duration::from_secs(60);
const IMAGE_INSPECT_TIMEOUT: Duration = Duration::from_secs(10);
const PODMAN_CHECK_TIMEOUT: Duration = Duration::from_secs(10);

pub fn host_podman_available() -> bool {
    let mut cmd = Command::new("podman");
    cmd.arg("--version");
    match status_with_timeout(cmd, PODMAN_CHECK_TIMEOUT) {
        Ok(Some(status)) if status.success() => true,
        Ok(Some(status)) => {
            eprintln!("skipping: podman is not usable on this host (status {status})");
            false
        }
        Ok(None) => {
            eprintln!(
                "skipping: podman --version timed out after {}s",
                PODMAN_CHECK_TIMEOUT.as_secs()
            );
            false
        }
        Err(err) => {
            eprintln!("skipping: podman --version could not run: {err}");
            false
        }
    }
}

pub fn ensure_daemon_test_image(socket: &Path) -> bool {
    let mut inspect = cli_command(socket);
    inspect.args(["images", "inspect", TEST_IMAGE]);
    if matches!(status_with_timeout(inspect, IMAGE_INSPECT_TIMEOUT), Ok(Some(status)) if status.success())
    {
        return true;
    }

    pull_daemon_test_image(socket).is_some()
}

pub fn pull_daemon_test_image(socket: &Path) -> Option<String> {
    let mut pull = cli_command(socket);
    pull.args(["images", "pull", TEST_IMAGE]);
    match status_with_timeout(pull, IMAGE_PULL_TIMEOUT) {
        Ok(Some(status)) if status.success() => Some(TEST_IMAGE.to_string()),
        Ok(Some(status)) => {
            eprintln!("skipping: image pull failed for {TEST_IMAGE} (status {status})");
            None
        }
        Ok(None) => {
            eprintln!(
                "skipping: image pull for {TEST_IMAGE} timed out after {}s",
                IMAGE_PULL_TIMEOUT.as_secs()
            );
            None
        }
        Err(err) => {
            eprintln!("skipping: image pull for {TEST_IMAGE} could not run: {err}");
            None
        }
    }
}

/// Drains a piped child's stdout/stderr on background threads and discards
/// the bytes.
///
/// Every `spawn_daemon()` in these `tests/e2e_*.rs` files runs the daemon
/// with `Stdio::piped()` stdout/stderr (so a failing test's `DaemonGuard`
/// output is available on `--nocapture`), but none of them ever calls
/// `.read()` on those handles during the test body — only `Drop` runs, and
/// it just kills + waits. A Linux pipe's kernel buffer is 64 KiB; the daemon
/// runs with `RUST_LOG=info,linpodx=debug` here, and its `#[instrument]`
/// spans plus `debug!(?cmd, ...)` podman-invocation logging can produce more
/// than that over a single test (e.g. `images_lifecycle`'s pull + inspect +
/// rm sequence). Once the pipe fills, the daemon blocks forever inside
/// `write()` the next time it tries to log anything — including the log
/// line for the very IPC call the test is waiting on — which hangs the CLI,
/// the test, and (under `--test-threads=1`) the entire ignored e2e sweep.
///
/// Call this immediately after `Command::spawn()` for any child spawned
/// with piped stdio, before constructing the `Drop` guard.
pub fn drain_piped_output(child: &mut std::process::Child) {
    if let Some(mut stdout) = child.stdout.take() {
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut stdout, &mut std::io::sink());
        });
    }
    if let Some(mut stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut stderr, &mut std::io::sink());
        });
    }
}

fn cli_command(socket: &Path) -> Command {
    let bin = AssertCommand::cargo_bin("linpodx")
        .expect("locate linpodx")
        .get_program()
        .to_owned();
    let mut cmd = Command::new(bin);
    cmd.arg("--socket").arg(socket);
    cmd
}

fn status_with_timeout(mut cmd: Command, timeout: Duration) -> std::io::Result<Option<ExitStatus>> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = cmd.spawn()?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
