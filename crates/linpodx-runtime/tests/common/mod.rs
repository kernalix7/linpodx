use linpodx_runtime::podman::Podman;
use std::time::Duration;

pub const TEST_IMAGE: &str = "docker.io/library/alpine:latest";

const IMAGE_PULL_TIMEOUT: Duration = Duration::from_secs(60);

pub async fn podman_available(podman: &Podman) -> bool {
    match podman.check().await {
        Ok(_) => true,
        Err(err) => {
            eprintln!("skipping: podman not available ({err})");
            false
        }
    }
}

pub async fn ensure_runtime_test_image(podman: &Podman) -> bool {
    match tokio::time::timeout(IMAGE_PULL_TIMEOUT, podman.pull(TEST_IMAGE)).await {
        Ok(Ok(())) => true,
        Ok(Err(err)) => {
            eprintln!("skipping: image pull failed for {TEST_IMAGE}: {err}");
            false
        }
        Err(_) => {
            eprintln!(
                "skipping: image pull for {TEST_IMAGE} timed out after {}s",
                IMAGE_PULL_TIMEOUT.as_secs()
            );
            false
        }
    }
}
