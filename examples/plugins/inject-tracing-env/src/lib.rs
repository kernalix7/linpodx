//! Sample linpodx `runtime_injector` plugin.
//!
//! Appends two OpenTelemetry env vars (`OTEL_SERVICE_NAME` + `OTEL_EXPORTER_OTLP_ENDPOINT`)
//! to every container the daemon is about to create. The plugin doesn't touch args or
//! security_opts — the registry merges its `InjectorPayload` with whatever other
//! injector plugins return.
//!
//! `unsafe` is required to talk to the host across `extern "C"` and raw pointer math
//! against linear memory.
#![allow(unsafe_code)]

extern "C" {
    fn host_log(level: i32, ptr: i32, len: i32);
    fn host_return_injector_payload(ptr: i32, len: i32);
}

const PAYLOAD_JSON: &str = concat!(
    r#"{"env_add":[["OTEL_SERVICE_NAME","linpodx"],"#,
    r#"["OTEL_EXPORTER_OTLP_ENDPOINT","http://localhost:4317"]],"#,
    r#""args_append":[],"security_opts_add":[]}"#,
);

fn log(msg: &str) {
    let bytes = msg.as_bytes();
    unsafe {
        host_log(1, bytes.as_ptr() as i32, bytes.len() as i32);
    }
}

fn return_payload(bytes: &[u8]) {
    unsafe {
        host_return_injector_payload(bytes.as_ptr() as i32, bytes.len() as i32);
    }
}

#[no_mangle]
pub extern "C" fn evaluate_runtime_injector() {
    log("inject-tracing-env: appending OTEL_SERVICE_NAME + OTEL_EXPORTER_OTLP_ENDPOINT");
    return_payload(PAYLOAD_JSON.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::PAYLOAD_JSON;

    #[test]
    fn payload_parses_back_to_two_env_vars() {
        // Sanity: the inline JSON is valid and contains both expected entries.
        assert!(PAYLOAD_JSON.contains("OTEL_SERVICE_NAME"));
        assert!(PAYLOAD_JSON.contains("OTEL_EXPORTER_OTLP_ENDPOINT"));
        assert!(PAYLOAD_JSON.contains("http://localhost:4317"));
    }
}
