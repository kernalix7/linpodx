//! Sample linpodx `profile_validator` plugin.
//!
//! Rejects every sandbox profile whose YAML body does not contain `read_only_rootfs:
//! true`. The check is a deliberate substring match — robust YAML parsing belongs in the
//! sandbox crate, not in a wasm plugin. The point of the sample is to demonstrate the
//! `profile_validator` ABI; production validators can layer real parsing on top.
//!
//! Decision codes (must match `host_return_validator_decision_impl` in linpodx-plugin):
//!   * 0 = Pass
//!   * 1 = Reject (with reason — surfaced in the `ProfileValidatorRejected` audit row)
//!
//! `unsafe` is required to talk to the host across `extern "C"` and raw pointer math
//! against linear memory.
#![allow(unsafe_code)]

extern "C" {
    fn host_log(level: i32, ptr: i32, len: i32);
    fn host_get_payload(ptr: i32, max: i32) -> i32;
    fn host_return_validator_decision(decision: i32, reason_ptr: i32, reason_len: i32);
}

const PASS: i32 = 0;
const REJECT: i32 = 1;

const REQUIRED_DIRECTIVE: &str = "read_only_rootfs: true";

fn log(msg: &str) {
    let bytes = msg.as_bytes();
    unsafe {
        host_log(1, bytes.as_ptr() as i32, bytes.len() as i32);
    }
}

fn return_decision(decision: i32, reason: &str) {
    let bytes = reason.as_bytes();
    unsafe {
        host_return_validator_decision(decision, bytes.as_ptr() as i32, bytes.len() as i32);
    }
}

fn read_payload() -> Vec<u8> {
    let needed = unsafe { host_get_payload(0, 0) };
    if needed <= 0 {
        return Vec::new();
    }
    let mut buf = vec![0u8; needed as usize];
    let copied = unsafe { host_get_payload(buf.as_mut_ptr() as i32, needed) };
    if copied < 0 {
        return Vec::new();
    }
    buf.truncate(copied as usize);
    buf
}

/// Returns `true` when `yaml` contains `read_only_rootfs: true` outside any commented-out
/// line. We strip leading whitespace + `#`-prefixed lines before checking so a
/// commented-out directive doesn't satisfy the validator.
fn has_readonly_rootfs(yaml: &str) -> bool {
    yaml.lines()
        .map(|line| line.split_once('#').map(|(l, _)| l).unwrap_or(line))
        .any(|line| line.trim_start().contains(REQUIRED_DIRECTIVE))
}

#[no_mangle]
pub extern "C" fn evaluate_profile_validator() {
    let payload = read_payload();
    let body = match std::str::from_utf8(&payload) {
        Ok(s) => s,
        Err(_) => {
            log("require-readonly-rootfs: non-utf8 yaml — rejecting");
            return_decision(REJECT, "profile yaml is not valid UTF-8");
            return;
        }
    };
    if has_readonly_rootfs(body) {
        return_decision(PASS, "read_only_rootfs: true present");
    } else {
        return_decision(
            REJECT,
            "profile must set read_only_rootfs: true (require-readonly-rootfs plugin)",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_profile_with_readonly_rootfs() {
        let yaml = "version: 1\nname: locked\nread_only_rootfs: true\n";
        assert!(has_readonly_rootfs(yaml));
    }

    #[test]
    fn rejects_profile_without_directive() {
        let yaml = "version: 1\nname: open\n";
        assert!(!has_readonly_rootfs(yaml));
    }

    #[test]
    fn rejects_profile_with_directive_only_in_comment() {
        let yaml = "version: 1\nname: tricky\n# read_only_rootfs: true\n";
        assert!(!has_readonly_rootfs(yaml));
    }

    #[test]
    fn rejects_profile_with_directive_set_false() {
        let yaml = "version: 1\nname: writable\nread_only_rootfs: false\n";
        assert!(!has_readonly_rootfs(yaml));
    }
}
