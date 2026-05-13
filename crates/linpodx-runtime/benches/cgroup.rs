//! Bench: cgroup v2 fixture parsing — `cpu.stat` + `/proc/<pid>/cgroup`.
//!
//! Mirrors the private `parse_usage_usec` and `parse_cgroup_v2_path` helpers in
//! `metrics.rs` without depending on the host actually having cgroup v2 mounted.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn parse_usage_usec(cpu_stat: &str) -> Option<u64> {
    for line in cpu_stat.lines() {
        if let Some(rest) = line.strip_prefix("usage_usec ") {
            return rest.trim().parse::<u64>().ok();
        }
    }
    None
}

fn parse_cgroup_v2_path(raw: &str) -> Option<String> {
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("0::") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

const CPU_STAT: &str = "usage_usec 12345678901\nuser_usec 9000000000\nsystem_usec 3000000000\nnr_periods 50\nnr_throttled 0\nthrottled_usec 0\n";
const CGROUP_FILE: &str = "1:name=systemd:/user.slice/user-1000.slice/session-3.scope\n0::/user.slice/user-1000.slice/user@1000.service/app.slice/podman-12345.scope\n";

fn bench_cgroup_parsers(c: &mut Criterion) {
    c.bench_function("cgroup/parse_usage_usec", |b| {
        b.iter(|| parse_usage_usec(black_box(CPU_STAT)))
    });
    c.bench_function("cgroup/parse_v2_path", |b| {
        b.iter(|| parse_cgroup_v2_path(black_box(CGROUP_FILE)))
    });
}

criterion_group!(benches, bench_cgroup_parsers);
criterion_main!(benches);
