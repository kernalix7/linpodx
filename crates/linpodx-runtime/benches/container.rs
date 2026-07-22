//! Bench: serde round-trip for [`ContainerSummary`] — IPC hot path.

use chrono::Utc;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use linpodx_common::state::{ContainerState, ContainerSummary};
use linpodx_common::types::ContainerId;

fn fixture() -> ContainerSummary {
    ContainerSummary {
        id: ContainerId::from("abc1234567890def"),
        names: vec!["happy_test".into(), "alt_name".into()],
        image: "docker.io/library/alpine:latest".into(),
        state: ContainerState::Running,
        status: "Up 5 seconds".into(),
        created: Utc::now(),
        command: Some("sleep infinity".into()),
        ports: vec!["8080->80/tcp".into(), "9090->90/tcp".into()],
        labels: Default::default(),
    }
}

fn bench_roundtrip(c: &mut Criterion) {
    let s = fixture();
    let json = serde_json::to_string(&s).unwrap();
    c.bench_function("container/serialize", |b| {
        b.iter(|| serde_json::to_string(black_box(&s)).unwrap())
    });
    c.bench_function("container/deserialize", |b| {
        b.iter(|| {
            let _: ContainerSummary = serde_json::from_str(black_box(&json)).unwrap();
        })
    });
}

criterion_group!(benches, bench_roundtrip);
criterion_main!(benches);
