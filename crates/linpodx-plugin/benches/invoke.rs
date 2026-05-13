//! Bench: PluginRegistry construction cost.
//!
//! Loading actual wasm modules requires a wasm32 toolchain which is too heavy for a
//! workspace-wide bench. We measure the wasmtime engine init that the daemon pays on
//! every IPC call (Phase 6 wiring spawns a fresh registry per call).

use criterion::{criterion_group, criterion_main, Criterion};
use linpodx_plugin::PluginRegistry;

fn bench_registry_new(c: &mut Criterion) {
    c.bench_function("plugin/registry/new", |b| {
        b.iter(|| {
            let r = PluginRegistry::new().unwrap();
            assert!(r.is_empty());
        })
    });
}

criterion_group!(benches, bench_registry_new);
criterion_main!(benches);
