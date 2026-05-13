//! Bench: classify lines from a synthetic `podman diff` output.
//!
//! Mirrors the categorisation logic in `snapshot::parse_diff` (module-private) without
//! reaching into runtime internals — kept self-contained so the bench survives any
//! refactor of the parser.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn classify(output: &str) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut a = Vec::new();
    let mut c = Vec::new();
    let mut d = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim_end();
        let (tag, path) = match trimmed.split_once(char::is_whitespace) {
            Some((t, p)) => (t, p.trim_start()),
            None => continue,
        };
        if path.is_empty() {
            continue;
        }
        match tag {
            "A" => a.push(path.to_string()),
            "C" => c.push(path.to_string()),
            "D" => d.push(path.to_string()),
            _ => {}
        }
    }
    a.sort();
    c.sort();
    d.sort();
    (a, c, d)
}

fn fixture(n: usize) -> String {
    let mut s = String::new();
    for i in 0..n {
        let tag = match i % 3 {
            0 => "A",
            1 => "C",
            _ => "D",
        };
        s.push_str(&format!("{tag} /var/lib/snapshot/path/{i}\n"));
    }
    s
}

fn bench_parse_diff(c: &mut Criterion) {
    let small = fixture(64);
    let large = fixture(2048);
    c.bench_function("snapshot/parse_diff/small", |b| {
        b.iter(|| classify(black_box(&small)))
    });
    c.bench_function("snapshot/parse_diff/large", |b| {
        b.iter(|| classify(black_box(&large)))
    });
}

criterion_group!(benches, bench_parse_diff);
criterion_main!(benches);
