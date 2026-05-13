#!/usr/bin/env python3
"""Compare a fresh `cargo bench --quick` run against the committed baseline.

Inputs:
  --baseline   Path to bench-results/linux-x86_64.json (the committed snapshot).
  --new-log    Path to a text file containing the captured stdout+stderr of
               `cargo bench --workspace -- --quick`. We grep criterion's
               "<bench-name>  time:   [low mid high]" output (mid is the mean).
  --threshold  Regression percent to call out in the markdown comment. Default 20.

Outputs (stdout):
  GitHub-flavored markdown with a per-bench delta table. Exit code is always 0
  even when regressions are present; the workflow surfaces the markdown via a
  PR comment rather than failing the build (informational only, see bench.yml).

Why no fail: criterion --quick has a wide confidence interval and CI noise on
shared GitHub runners can push individual benches well past 20%. Hard-failing
on every blip would be a poor signal-to-noise tradeoff. The PR comment lets a
reviewer look without blocking merges.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Matches criterion --quick output lines like:
#   cgroup/parse_usage_usec  time:   [25.157 ns 25.428 ns 26.508 ns]
# When the bench name is too long, criterion wraps and emits
#   <bench-name>
#                         time:   [...]
# The "Benchmarking <name>: Analyzing" line on stderr is the third variant.
# We track the last seen bench-name candidate and pair it with the next time line.
TIME_LINE = re.compile(
    r"time:\s*\[\s*([\d.]+)\s*(ns|µs|us|ms|s)\s+([\d.]+)\s*(ns|µs|us|ms|s)\s+([\d.]+)\s*(ns|µs|us|ms|s)\s*\]"
)
ANALYZING_LINE = re.compile(r"Benchmarking\s+(\S+):\s+Analyzing")
NAMED_TIME_LINE = re.compile(
    r"^([A-Za-z][A-Za-z0-9_./\-]*)\s+time:\s*\[\s*([\d.]+)\s*(ns|µs|us|ms|s)\s+([\d.]+)\s*(ns|µs|us|ms|s)\s+([\d.]+)\s*(ns|µs|us|ms|s)\s*\]"
)
# Bare bench-name line that precedes a wrapped `time:` line. Criterion bench
# names look like `mcp/policy/evaluate/allow` — slash-separated, no spaces.
BARE_NAME_LINE = re.compile(r"^([A-Za-z0-9_./\-]+)\s*$")


def to_ns(value: float, unit: str) -> float:
    if unit == "ns":
        return value
    if unit in ("us", "µs"):
        return value * 1_000.0
    if unit == "ms":
        return value * 1_000_000.0
    if unit == "s":
        return value * 1_000_000_000.0
    raise ValueError(f"unknown unit {unit!r}")


def parse_log(text: str) -> dict[str, float]:
    """Return {bench_name: mean_ns}. The mean is the middle value of the [low mid high] triple."""
    means: dict[str, float] = {}
    pending_name: str | None = None
    for line in text.splitlines():
        m = ANALYZING_LINE.search(line)
        if m:
            pending_name = m.group(1)
            continue

        m = NAMED_TIME_LINE.match(line)
        if m:
            name = m.group(1).strip()
            mid_val = float(m.group(4))
            mid_unit = m.group(5)
            means[name] = to_ns(mid_val, mid_unit)
            pending_name = None
            continue

        m = TIME_LINE.search(line)
        if m and pending_name:
            mid_val = float(m.group(3))
            mid_unit = m.group(4)
            means[pending_name] = to_ns(mid_val, mid_unit)
            pending_name = None
            continue

        m = BARE_NAME_LINE.match(line)
        if m and "/" in m.group(1):
            # Looks like a bench name on its own line. Hold it for the next time line.
            pending_name = m.group(1)
    return means


def fmt_ns(ns: float) -> str:
    if ns < 1_000:
        return f"{ns:.2f} ns"
    if ns < 1_000_000:
        return f"{ns / 1_000:.2f} µs"
    if ns < 1_000_000_000:
        return f"{ns / 1_000_000:.2f} ms"
    return f"{ns / 1_000_000_000:.2f} s"


def render_markdown(
    baseline: dict[str, float],
    new: dict[str, float],
    threshold_pct: float,
) -> str:
    lines: list[str] = []
    lines.append("## linpodx bench (criterion --quick)")
    lines.append("")
    lines.append("Comparison against `bench-results/linux-x86_64.json`. Informational only — CI does not fail on regression.")
    lines.append("")
    lines.append("| bench | baseline | new | Δ |")
    lines.append("| --- | --- | --- | --- |")

    seen: set[str] = set()
    regressions: list[str] = []
    for name in sorted(baseline.keys()):
        seen.add(name)
        base_ns = baseline[name]
        if name not in new:
            lines.append(f"| `{name}` | {fmt_ns(base_ns)} | — | _missing_ |")
            continue
        new_ns = new[name]
        delta_pct = ((new_ns - base_ns) / base_ns) * 100.0 if base_ns > 0 else 0.0
        marker = ""
        if delta_pct >= threshold_pct:
            marker = " ⚠️"
            regressions.append(f"{name} ({delta_pct:+.1f}%)")
        elif delta_pct <= -threshold_pct:
            marker = " ✅"
        lines.append(
            f"| `{name}` | {fmt_ns(base_ns)} | {fmt_ns(new_ns)} | {delta_pct:+.1f}%{marker} |"
        )

    extras = sorted(set(new.keys()) - seen)
    for name in extras:
        lines.append(f"| `{name}` | — | {fmt_ns(new[name])} | _new_ |")

    lines.append("")
    if regressions:
        lines.append(
            f"⚠️ {len(regressions)} bench(es) regressed by ≥{threshold_pct:.0f}%: "
            + ", ".join(regressions)
        )
    else:
        lines.append(f"No regressions ≥{threshold_pct:.0f}% detected.")

    return "\n".join(lines) + "\n"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--baseline", type=Path, required=True)
    p.add_argument("--new-log", type=Path, required=True)
    p.add_argument("--threshold", type=float, default=20.0)
    args = p.parse_args()

    baseline_doc = json.loads(args.baseline.read_text())
    baseline = {
        name: float(entry["mean_ns"])
        for name, entry in baseline_doc.get("benches", {}).items()
    }
    new = parse_log(args.new_log.read_text(errors="replace"))

    if not new:
        sys.stderr.write(
            "no bench results parsed from new-log; was 'cargo bench --quick' actually run?\n"
        )

    md = render_markdown(baseline, new, args.threshold)
    sys.stdout.write(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
