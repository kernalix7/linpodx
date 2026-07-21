# Contributing to linpodx

**English** | [한국어](docs/CONTRIBUTING.ko.md)

Thanks for your interest in contributing to linpodx.

## Development Setup

### Prerequisites

- Linux (Wayland or X11). The toolchain is Linux-only by design.
- Podman ≥ 4.6.0 (rootless preferred). Some snapshot integration tests want ≥ 5.0.
- Rust stable toolchain (≥ 1.85). `rust-toolchain.toml` pins this for you when you
  run `cargo` in the repo root.
- `rustfmt` + `clippy` components (requested automatically by `rust-toolchain.toml`).
- For GUI development: no extra system deps beyond a working Wayland/X11 session —
  iced ships pure-Rust rendering via wgpu.
- For Web UI / WASM plugin work: `rustup target add wasm32-unknown-unknown`.

### Build

```bash
git clone https://github.com/kernalix7/linpodx.git
cd linpodx
cargo build --workspace
```

First build is slow — the iced + wasmtime + axum + sqlx graph is large. Cached after
that.

### Run the daemon and CLI locally

```bash
cargo run -p linpodx-daemon &
cargo run -p linpodx-cli -- ps
cargo run -p linpodx-cli -- events
```

The daemon listens on `$XDG_RUNTIME_DIR/linpodx.sock` by default. Stop it with
`fg` + `Ctrl-C`.

## Test

### Unit tests (always run)

```bash
cargo test --workspace
```

### Integration tests (Podman required)

Integration tests that talk to a real Podman are gated with `#[ignore]` so the
default `cargo test` run stays hermetic. Install Podman 4.6.0 or newer (see
[docs/INSTALL.md](docs/INSTALL.md) for distro instructions), then run them
explicitly:

```bash
cargo test --workspace -- --ignored --test-threads=1
```

`--test-threads=1` is mandatory — multiple integration tests touching the same Podman
socket will race.

Cross-crate integration tests live under the workspace-level `tests/` crate.
Crate-local integration tests live under `crates/<crate>/tests/`. Both run from
the same `cargo test --workspace` command.

Snapshot-encryption integration tests honour the same environment variables the
daemon does (`LINPODX_SNAPSHOT_ENCRYPT_PASSPHRASE`, `LINPODX_SNAPSHOT_KEY`,
`LINPODX_SNAPSHOT_KDF`). Tests that need encryption set these variables on the
spawned daemon, not on the test process itself.

### Lint

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

`-D warnings` is required for CI to pass. Treat clippy hints as actionable.

### Docs

```bash
RUSTDOCFLAGS="-D rustdoc::broken-intra-doc-links -D warnings" \
  cargo doc --workspace --no-deps
```

Broken intra-doc links fail the doc build.

### Benches

Workspace benches are criterion-based and live under `crates/<crate>/benches/`.

```bash
# All benches, quick mode
cargo bench -p linpodx-runtime --bench snapshot --bench container --bench cgroup \
            -p linpodx-mcp --bench policy \
            -p linpodx-plugin --bench invoke -- --quick

# One bench, full statistical run
cargo bench -p linpodx-mcp --bench policy
```

Bench results are not asserted in CI; they're a local diagnostic.

## Scenario testing

The end-to-end scenarios under [`docs/scenarios/`](docs/scenarios/) are intended to be
runnable manually against a real Podman host. When you change a feature touched by
one of those scenarios, walk through the relevant scenario before merging:

- `ai-agent-sandbox.md` — sandbox profile + MCP bridge + audit chain + snapshot.
- `multi-distro-shell.md` — distro presets + persistent rootfs.
- `gui-app.md` — Wayland/audio/GPU passthrough.
- `remote-daemon.md` — WebSocket + mTLS + token bucket.
- `plugin-author.md` — WASM plugin install/activate.

Manual scenario validation is not enforced in CI but is part of the PR review checklist.

## Workflow

1. Fork the repository.
2. Create a feature branch: `git checkout -b feat/my-change`.
3. Commit with the Conventional Commits style (see below).
4. Push and open a Pull Request.

## Pull Request Checklist

- [ ] The change has a clear scope and rationale.
- [ ] Tests are added/updated where applicable.
- [ ] `cargo build --workspace` passes.
- [ ] `cargo fmt --all -- --check` passes.
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` passes.
- [ ] `cargo test --workspace` passes.
- [ ] `cargo doc --workspace --no-deps` passes (no broken intra-doc links).
- [ ] If a scenario in `docs/scenarios/` was affected, you walked through it manually.
- [ ] README / docs are updated when behavior changes (both English and Korean if
      applicable — the Korean translations live under `docs/`).

## Versioning and releases

linpodx follows Cargo-compatible SemVer with clean version tags. `Cargo.toml`
is the source of truth.

- `vX.Y.Z` is the public version tag.
- `REL-vX.Y.Z` is the release marker tag that triggers `.github/workflows/release.yml`.
- Pre-release tags use Cargo SemVer suffixes, for example `v0.2.0-rc.1` and
  `REL-v0.2.0-rc.1`.
- RTM suffixes and four-component versions are not used.

This release discipline keeps rapid tag iteration from publishing a GitHub Release
accidentally. A release needs both tags pointed at the same commit.

```bash
git tag -a vX.Y.Z -m "linpodx vX.Y.Z"
git tag -a REL-vX.Y.Z vX.Y.Z^{} -m "release linpodx vX.Y.Z"
git push origin vX.Y.Z REL-vX.Y.Z
```

The release workflow validates that the tag version matches `Cargo.toml`, runs the
workspace gates, builds release artifacts, extracts the matching `CHANGELOG.md`
section, and publishes the GitHub Release under the clean `vX.Y.Z` tag.

See [docs/RELEASE.md](docs/RELEASE.md) for the full versioning and release
checklist.

## Writing release notes

Each version section in `CHANGELOG.md` and `docs/CHANGELOG.ko.md` starts with
`### Highlights`. The release workflow extracts the version section verbatim, so
the highlights are the first thing users see on the GitHub Release page.

Skeleton:

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Highlights

**One-sentence headline.** Optional 1-2 sentence elaboration if useful.

- Most important user-visible change
- Second most important change
- Third important change

### Added
### Changed
### Fixed
```

## Commit Message Convention

Use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` for new features
- `fix:` for bug fixes
- `docs:` for documentation changes
- `refactor:` for internal improvements without behavior changes
- `test:` for test updates
- `chore:` for maintenance tasks
- `perf:` for performance improvements
- `build:` for build system changes
- `ci:` for CI / workflow changes

## NEVER add AI attribution

This is a hard rule, not a preference.

- Do **not** add AI co-author trailers to commit messages.
- Do **not** add tool-generation footers, badges, or emojis to PR titles, PR
  descriptions, issues, comments, commit messages, CHANGELOG entries, or release notes.
- Do **not** annotate code with `// generated by AI`, `# AI-written`, or similar.

The repository owner is the sole human author. AI attribution gets surfaced on
GitHub's Contributors / Co-Authors UI and is operationally painful to remove. Don't
create that work.

## Security

For security issues, follow the process in [SECURITY.md](SECURITY.md). Do not file a
public issue for a vulnerability.
