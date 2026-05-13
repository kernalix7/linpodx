# Release Process

[Back to README](../README.md)

linpodx uses the same release discipline as winpodx, adapted for Rust/Cargo:
clean public version tags plus a separate release marker tag.

## Version policy

`Cargo.toml` is the source of truth for the project version.

- Use Cargo-compatible Semantic Versioning: `X.Y.Z`.
- While linpodx is pre-1.0, user-visible capability changes normally bump
  `MINOR` and bugfix, packaging, or documentation hardening bumps `PATCH`.
- Breaking CLI, IPC, profile, or on-disk format changes may happen in `0.x`, but
  must be called out in `CHANGELOG.md`.
- Pre-releases use Cargo SemVer suffixes: `0.2.0-alpha.1`, `0.2.0-beta.1`,
  `0.2.0-rc.1`.
- Do not use RTM suffixes or four-component versions.

Examples:

| Kind | Cargo version | Public tag | Release marker |
|------|---------------|------------|----------------|
| Stable | `0.1.0` | `v0.1.0` | `REL-v0.1.0` |
| Patch | `0.1.1` | `v0.1.1` | `REL-v0.1.1` |
| Release candidate | `0.2.0-rc.1` | `v0.2.0-rc.1` | `REL-v0.2.0-rc.1` |

## Development flow

Use short topic branches:

- `feat/<name>` for user-visible features.
- `fix/<name>` for bugs.
- `docs/<name>` for documentation-only work.
- `ci/<name>` for workflow changes.
- `chore/<name>` for maintenance.

Commits follow Conventional Commits:

```text
feat: add remote daemon pin listing
fix: preserve read-only rootfs in sandbox profiles
docs: document offline install
ci: validate release marker tags
```

Every user-visible change should update `CHANGELOG.md`. Update
`docs/CHANGELOG.ko.md` when the change is part of a release-facing note.

## Release notes

Each version section starts with `### Highlights`. The release workflow extracts
the matching `CHANGELOG.md` section and publishes it as the GitHub Release body.

```markdown
## [0.2.0] - YYYY-MM-DD

### Highlights

**Short release headline.** Add one or two sentences if the release needs context.

- Most important user-visible change
- Second important change
- Third important change
```

## Release checklist

1. Update `Cargo.toml` `[workspace.package] version`.
2. Keep workspace crates on the same workspace version.
3. Update `CHANGELOG.md` and, when release-facing, `docs/CHANGELOG.ko.md`.
4. Run the release gates:

```bash
cargo +1.85 fmt --all -- --check
cargo +1.85 clippy --workspace --all-targets --all-features -- -D warnings
cargo +1.85 build --workspace
cargo +1.85 test --workspace
RUSTDOCFLAGS="-D rustdoc::broken-intra-doc-links -D warnings" cargo +1.85 doc --workspace --no-deps
```

5. Commit the release prep.
6. Create the public version tag and the release marker tag on the same commit:

```bash
git tag -a vX.Y.Z -m "linpodx vX.Y.Z"
git tag -a REL-vX.Y.Z vX.Y.Z^{} -m "release linpodx vX.Y.Z"
git push origin vX.Y.Z REL-vX.Y.Z
```

Only `REL-*` tags trigger the GitHub Release workflow. The workflow validates
that the public tag version matches `Cargo.toml`, runs the workspace checks,
builds artifacts, extracts release notes, and publishes under the clean public
`vX.Y.Z` tag.
