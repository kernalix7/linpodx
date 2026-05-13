# ADR 0008 — `SnapshotBackend` as a trait, multiple implementations

- **Status**: Accepted (2026-05, Phase 2B → 9)
- **Deciders**: kernalix7

## Context

Phase 2B shipped snapshots backed by `podman commit` — straightforward, works on every
host that has Podman, but it copies image layers on each snapshot and the resulting
"image" is not as cheap to roll back as a real layered FS.

Hosts that have overlayfs (every modern Linux desktop) or Btrfs (Fedora's default
filesystem) can do better:

- **overlayfs**: snapshot = an extra lower layer; rollback = drop the upper directory.
- **Btrfs**: snapshot = a CoW subvolume; rollback = swap the subvolume in.

We don't want the daemon dispatcher to know which path it's on.

## Decision

A `SnapshotBackend` trait in `linpodx_runtime::snapshot` with three concrete
implementations:

- `PodmanCommitBackend` — universal default, ships in v0.1.
- `OverlayfsBackend` — fuse-overlayfs based, opt-in via per-container config.
- `BtrfsBackend` — real subvolume snapshots, opt-in.

The migration `0012_snapshot_backend.sql` adds a discriminator column so `snapshot.list`
can render the kind and `snapshot.diff` can dispatch to the correct path-walker.

`backend_for(kind)` is the single factory the daemon calls.

## Consequences

**Positive:**
- The daemon's snapshot dispatch code is unaware of which backend is in use.
- New backends (zfs, lvm-thin, restic-style chunks) become a single new struct + a
  factory arm, not a refactor.
- Test coverage is per-backend — `PodmanCommitBackend` keeps its own integration
  test, the overlayfs/Btrfs paths are gated on host capability checks and run in a
  scratch directory.

**Negative:**
- Three backends means three test environments. `OverlayfsBackend` and `BtrfsBackend`
  are gated `#[ignore]` in CI and run on a host with the appropriate filesystem.
- Cross-backend snapshot copy ("clone overlayfs snapshot to a Btrfs host") is not
  supported and probably never will be — operators must export to OCI for that.
