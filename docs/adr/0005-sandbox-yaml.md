# ADR 0005 — YAML sandbox profile + tamper-evident audit log

- **Status**: Accepted (2026-05, Phase 1C)
- **Deciders**: kernalix7

## Context

Each AI agent or interactive session that runs inside a linpodx container needs a
declarative description of what it is allowed to do: capabilities, syscall sets,
mounts, network egress allowlist, and approval rules. That description must:

1. Be readable and reviewable by a human (security audit, code review).
2. Be diffable in git.
3. Be machine-parseable by the daemon.
4. Carry an audit trail that a malicious in-container process cannot silently rewrite.

## Decision

- **Profile format**: YAML, one file per profile. Parsed by `serde_yml` (the
  maintained fork of unmaintained `serde_yaml`).
- **Audit log**: SQLite table `audit_log`, each row referencing the previous row's
  SHA-256. The daemon refuses to start if the chain validation fails on load.
- **Hash function**: SHA-256 from `sha2`. Each row's hash covers `prev_hash || JSON(payload)`.

## Consequences

**Positive:**
- Profiles can live in dotfile repos and be bundled with project tooling.
- Tamper-evident: removing or rewriting an audit row breaks the chain at the next
  validation pass.
- Single audit pipeline — runtime, sandbox, MCP, and plugin all flow into the same
  `AuditSink` trait (see `linpodx_common::audit_sink`).

**Negative:**
- YAML's whitespace-sensitivity can be fragile in copy-paste workflows. Mitigated by
  shipping a `linpodx sandbox validate` CLI subcommand that surfaces parse errors
  with line/column.
- The hash chain is append-only. Operational truncation (e.g. log rotation) requires a
  documented "chain re-anchor" procedure (planned for Phase 4).
