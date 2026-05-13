# ADR 0007 — mTLS plus token, defence in depth

- **Status**: Accepted (2026-05, Phase 8)
- **Deciders**: kernalix7

## Context

For Phase 7 we exposed the daemon over WebSocket so the Web UI and remote operators
could reach it. WebSocket-only authentication leaves us with two unattractive options:

1. Bearer token only — simple, but a leaked token grants the full IPC surface.
2. mTLS only — strong, but a single mis-issued client cert is also game over and
   revocation tooling is operationally heavy.

In practice, attackers rarely compromise both at once. Layering is cheap.

## Decision

For remote daemon access:

- **Transport security**: rustls-backed mTLS. The server requires a client cert
  signed by the operator's CA (configured via `--client-ca`).
- **Application auth**: in addition, every JSON-RPC frame is checked against a token
  bucket scoped to the session that the cert established.
- **Local Unix socket**: unchanged — peer credentials via SO_PEERCRED are sufficient.

The token format is opaque to the daemon; rotation/issuance lives outside this repo.

## Consequences

**Positive:**
- A leaked token without a valid client cert is rejected at the TLS handshake.
- A mis-issued cert without a known token is rejected at the application layer.
- Operators can revoke either layer independently.

**Negative:**
- Setup cost: operators must run a small CA (rcgen makes this scriptable; see
  `examples/`).
- We carry rustls + axum-server + rustls-pemfile + x509-parser as workspace deps even
  for users who never enable remote access. Mitigated by `default-features = false`
  and feature gating on the daemon side (planned Phase 9.5).
