# ADR 0003 — JSON-RPC 2.0 over Unix socket (NDJSON framing)

- **Status**: Accepted (2026-04, Phase 0)
- **Deciders**: kernalix7

## Context

The daemon needs an IPC surface that the CLI, the iced GUI, the Web UI, and (later) AI
agents can all speak. Candidate transports:

- gRPC: typed but requires `protoc`, codegen, and a build script per language.
- Cap'n Proto: similar, with the additional cost of a brand-new IDL.
- JSON-RPC 2.0 over a stream socket: schema-less wire format, types live in shared
  Rust modules.

For the framing layer, we must pick between length-prefix, NDJSON (newline-delimited),
or websocket-style frames.

## Decision

- **Wire format**: JSON-RPC 2.0.
- **Framing**: NDJSON — one JSON value per `\n`-terminated line.
- **Transport (local)**: Unix domain socket at the user's `XDG_RUNTIME_DIR/linpodx.sock`.
- **Transport (remote)**: WebSocket over TLS (see [ADR-0007](./0007-mtls-defence-in-depth.md)).
- **Schema source of truth**: `linpodx_common::ipc` — one Rust module, one set of
  `#[derive(Serialize, Deserialize)]` types per request/response.

## Consequences

**Positive:**
- No codegen, no IDL — adding a new method is one struct + one match arm.
- Server push works trivially: the daemon emits NDJSON event frames on the same socket
  the client used for the call.
- Drop-in observability: every RPC is a JSON line, so `socat` + `jq` is a usable
  debugger.
- Same shape works over WebSocket for the remote/web case.

**Negative:**
- JSON is verbose vs. binary formats. For our payloads (small, infrequent CRUD calls
  + sparse event stream) this is irrelevant.
- No formal schema registry — we rely on integration tests + clippy `deny(warnings)`
  to catch breakage. A schema-export tool may follow in a later phase.
