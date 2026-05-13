# linpodx Architecture

This document is the canonical map of the linpodx workspace as of the Phase 9
stabilization pass. It covers crate boundaries, the major data flows that cross those
boundaries, and the SQLite schema that ties durable state together.

For motivation and trade-offs behind individual decisions, see the ADRs under
[`docs/adr/`](./adr/). For end-to-end usage walkthroughs, see
[`docs/scenarios/`](./scenarios/).

## 1. Crate Map

```mermaid
flowchart TB
    subgraph clients["Clients"]
        cli[linpodx-cli]
        gui[linpodx-gui]
        webui[linpodx-webui]
    end

    subgraph daemon_layer["Daemon"]
        daemon[linpodx-daemon]
        common[linpodx-common\nIPC schema · errors · types]
    end

    subgraph runtime_layer["Runtime + Policy"]
        runtime[linpodx-runtime\nPodman adapter · snapshot backends]
        sandbox[linpodx-sandbox\nYAML profile · audit log]
        mcp[linpodx-mcp\nstdio bridge · policy engine]
        plugin[linpodx-plugin\nWASM SDK · wasmtime host]
        distro[linpodx-distro\nUbuntu/Fedora/Arch presets]
        netfilter[linpodx-netfilter\nDNS egress filter]
        cluster[linpodx-cluster\nHTTP gossip · view aggregator]
    end

    cli -- JSON-RPC over Unix socket --> daemon
    gui -- JSON-RPC over Unix socket --> daemon
    webui -- WebSocket / mTLS --> daemon

    daemon --> common
    daemon --> runtime
    daemon --> sandbox
    daemon --> mcp
    daemon --> plugin
    daemon --> distro
    daemon --> cluster

    runtime --> common
    runtime --> netfilter
    sandbox --> common
    mcp --> common
    plugin --> common
    distro --> common
    cluster --> common
    netfilter --> common

    runtime -. spawns .-> podman[(podman CLI)]
    daemon -. persists .-> sqlite[(SQLite\n13 migrations)]
    plugin -. JIT-compiles .-> wasmtime[(wasmtime engine)]
    cluster -. reqwest .-> peers[(peer daemons)]
```

### Crates at a glance

| Crate | Responsibility |
|-------|----------------|
| `linpodx-common` | IPC schema (JSON-RPC params + responses), error taxonomy, newtype IDs (`ContainerId`, `ImageId`, …), `AuditSink` / `EventPublisher` / `ApprovalGateway` traits, `MetricsSample`. |
| `linpodx-daemon` | Long-running server. Owns the Unix socket, JSON-RPC dispatcher, SQLite migrations, the broadcast event bus, and the approval registry. |
| `linpodx-cli` | `linpodx` binary. Dumb client over the Unix socket; rendering only. |
| `linpodx-gui` | iced 0.13 desktop app. Read-mostly dashboard subscribed to the event stream. |
| `linpodx-webui` | Leptos SPA served by the daemon over the WebSocket transport. |
| `linpodx-runtime` | Podman wrapper. Container/image/volume/network CRUD, port mapping, snapshot backends (`PodmanCommitBackend`, `OverlayfsBackend`, `BtrfsBackend`), metrics collector, egress enforcer hook. |
| `linpodx-sandbox` | YAML profile parsing, capability/seccomp policy engine, tamper-evident audit log (SHA-256 hash chain). |
| `linpodx-mcp` | Host-stdio ↔ container MCP bridge with audit hooks and per-method `PolicyEngine`. |
| `linpodx-plugin` | WASM plugin SDK + wasmtime host. Hooks: approval, audit-filter, profile-validator. |
| `linpodx-distro` | Per-distro install/launch presets (ubuntu, fedora, alpine, arch). |
| `linpodx-netfilter` | DNS-based egress allowlist. Uses hickory-resolver/server. |
| `linpodx-cluster` | HTTP gossip + container-view aggregation across peer daemons. |

## 2. Core Data Flows

### 2.1 Container CRUD path

```mermaid
sequenceDiagram
    participant Client as cli/gui/webui
    participant D as daemon
    participant R as runtime
    participant P as podman (subprocess)
    participant DB as SQLite
    Client->>D: JSON-RPC container.create {opts}
    D->>R: Podman::create(opts)
    R->>P: spawn `podman create ...`
    P-->>R: container id (stdout)
    R->>R: parse_container_inspect()
    R-->>D: ContainerSummary
    D->>DB: insert container_events row
    D-->>Client: response
    D->>Client: server-push event{container.created}
```

### 2.2 Sandbox apply path

```mermaid
sequenceDiagram
    participant Client
    participant D as daemon
    participant S as sandbox
    participant DB as SQLite
    Client->>D: JSON-RPC sandbox.apply {profile_yaml}
    D->>S: parse YAML → Profile
    S->>S: PolicyEngine.validate(profile)
    S->>DB: insert sandbox_profiles row
    S->>S: AuditLog.append(SHA-256 hash chain)
    S-->>D: profile_id + audit hash
    D-->>Client: response
```

### 2.3 MCP bridge path

```mermaid
sequenceDiagram
    participant H as host stdio (AI-agent CLI)
    participant B as mcp::Bridge
    participant E as PolicyEngine
    participant A as ApprovalGateway
    participant C as container stdio
    H->>B: JSON-RPC line (e.g. tools/call)
    B->>B: McpMessage::parse
    B->>E: evaluate(rules, msg)
    alt decision = AutoAllow
        B->>C: forward verbatim
    else decision = Prompt
        B->>A: request_approval(payload)
        A-->>B: granted
        B->>C: forward
    else decision = Deny
        B-->>H: error (forbidden)
    end
    B->>B: AuditSink.record(method, decision)
```

### 2.4 Snapshot backend path

```mermaid
sequenceDiagram
    participant Client
    participant D as daemon
    participant SR as snapshot_jobs (DB)
    participant BE as SnapshotBackend
    Client->>D: snapshot.create {container_id}
    D->>SR: insert pending row, allocate job_id
    D->>BE: backend_for(kind).create_async(...)
    BE-->>D: spawned (returns immediately)
    D-->>Client: {job_id}
    Note over BE,SR: BE updates row to running → succeeded/failed
    Client->>D: snapshot.job_status {job_id}
    D->>SR: SELECT
    D-->>Client: JobStatusSnapshot
```

`SnapshotBackend` is a trait (see [ADR-0008](./adr/0008-snapshotbackend-trait.md)) so the
daemon is agnostic to whether the snapshot lands as a `podman commit` image, an overlayfs
layer, or a Btrfs subvolume.

### 2.5 Remote daemon path

```mermaid
sequenceDiagram
    participant W as linpodx-webui (leptos)
    participant Ax as axum/ws + mTLS
    participant D as daemon dispatcher
    W->>Ax: WebSocket Upgrade (client cert)
    Ax->>Ax: rustls verify cert chain
    Ax->>D: forward JSON-RPC frame
    D-->>Ax: response frame
    Ax-->>W: WebSocket message
    Note over Ax: Token bucket per session<br/>after mTLS (defence in depth)
```

## 3. Persistence

SQLite is the durability store. Migrations live under
`crates/linpodx-daemon/migrations/` and are applied on daemon start.

| # | Migration | Notes |
|---|-----------|-------|
| 0001 | `init` | Bootstrap (containers/images/volumes/networks event log). |
| 0002 | `sandbox_profiles` | YAML profile rows + revisions. |
| 0003 | `audit_log` | Tamper-evident hash chain (SHA-256 over prev_hash + payload). |
| 0004 | `snapshots` | Snapshot metadata (container_id, label, image_ref, size_bytes). |
| 0005 | `mcp_sessions` | One row per active stdio bridge. |
| 0006 | `mcp_events` | Per-message audit (method, decision, latency_ms). |
| 0007 | `distro_instances` | Distro template instantiations. |
| 0008 | `snapshot_jobs` | Async snapshot lifecycle (pending → running → succeeded/failed). |
| 0009 | `mcp_policies` | `(method, tool_name?) → decision` rules. |
| 0010 | `snapshot_branches` | Snapshot lineage / fork tracking. |
| 0011 | `plugins` | Installed WASM plugin manifests. |
| 0012 | `snapshot_backend` | Per-snapshot backend kind discriminator. |
| 0013 | `cluster_peers` | Known peer daemons for gossip. |

## 4. Cross-cutting traits

Three trait surfaces in `linpodx-common` keep the daemon decoupled from concrete
implementations:

- **`EventPublisher`** — daemon broadcast bus; runtime/sandbox emit, GUI/CLI subscribe.
- **`ApprovalGateway`** — runtime/MCP/plugin request approval; CLI listener resolves
  with the user's Y/N answer.
- **`AuditSink`** — sandbox/MCP/runtime hash-chain audit; pluggable target (SQLite by
  default; Noop in tests).

Wiring these as traits kept Phase 2 implementation streams decoupled and testable.
