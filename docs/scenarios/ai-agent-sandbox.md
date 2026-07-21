# Scenario — Run an AI agent inside a linpodx sandbox

> **Status — illustrative end-to-end walkthrough.** Today the runnable
> surface is `linpodx sandbox {list, show, reload, apply, audit, verify,
> profile compile}` for the profile lifecycle and `linpodx mcp {start, stop,
> status, policy}` for the bridge. `linpodx sandbox validate` and the
> in-line `apply --profile <path>` form below are planned; the supported
> path today is to drop the YAML in the profiles directory and run
> `linpodx sandbox reload`. `linpodx audit verify --session <id>` is
> rendered as `linpodx sandbox verify` + `linpodx session timeline` today.
> The encryption-status, approval gates, and snapshot-encryption flows
> shown later are real.

This walks through running an AI-agent CLI inside a sandboxed
linpodx container so it can execute shell commands without touching the host.

## What you get

- Container has its own rootfs and `$HOME`.
- Egress is filtered to a DNS allowlist (no exfiltration to arbitrary hosts).
- Every shell command the agent runs flows through an approval gate; auto-allow,
  prompt, or deny per rule.
- Audit log entry per command, hash-chained.

## Prerequisites

- `linpodx` daemon running (`linpodx-daemon &` or systemd user unit).
- Podman ≥ 4.6.0 rootless.
- A YAML sandbox profile (we'll create one).

## 1. Author the profile

`~/.config/linpodx/profiles/agent-readonly.yml`:

```yaml
name: agent-readonly
description: AI agent sandbox — read-only host project mount, prompt on writes
mounts:
  - source: ${HOME}/projects/demo
    target: /work
    read_only: true
network:
  egress_dns_allowlist:
    - registry.npmjs.org
    - crates.io
mcp_policy:
  - method: tools/call
    tool_name: read_file
    decision: auto_allow
  - method: tools/call
    tool_name: write_file
    decision: prompt
  - method: tools/call
    decision: prompt
audit:
  hash_chain: true
```

Validate it:

```console
$ linpodx sandbox validate ~/.config/linpodx/profiles/agent-readonly.yml
profile: agent-readonly
status:  ok
mounts:  1
egress:  2 hosts allowed
mcp:     3 rules
```

## 2. Apply the profile

```console
$ linpodx sandbox apply --profile ~/.config/linpodx/profiles/agent-readonly.yml
profile_id: prof_01HZ...
audit_hash: 9f2c8a1c...
```

## 3. Launch the container with the profile

```console
$ linpodx run \
    --profile agent-readonly \
    --image docker.io/library/node:20-alpine \
    --interactive --tty \
    --name agent-1
container_id: abc123...
state:        running
```

## 4. Start the MCP bridge

In a second terminal:

```console
$ linpodx mcp attach --container agent-1 -- automation-agent mcp serve
mcp_session_id: sess_01HZ...
bridge:         host stdio <-> container stdio
policy:         3 rules loaded
```

## 5. Watch approvals as they arrive

```console
$ linpodx events --filter approval
[2026-05-10T09:14:02Z] sess_01HZ... tools/call write_file → PROMPT
   payload: {"path":"/work/src/index.ts","content":"..."}
   approve? [y/N]: n
[2026-05-10T09:14:09Z] sess_01HZ... tools/call read_file → AUTO_ALLOW
[2026-05-10T09:14:11Z] sess_01HZ... tools/call write_file → PROMPT
   payload: {"path":"/work/notes.md","content":"..."}
   approve? [y/N]: y
```

## 6. Inspect the audit chain

```console
$ linpodx audit verify --session sess_01HZ...
session: sess_01HZ...
events:  47
chain:   OK (head 9f2c8a1c..., tail 4d11abef...)
```

## 7. Snapshot before the agent starts a risky refactor

```console
$ linpodx snapshot create agent-1 --label "before-refactor"
job_id: snap-7a3f4c2

$ linpodx snapshot job-status snap-7a3f4c2
status: succeeded
image:  linpodx/snapshot/agent-1:before-refactor

$ linpodx snapshot rollback agent-1 --to before-refactor
rolled_back: true
```

If the daemon was started with `LINPODX_SNAPSHOT_ENCRYPT_PASSPHRASE` or
`LINPODX_SNAPSHOT_KEY`, the snapshot is written encrypted at rest. Inspect the
recorded encryption metadata:

```console
$ linpodx snapshot encryption-status snap-7a3f4c2
algorithm: aes-256-gcm
kdf:       argon2id (m=19456, t=2, p=1)
encrypted: true
```

The `auto_encrypt_snapshots: true` profile field flips this on for every
pre-run snapshot taken under the active sandbox profile.

## Troubleshooting

- **`error: profile not found`** — run `linpodx sandbox apply` first; the daemon
  doesn't read `~/.config` on its own.
- **`error: dns lookup denied for github.com`** — add the host to
  `network.egress_dns_allowlist` in the profile and reapply.
- **Approval prompt never appears** — make sure `linpodx events` is running and not
  filtered out; CLI listener resolves prompts within a 30-second window before the
  call is denied by default.
