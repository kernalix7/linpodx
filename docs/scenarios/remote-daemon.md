# Scenario — Manage a remote linpodx daemon over WebSocket + mTLS

> **Status — illustrative end-to-end walkthrough.** The daemon's actual
> flags today are `--remote-listen <addr>` / `--remote-token <token>` /
> `--tls-cert` / `--tls-key` / `--client-ca` / `--pin-clients`, and the
> client uses `linpodx --remote <ws-or-wss-url> --token <token>` (plus
> `--client-cert` / `--client-key` / `--client-ca` for mTLS). The
> `--listen-tcp` / `--remote-token-file` / `linpodx ctx add` ergonomics
> shown below are planned; until they ship use the README's
> [Remote daemon](../../README.md#remote-daemon) section as the source of
> truth.

You can drive a linpodx daemon on a remote box (a homelab server, a CI runner, a
co-located dev workstation) from your laptop's CLI, GUI, or Web UI. The transport is
WebSocket over TLS with mutual auth.

See [ADR-0007](../adr/0007-mtls-defence-in-depth.md) for the auth layering.

## 1. Issue certificates with the bundled helper

`examples/gen-certs.sh` (rcgen-based) produces a fresh CA + server cert + one client
cert under `./pki/`:

```console
$ examples/gen-certs.sh server.lan alice
generating CA   ... pki/ca.{crt,key}
generating srv  ... pki/server.{crt,key} (CN=server.lan, SAN=server.lan,IP=...)
generating cli  ... pki/alice.{crt,key} (CN=alice)
```

## 2. Boot the daemon with TLS enabled

On `server.lan`:

```console
$ linpodx-daemon \
    --listen-tcp 0.0.0.0:7320 \
    --tls-cert pki/server.crt \
    --tls-key  pki/server.key \
    --client-ca pki/ca.crt \
    --remote-token-file /etc/linpodx/tokens.txt
[info] listening on unix:/run/user/1000/linpodx.sock
[info] listening on tls 0.0.0.0:7320 (mTLS required)
[info] loaded 1 remote tokens
```

`tokens.txt` is one opaque token per line. The daemon doesn't care about format; it
hashes them at boot and matches per-call.

## 3. Configure the client

On your laptop:

```console
$ linpodx ctx add prod-server \
    --endpoint wss://server.lan:7320 \
    --tls-ca pki/ca.crt \
    --client-cert pki/alice.crt \
    --client-key pki/alice.key \
    --token-file ~/.config/linpodx/prod-token
context prod-server saved.

$ linpodx ctx use prod-server
active context: prod-server
```

## 4. Use it like a local daemon

```console
$ linpodx ps
ID         NAME             IMAGE                  STATE     UPTIME
4d11abef   web-1            nginx:1.27             running   3d
9f2c8a1c   redis            redis:7-alpine         running   3d

$ linpodx logs web-1 --tail 5
2026-05-10T09:14:02Z 200 GET /
2026-05-10T09:14:03Z 200 GET /assets/app.js
2026-05-10T09:14:04Z 304 GET /favicon.ico
...
```

Every JSON-RPC frame is checked twice: TLS handshake first (client cert against the
CA), then the daemon-side token bucket.

## 5. Subscribe to events from afar

```console
$ linpodx events
[2026-05-10T09:15:00Z] container.started   web-1
[2026-05-10T09:15:01Z] image.pulled        nginx:1.27 (52MB)
```

The WebSocket stays open; events stream as the daemon emits them.

## 6. Open the Web UI

Point a browser at `https://server.lan:7320/` (the daemon serves `linpodx-webui` on
the same TLS port). The browser will need the CA imported and a P12 bundle of
`alice.crt` + `alice.key` installed in the keychain.

## 7. Revocation

Two independent kill switches:

```console
# Kill alice's token (application layer)
$ ssh server.lan "sudo sed -i '/alice-token/d' /etc/linpodx/tokens.txt && \
                  sudo systemctl reload linpodx-daemon"

# Or kill alice's cert (transport layer) by re-issuing the CA bundle without it
$ examples/revoke-cert.sh alice
```

Either layer alone is enough to lock the user out, by design.

## Troubleshooting

- `tls handshake failure: unknown ca` — laptop is using a `--tls-ca` that doesn't
  contain the server's chain. Regenerate or distribute the right CA.
- `401 token rejected` — TLS handshake succeeded, but the token isn't in
  `tokens.txt`. The CN of the client cert doesn't grant access by itself.
- `connection refused` — daemon is bound to `127.0.0.1` not `0.0.0.0`; check
  `--listen-tcp`.
