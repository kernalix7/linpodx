# inject-tracing-env

Sample linpodx `runtime_injector` plugin. Returns an `InjectorPayload` that appends two
OpenTelemetry env vars to every container the daemon is about to create:

- `OTEL_SERVICE_NAME=linpodx`
- `OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317`

The daemon merges the payload into `CreateOptions.env` *after* sandbox
`apply_to_create` runs, so the additions never override profile-injected env vars but
are visible to the container.

## Behavior

| Existing env | After plugin |
|--|--|
| `[]` | `[OTEL_SERVICE_NAME=linpodx, OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317]` |
| `[FOO=bar]` | `[FOO=bar, OTEL_SERVICE_NAME=linpodx, OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317]` |

`args_append` and `security_opts_add` are left empty — this plugin only adds env vars.

## Build

```sh
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown
```

The compiled artifact lands at:

```
target/wasm32-unknown-unknown/release/inject_tracing_env.wasm
```

`linpodx-plugin.toml` references it as `inject_tracing_env.wasm`. Copy the wasm file
next to the manifest before installing:

```sh
cp target/wasm32-unknown-unknown/release/inject_tracing_env.wasm \
   examples/plugins/inject-tracing-env/inject_tracing_env.wasm
```

## Install into the running daemon

```sh
linpodx plugin install examples/plugins/inject-tracing-env
linpodx plugin list
linpodx plugin disable inject-tracing-env      # toggle off without uninstalling
linpodx plugin enable  inject-tracing-env
linpodx plugin remove  inject-tracing-env --force   # delete on-disk dir too
```

## Host ABI used

This plugin needs two imported functions from the `linpodx_host` namespace:

- `host_log(level, ptr, len)`
- `host_return_injector_payload(ptr, len)` — write a JSON-encoded `InjectorPayload`.

The export the host calls is `evaluate_runtime_injector()` (no args, no result). The
host reads the request payload (the JSON-encoded `CreateOptions` the daemon is about
to use) via `host_get_payload` if your plugin wants to make decisions based on the
container shape — this template ignores it because OTEL endpoints are static.

The `InjectorPayload` JSON shape is:

```json
{
  "env_add": [["KEY", "VALUE"], ...],
  "args_append": ["--flag", ...],
  "security_opts_add": ["seccomp=foo", "label=type:bar", ...]
}
```

The daemon merges the payload across all enabled `runtime_injector` plugins by
concatenating each `Vec` field — there is no de-duplication.
