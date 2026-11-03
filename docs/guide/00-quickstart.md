# Quickstart

*Build Onyx Server, write a minimal config, and start the daemon.*

Onyx Server is a pure-Zig IRC/IRCX mesh daemon. The source manifest is **0.9.0**. The accepted fleet image is recorded in [production paths](../ops/onyx-server-paths.md); a fresh build of this tree is a separate candidate. The build package declares
Zig `0.17.0` as the minimum compiler, and the
daemon build rejects 32-bit targets. The browser WASM artifacts are the only
deliberate 32-bit exception.

## Build

From the repository root:

```sh
zig build
```

The default build installs the `onyx-server` executable under `zig-out/bin`.

For a fast semantic check:

```sh
zig build check
```

The `check` step analyzes `src/main.zig` without emitting a daemon binary.

## Minimal config

The parser requires only `[node].id` and `[listen].irc`:

```toml
[node]
id = 1

[listen]
host = "127.0.0.1"
irc = 6680
```

Save this as a local TOML file, or start from the runnable reference at `etc/onyx-server.reference.toml`. The current source still requires `[listen].irc` even for TLS-first deployments.

Validate a config without binding ports or dialing mesh peers:

```sh
zig build run -- --check-config etc/onyx-server.reference.toml
```

## First run

Run the daemon with an explicit config path:

```sh
zig build run -- etc/onyx-server.reference.toml
```

`src/main.zig` treats the first non-command argument as the config file path. It
reads up to 2 MiB, parses the file, maps it onto `server.Config`, and stores the
path for live `REHASH`. An explicitly named missing or invalid configuration aborts startup.
Both packaged supervisor kits additionally run `--check-config` before start
and reload. This does not exercise the reactor, actual listeners or full TLS
startup under the service sandbox.
Always run `--check-config` explicitly before a reload or cold start.

The default listener port is `6680` before config overlay. The boot sequence then
installs the configured network name, ISUPPORT limits, mesh identity, SASL
account store, cloaking key, TLS listener, and optional STS policy before
starting the server loop.

For an end-to-end local smoke after `zig build`:

```sh
python3 tools/runtime_smoke.py zig-out/bin/onyx-server
```

This boots a temporary loopback daemon, registers a client, verifies PING/PONG,
and shuts the process down cleanly.

## Config indirection

The parser supports `env:NAME` and `@file:path` string indirection for string
values. The normal CLI boot path wires both resolvers, so configs can keep
secrets in the process environment or in files relative to the daemon working
directory.

## Connection classes

After the basic setup, define connection classes under `[class.<name>]` to control per-client resource limits, flood policies, and admission rules by IP, TLS, account, or oper status. Every custom class inherits sensible fallbacks from the built-in `user` and `server` classes. See [operators.md](operators.md) for detailed coverage.

## Production next steps

- Use `zig build package --prefix ./.cache/onyx-server-stage` to stage a ReleaseFast
  **`onyx-server`** binary, reference config, and Linux OpenRC/systemd kits.
  Follow [service management](service-management.md) to provision the selected kit.
- For a public node: [Production TLS card](tls.md#production-tls-card) (DNS, ACME,
  `ws_plain = false`) — also summarized in [`packaging/README.md`](../../packaging/README.md).
- Build a current release with `packaging/release.sh` and verify it independently
  with `packaging/verify-release.sh`. Historical public downloads have their own
  version and validation scope; do not substitute one for the accepted fleet image.
  See [packaging](../../packaging/README.md).
- Read the [runbook](../RUNBOOK.md) before deploying or hot-upgrading a live node.
- For the verified two-node production baseline, use
  [`docs/ops/onyx-server-paths.md`](../ops/onyx-server-paths.md); its current
  image is separate from any public download channel.
- Read [testing.md](testing.md) for the focused roadmap gates and long-run verbose
  assurance lanes.
