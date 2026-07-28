# Quickstart

*Build Onyx Server, write a minimal config, and start the daemon.*

Onyx Server is a pure-Zig 0.17-dev clean-room IRC daemon. The build package declares
Zig `0.17.0-dev.1282+c0f9b51d8` as the minimum supported compiler, and the
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
reads up to 1 MiB, parses the file, maps it onto `server.Config`, and stores the
path for live `REHASH`. If the file is missing or invalid, boot logs the error
and keeps defaults instead of aborting.

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
  **`onyx-server`** binary, reference config, and systemd unit (the unit includes
  `ExecStartPre=… --check-config …`).
- For a public node: [Production TLS card](tls.md#production-tls-card) (DNS, ACME,
  `ws_plain = false`) — also summarized in [`packaging/README.md`](../../packaging/README.md).
- Download the verified static binary and quickstart from the public
  [`v0.5.7` release](https://github.com/devinkbrown/onyx-server/releases/tag/v0.5.7),
  or independently rebuild it with `packaging/release.sh`. The published path
  passed checksum, reproducibility, config, IRC, and WebSocket download smoke;
  it is currently unsigned, so do not imply signature-backed provenance.
- Read the [runbook](../RUNBOOK.md) before deploying or hot-upgrading a live node.
- Read [testing.md](testing.md) for the focused roadmap gates and long-run verbose
  assurance lanes.
