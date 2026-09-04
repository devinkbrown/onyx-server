# Onyx Server

> A pure-Zig, clean-room IRC daemon — IRCv3 · IRCX · SASL · in-process services ·
> browser WebSocket · voice/video — over a post-quantum cryptographic mesh, with no C interop.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)
[![Zig 0.17 dev](https://img.shields.io/badge/Zig-0.17--dev-f7a41d?logo=zig&logoColor=white)](https://ziglang.org)
[![C interop: none](https://img.shields.io/badge/C%20interop-none-success.svg)](#design-pillars)
[![Status: in production](https://img.shields.io/badge/status-in%20production-success.svg)](#status)

**Onyx Server** is a **100% clean-slate, fully Zig-native**
IRC daemon built from first principles. The daemon *and its entire substrate* — the
systems library and the crypto/TLS stack — are written from scratch in Zig with **no C
interop**. It covers a full modern feature surface (IRCv3, IRCX, SASL, in-process
services, WebSocket, CHATHISTORY,
voice/video), adds class-based connection policy with bounded growable SendQ/RecvQ and
nick-delay protection, and replaces the legacy TS6 server-to-server protocol with the
native **Undertow + Mooring** cryptographic mesh.

**Quick links:** [Download v0.5.6 (latest published)](https://github.com/devinkbrown/onyx-server/releases/tag/v0.5.6) · source **0.5.8** (`build.zig.zon`) · [Quickstart](docs/guide/00-quickstart.md) ·
[Documentation](docs/README.md) · [Architecture](docs/architecture/00-overview.md) ·
[Command reference](docs/reference/commands/_index.md) ·
[Contributing](CONTRIBUTING.md) · [Runbook](docs/RUNBOOK.md) ·
[Security](SECURITY.md) · [License](LICENSE)

## From clone to live chat

Onyx Server is a single static binary with **zero external dependencies** — no database
server, no OpenSSL, no runtime to install.

**Docker (build from source).** There is no published registry image yet, so you
build `onyx-server:latest` locally from the verified static binary:

```sh
git clone https://github.com/devinkbrown/onyx-server && cd onyx-server
packaging/release.sh                                   # reproducible static binary → dist/
docker build -f packaging/Dockerfile -t onyx-server:latest .
docker run -p 6667:6667 -p 8080:8080 -v onyx-server:/data onyx-server:latest
```

**Native (fastest to a running node).** Current source version is **0.5.8**
(`build.zig.zon:18`). The latest published GitHub Release is still
[`v0.5.6`](https://github.com/devinkbrown/onyx-server/releases/tag/v0.5.6); build
locally for 0.5.8:

```sh
git clone https://github.com/devinkbrown/onyx-server && cd onyx-server
packaging/release.sh                                   # → dist/onyx-server-0.5.8-x86_64-linux-musl
./dist/onyx-server-0.5.8-x86_64-linux-musl --check-config packaging/onyx-server.quickstart.toml
./dist/onyx-server-0.5.8-x86_64-linux-musl packaging/onyx-server.quickstart.toml
```

Or download the published **v0.5.6** prebuilt:

```sh
release=https://github.com/devinkbrown/onyx-server/releases/download/v0.5.6
curl -fLO "$release/onyx-server-0.5.6-x86_64-linux-musl"
curl -fLO "$release/onyx-server.quickstart.toml"
curl -fLO "$release/SHA256SUMS"
grep ' onyx-server-0.5.6-x86_64-linux-musl$' SHA256SUMS | sha256sum -c -
chmod +x onyx-server-0.5.6-x86_64-linux-musl
./onyx-server-0.5.6-x86_64-linux-musl onyx-server.quickstart.toml
```

Either way you get a working node — **`ws://localhost:8080`** for the Onyx browser
client and **`irc://localhost:6667`** for any IRC client. The node's sovereign
identity key and account store self-generate in the data directory on first run;
nothing to configure. For production, swap the quickstart config for a TLS config
(real certs or the built-in ACME client) and set `ws_plain = false`.

The binary is **bit-for-bit reproducible** and ships a CycloneDX SBOM plus an SLSA
provenance attestation — see [`packaging/`](packaging/README.md) to rebuild and
verify it yourself (`packaging/verify-release.sh`).
The current public release is checksum-verified but unsigned; the packaging guide
states the exact trust boundary and independent rebuild path.

## Highlights

- **Pure Zig, top to bottom** — substrate, crypto, TLS, and daemon, with zero C dependencies.
- **Post-quantum mesh** — a CRDT state mesh with durable exact-once message delivery over an X25519 + ML-KEM-768 forward-secret ratchet, replacing TS6.
- **Full IRCv3 + IRCX + SASL** — including CHATHISTORY, the Event Spine, and in-process channel/nick services (no pseudo-clients).
- **Passwordless + interop-friendly** — WebAuthn/passkey login (with attestation verification), named conversations (topics) inside a channel, and Discord-compatible plus Block-Kit-lite incoming webhooks.
- **Browser-native** — a first-class WebSocket listener and a voice/video media plane.
- **Operates like a daemon should** — class-based admission policy, layered anti-abuse, and session-preserving `USR2` hot-upgrades.

## Design pillars

- **Zig top to bottom, no C interop.** Substrate, crypto, daemon, and tooling are all
  Zig; `comptime` powers the module machinery and generates wire codecs and
  dispatch tables.
- **Mesh, not tree.** **Undertow** (水脈) — a CRDT state mesh with Ripple gossip and
  Merkle anti-entropy — over **Mooring** — a post-quantum-hybrid (X25519 + ML-KEM-768)
  forward-secret ratchet. No TS6. Operator surfaces are network-wide: the Event Spine
  (connect/quit/oper alerts and the targeted `EVENT OBSERVE` feed) fans every event to
  all nodes rendered with the origin server, and a cross-node `MODE` shows the setter's
  nick, not the server. Message delivery across the mesh is **durable exact-once** —
  per-origin ordered replay, a per-hop retransmit-until-ACK outbox, and a signed
  replay/equivocation guard — with custody preserved across a session-preserving
  `USR2` hot-upgrade.
- **Safety as a type.** `Secret(T)` makes a data-dependent branch on secret bytes a
  compile error; TLS is **1.3 plus a hardened 1.2 profile** (AEAD/ECDHE-only; no RSA key
  exchange, CBC, compression, or renegotiation) with **Extended Master Secret (RFC 7627)
  required by default**, a single-shot suite-pinned HelloRetryRequest, and a 0-RTT
  ticket-age freshness window.
- **Trust through simulation.** Deterministic-simulation testing (the *Deterministic
  Ocean* harness) drives the CRDT mesh and crypto via injected clock/net/RNG, so any
  failure replays from a 64-bit seed.
- **Policy at registration.** `[class.*]` connection classes match IPv4/IPv6 CIDR,
  implicit TLS, SASL account state, oper state, ident, and host globs, then apply
  per-class sendq/recvq, flood, admission, clone, channel, target, monitor, silence,
  ping, and registration-timeout policy.
- **Elastic queues, explicit bounds.** Outbound SendQ and inbound RecvQ stay inline on
  the hot path and spill to heap overflow only when needed, bounded by the matched class.
  Optional `[limits].nick_delay` holds released nicks after exit to reduce nick camping,
  while `STATS Y`, `STATS l`, and richer `INFO` expose the live policy and mesh state.
- **Layered anti-abuse.** A single per-connection flood guard (keep-alives free, commands
  weighted, distinct-target spread throttle, decaying excess → disconnect) derived from
  each class's policy; a `+j` join-throttle with a network-wide raid-guard default
  (`[limits].raid_joins`) and one-shot operator raid alerts; operator-designated
  spam-trap honeypots (`SPAMTRAP`); and first-class nick services (`RECOVER`/`RELEASE`,
  per-account `SECURE`/`ENFORCE`) — all real server commands, no pseudo-clients.

## Architecture

| Package | Role |
|---|---|
| `src/substrate` | Ringlane `io_uring` reactor, lock-free queues, allocators, the Undertow math (HLC/vector clocks, delta-state CRDTs, Merkle sync, Ripple, sketches), and the Deterministic Ocean simulator |
| `src/crypto` | `Secret(T)`, SHA-2/HMAC/HKDF, AEADs, X25519 + ML-KEM key schedule, the Mooring ratchet, and the Armor TLS stack |
| `src/proto` | zero-copy IRCv3 parser, CoilPack wire codec, CAP state machine, Undertow frame layer, SASL |
| `src/daemon` | SerpentRegistry (comptime modules), client/channel model, connection classes, growable SendQ/RecvQ, nick delay and nick services, runtime flood guard, `+j` raid guard, spam-trap, command dispatch, OroStore, `STATS`/`INFO`, and the live mesh server |

See the [architecture overview](docs/architecture/00-overview.md) for subsystems, request
flow, and a full source map.

## Build & run

Onyx Server targets **Zig 0.17.0-dev.1282+c0f9b51d8** on 64-bit Linux (the reactor uses `io_uring`).

```sh
zig build              # build the daemon (and the `armor` crypto CLI) into zig-out/bin
zig build check        # fast semantic analysis, no binary
zig build test         # run the full test suite
zig build test-smoke   # fast roadmap gate: check + focused TLS/server/config suites
zig build test-roadmap # server roadmap gate: check + focused daemon/protocol suites
zig build all-checks   # deterministic pre-push gate: check + wasm + tests + fuzz + BoGo smokes
zig build all-checks-verbose # same gate with per-test progress for long runs
zig build release      # optimized, stripped ReleaseFast daemon -> zig-out/bin/onyx-server
zig build package      # stage release binary + reference config + systemd unit
zig build run          # run the daemon locally
./tools/genroots.sh    # regenerate package-root imports from the files present
```

Start from the [quickstart](docs/guide/00-quickstart.md), then see the
[operator guide](docs/guide/operators.md), [testing guide](docs/guide/testing.md),
[runbook](docs/RUNBOOK.md), [TLS guide](docs/guide/tls.md), and
[mesh guide](docs/guide/mesh.md). A complete, commented configuration reference lives in
[`docs/reference/config.md`](docs/reference/config.md) and
[`etc/onyx-server.reference.toml`](etc/onyx-server.reference.toml).

## Documentation

The [`docs/`](docs/README.md) tree is grounded in, and cites, the live source:

- **[Guides](docs/guide/00-quickstart.md)** — quickstart, build, TLS, mesh, operators, persistence, upgrade.
- **[Runbook](docs/RUNBOOK.md)** — staging, systemd install, config validation, health checks, hot-upgrade, rollback.
- **[Architecture](docs/architecture/00-overview.md)** — reactor and threading, dispatch and modules, mesh, cryptography, media, upgrade.
- **[Reference](docs/reference/commands/_index.md)** — every command, the config schema, IRCv3/IRCX, modes, numerics, and ISUPPORT.

## Status

**In production.** Onyx Server runs a live two-node post-quantum mesh with session-preserving
`USR2` hot-upgrades, serving IRCv3/IRCX clients and a browser WebSocket client. The
surface includes full IRCv3 + IRCX + SASL, in-process channel/nick services, class-based
connection policy, a single runtime flood guard, `+j` network raid protection, and
spam-trap honeypots. The tree is 900+ Zig source files (300+ daemon modules) with a
deterministic-simulation test suite, all building under Zig 0.17-dev.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for build, test, and
pull-request guidance. Report security issues privately per [SECURITY.md](SECURITY.md).

## License

Onyx Server is licensed under the **GNU Affero General Public License v3.0 or later
(AGPL-3.0-or-later)**. See [`LICENSE`](LICENSE) for the full text; every source file
carries an SPDX header.

Onyx Server is clean-room — it does **not** derive from any prior daemon's code, so this license is
chosen freely rather than inherited. AGPL is deliberate: Onyx Server is a network server, and
§13 ("Remote Network Interaction") means **anyone who runs a modified Onyx Server as a network
service — for example, operating an IRC network — must offer that service's users the
complete corresponding source of their modifications.** Running a private, unmodified
copy carries no such obligation; the requirement attaches only to changes you put into
service. The daemon advertises its source location (the `INFO` source URL) to satisfy
§13's prominent-offer requirement for interactive network users.

Copyright © 2026 Devin Brown.
