# Onyx Server

Onyx Server is a pure-Zig IRC/IRCX mesh daemon. It includes its own TLS stack,
account services, persistent history, browser WebSocket transport, and media
plane. **Onyx** is the network/client brand. The daemon uses native Undertow
state replication over secured Mooring links rather than a tree S2S protocol.
The production daemon has no C interop or external database dependency.

[Quickstart](docs/guide/00-quickstart.md) · [Feature reference](docs/reference/features.md) ·
[Documentation](docs/README.md) · [Development](docs/development.md) ·
[News](NEWS.md) · [Security](SECURITY.md) · [AGPL-3.0-or-later](LICENSE)

## Build and try it

The accepted Linux release was built with **Zig 0.17.0**. Compiler identity,
platform differences and build targets are documented in the
[build guide](docs/guide/build.md). Use the pinned compiler described there;
development compiler snapshots are not interchangeable.

```sh
git clone https://github.com/devinkbrown/onyx-server.git
cd onyx-server
zig build
./zig-out/bin/onyx-server --check-config packaging/onyx-server.quickstart.toml
./zig-out/bin/onyx-server packaging/onyx-server.quickstart.toml
```

The evaluation configuration listens on plaintext IRC `:6667` and WebSocket
`:8080`. Relative account state uses the working directory; the automatically
generated node key is stored beside the selected configuration file. Use a dedicated
writable directory for persistent deployments. Configure certificates and TLS
before public use; follow the [quickstart](docs/guide/00-quickstart.md) and
[TLS guide](docs/guide/tls.md). For containers, release bundles, Alpine packages
and verification, see [packaging](packaging/README.md).

## Features and their boundaries

| Surface | Behavior | Detailed documentation |
|---|---|---|
| IRC and IRCX | Registration, channels, modes, access lists, properties, events, monitoring, moderation and operator commands. | [Command index](docs/reference/commands/_index.md), [IRCX](docs/reference/ircx/README.md) |
| Capabilities and history | IRCv3 negotiation, message IDs/timestamps, history and conversation tags. Advertised capabilities depend on runtime configuration. | [Capabilities](docs/reference/protocol/caps.md), [messaging](docs/reference/commands/messaging.md) |
| Accounts and reusable sessions | Account authentication, SCRAM, certificate authentication, durable account tokens, exact attachment credentials and mesh session policy. These credential types have different recovery guarantees. | [Services](docs/reference/commands/accounts-services.md), [credential domains](docs/reference/credential-domains.md) |
| Mesh and event delivery | Hybrid post-quantum secured links, signed-origin events, retained replay authority, retry and duplicate/equivocation handling. Cold-restart custody has explicit limits. | [Mesh](docs/guide/mesh.md), [MESSAGE_V2 contract](docs/design/message-v2-exact-once.md) |
| TLS and cryptography | Armor TLS 1.3, hardened TLS 1.2, certificate tooling and configured kTLS offload; supported paths vary by platform and certificate policy. | [TLS](docs/guide/tls.md), [cryptography](docs/architecture/crypto.md) |
| Browser and media | WebSocket, WebTransport, native media and WebRTC/SFU components, codecs and authenticated media paths. Active transport state can block upgrades. | [Media architecture](docs/architecture/03-media.md), [media commands](docs/reference/commands/media.md) |
| Operations | Connection classes, bounded queues, anti-abuse policy, cloaking, metrics, status feeds, backups, diagnostics, setup plans and service kits. | [Configuration](docs/reference/config.md), [operators](docs/guide/operators.md), [runbook](docs/RUNBOOK.md) |
| Helix upgrades | Guarded, transactional handoff where the platform, candidate and active listener/session state are compatible. Refusal preserves the predecessor. | [Upgrade guide](docs/guide/upgrade.md), [architecture](docs/architecture/04-upgrade-wasm.md) |

The [complete feature index](docs/reference/features.md) connects the public
surfaces to configuration, commands, source ownership and verification. A
compiled primitive, a proposal, and an accepted deployed feature are separate
claims; historical roadmaps do not establish support.

## Current release status

The source manifest is **0.9.0**. Both production nodes use the improved
OpenRC/systemd kits. Exact running revisions and hashes, service paths,
acceptance scope and rollback facts have one
canonical home: [production status](docs/ops/onyx-server-paths.md).

The deployed WebTransport listener blocks production Helix; that fleet uses
cold restarts one node at a time. Saved durable account-token recovery was
verified after both restarts. The acceptance does not claim preservation of
old exact attachment tokens across a cold boundary.

The latest published GitHub asset release, checked **2026-11-03**, is still
[v0.5.6](https://github.com/devinkbrown/onyx-server/releases/tag/v0.5.6).
The source version, running image and published release tag are independent.
See [NEWS](NEWS.md) for the accepted release and later test-only changes.

## Development and testing

```sh
zig build check                          # semantic check
zig build test-mod -Dtest-filter=ACCESS  # compile a focused selection
zig build test-cached -- --test-filter="reusable session"
zig build all-checks --summary all       # full deterministic Debug release gate
zig build test -Doptimize=safe --summary all
```

On supported native POSIX hosts, unfiltered full gates cover all three test
roots with bounded parallel workers. Cached lanes reuse a root binary for
runtime selections; documentation-only commits no longer invalidate test
version metadata. Windows and cross targets retain their documented graphs.

The measured complete Debug gate fell from **22.1 to 15.7 minutes** after the
combined test improvements, with all previous test names preserved and two
controls added: **11,236 passed, 313 skipped, zero failures**. Cold ReleaseSafe
compilation remains expensive. Exact provenance and measurement limits are in
the [verification report](docs/audit/release-and-test-speed-2026-11-03.md).

Start with [development](docs/development.md), then use the detailed
[testing guide](docs/guide/testing.md), [source map](docs/architecture/source-modules.md),
and [contribution process](CONTRIBUTING.md). Documentation changes are checked
with `python3 -B tools/check_docs.py`; [maintenance rules](docs/MAINTENANCE.md)
explain how current references and historical evidence stay distinct.
