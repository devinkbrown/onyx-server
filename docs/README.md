# Onyx Server documentation

*The complete guide, architecture, and reference for the Onyx Server IRC daemon — grounded in, and cited against, the live source.*

Onyx Server is a pure-Zig (0.17-dev) clean-room IRC daemon, built from first principles — not a
clone of any prior daemon. It speaks IRCv3 + IRCX, runs a custom Undertow CRDT mesh with
forward-secret Mooring server links, and ships its own pure-Zig TLS (Armor), media codecs
(CadenceVox/CadenceVis), and in-place upgrade (Helix).

The current daemon surface includes `[class.*]` connection classes for registration-time
resource/admission/flood policy, bounded growable SendQ and RecvQ, optional nick-delay
holds against camping, and live operator introspection through `STATS Y`, `STATS l`, and
richer `INFO`.

**New here?** Start with the [Quickstart](guide/00-quickstart.md), then the
[architecture overview](architecture/00-overview.md). The
[codename glossary](reference/glossary.md) decodes the mythos vocabulary
(Undertow, Mooring, Ripple, Helix, Armor, …).

## Operations

- [Runbook](RUNBOOK.md) — staging, systemd install, config validation, hot-upgrade, rollback, health checks
- [Contributing](../CONTRIBUTING.md) — source-of-truth workflow, build/test lanes, PR checklist
- [Security policy](../SECURITY.md) — private vulnerability reporting

## Guides

- [Quickstart](guide/00-quickstart.md) — build, configure, and run in minutes
- [Building](guide/build.md) — build targets and cross-compilation
- [Testing](guide/testing.md) — focused test lanes, smoke gates, and deterministic assurance
- [TLS](guide/tls.md) — the Armor stack, certificates, and mTLS
- [Operators](guide/operators.md) — SASL-only operator setup and tooling
- [Mesh / S2S linking](guide/mesh.md) — linking nodes into an Undertow mesh
- [In-place upgrade](guide/upgrade.md) — session-preserving `USR2` hot-upgrades
- [Persistence](guide/persistence.md) — the OroStore key/value store

## Architecture

- [Overview](architecture/00-overview.md) — subsystems, request flow, source map
- [Reactor & threading](architecture/01-reactor-threading.md) — `io_uring` and sharded workers
- [World, dispatch & modules](architecture/02-world-dispatch-modules.md) — the SerpentRegistry command system
- [Mesh & S2S](architecture/mesh-s2s.md) — Undertow CRDT, links, partition detection, oper-grant sharing
- [Mesh security](architecture/mesh-security.md) — threat model, AEAD record layer, origin signing, media capabilities
- [Cryptography](architecture/crypto.md) — the Mooring handshake, Armor, signing, sealed tokens
- [Media](architecture/03-media.md) — SFU, transport stack, codecs, WASM shims
- [Upgrade & WASM host](architecture/04-upgrade-wasm.md) — Helix in-place upgrade, OroWasm plugins
- [Event Spine](architecture/event-spine.md) — typed operator/observer events: subscription, severity, replay, stats, flood-collapse
- [Observability & stats](architecture/observability-stats.md) — channel-statistics engine and the public `status.json` mesh-health feed

## Design notes & TLS development

Forward-looking design and hardening docs. These describe *intent and gap
analysis*, not necessarily shipped behavior — where they disagree with the
architecture and reference docs above (verified against code), those are
authoritative.

- [TLS hardening roadmap](dev/tls-roadmap.md) — gap analysis vs. BoringSSL/WolfSSL, with DONE/TODO status (EMS-required, HRR pinning, 0-RTT freshness window, ECH `retry_configs`)
- [BoGo interop](dev/tls-design/bogo.md) — the BoringSSL test-suite shim and coverage
- [Certificate compression](dev/tls-design/cert-compression.md) — RFC 8879 `compress_certificate`
- [kTLS](dev/tls-design/ktls.md) — kernel-offload TLS 1.3 design
- [OCSP stapling](dev/tls-design/ocsp-stapling.md) — must-staple, freshness, delegated responders
- [E2EE Everywhere (Kintsugi)](design/e2ee-everywhere-blueprint.md) — group/channel end-to-end encryption blueprint (design)
- [Adversarial exploit-suite blueprint](research/exploit-suite-blueprint.md) — the direction for a `test-exploit` fail-closed attack harness (`src/security/exploit/`) (research/design)
- [TLS/SSL library comparison](research/tls-ssl-library-comparison.md) — OpenSSL/BoringSSL/LibreSSL/mbedTLS/wolfSSL governance, licensing, CVE history (external-library background, not an Armor evaluation) (research)
- [Zig 0.17 porting notes](dev/zig016-notes.md) — language/stdlib migration notes

## Command reference

- [Index](reference/commands/_index.md) — every command, one line each
- [Connection & registration](reference/commands/connection.md)
- [Messaging](reference/commands/messaging.md)
- [Channels](reference/commands/channels.md)
- [Queries](reference/commands/queries.md)
- [Informational](reference/commands/informational.md) — `INFO`, `STATS Y`, `STATS l`
- [Operator & moderation](reference/commands/oper-moderation.md)
- [Mesh operations](reference/commands/mesh-ops.md)
- [Accounts & services](reference/commands/accounts-services.md)
- [IRCX](reference/commands/ircx.md)
- [Media](reference/commands/media.md)
- [Fantasy / bot commands](reference/commands/fantasy-bot.md)

## Protocol reference

- [Codename glossary](reference/glossary.md) — the mythos vocabulary (Undertow, Mooring, Ripple, Helix, Armor, Ringlane, Koshi, Memo, MeshPass) mapped to source
- [Numerics](reference/protocol/numerics.md)
- [Modes](reference/protocol/modes.md) — user and channel modes, status prefixes
- [ISUPPORT (005)](reference/protocol/isupport.md)
- [Capabilities (IRCv3)](reference/protocol/caps.md)
- [Halloy capability matrix](reference/client-interop-halloy.md) — third-party interop (Halloy vs live CAP/ISUPPORT/commands)
- [IRCv3 profile](reference/ircv3.md) — Onyx Server IRCv3 surface, exclusions, and wire limits
- [CAP registry](reference/protocol/caps.md) — live `CAP LS` table from `cap_specs`
- [IRCX](reference/ircx/README.md) — the IRCX protocol surface (PROP, ACCESS, EVENT, AUTH)
- [Native media MAC](reference/native-media-mac.md) — the media authentication tag
- [Web Push](reference/web-push.md) — browser push for offline DMs (RFC 8291/8292, VAPID discovery)
- [Host cloaking](reference/host-cloaking.md) — keyed-HMAC cloaks, per-account cloak, rotation, and oper cross-mesh identity

## Configuration

- [Config reference](reference/config.md) — every section and key, including `[limits].nick_delay` and `[class.*]`, cited to `src/daemon/config_format.zig`
- [`etc/onyx-server.reference.toml`](../etc/onyx-server.reference.toml) — runnable, annotated example

## Project

- [Q4 2026 feature roadmap](ROADMAP-2026-Q4.md) — daemon feature waves (Now / Next / Later / Moonshot), priorities, and cross-stack dependencies
- [Project README](../README.md)
- [Contributing](../CONTRIBUTING.md)
- [Runbook](RUNBOOK.md)
- [Security policy](../SECURITY.md)
- [License (AGPL-3.0-or-later)](../LICENSE)
