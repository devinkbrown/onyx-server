# Onyx Server architecture overview

_System overview of the client-facing daemon, request flow, source map, and the architecture document index._

Onyx Server is a Zig package and daemon executable. The package manifest sets `.minimum_zig_version = "0.17.0-dev.1282+c0f9b51d8"` and lists an empty `.dependencies` table, so the current tree builds from checked-in Zig source. Evidence: `build.zig.zon:34`, `build.zig.zon:40`. The library root re-exports the major namespaces `crypto`, `daemon`, `proto`, and `substrate`, plus the OroWasm host and browser transport shim roots. Evidence: `src/root.zig:20`, `src/root.zig:21`, `src/root.zig:22`, `src/root.zig:23`, `src/root.zig:29`, `src/root.zig:34`.

This overview covers the client-facing daemon, local world, module dispatch, Ringlane reactor model, media, Helix upgrade, OroWasm, and source-tree orientation. Undertow mesh/S2S and cryptography are summarized here only at subsystem level; see [mesh-s2s.md](mesh-s2s.md) and [crypto.md](crypto.md) for their deeper design.

## Major subsystems

| Area | Current source of truth | What it owns | Evidence |
| --- | --- | --- | --- |
| Build/package | `build.zig`, `build.zig.zon`, `etc/systemd/onyx-server.service` | Zig package metadata, `onyx-server` executable, focused test/run steps, ReleaseFast package staging, systemd unit, 64-bit daemon target guard | `build.zig`, `build.zig.zon`, `etc/systemd/onyx-server.service` |
| Daemon server | `src/daemon/server.zig` | Linux TCP server, connection table, registration integration, live stores, registry/WASM dispatch, media/upgrade wiring | `src/daemon/server.zig:2777`, `src/daemon/server.zig:30232` |
| Ringlane I/O | `src/substrate/io/root.zig`, `src/substrate/io/ring.zig`, `src/substrate/io/buf_ring.zig`, `src/daemon/server.zig` | Linux io_uring fast path, completion decoding, provided-buffer bookkeeping, per-shard reactor rings | `src/substrate/io/root.zig:4`, `src/substrate/io/ring.zig:4`, `src/substrate/io/buf_ring.zig:4`, `src/daemon/server.zig:711` |
| Connection classes | `src/daemon/conn_class.zig`, `src/daemon/server.zig` | Named per-connection policy: sendq/recvq ceilings, max_clients/per_ip/channels, timeouts, TLS/SASL requirements, flood control, nick-delay exemption; CIDR/TLS/account/oper/ident/host matching; per-class assignment at registration | `src/daemon/conn_class.zig:4`, `src/daemon/server.zig:9766` |
| Nick delay | `src/daemon/nick_delay.zig`, `src/daemon/server.zig` | Held-nick registry; holds a released nick for a configured window to prevent nick camping; per-account reclaim and oper/class bypass | `src/daemon/nick_delay.zig:4`, `src/daemon/server.zig:4547`, `src/daemon/server.zig:8606`, `src/daemon/server.zig:8632` |
| Pre-registration dispatch | `src/daemon/dispatch.zig` | PASS/NICK/USER/CAP/AUTHENTICATE/PING/PONG/QUIT, CAP/labeled-response handling, welcome burst | `src/daemon/dispatch.zig:1587`, `src/daemon/dispatch.zig:1710`, `src/daemon/dispatch.zig:2078` |
| Protocol inventory | `src/proto/protocol_inventory.zig` | Canonical network name, server name, ISUPPORT tokens, CHANMODES, runtime advertised-limit override | `src/proto/protocol_inventory.zig:4`, `src/proto/protocol_inventory.zig:17`, `src/proto/protocol_inventory.zig:58`, `src/proto/protocol_inventory.zig:61` |
| Local world | `src/daemon/world.zig` | Nick ownership, channel membership, topics, modes, bans, invitations, RCU mirrors, local-only state | `src/daemon/world.zig:4`, `src/daemon/world.zig:13`, `src/daemon/world.zig:172` |
| Undertow CRDT mesh | `src/substrate/undertow/root.zig`, `src/substrate/undertow/mesh.zig`, `src/substrate/undertow/s2s_peer.zig`, `src/daemon/secured_s2s_link.zig` | CRDT/gossip mesh primitives, S2S peer driver, route/membership state, secured live S2S integration | `src/substrate/undertow/root.zig:7`, `src/substrate/undertow/mesh.zig:4`, `src/substrate/undertow/s2s_peer.zig:4`, `src/daemon/secured_s2s_link.zig:4` |
| Membership repair | `src/daemon/server.zig` | Reactor 0 re-bursts the full local roster to every established peer about every 30 seconds (`membership_resync_interval_ms`); cost grows with peers times the local roster. A two-node link dies on ping timeout. Ripple is a library, not on the daemon timer. | `src/daemon/server.zig:1117`, `src/daemon/server.zig:6307`, `src/daemon/server.zig:6362` |
| Mooring handshake | `src/crypto/mooring_handshake.zig`, `src/crypto/mooring_session.zig`, `src/proto/mooring.zig`, `src/daemon/secured_s2s_link.zig` | S2S secure-channel handshake, session record layer, frame-family admission, Helix resume state for secured links | `src/crypto/mooring_handshake.zig:4`, `src/crypto/root.zig:60`, `src/crypto/root.zig:61`, `src/daemon/secured_s2s_link.zig:29` |
| Armor TLS | `src/crypto/root.zig`, `src/crypto/tls*.zig`, `src/daemon/tls_conn.zig` | Pure Zig TLS policy, client/server handshakes, record layer, kTLS adapter, TLS resume/export state | `src/crypto/root.zig:4`, `src/crypto/root.zig:50`, `src/crypto/root.zig:56`, `src/daemon/tls_conn.zig:4` |
| SerpentRegistry modules | `src/daemon/registry.zig`, `src/daemon/modules/manifest.zig`, `src/daemon/modules/*.zig` | Comptime module metadata, validated command/hook/cap tables, gated command dispatch, MODULES/COMMANDS introspection | `src/daemon/registry.zig:4`, `src/daemon/modules/manifest.zig:4`, `src/daemon/registry.zig:521`, `src/daemon/registry.zig:556` |
| Reactor/threading | `src/daemon/server.zig`, `src/daemon/reactor_pool.zig`, `src/daemon/reactor_fabric.zig`, `src/substrate/reactor.zig` | Per-reactor connection slabs, optional worker pool, cross-shard delivery fabric, io_uring completion loop integration | `src/daemon/server.zig:2510`, `src/daemon/server.zig:5474`, `src/daemon/reactor_pool.zig:1`, `src/daemon/reactor_fabric.zig:1`, `src/substrate/reactor.zig:4` |
| Media | `src/substrate/undertow/media.zig`, `src/daemon/media_room.zig`, `src/daemon/media_plane.zig`, `src/daemon/native_media_transport.zig`, `src/daemon/media_bridge.zig` | SFU participant model, per-channel rooms, RTP/STUN media plane, native CadenceVox/CadenceVis UDP leg, cross-leg rewrap | `src/substrate/undertow/media.zig`, `src/daemon/media_room.zig`, `src/daemon/media_plane.zig`, `src/daemon/native_media_transport.zig`, `src/daemon/media_bridge.zig` |
| Helix upgrade | `src/daemon/modules/upgrade.zig`, `src/daemon/server.zig`, `src/daemon/helix/live.zig`, `src/daemon/helix/handoff.zig` | UPGRADE command, sealed memfd arena, listener/session fd inheritance, successor adoption | `src/daemon/modules/upgrade.zig`, `src/daemon/server.zig:1622`, `src/daemon/helix/live.zig`, `src/daemon/helix/handoff.zig` |
| OroWasm | `src/wasm/host/*`, `src/wasm/cadence_wasm.zig`, `src/wasm/browser_transport.zig` | Control-plane plugin interpreter/bridge/capabilities and browser CadenceVox/CadenceVis exports | `src/wasm/host/interp.zig`, `src/wasm/host/bridge.zig`, `src/wasm/cadence_wasm.zig`, `src/wasm/browser_transport.zig` |
| OroStore persistence | `src/daemon/store.zig`, `src/daemon/services.zig`, `src/main.zig` | Embedded WAL/snapshot persistence, services account/channel state, storage config, account-store boot integration | `src/daemon/store.zig:4`, `src/daemon/store.zig:97`, `src/daemon/services.zig:4`, `src/main.zig:391` |
| Event Spine | `src/daemon/event_spine.zig`, `src/daemon/event_history.zig`, `src/daemon/event_collapse.zig`, `src/daemon/server.zig` | Typed operator/observer events: `EVENT` category subscription and severity filtering, `OBSERVE` mask feed, `EVENT REPLAY` history ring, `EVENT STATS`, IRCv3 message-tags, flood-collapse | `src/daemon/event_spine.zig:91`, `src/daemon/event_spine.zig:194`, `src/daemon/event_history.zig:4`, `src/daemon/event_collapse.zig:4` |
| Web Push | `src/crypto/webpush.zig`, `src/daemon/webpush.zig` | Browser push for offline DMs: RFC 8291 content encryption plus RFC 8292 VAPID, background delivery worker, ISUPPORT `VAPID=` discovery, account-scoped subscriptions | `src/crypto/webpush.zig:5`, `src/daemon/webpush.zig:6`, `src/daemon/webpush.zig:152` |
| Host cloaking | `src/proto/cloak.zig`, `src/daemon/config_format.zig`, `src/daemon/server.zig`, `src/daemon/whois.zig` | Keyed-HMAC v2 IP cloaks, hierarchical or opaque mode, per-account cloak, rotatable key with ban continuity, GeoIP/ASN mixing, oper-only real host/certfp in WHOIS | `src/proto/cloak.zig:4`, `src/daemon/config_format.zig:611`, `src/daemon/server.zig:5733`, `src/daemon/whois.zig:692` |
| Observability / stats | `src/daemon/chanstats.zig`, `src/daemon/server.zig` | Per-channel statistics engine, JSON dashboard feed, USR2-durable binary snapshot, dead-channel prune, and public `status.json` mesh-health feed | `src/daemon/chanstats.zig:1`, `src/daemon/server.zig:5081`, `src/daemon/server.zig:5105` |

## Build, Test, And Package Surface

The build graph is part of the architecture, not only developer tooling. It exposes
the operational lanes used to keep the daemon deployable:

| Step | Role |
|---|---|
| `check` | Type-checks the daemon without emitting a binary. |
| `test-smoke` | Fast inner-loop gate for semantic, TLS, server, and config behavior. |
| `test-roadmap` | Server-roadmap gate spanning server/config/IRCX/event/mesh/services/TLS. |
| `test-media` / `test-helix` | Focused media and upgrade lanes kept independently runnable. |
| `test-mesh` / `test-tls` / `test-server` / `test-ircx` | Focused subsystem suites for Undertow, Armor TLS, daemon integration, and IRCX behavior. |
| `test-cli` | Tests for the standalone `armor` crypto toolkit (openssl-parity verbs over the Armor substrate). Evidence: `build.zig:478`. |
| `all-checks` | Deterministic pre-push gate: check, WASM build, full tests, fuzz corpus replay, and BoGo shim self-tests. |
| `tools/bogo.sh` / CI `bogo` | External pinned BoringSSL interoperability gate with exact non-vacuous pass/skip baseline enforcement. |
| `release` | ReleaseFast stripped production binary. |
| `package` | ReleaseFast daemon plus reference config and systemd unit staged into the install prefix. |

Verbose test variants use `tools/verbose_test_runner.zig` to print each test name,
duration, summary counts, and the slowest tests, which makes long daemon suites
observable in CI and tmux.

A forward-looking assurance direction — an adversarial exploit/attack harness
(`zig build test-exploit` over a `src/security/exploit/` tree, table-driven over
hostile-input corpora, asserting the daemon fails closed) — is specified in
[docs/research/exploit-suite-blueprint.md](../research/exploit-suite-blueprint.md).
That is a design blueprint (research), not shipped behavior.

## End-to-end client request flow

| Step | Flow | Evidence |
| --- | --- | --- |
| 1 | `runOnce` binds the current thread to its reactor, performs the mesh auto-connect boot pass on reactor 0, arms accept/wake/timer operations, waits for at least one io_uring completion, reaps completions, drains cross-shard fabric if present, then drains webhook posts. | `src/daemon/server.zig:5424`, `src/daemon/server.zig:5429`, `src/daemon/server.zig:5434`, `src/daemon/server.zig:5441`, `src/daemon/server.zig:5444`, `src/daemon/server.zig:5449`, `src/daemon/server.zig:5457` |
| 2 | A recv completion calls `handleRecv`: inbound bytes flow through `driveClientBytes`, kTLS control records are demuxed by the kTLS path, and S2S links are routed to the secured/plain S2S drivers before ordinary client/TLS handling. | `src/daemon/server.zig:6748`, `src/daemon/server.zig:6752`, `src/daemon/server.zig:6789`, `src/daemon/server.zig:6522`, `src/daemon/server.zig:6523`, `src/daemon/server.zig:6525`, `src/daemon/server.zig:6541` |
| 3 | Complete client lines accumulate through the RecvQ, then `processLiveLine` parses them with the shared IRC line parser. The parser strips CR/LF endings, rejects embedded NUL/line breaks, supports tags and prefixes, and caps params/tags. | `src/daemon/server.zig:8098`, `src/daemon/server.zig:8114`, `src/daemon/server.zig:8120`, `src/proto/irc_line.zig:4`, `src/proto/irc_line.zig:63`, `src/proto/irc_line.zig:152` |
| 4 | Before registration, the server handles IRCX enable/query and pre-away locally, then calls `processLine`, which adapts into `dispatch.dispatchLine`. | `src/daemon/server.zig:8152`, `src/daemon/server.zig:8155`, `src/daemon/server.zig:8177`, `src/daemon/server.zig:8208`, `src/daemon/server.zig:2355`, `src/daemon/server.zig:2379` |
| 5 | When `dispatchLine` completes registration, the server applies the visible host, registers the nick in `World`, sends LUSERS/MOTD, enforces Warden/DNSBL/SACCESS/class admission, applies seen/session/autojoin/offline-delivery hooks, assigns the connection class, emits the local welcome, fires the registry `client_registered` hook, and evaluates nick protection. | `src/daemon/server.zig:8224`, `src/daemon/server.zig:8230`, `src/daemon/server.zig:8231`, `src/daemon/server.zig:8235`, `src/daemon/server.zig:8240`, `src/daemon/server.zig:8267`, `src/daemon/server.zig:8270`, `src/daemon/server.zig:8284`, `src/daemon/server.zig:8285`, `src/daemon/server.zig:8503`, `src/daemon/server.zig:9766` |
| 6 | After registration, PING still uses `processLine`, but other lines enter `dispatchRegistered`. | `src/daemon/server.zig:8294`, `src/daemon/server.zig:8296`, `src/daemon/server.zig:8310`, `src/daemon/server.zig:8321` |
| 7 | `dispatchRegistered` refreshes the world's wall-clock, routes multiline batches if negotiated, dispatches through SerpentRegistry, then through OroWasm plugins, then falls back to the lower registration-handshake processor for handshake verbs. | `src/daemon/server.zig:8328`, `src/daemon/server.zig:8333`, `src/daemon/server.zig:8341`, `src/daemon/server.zig:8371`, `src/daemon/server.zig:8382`, `src/daemon/server.zig:8412`, `src/daemon/server.zig:8434` |
| 8 | Finished output is queued to a connection-local send buffer (inline plus heap overflow, bounded by per-class `sendq`) or handed to the owning shard through `enqueueDelivery`; send completions drain the buffer and close when needed. Exceeding the SendQ ceiling fails the append. | `src/daemon/server.zig:6844`, `src/daemon/server.zig:6888`, `src/daemon/server.zig:6898`, `src/daemon/server.zig:6916`, `src/daemon/server.zig:6801`, `src/daemon/server.zig:6814`, `src/daemon/server.zig:30734`, `src/daemon/server.zig:30759` |

## Source tree map

| Path | Role | Evidence |
| --- | --- | --- |
| `src/main.zig` | Boot CLI, config loading, server initialization, OroStore account-store setup, Helix successor adoption, run loop | `src/main.zig:109`, `src/main.zig:244`, `src/main.zig:391`, `src/main.zig:749`, `src/main.zig:898` |
| `src/root.zig` | Public package root and namespace re-exports | `src/root.zig:4`, `src/root.zig:20`, `src/root.zig:29`, `src/root.zig:34` |
| `src/daemon/` | IRC daemon runtime, world, modules, services, media plane, Helix, reactor helpers, OroStore consumers | `src/daemon/root.zig:4`, `src/daemon/root.zig:46`, `src/daemon/root.zig:84`, `src/daemon/root.zig:102`, `src/daemon/root.zig:142` |
| `src/proto/` | Protocol codecs/builders/inventory used by daemon, modules, mesh links, media, TLS-adjacent codecs, and tests | `src/proto/root.zig:8`, `src/proto/root.zig:222`, `src/proto/root.zig:253`, `src/proto/root.zig:319`, `src/proto/root.zig:320` |
| `src/substrate/` | Lower-level runtime primitives: Ringlane backend, Undertow package, reactor abstraction, queues, EBR/RCU support, CRDT/data structures, media transport helpers | `src/substrate/root.zig:46`, `src/substrate/root.zig:95`, `src/substrate/root.zig:120`, `src/substrate/root.zig:138`, `src/substrate/io/root.zig:4`, `src/substrate/undertow/root.zig:7` |
| `src/crypto/` | Armor TLS, Mooring handshake/session, primitives, Web Push crypto, X.509 and signing/verification surfaces | `src/crypto/root.zig:4`, `src/crypto/root.zig:50`, `src/crypto/root.zig:56`, `src/crypto/root.zig:60`, `src/crypto/root.zig:64` |
| `src/wasm/` | OroWasm host, browser transport shim, and CadenceVox/CadenceVis browser exports | `src/root.zig:29`, `src/root.zig:34`, `src/wasm/cadence_wasm.zig`, `src/wasm/browser_transport.zig` |

## Architecture index

| Document | Scope |
| --- | --- |
| [00-overview.md](00-overview.md) | System overview, request flow, source map, architecture index |
| [01-reactor-threading.md](01-reactor-threading.md) | Ringlane/io_uring reactor, worker shards, world locking, live multithreading status |
| [02-world-dispatch-modules.md](02-world-dispatch-modules.md) | `World`, preregistration dispatch, SerpentRegistry modules, hooks, introspection |
| [03-media.md](03-media.md) | SFU/session model, media rooms, RTP/STUN plane, native CadenceVox/CadenceVis transport, WASM shims |
| [04-upgrade-wasm.md](04-upgrade-wasm.md) | Helix UPGRADE handoff and OroWasm plugin host |
| [event-spine.md](event-spine.md) | Typed operator/observer event plane: subscription, severity, replay, stats, flood-collapse |
| [observability-stats.md](observability-stats.md) | Channel-statistics engine plus the public `status.json` mesh-health feed |
| [mesh-s2s.md](mesh-s2s.md) | Mesh/S2S architecture; separate document |
| [mesh-security.md](mesh-security.md) | S2S threat model, AEAD record layer, per-frame origin signing, host-cloak federation |
| [crypto.md](crypto.md) | Cryptography architecture; separate document |

## Planning notes and divergences

This architecture set treats the current source as authoritative. The table below records places where the live code has moved ahead of, or diverged from, older design intent.

| Topic | Current-code finding | Evidence |
| --- | --- | --- |
| Registered command dispatch | Current `dispatchRegistered` says daemon-owned post-registration commands are resolved by the registry block; its remaining direct path is the preregistration command processor. This diverges from any older design text that describes a live legacy if/else command chain. | `src/daemon/server.zig:8341`, `src/daemon/server.zig:8371`, `src/daemon/server.zig:8412` |
| Multithreading | Default config is one shard, but current code can allocate multiple reactors and spawn one worker per reactor when `num_shards > 1`. A nearby comment still says values above 1 are clamped at `runThreaded`, which does not match the current implementation. | `src/daemon/server.zig:1635`, `src/daemon/server.zig:3246`, `src/daemon/server.zig:5479`, `src/daemon/server.zig:5485`, `src/daemon/server.zig:5500` |
| Helix session carry-over | `session_snapshot.zig` now documents channel memberships as part of the wire format, and the successor re-joins carried memberships with their member-mode bits. | `src/daemon/helix/session_snapshot.zig:7`, `src/daemon/helix/session_snapshot.zig:20`, `src/daemon/helix/session_snapshot.zig:51`, `src/daemon/server.zig:16773`, `src/daemon/server.zig:16776` |
