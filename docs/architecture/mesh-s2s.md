# Onyx Server mesh and S2S architecture

*The Undertow mesh and server-to-server layer as implemented in the current source tree.*

The mesh vocabulary (see the [glossary](../reference/glossary.md)): Undertow is the S2S CRDT mesh state model, Mooring is the secure handshake layer, Ripple is the witness-quorum library, and Concord is the CRDT library. The running daemon repairs membership by re-bursting the full local roster about every 30 seconds to each established peer, so cost grows with peers times the local roster. A two-node link dies on ping timeout; with `witness_quorum` floored at 2, a pair cannot form a witnessed quorum. The design uses a sovereign node identity and does not key the mesh on server names, origins, or nicks. The code today implements a clean-room Onyx Server mesh.

## Layer map

| Layer | Source | Current role |
| --- | --- | --- |
| IRC daemon integration | `src/daemon/server.zig` | Owns sockets, peer connection lifecycle, local world projection, membership burst, relay delivery, mesh operator commands, partition transition logging, oper grants, and session reclaim. |
| Secured link adapter | `src/daemon/secured_s2s_link.zig` | Frames the Mooring TOFU prekey and AKE messages, authenticates the peer identity, then passes decrypted inner CRDT/S2S bytes to `S2sLink`. |
| Plain link adapter | `src/daemon/s2s_link.zig` | Buffering adapter around the pure `S2sPeer`; owns per-peer channel CRDT state and outbound byte accumulation. |
| Pure peer driver | `src/substrate/undertow/s2s_peer.zig` | Streams length-prefixed frames, performs mesh handshake/burst/delta/gossip dispatch, queues inbound user messages and oper grants, and maintains per-peer registry and route state. |
| Mesh state substrate | `src/substrate/undertow/*.zig` | CRDT channel state, bounded membership views, gossip rounds, route tables, server registry, Merkle-guided repair, message relay, and partition analysis. |
| Wire frame codec | `src/proto/s2s_frame.zig` | Five-byte S2S frame header: frame type plus little-endian payload length. |

## Identities and registries

The secured hot path authenticates a canonical 20-byte Mooring node id and derives the Undertow `u64` routing handle from it with `node_short_id.shortId`; that `shortId` is the mesh handle used by `S2sPeer`, route tables, and gossip, while server names, origins, and nicks are not identities ([src/crypto/node_short_id.zig](../../src/crypto/node_short_id.zig), [src/crypto/mooring_session.zig](../../src/crypto/mooring_session.zig)). Registry entries store `node_id`, display `name`, description, hop count, optional `uplink`, and `last_seen_ms` ([src/substrate/undertow/server_registry.zig](../../src/substrate/undertow/server_registry.zig)).

On a raw `S2sLink`, the adapter initializes the channel CRDT replica lane from the local node id ([src/daemon/s2s_link.zig](../../src/daemon/s2s_link.zig)). On a secured link, the authenticated Mooring peer short id becomes the inner link's remote node id, while the local node id is derived from the configured node identity ([src/daemon/secured_s2s_link.zig](../../src/daemon/secured_s2s_link.zig)).

The daemon also keeps operational mesh state outside the substrate: peer health, a bounded mesh event log, and a persistent partition `SeenSet` ([src/daemon/server.zig](../../src/daemon/server.zig)).

## S2S frame codec

`s2s_frame.zig` defines a simple length-prefixed frame. The header is exactly five bytes: one `u8` frame type tag and a little-endian `u32` payload length, followed by the payload bytes ([src/proto/s2s_frame.zig](../../src/proto/s2s_frame.zig)). The default maximum frame size is 1 MiB ([src/proto/s2s_frame.zig](../../src/proto/s2s_frame.zig)).

`src/proto/s2s_frame.zig` is now the source of truth for the public S2S frame catalog and the handshake capability catalog. `frame_catalog` records the tag, family, authentication mode, capability gate, and summary for every known frame; the codec tests assert that every `FrameType` is covered exactly once. `capability_catalog` records the stable handshake bits used by the peer driver and Helix resume snapshots.

| Capability | Bit | Mask | Meaning |
|---|---:|---:|---|
| `frame-signing` | `0` | `0x01` | Signed-frame envelopes for direct-owned state, oper-trust facts, and repair frames. |
| `member-account` | `1` | `0x02` | Optional account fields on membership and nick-change propagation. |
| `member-oper-info` | `2` | `0x04` | Secured-only real-host and certificate fingerprint propagation for oper-visible identity. |
| `repair-frames` | `3` | `0x08` | Merkle-guided anti-entropy repair summary, request, and response frames. |
| `session-replica-v2` | `4` | `0x10` | Secured signed OFFER, ACK, and REVOKE transport for reusable session replicas. |
| `secure-relay-v2` | `5` | `0x20` | Secured multi-hop user relay with immutable origin-signed routing scope. |
| `session-attachment-lease-v2` | `6` | `0x40` | Secured short-lived positive attachment evidence for SESSION_REPLICA v2. |
| `event-spine-v2` | `7` | `0x80` | Secured multi-hop operator events with immutable origin signatures. |

The complete 48-frame catalog below is reconciled against `FrameType` and
`frame_catalog`; `secured_signed` means secured-link admission plus the applicable
signature checks. A listed codec family is not itself a deployment-enable switch.
MESSAGE/MESSAGE_V2 have a separate 64 KiB payload bound below the generic 1 MiB
frame ceiling. Per-peer secured media budgets can be larger without increasing
portable-session snapshot limits.

| Frame | Tag | Family | Authentication | Gate | Purpose |
|---|---:|---|---|---|---|
| `HANDSHAKE` | `0x01` | handshake | `unsigned` | family-specific | Exchanges node id, epoch, server name, description, and negotiated S2S capabilities. |
| `BURST` | `0x02` | crdt | `unsigned` | family-specific | Initial serialized channel CRDT state burst. |
| `DELTA` | `0x03` | crdt | `unsigned` | family-specific | Incremental channel CRDT delta. |
| `GOSSIP` | `0x04` | membership | `unsigned` | family-specific | Ripple membership and suspicion gossip payload. |
| `PING` | `0x05` | control | `unsigned` | family-specific | Liveness probe; answered with a matching PONG payload. |
| `PONG` | `0x06` | control | `unsigned` | family-specific | Liveness probe response. |
| `QUIT` | `0x07` | control | `unsigned` | family-specific | Remote peer close notification. |
| `MEMBERSHIP` | `0x08` | membership | `signable` | family-specific | Channel-member route fact; optional account and oper-info extensions are capability-gated. |
| `MESSAGE` | `0x09` | relay | `signed` | family-specific | Cross-node PRIVMSG, NOTICE, TAGMSG, DATA, and WHISPER relay with self-contained origin signature. |
| `OPER_GRANT` | `0x0A` | oper | `secured_signed` | family-specific | Cross-mesh operator authorization grant verified against the secured peer identity. |
| `CHANNEL_MODE_FLAGS` | `0x0B` | membership | `signable` | family-specific | Boolean channel-mode flag fact. |
| `CHANNEL_LIST` | `0x0C` | membership | `signable` | family-specific | Channel list-mode fact for ban, exception, and invite-exception lists. |
| `CHANNEL_PROP` | `0x0D` | membership | `signed` | family-specific | IRCX channel property LWW fact with multi-hop origin signature. |
| `TOPIC` | `0x0E` | membership | `signable` | family-specific | Channel topic fact. |
| `NICKCHANGE` | `0x0F` | membership | `signable` | family-specific | Remote nick-change fact; optional account extension is capability-gated. |
| `CHANNEL_MODE_STATE` | `0x10` | membership | `signable` | family-specific | Parameter and IRCX channel-mode state snapshot. |
| `SESSION_MIGRATE` | `0x11` | relay | `signed` | family-specific | Signed session-migration capsule for live reclaim on the owning node. |
| `ENTITY_PROP` | `0x12` | membership | `signed` | family-specific | IRCX user/member property LWW fact with kind-tagged multi-hop origin signature. |
| `CLONE_COUNT` | `0x13` | notification | `unsigned` | family-specific | Per-node clone-count gossip using salted IP hashes. |
| `OPER_EVENT` | `0x14` | oper | `signed` | family-specific | Network-wide Event-Spine operator notification. |
| `OBSERVE_EVENT` | `0x15` | oper | `signed` | family-specific | Network-wide operator OBSERVE lifecycle record. |
| `KILL` | `0x16` | oper | `signed` | family-specific | Targeted cross-mesh operator KILL command. |
| `WARD` | `0x17` | oper | `signed` | family-specific | Network-wide Warden mesh-ban convergence record. |
| `RESYNC` | `0x18` | control | `unsigned` | family-specific | Full-state resync request after hot-upgrade link preservation. |
| `REPAIR_SUMMARY` | `0x19` | repair | `signed` | repair-frames | Merkle/RBSR anti-entropy summary. |
| `REPAIR_REQUEST` | `0x1A` | repair | `signed` | repair-frames | Request for CRDT records whose hashes differ from a repair summary. |
| `REPAIR_RESPONSE` | `0x1B` | repair | `signed` | repair-frames | Repair records that backfill requested CRDT entities. |
| `MEMO_PUSH` | `0x1C` | notification | `secured_signed` | family-specific | Secured-only Web Push hint for offline memo delivery. |
| `SESSION_MIGRATE_CONSUMED` | `0x1D` | relay | `signed` | family-specific | Converges a successful session claim and prevents stale migration resurrection. |
| `SESSION_REPLICA_OFFER` | `0x1E` | session | `secured_signed` | session-replica-v2 | SESSION_REPLICA v2 signed upsert offer. |
| `SESSION_REPLICA_ACK` | `0x1F` | session | `secured_signed` | session-replica-v2 | SESSION_REPLICA v2 signed acknowledgment and route observation. |
| `SESSION_REPLICA_REVOKE` | `0x20` | session | `secured_signed` | session-replica-v2 | SESSION_REPLICA v2 signed removal tombstone. |
| `MESSAGE_V2` | `0x21` | relay | `secured_signed` | secure-relay-v2 | Secured multi-hop user relay with immutable origin signature and routing scope. |
| `SESSION_REPLICA_ATTACHMENT_LEASE` | `0x22` | session | `secured_signed` | session-replica-v2 | SESSION_REPLICA v2 signed positive attachment lease. |
| `OPER_EVENT_V2` | `0x23` | oper | `secured_signed` | event-spine-v2 | Secured multi-hop Event Spine notification with immutable origin signature. |
| `MESSAGE_V2_ACK` | `0x24` | relay | `secured_signed` | secure-relay-v2 | Secured hop receipt for an admitted MESSAGE_V2 RelayId. |
| `MEDIA_WS_DATAGRAM` | `0x25` | media | `secured_signed` | family-specific | Origin-only cascade of an already-validated browser Cadence WS media datagram. |
| `E2EE_GROUP` | `0x26` | relay | `secured_signed` | secure-relay-v2 | Secured opaque E2EEGROUP control with immutable origin signature and RelayId. |
| `E2EE_GROUP_ACK` | `0x27` | relay | `secured_signed` | secure-relay-v2 | Secured immediate-hop receipt for an admitted E2EEGROUP RelayId. |
| `MEMBERSHIP_SYNC` | `0x28` | membership | `signable` | family-specific | Authenticated completion marker for a full peer membership snapshot. |
| `SEARCH_QUERY` | `0x29` | relay | `signed` | family-specific | Signed history search request for one target. Gated by a PING extension, not a new handshake bit. |
| `SEARCH_REPLY` | `0x2A` | relay | `signed` | family-specific | Signed history search hits. The asker authorizes each hit and drops ciphertext. |
| `KEYTRANS_HEAD` | `0x2B` | relay | `signed` | family-specific | Signed key-transparency log head. Gated by a PING extension. A higher entry count replaces the stored head; an older head does not. |
| `GUEST_PRESENCE` | `0x2C` | relay | `secured_signed` | family-specific | Original mesh-presence v2 record. The hop envelope authenticates the immediate peer; the origin signature is unchanged. |
| `GUEST_DIRECT` | `0x2D` | relay | `secured_signed` | family-specific | Exact ordinary-guest direct message bound to both guest incarnations. Forward only toward the recipient. |
| `WHOIS_PROFILE` | `0x2E` | membership | `signable` | family-specific | Remote WHOIS session facts. Gated by a PING extension. rDNS is present only on a secured oper-info link. |
| `GUEST_FRONTIER` | `0x2F` | relay | `secured_signed` | family-specific | Original signed complete guest-retirement frontier; gated by its own PING/PONG extension. |
| `ACCESS_EVENT_V1` | `0x30` | oper | `secured_signed` | event-spine-v2 | Secured multi-hop IRCX channel ACCESS fact with immutable origin signature. |

Unknown tags are skipped only after enforcing their declared frame-size bound.
That forward-compatibility behavior is not evidence that an older node can relay
or apply a new family. `WHOIS_PROFILE` and `GUEST_FRONTIER` additionally use their
own PING/PONG extension negotiation; consult the live emitter before sending them.

## Ordinary guest presence

Account-less clients publish one mesh-presence v2 record (`onyx-mesh-presence-v2`, magic `OPRS`). The live path does not encode, admit, or forward mesh-presence v1. The v1 codec and the v1 issuer remain in the tree and are not the route.

The origin signs the record. Each hop wraps its own envelope and leaves the origin bytes unchanged. The next hop is the secured link that should receive the record. Hop 0 means local. A remote admit with hop 0 is refused. On a duplicate, the first path stays. On an update, the next hop is replaced. A quarantined contradiction is hidden. An expired record fails the clock check and is not returned. A full table fails closed. It does not evict a live subject.

WHOIS for a live ordinary guest renders 311, 312, and 318 from that record, including the signed home server. PRIVMSG to that guest is one guest-direct frame (`onyx-guest-direct-v1`, magic `OGDM`): the sender's node writes it only to the recipient's next hop, an intermediate node forwards the original bytes only onward, and the home node delivers only when the recipient origin is that node and the local guest id matches. Guest counters restart on each node, so the id alone is not a mesh-wide identity. The sender is echoed once. NOTICE does not use this path. A nick with no signed guest subject stays on the existing unknown-nick path. A known guest subject does not fall through to the legacy MESSAGE nick relay.

Guest identity and session credentials are separate. Current `.clients` v8 state
carries the exact guest incarnation, presence revision and stable nick-claim
revision/HLC; the mandatory local-guest issuer and presentation families carry
their coupled authority. The world checkpoint remains a separate v2 schema.
Do not infer missing guest carry from the unchanged World schema number. Source:
`helix/session_snapshot.zig`, `helix/local_guest_issuer_capsule.zig`, and
`helix/handoff_relations.zig`.

Full Debug/ReleaseSafe release evidence is now recorded in the
[2026-11-03 audit](../audit/release-and-test-speed-2026-11-03.md). That full-suite
result is separate from the bounded live two-node acceptance recorded there.

> Origin authentication, the per-link vs multi-hop signing modes, and the
> handshake-negotiated signing capability are documented in
> [mesh-security.md](mesh-security.md).

The enum and tag mapping are in `FrameType` ([src/proto/s2s_frame.zig](../../src/proto/s2s_frame.zig)), and the streaming decoder buffers partial input until a complete frame is available ([src/proto/s2s_frame.zig](../../src/proto/s2s_frame.zig)). Unknown frame tags are skipped after the bounded payload length is validated ([src/proto/s2s_frame.zig](../../src/proto/s2s_frame.zig)).

## Peer handshake and link adapters

The pure peer driver has an internal Undertow handshake payload with magic `S2PH`, version `2`, node id, epoch, name, description, and a single-byte capability bitfield. v1 peers omit the byte and decode as `caps == 0`; unknown future capability bits are ignored. If the expected remote id is zero, the receiver adopts the id from the first handshake; otherwise it rejects an unexpected id.

Once established, the peer records the remote server in the registry, maps the remote server name to the remote node in the route table, establishes the link session, clears pending link-session outbound data, and emits a CRDT burst ([src/substrate/undertow/s2s_peer.zig](../../src/substrate/undertow/s2s_peer.zig)).

`S2sLink` is reactor-independent: it owns the per-peer CRDT state, a stable monotonic clock cell, and an outbound buffer used by the peer driver's `ByteSink` ([src/daemon/s2s_link.zig](../../src/daemon/s2s_link.zig)). The daemon calls `start` after outbound connect completion for plaintext links ([src/daemon/server.zig](../../src/daemon/server.zig)).

`SecuredLink` wraps the same inner path with Mooring. During the handshake only the TOFU prekey preamble and the two AKE messages are length-prefixed with a four-byte little-endian length ([src/daemon/secured_s2s_link.zig](../../src/daemon/secured_s2s_link.zig)). Mooring is the PQ-hybrid Noise-IK-shaped AKE: Ed25519 is the static node identity, X-Wing transport prekeys provide hybrid KEM entropy, and the initiator node id plus MeshPass bytes are only present inside encrypted M1 ([src/crypto/mooring_handshake.zig](../../src/crypto/mooring_handshake.zig)). After establishment the post-handshake CRDT byte stream is **encrypted**: `feedInner`/`drainInner` wrap each inner chunk in a ChaCha20-Poly1305 AEAD record keyed on the Mooring `Established` send/recv keys with a per-record counter nonce bound as AAD, so a tampered or reordered record drops the link rather than reaching `S2sLink` ([src/daemon/secured_s2s_link.zig](../../src/daemon/secured_s2s_link.zig), [src/crypto/mooring_handshake.zig](../../src/crypto/mooring_handshake.zig)). Derived session keys and temporary key material are secure-zeroed on deinit and after use ([src/crypto/mooring_handshake.zig](../../src/crypto/mooring_handshake.zig)). The responder immediately queues its signed prekey; the initiator verifies the prekey and optional trust pin before opening the Mooring session ([src/daemon/secured_s2s_link.zig](../../src/daemon/secured_s2s_link.zig)). The end-to-end origin-authentication and capability-negotiation model layered on top of this is documented separately in [mesh-security.md](mesh-security.md).

MeshPass admission is inside that encrypted M1. With signer roots configured, the responder decodes a signed MeshPass token, binds it to the authenticated peer node key, requires the relay role plus control/sync/mooring frame families, and carries admitted frame-family rights into the established session; without signer roots it keeps the shared-secret gate and compares the M1 MeshPass bytes in constant time ([src/crypto/mooring_handshake.zig](../../src/crypto/mooring_handshake.zig)). MeshPass token validation enforces realm, revocation epoch, expiry, and not-before via `issued_ms` ([src/proto/meshpass.zig](../../src/proto/meshpass.zig)).

The secured adapter exposes `peerNodeKey`, the authenticated raw Ed25519 signing public key recovered from the Mooring session, and the daemon uses that key to verify cross-mesh oper grants ([src/daemon/secured_s2s_link.zig](../../src/daemon/secured_s2s_link.zig), [src/daemon/server.zig](../../src/daemon/server.zig)).

## Channel CRDT model

The implemented channel CRDT covers one channel. Membership is an add-wins observed-remove set keyed by stable `MemberId`, and modes are last-writer-wins registers ordered by `(HLC, replica_id)` ([src/substrate/undertow/channel_crdt.zig](../../src/substrate/undertow/channel_crdt.zig)). HLC is a wall-clock timestamp plus logical counter, encoded to the LWW key in the same order as its compare function, so cross-host LWW uses wall-clock HLC ordering rather than local monotonic age checks ([src/substrate/undertow/clock.zig](../../src/substrate/undertow/clock.zig)). Member status stores voice/op/owner/founder bits ([src/substrate/undertow/channel_crdt.zig](../../src/substrate/undertow/channel_crdt.zig)).

| Entity | Current representation | Merge behavior |
| --- | --- | --- |
| Membership | Per-member add dots plus causal context (`MemberEntry.adds`, `MemberEntry.context`). | Local join increments the version vector, observes the new dot, and appends a `MemberAdd`; local part clears observed adds; merge removes adds covered by remote context and keeps concurrent live adds. |
| Member status | `MemberStatus` bitset stored on each live add. | `memberStatus` unions the status bits across live adds, so concurrent adds accumulate prefix bits. |
| Boolean channel modes | Concord LWW registers for invite-only, moderated, no-external, topic-protected, secret. | Register merge decides by timestamp/replica ordering. |
| Parameter modes | LWW registers for key and limit. | Same LWW path as booleans, with bounded key length and `present` flags. |

The join mutator creates a new dot from the version vector, advances HLC, observes the dot in both local and delta contexts, removes covered adds while keeping the new dot, and returns a delta CRDT ([src/substrate/undertow/channel_crdt.zig](../../src/substrate/undertow/channel_crdt.zig)). Merge combines HLC, version vectors, member adds/contexts, and mode registers ([src/substrate/undertow/channel_crdt.zig](../../src/substrate/undertow/channel_crdt.zig)). The merge law is intentional: tests cover commutativity, idempotence, multi-order convergence, add-wins rejoin over observed part, and netsplit/heal convergence ([src/substrate/undertow/channel_crdt.zig](../../src/substrate/undertow/channel_crdt.zig)).

## Burst, delta, and anti-entropy

`burst.zig` serializes a channel CRDT with magic `SBST`, version `1`, a header record, member delta records, and mode records ([src/substrate/undertow/burst.zig](../../src/substrate/undertow/burst.zig)). The header carries HLC and the version vector ([src/substrate/undertow/burst.zig](../../src/substrate/undertow/burst.zig)); member records use `delta_codec` membership views with context dots, live add dots, and derived remove dots ([src/substrate/undertow/burst.zig](../../src/substrate/undertow/burst.zig)). Applying a burst builds an incoming CRDT and merges it into the target ([src/substrate/undertow/burst.zig](../../src/substrate/undertow/burst.zig)).

`LinkSession` is the pure orchestration layer for initial burst, live deltas, gossip payloads, and Merkle-guided repair ([src/substrate/undertow/link_session.zig](../../src/substrate/undertow/link_session.zig)). On establishment it observes the remote node in gossip and enqueues a burst ([src/substrate/undertow/link_session.zig](../../src/substrate/undertow/link_session.zig)). On tick it emits gossip after `gossip_interval_ms` and repair summaries after `repair_interval_ms` ([src/substrate/undertow/link_session.zig](../../src/substrate/undertow/link_session.zig)).

The repair module summarizes each member and present mode into Merkle entries, diffs local and remote summaries, builds key requests, builds record responses, and applies responses through a temporary CRDT merge ([src/substrate/undertow/anti_entropy_repair.zig](../../src/substrate/undertow/anti_entropy_repair.zig)). Member repair prefers the canonical dense `DeltaView` payload and falls back to the compact version-vector frontier form only when dense causal-context expansion overflows; the compact encoder sorts context and adds so equal logical state hashes to identical bytes and avoids repair livelock ([src/substrate/undertow/anti_entropy_repair.zig](../../src/substrate/undertow/anti_entropy_repair.zig), [src/substrate/undertow/member_compact.zig](../../src/substrate/undertow/member_compact.zig)). `S2sPeer.repairRoot` exposes the current Merkle root for its state ([src/substrate/undertow/s2s_peer.zig](../../src/substrate/undertow/s2s_peer.zig)).

Current-code boundary: `s2s_peer.zig` directly dispatches S2S `BURST`, `DELTA`, `GOSSIP`, and capability-gated repair frames. `LinkSession` still has its own pure repair-summary/request/response message-kind path over `peer_link` payloads, but the daemon's live S2S path uses the `S2sPeer` frame path through `S2sLink`/`SecuredLink` ([src/substrate/undertow/s2s_peer.zig](../../src/substrate/undertow/s2s_peer.zig), [src/substrate/undertow/link_session.zig](../../src/substrate/undertow/link_session.zig)).

## Gossip and membership view

`membership_view.zig` implements a bounded Undertow partial view: a small active view and larger passive view, with caller-supplied time and deterministic randomness ([src/substrate/undertow/membership_view.zig](../../src/substrate/undertow/membership_view.zig)). Joining an overflowed active view demotes one active peer to passive ([src/substrate/undertow/membership_view.zig](../../src/substrate/undertow/membership_view.zig)). Active failure removes the failed active member and may promote a passive candidate ([src/substrate/undertow/membership_view.zig](../../src/substrate/undertow/membership_view.zig)).

The transport-agnostic `mesh.zig` coordinator composes the bounded view, eager/lazy Undertow broadcast, and Ripple failure detection into one deterministic state machine; `broadcast` emits eager payloads, lazy notices request missing payloads with graft actions, and `tick` advances probes, retries, and death-driven view cleanup ([src/substrate/undertow/mesh.zig](../../src/substrate/undertow/mesh.zig)). `ripple.zig` is the pure Ripple detector: suspicion needs a configured witness quorum before dead promotion, and dirty membership declarations carry witness snapshots ([src/substrate/undertow/ripple.zig](../../src/substrate/undertow/ripple.zig)).

Current-code boundary: the daemon timer calls `maybeProbeMeshPeerRtt` to probe RTT and, about every 30 seconds, `resyncMeshStateToPeers` to re-burst the full local roster to every established peer. It does not call `S2sPeer.tick`. A secured peer with `session_replica_replay_pending` defers its burst through `session_replica_resync_burst_pending` ([src/daemon/server.zig](../../src/daemon/server.zig)).

`gossip_round.zig` combines the bounded view with Ripple liveness state. Members can be `alive`, `suspect`, `dead`, or `left` ([src/substrate/undertow/gossip_round.zig](../../src/substrate/undertow/gossip_round.zig)). Suspicion records witnesses and transitions to dead only after the configured witness quorum and suspicion timeout ([src/substrate/undertow/gossip_round.zig](../../src/substrate/undertow/gossip_round.zig)). A gossip round applies received payloads, reaps suspects, selects peers by fanout, and builds a payload of member deltas and suspicions ([src/substrate/undertow/gossip_round.zig](../../src/substrate/undertow/gossip_round.zig)).

The peer driver serializes gossip payloads as little-endian origin/incarnation, varint member-delta count, per-delta id/state/incarnation, varint suspicion count, and per-suspicion node/incarnation/witness ([src/substrate/undertow/s2s_peer.zig](../../src/substrate/undertow/s2s_peer.zig)).

## Route table and remote membership projection

The route table has two separate projections: nick-to-node routing and per-channel remote member rosters. Channel routing tracks node fanout counts, while `channel_members` stores remote `nick`, `node`, `status`, and `hlc` for NAMES/WHO-style projection ([src/substrate/undertow/route_table.zig](../../src/substrate/undertow/route_table.zig)).

`MEMBERSHIP` frame payloads are compact binary records: `present`, `status`, `origin_node`, `hlc`, channel/nick length-strings, the member's propagated identity (username/realname/visible host), and an optional trailing `setter` ([src/proto/membership_event.zig](../../src/proto/membership_event.zig)). `setter` is the nick that ran an explicit `/MODE` on the member, so a remote node renders the prefix change as `:<setter> MODE …` rather than the origin server; it is **omitted from the wire when empty**, keeping a join/part event byte-identical to the pre-setter format (the routing fields — `present`/`status`/`hlc` — drive convergence; identity and setter are display-only). The peer driver decodes inbound membership and applies it to the route table; malformed payloads are dropped without faulting the link ([src/substrate/undertow/s2s_peer.zig](../../src/substrate/undertow/s2s_peer.zig)). Route-table membership updates are LWW by HLC; stale updates are ignored, newer present updates replace status/node, and newer parts remove the entry and prune empty channels ([src/substrate/undertow/route_table.zig](../../src/substrate/undertow/route_table.zig)).

Nickname collision handling is deterministic and non-destructive. `resolveIncomingNick` keeps the wire nick when uncontested, renames a losing remote member to its stable mesh UID when it collides with a local or higher-priority remote holder, and lets same-account duplicates converge by LWW instead of minting a UID; the route table and peer driver explicitly never signal a kill for a collision loser ([src/substrate/undertow/route_table.zig](../../src/substrate/undertow/route_table.zig), [src/substrate/undertow/s2s_peer.zig](../../src/substrate/undertow/s2s_peer.zig)). The fallback UID is canonical, fixed-width base-36 over node/counter state, and the collision path derives it from the owning node's short id plus contested nick ([src/substrate/undertow/nick_collision.zig](../../src/substrate/undertow/nick_collision.zig), [src/substrate/undertow/uid_alloc.zig](../../src/substrate/undertow/uid_alloc.zig)).

The daemon announces local membership changes to all established peer links. JOIN sends the member's current mode bits after local join handling, and PART sends a `present=false` event after removing the local membership ([src/daemon/server.zig](../../src/daemon/server.zig)). The shared announcer sends over both secured and plaintext established links and flushes each link's outbound buffer ([src/daemon/server.zig](../../src/daemon/server.zig)).

On link-up, the daemon sends a one-time full local channel-member roster to that peer so the peer does not have to wait for future joins to build a roster ([src/daemon/server.zig](../../src/daemon/server.zig)). The burst walks all local channels and local client members, sends their status bits, then flushes the peer link ([src/daemon/server.zig](../../src/daemon/server.zig)).

## Cross-node message relay

The production active authoring lane uses signed `MESSAGE_V2`, daemon-global
RVG2 replay admission, accepted-event and per-hop custody, and per-attachment
rendered output. It preserves canonical origin bytes, stable msgid/time and
allocation-failure atomic publication. Scope and recipient policy remain checks
at the accepted boundary, not an assumption derived from neighbor membership.
The [MESSAGE_V2 contract](../design/message-v2-exact-once.md) defines activation,
ACK/retry ownership, slowmode publication and cold-restart limitations.

### Legacy MESSAGE compatibility path

`message_relay.zig` defines the cross-node user-message schema for relayed PRIVMSG, NOTICE, and TAGMSG. It is a canonical CoilPack map with stable field order, carrying verb, target, source nick/prefix, account, tags, text, origin node, and HLC ([src/substrate/undertow/message_relay.zig](../../src/substrate/undertow/message_relay.zig)). Each peer has a bounded `SeenSet` keyed by `(origin_node, hlc)` to suppress duplicates and echoes ([src/substrate/undertow/message_relay.zig](../../src/substrate/undertow/message_relay.zig)).

Inbound `MESSAGE` frames are decoded, loop-checked, and queued for daemon delivery; malformed payloads are ignored ([src/substrate/undertow/s2s_peer.zig](../../src/substrate/undertow/s2s_peer.zig)). Outbound messages are observed in the same seen set before being encoded and emitted as `MESSAGE` frames ([src/substrate/undertow/s2s_peer.zig](../../src/substrate/undertow/s2s_peer.zig)).

The daemon drains queued inbound messages from both link types after driving the link and calls `deliverRelay` ([src/daemon/server.zig](../../src/daemon/server.zig)). `deliverRelay` delivers to local channel members or a local nick, then re-forwards for multi-hop using a route-table-derived scope; unknown nick routes widen to all peers ([src/daemon/server.zig](../../src/daemon/server.zig)).

Outbound channel messages are relayed only to peers that have announced members of the channel, and outbound nick messages are first sent to the peer that claims the nick route; if no nick route is known, the daemon floods all established peers ([src/daemon/server.zig](../../src/daemon/server.zig)). The peer selection function supports `.all`, `.channel`, and `.nick` scopes and checks channel roster or nick route availability on each link ([src/daemon/server.zig](../../src/daemon/server.zig)).

## Netsplit and netjoin batches

`netsplit_batch.zig` is a pure formatter for IRCv3 netsplit/netjoin `BATCH` messages. It allocates nothing and leaves recipient selection to the daemon ([src/daemon/netsplit_batch.zig](../../src/daemon/netsplit_batch.zig)). `writeNetsplit` wraps ghost QUIT lines in a `netsplit` batch; `writeNetjoin` wraps ghost JOIN lines in a `netjoin` batch ([src/daemon/netsplit_batch.zig](../../src/daemon/netsplit_batch.zig)).

The current daemon calls the netsplit path on S2S peer drop, before deinitializing the link, so it can still read the peer's remote member roster ([src/daemon/server.zig](../../src/daemon/server.zig)). For each local channel, it reads the dropped peer's remote members, renders ghost prefixes as `nick!*@remote_server`, emits a netsplit batch, and sends it to local channel members ([src/daemon/server.zig](../../src/daemon/server.zig)).

Current `tryEmitNetjoinRun` rendering calls `writeNetjoin` for a
multi-member join run and uses plain JOIN for the single-run path. Publication
prepares both batch-capable and plain forms before committing the remote
presentation. Roster/state admission and local client rendering remain separate
authorities; codec existence alone is not the old implementation boundary.

## Link preservation across compatible Helix

An established secured link must be carried exactly or UPGRADE is refused. It
must not silently degrade into drop-and-redial. Current `.s2s_link` v6 captures
Mooring keys/nonces/counters, partial encrypted input, unsent outer records,
inner framing/custody and the remote-member roster. The successor validates the
complete mandatory state, adopts the same fd, and resumes record counters without
running another AKE. Source: `secured_s2s_link.zig`, `helix/s2s_snapshot.zig`,
`sealSecuredLink`, `adoptSecuredLink`, and the whole-handoff relation validator.

The roster, oper grants/revocation tombstones and their revision authority are
primed before socket I/O and RESYNC activation. An unchanged peer roster/topic
must not re-announce logical JOINs, operator prefixes or unchanged TOPIC lines.
The periodic state burst repairs convergent state; it does not replace exact
transport and replay custody at the handoff boundary.

A generic codec can decode older schemas for explicit migration tests without
making them valid current live arenas. Mandatory manifest/capability checks
reject incompatible predecessors/successors before publication; pre-v4 empty
roster fallback is not current Helix behavior. Refusal before exec leaves the
predecessor running, while fatal failure after Linux exec needs cold recovery.
See [upgrade architecture](04-upgrade-wasm.md) for other continuity blockers and
[MESSAGE_V2](../design/message-v2-exact-once.md) for RAM-only custody limits.

## Multi-hop partition detection and quorum

`partition_detector.zig` is pure graph logic. Callers provide known nodes, liveness, and undirected edges; dead nodes are excluded from counts, reachability, components, and quorum, while suspect nodes remain in the graph ([src/substrate/undertow/partition_detector.zig](../../src/substrate/undertow/partition_detector.zig)). The detector reports reachability, partition status, connected-component count, and strict-majority quorum from the local node's component ([src/substrate/undertow/partition_detector.zig](../../src/substrate/undertow/partition_detector.zig)).

For daemon snapshots, `TopoNode` stores `node_id` plus optional `uplink`, and `analyze` treats each uplink as an undirected edge while always including the local node ([src/substrate/undertow/partition_detector.zig](../../src/substrate/undertow/partition_detector.zig)). `SeenSet` remembers observed node ids with last-seen time so a node that vanishes with a dropped link remains expected until TTL expiry ([src/substrate/undertow/partition_detector.zig](../../src/substrate/undertow/partition_detector.zig)).

The daemon assembles topology from every established direct peer plus each peer's gossiped registry view. For plaintext links it uses `remoteNodeId`; for secured links it uses the authenticated peer short id; both then append `collectTopology` from the link ([src/daemon/server.zig](../../src/daemon/server.zig)).

`updatePartitionTransitions` runs on link establishment and drop. It observes local and visible topology nodes into the daemon's persistent `SeenSet`, prunes nodes older than five minutes, builds edges from the current topology, and logs a `.split` or `.heal` mesh event only when the partitioned boolean crosses state ([src/daemon/server.zig](../../src/daemon/server.zig)).

`MESH` renders reachability and partition counts from `partition_detector.analyze`, then reports quorum as `reachable_nodes > partitioned_nodes`, equivalent to local reachability being more than half of known nodes ([src/daemon/server.zig](../../src/daemon/server.zig)).

## Secure cross-mesh oper grants

Cross-mesh oper grants never carry the operator password. `oper_cred_share.zig` defines a signed, expiring authorization grant with account, privilege bitfield, class, title, issuer node, incarnation, issue time, and expiry ([src/proto/oper_cred_share.zig](../../src/proto/oper_cred_share.zig)). The signed region is fixed-order and length-prefixed; Ed25519 signs exactly those canonical bytes, and verification checks structure, signature, and expiry ([src/proto/oper_cred_share.zig](../../src/proto/oper_cred_share.zig)). The fixed-capacity registry merges grants by account and rejects older-or-equal incarnations/replays ([src/proto/oper_cred_share.zig](../../src/proto/oper_cred_share.zig)).

The daemon stores recognized grants in `oper_grants` ([src/daemon/server.zig](../../src/daemon/server.zig)). Locally authorized SASL operators mint a 24-hour grant signed by this node's Ed25519 key and broadcast it to established secured peers only ([src/daemon/server.zig](../../src/daemon/server.zig)). The plaintext S2S path is deliberately skipped for grant broadcast because it lacks an authenticated peer identity ([src/daemon/server.zig](../../src/daemon/server.zig)).

Inbound `OPER_GRANT` frames are opaque to the link layer; secured `driveS2sSecured` drains them and verifies each against `peerNodeKey` before applying it to local authority ([src/substrate/undertow/s2s_peer.zig](../../src/substrate/undertow/s2s_peer.zig), [src/daemon/server.zig](../../src/daemon/server.zig)). Accepted grants are logged and immediately applied to already-connected sessions for the same account ([src/daemon/server.zig](../../src/daemon/server.zig)). If an account has no local oper binding, `elevateOperFromAccount` can still derive operator privileges from a live cross-mesh grant ([src/daemon/server.zig](../../src/daemon/server.zig)).

Operators can inspect recognized grants with `MESH GRANTS`, which lists account, class, title, issuer, and remaining TTL ([src/daemon/server.zig](../../src/daemon/server.zig)).

## Cross-server session reclaim

`SESSION RESUME` first parses the credential family; it must not guess semantics
from token length. Bare local tokens, composite local exact selectors, legacy
SRM1 and signed SRM2 exact-restore claims have different issuer, account,
destination and lifecycle checks. A live exact portable claim is currently
issuer-bound: another mesh node redirects instead of manufacturing a new physical
attachment. Legacy eligible replicas can support reusable logical attachment.

A signature or HMAC authenticates only its credential statement. Live restore
also checks current retained/session/replica authority and permanent group denials;
codec-only consume/replay helpers do not make all logical credentials one-shot.
Durable account-login `sst_` tokens are a separate Services credential and cannot
be used as a SESSION RESUME selector. See [credential domains](../reference/credential-domains.md)
and [the living session contract](../design/session-resume-anywhere-blueprint.md)
for exact formats, time units, defaults, retry and redirect handling.

## Operational commands and observability

| Command/path | Current behavior |
| --- | --- |
| `CONNECT <host> <port>` | Operator command gated by `mesh_admin`; creates a secured initiator when node identity and crypto I/O are configured, otherwise creates a plaintext `S2sLink`; submit-connect owns the socket lifecycle ([src/daemon/server.zig](../../src/daemon/server.zig)). |
| `SQUIT <server>` | Operator command gated by `mesh_admin`; finds an active secured or plaintext peer by authenticated/learned remote name and closes it through the normal owner path ([src/daemon/server.zig](../../src/daemon/server.zig)). The live selector is `findSquitVictim`; retained retiring legs cannot shadow an active survivor. |
| `MESH` / `NETSTAT` | Renders peer state, link health, reachability counts, and quorum summary from live links and the partition detector ([src/daemon/server.zig](../../src/daemon/server.zig)). |
| `MESH LOG` | Renders recent mesh events from the bounded mesh event ring ([src/daemon/server.zig](../../src/daemon/server.zig)). |
| `MESH GRANTS` | Lists live cross-mesh oper grants ([src/daemon/server.zig](../../src/daemon/server.zig)). |
| `ROUTE` | Renders this node plus one-hop established peers; the code comments note that multi-hop routes are not yet lit in this report ([src/daemon/server.zig](../../src/daemon/server.zig)). |
| `NETHEALTH` | Renders this node and established peers with link RTT/idle health ([src/daemon/server.zig](../../src/daemon/server.zig)). |

## Current implementation boundaries

The source currently implements a frame-based peer driver and daemon relay path, not a full future banded protocol. The source today has Mooring-secured link establishment, CRDT burst/delta/gossip frames, route-table-scoped message relay, membership frame projection, nickname collision rename-to-UID handling, capability-gated repair frames, oper-grant sharing over secured links, and mesh-session reclaim. Where the code only provides pure helpers, this document calls that out: netjoin rendering is wired to accepted remote membership runs; `LinkSession` contains a pure repair message path, while the live daemon peer path dispatches repair through `s2s_frame` messages in `S2sPeer`.
