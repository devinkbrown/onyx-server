# Physical media owner namespace — proposed, not implemented

2026-10-27. Design proposal; implementation and acceptance remain open. All names, capability strings, versions and domains below are proposals, not reserved or advertised protocol. No client repository was inspected. Local cohort04 collision rejection remains useful but cannot establish mesh uniqueness.

Source coordinates below describe native candidate `83733d1444ded3e8be826d22eac6a9f589d4f3df37b9c61615b9f6f6b376ad3f`, before promotion of the separate media cohort. References to cohort04 describe that isolated proposal.

## Observed boundary

Current `src/daemon/media_cmd.zig:350–393` accepts an enrolled account's signed handshake and binds its client-selected attachment ID to the current connection. `server.zig:40281–40322` validates the envelope and signs/verifies channel plus envelope; the transcript contains no server-issued physical owner. Two same-token physical clients may replay one envelope on different nodes.

Event Spine correctly treats those as different authored events: `event_spine_replay_guard.zig:88` uses sovereign public key/HLC/event ID; `proto/oper_event.zig:391` hashes the complete signed origin transcript. `server.zig:61311–61331` admits, delivers and forwards remote events without media-owner arbitration. EVENT preserves the origin server prefix (`60664–60708`), but GROUPKEY names target nick/attachment without target origin (`media_cmd.zig:399–435`). Prefix preservation alone is not an established receiver namespace. The documented receiver clears its keys on its own DETACH (`docs/architecture/03-media.md:183–200`).

## Choice

Choose **owner-qualified signed messages**, not a globally unique claim on the old client-selected attachment ID. Independent physical connections remain distinct even if their users intentionally choose identical IDs. This works during partitions without electing a winner or disconnecting a sibling.

A serialized claim alternative needs a single authority or quorum for each old tuple, durable reservations/tombstones, partition refusal, transfer and recovery. An asynchronously replicated occupancy table cannot prevent simultaneous acceptance. That machinery adds availability costs without a product requirement that two physical connections share one crypto identity.

## Owner and handshake

Define an opaque owner as `(full sovereign issuer public key, 256-bit random physical-incarnation nonce)`. Never use the short node ID, fd, slot alone, nick, account, token, or client-supplied attachment ID as owner. Mint via the existing cryptographic RNG under the exact connection's authority; reject RNG failure and local collision. The nonce is public, not a bearer credential, and is neither derived from nor equal to a session credential. Randomness gives cryptographic uniqueness, not a mathematical global counter guarantee.

An authenticated, negotiated connection requests an owner challenge for an exact canonical channel. Stage owned challenge data and capacity before publishing its reply; bind it to full local ClientId/generation, channel and account-enrollment context. Repeated request returns the same outstanding challenge or explicitly replaces an unaccepted challenge. Concurrent requests cannot alias physical owners. No network wait is needed under World.

Proposed signed-v3 envelope includes owner, client attachment ID, existing identity/ephemeral keys and nonce, and an explicit handshake generation. The client signature covers a new domain, version, canonical channel, owner and every envelope byte. Server verifies the challenge belongs to this exact live connection, channel and current authenticated account before superseding any accepted scope. Old v2 bytes cannot satisfy v3 by server-side wrapping or guessed fields. A duplicate exact accepted handshake is idempotent; a changed handshake requires a new generation and ordered retirement of the old generation. Overflow fails closed.

The authoritative accepted scope is `(owner, handshake generation, channel, participant, client attachment ID)`. Channel/nick remain display and policy fields; owner/generation identify crypto custody. Existing local collision rejection can remain for v2 compatibility, but v3 permits equal attachment IDs on distinct owners.

## Messages and receivers

Proposed HANDSHAKE3, GROUPKEY3 and DETACH3 carry the complete source owner/generation. GROUPKEY3 also carries the complete target owner/generation, target nick and attachment ID. Its encrypted key-wrap associated data must bind both owners/generations and channel/epoch; otherwise textual disambiguation alone does not separate crypto sessions. Client group state, pairwise keys, receive windows and detach matching use the qualified identity. A DETACH for A must never clear B merely because nick/attachment match.

An authoritative node may author lifecycle/control for an owner only when the owner issuer equals that node's full signing key and the exact local connection/scope proves custody. Remote admission checks this binding before replay/history mutation. Relays retain byte-identical signed origins and existing exact-once Event Spine identity. They do not reassign owners to the immediate hop. Target-owner observations are advisory routing/presence information, not permission to author as that target.

Require explicit per-owner generation ordering and terminal state at receivers: DETACH can arrive before delayed HANDSHAKE and must prevent resurrection. Retain terminal generations through the applicable replay horizon; define exhaustion, bounded storage/backpressure and late-event behavior before implementation. Reuse Event Spine accepted-event retention/anti-entropy where available; do not assume exact-once alone guarantees all offline peers receive a missed edge. A reconnect synchronization barrier must supply authoritative current owner scopes plus terminal coverage before reopening media. Never accept an unversioned nickname-wide LEAVE as permission to erase all remote owners; qualified departure removes only its named scope, and clients derive aggregate visible presence from surviving scopes.

## Compatibility and lifecycle

Propose explicit client and secured-mesh capability negotiation. A v3 media session requires qualified end-to-end consumers and a forwarding/admission path with the requisite checks. Never down-convert qualified events to ambiguous v2 events. Legacy clients may retain explicitly isolated local v2 media; if isolation cannot be enforced, refuse only media setup with a typed incompatibility response while keeping IRC and every physical attachment connected. Capability-old peers must not silently create a mixed qualified/unqualified call. Defining the activation policy and actual client implementation is required work, not covered by this design.

Reusable session tokens remain unchanged. A fifth RESUME creates its own media owner. Connection migration to a different issuer establishes a new media owner after retiring the old one; it does not rewrite signed origin bytes or transfer an owner by nick. IRC attachment preservation remains mandatory.

Windows current-state adoption must carry mandatory owner/challenge/generation, negotiated mode and accepted scope rows independently of browser routing, plus retained retirement obligations. Bump the current graph/process capabilities from the proposed cohort04 schema again; stage/remap exact ClientIds atomically, validate issuer and uniqueness, and reject missing fields/older hot images. Never infer owner from an old attachment ID.

Linux currently treats media crypto state as ephemeral (`server.zig:3451`); this design does not claim otherwise. For v3, choose an explicit pre-exec media reset: accept qualified retirements and drain their obligations before discarding scopes, preserve all IRC/TLS connections and session tokens, then require fresh owner challenges/handshakes after adoption. Failed retirement admission aborts the upgrade preparation; no post-reactor-join SEND. Clients must understand this reset. If seamless media continuity becomes required, implement mandatory Linux scope/counter custody instead; do not silently infer it from session preservation.

## Implementation and falsification gates

1. Specify canonical encodings, transcript vectors, owner lifecycle, receiver ordering and capability activation first. Add a pure bounded protocol/owner leaf; integrator alone wires `server.zig`. Preserve v2 bytes and advertise nothing until end-to-end support exists.
2. Two secured nodes, four real TLS attachments sharing one reusable token. Submit identical valid v2 envelope bytes concurrently: qualified mode rejects them. Obtain distinct real challenges, sign equivalent v3 payloads with equal client attachment IDs, accept both, and verify exact forwarded signed bytes and qualified GROUPKEY exchange. Retire A; B remains connected and can exchange/decrypt fresh media. No receiver exists in this repo, so use an explicit reference receiver plus later real-client acceptance, clearly distinguished.
3. Partition before both admissions, merge through A–B–C and a diamond, inject duplicate/out-of-order HANDSHAKE/DETACH and replay retired generations. Prove convergence, no resurrection, no unrelated owner teardown, and bounded pending work; exercise reconnect synchronization and missing-retention refusal.
4. Sequential A/B Helix: preserve every physical TLS connection and local token, validate Windows strict carried scopes or Linux explicit media reset, then resume fifth remotely. Sweep allocation/send-pressure failures across challenge, admission, retirement, snapshot and adopt in Debug/Safe. Old-schema hot adoption must refuse transactionally. Client upgrades and native multi-node execution remain prerequisites for claiming mesh crypto isolation.
