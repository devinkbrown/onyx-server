# Mesh and S2S

*Configure server-to-server linking over the [Undertow](../reference/glossary.md) mesh, including secured and plaintext links and operator inspection views.*

Onyx Server's server-to-server (S2S) linking runs on the [Undertow](../reference/glossary.md) mesh runtime. Configure node identity in `[node]`, mesh settings in `[mesh]`, and the inbound S2S listener in `[listen].s2s`.

```toml
[node]
id = 1
secret_key = "env:ONYX_NODE_SECKEY"

[listen]
irc = 6680
s2s = 7700

[mesh]
realm = "example"
mesh_pass = "env:ONYX_MESH_PASS"
presence_store_path = "/var/lib/onyx-server/guest-presence.wal"
```

## Ordinary guests

An account-less client publishes one mesh-presence v2 record. WHOIS and PRIVMSG for that nick follow the signed record, including across a node that is not directly linked to the guest's home. NOTICE does not. There is no second presence version and no new handshake bit. Authenticated clients and reusable sessions stay on their existing MESSAGE_V2 and session paths. The Helix world checkpoint stays version 2 and does not carry the guest id. See [mesh architecture](../architecture/mesh-s2s.md#ordinary-guest-presence). Current release verification and the narrower live acceptance are recorded in
[the release audit](../audit/release-and-test-speed-2026-11-03.md); neither is
a blanket certification of every topology or platform.

Identity-bearing production meshes must configure a private durable
`[mesh].presence_store_path`; startup otherwise fails with
`MissingMeshPresenceStorePath`. Preserve that store with the node identity.
Guest-presence authority, account persistence and exact-session credentials
are separate ownership domains. See [persistence](persistence.md) and
[credential domains](../reference/credential-domains.md).

## MESSAGE_V2 bridge and activation

MESSAGE_V2 uses a mesh-wide compatibility barrier so one logical event is never
sent once as legacy and later replayed as V2. The safe default is
`relay_v2_authoring = "compat"`: the node can receive, acknowledge, retain, and
forward V2, but its own events remain legacy-only.

The sequence below describes first activation of an eligible compat fleet.
An already-active fleet must preserve its exact mode, epoch and roster digest;
do not reset it to `compat` or repeat an old activation recipe. Use the
[current production baseline](../ops/onyx-server-paths.md) and live status,
and check the full current Helix token before selecting a reload path.

Use these distinct passes for first activation. Do not combine staging and activation
in one reload:

1. Deploy the bridge-capable binary to every node while authoring remains
   `compat` and no activation plan is present. If the running image predates the
   exact `mesh-clock-v3` Helix token, this first bridge deployment requires a
   planned cold restart; see [Helix upgrade](upgrade.md).
2. Run the newly staged binary's `--check-config` against each node's exact
   configuration. A plan requires an explicit `[node].secret_key` or matching
   `[node].public_key`, secured S2S,
   signed frames, at least one direct trust root, and a full roster containing
   the local key and every direct root.
3. Configure one never-before-used, strictly increasing
   `relay_v2_activation_epoch` and the complete full-mesh `relay_v2_roster` on
   every node, still in `compat`. Run the new binary's `--check-config` against
   this final staged configuration, then Helix-reload every process once so the
   plan is present in live MHLC state.
4. Verify every roster member reports `bridge_implemented=true`, `authoring=compat`,
   the same non-zero epoch and digest, and the expected roster count. Direct-neighbor
   capability probes are insufficient for a line such as A-B-C because A cannot
   infer whether hidden node C is ready.
5. Change only `relay_v2_authoring` to `"active"`, rerun `--check-config`, and
   Helix-reload nodes sequentially. After each node, stop and require its
   `authoring_eligible=true` with the unchanged epoch/count/digest, healthy
   links, and an exact-once channel plus shared portable-session event observed
   on every live attachment. Every still-compat bridge accepts V2 during this
   pass. Do not advance when any per-node gate fails; follow the detailed
   [runbook activation procedure](../RUNBOOK.md#message_v2-activation-runbook).
6. After the last per-node gate, verify every roster member reports
   `authoring=active` and `authoring_eligible=true` with the unchanged epoch,
   count, and digest.

```toml
[mesh]
require_secured = true
require_signed_frames = true
trust_roots = ["env:DIRECT_PEER_PUBKEY"]
relay_v2_authoring = "compat" # change to "active" only after the barrier
relay_v2_activation_epoch = 1
relay_v2_roster = ["env:NODE_A_PUBKEY", "env:NODE_B_PUBKEY", "env:NODE_C_PUBKEY"]
```

The roster is separate from `trust_roots`: the former is the complete mesh;
the latter is the local node's direct-neighbor allowlist and, under a staged
plan, its MESSAGE_V2 **custody membership** — the confirmed-node set each durable
RVL2 accepted-event row collects ACKs from before it retires its retained wire
(`src/daemon/config_format.zig`, `src/daemon/relay_v2_event_log.zig`). It
is also distinct from `admission_roots` (MeshPass signer roots). Onyx Server canonicalizes
the full public keys into a roster digest and carries `{mode, epoch, digest}` in
the mandatory MHLC v3 Helix checkpoint. Current handoff rejects an unstaged
activation, a roster mismatch, active-to-compat downgrade, malformed state, or
an older MHLC version before publishing inherited state. Mesh-wide READY proof
is currently an external deployment gate; the daemon does not infer it from
only its adjacent links. Roster order and hex-versus-base64 encoding do not
affect the digest, but the roster alone proves neither topology nor readiness.
`bridge_implemented` is only a local build marker; it is not a negotiated-peer
or mesh-wide readiness proof.

Inspect the file-backed status surface and the oper IRC surface on every node:

```sh
jq '.relay_v2' /path/to/stats/status.json
# From an oper client:
/quote MESH ADMISSION
```

Once any member activates, never remove or decrease the staged epoch, bind the
same epoch to another roster, or switch that member back to `compat`. Roster
change after activation is not implemented; it requires a future protocol and
release. A strictly higher epoch may replace a plan only while the predecessor
is still `compat`. A cold boot validates the configuration but has no durable
record of a previously active generation, so deployment automation must preserve
the exact active tuple and must never start an image that lacks the exact
activation/capability semantics or changes the tuple during rollback.

Activation accepts 1..255 unique direct roots. No direct root may be the local
key, duplicate another key, or collide with another configured node's compact
u64 id, and every direct root must appear in the 2..4096-key full roster.
“V2-eligible” currently covers authored channel `PRIVMSG`, `NOTICE`, `TAGMSG`,
and typed `DATA`/`REQUEST`/`REPLY`; direct-message variants additionally require
an authenticated portable recipient-session token. Other IRC events stay on
their existing paths.

The durable MESSAGE_V2 custody plane (accepted-event log RVL2, per-hop outbox
RVO2, replay guard RVG2, and rendered-record spool ADS1) is a
retransmit-until-ACK obligation that survives a **[Helix](../reference/glossary.md)
(`SIGUSR2`) hot-upgrade only** — its checkpoints ride the in-memory upgrade
capsule, not a disk write-ahead log. A cold restart under either supervisor
or power loss drops any in-flight custody obligation, so hard-restart a node only
from a drained boundary. See the [MESSAGE_V2 exact-once
design](../design/message-v2-exact-once.md) and [Helix upgrade](upgrade.md).

`[listen].s2s` maps to `server.Config.s2s_port`; `0` disables the inbound S2S listener (`src/daemon/config_boot.zig`, `src/daemon/server.zig`). The server binds it alongside the IRC listener when the value is non-zero (`src/daemon/server.zig`, `src/daemon/server.zig`).

## Secured vs. plaintext links

Post-quantum-secured S2S is enabled by default when a node identity and CSPRNG are available. An explicit `[node].secret_key` takes precedence; otherwise `main.zig` loads or creates `onyx-server-node.key` beside the config path, derives the identity using `[mesh].realm`, sets `server.Config.node_identity`, and copies `mesh_pass` if configured (`src/main.zig`, `src/main.zig`, `src/main.zig`, `src/main.zig`, `src/main.zig`, `src/main.zig`). Keyfile or identity failures must be treated as failed mesh readiness;
`mesh.require_secured = true` prevents configured mesh operation from silently
falling back to plaintext. The optional legacy plaintext path is a separate
explicit policy (`src/main.zig`, `src/main.zig`, `src/main.zig`). The live secured check is `node_identity != null and crypto_io != null` (`src/daemon/server.zig`, `src/daemon/server.zig`).

Outbound `CONNECT <host> <port>` is an operator command that requires `mesh_admin` (`src/daemon/server.zig`, `src/daemon/server.zig`). If the local server has secured S2S enabled, `CONNECT` starts a secured handshake; otherwise it starts a plaintext S2S link (`src/daemon/server.zig`, `src/daemon/server.zig`, `src/daemon/server.zig`). `SQUIT <server>` tears down a peer link by handshake-learned server name and also requires `mesh_admin` (`src/daemon/server.zig`, `src/daemon/server.zig`, `src/daemon/server.zig`, `src/daemon/server.zig`).

## Operator views

The operator security module exposes the current mesh inspection commands (`src/daemon/modules/oper_security.zig`, `src/daemon/modules/oper_security.zig`):

| Command | View |
|---|---|
| `MESH` or `NETSTAT` | Direct S2S peer/link health, multi-hop reachability, partition summary, `MESH LOG`, `MESH ADMISSION`, and `MESH GRANTS` (`src/daemon/server.zig`, `src/daemon/server.zig`, `src/daemon/server.zig`, `src/daemon/server.zig`, `src/daemon/server.zig`). |
| `ROUTE` | Current routing view: local node plus established one-hop peers; multi-hop routing is noted as future substrate work (`src/daemon/server.zig`, `src/daemon/server.zig`). |
| `NETHEALTH` | Lists this node and each established peer as alive with RTT and idle time; this is not a witness-quorum death decision. A pair loses the link on ping timeout (`src/daemon/server.zig`, `src/daemon/server.zig`, `src/daemon/server.zig`). |
| `CONNECT` | Opens outbound S2S to a peer (`src/daemon/server.zig`, `src/daemon/server.zig`). |
| `SQUIT` | Tears down an S2S link by server name (`src/daemon/server.zig`, `src/daemon/server.zig`). |

`MESH ADMISSION` reports [MeshPass](../reference/glossary.md) admission mode, secured-S2S status, signed-frame policy, root count, token presence, and minimum revocation epoch without exposing shared secret or token bytes (`src/daemon/server.zig`, `src/daemon/server.zig`, `src/daemon/server.zig`).

`MESH` reflects both plaintext and secured S2S peers in the same report (`src/daemon/server.zig`, `src/daemon/server.zig`).
