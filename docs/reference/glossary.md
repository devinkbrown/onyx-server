# Glossary & brand names

*Audience: all readers. The one authoritative key to the naming — the branded
house (Onyx network / Onyx Server engine / retired IRCXNet) and the engine's
mythos-derived subsystem vocabulary. Each invented
codename says what it actually is and where it lives in the source. Every
codename entry is cited to `src/`; the daemon's own `/INFO` body renders the
same subsystem summary (`src/proto/server_about.zig`). The site, the Onyx
client, the MOTD, and every other doc defer to this file for what each name
means.*

## Brand & product names

Three names, one product family — a branded house. Keep these distinct; do not
use "IRCXNet" as a public product or network identity in new copy.

| Name | What it is | Use it for |
| --- | --- | --- |
| **Onyx** | The consumer-facing **network and product** — the thing people join. It is the browser client (`/home/kain/onyx`, SolidJS) *and* the community/network that client connects to. | "Join **Onyx**." The network name, the web app, the brand a user sees. |
| **Onyx Server** (formerly **Orochi**) | The **engine**: the pure-Zig, clean-room daemon you self-host (`/home/kain/onyx-server`, binary `onyx-server`) and the internal subsystem codenames below (Undertow, Ripple, Mooring, Armor, Helix …). The `onyx/*` protocol/config namespace and `onyx.local`/`onyx-server-node.key`-style tokens are the **live wire/config literals** (cut over from the historical `orochi/*` naming era). | "Run your own **Onyx Server** node." The daemon, the wire/config surface, the codebase. |
| **IRCXNet** | **Retired** as a public identity. Survives **only** as a legacy/wire token where it is a literal value, not a brand — e.g. the `[cloak] suffix` tail (`kain.users.ircxnet`) and existing server/host slugs. | Never in new user-facing copy. Leave in place only as a wire/legacy literal. |
| **IRCX** | The **protocol** (extended IRC: `PROP`/`ACCESS`/`EVENT`/`AUTH`). Unrelated to the retired "IRCXNet" name — do not conflate. | The wire protocol Onyx Server speaks. |
| **Ink & Vermillion** | The **visual identity** — the palette/typography direction of the Onyx surfaces. | The look-and-feel, not the product name. |

The **network name is operator-configured**, not hard-coded to any brand: `[network]
name` sets the string emitted in the `001` welcome (`src/daemon/dispatch.zig`,
`emitWelcome`), the `NETWORK` `005` token (`src/proto/isupport.zig`), and
the `/INFO` `Network:` line (`src/proto/server_about.zig`). The protocol layer's
default network name constant is **`Onyx`** (`src/proto/protocol_inventory.zig`).
In normal operation `Config.initDefaults` also seeds `[network] name` to **`Onyx`**
(`src/daemon/config_format.zig`) and `main.zig` installs it via `setNetworkName`
before serving, so a fresh self-hosted node with no `[network]` section already
advertises **`Onyx`** — the same value as the flagship deployment. An operator
running their own node can still pick their own name via `[network] name`.

## Subsystems

Onyx Server gives its major subsystems evocative codenames rather than generic
acronyms. Several started as Japanese mythos/terms and are now rendered in
English, with the original term kept in parentheses as etymology. First use of a
codename in the guides and architecture docs links here.

| Codename | What it is | Source |
| --- | --- | --- |
| **Undertow** (水脈) | The S2S CRDT mesh **state model**: logical/hybrid-logical clocks, delta-state CRDTs, and Merkle anti-entropy — the building blocks of the replicated mesh world state. (The running daemon repairs membership with the reactor-0 full local-roster re-burst.) | `src/substrate/undertow/root.zig`, `src/substrate/undertow/` |
| **Ripple** (漣) | A pure witness-quorum failure-detection library, not the daemon's live failure detector; `witness_quorum` floors at 2, so a pair cannot form a witnessed quorum. | `src/substrate/undertow/ripple.zig`, `src/substrate/undertow/gossip_round.zig` |
| **Concord** | The delta-state CRDT library (OR-Set, LWW register, dots/causal context) that models mesh membership and other replicated state carried over Undertow. | `src/substrate/undertow/concord.zig` |
| **Mooring** (紡ぎ) | The S2S secure-channel AKE and session ratchet: a Noise-IK-shaped, post-quantum-hybrid handshake (Ed25519 static node identity + X-Wing hybrid KEM) that establishes and re-keys the encrypted server-to-server link. | `src/crypto/mooring_handshake.zig`, `src/crypto/mooring_session.zig` |
| **MeshPass** | Ed25519-signed capability admission tokens that gate which nodes may join the mesh; verified inside the encrypted handshake, fail-closed on tampered/untrusted material. | `src/proto/meshpass_props.zig`, `src/proto/server_about.zig` |
| **Armor** (鎧) | The from-scratch, pure-Zig TLS stack and cryptographic primitive library (TLS 1.3 + hardened TLS 1.2, PQ-hybrid key exchange, AEADs, signing). | `src/proto/server_about.zig`, `src/crypto/` |
| **Ringlane** | The production Linux io_uring ring. It probes multishot accept and multishot wake-poll, sizes the completion queue for a reactor batch, and arms cooperative task-work. It never requests `DEFER_TASKRUN` or `SINGLE_ISSUER`. On Linux each reactor installs a provided-buffer group and arms multishot recv. Completions are copied into the connection buffer, then the pool slice is replenished. Sends are zero-copy until the notification completion, except kTLS. Fixed files stay off the connection path. `src/substrate/io/ring.zig` is not this backend. `src/substrate/reactor.zig` is the separate clock seam. | `src/daemon/ringlane.zig`, `src/daemon/server.zig` |
| **Guest presence** | The one live ordinary-guest identity on the mesh. An account-less client publishes a mesh-presence v2 record (`onyx-mesh-presence-v2`). The origin signature stays intact across hops. Mesh-presence v1 is not encoded, admitted, or forwarded on this path. Current clients-v8 capsule state carries the guest incarnation and presence/nick-claim revisions, with separate mandatory issuer/presentation custody. World remains its own v2 schema. | `src/proto/mesh_presence_v2.zig`, `src/daemon/guest_presence_route.zig`, `src/proto/s2s_frame.zig` |
| **Guest direct** | A signed ordinary-guest PRIVMSG (`onyx-guest-direct-v1`) sent only to the recipient's next hop. The home node delivers it only when the recipient origin is that node and the local guest id matches. NOTICE does not use it. A nick with no signed guest subject stays on the existing unknown-nick path. | `src/proto/guest_direct.zig`, `src/proto/s2s_frame.zig` |
| **Helix** | The in-place `USR2` hot-upgrade: a replacement image is `execve`'d and adopts the running listener, live sessions, and the converged mesh view (each link's remote-member roster + the cross-mesh oper-grant registry) through validated migration capsules when the image and all live owners satisfy the compatibility contract. These capsules ride in memory across `execve`, so the carried mesh state survives a hot-upgrade but not a cold restart. | `src/daemon/helix/live.zig`, `src/substrate/upgrade_capsule.zig` |
| **Content filter** (formerly Koshi) | The operator-curated filter: a small set of oper-curated patterns matched against outbound `PRIVMSG`/`NOTICE` bodies, where a hit blocks the message. | `src/daemon/content_filter.zig` |
| **Memo** | Onyx Server-native offline messaging keyed by account: a direct message left for an account with no attached session is stored and delivered when that account next logs in (with an optional Web Push nudge via local delivery and secured `MEMO_PUSH` mesh hints). | `src/daemon/memo.zig`, `src/proto/memo_push_relay.zig`, `src/proto/s2s_frame.zig` |

## Media codecs

| Codename | What it is | Source |
| --- | --- | --- |
| **CadenceVox** | The native voice/audio codec used on the media plane and in the browser WASM export. | `src/proto/server_about.zig`, `src/wasm/cadence_wasm.zig` |
| **CadenceVis** | The native video codec (intra/inter frames) paired with CadenceVox. | `src/proto/server_about.zig`, `src/wasm/cadence_wasm.zig` |

## Cryptographic terms

These are standard cryptographic concepts (not mythos codenames) that recur in
the TLS, cloak, and account docs.

| Term | What it is | Source |
| --- | --- | --- |
| **argon2id** | Memory-hard KDF (Password Hashing Competition winner). Used by the explicit Argon2 KDF/PHC helpers and to stretch `[cloak] secret` into the cloak key with a fixed domain-separation salt; the live account Services password path currently uses PBKDF2-HMAC-SHA256 — raising the cost of offline guesses against the enumerable IPv4 space; a high-entropy secret is still required. | `src/crypto/argon2_kdf.zig` (`deriveKey`), `src/crypto/argon2_kdf.zig` (`cloak_key_salt`) |
| **Epoch cloak** | The auth-split anonymous cloak: an unauthenticated client's IP is cloaked with an opaque 128-bit token that folds in a wall-clock epoch (`floor(meshWallMs/1000/anon_epoch_secs)`), so the cloak token changes across epochs and exposes no subnet hierarchy; nicks/accounts and other metadata can still correlate clients. A connection that stays up is re-cloaked when the epoch changes. See [host cloaking](host-cloaking.md#anonymous-auth-split-cloak-epoch-rotating). | `cloakOpaqueEpochV3` in `src/proto/cloak.zig`, `anonCloakEpoch` in `src/daemon/server.zig` |
| **EMS** (Extended Master Secret, RFC 7627) | TLS-1.2 master-secret derivation bound to the full handshake transcript, closing the triple-handshake class of attacks. Onyx Server's hardened TLS 1.2 profile **refuses a non-EMS handshake**. | `src/crypto/tls12.zig` (`deriveExtendedMasterSecret`), `src/crypto/tls_server.zig` |
| **0-RTT freshness window** | The RFC 8446 §8.2–8.3 freshness bound on TLS 1.3 early data. Acceptance requires a configured clock plus a sealed issue time, `ticket_age_add`, and lifetime. Missing evidence refuses early data before consuming a replay slot; eligible tickets may still resume at 1-RTT under the separate lifetime policy. Freshness alone does not prevent replay across nodes. | `src/crypto/tls_server.zig` (`ticketAgeWithinWindow`, `tryAcceptPsk`), `src/crypto/tls_resumption.zig` |

## See also

- [Mesh & S2S architecture](../architecture/mesh-s2s.md) — how Undertow, Mooring, Ripple, Concord, and ordinary guest presence fit together.
- [Cryptography architecture](../architecture/crypto.md) — Armor and the Mooring handshake in depth.
- [Upgrade & WASM host](../architecture/04-upgrade-wasm.md) — the Helix upgrade path.
- [Media architecture](../architecture/03-media.md) — the media plane and CadenceVox/CadenceVis.
