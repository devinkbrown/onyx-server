# Glossary & brand names

*Audience: all readers. The one authoritative key to the naming — the branded
house (Onyx network / Onyx Server engine / retired IRCXNet) and the engine's
mythos-derived subsystem vocabulary. Each invented
codename says what it actually is and where it lives in the source. Every
codename entry is cited to `src/`; the daemon's own `/INFO` body renders the
same subsystem summary (`src/proto/server_about.zig:63`). The site, the Onyx
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
name` sets the string emitted in the `001` welcome (`src/daemon/dispatch.zig:2094`,
`emitWelcome`), the `NETWORK` `005` token (`src/proto/isupport.zig:265`, `:350`), and
the `/INFO` `Network:` line (`src/proto/server_about.zig:71`). The protocol layer's
default network name constant is **`Onyx`** (`src/proto/protocol_inventory.zig:19`).
In normal operation `Config.initDefaults` also seeds `[network] name` to **`Onyx`**
(`src/daemon/config_format.zig:879`) and `main.zig` installs it via `setNetworkName`
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
| **Undertow** (水脈) | The S2S CRDT mesh **state model**: logical/hybrid-logical clocks, delta-state CRDTs, and Merkle anti-entropy — the building blocks of the replicated mesh world state. (The running daemon repairs membership with the reactor-0 full local-roster re-burst.) | `src/substrate/undertow/root.zig:4`, `src/substrate/undertow/` |
| **Ripple** (漣) | A pure witness-quorum failure-detection library, not the daemon's live failure detector; `witness_quorum` floors at 2, so a pair cannot form a witnessed quorum. | `src/substrate/undertow/ripple.zig:4`, `src/substrate/undertow/gossip_round.zig:4` |
| **Concord** | The delta-state CRDT library (OR-Set, LWW register, dots/causal context) that models mesh membership and other replicated state carried over Undertow. | `src/substrate/undertow/concord.zig:4` |
| **Mooring** (紡ぎ) | The S2S secure-channel AKE and session ratchet: a Noise-IK-shaped, post-quantum-hybrid handshake (Ed25519 static node identity + X-Wing hybrid KEM) that establishes and re-keys the encrypted server-to-server link. | `src/crypto/mooring_handshake.zig:4`, `src/crypto/mooring_session.zig` |
| **MeshPass** | Ed25519-signed capability admission tokens that gate which nodes may join the mesh; verified inside the encrypted handshake, fail-closed on tampered/untrusted material. | `src/proto/meshpass_props.zig:6`, `src/proto/server_about.zig:64` |
| **Armor** (鎧) | The from-scratch, pure-Zig TLS stack and cryptographic primitive library (TLS 1.3 + hardened TLS 1.2, PQ-hybrid key exchange, AEADs, signing). | `src/proto/server_about.zig:65`, `src/crypto/` |
| **Ringlane** | The reactor seam: all time and I/O flow through `Reactor`, so the daemon runs unchanged against either the real io_uring/system backend or the deterministic simulator (Deterministic Ocean). | `src/substrate/reactor.zig:4` |
| **Helix** | The in-place `USR2` hot-upgrade: a replacement image is `execve`'d and adopts the running listener, live sessions, and the converged mesh view (each link's remote-member roster + the cross-mesh oper-grant registry) through typed migration capsules, with no connection-refused window. These capsules ride in memory across `execve`, so the carried mesh state survives a hot-upgrade but not a cold restart. | `src/daemon/helix/live.zig:4`, `src/substrate/upgrade_capsule.zig:4` |
| **Koshi** | The operator-curated content filter: a small set of oper-curated patterns matched against outbound `PRIVMSG`/`NOTICE` bodies, where a hit blocks the message. | `src/daemon/content_filter.zig:4` |
| **Memo** | Onyx Server-native offline messaging keyed by account: a direct message left for an account with no attached session is stored and delivered when that account next logs in (with an optional Web Push nudge via local delivery and secured `MEMO_PUSH` mesh hints). | `src/daemon/memo.zig:4`, `src/proto/memo_push_relay.zig:4`, `src/proto/s2s_frame.zig:109` |

## Media codecs

| Codename | What it is | Source |
| --- | --- | --- |
| **CadenceVox** | The native voice/audio codec used on the media plane and in the browser WASM export. | `src/proto/server_about.zig:66`, `src/wasm/cadence_wasm.zig:1` |
| **CadenceVis** | The native video codec (intra/inter frames) paired with CadenceVox. | `src/proto/server_about.zig:66`, `src/wasm/cadence_wasm.zig:1` |

## Cryptographic terms

These are standard cryptographic concepts (not mythos codenames) that recur in
the TLS, cloak, and account docs.

| Term | What it is | Source |
| --- | --- | --- |
| **argon2id** | Memory-hard KDF (Password Hashing Competition winner). Used for account-password storage (PHC strings) and to stretch the `[cloak] secret` into the cloak key with a fixed domain-separation salt — so a low-entropy operator passphrase is not offline-brute-forceable against the enumerable IPv4 space. | `src/crypto/argon2_kdf.zig:130` (`deriveKey`), `src/crypto/argon2_kdf.zig:117` (`cloak_key_salt`) |
| **Epoch cloak** | The auth-split anonymous cloak: an unauthenticated client's IP is cloaked with an opaque 64-bit token that folds in a wall-clock epoch (`floor(now/anon_epoch_secs)`), so the same address is unlinkable across epochs and leaks no subnet co-membership. See [host cloaking](host-cloaking.md#anonymous-auth-split-cloak-epoch-rotating). | `src/proto/cloak.zig:187` (`cloakOpaqueEpoch`), `src/daemon/server.zig:5981` (`anonCloakEpoch`) |
| **EMS** (Extended Master Secret, RFC 7627) | TLS-1.2 master-secret derivation bound to the full handshake transcript, closing the triple-handshake class of attacks. Onyx Server's hardened TLS 1.2 profile **refuses a non-EMS handshake**. | `src/crypto/tls12.zig:302` (`deriveExtendedMasterSecret`), `src/crypto/tls_server.zig:343` |
| **0-RTT freshness window** | The RFC 8446 §8.2–8.3 anti-replay bound on TLS 1.3 early data. v3 session tickets seal the `ticket_age_add`, so any node holding the ticket key can un-obfuscate the client's reported `obfuscated_ticket_age` and enforce the window; legacy v1/v2 tickets degrade to no window check (never a failure). | `src/crypto/tls_resumption.zig:27`, `src/crypto/tls_resumption.zig:386` |

## See also

- [Mesh & S2S architecture](../architecture/mesh-s2s.md) — how Undertow, Mooring, Ripple, and Concord fit together.
- [Cryptography architecture](../architecture/crypto.md) — Armor and the Mooring handshake in depth.
- [Upgrade & WASM host](../architecture/04-upgrade-wasm.md) — the Helix upgrade path.
- [Media architecture](../architecture/03-media.md) — the media plane and CadenceVox/CadenceVis.
