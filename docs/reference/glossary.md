# Codename glossary

*Audience: all readers. A key to the Orochi mythos vocabulary — each invented
codename, what it actually is, and where it lives in the source. Every entry is
cited to `src/`; the daemon's own `/INFO` body renders the same summary
(`src/proto/server_about.zig:63`).*

Orochi names its major subsystems after Japanese mythos/terms rather than
generic acronyms. First use of a codename in the guides and architecture docs
links here.

## Subsystems

| Codename | What it is | Source |
| --- | --- | --- |
| **Suimyaku** (水脈) | The S2S CRDT mesh **state model**: logical/hybrid-logical clocks, delta-state CRDTs, and Merkle anti-entropy — the building blocks of the replicated mesh world state. (Membership and liveness are handled by Sazanami + Goryu below, not Suimyaku itself.) | `src/substrate/suimyaku/root.zig:4`, `src/substrate/suimyaku/` |
| **Sazanami** (漣) | The witnessed failure-detection membership state machine: a pure, deterministic liveness detector driven by gossip probes and a witness quorum, deciding which nodes are alive/suspect/dead. | `src/substrate/sazanami.zig:4`, `src/substrate/suimyaku/gossip_round.zig:4` |
| **Goryu** | The delta-state CRDT library (OR-Set, LWW register, dots/causal context) that models mesh membership and other replicated state carried over Suimyaku. | `src/substrate/suimyaku/goryu.zig:4` |
| **Tsumugi** (紡ぎ) | The S2S secure-channel AKE and session ratchet: a Noise-IK-shaped, post-quantum-hybrid handshake (Ed25519 static node identity + X-Wing hybrid KEM) that establishes and re-keys the encrypted server-to-server link. | `src/crypto/tsumugi_handshake.zig:4`, `src/crypto/tsumugi_session.zig` |
| **MeshPass** | Ed25519-signed capability admission tokens that gate which nodes may join the mesh; verified inside the encrypted handshake, fail-closed on tampered/untrusted material. | `src/proto/meshpass_props.zig:6`, `src/proto/server_about.zig:64` |
| **Yoroi** (鎧) | The from-scratch, pure-Zig TLS stack and cryptographic primitive library (TLS 1.3 + hardened TLS 1.2, PQ-hybrid key exchange, AEADs, signing). | `src/proto/server_about.zig:65`, `src/crypto/` |
| **Ringlane** | The reactor seam: all time and I/O flow through `Reactor`, so the daemon runs unchanged against either the real io_uring/system backend or the deterministic simulator (Deterministic Ocean). | `src/substrate/reactor.zig:4` |
| **Helix** | The in-place `USR2` hot-upgrade: a replacement image is `execve`'d and adopts the running listener and live sessions through a typed migration capsule, with no connection-refused window. | `src/daemon/helix/live.zig:4`, `src/substrate/upgrade_capsule.zig:4` |
| **Koshi** | The operator-curated content filter: a small set of oper-curated patterns matched against outbound `PRIVMSG`/`NOTICE` bodies, where a hit blocks the message. | `src/daemon/content_filter.zig:4` |
| **Tegami** (手紙) | Orochi-native offline messaging keyed by account: a direct message left for an account with no attached session is stored and delivered when that account next logs in (with an optional Web Push nudge). | `src/daemon/tegami.zig:4`, `src/proto/tegami_push_relay.zig:5` |

## Media codecs

| Codename | What it is | Source |
| --- | --- | --- |
| **KaguraVox** | The native voice/audio codec used on the media plane and in the browser WASM export. | `src/proto/server_about.zig:66`, `src/wasm/kagura_wasm.zig:1` |
| **KaguraVis** | The native video codec (intra/inter frames) paired with KaguraVox. | `src/proto/server_about.zig:66`, `src/wasm/kagura_wasm.zig:1` |

## Cryptographic terms

These are standard cryptographic concepts (not mythos codenames) that recur in
the TLS, cloak, and account docs.

| Term | What it is | Source |
| --- | --- | --- |
| **argon2id** | Memory-hard KDF (Password Hashing Competition winner). Used for account-password storage (PHC strings) and to stretch the `[cloak] secret` into the cloak key with a fixed domain-separation salt — so a low-entropy operator passphrase is not offline-brute-forceable against the enumerable IPv4 space. | `src/crypto/argon2_kdf.zig:130` (`deriveKey`), `src/crypto/argon2_kdf.zig:117` (`cloak_key_salt`) |
| **Epoch cloak** | The auth-split anonymous cloak: an unauthenticated client's IP is cloaked with an opaque 64-bit token that folds in a wall-clock epoch (`floor(now/anon_epoch_secs)`), so the same address is unlinkable across epochs and leaks no subnet co-membership. See [host cloaking](host-cloaking.md#anonymous-auth-split-cloak-epoch-rotating). | `src/proto/cloak.zig:187` (`cloakOpaqueEpoch`), `src/daemon/server.zig:5981` (`anonCloakEpoch`) |
| **EMS** (Extended Master Secret, RFC 7627) | TLS-1.2 master-secret derivation bound to the full handshake transcript, closing the triple-handshake class of attacks. Orochi's hardened TLS 1.2 profile **refuses a non-EMS handshake**. | `src/crypto/tls12.zig:302` (`deriveExtendedMasterSecret`), `src/crypto/tls_server.zig:343` |
| **0-RTT freshness window** | The RFC 8446 §8.2–8.3 anti-replay bound on TLS 1.3 early data. v3 session tickets seal the `ticket_age_add`, so any node holding the ticket key can un-obfuscate the client's reported `obfuscated_ticket_age` and enforce the window; legacy v1/v2 tickets degrade to no window check (never a failure). | `src/crypto/tls_resumption.zig:27`, `src/crypto/tls_resumption.zig:386` |

## See also

- [Mesh & S2S architecture](../architecture/mesh-s2s.md) — how Suimyaku, Tsumugi, Sazanami, and Goryu fit together.
- [Cryptography architecture](../architecture/crypto.md) — Yoroi and the Tsumugi handshake in depth.
- [Upgrade & WASM host](../architecture/04-upgrade-wasm.md) — the Helix upgrade path.
- [Media architecture](../architecture/03-media.md) — the media plane and KaguraVox/KaguraVis.
