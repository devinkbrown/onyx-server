# Cryptography and secure-channel architecture

*The cryptography implemented in the current Onyx Server source tree: primitives, TLS, the Mooring AKE, and the signed-object formats that protect mesh traffic.*

This document describes the cryptography that exists in the current Onyx Server
source tree. Every behavioral claim is cited to `src/`.

## Scope and stance

Onyx Server is a clean-room, pure-Zig IRC daemon built from first principles: the daemon,
substrate, and crypto/TLS library are all written from scratch in Zig, and
no prior daemon is derived from as source (`README.md:3`, `README.md:133`).
The pinned toolchain target is Zig 0.17.0-dev.1282+c0f9b51d8 (`build.zig.zon:34`).

The crypto and TLS paths covered here are Zig modules built from `std.crypto`
and local code. For example, X-Wing builds on `std.crypto.kem.ml_kem.MLKem768`
and `std.crypto.dh.X25519` (`src/crypto/xwing.zig:15`, `src/crypto/xwing.zig:17`,
`src/crypto/xwing.zig:18`), TLS server AEADs come from `std.crypto`
(`src/crypto/tls_server.zig:29`, `src/crypto/tls_server.zig:30`,
`src/crypto/tls_server.zig:31`), and MeshPass uses `std.crypto.sign.Ed25519`
(`src/proto/meshpass.zig:9`).

The deployed client TLS stance is implicit TLS, with no STARTTLS.
`main.zig` configures an implicit TLS port and states "No STARTTLS" explicitly
(`src/main.zig:213`, `src/main.zig:216`). `server.Config` repeats the policy:
the TLS listener wraps ordinary IRC clients and is "no STARTTLS"
(`src/daemon/server.zig:1037`, `src/daemon/server.zig:1038`). The preferred
listener path is TLS 1.3; when a TLS 1.2 config is present, `TlsConn.initDual`
routes non-1.3 ClientHello traffic into the hardened TLS 1.2 server
(`src/daemon/tls_conn.zig:64`, `src/daemon/tls_conn.zig:69`,
`src/daemon/tls_conn.zig:93`, `src/daemon/tls_conn.zig:96`). The TLS 1.3
server supports X25519, secp256r1, and X25519MLKEM768 key shares,
Ed25519/ECDSA-P256/RSA CertificateVerify keys, and
AES-128-GCM/AES-256-GCM/ChaCha20-Poly1305 suites
(`src/crypto/tls_server.zig:119`, `src/crypto/tls_server.zig:127`,
`src/crypto/tls_server.zig:131`, `src/crypto/tls_server.zig:135`,
`src/crypto/tls_server.zig:361`, `src/crypto/tls_server.zig:363`,
`src/crypto/tls_server.zig:1471`, `src/crypto/tls_server.zig:1499`).
The TLS 1.2 fallback is intentionally fail-closed: TLS 1.2 only, null
compression, secp256r1 ECDHE, ECDSA-P256/RSA authentication, and AEAD suites
only; policy rejects RSA key exchange, CBC, RC4, export, NULL, TLS 1.0/1.1,
compression, and renegotiation (`src/crypto/tls12_server.zig:4`,
`src/crypto/tls12_server.zig:10`, `src/crypto/tls.zig:173`,
`src/crypto/tls.zig:207`, `src/crypto/tls.zig:724`,
`src/crypto/tls.zig:749`). The source above is the authority for what is
implemented.

## Primitive inventory

| Surface | Implemented primitive / format | Source evidence |
| --- | --- | --- |
| X-Wing KEM | ML-KEM-768 + X25519 hybrid KEM; public key is ML-KEM-768 public key plus X25519 public key; ciphertext is ML-KEM-768 ciphertext plus X25519 ephemeral public key; shared secret is SHA3-256 over `ss_M || ss_X || ct_X || pk_X || XWingLabel`. | `src/crypto/xwing.zig:1`, `src/crypto/xwing.zig:5`, `src/crypto/xwing.zig:6`, `src/crypto/xwing.zig:7`, `src/crypto/xwing.zig:129`, `src/crypto/xwing.zig:135` |
| Ed25519 identity and signatures | Mooring node identity and signed prekeys use the local Ed25519 signing key; `SignedPrekey` embeds the node key and Ed25519 signature. | `src/crypto/mooring_handshake.zig:99`, `src/crypto/mooring_handshake.zig:101`, `src/crypto/mooring_handshake.zig:110`, `src/crypto/mooring_handshake.zig:136`, `src/crypto/mooring_handshake.zig:137` |
| Mooring handshake payload AEAD | Handshake payloads are sealed/opened with ChaCha20-Poly1305. Keys are derived with HKDF-SHA256 over the X-Wing secret and a BLAKE3 salt over label/AAD. | `src/crypto/mooring_handshake.zig:17`, `src/crypto/mooring_handshake.zig:18`, `src/crypto/mooring_handshake.zig:467`, `src/crypto/mooring_handshake.zig:473`, `src/crypto/mooring_handshake.zig:474`, `src/crypto/mooring_handshake.zig:489`, `src/crypto/mooring_handshake.zig:495` |
| TLS listener AEADs | TLS 1.3 server supports `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, and `TLS_CHACHA20_POLY1305_SHA256`; TLS 1.2 policy allows only ECDHE AEAD suites. | `src/crypto/tls_server.zig:361`, `src/crypto/tls_server.zig:363`, `src/crypto/tls_server.zig:407`, `src/crypto/tls_server.zig:411`, `src/crypto/tls.zig:173`, `src/crypto/tls.zig:207` |
| Secret(T) | Fixed-size and runtime-length byte-secret wrappers require explicit `expose`/`declassify`, compare without data-dependent early exit, format as redacted, and wipe wrapped bytes. Compile-time checks reject non-byte wrappers or non-mutable storage for wipe. | `src/crypto/secret.zig:4`, `src/crypto/secret.zig:9`, `src/crypto/secret.zig:27`, `src/crypto/secret.zig:42`, `src/crypto/secret.zig:44`, `src/crypto/secret.zig:63`, `src/crypto/secret.zig:67`, `src/crypto/secret.zig:89`, `src/crypto/secret.zig:100`, `src/crypto/secret.zig:129` |
| HPKE | Base mode DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305. | `src/crypto/hpke.zig:1`, `src/crypto/hpke.zig:9`, `src/crypto/hpke.zig:10`, `src/crypto/hpke.zig:11`, `src/crypto/hpke.zig:14`, `src/crypto/hpke.zig:15`, `src/crypto/hpke.zig:16` |
| TreeKEM-style group root | MLS-like left-balanced tree; leaves are X25519 member keys and parent/path secrets use HKDF-SHA256. | `src/crypto/treekem.zig:1`, `src/crypto/treekem.zig:4`, `src/crypto/treekem.zig:5`, `src/crypto/treekem.zig:11`, `src/crypto/treekem.zig:12` |
| Session reclaim | Canonical length-prefixed fields with trailing HMAC-SHA256 tag. | `src/proto/session_reclaim_mesh.zig:1`, `src/proto/session_reclaim_mesh.zig:8`, `src/proto/session_reclaim_mesh.zig:9`, `src/proto/session_reclaim_mesh.zig:19` |
| CoilPack | Canonical self-describing binary atoms and a canonical value layer for stable signing. | `src/proto/coilpack.zig:1`, `src/proto/coilpack.zig:3`, `src/proto/coilpack.zig:5`, `src/proto/coilpack_value.zig:1`, `src/proto/coilpack_value.zig:10`, `src/proto/coilpack_value.zig:11` |

## Account key transparency

`src/daemon/key_transparency.zig` is the server-side substrate for verifiable
account identity. It defines credential events for CERTFP and WebAuthn/passkey
bind/delete mutations, hashes each event with BLAKE3 under the
`ONYX-KT-EVENT-v1` domain, length-frames account and key identifiers, and
appends the resulting leaf to the existing Merkle Mountain Range substrate
(`src/daemon/key_transparency.zig:19`, `src/daemon/key_transparency.zig:24`,
`src/daemon/key_transparency.zig:29`, `src/daemon/key_transparency.zig:49`,
`src/daemon/key_transparency.zig:69`, `src/daemon/key_transparency.zig:85`,
`src/daemon/key_transparency.zig:105`).

The daemon's live account-services path attaches a `KeyTransparencyLog`; CERTFP
bind/delete and WebAuthn bind/delete append canonical events under the services
mutation lock (`src/main.zig`, `src/daemon/services.zig`). WebAuthn events hash
the raw COSE public key material, while CERTFP events hash the fingerprint
string. The public `status.json` feed exposes whether key transparency is live,
the current append count, and the current MMR root. Clients and operators can
also query the same log through the `KEYTRANS` server command: `STATUS`/`ROOT`
returns the current root and size, while `PROOF <position>` streams the copied
path and peak hashes needed to verify one inclusion proof
(`src/daemon/server.zig`, `src/daemon/services.zig`,
`src/daemon/key_transparency.zig`).

## E2EE control plane

Onyx Server's daemon does not decrypt client E2EE payloads. The implemented server
surface is a control plane: the `onyx/e2ee` capability allows the client-only
`+onyx/e2ee` message tag, and the channel PROP `encryption-policy` accepts
`off`, `optional`, or `required`. Required rooms reject plaintext `PRIVMSG`
delivery with `FAIL PRIVMSG E2EE_REQUIRED`; `NOTICE` is silently dropped per IRC
NOTICE error rules. The policy value is an ordinary signed channel PROP, so it
persists and converges through the existing channel PROP CRDT.

Public account device keys are advertised with `E2EEKEY`, which stores bounded
`e2ee.device.<device-id>` user PROP records as `<algorithm>:<public-key>` and
fans changes through signed `ENTITY_PROP` replication. This gives clients a
mesh-visible device-key directory without introducing a second key store or a
server-side plaintext path.

### 1.x threat boundary

A retained `ONYXROOM1` envelope from an old epoch stays readable by whoever
held that epoch's key. The daemon does not hold the key. `E2EE.COMMIT`,
`E2EE.WELCOME`, and `E2EE.KEYPACKAGE` payloads stay opaque base64url, and a
required room stores the envelope rather than plaintext. Re-encrypting history
on the server would require the daemon to see the epoch key or the plaintext.
Erasing a former member's copy of an old epoch key is a client choice. 1.x
does not add a server history-rekey mode.

Metadata-min mode, which would hide nicks, sizes, and timing from the server,
is not a daemon mode. `NAMES` still lists members. Authorized search still
returns plaintext the caller can see, and it still drops ciphertext bodies.
Abuse handling still sees the connection. A sealed room is a separate opt-in
that refuses only that room's clear roster. Neither history rekey nor
metadata-min follows from this boundary.

### Sealed room prototype

The server still sees three things for a sealed room. Routing uses the channel
name, and the world membership that delivers a message stays in place. Abuse
handling still names the one nick an operator supplies to `KICK`. Helix keeps
that delivery membership and does not publish it as a clear roster. No new
capsule kind is added.

The server does not emit the member list in the clear. `NAMES`, `WHO`, and
`WHOX` on `membership-visibility=sealed` fail with `MEMBERSHIP_SEALED` and do
not send a roster or an empty end-of-list. Absent and `ordinary` keep today's
lists, so an ordinary channel is unchanged. A value other than those two is
rejected, and a stored value the server does not understand refuses the roster.

## Portable account identity

Ryujin portable identity starts as account-owned Ed25519 assertions. `IDENTITY`
does not generate keys; it verifies that a supplied public key signed Onyx Server's
domain-separated account-binding transcript for `{account, label, public_key}`.
Verified records are stored as account user PROP facts under
`identity.key.<label>` with value `<pubkey-hex>:<signature-hex>`, then announced
through the existing signed `ENTITY_PROP` replication path. The result is a
mesh-visible public identity-key directory for clients and future cross-mesh
admission flows without making server-local account rows the only source of
identity truth.

## ProofMark moderation proofs

`src/daemon/proofmark.zig` defines signed moderation proofs for privileged policy
decisions. The signed transcript is fixed-order and length-prefixed, committing
to actor, target, action code, SHA-256 reason hash, policy version, issue time,
and expiry. The module now also derives a public proof id from the canonical
proof body plus detached Ed25519 signature, so audit output can cite a stable
identifier without exposing the full reason text beyond its hash.

The live oper audit ring stores the proof id plus detached signature, public key,
reason hash, policy version, issue time, and expiry for signed privileged
actions. `LinuxServer.recordOperAudit` mints that evidence when the node has a
mesh signing key, `AUDIT` renders Event Spine `EVENT <oper> AUDIT ...` lines with
`proof=<id>` on signed records, and `AUDIT PROOF <id>` lets an operator inspect
the stored proof material after the server re-verifies the signature and proof
id. `AUDIT JSON` and `AUDIT PROOF JSON <id>` use the same Event Spine line shape
with stable JSON payloads for operator UIs. Moderation Event Spine notices for
signed actions also carry the same `proof=<id>` token, so an operator watching
`EVENT` can jump directly to `AUDIT PROOF`. Current signed daemon actions include
KILL, JUPE, native WARD ADD/DEL, SHUN, UNSHUN, CONNECT, SQUIT, REDACT, IRCX
ACCESS add/delete/clear mutations, and FORCE* channel actions. Nodes without a
mesh key keep unsigned audit and event lines.

## Node identity

`src/daemon/node_identity.zig` derives all live Mooring identity material from
the configured `node.secret_key` and `mesh.realm`. The sovereign seed is a
32-byte Ed25519 seed supplied as 64 hex chars; `fromConfig` rejects other sizes
or invalid hex (`src/daemon/node_identity.zig:90`,
`src/daemon/node_identity.zig:92`, `src/daemon/node_identity.zig:93`,
`src/daemon/node_identity.zig:95`). From that seed:

| Derived value | Derivation | Source evidence |
| --- | --- | --- |
| Ed25519 static keypair | `sign.KeyPair.fromSeed(seed)` | `src/daemon/node_identity.zig:79`, `src/daemon/node_identity.zig:80` |
| X-Wing KEM keypair | KEM seed is BLAKE3 over `"MZ-KEM"` and the Ed25519 seed; X-Wing keypair is deterministic from that seed. | `src/daemon/node_identity.zig:69`, `src/daemon/node_identity.zig:71`, `src/daemon/node_identity.zig:72`, `src/daemon/node_identity.zig:81` |
| Canonical node id | first 20 bytes of BLAKE3(Ed25519 public key). | `src/daemon/node_identity.zig:63`, `src/daemon/node_identity.zig:65`, `src/daemon/node_identity.zig:66` |
| Realm id | BLAKE3(realm string), 32 bytes. | `src/daemon/node_identity.zig:57`, `src/daemon/node_identity.zig:59`, `src/daemon/node_identity.zig:86` |
| Signed prekey | `SignedPrekey.create` over local signing key, KEM keypair, realm, prekey id, time window, usage, bands, and features. | `src/daemon/node_identity.zig:44`, `src/daemon/node_identity.zig:45`, `src/daemon/node_identity.zig:52`, `src/daemon/node_identity.zig:53` |

The 20-byte node id is canonical identity. `node_short_id.shortId` derives a
u64 routing handle from it using BLAKE3 with domain label
`MZ-S2S-SHORTID-v1`, reads the first 8 bytes big-endian, and maps a derived zero
to one because zero is an unknown-peer sentinel (`src/crypto/node_short_id.zig:1`,
`src/crypto/node_short_id.zig:3`, `src/crypto/node_short_id.zig:10`,
`src/crypto/node_short_id.zig:24`, `src/crypto/node_short_id.zig:30`,
`src/crypto/node_short_id.zig:36`, `src/crypto/node_short_id.zig:37`).
`mooring_session.Session` captures both identities on establishment:
`peerNodeId()` returns the authenticated 20-byte id, `peerNodeKey()` returns the
authenticated Ed25519 public key, and `peerShortId()` returns the u64 routing
handle (`src/crypto/mooring_session.zig:120`,
`src/crypto/mooring_session.zig:129`, `src/crypto/mooring_session.zig:140`).

At boot, a configured `node.secret_key` enables PQ-secured S2S by deriving this
identity; without it, S2S stays plaintext for compatibility
(`src/main.zig:138`, `src/main.zig:139`, `src/main.zig:141`,
`src/main.zig:145`, `src/main.zig:146`, `src/main.zig:148`,
`src/main.zig:150`, `src/main.zig:152`).

## Mooring PQ-hybrid S2S handshake

The Mooring handshake is implemented in `src/crypto/mooring_handshake.zig` and
wrapped by `src/crypto/mooring_session.zig`. The module comment describes it as
a compact Noise-IK-shaped AKE: Ed25519 is the static node identity, X-Wing
transport prekeys provide hybrid KEM entropy, and the initiator node id plus
MeshPass bytes appear only inside encrypted M1
(`src/crypto/mooring_handshake.zig:1`, `src/crypto/mooring_handshake.zig:3`,
`src/crypto/mooring_handshake.zig:4`, `src/crypto/mooring_handshake.zig:5`,
`src/crypto/mooring_handshake.zig:6`).

### Wire constants and limits

| Item | Value / behavior | Source |
| --- | --- | --- |
| Magic | `MZTH` | `src/crypto/mooring_handshake.zig:48` |
| Message types | M1 = 1, M2 = 2 | `src/crypto/mooring_handshake.zig:49`, `src/crypto/mooring_handshake.zig:50` |
| Protocol version | 1 | `src/crypto/mooring_handshake.zig:30` |
| M1/M2 payload schemas | `0x3002`, `0x3003` | `src/crypto/mooring_handshake.zig:51`, `src/crypto/mooring_handshake.zig:52` |
| Signature domains | `tsumugi-prekey-v1`, `tsumugi-m1-v1`, `tsumugi-m2-v1` | `src/crypto/mooring_handshake.zig:53`, `src/crypto/mooring_handshake.zig:54`, `src/crypto/mooring_handshake.zig:55` |
| MeshPass byte cap | default 4096, configurable as `[tls].tsumugi_max_meshpass_len`; zero/absent leaves the cap unchanged. | `src/crypto/mooring_handshake.zig:33`, `src/crypto/mooring_handshake.zig:38`, `src/crypto/mooring_handshake.zig:40`, `src/crypto/mooring_handshake.zig:42`, `src/crypto/mooring_handshake.zig:43`, `src/crypto/mooring_handshake.zig:44` |

### SignedPrekey

`SignedPrekey` contains the realm, Ed25519 node key, 20-byte node id, prekey id,
X-Wing public key, validity window, usage bits, supported bands/features, and
signature (`src/crypto/mooring_handshake.zig:99`,
`src/crypto/mooring_handshake.zig:100`, `src/crypto/mooring_handshake.zig:101`,
`src/crypto/mooring_handshake.zig:102`, `src/crypto/mooring_handshake.zig:103`,
`src/crypto/mooring_handshake.zig:104`, `src/crypto/mooring_handshake.zig:105`,
`src/crypto/mooring_handshake.zig:106`, `src/crypto/mooring_handshake.zig:107`,
`src/crypto/mooring_handshake.zig:108`, `src/crypto/mooring_handshake.zig:109`,
`src/crypto/mooring_handshake.zig:110`). Creation computes the node id from the
Ed25519 public key, hashes all prekey fields with BLAKE3 domain
`MZ-TSUMUGI-PREKEY-v1`, and signs that digest in the prekey domain
(`src/crypto/mooring_handshake.zig:126`,
`src/crypto/mooring_handshake.zig:136`, `src/crypto/mooring_handshake.zig:137`,
`src/crypto/mooring_handshake.zig:383`, `src/crypto/mooring_handshake.zig:385`,
`src/crypto/mooring_handshake.zig:386`, `src/crypto/mooring_handshake.zig:390`,
`src/crypto/mooring_handshake.zig:394`, `src/crypto/mooring_handshake.zig:395`).
Verification checks node-id consistency, the validity window, and the Ed25519
signature (`src/crypto/mooring_handshake.zig:141`,
`src/crypto/mooring_handshake.zig:142`, `src/crypto/mooring_handshake.zig:143`,
`src/crypto/mooring_handshake.zig:144`, `src/crypto/mooring_handshake.zig:145`).

`secured_s2s_link` adds a TOFU preamble around the AKE: the responder announces
its signed prekey, the initiator verifies signature and validity, optionally
pins the expected remote node id, and then starts IK
(`src/daemon/secured_s2s_link.zig:11`, `src/daemon/secured_s2s_link.zig:12`,
`src/daemon/secured_s2s_link.zig:13`, `src/daemon/secured_s2s_link.zig:95`,
`src/daemon/secured_s2s_link.zig:96`, `src/daemon/secured_s2s_link.zig:233`,
`src/daemon/secured_s2s_link.zig:235`, `src/daemon/secured_s2s_link.zig:236`,
`src/daemon/secured_s2s_link.zig:237`, `src/daemon/secured_s2s_link.zig:240`,
`src/daemon/secured_s2s_link.zig:248`). Live prekeys are freshly built with a
24-hour TTL and a five-minute backdate for clock skew
(`src/daemon/server.zig:2587`, `src/daemon/server.zig:2591`,
`src/daemon/server.zig:2595`, `src/daemon/server.zig:2596`).

### M1

The initiator verifies both local and responder prekeys, checks realm, enforces
the MeshPass length cap, then X-Wing encapsulates to the responder's signed
prekey public key (`src/crypto/mooring_handshake.zig:183`,
`src/crypto/mooring_handshake.zig:185`, `src/crypto/mooring_handshake.zig:186`,
`src/crypto/mooring_handshake.zig:187`, `src/crypto/mooring_handshake.zig:188`,
`src/crypto/mooring_handshake.zig:190`). M1 prefix is header + responder
prekey id + X-Wing ciphertext + nonce; the sealed body length and
ChaCha20-Poly1305 ciphertext/tag follow (`src/crypto/mooring_handshake.zig:193`,
`src/crypto/mooring_handshake.zig:195`, `src/crypto/mooring_handshake.zig:196`,
`src/crypto/mooring_handshake.zig:197`, `src/crypto/mooring_handshake.zig:198`,
`src/crypto/mooring_handshake.zig:199`, `src/crypto/mooring_handshake.zig:203`,
`src/crypto/mooring_handshake.zig:209`, `src/crypto/mooring_handshake.zig:210`).

The encrypted M1 payload contains the initiator node id, initiator Ed25519
public key, initiator signed prekey, requested bands/features, local time,
MeshPass bytes, and an Ed25519 signature over the M1 transcript digest
(`src/crypto/mooring_handshake.zig:247`, `src/crypto/mooring_handshake.zig:253`,
`src/crypto/mooring_handshake.zig:254`, `src/crypto/mooring_handshake.zig:255`,
`src/crypto/mooring_handshake.zig:256`, `src/crypto/mooring_handshake.zig:257`,
`src/crypto/mooring_handshake.zig:258`, `src/crypto/mooring_handshake.zig:259`,
`src/crypto/mooring_handshake.zig:260`, `src/crypto/mooring_handshake.zig:262`,
`src/crypto/mooring_handshake.zig:263`). The responder decapsulates, opens M1,
verifies the initiator prekey, realm, node id/key consistency, anti-downgrade
bands/features, and M1 signature (`src/crypto/mooring_handshake.zig:299`,
`src/crypto/mooring_handshake.zig:301`, `src/crypto/mooring_handshake.zig:303`,
`src/crypto/mooring_handshake.zig:304`, `src/crypto/mooring_handshake.zig:305`,
`src/crypto/mooring_handshake.zig:306`, `src/crypto/mooring_handshake.zig:307`,
`src/crypto/mooring_handshake.zig:308`, `src/crypto/mooring_handshake.zig:310`,
`src/crypto/mooring_handshake.zig:311`, `src/crypto/mooring_handshake.zig:312`,
`src/crypto/mooring_handshake.zig:313`).

Current-state note: `cfg.mesh_pass` is included in encrypted M1. When the
responder has configured MeshPass signer roots, those bytes must decode to a
signed MeshPass token whose signed node public key matches the authenticated M1
node key and whose capabilities include relay role plus the control/sync/irc_app
/mooring frame families. Without signer roots, the responder uses the same
encrypted bytes as the shared-secret fallback gate and returns
`MeshPassMismatch` on mismatch.

### M2

After validating M1, the responder encapsulates to the initiator's signed
prekey, computes an M2 secret from the first shared secret, the second shared
secret, M1, and the M2 prefix, and seals the M2 payload
(`src/crypto/mooring_handshake.zig:316`, `src/crypto/mooring_handshake.zig:320`,
`src/crypto/mooring_handshake.zig:321`, `src/crypto/mooring_handshake.zig:322`,
`src/crypto/mooring_handshake.zig:324`, `src/crypto/mooring_handshake.zig:328`,
`src/crypto/mooring_handshake.zig:330`). M2 payload contains responder node id,
responder Ed25519 key, accepted bands/features, time, two reserved zero u32
fields, and an Ed25519 signature over M1 + M2 prefix + payload
(`src/crypto/mooring_handshake.zig:345`, `src/crypto/mooring_handshake.zig:356`,
`src/crypto/mooring_handshake.zig:357`, `src/crypto/mooring_handshake.zig:358`,
`src/crypto/mooring_handshake.zig:359`, `src/crypto/mooring_handshake.zig:360`,
`src/crypto/mooring_handshake.zig:361`, `src/crypto/mooring_handshake.zig:362`,
`src/crypto/mooring_handshake.zig:363`, `src/crypto/mooring_handshake.zig:364`,
`src/crypto/mooring_handshake.zig:365`).

The initiator decapsulates M2 using its local prekey secret, opens M2, verifies
the responder node id/key, anti-downgrade bands/features, and M2 signature, then
derives `Established` (`src/crypto/mooring_handshake.zig:224`,
`src/crypto/mooring_handshake.zig:225`, `src/crypto/mooring_handshake.zig:228`,
`src/crypto/mooring_handshake.zig:229`, `src/crypto/mooring_handshake.zig:233`,
`src/crypto/mooring_handshake.zig:234`, `src/crypto/mooring_handshake.zig:235`,
`src/crypto/mooring_handshake.zig:236`, `src/crypto/mooring_handshake.zig:238`,
`src/crypto/mooring_handshake.zig:239`, `src/crypto/mooring_handshake.zig:240`,
`src/crypto/mooring_handshake.zig:241`, `src/crypto/mooring_handshake.zig:244`).

### Established keys

`Established` contains a root key, directional send/receive keys and nonces,
authenticated peer node id, authenticated peer Ed25519 public key, and accepted
bands/features (`src/crypto/mooring_handshake.zig:78`,
`src/crypto/mooring_handshake.zig:79`, `src/crypto/mooring_handshake.zig:80`,
`src/crypto/mooring_handshake.zig:81`, `src/crypto/mooring_handshake.zig:82`,
`src/crypto/mooring_handshake.zig:83`, `src/crypto/mooring_handshake.zig:84`,
`src/crypto/mooring_handshake.zig:85`, `src/crypto/mooring_handshake.zig:88`,
`src/crypto/mooring_handshake.zig:89`, `src/crypto/mooring_handshake.zig:90`).
The final handshake secret is BLAKE3 over domain `MZ-TSUMUGI-XWING-IK-v1`,
both X-Wing shared secrets, and the full M1/M2 wires, then HKDF-SHA256 derives:

| Derived field | HKDF label | Role mapping |
| --- | --- | --- |
| root | HKDF extract salt `"MZ root"` over the BLAKE3 handshake secret | same on both peers |
| c2s key | `"c2s aead key gen0"` | initiator send / responder recv |
| s2c key | `"s2c aead key gen0"` | responder send / initiator recv |
| c2s nonce | `"c2s nonce gen0"` | initiator send / responder recv |
| s2c nonce | `"s2c nonce gen0"` | responder send / initiator recv |

Evidence: `src/crypto/mooring_handshake.zig:418`,
`src/crypto/mooring_handshake.zig:421`, `src/crypto/mooring_handshake.zig:422`,
`src/crypto/mooring_handshake.zig:423`, `src/crypto/mooring_handshake.zig:424`,
`src/crypto/mooring_handshake.zig:425`, `src/crypto/mooring_handshake.zig:427`,
`src/crypto/mooring_handshake.zig:434`, `src/crypto/mooring_handshake.zig:435`,
`src/crypto/mooring_handshake.zig:436`, `src/crypto/mooring_handshake.zig:437`,
`src/crypto/mooring_handshake.zig:439`, `src/crypto/mooring_handshake.zig:440`,
`src/crypto/mooring_handshake.zig:441`.

Mooring's established key hygiene is source-backed: `Established.deinit` wipes
the root, send, and receive keys; `deriveEstablished` copies the derived raw
directional keys into `Secret(T)` wrappers and secure-zeroes the raw stack
arrays afterward; post-handshake record seal/open declassify directional keys
into local stack arrays with `defer secureZero(&key)` before using
ChaCha20-Poly1305. Nonces are directional bases plus per-record counters, so
each sealed/opened record uses a unique nonce for that direction
(`src/crypto/mooring_handshake.zig:104`, `src/crypto/mooring_handshake.zig:108`,
`src/crypto/mooring_handshake.zig:190`, `src/crypto/mooring_handshake.zig:207`,
`src/crypto/mooring_handshake.zig:566`, `src/crypto/mooring_handshake.zig:581`,
`src/crypto/mooring_session.zig:77`, `src/crypto/mooring_session.zig:83`).

`mooring_session.Session` stores the established state and bridges
`peer_node_id` to `node_short_id.shortId(peer)` for S2S routing
(`src/crypto/mooring_session.zig:1`, `src/crypto/mooring_session.zig:10`,
`src/crypto/mooring_session.zig:11`, `src/crypto/mooring_session.zig:14`,
`src/crypto/mooring_session.zig:95`, `src/crypto/mooring_session.zig:99`,
`src/crypto/mooring_session.zig:105`, `src/crypto/mooring_session.zig:111`,
`src/crypto/mooring_session.zig:112`, `src/crypto/mooring_session.zig:146`).

### Current S2S wiring boundary

`src/daemon/secured_s2s_link.zig` frames only the TOFU prekey preamble, M1, and
M2 with a u32 little-endian length. Once the AKE establishes, trailing and
future bytes enter a Mooring record layer: complete records are AEAD-opened with
the `Established` receive key and per-record counter AAD before plaintext reaches
the inner CRDT `S2sLink`; outbound inner bytes are sealed with the send key,
counter AAD, and a length-prefixed ciphertext+tag record
(`src/daemon/secured_s2s_link.zig:4`, `src/daemon/secured_s2s_link.zig:13`,
`src/daemon/secured_s2s_link.zig:43`, `src/daemon/secured_s2s_link.zig:66`,
`src/daemon/secured_s2s_link.zig:760`, `src/daemon/secured_s2s_link.zig:884`,
`src/daemon/secured_s2s_link.zig:911`, `src/daemon/secured_s2s_link.zig:916`,
`src/daemon/secured_s2s_link.zig:930`, `src/daemon/secured_s2s_link.zig:953`,
`src/daemon/secured_s2s_link.zig:954`). The inner link still owns semantic
`s2s_frame` parsing, so there is no semantic double-framing: Mooring secures the
byte stream, and `S2sLink` decodes the recovered frame stream.

The server enables secured S2S only when `node_identity` and `crypto_io` are
configured (`src/daemon/server.zig:2582`, `src/daemon/server.zig:2583`,
`src/daemon/server.zig:2584`). Incoming and outgoing peer setup choose
`SecuredLink` when that predicate is true (`src/daemon/server.zig:2346`,
`src/daemon/server.zig:2354`, `src/daemon/server.zig:2364`,
`src/daemon/server.zig:6327`, `src/daemon/server.zig:6330`,
`src/daemon/server.zig:6335`, `src/daemon/server.zig:6338`).

Inside the CRDT peer driver, secured links pass the node Ed25519 signing key into
`S2sPeer`, which advertises `frame_signing` and signs direct-owned state frames.
`mesh.require_signed_frames` defaults true: when this node has a signing key, a
remote peer that does not advertise signing is rejected during handshake, and
unsigned direct-owned state frames are dropped unless the operator explicitly
sets that key false for a mixed rollout. The same peer path now also
capability-gates signed Merkle repair frames (`REPAIR_SUMMARY`,
`REPAIR_REQUEST`, `REPAIR_RESPONSE`) and applies valid repair responses through
the CRDT repair substrate before requesting daemon resync
(`src/proto/s2s_frame.zig:151`, `src/proto/s2s_frame.zig:166`,
`src/proto/s2s_frame.zig:169`, `src/substrate/undertow/s2s_peer.zig:55`,
`src/substrate/undertow/s2s_peer.zig:67`,
`src/substrate/undertow/s2s_peer.zig:592`,
`src/substrate/undertow/s2s_peer.zig:696`,
`src/substrate/undertow/s2s_peer.zig:2118`,
`src/substrate/undertow/s2s_peer.zig:2134`,
`src/substrate/undertow/s2s_peer.zig:2146`).

## Armor TLS library and daemon use

Armor is the pure-Zig crypto and TLS surface in `src/crypto` and
`src/proto/tls_*`; the daemon wires it directly for client TLS, ACME HTTPS, and
secured S2S.

The same substrate backs a standalone `armor` toolkit executable
(`src/cli/armor_main.zig`) built as its own artifact by `build.zig`
(`build.zig:458`, `build.zig:459`, `build.zig:471`). It exposes openssl-parity
verbs — `x509`, `genpkey`, `pkey`, `req`, `dgst`, `verify`, `rand`, `ciphers`,
`asn1parse` — with deterministic scriptable exit codes (`0` ok, `1` failed,
`2` usage, `3` not implemented), and never shells out to OpenSSL: each verb
routes through the Zig crypto modules above (`src/cli/root.zig`,
`src/cli/armor_main.zig:4`). `s_client`/`s_server`/`enc`/`ocsp`/`crl` are
declared but return exit `3` (not yet implemented). The CLI has its own test
step, `zig build test-cli` (`build.zig:478`).

### TLS server

| Topic | Current behavior | Source |
| --- | --- | --- |
| Listener type | Separate implicit-TLS client listener; no STARTTLS. | `src/main.zig:213`, `src/main.zig:216`, `src/daemon/server.zig:1037`, `src/daemon/server.zig:1038` |
| Certificate material | Loads PEM/DER leaf-first chains and Ed25519, ECDSA-P256, or RSA private keys when cert/key paths are set. If enabled without paths, bootstraps a self-signed Ed25519 leaf for TLS 1.3; the hardened TLS 1.2 bootstrap mints an ECDSA-P256 leaf. | `src/daemon/tls_certs.zig:4`, `src/daemon/tls_certs.zig:20`, `src/daemon/tls_certs.zig:85`, `src/daemon/tls_certs.zig:119`, `src/daemon/tls_certs.zig:121`, `src/daemon/tls_certs.zig:157`, `src/daemon/tls_certs.zig:160`, `src/daemon/tls_certs.zig:209`, `src/daemon/tls_certs.zig:240`, `src/daemon/tls_certs.zig:283`, `src/daemon/tls_certs.zig:286`, `src/daemon/tls_certs.zig:320`, `src/daemon/tls_certs.zig:323`, `src/daemon/tls_certs.zig:357` |
| Server state machine | Socketless TLS 1.3 server state machine; `TlsConn` can route a first ClientHello to either TLS 1.3 or the optional hardened TLS 1.2 server. | `src/crypto/tls_server.zig:1`, `src/crypto/tls_server.zig:4`, `src/daemon/tls_conn.zig:82`, `src/daemon/tls_conn.zig:97` |
| Key exchange | TLS 1.3 accepts X25519, secp256r1, and X25519MLKEM768 shares; if no usable share exists but a supported group was advertised, it sends HelloRetryRequest before failing. Selection prefers X25519, then secp256r1, then X25519MLKEM768. | `src/crypto/tls_server.zig:1471`, `src/crypto/tls_server.zig:1499`, `src/crypto/tls_server.zig:1594`, `src/crypto/tls_server.zig:1605`, `src/crypto/tls_server.zig:1662`, `src/crypto/tls_server.zig:1711` |
| HelloRetryRequest hardening | Only one HRR is ever issued (`hrr_sent` guard). The second ClientHello is pinned to the HRR commitments (RFC 8446 §4.1.2/§4.1.4): the cipher suite must equal the `hrr_suite` stamped when the HRR was sent, the `key_share` must supply exactly the requested `hrr_group` (shares for any other group are dropped, and no remaining share is fatal), and a peer that keeps `early_data` after HRR is rejected — 0-RTT is not permitted after a retry. | `src/crypto/tls_server.zig:481`, `src/crypto/tls_server.zig:486`, `src/crypto/tls_server.zig:1331`, `src/crypto/tls_server.zig:1332`, `src/crypto/tls_server.zig:1665`, `src/crypto/tls_server.zig:1672`, `src/crypto/tls_server.zig:1675`, `src/crypto/tls_server.zig:1690` |
| 0-RTT early data | Opt-in via `[tls] early_data_max_size` (default 0 = off); wired end-to-end through `TlsConn`. Accepting 0-RTT requires a non-zero limit AND a binder not seen before (single-process replay ring) AND a reported ticket age inside the RFC 8446 §8.2–8.3 freshness window: the server un-obfuscates the client's `obfuscated_ticket_age` with the `ticket_age_add` sealed into its v3 ticket and rejects any skew beyond `early_data_age_skew_ms` (default 10 s). Legacy v1/v2 tickets carry no `age_add` and degrade to the binder-ring-only check. HRR forecloses early data entirely. | `src/crypto/tls_server.zig:174`, `src/crypto/tls_server.zig:186`, `src/crypto/tls_server.zig:196`, `src/crypto/tls_server.zig:1700`, `src/crypto/tls_server.zig:1801`, `src/crypto/tls_server.zig:1843`, `src/crypto/tls_server.zig:1859`, `src/crypto/tls_server.zig:2511`, `src/crypto/tls_resumption.zig:25`, `src/crypto/tls_resumption.zig:48`, `src/daemon/config_format.zig:686`, `src/main.zig:699` |
| ECH (Encrypted Client Hello) | draft-ietf-tls-esni. When ECH keys are configured, a `ClientHelloOuter` we cannot open latches `ech_offered`; on ECH-not-accepted the server returns the published `ECHConfigList` as `retry_configs` in EncryptedExtensions so the client can refresh its config, but ONLY in response to an offered-and-unaccepted ECH — a plain non-ECH client never draws an unsolicited `retry_configs` (the wire stays byte-identical). ECH acceptance is signaled only on the ServerHello of a single-round handshake. | `src/crypto/tls_server.zig:240`, `src/crypto/tls_server.zig:249`, `src/crypto/tls_server.zig:613`, `src/crypto/tls_server.zig:620`, `src/crypto/tls_server.zig:1415`, `src/crypto/tls_server.zig:1498`, `src/crypto/tls_server.zig:2018` |
| TLS 1.3 PQ hybrid | X25519MLKEM768 client share is `ml-kem_ek || x25519_pk`; the server encapsulates ML-KEM-768, does X25519 ECDH, emits `ml-kem_ct || x25519_pk`, and feeds the raw concatenation `mlkem_ss || x25519_ss` to the TLS key schedule. | `src/crypto/tls_server.zig:1662`, `src/crypto/tls_server.zig:1663`, `src/crypto/tls_server.zig:1682`, `src/crypto/tls_server.zig:1711` |
| CertificateVerify | Server signs `CertificateVerify` with the active Ed25519, ECDSA-P256, RSA-PSS, or delegated-credential key. | `src/crypto/tls_server.zig:119`, `src/crypto/tls_server.zig:135`, `src/crypto/tls_server.zig:2127`, `src/crypto/tls_server.zig:2173` |
| Hardened TLS 1.2 | Optional fallback is TLS 1.2 only, secp256r1 ECDHE, ECDSA-P256/RSA authentication, null compression, and AEAD suites; RSA key exchange, CBC/RC4/export/NULL suites, TLS 1.0/1.1, compression, and renegotiation are outside policy. | `src/crypto/tls12_server.zig:4`, `src/crypto/tls12_server.zig:10`, `src/crypto/tls12_server.zig:508`, `src/crypto/tls12_server.zig:528`, `src/crypto/tls12_server.zig:538`, `src/crypto/tls12_server.zig:646`, `src/crypto/tls.zig:173`, `src/crypto/tls.zig:207`, `src/crypto/tls.zig:724`, `src/crypto/tls.zig:749` |
| TLS 1.2 Extended Master Secret | RFC 7627 EMS is REQUIRED by default on both the TLS 1.2 server and client (`require_extended_master_secret = true`): a ServerHello that fails to echo the (empty) `extended_master_secret` extension aborts with `EmsRequired`, and the master secret derives from the session hash rather than the raw randoms. The policy flag can be relaxed only for legacy interop; even then EMS is still negotiated and used whenever the peer offers it, and resumption tickets carry an `EM12` tag so resumed sessions prove the original handshake was EMS. | `src/crypto/tls12_server.zig:65`, `src/crypto/tls12_server.zig:98`, `src/crypto/tls12_server.zig:103`, `src/crypto/tls12_server.zig:199`, `src/crypto/tls12_client.zig:70`, `src/crypto/tls12_client.zig:89`, `src/crypto/tls12_client.zig:94`, `src/crypto/tls12.zig:297`, `src/crypto/tls12.zig:308` |
| mTLS | Optional `CertificateRequest` advertises Ed25519, ECDSA-P256, and RSA-PSS client cert signatures. Possession proof failure clears the captured client cert, but CertFP pinning does not require CA chain validation. | `src/crypto/tls_server.zig:486`, `src/crypto/tls_server.zig:497`, `src/crypto/tls_server.zig:1018`, `src/crypto/tls_server.zig:1052`, `src/crypto/tls_server.zig:1915`, `src/crypto/tls_server.zig:1945`, `src/crypto/tls_server.zig:2668`, `src/crypto/tls_server.zig:2674` |
| CertFP | After TLS handshake, the daemon computes SHA-256 CertFP from the verified client leaf DER for SASL EXTERNAL. | `src/daemon/tls_conn.zig:246`, `src/daemon/tls_conn.zig:255`, `src/daemon/server.zig:7937`, `src/daemon/server.zig:7942` |
| STS | Advertised only when `[sts]` is enabled and a TLS listener is live. | `src/main.zig:239`, `src/main.zig:241`, `src/main.zig:244`, `src/main.zig:245`, `src/main.zig:251`, `src/main.zig:258` |

`src/daemon/tls_conn.zig` is the per-connection adapter that frames records
before feeding the socketless TLS server. It buffers partial records, returns
handshake flight ciphertext, exposes decrypted plaintext after handshake, and
encrypts outbound application bytes (`src/daemon/tls_conn.zig:267`,
`src/daemon/tls_conn.zig:313`, `src/daemon/tls_conn.zig:382`,
`src/daemon/tls_conn.zig:398`, `src/daemon/tls_conn.zig:408`,
`src/daemon/tls_conn.zig:445`).
`LinuxServer` creates the TLS listener only when it has a cert chain and signing
key, instantiates `TlsConn` per accepted TLS connection, and routes decrypted
bytes into the normal IRC parser (`src/daemon/server.zig:3252`,
`src/daemon/server.zig:3257`, `src/daemon/server.zig:3304`,
`src/daemon/server.zig:3314`, `src/daemon/server.zig:6030`,
`src/daemon/server.zig:6058`, `src/daemon/server.zig:7918`,
`src/daemon/server.zig:7944`).

TLS record handling keeps nonce and sequence uniqueness explicit. TLS 1.3
derives each record nonce as `write_iv XOR (0^4 || seq)` and rejects malformed
record headers, wrong outer content types, overflow, bad inner content types,
and surplus/truncated ciphertext before returning plaintext. TLS 1.2 refuses
sequence exhaustion, binds the sequence number into AEAD AAD, takes AES-GCM
explicit nonces from the wire while keeping sequence-bound AAD, and uses
sequence-derived ChaCha20-Poly1305 nonces (`src/crypto/tls_record.zig:176`,
`src/crypto/tls_record.zig:185`, `src/crypto/tls_record.zig:196`,
`src/crypto/tls_record.zig:207`, `src/crypto/tls_record.zig:233`,
`src/crypto/tls_record.zig:313`, `src/crypto/tls12.zig:376`,
`src/crypto/tls12.zig:486`).

TLS 1.3 HKDF helpers implement RFC 8446 HKDF-Expand-Label, derive early,
handshake, master, traffic, exporter, and Finished secrets over typed
`Secret(T)` material. The generic AEAD layer exposes fixed-size key/nonce/tag
types, maps auth failure to an explicit error, and provides counter nonces that
refuse to wrap before reuse (`src/crypto/hkdf_tls13.zig:4`,
`src/crypto/hkdf_tls13.zig:9`, `src/crypto/hkdf_tls13.zig:67`,
`src/crypto/hkdf_tls13.zig:208`, `src/crypto/aead.zig:4`,
`src/crypto/aead.zig:19`, `src/crypto/aead.zig:24`,
`src/crypto/aead.zig:42`, `src/crypto/aead.zig:66`,
`src/crypto/aead.zig:119`, `src/crypto/aead.zig:130`,
`src/crypto/aead.zig:213`).

Linux kTLS support is TLS 1.3-only in the daemon adapter. `ktls.zig` encodes
kernel `crypto_info` for AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305,
probes the TLS ULP, and attaches TX/RX via `setsockopt`. `TlsConn` only exports
kTLS state for completed TLS 1.3 sessions; TLS 1.2 returns
`KtlsUnsupportedEngine`, and RX KeyUpdate re-installs the kernel RX key or
closes fail-safe on error (`src/daemon/ktls.zig:37`,
`src/daemon/ktls.zig:59`, `src/daemon/ktls.zig:71`,
`src/daemon/ktls.zig:112`, `src/daemon/ktls.zig:144`,
`src/daemon/ktls.zig:198`, `src/daemon/ktls.zig:220`,
`src/daemon/ktls.zig:247`, `src/daemon/ktls.zig:261`,
`src/daemon/ktls.zig:295`, `src/daemon/tls_conn.zig:122`,
`src/daemon/tls_conn.zig:158`, `src/daemon/tls_conn.zig:161`,
`src/daemon/tls_conn.zig:209`).

### X.509, OCSP, SCT, and CRL parsing

Armor's X.509/DER reader is deliberately minimal and fail-closed: it refuses
empty, oversized, over-depth, truncated, trailing, non-canonical, indefinite,
unsupported, or structurally invalid DER before higher layers consume
certificate fields. Extension parsing requires each extension to be a DER
sequence with OID, optional boolean, OCTET STRING value, and no trailing bytes;
AIA OCSP and TLS Feature must-staple are parsed from those strict extension
values (`src/crypto/x509.zig:4`, `src/crypto/x509.zig:8`,
`src/crypto/x509.zig:20`, `src/crypto/x509.zig:49`,
`src/crypto/x509.zig:123`, `src/crypto/x509.zig:201`,
`src/crypto/x509.zig:947`, `src/crypto/x509.zig:1019`).

OCSP staples parse and verify fail-closed at the security boundary: a servable
staple must parse as successful, verify directly or through an authorized
delegated responder, match the requested serial with status `good`, carry
`nextUpdate`, and be within freshness bounds. OCSP-delivered SCTs are accepted
as the third CT source by mining the SCT extension from `SingleResponse`
extensions; malformed SCT extension DER returns a typed error rather than
falling through (`src/crypto/ocsp.zig:132`, `src/crypto/ocsp.zig:172`,
`src/crypto/ocsp.zig:197`, `src/crypto/ocsp.zig:224`,
`src/crypto/ocsp.zig:232`, `src/crypto/ocsp.zig:267`,
`src/crypto/ocsp.zig:901`, `src/crypto/ocsp.zig:927`,
`src/crypto/sct.zig:267`, `src/crypto/sct.zig:331`,
`src/crypto/sct.zig:671`, `src/crypto/sct.zig:740`).

CRL parsing is strict and allocation-free, but the documented default policy is
soft-fail for unreachable or unauthenticated CRL fetches. A definitive revoked
serial from an authenticated, current CRL is fail-closed, and a CRL signature
that does not verify under the issuing CA is discarded and never trusted
(`src/crypto/crl.zig:4`, `src/crypto/crl.zig:36`, `src/crypto/crl.zig:92`,
`src/crypto/crl.zig:130`, `src/crypto/crl.zig:175`,
`src/crypto/crl.zig:208`, `src/crypto/crl.zig:279`,
`src/crypto/crl.zig:304`).

### TLS client and protocol codecs

`src/crypto/tls_client.zig` is a socketless TLS 1.3 client used by ACME/HTTPS
code. It offers TLS 1.3, SNI, X25519MLKEM768, X25519, and P-256 shares, and
signature algorithms including RSA-PSS, ECDSA P-256/P-384, Ed25519, and
RSA-PKCS1-SHA256 (`src/crypto/tls_client.zig:1`,
`src/crypto/tls_client.zig:4`, `src/crypto/tls_client.zig:945`,
`src/crypto/tls_client.zig:957`, `src/crypto/tls_client.zig:1249`,
`src/crypto/tls_client.zig:1275`, `src/crypto/tls_client.zig:1489`,
`src/crypto/tls_client.zig:1501`, `src/crypto/tls_client.zig:1509`,
`src/crypto/tls_client.zig:1546`). The live
ACME runner uses this client for HTTPS and explicitly states that it does not
shell out to external TLS or certificate-management tools (`src/daemon/acme_runner.zig:1`,
`src/daemon/acme_runner.zig:9`, `src/daemon/acme_runner.zig:10`,
`src/daemon/acme_runner.zig:11`, `src/daemon/acme_runner.zig:121`,
`src/daemon/acme_runner.zig:124`).

The `src/proto/tls_*` files are pure codecs and helpers around TLS 1.3
structures. Examples:

| Codec | Role | Source |
| --- | --- | --- |
| `tls_extension.zig` | Zero-allocation extension-list envelope codec; contents parsed by sibling modules. | `src/proto/tls_extension.zig:1`, `src/proto/tls_extension.zig:3`, `src/proto/tls_extension.zig:9`, `src/proto/tls_extension.zig:14` |
| `tls_keyshare.zig` | TLS 1.3 key_share inner codec. Defines X25519, secp256r1, and X25519MLKEM768 group ids; the TLS server selects classical X25519/secp256r1 when offered, or the X25519MLKEM768 PQ hybrid when only that usable share is available. | `src/proto/tls_keyshare.zig:41`, `src/proto/tls_keyshare.zig:49`, `src/crypto/tls_server.zig:1471`, `src/crypto/tls_server.zig:1499`, `src/crypto/tls_server.zig:1662`, `src/crypto/tls_server.zig:1711` |
| `tls_signature_scheme.zig` | SignatureAlgorithms codec including Ed25519, ECDSA P-256/P-384, RSA-PSS, and RSA-PKCS1-SHA256. | `src/proto/tls_signature_scheme.zig:29`, `src/proto/tls_signature_scheme.zig:44` |
| `tls_finished.zig` | TLS 1.3 Finished MAC using HKDF-Expand-Label and HMAC over transcript hash. | `src/proto/tls_finished.zig:1`, `src/proto/tls_finished.zig:4`, `src/proto/tls_finished.zig:6`, `src/proto/tls_finished.zig:7`, `src/proto/tls_finished.zig:10`, `src/proto/tls_finished.zig:13` |
| `tls_key_update.zig` | KeyUpdate codec plus `"traffic upd"` application-secret ratchet helper. | `src/proto/tls_key_update.zig:1`, `src/proto/tls_key_update.zig:4`, `src/proto/tls_key_update.zig:5`, `src/proto/tls_key_update.zig:10`, `src/proto/tls_key_update.zig:91` |
| `tls_session_ticket.zig` / `tls_psk.zig` | NewSessionTicket and PSK extension codecs. Resumption and 0-RTT ARE now wired into daemon policy — the sealed-ticket format and the freshness/replay checks live in `tls_resumption.zig` and `tls_server.zig`, gated by `[tls] early_data_max_size` (see the "0-RTT early data" row above). | `src/proto/tls_session_ticket.zig:1`, `src/proto/tls_session_ticket.zig:3`, `src/proto/tls_psk.zig:1`, `src/proto/tls_psk.zig:3`, `src/crypto/tls_resumption.zig:25` |

## MeshPass admission and capability envelope

Two similarly named surfaces share the MeshPass name:

1. `mooring_handshake.Config.mesh_pass`: bytes inserted into encrypted M1 with a
   length cap. With configured signer roots these bytes are a signed MeshPass
   admission token; otherwise they are the shared-secret fallback.
2. `src/proto/meshpass.zig`: a signed admission/capability token format.

The `meshpass.zig` token is the actual MeshPass admission/capability envelope.
Its signed payload is a fixed-order CoilPack schema; Ed25519 signs and verifies
the canonical bytes (`src/proto/meshpass.zig:1`, `src/proto/meshpass.zig:3`,
`src/proto/meshpass.zig:4`, `src/proto/meshpass.zig:5`). Fields include node
public key, realm, role bitset, issue/expiry times, allowed frame families,
max fanout, media rights, and revocation epoch (`src/proto/meshpass.zig:53`,
`src/proto/meshpass.zig:54`, `src/proto/meshpass.zig:55`,
`src/proto/meshpass.zig:56`, `src/proto/meshpass.zig:57`,
`src/proto/meshpass.zig:58`, `src/proto/meshpass.zig:59`,
`src/proto/meshpass.zig:60`, `src/proto/meshpass.zig:61`,
`src/proto/meshpass.zig:62`). Role/family/right helpers build bitsets from
comptime enum lists (`src/proto/meshpass.zig:108`,
`src/proto/meshpass.zig:117`, `src/proto/meshpass.zig:126`).

| Operation | Behavior | Source |
| --- | --- | --- |
| Issue | Validates fields, encodes signed fields into canonical CoilPack, signs with issuer Ed25519 key. | `src/proto/meshpass.zig:135`, `src/proto/meshpass.zig:136`, `src/proto/meshpass.zig:137`, `src/proto/meshpass.zig:139`, `src/proto/meshpass.zig:140`, `src/proto/meshpass.zig:141` |
| Verify | Re-encodes fields, verifies Ed25519 signature, checks realm, revocation epoch, and expiry. | `src/proto/meshpass.zig:149`, `src/proto/meshpass.zig:153`, `src/proto/meshpass.zig:154`, `src/proto/meshpass.zig:157`, `src/proto/meshpass.zig:159`, `src/proto/meshpass.zig:161`, `src/proto/meshpass.zig:162`, `src/proto/meshpass.zig:163` |
| Encode token | Writes token schema id, token field bitmap, signed payload bytes, and signature. | `src/proto/meshpass.zig:186`, `src/proto/meshpass.zig:191`, `src/proto/meshpass.zig:192`, `src/proto/meshpass.zig:193`, `src/proto/meshpass.zig:194`, `src/proto/meshpass.zig:195` |
| Decode token | Parses schema/bitmap, extracts signed payload and signature, rejects trailing bytes. | `src/proto/meshpass.zig:199`, `src/proto/meshpass.zig:201`, `src/proto/meshpass.zig:202`, `src/proto/meshpass.zig:203`, `src/proto/meshpass.zig:205`, `src/proto/meshpass.zig:206`, `src/proto/meshpass.zig:207`, `src/proto/meshpass.zig:211` |
| Capability checks | Helpers test role, frame family, fanout, and media rights. | `src/proto/meshpass.zig:166`, `src/proto/meshpass.zig:171`, `src/proto/meshpass.zig:176`, `src/proto/meshpass.zig:181` |

The format is convergent in the sense that the same logical fields encode to
the same canonical bytes, making signatures stable across honest nodes. That
comes from fixed field order and CoilPack canonical equality, not from a
separate consensus protocol (`src/proto/meshpass.zig:216`,
`src/proto/meshpass.zig:220`, `src/proto/meshpass.zig:221`,
`src/proto/meshpass.zig:223`, `src/proto/meshpass.zig:231`,
`src/proto/coilpack.zig:25`, `src/proto/coilpack.zig:26`,
`src/proto/coilpack.zig:29`).

## Oper credential signing

`src/proto/oper_cred_share.zig` implements cross-mesh operator authorization
grants. Passwords never cross the mesh; a home node signs an expiring grant
after local authentication, and peers verify the grant using the issuer's
Ed25519 public key (`src/proto/oper_cred_share.zig:1`,
`src/proto/oper_cred_share.zig:3`, `src/proto/oper_cred_share.zig:4`,
`src/proto/oper_cred_share.zig:6`, `src/proto/oper_cred_share.zig:7`,
`src/proto/oper_cred_share.zig:8`). The grant carries account, privilege bits,
oper class, title, issuer node, incarnation, issued time, and expiry time
(`src/proto/oper_cred_share.zig:43`, `src/proto/oper_cred_share.zig:45`,
`src/proto/oper_cred_share.zig:47`, `src/proto/oper_cred_share.zig:49`,
`src/proto/oper_cred_share.zig:51`, `src/proto/oper_cred_share.zig:53`,
`src/proto/oper_cred_share.zig:55`, `src/proto/oper_cred_share.zig:57`,
`src/proto/oper_cred_share.zig:59`).

The canonical encoding is fixed-order, length-prefixed, big-endian for numeric
fields, and bounded to 255 bytes per variable-length field
(`src/proto/oper_cred_share.zig:10`, `src/proto/oper_cred_share.zig:11`,
`src/proto/oper_cred_share.zig:29`, `src/proto/oper_cred_share.zig:31`,
`src/proto/oper_cred_share.zig:100`, `src/proto/oper_cred_share.zig:106`,
`src/proto/oper_cred_share.zig:112`, `src/proto/oper_cred_share.zig:113`,
`src/proto/oper_cred_share.zig:166`, `src/proto/oper_cred_share.zig:170`,
`src/proto/oper_cred_share.zig:178`). `sign` appends a 64-byte Ed25519
signature to the canonical signed region; `verify` parses structure first,
then verifies Ed25519 and freshness (`src/proto/oper_cred_share.zig:213`,
`src/proto/oper_cred_share.zig:217`, `src/proto/oper_cred_share.zig:218`,
`src/proto/oper_cred_share.zig:221`, `src/proto/oper_cred_share.zig:224`,
`src/proto/oper_cred_share.zig:228`, `src/proto/oper_cred_share.zig:231`,
`src/proto/oper_cred_share.zig:234`, `src/proto/oper_cred_share.zig:239`,
`src/proto/oper_cred_share.zig:241`, `src/proto/oper_cred_share.zig:242`,
`src/proto/oper_cred_share.zig:244`).

On secured S2S links, inbound grant payloads are verified against
`peerNodeKey()`, the authenticated Ed25519 key learned from Mooring, before they
can confer operator authority (`src/daemon/secured_s2s_link.zig:127`,
`src/daemon/secured_s2s_link.zig:129`, `src/daemon/secured_s2s_link.zig:167`,
`src/daemon/secured_s2s_link.zig:176`, `src/daemon/server.zig:2650`,
`src/daemon/server.zig:2651`, `src/daemon/server.zig:2654`,
`src/daemon/server.zig:2657`).

## Session reclaim sealing

`src/proto/session_reclaim_mesh.zig` implements portable session reclaim tokens
that any mesh node with the shared mesh key can verify
(`src/proto/session_reclaim_mesh.zig:1`, `src/proto/session_reclaim_mesh.zig:3`,
`src/proto/session_reclaim_mesh.zig:4`, `src/proto/session_reclaim_mesh.zig:5`,
`src/proto/session_reclaim_mesh.zig:10`). The token body is magic `SRM\x01`,
three u16-length-prefixed byte strings (`account`, `session_id`,
`origin_node`), three big-endian u64s (`issued_ms`, `expiry_ms`, `nonce`), and a
trailing HMAC-SHA256 tag (`src/proto/session_reclaim_mesh.zig:29`,
`src/proto/session_reclaim_mesh.zig:31`, `src/proto/session_reclaim_mesh.zig:33`,
`src/proto/session_reclaim_mesh.zig:36`, `src/proto/session_reclaim_mesh.zig:39`,
`src/proto/session_reclaim_mesh.zig:41`, `src/proto/session_reclaim_mesh.zig:43`,
`src/proto/session_reclaim_mesh.zig:45`, `src/proto/session_reclaim_mesh.zig:47`,
`src/proto/session_reclaim_mesh.zig:49`).

`seal` serializes deterministically and appends HMAC-SHA256 over the body
(`src/proto/session_reclaim_mesh.zig:111`,
`src/proto/session_reclaim_mesh.zig:114`, `src/proto/session_reclaim_mesh.zig:119`,
`src/proto/session_reclaim_mesh.zig:122`, `src/proto/session_reclaim_mesh.zig:127`,
`src/proto/session_reclaim_mesh.zig:131`, `src/proto/session_reclaim_mesh.zig:132`).
`open` checks minimum size and magic, parses the body, rejects body trailing
garbage, recomputes HMAC-SHA256, compares the tag with
`std.crypto.timing_safe.eql`, and rejects expired tokens
(`src/proto/session_reclaim_mesh.zig:170`,
`src/proto/session_reclaim_mesh.zig:172`, `src/proto/session_reclaim_mesh.zig:174`,
`src/proto/session_reclaim_mesh.zig:176`, `src/proto/session_reclaim_mesh.zig:179`,
`src/proto/session_reclaim_mesh.zig:182`, `src/proto/session_reclaim_mesh.zig:188`,
`src/proto/session_reclaim_mesh.zig:192`, `src/proto/session_reclaim_mesh.zig:195`,
`src/proto/session_reclaim_mesh.zig:196`, `src/proto/session_reclaim_mesh.zig:200`).

Replay protection is caller-owned and bounded: `ReplayRing(capacity)` stores
recent nonces in a fixed-size ring, returns true for repeats, and otherwise
records/evicts (`src/proto/session_reclaim_mesh.zig:236`,
`src/proto/session_reclaim_mesh.zig:237`, `src/proto/session_reclaim_mesh.zig:238`,
`src/proto/session_reclaim_mesh.zig:239`, `src/proto/session_reclaim_mesh.zig:244`,
`src/proto/session_reclaim_mesh.zig:251`, `src/proto/session_reclaim_mesh.zig:254`,
`src/proto/session_reclaim_mesh.zig:256`, `src/proto/session_reclaim_mesh.zig:258`).

## Secure channel and group key material

Current source has several secure-channel building blocks. They are distinct
from the live `secured_s2s_link` behavior described above.

### crypto/secure_channel.zig

`secure_channel.zig` composes two surfaces:

| Surface | Behavior | Source |
| --- | --- | --- |
| 1:1 channel | HPKE bootstraps a shared root; a Signal-style double ratchet provides per-frame AEAD. | `src/crypto/secure_channel.zig:1`, `src/crypto/secure_channel.zig:4`, `src/crypto/secure_channel.zig:5`, `src/crypto/secure_channel.zig:61`, `src/crypto/secure_channel.zig:66`, `src/crypto/secure_channel.zig:76`, `src/crypto/secure_channel.zig:77`, `src/crypto/secure_channel.zig:78`, `src/crypto/secure_channel.zig:83`, `src/crypto/secure_channel.zig:91`, `src/crypto/secure_channel.zig:93` |
| Group channel | TreeKEM derives a group root; add/remove/update rekeys. | `src/crypto/secure_channel.zig:7`, `src/crypto/secure_channel.zig:113`, `src/crypto/secure_channel.zig:114`, `src/crypto/secure_channel.zig:118`, `src/crypto/secure_channel.zig:127`, `src/crypto/secure_channel.zig:131`, `src/crypto/secure_channel.zig:135`, `src/crypto/secure_channel.zig:139` |

The module comments state that live wiring onto S2S waits on Mooring identity and
that the module is transport-agnostic (`src/crypto/secure_channel.zig:10`,
`src/crypto/secure_channel.zig:11`, `src/crypto/secure_channel.zig:12`,
`src/crypto/secure_channel.zig:13`). Therefore, document it as available crypto
building block material, not as the current S2S stream encryption layer.

The underlying `ratchet.zig` derives root/chain keys with HKDF-SHA256, uses
ChaCha20-Poly1305 per message, binds associated data plus encoded header into
AEAD AAD, and maintains a bounded skipped-key window
(`src/crypto/ratchet.zig:1`, `src/crypto/ratchet.zig:4`,
`src/crypto/ratchet.zig:5`, `src/crypto/ratchet.zig:6`,
`src/crypto/ratchet.zig:30`, `src/crypto/ratchet.zig:32`,
`src/crypto/ratchet.zig:47`, `src/crypto/ratchet.zig:49`,
`src/crypto/ratchet.zig:148`, `src/crypto/ratchet.zig:155`,
`src/crypto/ratchet.zig:163`, `src/crypto/ratchet.zig:165`,
`src/crypto/ratchet.zig:224`, `src/crypto/ratchet.zig:226`,
`src/crypto/ratchet.zig:236`, `src/crypto/ratchet.zig:307`,
`src/crypto/ratchet.zig:311`).

### HPKE

HPKE base mode uses X25519 DH, labeled HKDF-SHA256, ChaCha20-Poly1305, sequence
number nonces, and rejects message limit exhaustion
(`src/crypto/hpke.zig:1`, `src/crypto/hpke.zig:5`, `src/crypto/hpke.zig:6`,
`src/crypto/hpke.zig:37`, `src/crypto/hpke.zig:39`,
`src/crypto/hpke.zig:101`, `src/crypto/hpke.zig:111`,
`src/crypto/hpke.zig:127`, `src/crypto/hpke.zig:199`,
`src/crypto/hpke.zig:215`, `src/crypto/hpke.zig:216`,
`src/crypto/hpke.zig:217`, `src/crypto/hpke.zig:245`,
`src/crypto/hpke.zig:251`, `src/crypto/hpke.zig:254`,
`src/crypto/hpke.zig:282`, `src/crypto/hpke.zig:283`,
`src/crypto/hpke.zig:337`, `src/crypto/hpke.zig:348`).

### TreeKEM

TreeKEM's `Group` creates members from deterministic X25519 seeds, derives the
root over a left-balanced tree, and emits commits containing roster, per-member
envelopes, and tree hash (`src/crypto/treekem.zig:187`,
`src/crypto/treekem.zig:194`, `src/crypto/treekem.zig:195`,
`src/crypto/treekem.zig:196`, `src/crypto/treekem.zig:201`,
`src/crypto/treekem.zig:208`, `src/crypto/treekem.zig:276`,
`src/crypto/treekem.zig:284`, `src/crypto/treekem.zig:287`,
`src/crypto/treekem.zig:298`, `src/crypto/treekem.zig:305`). Update, add, and
remove all increment the epoch, change membership or member keys, derive a new
root, and produce a commit (`src/crypto/treekem.zig:238`,
`src/crypto/treekem.zig:240`, `src/crypto/treekem.zig:243`,
`src/crypto/treekem.zig:247`, `src/crypto/treekem.zig:251`,
`src/crypto/treekem.zig:257`, `src/crypto/treekem.zig:261`,
`src/crypto/treekem.zig:265`, `src/crypto/treekem.zig:268`,
`src/crypto/treekem.zig:272`). Root envelopes are X25519/HKDF masks over the
root secret, and omitted members cannot decrypt a commit that has no envelope
for them (`src/crypto/treekem.zig:376`, `src/crypto/treekem.zig:384`,
`src/crypto/treekem.zig:385`, `src/crypto/treekem.zig:388`,
`src/crypto/treekem.zig:392`, `src/crypto/treekem.zig:396`,
`src/crypto/treekem.zig:401`, `src/crypto/treekem.zig:405`,
`src/crypto/treekem.zig:421`).

### proto/mooring.zig frame ratchet

`src/proto/mooring.zig` is a symmetric ratchet for post-kx UNDERTOW frames. It
does not perform X25519, ML-KEM, or identity work; it expects an authenticated
hybrid root secret from a lower layer (`src/proto/mooring.zig:1`,
`src/proto/mooring.zig:3`, `src/proto/mooring.zig:4`,
`src/proto/mooring.zig:5`). It splits that root into initiator/responder
send/receive chains with HKDF labels, encrypts frames with ChaCha20-Poly1305,
tracks replay/too-far-ahead state, and emits rekey signals by frame interval,
epoch, or counter exhaustion (`src/proto/mooring.zig:19`,
`src/proto/mooring.zig:21`, `src/proto/mooring.zig:22`,
`src/proto/mooring.zig:23`, `src/proto/mooring.zig:92`,
`src/proto/mooring.zig:109`, `src/proto/mooring.zig:126`,
`src/proto/mooring.zig:127`, `src/proto/mooring.zig:129`,
`src/proto/mooring.zig:136`, `src/proto/mooring.zig:179`,
`src/proto/mooring.zig:341`, `src/proto/mooring.zig:345`,
`src/proto/mooring.zig:346`, `src/proto/mooring.zig:347`,
`src/proto/mooring.zig:358`, `src/proto/mooring.zig:359`,
`src/proto/mooring.zig:367`, `src/proto/mooring.zig:377`,
`src/proto/mooring.zig:381`). Its tests verify that AEAD AAD binds frame kind,
generation, counter, and outer header (`src/proto/mooring.zig:731`,
`src/proto/mooring.zig:741`, `src/proto/mooring.zig:742`,
`src/proto/mooring.zig:744`, `src/proto/mooring.zig:750`,
`src/proto/mooring.zig:753`).

`frame.zig` reserves Mooring frame types for handshake, handshake response,
ratchet, and group key; the Mooring band is treated as control priority and
does not debit credit (`src/proto/frame.zig:131`, `src/proto/frame.zig:132`,
`src/proto/frame.zig:133`, `src/proto/frame.zig:134`,
`src/proto/frame.zig:220`, `src/proto/frame.zig:227`,
`src/proto/frame.zig:355`, `src/proto/frame.zig:360`,
`src/proto/frame.zig:363`, `src/proto/frame.zig:365`).

## CoilPack canonical signing

CoilPack has two layers:

| Layer | Purpose | Source |
| --- | --- | --- |
| `coilpack.zig` | Low-level atoms: little-endian fixed integers, minimal unsigned LEB128 varints, length-prefixed byte strings, booleans, and the fixed UNDERTOW header. Decoders reject non-minimal varints; canonical equality is byte equality. | `src/proto/coilpack.zig:1`, `src/proto/coilpack.zig:3`, `src/proto/coilpack.zig:5`, `src/proto/coilpack.zig:25`, `src/proto/coilpack.zig:26`, `src/proto/coilpack.zig:29`, `src/proto/coilpack.zig:106`, `src/proto/coilpack.zig:126`, `src/proto/coilpack.zig:127`, `src/proto/coilpack.zig:237`, `src/proto/coilpack.zig:253` |
| `coilpack_value.zig` | Structured canonical values: nil, booleans, u64, i64, bytes, UTF-8 strings, arrays, and maps. Encoder sorts map entries by raw key bytes; decoder rejects unsorted or duplicate keys, invalid UTF-8, truncation, trailing bytes, and overlong varints. | `src/proto/coilpack_value.zig:1`, `src/proto/coilpack_value.zig:7`, `src/proto/coilpack_value.zig:10`, `src/proto/coilpack_value.zig:11`, `src/proto/coilpack_value.zig:12`, `src/proto/coilpack_value.zig:17`, `src/proto/coilpack_value.zig:29`, `src/proto/coilpack_value.zig:86`, `src/proto/coilpack_value.zig:131`, `src/proto/coilpack_value.zig:134`, `src/proto/coilpack_value.zig:206`, `src/proto/coilpack_value.zig:222`, `src/proto/coilpack_value.zig:224`, `src/proto/coilpack_value.zig:226`, `src/proto/coilpack_value.zig:331`, `src/proto/coilpack_value.zig:340`, `src/proto/coilpack_value.zig:346` |

The generic signing composition is in `signed_object.zig`, which signs the
canonical `coilpack_value` bytes with Ed25519 and verifies against the embedded
or expected signer (`src/proto/signed_object.zig:1`,
`src/proto/signed_object.zig:3`, `src/proto/signed_object.zig:5`,
`src/proto/signed_object.zig:7`, `src/proto/signed_object.zig:33`,
`src/proto/signed_object.zig:35`, `src/proto/signed_object.zig:37`,
`src/proto/signed_object.zig:45`, `src/proto/signed_object.zig:47`,
`src/proto/signed_object.zig:49`, `src/proto/signed_object.zig:51`,
`src/proto/signed_object.zig:53`). Tests assert that maps with the same logical
contents but different insertion order produce identical canonical bytes and
signatures (`src/proto/signed_object.zig:88`, `src/proto/signed_object.zig:97`,
`src/proto/signed_object.zig:102`, `src/proto/signed_object.zig:104`,
`src/proto/signed_object.zig:107`, `src/proto/signed_object.zig:108`).

MeshPass is a concrete CoilPack signing consumer: its signed fields are written
in fixed order through `coilpack.Cbb`, and token verification re-encodes those
same signed fields before Ed25519 verification (`src/proto/meshpass.zig:216`,
`src/proto/meshpass.zig:220`, `src/proto/meshpass.zig:231`,
`src/proto/meshpass.zig:153`, `src/proto/meshpass.zig:154`,
`src/proto/meshpass.zig:159`).

## Current gaps and non-claims

| Do not claim | Current source evidence |
| --- | --- |
| Do not claim STARTTLS support. | The daemon's TLS is implicit only; `dispatch.zig` notes STARTTLS is "deliberately never implement[ed]". |
| Do not claim `secure_channel.zig` is live S2S wiring. | Its own header comment says live wiring waits on Mooring and the module is transport-agnostic. |
| Do not claim `Secret(T)` makes all secret-dependent branches impossible by itself. | `Secret(T)` enforces explicit exposure/declassification, redacted formatting, constant-time equality, byte-wrapper checks, and wipes, but exposed/declassified bytes can still be branched on by ordinary code (`src/crypto/secret.zig:27`, `src/crypto/secret.zig:63`, `src/crypto/secret.zig:100`, `src/crypto/secret.zig:129`). |
| Do not claim TLS 1.3 or TLS 1.2 `sealRecord`/`openRecord` stack key copies are currently secure-zeroed. | The current TLS record helpers copy AEAD keys into local arrays/values without a matching `defer secureZero(&key)`: TLS 1.3 server seal/open copies at `src/crypto/tls_server.zig:2899`, `src/crypto/tls_server.zig:2905`, `src/crypto/tls_server.zig:2911`, `src/crypto/tls_server.zig:2930`, `src/crypto/tls_server.zig:2935`, `src/crypto/tls_server.zig:2940`; TLS 1.2 seal/open copies at `src/crypto/tls12.zig:405`, `src/crypto/tls12.zig:412`, `src/crypto/tls12.zig:419`, `src/crypto/tls12.zig:464`, `src/crypto/tls12.zig:471`, `src/crypto/tls12.zig:478`. |
| Do not claim ECH is signaled across a HelloRetryRequest. | ECH acceptance is confirmed ONLY on the ServerHello of a single-round handshake. ECH+HRR is deferred: a `ClientHelloOuter` the server opened (`ech_accepted`) that then needs an HRR reaches `writeServerHello` again with `hrr_sent` set, where the confirmation is deliberately NOT stamped so the path fail-closes rather than emitting an unreproducible signal (`signal_ech = ech_accepted and !hrr_sent`). The Onyx Server client stands ECH+HRR down to plain; only a client withholding its inner key_share could reach this path. Status is being revisited in a parallel change — treat this as the verified current behavior, not the final design. | `src/crypto/tls_server.zig:1906`, `src/crypto/tls_server.zig:1911` |
| `signature_algorithms_cert` (RFC 8446 §4.2.3) is implemented (opt-in, fail-closed). | Extension type 50 modeled in `tls_extension.zig`. The client emits it opt-in (`Options.cert_signature_schemes`, byte-identical when unset, re-emitted across HRR / in the ECH inner); the server retains it and — gated behind `enforce_cert_signature_algorithms` (OFF by default ⇒ byte-identical when off) — constrains chain-cert signature acceptance to the client's cert list (falling back to `signature_algorithms`), fail-closed on unclassifiable OIDs. Covered by in-repo tests; the bounded external BoGo gate is 24 pass / 3 explicit skip and is not a full-corpus claim. | `src/crypto/tls_server.zig:384`, `:2192`, `src/proto/cert_sig_scheme.zig` |

The following former guardrails are now OBSOLETE — the capabilities they cautioned against ARE implemented as of this writing, so claiming them is correct:

- **TLS server PQ/hybrid groups:** `tls_server.zig` selects `x25519mlkem768` and performs the real X25519 ECDH + ML-KEM decapsulation when a client offers the hybrid share.
- **`secured_s2s_link` encrypts CRDT frames:** a Post-AKE AEAD record layer (ChaCha20-Poly1305) seals every byte with the Mooring `Established` `send_key`/`recv_key` and opens with per-record counters.
- **MeshPass enforced by the Mooring responder:** M1 carries admission bytes encrypted. Configured signer roots require a signed token bound to the peer node key and S2S frame-family capabilities; otherwise the responder constant-time-compares the shared-secret fallback.
