# E2EE Everywhere (Kintsugi) — Architecture Blueprint

*From client-only E2EE DMs to group/channel end-to-end encryption. Roadmap v1.5
"Kintsugi" — the fortress era. Status: design. Author: stack-architect. Date: 2026-07-11.*

> This is a **blueprint**, not an implementation. Onyx Server Zig → zig-coder; Onyx
> TypeScript → solidjs-coder; external-fact confirmation → deep-researcher. No source
> in either repo is modified by this document.

---

## 1 — Problem & non-functional targets

### 1.1 What must be true when this is done

Two strangers on two different self-hosted nodes can hold a group conversation (a
channel, a multi-party DM, and later a call) whose plaintext **no server operator on
either node can read**, where **removing a member cryptographically locks them out of
future messages** (forward secrecy is already implied by the DM design; the new bar is
**post-compromise security** — a member whose device was compromised recovers once they
re-key), and where **no operator can silently swap a user's public key** without the
victim's client detecting it (key transparency). The local-first history vault keeps
working: decrypted plaintext is view-only and never persists; only ciphertext is at rest.

This enables the roadmap's headline claim: *the only self-hostable Discord-class platform
with audited-design, post-quantum, end-to-end-encrypted text and (later) voice.*

### 1.2 Must-have vs nice-to-have (YAGNI gate)

| Must-have (v1.5) | Nice-to-have / later era |
| --- | --- |
| Group E2EE for **text channels + multi-party DMs** | E2EE **voice at scale** / stages (v2.3 Cadence) |
| Server is **delivery-service, never a group member** | Full **RFC 9420 wire interoperability** with 3rd-party MLS clients |
| Forward secrecy **and** post-compromise security on membership change | Federated cross-node MLS with adversarial nodes proven in DST |
| **Multi-device** as first-class (a user = N leaves, not 1) | Post-quantum client handshake (**PQXDH-style**) — *staged, see §5* |
| **Key transparency** covering the E2EE device/identity keys | VRF-private KT lookups |
| Byte-identical / no-op when the feature is off | Sender re-ordering / metadata-privacy hardening |

### 1.3 Non-functional targets

- **Trust boundary (hard):** the daemon MUST NOT possess any key that decrypts group
  content. It stores/forwards **opaque** blobs (KeyPackages, Welcomes, Commits,
  ciphertext) and enforces only *control-plane policy* it can see (channel
  `encryption-policy`, the `+onyx/e2ee` tag, membership/authz gates). This is the
  DAVE "external sender / delivery service" pattern.
- **Latency / hot path:** group crypto runs in the **browser**, off the daemon hot path.
  A steady-state encrypted message costs one symmetric AEAD seal on the sender and one
  open per recipient (sender-ratchet), not an O(N) TreeKEM op. TreeKEM cost is paid only
  on **membership change** (add/remove/update), amortized.
- **Memory:** per-connection daemon cost is unchanged — group state lives client-side and
  in opaque PROP/METADATA the store already bounds (device value ≤ 180 B key, ≤ 512 B
  metadata value — `src/proto/metadata.zig:12`, `src/proto/e2ee_policy.zig:15-18`).
- **Security posture:** fail-closed. `encryption-policy=required` means a client that
  cannot encrypt cannot send. Wrong-key / wrong-epoch decrypt yields a **locked
  placeholder**, never a silent wrong plaintext (the existing honest-failure pattern —
  `dmCipher.ts:30,230`). Constant-time secret compare, secure-zero of all group secrets
  (already the discipline in `treekem.zig:522`).
- **Compatibility:** wire-format changes deploy **client-FIRST** (Onyx/Ruri is the live
  consumer of every wire change — see the WS framing / MEDIA-plane
  precedent). Old clients that never negotiate the `onyx/e2ee` cap keep working on
  plaintext channels unchanged. Capsule-version discipline for anything Helix carries.
- **Operability:** epoch state must survive USR2 (Helix) on the daemon side only insofar
  as it holds *opaque* material; the authoritative group state is client-side + the
  signed CRDT PROP store, which already survives upgrade and partition.

### 1.4 Invariants it must not violate

- Clean-room: no competitor product names in source (describe behavior generically).
- Mesh identity = shortId; cross-host LWW = wall-clock HLC.
- CRDT records stay `{origin, HLC/dot, authority}` and self-certifying (ENTITY_PROP
  already signs per-origin — `src/proto/entity_prop_event.zig:13-31`).
- Vault: ciphertext-only at rest (`historyVault.ts:122-125` strips `plaintext`).
- Onyx store immutability; no-destructure-props reactivity; both-themes/a11y bar.
- **Byte-identical when off.**

---

## 2 — Current architecture (what already exists, with citations)

The striking finding: **most of the primitives are already in the tree.** The work is
*glue and correct placement of the trust boundary*, not net-new cryptography.

### 2.1 Onyx client — DM E2EE (shipped, Phase 3.6)

```
 sender                                 wire (PRIVMSG)                 recipient
 ------                                 -------------                  ---------
 text ──sealDm(peerKey,text)──► "TSUMUGI1 <b64(nonce‖ct‖tag)>" ──► openDm()──► plaintext
        static-static P-256 ECDH                                    (view-only)
        HKDF-SHA256, AES-256-GCM
```

- `onyx/src/lib/e2ee/dmCipher.ts` — the whole DM cipher. Device keypair is a
  **non-extractable** P-256 ECDH key in its own IndexedDB (`onyx-keys`, separate from the
  history vault so "forget history" never destroys identity — `dmCipher.ts:19-21,95-129`).
  `sharedKeyWith` is static-static and **symmetric** (HKDF `info` sorts both pubkeys), so
  either party — or a replay of history — derives the same key (`dmCipher.ts:144-182`).
- `onyx/src/lib/e2ee/policy.ts` — control-plane contract already models the future:
  `EncryptionPolicy = off|optional|required`, `E2eeMessageKind = generic|mls|sframe`, the
  `+onyx/e2ee` message tag, and `e2ee.device.*` device-prop keys (`policy.ts:2-31`).
  **`mls` is already a reserved tag value** — the wire is forward-designed for this work.
- Store wiring: DM seal path only stamps `+onyx/e2ee` **after** the payload is sealed
  (`store.ts:3222-3255`); this device's pubkey is published to METADATA `ocean.dm-key`
  and the E2EEKEY registry on login (`store.ts:5075`, `8769-8773`); inbound
  METADATA/envelope handling and the locked-placeholder path
  (`store.ts:8732-8787`, `1678-1679` `peerDmKeys`); vaulted DMs decrypt on hydrate but
  stay ciphertext at rest (`store.ts:2972`, `historyVault.ts:122-125`).
- `E2EEKEY STATUS|LIST|ADD|DEL` and `KEYTRANS` are **already client commands**
  (`store.ts:632-639,3471-3493,5659`).

**Limits:** DM E2EE is **per-device pairwise** with **no group construction, no ratchet,
no PCS** (a static-static key never rotates — no forward secrecy across the *long-term*
device key, only per-message nonce separation), and **no multi-device** (a second device
on the same account shows the locked placeholder — `dmCipher.ts:16-17`). It is the
correct *foundation* (a pairwise secure channel to bootstrap group key delivery) but is
**not** the group solution.

### 2.2 Onyx Server — the group-crypto primitives (in tree, server-side today)

| File | What it is | RFC | Gap for E2EE-everywhere |
| --- | --- | --- | --- |
| `src/crypto/treekem.zig` | MLS-style left-balanced TreeKEM ratchet tree; add/remove/update Commits, per-member X25519/HKDF envelopes, all retained members converge on a root secret, evicted members cannot (`treekem.zig:191-337`) | MLS-*shaped*, **not** 9420 wire | Runs **server-side**; custom envelope, not RFC 9420 framing; **not compiled to the browser** where it must run |
| `src/crypto/mls_keyschedule.zig` | RFC 9420 §8 key schedule — labeled `ExpandWithLabel`/`DeriveSecret`, full per-epoch secret derivation for `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` | RFC 9420 §8 | Not wired to treekem or exporter; not in browser |
| `src/crypto/ratchet.zig` | X25519 double ratchet (per-sender FS) | Signal-style | Not wired to a group / sender-key layer |
| `src/crypto/hpke.zig` | HPKE base mode DHKEM(X25519)/HKDF-SHA256/ChaCha20 | RFC 9180 | The KEM for KeyPackage/Welcome sealing; not wired |
| `src/crypto/sframe.zig` | SFrame media frame encryption, AES-128-GCM / ChaCha20 | RFC 9605 | For E2EE **media** (v2.3); keys must come from the MLS exporter |

### 2.3 Onyx Server — control plane + transport (untrusted-for-content)

- `src/proto/e2ee_policy.zig` — server-enforceable policy: channel `encryption-policy`,
  the `+onyx/e2ee` tag validator, bounded `e2ee.device.*` device-key PROP
  validation (`e2ee_policy.zig:12-102`). The daemon **never decrypts** — it only checks
  presence of the tag and enforces the channel policy.
- **Device keys already cross the mesh as signed CRDT PROP.** `handleE2eeKey ADD` stores
  the key as a `user` entity PROP and calls `propagateLocalEntityProp`
  (`server.zig:23807-23811`), which rides `ENTITY_PROP` — a **self-certifying,
  per-origin Ed25519-signed** CRDT fact re-broadcast across the mesh
  (`entity_prop_event.zig:13-31`). This is the exact delivery substrate a group protocol
  needs for KeyPackage publication, and it is already authenticated end-to-end.
- `src/daemon/key_transparency.zig` — an **MMR append log** with inclusion proofs
  (`key_transparency.zig:49-83`) plus `KEYTRANS` command. **But today it only logs
  `certfp` and `webauthn` credentials** (`CredentialKind` — `key_transparency.zig:19-22`);
  it does **not** yet cover the E2EE device/identity keys. Extending `CredentialKind` to
  cover E2EE keys is the roadmap's "verifiable identity" hook, and it is small.
- `src/wasm/host/` — an in-daemon WASM host (`bridge.zig`, `interp.zig`, ABI v1). Onyx
  already runs WASM in the browser for media codecs (`OpcodecWasm.ts`,
  `videoEncodeWorker.ts`). **This is the linchpin of the recommendation** (§4).

### 2.4 The seam, drawn

```
        ONYX (browser)                       ONYX SERVER (daemon, untrusted for content)
  ┌───────────────────────────┐        ┌──────────────────────────────────────────┐
  │ group crypto (MUST live    │        │ control plane it CAN see:                 │
  │ here): TreeKEM epoch, key   │  wss   │  • encryption-policy PROP (enforce)        │
  │ schedule, sender ratchet,   │◄──────►│  • +onyx/e2ee tag (presence only)        │
  │ SFrame keys, KT audit       │        │  • authz/membership gate on the channel    │
  │                            │        │ opaque blobs it FORWARDS, never opens:     │
  │ device/identity keypair     │        │  • KeyPackage  (METADATA/ENTITY_PROP CRDT) │
  │ (non-extractable, IDB)      │        │  • Welcome     (targeted, opaque relay)    │
  └───────────────────────────┘        │  • Commit/epoch (Event Spine, opaque)      │
                                        │  • ciphertext  (PRIVMSG/TAGMSG payload)    │
                                        │ verifiable identity:                       │
                                        │  • KT MMR append log (device+identity keys)│
                                        └──────────────────────────────────────────┘
```

The single most important correction the design must make: **`treekem.zig` today runs
on the daemon.** For E2EE-everywhere it must run in the **client**. The daemon may keep a
copy *only* for reference/tests/DST — never on a path that touches a live group secret.

---

## 3 — Candidate designs for group E2EE

Three genuinely different shapes. All keep the server as delivery-service-never-member;
they differ in *what group cryptography runs in the browser* and *how much RFC 9420 we
adopt*.

### Option A — Sender-keys (Megolm / Signal-group style)

Each sender owns a symmetric hash-ratchet "sender key." A member distributes its current
sender key to every other member **pairwise**, bootstrapped over the existing DM E2EE
channel (§2.1). Messages are one AES-GCM seal broadcast to all; each recipient advances
that sender's ratchet to open.

- **Group state:** a map `member → sender-chain` per member, per channel.
- **Membership change:** on **remove**, every remaining member must **rotate and
  re-distribute** its sender key pairwise to all others (O(N²) messages) — otherwise the
  removed member keeps decrypting. Add is cheap (just send existing keys to the newcomer,
  but that leaks history unless you also rotate).
- **FS:** yes, per-message (ratchet). **PCS:** weak — a compromised member's key stays
  valid until the next full rotation; no automatic healing.

### Option B — Full RFC 9420 MLS in the client (WASM), wire-interoperable

Port/compile a complete MLS stack to the browser: RFC 9420 KeyPackage / Welcome /
Commit / GroupInfo TLS-presentation-language framing, TreeKEM, the §8 key schedule,
exporter for SFrame. Wire-interoperable with third-party MLS clients.

- **Group state:** one TreeKEM tree per channel; members are leaves (multi-device = N
  leaves). Epoch advances on every Commit.
- **Membership change:** TreeKEM Commit — O(log N) ciphertext, **automatic PCS** (the
  committer re-keys its direct path; a removed leaf is blanked). This is the gold
  standard.
- **Cost:** a full, spec-conformant, **audited** MLS implementation in TypeScript/WASM is
  the single largest and riskiest deliverable in the roadmap. `treekem.zig` is *MLS-shaped
  but not 9420-wire*; adopting full 9420 means either finishing 9420 framing in Zig +
  WASM-compiling it, or adopting a third-party browser MLS (breaks the clean-room /
  pure-in-house posture and adds a supply-chain trust dependency).

### Option C — Staged hybrid: "MLS-shaped" TreeKEM group (in-house, WASM) → SFrame → (defer full 9420 interop)

Compile the **existing** `treekem.zig` + `mls_keyschedule.zig` to WASM and run them **in
the browser** as the group ratchet, over an **in-house wire** (not full RFC 9420
interop). Text messages use a per-sender SFrame-style key derived from the MLS **exporter
secret** (so the O(N) TreeKEM cost is paid only at epoch change, and steady-state sending
is one symmetric seal). Welcome/Commit ride the existing opaque-blob transport. RFC 9420
*wire interoperability* with foreign clients is explicitly **deferred** — we control all
clients (Onyx), so we get MLS's security properties without owing byte-level 9420 framing
on day one. Later, swap the in-house framing for 9420 framing behind the same client API.

- **Group state:** one TreeKEM tree per channel (Option B's model), but the serialized
  Commit/Welcome/KeyPackage use our own bounded encoding rather than 9420
  presentation-language.
- **Membership change:** TreeKEM Commit (`treekem.zig` already implements add/remove/
  update with converging roots and eviction — `treekem.zig:242-312`). **Automatic PCS.**
- **Cost:** reuses the **already-KAT-tested** in-tree crypto; the new work is (1) a WASM
  build of the Zig group crypto, (2) a thin TS binding, (3) the opaque-blob transport
  wiring, (4) SFrame keying from the exporter, (5) KT extension. No third-party MLS
  dependency; clean-room preserved.

### 3.1 Scorecard

| Criterion | A: Sender-keys | B: Full RFC 9420 | C: Staged hybrid (rec.) |
| --- | --- | --- | --- |
| Forward secrecy | ✅ per-message | ✅ | ✅ per-message (SFrame) + epoch |
| **Post-compromise security** | ❌ weak (manual rotate) | ✅ automatic (TreeKEM) | ✅ automatic (TreeKEM) |
| Membership-change cost | ❌ O(N²) on remove | ✅ O(log N) | ✅ O(log N) |
| Reuses in-tree crypto | partial (`ratchet.zig`) | ❌ needs new 9420 stack | ✅ `treekem`+`keyschedule`+`sframe` |
| Clean-room / no 3rd-party crypto | ✅ | ⚠️ likely a JS/WASM MLS dep | ✅ |
| Multi-device natural | ⚠️ each device a sender | ✅ leaf-per-device | ✅ leaf-per-device |
| Time-to-first-ship | fast | slowest / highest risk | medium |
| Standards / interop story | none | best | deferred (swap-in later) |
| Audit surface | small but weak guarantees | huge | **bounded** (reuse audited primitives) |
| Media (SFrame) path | awkward keying | exporter | ✅ exporter (native fit) |

---

## 4 — Decision & rationale

**Adopt Option C — the staged hybrid ("Kintsugi ratchet").**

Why it wins on the targets that matter:

1. **PCS + O(log N) membership** rule out Option A: a self-hostable Discord-class E2EE
   platform whose remove-a-member is O(N²) and doesn't heal after compromise fails the
   fortress-era exit criterion.
2. **Reuse of the audited, KAT-tested in-tree crypto** (`treekem.zig`,
   `mls_keyschedule.zig`, `sframe.zig`, `hpke.zig`) is decisive against Option B. The
   roadmap's own risk note is correct: *the primitives already exist and are KAT-tested;
   the work is glue.* Option B throws that away and re-introduces the largest bet
   (net-new clean-room MLS in the browser) plus a likely third-party dependency that
   violates the pure-in-house posture.
3. **One implementation, two runtimes.** Compiling the Zig group crypto to WASM means the
   browser and the daemon (for tests/DST/reference) run the **same** audited code — no
   drift between a TS re-implementation and the Zig one. Onyx already ships WASM codecs
   (`OpcodecWasm.ts`), so the loading/worker plumbing exists.
4. **Deferring 9420 wire-interop is honest YAGNI.** We control every client. MLS's
   *security properties* come from TreeKEM + the key schedule, which we have; the *wire
   framing* is what buys foreign-client interop, which no requirement asks for in v1.5.
   The client API is designed so 9420 framing swaps in later without touching call sites.

What it trades: no interop with external MLS clients until a later phase; the "MLS-shaped"
wire is our own contract and must be versioned carefully; and we must correct the known
DAVE flaws ourselves (§4.2) rather than inheriting a spec's mitigations.

### 4.1 The load-bearing placement decision

- **Group crypto runs in the browser (WASM).** The daemon holds a copy of `treekem.zig`
  **only** for unit tests and DST; **no live group secret ever exists in daemon memory.**
  A DST/CI guard should assert the daemon never derives a group root from a real channel's
  material.
- **The daemon is external-sender / delivery-service.** It forwards four opaque blob
  kinds (KeyPackage, Welcome, Commit, ciphertext) and enforces three visible controls
  (channel `encryption-policy`, `+onyx/e2ee` presence, channel membership/authz).

### 4.2 DAVE-flaw corrections (must be in the design from day one)

The roadmap explicitly requires correcting Discord-DAVE's known weaknesses:

- **Authenticate the clear-range metadata in AAD.** Any unencrypted framing (epoch id,
  sender leaf id, generation) MUST be bound into the AEAD associated data so a relay
  cannot tamper with it undetected. `sframe.zig` header + `treekem.zig` envelope context
  already thread epoch/operation/member into the derivation
  (`treekem.zig:414-427`); the SFrame layer must bind its header likewise.
- **Key-committing AEAD.** Plain AES-GCM is not key-committing; use a key-committing
  construction (e.g. a commitment tag over the key, or a committing-AEAD wrapper) so a
  single ciphertext cannot be opened to two different plaintexts under two keys.
  *(deep-researcher item — §6.)*
- **No downgrade / passthrough mode.** Because we control all clients, there is **no**
  unencrypted-passthrough fallback inside an E2EE channel. `encryption-policy=required`
  is fail-closed at both the client and the server tag-gate.

---

## 5 — Contracts (the load-bearing specification)

### 5.1 Capability & tags (wire)

- Cap: `onyx/e2ee` (already reserved — `policy.ts:2`). Advertised only when the daemon
  build has the E2EE control plane enabled; **absent → byte-identical old behavior.**
- Message tag: `+onyx/e2ee=mls` on group ciphertext (the `mls` value is already
  validated server-side — `e2ee_policy.zig:50` — and client-side — `policy.ts:29`).
- Channel policy PROP: `encryption-policy = off|optional|required`
  (`e2ee_policy.zig:12,20-24`). Server enforces `required` by rejecting untagged PRIVMSG
  to that channel with a standard `FAIL`.

### 5.2 Key material published as signed CRDT PROP (server stores, never reads)

Keep long-term device identity and optional transparency hints in the existing
signed ENTITY_PROP CRDT. Ephemeral KeyPackage, Welcome, and Commit material uses
the bounded `E2EEGROUP` control-record contract in §5.3 instead of creating a
second persisted group-state authority in PROP.

| PROP key (user entity) | Value (opaque, bounded) | Purpose |
| --- | --- | --- |
| `e2ee.device.<id>` | `alg:b64key` (existing, `e2ee_policy.zig:82-98`) | Long-term device identity pubkey (bootstrap) |
| `e2ee.kt.<id>` (**new, optional**) | `b64(kt-inclusion-proof-hint)` | Client-cached KT position for audit |

Values stay inside the existing metadata-store bound. Group control records have
their own canonical base64url and 4096-byte opaque-payload bounds, so no
namespace-specific PROP value-cap exception is required.

### 5.3 Group control blobs (server FORWARDS, never opens)

- **One versioned command surface** — `E2EEGROUP <channel>
  <key-package|commit> <from-device> :<b64blob>` fans a bounded opaque record to
  capable channel members. `E2EEGROUP <channel> welcome <from-device>
  <to-account> <to-device> :<b64blob>` targets only the named account/device.
  The sender must be an authenticated member and own the advertised
  `e2ee.device.<from-device>` PROP. The daemon sees routing metadata and size,
  never group secrets.
- **Mesh relay** — the exact parsed control record is origin-signed and forwarded
  under its own replay/equivocation authority. The v1 contract is deliberately
  non-persistent: an offline Welcome fails explicitly and the client retries
  after the target reconnects. Helix preserves replay authority, not payloads.
- **Ciphertext** — ordinary `PRIVMSG`/`TAGMSG` carrying `SFrame(payload)` with
  `+onyx/e2ee=mls`. CHATHISTORY, session-sync, and the outbox already carry it
  untouched (the DM precedent — `dmCipher.ts:14-16`).

**Deploy-order:** every one of these is a wire change → **client-FIRST**. Onyx must
tolerate a daemon that does not yet expose `E2EEGROUP` (feature-detect via the
`onyx/e2ee` cap) and vice-versa.

### 5.4 Client group-state module (Onyx, new — `src/lib/e2ee/group/`)

Concrete TS surface (implemented by solidjs-coder; crypto delegated to the WASM module):

```ts
// src/lib/e2ee/group/mlsGroup.ts — thin binding over the WASM group crypto
export interface MlsGroup {
  readonly channel: string;
  readonly epoch: number;
  keyPackage(): Promise<Uint8Array>;              // publish to e2ee.kp.<id>
  addMember(kp: Uint8Array): Promise<Commit>;      // → Welcome + Commit blobs
  removeMember(leaf: number): Promise<Commit>;     // TreeKEM remove (PCS)
  update(): Promise<Commit>;                        // self-update (PCS heal)
  applyCommit(blob: Uint8Array): Promise<void>;    // advance epoch
  joinFromWelcome(blob: Uint8Array): Promise<void>;
  senderKey(): Promise<CryptoKey>;                 // SFrame key from exporter(epoch)
}
export interface Commit { welcome?: Uint8Array; commit: Uint8Array; epoch: number; }
```

- Group secrets live only in WASM linear memory + non-extractable Web Crypto handles;
  never serialized to the vault.
- The store gains a `groupEpochs: Map<channel, MlsGroupState>` slice (onyx-store),
  immutable updates only.

### 5.5 Vault interaction (unchanged invariant, extended)

`serializeMessage` already strips decrypted `plaintext` and persists only ciphertext
(`historyVault.ts:122-125`). Group messages are identical: the `text` field is the
SFrame envelope; `plaintext` is view-only, derived on hydrate by advancing the sender
ratchet if the epoch key is still held. **New rule:** the client must retain
per-epoch exporter keys long enough to decrypt vault history it chooses to keep, OR accept
that pruned-epoch history becomes unreadable (an FS/usability trade — a per-channel
"keep readable history" toggle decides). This is a genuine design tension: **strong FS
means old ciphertext eventually can't be reopened.** Recommend: keep a bounded ring of
recent epoch-exporter keys in the `onyx-keys` IDB (separate from history), sized to the
vault retention window (`VAULT_KEEP` — onyx-vault owns the constant).

### 5.6 Key transparency hook (the roadmap's "verifiable identity")

Extend `key_transparency.zig` `CredentialKind` (`key_transparency.zig:19-22`) with an
`e2ee_device = 3` (and `identity = 4`) variant, and append a KT event whenever
`handleE2eeKey ADD/DEL` mutates a device key (`server.zig:23807-23826`) — exactly as
certfp/webauthn already append. The client:

1. On learning a peer's `e2ee.device.*` / `e2ee.kp.*`, calls `KEYTRANS` for an inclusion
   proof against the current MMR root.
2. Audits its **own** key history (append-only, monotonic root) to detect an operator
   silently swapping its key — the WhatsApp/iMessage KT pattern.
3. Gossips/compares roots so a split-view (operator shows victim a different log than the
   world) is detectable. The MMR root already crosses the mesh; consistency-proof
   checking between roots is the new client work.

The server-side change is **small and additive** (a new enum value + two append call
sites + the proof already exists). The client-side audit loop is the substantive new work.

### 5.7 Multi-device

A user = **N leaves** in the TreeKEM tree, one per device KeyPackage
(`e2ee.kp.<id>`). Adding a new device = an Add Commit + Welcome to that device; removing
a lost device = a Remove Commit (PCS locks the lost device out). This is strictly better
than the current DM design's "other device shows locked placeholder"
(`dmCipher.ts:16-17`) and is the natural MLS model — a reason Option C beats Option A.

---

## 6 — What needs deep-researcher BEFORE committing

Confirm against primary sources (RFC texts, the MLS/DAVE specs, PQ drafts) — do not guess:

1. **RFC 9420 conformance scope.** Confirm precisely which parts of 9420 give the
   security properties (TreeKEM path secrets, key schedule, tree-hash/parent-hash
   integrity, transcript hash) vs which are wire-framing-only, to validate that Option C's
   "MLS-shaped, defer framing" keeps the **security** guarantees. Verify `treekem.zig`'s
   left-balanced tree + parent/leaf derivation matches 9420's ratchet-tree semantics
   closely enough that a later swap to 9420 framing is behavior-preserving. **Critically:
   confirm whether `treekem.zig`'s custom envelope provides the tree-hash / parent-hash
   binding 9420 requires to prevent tree-substitution attacks** — if not, that's a design
   gap to close before shipping.
2. **Key-committing AEAD** — the correct, current construction to fix the DAVE
   non-committing-AEAD flaw (CTX / committing-HKDF-over-key / a vetted committing-AEAD),
   and whether Zig std.crypto can express it without new primitives.
3. **DAVE flaw inventory** — the authoritative list of DAVE's known weaknesses to be sure
   §4.2 is complete (clear-range AAD authentication, downgrade, media-key rotation cadence,
   MLS external-sender handling).
4. **Post-quantum path** — confirm the current state of PQ-MLS / PQXDH: whether to extend
   the KeyPackage KEM to X-Wing/hybrid now or stage it, and whether the in-tree
   `xwing.zig`/ML-KEM material (mesh layer) is reusable for the client handshake. The
   roadmap wants PQ "from the wire up"; confirm the *client E2EE* PQ story is realistically
   v1.5 or a fast-follow.
5. **KT consistency/audit protocol** — confirm the MMR consistency-proof + split-view
   detection approach matches the current KT literature (CONIKS/Parakeet/WhatsApp-Auditable-Key-Directory lineage) and whether VRF-private lookups are needed in v1.5 or deferrable.

---

## 7 — Phased, testable build order & ownership

Each phase compiles, gates on its own suite, lands independently, and is **byte-identical
/ no-op when `onyx/e2ee` is not advertised**. Wire phases deploy **client-FIRST**.

| Phase | Deliverable | Owner | Gate / tests | Deploy note |
| --- | --- | --- | --- | --- |
| **0. Research** | §6 items confirmed; the tree-hash-binding gap in `treekem.zig` resolved as design input | **deep-researcher** | brief with citations + confidence | — |
| **1. KT covers E2EE keys** | `CredentialKind.e2ee_device`/`identity`; KT append at `handleE2eeKey ADD/DEL`; `KEYTRANS` returns device-key proofs | zig-coder (onyx-server-ircx for command surface, onyx-server-crypto-reviewer review) | unit + KAT for `eventDigest`; additive, no wire break | server-safe (additive) |
| **2. WASM group crypto** | Build `treekem.zig`+`mls_keyschedule.zig`+`sframe.zig` to a browser WASM module; thin TS `mlsGroup.ts` binding; parity tests vs the Zig unit tests | zig-coder (WASM build) + solidjs-coder (binding) | KAT parity WASM↔Zig; `onyx pnpm test` | client-only, no wire yet |
| **3. Group state in store** | `groupEpochs` slice; device KeyPackages queued for bounded `E2EEGROUP` publication; epoch state immutable in store | onyx-store | slice tests; no-op when cap absent | client-FIRST |
| **4. Opaque transport** | Daemon forwards versioned `E2EEGROUP` KeyPackage/Welcome/Commit records; membership/device-ownership gate; **never opens or persists** blobs; policy-`required` fail-closed tag-gate | onyx-server-ircx + onyx-server-integrator (+ onyx-server-mesh-reviewer) | loopback e2e; DST for mesh crossing + USR2 replay-authority carry | **client-FIRST**, then server |
| **5. Text E2EE end-to-end** | SFrame text sealing from the exporter; send/receive/CHATHISTORY/vault-at-rest; locked-placeholder on wrong epoch; DAVE-flaw AAD + committing-AEAD | solidjs-coder + onyx-vault (retention) | onyx-e2e critical flow (two contexts, encrypted channel); vault ciphertext-only regression | client-FIRST |
| **6. KT audit loop** | Client audits own key history + peer inclusion + root consistency (split-view detection) | solidjs-coder | unit for proof verify; e2e for swap-detection | client-only |
| **7. Multi-device** | N-leaf-per-user; add/remove device Commits | solidjs-coder + onyx-store | e2e: second device joins & reads; removed device locked | client-FIRST |
| **8. PQ / voice** | (fast-follow / v2.3) PQXDH KeyPackage KEM; SFrame media keys from exporter for calls | per §6 outcome | — | staged |

DST is **mandatory** for Phase 4 (mesh crossing of opaque blobs, epoch state across
partition + USR2) — route to **onyx-server-dst** with a seeded partition/heal/upgrade campaign
asserting: no plaintext ever in daemon memory, opaque blobs converge, epoch monotonicity.

---

## 8 — Risks, failure modes, rollback

- **Trust-boundary regression (CRITICAL).** If any group secret is ever derivable
  server-side, the whole claim collapses. *Mitigation:* group crypto is WASM-in-browser
  only; a CI/DST guard asserts the daemon never derives a real channel root; code review
  by onyx-server-crypto-reviewer on any daemon file that touches `treekem`/exporter.
- **Mid-upgrade peer / old client.** An old daemon that doesn't forward `E2EE`/`EPOCH`, or
  an old client that can't decrypt, must degrade to *locked placeholder* + a visible "your
  peer can't do E2EE yet" state — never a silent plaintext leak and never a crash.
  *Mitigation:* strict cap gating; `encryption-policy=required` is the only fail-closed
  mode, `optional` tolerates mixed fleets during rollout.
- **Partition / USR2 during an epoch change.** A Commit that crosses the mesh mid-partition
  could be seen out of order. *Mitigation:* TreeKEM Commits are epoch-numbered and applied
  in order; a client that receives epoch N+1 without N requests a re-sync (the group
  equivalent of the existing mesh RESYNC). DST proves convergence.
- **FS vs vault readability (design tension, §5.5).** Strong FS makes old ciphertext
  unreadable once epoch keys are dropped. *Mitigation:* bounded epoch-key ring sized to
  vault retention; a per-channel toggle; documented honestly.
- **KT split-view.** An operator shows a victim a different log than the world.
  *Mitigation:* root consistency-proofs + cross-mesh root comparison (Phase 6); the MMR is
  append-only so tampering breaks monotonicity.
- **Clean-room / supply-chain.** Option C explicitly avoids a third-party MLS dependency;
  do not regress into pulling one in "just for framing."
- **Rollback.** The feature is a cap + build flag. Dropping the `onyx/e2ee` advertisement
  returns the fleet to byte-identical plaintext behavior (channels were `optional`);
  `required` channels stop accepting messages until the cap returns (fail-closed, by
  design). No persisted daemon state needs unwinding — all group state is client-side +
  opaque PROP the daemon already treats as bytes.

---

## 9 — Handoff summary

- **deep-researcher** first (Phase 0): §6 — especially the `treekem.zig` tree-hash-binding
  question and the key-committing-AEAD construction. **These gate the design.**
- **zig-coder** (+ onyx-server-crypto-reviewer, onyx-server-mesh-reviewer, onyx-server-helix-reviewer):
  Phases 1, 2 (WASM build), 4 (opaque transport). Additive, fail-closed, no plaintext
  server-side.
- **solidjs-coder** (+ onyx-store, onyx-vault, onyx-e2e): Phases 2 (binding), 3, 5, 6, 7.
- **onyx-server-dst**: Phase 4 seeded partition/USR2 campaign.
- **onyx-server-config**: the `e2ee.*` metadata value-cap raise (§5.2).

**The one-line recommendation:** ship group E2EE as a **staged, in-house MLS-shaped
TreeKEM ratchet compiled to WASM** (reusing the already-KAT-tested `treekem.zig` /
`mls_keyschedule.zig` / `sframe.zig`), with the **daemon as delivery-service-never-member**
forwarding opaque KeyPackage/Welcome/Commit/ciphertext blobs over the existing
signed-CRDT-PROP + Event-Spine transport, **key transparency extended to cover the E2EE
device keys**, and **RFC 9420 wire-interop explicitly deferred** — correcting the known
DAVE flaws (AAD-authenticated metadata, key-committing AEAD, no downgrade) from day one.
