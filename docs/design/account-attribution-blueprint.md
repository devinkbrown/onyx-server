
> **Superseded / historical — preserved as evidence.** This document is a point-in-time record and does not describe the current source or fleet. Current truth: [docs hub](../README.md) and [production paths](../ops/onyx-server-paths.md). Do not execute it as a current procedure.

<!--
SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Blueprint — Cryptographic account attribution for mesh membership (F1 proper fix)

Status: **DESIGN — GO** (no open CRITICAL; one HIGH owned + DST-gated — the liveness/value
sticky-trust rule in §4.4). Grounded against onyx-server @ HEAD and onyx @ HEAD.
Author: stack-architect. Reconciled after a 3-lens adversarial refute pass (§7).

Scope: close the Byzantine-account-forgery hole (F1) **while restoring** legitimate multi-device
coexistence — the thing the conservative branch fix `fix/mesh-forged-account-homing` (commit
`066b832`) deliberately gives up.

> **Deploy verdict up front (the question asked):** This is **ALL a follow-up.** Nothing here is
> a hotfix and no phase should be rushed into the current multi-client deploy. The correct thing
> live *right now* is the conservative `wire_account_trusted = false` fix (branch
> `fix/mesh-forged-account-homing`), which closes F1 today at the cost of 3rd-node multi-device
> coexistence. Every phase below is **no-op when off** and lands incrementally, but the feature
> only becomes *useful* (multi-device restored) once the daemon groundwork **and** the onyx
> client half ship **and** accounts have enrolled an identity key. Until then every account stays
> on the conservative UID path — so there is **no window where F1 reopens**. Treat the
> conservative fix as the live baseline until this lands end-to-end.

> **Refute-driven revision:** the first draft carried the proof in a new MEMBERSHIP wire block
> (cap bit + Helix capsule bump) and hand-waved a "KT-anchored pubkey." The adversarial pass
> killed both: the KT log stores digests and does not replicate; and a membership block re-opens
> the USR2-collapse + positional-layering hazards. The chosen design instead **rides the proof
> over the existing ENTITY_PROP replication** (which already meshes and survives USR2) and
> verifies against the **receiver-owned, replicated `identity.key.*` pubkey** — never the KT log,
> never a key from the wire. This is smaller, and it is what closes the holes.

---

## 1. Problem & non-functional targets (§2.1)

### 1.1 The requirement, in one paragraph
On the Undertow mesh a `MEMBERSHIP` frame carries a plaintext `account` field
(`src/proto/membership_event.zig:92`). Frame signing (`s2s_peer.verifiedPayload`,
`originShortId(pubkey) == remote_node_id`) proves **which node authored the frame**, not that the
node **authenticated a user** under that account — and the account bytes ride inside that
node-signed payload, so a node can put anything there. A compromised *admitted* peer therefore
emits `MEMBERSHIP nick=kain account=kain`; `route_table.resolveIncomingNick`
(`src/substrate/undertow/route_table.zig:479`) reads `sameAccount(...)`, returns
`local_same_account` / `remote_same_account` / `reclaim_local`, **suppresses the UID-rename**, and
homes the phantom under the real nick — drawing a third node's cross-node DM/metadata delivery to
the attacker. **When this is done:** a node can *verify* that a remote `account=kain` claim is
really kain, using a proof a Byzantine node **cannot manufacture**, so (a) forgeries are rejected
fail-closed and (b) a genuine `kain` logged in on two nodes coexists under the real nick on a
third. This is the substrate for roadmap v2.0 **Ryūjin R1** (`CODEX_ROADMAP.md:255`).

### 1.2 Must-have vs nice-to-have (YAGNI gate)
- **Must:** prevent a **non-home** Byzantine admitted peer from forging any account; restore
  multi-device coexistence for accounts that enrolled a key; conservative UID fallback for
  guests / unenrolled / legacy / mid-upgrade / pre-convergence; fail-closed on every unverifiable
  path.
- **Nice-to-have (explicitly deferred — do NOT build now):** defending against a compromised
  **home** node lying about *its own* users (a bounded residual, §4.3 / §6-R2); per-frame
  re-signing (only helps against a compromised home node — gold-plating for F1); KT audit
  anchoring; UCAN/Biscuit capabilities (R5); full session roaming (R2). Building these now is
  speculative generality F1 does not ask for.

### 1.3 Non-functional targets
| Target | Constraint |
|---|---|
| Hot-path cost | Verification is **login-time-amortized**: the client signs **one** residence proof per login/epoch, not per frame. The verify runs on the S2S membership *apply* path (not per user message): one Ed25519 verify + one PROP lookup per *present, cross-node/local-colliding* same-account claim. No per-datagram cost; no allocation on the apply path (borrow the replicated PROP + frame buffers). |
| Memory/conn | Zero new per-connection state on client legs. The proof is a **replicated PROP** (`identity.residence.<node>`), not a per-session cache — it already fits the prop store's bounded model. |
| Security posture | Fail-**closed**: any missing pubkey, missing/expired proof, decode error, or binding mismatch ⇒ `account_trusted = false` ⇒ conservative UID path, **and the caller forces `account=""` into `resolveIncomingNick`** so no downstream path trusts the raw wire account. Verify side holds no secrets. |
| Back/forward compat | Old peer, mid-USR2 peer, unenrolled account, and pre-convergence cold node all degrade to today's safe behavior. **No membership wire change** — the proof rides existing ENTITY_PROP, so the membership frame is byte-identical. |
| Operability | No new cap bit, **no Helix capsule bump** — the proof is prop state that already survives USR2 and re-converges via the existing prop burst / anti-entropy. `assertion_ttl_ms` is a config knob (onyx-server-config), not hardcoded. |

### 1.4 Invariants & §2.1.1 guard-rails
- **Mesh identity = shortId.** The residence proof binds `origin_node` as the **shortId**; the
  verifier checks `proof.node == frame.origin_node`, and `verifiedPayload` already pins that
  origin to `originShortId(frame.pubkey)` (`s2s_peer.zig` `verifiedPayload`). Never a nick/UID.
- **HLC liveness vs value convergence are orthogonal (the sharpest refute finding).** The proof
  gates the **initial** same-account *coexist admission* only. It does **NOT** continuously gate
  an already-established member, is **NOT** fed by the LWW/HLC value path, and its **expiry never
  prunes a live member** — actual departure is the existing local-clock staleness GC. A late
  proof refresh (partition / USR2 / loss) must **not** rename a live established member. See the
  sticky-trust rule in §4.4 — this is the load-bearing correctness requirement.
- **Fail-closed crypto.** Mirrors `require_signed_frames` failing closed (`s2s_peer.zig:391`,
  `inboundSignedFramesRequired` returns null on unsigned in-scope frames). Residence trust
  **requires** the carrying MEMBERSHIP frame be origin-authenticated (`verifiedPayload` non-null);
  an unsigned/keyless path can never yield `account_trusted = true`.
- **Multi-reactor timer fan-out.** No new per-session cache and no new fan-out timer: the proof is
  prop state, tombstoned inline on the owning client shard at session close (§4.3). **If** a
  periodic residence-prop staleness sweep is ever added it gates on `reactors[0]`
  (`rx() == &reactors[0]`), the mesh-maintenance convention — a peerless sibling reactor must
  never run it. Owner: **reactor 0.**
- **onyx E2EE fails closed.** The device **signing** key is separate from the E2EE DM **ECDH**
  key; a sign failure is an error, never a plaintext/untrusted downgrade.
- **Clean-room.** New names are generic (`account_presence` / `residence`; no competitor terms).

---

## 2. Current architecture — what already exists (§2.2)

The load-bearing discovery (confirmed independently by the minimalist refute lens): **the
account-key substrate is already ~70% built, already replicates, and already survives USR2.**

```
 onyx client (home)            home daemon H                    remote daemon R
 ───────────────────           ───────────────────             ───────────────────
 device ECDH key (E2EE)        ClientSession.account()          RouteTable (remote members)
 [ADD: device SIGN key]        IDENTITY ADD/DEL/LIST  ◄── cmd    resolveIncomingNick(...,
 passkey (WebAuthn)            account_identity.verifyClaim       account, account_trusted)
                               props.setProp identity.key.*     ENTITY_PROP replica holds
 [ADD: sign residence] ──────► [ADD: IDENTITY RESIDENCE]         identity.key.* AND
                               props.setProp identity.residence   identity.residence.* for kain ✅
                               propagateLocalEntityProp ──────►  (both already replicate + persist)
 MEMBERSHIP (unchanged) ──────► signed_frame node signature ───► verifiedPayload(.MEMBERSHIP)
                                                                  + verify residence proof vs
                                                                    replicated identity.key pubkey
```

### 2.1 Seams already in the tree (cite `file:line`)
- **Sovereign account key — `src/proto/account_identity.zig`.** Ed25519 pubkey + **self-signature**
  over `"ONYX-ACCOUNT-IDENTITY-v1" ++ account ++ label ++ pubkey` (`:23,55,77`
  `transcript`/`verifyClaim`). We add a **residence** transcript alongside it (§4.2).
- **Registration + revocation — wired.** `IDENTITY ADD <label> <pub-hex> <sig-hex>` is
  **account-control gated** (`server.zig:24376` `session.account() orelse NOT_LOGGED_IN`),
  **verifies the self-signed binding** (`:24379`), stores + **replicates** it (`:24388-24390`
  `setProp` + `propagateLocalEntityProp`). `IDENTITY DEL` (`:24397`) is revocation. `IDENTITY LIST`
  reads them back.
- **Pubkey distribution + durability is FREE.** `identity.key.*` rides **ENTITY_PROP** CRDT
  replication, so **every node already holds kain's real pubkey keyed by account**, independent of
  any claiming node — and the prop store is **durable** (`server.zig:2974` "`.props` store for
  durability and lazily reloaded here at login"), so it survives USR2 and re-converges via the
  normal prop burst / anti-entropy. *This is the fact that kills the "no key to verify against"
  and "USR2 collapse" refute objections — the pubkey source is the replicated prop, never the KT
  digest-log.*
- **Signed-mesh-assertion + replay/freshness precedent — `src/proto/oper_cred_share.zig`.**
  Canonical length-prefixed serialization, magic, `verifyStrict`, wall-clock expiry, and a
  **supersede Registry** (incarnation floor, `:322,385`). We copy the freshness/replay shape for
  the residence proof.
- **Origin authentication — `s2s_peer.verifiedPayload` + `signed_frame.zig`.** A signing peer's
  in-scope frame MUST be a signed envelope; the self-certified origin
  `shortId(nodeIdFromPublicKey(pubkey))` must equal the peer's authenticated node id, else the
  frame is dropped (`verifiedPayload`, `s2s_peer.zig:~1305`; `inboundSignedFramesRequired`
  fail-closed at `:1274`). This is the anchor the residence-`node` binding leans on.
- **The decision point — `route_table.resolveIncomingNick`** (`:479`), already carrying the
  `account_trusted: bool` parameter from branch `066b832`; caller `recvMembership`
  (`s2s_peer.zig:1354-1432`) / `recvNickChange` (`:1943`).
- **onyx keys.** Device ECDH P-256 for E2EE DM in `onyx-keys` IndexedDB
  (`onyx/src/lib/e2ee/dmCipher.ts`); WebAuthn passkeys (`onyx/src/lib/webauthn/passkey.ts`). The
  new device **signing** key lives alongside, non-extractable.

### 2.2 The conservative fix this replaces
Branch `fix/mesh-forged-account-homing` (`066b832`) added `account_trusted: bool` to
`resolveIncomingNick` and passes const `wire_account_trusted = false`, so **every** cross-node
same-account claim UID-disambiguates. This blueprint keeps that signature/default and makes
`account_trusted` a **per-claim verified bool**.

---

## 3. Candidate designs & honest trade-offs (§2.3)

All keep the conservative UID fallback for the untrusted path; they differ in what makes
`account_trusted` true, and in *where the proof rides*.

### Design A — client-held account key, per-frame presence assertion in the MEMBERSHIP wire
Device key signs a presence assertion per membership; it rides a **new membership trailing block**
(cap bit + Helix capsule bump); verified against the account pubkey.
- **Prevents** non-home forgery. **Cost:** new wire block, cap negotiation, capsule migration, and
  the per-frame signing cadence. The refute pass showed the wire block re-introduces the
  USR2-collapse and positional-layering hazards, and per-frame signing only buys defense against a
  *compromised home node* (out of scope). **Rejected as over-built.**

### Design B — home-node-attested (oper_cred_share generalized)
The **home** node signs "I authenticated kain," verified against the home node's key.
- **Does NOT close F1.** Proven against real source: `applyMeshGrant` (`server.zig:22793`) verifies
  a grant **only against the direct peer's key** with **no check that the signer is authoritative
  for the account** — an admitted Byzantine peer can already mint a forged grant for any account.
  B embodies node-trust; F1's adversary *is* an admitted node. The trust root must sit **below the
  node, at the account.** **Rejected — reproduces the vulnerability.**

### ★ Design C (CHOSEN) — account-key residence proof over ENTITY_PROP, verified vs the replicated pubkey
The account key (already replicated as `identity.key.*`) signs **one** residence proof at login/
epoch, binding `{account, node-shortId, epoch, expiry_ms}`. The home node stores it as a
replicated prop `identity.residence.<node>` (same ENTITY_PROP path — already meshes, already
persists, already survives USR2). Any node sets `account_trusted = true` for an incoming
`{nick, origin=N, account=kain}` **iff** a live residence proof for kain verifies against kain's
**receiver-owned replicated** identity pubkey **and** binds `node == N (== the frame's
signed-origin)`. Else `false` → conservative UID.
- **Prevents** non-home forgery (B holds no account key → no proof binding kain to B).
- **Restores** multi-device (kain on A and D each publish their own residence proof; a third node
  verifies both → `remote_same_account` coexistence, `route_table.zig:510`).
- **Reuses** enrollment / distribution / durability / revocation wholesale; the *only* new pieces
  are one transcript, one `IDENTITY RESIDENCE` command, one verify wrapper, one onyx signature.

### Scoring
| Criterion | A (wire block) | B (home-attested) | **C (residence-prop) ★** |
|---|---|---|---|
| Closes stated F1 (non-home peer) | ✅ | ❌ (node-trust) | ✅ |
| Restores multi-device | ✅ | ✅ | ✅ |
| "No trust in any node's word" | ✅ | ❌ | ✅ |
| Survives USR2 without new migration | ❌ (capsule bump + collapse risk) | n/a | ✅ (rides durable prop) |
| Membership wire byte-identical | ❌ (new block) | ✅ | ✅ |
| New mechanism count | block+cap+capsule+codec | reuse only | 1 transcript + 1 cmd + verify |
| Guests/unenrolled/legacy handled | needs fallback | needs fallback | ✅ built-in fallback |
| onyx co-change | per-frame signer | none | **one login-time signature** |

**C wins:** it is the only option that closes F1 at the account root **and** is the smallest —
because distribution/durability/revocation already exist and it touches **zero** membership wire.

Confidence: the shape is **CONFIRMED** against real source (every seam cited, three-lens refute
reconciled). The one **PLAUSIBLE** axis is the sticky-trust liveness rule (§4.4) — correct by
construction here, proven by Phase-4 DST before the verify gate lands.

---

## 4. Decision & contract (§2.4)

**Chosen: Design C — account-key residence proof over ENTITY_PROP.**

### 4.1 Module boundaries (new/changed; each ≤ ~200 lines)
| File | New/changed | Single responsibility |
|---|---|---|
| `src/proto/account_identity.zig` | changed (+~80) | Add the **residence** transcript + `signResidence`/`verifyResidence`: canonical length-prefixed `{magic "ARP1", account, node:u64(shortId), epoch:u64, expiry_ms:u64}`, own domain label, `verifyStrict`. Structural-parse-before-crypto (copy `oper_cred_share` shape). Std-only, allocation-free. Lives here because it reuses the identity key + hex helpers. |
| `src/daemon/server.zig` | changed | (a) new command **`IDENTITY RESIDENCE <node-shortId> <epoch> <expiry_ms> <sig-hex>`**: account-gated, `verifyResidence` against the caller's own replicated `identity.key.*` pubkey, store as prop `identity.residence.<node>` and `propagateLocalEntityProp`; (b) **`verifyResidenceTrust(account, ev.origin_node, now)`** helper → the per-claim `bool`; (c) tombstone the residence prop on the client's session close (§4.3); (d) advertise an ISUPPORT token so onyx knows the daemon supports it. |
| `src/substrate/undertow/s2s_peer.zig` | changed | In `recvMembership`/`recvNickChange`, compute `account_trusted = server.verifyResidenceTrust(ev.account, ev.origin_node, now)` **only when the frame passed `verifiedPayload`** (origin-authenticated), and pass it to `resolveIncomingNick`. On `false`, pass `account = ""` (belt-and-braces so no downstream path trusts the wire account). |
| `src/substrate/undertow/route_table.zig` | changed (−1 const) | No signature change (already takes `account_trusted`). Delete the `wire_account_trusted` const; the value now flows from the verifier. Enforce the **sticky-trust** rule in §4.4 at the same-node re-affirm path. |
| onyx `src/lib/e2ee/deviceSign.ts` | **new** | Device Ed25519 signing key in `onyx-keys` (non-extractable); `enrollIdentity()` → `IDENTITY ADD`; `signResidence({account,node,epoch,expiry})` → `IDENTITY RESIDENCE`. Fail-closed (a sign error blocks the trusted path, never downgrades). |
| onyx `src/lib/irc/*` + `src/lib/store/*` | changed | On login (token advertised): enroll key if absent, learn the home node-shortId (from `001`/ISUPPORT), sign + send `IDENTITY RESIDENCE`; re-sign on reconnect-to-different-node / epoch change. |

### 4.2 Data contract (exact)
**Residence transcript** (account device key signs; verified vs the replicated `identity.key.*`
pubkey):
```
domain  = "ONYX-ACCOUNT-RESIDENCE-v1"       # DISTINCT from "ONYX-ACCOUNT-IDENTITY-v1",
                                              #   signed_frame's domain, and oper_cred_share "OCG1"
signed  = magic:u32("ARP1") || len8(account) || node:u64(shortId) || epoch:u64 || expiry_ms:u64
wire    = signed || sig:64                    # Ed25519 verifyStrict over signCtx(domain, signed)
```
**Carriage:** the `wire` bytes are the value of user PROP **`identity.residence.<node-hex>`**,
stored + replicated over the existing ENTITY_PROP path (`server.zig:24388` `setProp` +
`propagateLocalEntityProp`). **No membership-frame change.** Multi-device = one residence prop per
node (`identity.residence.<A>`, `identity.residence.<D>`), each independently verifiable.

**Verifier check order (fail-closed; ALL must pass or `account_trusted=false` AND `account=""`):**
1. The carrying MEMBERSHIP frame passed `verifiedPayload` (origin-authenticated; `origin_node` is
   pinned to `originShortId(frame.pubkey)`). If not (unsigned / `require_signed_frames` off for
   this link) → false.
2. Account `kain` has a replicated `identity.key.*` pubkey `P` in **this node's** prop replica
   (receiver-owned; **never** taken from any wire field). Absent → false.
3. A live residence prop `identity.residence.<ev.origin_node>` exists for `kain`; structural parse
   ok; `magic == "ARP1"`. Absent/malformed → false.
4. `verifyStrict(signCtx(domain, signed), sig, P)` succeeds. Fail → false.
5. `proof.account == ev.account` (casemap) **and** `proof.node == ev.origin_node`
   (== the frame's signed origin). A valid kain-proof-for-N cannot be reattached to a different
   node or account. Fail → false.
6. Freshness: `now_ms < proof.expiry_ms` (wall-clock), and reject `expiry_ms` beyond a hard max
   window (bounds the replay blast radius). Per-`(account, node)` monotonic **epoch floor** (copy
   `oper_cred_share.Registry` supersede, keyed by `(account, node)` so multi-device is preserved):
   reject `epoch <= last_accepted[(account,node)]`. Fail → false.
7. Per-claim result: `account_trusted = true`, pass `ev.account`. Else `account=""`.

### 4.3 Freshness, replay, revocation, session-lifetime
- **Non-home replay (the stated F1):** fully closed. B cannot produce a proof binding kain to B
  (no account key), and a genuine proof-for-N fails check 5 on B's frame (`proof.node=N ≠
  origin=B`).
- **Session-tied lifetime:** the home node **tombstones** `identity.residence.<node>` (a prop
  DEL + `propagateLocalEntityProp`) when kain's local session closes, so an honest home node stops
  vouching immediately; members then fall to UID on the next resolve. Inline on the client's
  shard — no timer.
- **Bounded home-node residual (deferred threat):** a *compromised* home node kain actually
  authenticated on can keep re-publishing kain's current proof until `expiry_ms`. This is the
  **compromised-home-node** class (out of scope for F1) and is bounded by a short `expiry_ms`
  (recommend ≤ 30 min; re-signed at login/epoch, not per frame, so the TTL can comfortably exceed
  clock skew). It grants that node nothing it does not already hold (it terminates kain's
  DMs/metadata anyway). Documented, bounded, not F1.
- **Revocation currency:** the pubkey source is the **current** prop value (ENTITY_PROP LWW + DEL
  tombstone), **not** an MMR inclusion proof — so `IDENTITY DEL` (or a superseding ADD) revokes
  immediately on convergence; a stale proof then fails check 2/4. (This is why the design does
  **not** use the KT log as the source: an inclusion proof proves membership, not currency.)
- **Clock skew:** verifier uses its own wall clock; skew only affects **initial** admission
  (verifier-ahead → brief UID until re-converge; verifier-behind → wider replay window, bounded by
  the home-node-only residual + epoch floor + hard-max window). Sticky trust (§4.4) means skew
  never tears down an **established** member.
- **Unenrolled / pre-convergence:** no pubkey or no proof yet → false → conservative UID (safe),
  self-healing on the next re-burst after prop convergence.

### 4.4 The sticky-trust rule (liveness vs value — the load-bearing correctness requirement)
The residence proof gates the **initial same-account coexist admission**, **not** continuous
membership. Concretely:
- `resolveIncomingNick` already returns `.keep` for a re-affirm from the **same node**
  (`route_table.zig:504` `if (incumbent.node_id == node) return .keep`) — **independent of
  `account_trusted`.** So a periodic re-burst of an already-established remote member does **not**
  re-run the account gate and a late/expired proof **cannot** rename a live established member.
  This is what preserves the liveness-vs-value split.
- `account_trusted` therefore only bites on a **new** cross-node/local *collision* decision (the
  `sameAccount` short-circuits at `:487,510`). Trust admits the member into coexistence; departure
  is the existing **local-clock staleness GC** (orthogonal, unchanged).
- **Must-implement + must-DST:** Phase 3 must not add any path where an established member's
  continued presence is gated on a *fresh* proof; Phase 4 DST proves a genuine multi-device member
  survives a partition/USR2 that delays its proof refresh (no mid-session UID rename). This is the
  one HIGH; its owner is onyx-server-mesh and its gate is onyx-server-dst.

### 4.5 Client↔daemon carriage & deploy ordering
- **client→home-daemon (`IDENTITY ADD`, `IDENTITY RESIDENCE`):** onyx-visible. The **daemon
  advertises** an ISUPPORT token; onyx sends these only when advertised — ordinary CAP/ISUPPORT
  discipline (**daemon advertises first**, client uses when advertised). Because the server emits
  *nothing new to the client* (proofs flow up, then node→node as prop replication), the
  "server→client wire change ⇒ client-first" rule does not apply here. An old onyx simply never
  enrolls ⇒ its account stays on the conservative UID path (safe).
- **daemon↔daemon:** **no new S2S wire** — the proof is an ordinary `identity.residence.*` prop on
  the ENTITY_PROP path an old/mid-USR2 peer already speaks. A peer that predates the residence
  convention simply carries the prop opaquely (it is just another user prop) and never verifies —
  it stays on the conservative UID path locally. No cap bit, no capsule bump, no mixed-fleet
  hazard.

---

## 5. Phased build order & ownership (§2.5)

Each phase compiles, gates on its own suite, and is **no-op when off**.

| Phase | Deliverable | Gate | Owner | No-op-when-off |
|---|---|---|---|---|
| **0 (live now)** | Keep the conservative `wire_account_trusted=false` fix deployed as the baseline. | — | onyx-server-deploy (already) | This IS the safe baseline. |
| **1** | Residence transcript + `signResidence`/`verifyResidence` in `account_identity.zig` (KATs: domain separation, replay/binding, verifyStrict rejects malleable, every failure ⇒ error). Pure, unwired. | `zig build test` | zig-coder → **onyx-server-crypto-reviewer** gate | Unreferenced additions; zero runtime effect. |
| **2** | `IDENTITY RESIDENCE` command + prop store/tombstone + ISUPPORT advertise. No verify wiring in the mesh yet. | `zig build test` | zig-coder + **onyx-server-ircx** (command surface) | No client sends RESIDENCE ⇒ no residence prop ⇒ inert. |
| **3** | `verifyResidenceTrust` + wire it into `recvMembership`/`recvNickChange` as the per-claim `account_trusted` (gated on `verifiedPayload`); drop the `wire_account_trusted` const; implement + assert the **sticky-trust** rule (§4.4). | `zig build test-mesh` | **onyx-server-mesh** (implement) → **onyx-server-mesh-reviewer** gate | No residence prop present ⇒ `false` ⇒ today's conservative behavior, byte-identical membership wire. |
| **4** | DST: seeded convergence-after-partition + USR2-under-fault proving (a) a forged/non-home claim is UID-homed, (b) a genuine 3rd-node multi-device claim coexists, (c) a partition/USR2 that delays a proof refresh does **NOT** rename a live established member (sticky trust), (d) a cold/pre-convergence node falls to UID, never false-accepts. | `zig build test-mesh` (seeded) | **onyx-server-dst** | Test-only. |
| **5** | onyx: `deviceSign.ts` (device Ed25519 in `onyx-keys`), enroll on login, sign + `IDENTITY RESIDENCE` on join / node-change, gated on the advertised token; fail-closed. | `pnpm typecheck/lint/test` | **onyx-crypto** + solidjs-coder | Token not advertised ⇒ onyx never enrolls ⇒ UID path. |

**Cross-repo deploy ordering:** Phases 1–4 are daemon-only and inert; they may land on `main` and
even deploy (no-op) ahead of onyx. The feature turns on for an account only after Phase 5 onyx
ships **and** that account enrolls a key **and** its home node runs Phase 2+3 — so there is **no
window where F1 reopens**; unenrolled accounts stay on the conservative UID path throughout. onyx
stays **local-only**; any Onyx Server node deploy/USR2 is **human-gated** → onyx-server-deploy.

---

## 6. Risks, failure modes, rollback (severity-tagged)

| # | Sev | Scenario: inputs → what goes wrong → blast radius | Owner / mitigation |
|---|---|---|---|
| R1 | **HIGH** | **Liveness/value coupling.** If Phase 3 gates an *established* member's continued presence on a *fresh* proof, a partition/USR2/loss that delays the refresh renames a live multi-device member to a UID mid-session — the forbidden coupling. inputs: delayed proof refresh → true→false flip → `.rename_to_uid` → live device UID-renamed. blast radius: every logged-in multi-device user on every deploy/partition. | onyx-server-mesh implements the **sticky-trust** rule (§4.4: same-node re-affirm is `.keep` independent of `account_trusted`); **onyx-server-dst** proves it (Phase 4c). This is the gating HIGH — do not land Phase 3 without 4c green. |
| R2 | MEDIUM | **Compromised-home-node replay within expiry.** A node kain authenticated on, if Byzantine, re-publishes kain's current proof until `expiry_ms` after kain leaves. inputs: home node keeps vouching → phantom-kain homed to that node until expiry. blast radius: bounded to a node kain actually used (out-of-scope compromised-home class), bounded by TTL. | Short `expiry_ms` (≤30 min, config); session-close tombstone for honest nodes; epoch floor. Documented as the deferred threat, not F1. |
| R3 | MEDIUM | **Pre-convergence / cold node.** A membership claim for kain arrives before kain's `identity.key.*`/residence props have replicated → `false` → kain briefly UID-disambiguated until convergence. inputs: cold/healed node, props in flight → temporary UID for a genuine multi-device claim. blast radius: transient, self-healing on the next re-burst after convergence. | Rides the same prop-convergence the mesh already depends on (channel props, etc.); re-burst re-runs `resolveIncomingNick`. Sticky trust means only the *initial* coexist is delayed, never an established member. Phase-4d DST bounds it. |
| R4 | MEDIUM | **TTL vs re-sign cadence / clock skew.** Too-short TTL or verifier-ahead skew → genuine initial claims briefly hit UID. | TTL ≥ 2× the client re-sign interval + expected skew; login-time signing (not per-frame) lets TTL be generous. Config knob (onyx-server-config). |
| R5 | LOW→CRITICAL-if-mishandled | **Fail-open regression.** A future edit takes the pubkey from the wire proof, or returns `true` on a decode/lookup error, or trusts an unsigned frame. | Pubkey is **receiver-owned replicated prop only** (check 2); `true` only on the single all-checks-pass branch; residence trust requires `verifiedPayload` non-null (check 1). KAT asserts every failure ⇒ `false`. onyx-server-crypto-reviewer gates Phases 1–3. **Designed closed.** |

**Rollback:** revert Phases 3→2→1 independently (each no-op-when-off); or restore
`wire_account_trusted` to a const `false` to return to the conservative baseline instantly with no
wire change (nothing on the wire changed in the first place).

---

## 7. Refute pass (§2.6) — reconciliation

Three fresh adversarial reviewers ran against the requirement + targets + first-draft decision
(not the rationale): a **Skeptic** (partition/USR2), a **Minimalist** (60%-less), and a
**Security** reviewer (fail-open/replay/confusion). Every surviving objection and its disposition:

| Objection (lens) | Verdict | Disposition |
|---|---|---|
| **No pubkey to verify against; KT stores digests, not keys, and doesn't replicate** (Skeptic #1, Security H1 — both **CONFIRMED**) | **Design-changing** | *Adopted.* The pubkey source is the **receiver-owned, ENTITY_PROP-replicated `identity.key.*` prop** (`server.zig:24388`), **never** the KT log and **never** the wire. KT is not used by F1. This was a first-draft muddle; corrected. |
| **USR2 collapses the feature network-wide** (Skeptic #2, CONFIRMED against a *membership-block/KT-cache* design) | **Design-changing** | *Adopted.* No wire block, no cap bit, **no capsule bump**, no per-session cache — the proof is a **durable, replicated prop** (`server.zig:2974`) that survives USR2 and re-converges like all prop state. The collapse premise is removed. |
| **oper_cred_share (Design B) does not close F1** (Minimalist, CONFIRMED via `applyMeshGrant` `server.zig:22793` accepting any admitted peer's signature for any account) | Accepted | B rejected; the trust root sits at the account, not the node. |
| **Per-frame signing / new codec / cap bit / capsule bump are gold-plating** (Minimalist) | Accepted | Dropped all four; login-time signature over ENTITY_PROP; reuse `account_identity` + `oper_cred_share` freshness shape. |
| **Liveness-vs-value: a late refresh renames a live member** (Skeptic #4, CONFIRMED) | **Design-changing** | *Adopted* as the **sticky-trust** rule (§4.4) + the gating HIGH R1 + Phase-4c DST. The same-node `.keep` at `route_table.zig:504` is the mechanism. |
| **Bearer-token replay within expiry after the user leaves node N** (Skeptic #3, Security H4, CONFIRMED) | Bounded/accepted | Session-close tombstone (honest nodes) + short expiry + `(account,node)` epoch floor. Residual is the **compromised-home-node** class (R2), out of scope for F1, bounded by TTL. |
| **Must require origin-authenticated (signed) frame + `proof.node == frame.origin`** (Security H3, CONFIRMED-as-gap) | Accepted | Check 1 (gated on `verifiedPayload`) + check 5 (node binding). Fails closed when `require_signed_frames` off. |
| **Domain separation / length-framing / verifyStrict** (Security H5) | Accepted | Distinct `"ONYX-ACCOUNT-RESIDENCE-v1"` domain + magic `"ARP1"`, length-prefixed fields, `verifyStrict`. |
| **Per-claim match, not frame-global** (Security H6) | Accepted | `account_trusted` is per-claim; check 5 matches `proof.account/node` to the exact roster entry; `account=""` forced on false. |
| **Revocation currency ≠ MMR inclusion** (Security H2) | Dissolved | Source is the current prop value (LWW + DEL), not an inclusion proof. |
| **Reactor-0 guard on any cache prune** (Skeptic #7) | Dissolved/answered | No cache; session-close tombstone is inline on the client shard; any future sweep is reactor-0 (§1.4). |
| **Positional block #5 forces empty oper-info slots** (Skeptic #8) | Dissolved | No membership block at all. |
| **Re-verify-on-convergence hook missing** (Skeptic #6, my R3) | Bounded/accepted | Re-burst re-runs `resolveIncomingNick`; sticky trust means only initial coexist is delayed. Phase-4d DST bounds it. |

**CONFIRMED design properties:** fail-closed verify order (checks 1–7), account-rooted trust
(defeats non-home forgery), no membership wire change, USR2-safe via durable props.
**PLAUSIBLE (proven by DST, not by argument alone):** the sticky-trust liveness rule (R1) and the
pre-convergence recovery bound (R3) — both gated behind Phase-4 seeds before Phase-3 mesh wiring is
trusted.

### What I did NOT check / assumptions
- I did **not** run `zig build` — this is design, not code.
- I assume `IDENTITY ADD`/`RESIDENCE` are reachable over the current CAP/ISUPPORT surface; Phase 2
  confirms the advertisement wiring (onyx-server-ircx).
- I assume the ENTITY_PROP burst re-delivers `identity.residence.*` on RESYNC/anti-entropy exactly
  as it does `identity.key.*` (same code path); Phase-4 DST is the proof.
- I assume `route_table.zig:504` same-node `.keep` fully covers the established-member re-affirm
  path so no established member is ever re-gated — **Phase 3 must verify this holds for the
  `reclaim_local`/status-change edges too**, or add an explicit "established ⇒ keep" guard.

---

## 8. Design verdict

**GO** — no open CRITICAL (the fail-open path is designed closed against the receiver-owned
replicated pubkey; no membership wire change; USR2-safe via durable props; the multi-reactor,
shortId, deploy-order, and fail-closed guard-rails all answered). **One HIGH (R1, sticky-trust
liveness)** with a named owner (onyx-server-mesh) and a hard gate (onyx-server-dst Phase-4c) — Phase 3 must
not land without it. MEDIUMs (R2 bounded home-node residual, R3 pre-convergence, R4 TTL/skew) are
owned and bounded.

**Ship reminder:** the conservative `wire_account_trusted=false` fix stays live as the baseline;
this proper fix is **all follow-up**, landing no-op-when-off phase by phase, and only restores
multi-device once the daemon groundwork (Phases 1–3) and the onyx signer (Phase 5) are both
deployed and accounts enroll keys.
