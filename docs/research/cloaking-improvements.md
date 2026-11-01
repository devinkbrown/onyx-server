# Onyx Server Host-Cloaking — Prioritized Improvement Brief

> **Superseded / historical — preserved as evidence.** This document is a point-in-time record and does not describe the current source or fleet. Current truth: [docs hub](../README.md) and [production paths](../ops/onyx-server-paths.md). Do not execute it as a current procedure.


Research brief · 2026-07-11 · analyst: deep-researcher · scope: `src/proto/cloak.zig`,
key derivation in `src/main.zig`, `applyVisibleHost`/`prevKeyCloakHost` in
`src/daemon/server.zig`, the Guise vHost system (`src/daemon/guise.zig`,
`host_request.zig`), the WARD facets (`src/daemon/warden.zig`), and adjacent
privacy plumbing (`dnsbl_resolver.zig`, `ip_reputation.zig`, `crypto/argon2_kdf.zig`).

> **In-scope caveat.** Two HIGH audit findings — (a) the per-boot/per-node *default*
> cloak key breaking federation + ban persistence, and (b) VHOST `CLAIM` lacking account
> binding — already have fixes in progress and are **deliberately excluded** here. This
> brief is everything *beyond* those.

---

## BLUF

**Onyx Server's cloak is already on the correct side of IRCd history — the improvement
opportunities are about the *policy layer* around a fundamentally-sound primitive, not
the primitive itself.** The single highest-value change is to **split cloak policy by
authentication state**: give logged-in users the stable, moderatable account cloak (already
built) and give *anonymous* users an **opaque, epoch-rotated cloak by default**, then move
abuse control up to account bans + registration friction. This is the exact balance the
mature field (Libera, InspIRCd v4, UnrealIRCd 6) converged on, and it directly retires
Onyx Server's two structural privacy weaknesses — *forever-linkability* of a static-IP anonymous
user and *subnet co-membership leakage* — without weakening moderation.

- **Likelihood this assessment is correct:** *very likely (80–95%)* — every "what exists"
  claim was read in Onyx Server source at file:line; every "state of the art" claim was
  triangulated against primary vendor docs and, where possible, the daemons' own source.
- **Analytic confidence:** *High* on what Onyx Server does today and on the account-ban
  direction (multiple primary IRCd sources agree); *Moderate* on specific tunables (epoch
  cadence, tier depth) — those are policy tradeoffs with no authoritative "correct" value.

Two axes kept separate throughout: **likelihood** a claim is true (calibrated word) vs.
**evidence quality** (High/Med/Low confidence).

---

## §0 — What Onyx Server already does WELL (VERIFIED, read in source)

Do not regress these; they are genuinely ahead of most of the field.

- **Keyed HMAC-SHA256 PRF, not an unkeyed or broken hash.** `macTag` = `HMAC-SHA256(key,
  domain‖data)` (`cloak.zig:356-365`). This matches the modern consensus (InspIRCd v4
  `cloak_sha256`, UnrealIRCd 6 `cloak_sha256.c`) and is strictly stronger than
  Solanum/Charybdis, whose `ip_cloaking.c` uses **unkeyed FNV** — a network-independent,
  offline-reproducible obfuscation with no anonymity value (VERIFIED, Solanum source per
  researcher). It also beats the deprecated InspIRCd v3 / old-UnrealIRCd **truncated-MD5**
  modes that motivated CVE-2004-0679 (weak IP-cloak hashing → brute-force recovery).
- **Versioned per-family domain tags** (`ip4/v2/32|`, `ip6/v2/64|`, `ip4/v2/opq|`, …,
  `cloak.zig:191-232`) give clean **key-separation across token families** — a principled
  version of what UnrealIRCd hand-rolls with its three-key envelope.
- **64-bit collision-resistant full token** (`token64`, `full_token_hex_len = 16`,
  `cloak.zig:47-51,349-353`) — deliberately widened from 32-bit to push birthday collisions
  past 4 billion addresses. This is *wider* than UnrealIRCd's `downsample()`-to-32-bit and
  InspIRCd's truncated segments, so Onyx Server bans are more collision-precise.
- **Hierarchical subnet coherence + ban-able geo/ASN labels** (`cloakIPv4`/`cloakIPv6` +
  `appendGeo`, `cloak.zig:180-321`): `*.us.ip.<net>` bans a country, `*.a13335.*` bans an
  ASN, all without exposing the address. Strong moderation surface.
- **Rotation grace via `previous_secret` dual-match** (`prevKeyCloakHost`,
  `server.zig:5816-5831`; `enforceWard` fallback) — this solves the *exact* ban-continuity
  failure UnrealIRCd's docs warn about ("rotation makes all bans on cloaked hosts
  ineffective").
- **Key hygiene + oper-gated deanonymization**: key bytes `secureZero`'d after every use
  (`cloak.zig:356-364`); real IP/geo/certfp ride **only the secured mesh leg** to oper
  requesters (`docs/reference/host-cloaking.md` §"Cross-mesh operator view").
- **Opaque max-privacy mode already exists** (`cloakOpaque`, `cloak.zig:160-174`) — the
  primitive P0 needs is already in the tree.

---

## §1 — The core structural weakness (context for the priorities)

A deterministic keyed cloak is a **confirmation oracle, not a confidentiality primitive**
(VERIFIED — UnrealIRCd docs state a known key lets an attacker "brute force the original
host"; DerbyCon "Uncloaking IP Addresses on IRC" shows identical cloak ⇒ identical source
IP, harvested via WHOIS/WHOWAS). Two consequences that Onyx Server inherits by construction:

1. **Forever-linkability.** `cloak = HMAC(key, IP)` is deterministic (by design —
   `docs/reference/host-cloaking.md:22`), so a static-IP anonymous user carries **one stable
   pseudonym across every channel and session indefinitely**, even though the raw IP stays
   masked.
2. **Subnet co-membership leak.** The hierarchical chain publishes tokens over *cumulative
   prefixes* (`<f/32>.<t/24>.<t/16>.<t/8>`). Shared coarse tokens reveal *which users are on
   the same /24, /16, /8*, and each coarser token is a PRF over a **smaller preimage space**,
   so the online confirmation attack (guess an IP, recompute, compare) gets cheaper the
   coarser you go: confirming a /24 is ≤256 guesses (INFERENCE from PRF-preimage sizing,
   Moderate confidence).

The accepted field tradeoff is that hierarchical cloaks *intentionally* leak subnet
co-membership because that is the exact property that makes wildcard subnet bans work — and
the privacy-maximal alternative (opaque) is offered opt-in and loses subnet bans. Onyx Server
already implements both forks; the improvement is to **choose the fork by who the user is**.

**One myth to kill (VERIFIED reasoning):** shortening the token does **not** buy privacy —
it does not defeat the online oracle (the attacker recomputes the short token from a guessed
IP just as easily) and it *breaks ban precision* via collisions. Onyx Server's 64-bit choice is
correct; keep it.

---

## P0 — Highest value

### P0-1 — Split cloak policy by auth state: opaque + epoch-rotated for anonymous, stable account cloak for logged-in  ⭐ single highest-value change

- **Improvement.** Logged-in clients keep the stable `<account>.users.<suffix>` account
  cloak (already built). **Anonymous** (unauthenticated) clients default to the **opaque**
  form *and* mix a **rotating server epoch salt** into the HMAC, so an anonymous user is
  neither linkable across epochs nor leaks subnet co-membership. Pair with a policy stance:
  moderation of anonymous abuse moves to **account bans + registration friction**, not host
  tracking.
- **Why.** This is the mature balance the whole field converged on (VERIFIED): Libera uses a
  durable per-account cloak (`user/<account>`) that is banned *by account*, applies it
  **SASL-before-visible**, and leans on verified-email/account-age gates. It simultaneously
  fixes both §1 weaknesses for the population that most needs privacy (anonymous users) while
  keeping a *stronger* moderation handle (the account) for everyone who logs in.
- **Maps to cloak.zig.** The selection lives in `applyVisibleHost` (`server.zig:5739-5789`),
  whose order is already account → opaque → hierarchical. Change: when **no account** and
  the client is anonymous, route to `cloakOpaque` (already exists, `cloak.zig:160`) instead
  of hierarchical, and thread a new `epoch: u64` (or a 16-byte epoch salt) into the HMAC
  domain — e.g. extend `macTag`/`token64` to fold an epoch tag (`"ip4/v2/opq/e<N>|"`).
  Account cloaks stay epoch-free (they *are* the durable identity). `cloakAccount`
  (`cloak.zig:292`) is untouched.
- **Security tradeoff.** Host-based tracking of an anonymous abuser weakens **by design** —
  you can no longer follow "that guy" across reconnects by host. That is the same bit as
  "anonymous users are unlinkable"; you cannot have both. The answer is account bans +
  registration friction (P0-3). Also: opaque anon cloaks are **not subnet-bannable**, so an
  op facing an anon flood from one subnet must fall back to the geo/ASN labels or a
  connect-class rule — acceptable, and arguably better than a subnet ban that catches
  innocents.
- **Effort.** **M.** Most primitives exist (opaque, account cloak, the selection point). Net
  work: an epoch-salt parameter through `macTag`/`token*`, an epoch clock + rotation knob,
  and the auth-state branch in `applyVisibleHost`. Note the epoch salt is the *same shape* as
  the existing per-boot random key and the `deriveCloneKey` salt (`server.zig:5837`), so the
  plumbing pattern is already in the codebase.

### P0-2 — Harden cloak-key derivation: full-entropy key or argon2id, with per-purpose HKDF subkeys

- **Improvement.** Replace the bare `SHA256([cloak] secret)` derivation (`main.zig:465,472`)
  with: **(a)** if the operator supplies a passphrase, run it through **argon2id** (already
  in-tree: `crypto/argon2_kdf.zig`, default t=2/m=64 MiB) before it becomes HMAC key
  material; **(b)** better, follow the mature IRCds and *generate/require a full-entropy
  random key* (à la UnrealIRCd `gencloak`), refusing short/low-entropy secrets; **(c)** derive
  the primary, previous, and epoch-salt keys as **separate subkeys via HKDF** from one master
  with distinct `info` labels, rather than independent SHA256 calls.
- **Why.** `SHA256(passphrase)` over a low-entropy operator-chosen passphrase is
  offline-brute-forceable (VERIFIED direction; the whole cloak security model rests on key
  secrecy because the IPv4 input space is fully enumerable). The mature daemons sidestep this
  by **refusing passphrases** — InspIRCd enforces a 30-char minimum key; UnrealIRCd mandates
  three ≥80-char *random* keys via `gencloak` (VERIFIED from their source per researcher).
  Onyx Server currently accepts an arbitrary passphrase and single-hashes it — the one place the
  design is weaker than the field.
- **Maps to cloak.zig.** Derivation is in `main.zig:459-490`, not `cloak.zig` — `cloak.zig`
  just consumes a `SecretKey`. Add a `keygen` path to the `onyx-server` CLI and a
  boot-time entropy/length check; swap the two `Sha256.hash` calls for argon2id-or-HKDF. The
  `deriveCloneKey` pattern (`server.zig:5837`, domain-tagged SHA256 → stable mesh-wide key) is
  the template for the HKDF `info`-label separation.
- **Security tradeoff.** Argon2id adds a one-time boot cost (tens of ms) — negligible.
  Requiring a random key is a small operator-UX friction (they must run `keygen`), repaid by
  removing the offline-brute-force path. No wire/ban impact if the *derived* key is unchanged
  for existing deployments (gate the new derivation behind a config version to avoid silently
  invalidating live bans).
- **Effort.** **S–M.** argon2id already exists; the work is CLI keygen + entropy validation +
  wiring, and a migration guard so the derivation change does not orphan existing cloaks.

---

## P1 — High value

### P1-3 — Account-first moderation + registration friction (the other half of P0-1)

- **Improvement.** Make account-facet bans first-class and mesh-portable (WARD already has an
  `account` facet, `warden.zig:31,152`), and add connect-class friction knobs:
  **SASL-before-visible** (apply the account cloak *before* the client is joinable, Libera's
  model), plus optional verified-email / account-age gates before an anonymous client may
  speak or before anon restrictions lift.
- **Why.** P0-1 deliberately makes the anonymous host a weak/rotating handle; that only works
  if the durable, moderatable identity is the **account** and creating a fresh account has
  real cost (VERIFIED — this is Libera's entire model). Without friction, opaque+rotating anon
  cloaks would just be free ban evasion.
- **Maps to cloak.zig.** No `cloak.zig` change. Touches the registration/auth path
  (`applyVisibleHost` re-apply on login already exists via `maybeApplyAccountCloak`,
  `server.zig:27311`) and WARD account-ban propagation across the mesh.
- **Security tradeoff.** Friction raises the barrier for legitimate new anonymous users too;
  keep gates configurable and off-by-default so small networks aren't forced into it.
- **Effort.** **M.** Partly present (WARD account facet, account-cloak re-apply); the friction
  knobs and SASL-before-visible ordering are the net-new work.

### P1-4 — DNSBL / Tor-DNSEL "mark" path + coarse origin-class cloak label (tor/vpn/dc)

- **Improvement.** At registration, run **non-blocking** lookups against DroneBL
  (`<rev-ip>.dnsbl.dronebl.org`), the Tor exit DNSEL (`<rev-ip>.dnsel.torproject.org` → A
  `127.0.0.2`), and classify hosting/VPN origin from the **ASN Onyx Server already resolves**. Add
  a **`mark`** action (not just refuse) that routes the connection into a restricted
  connect-class and appends a coarse origin-class label — `tor` / `vpn` / `dc` — to the cloak
  tail, reusing the existing `appendGeo` label machinery. Optionally require SASL for `tor`.
- **Why.** This is the mainstream mechanism (VERIFIED — InspIRCd `dnsbl` module supports
  `gline`/`zline`/`kill`/**`mark`**; Libera gates its Tor onion behind pubkey SASL). It gives
  ops a *moderation signal* ("this is a Tor/hosting connection") that is ban-able as a class
  (`*.tor.*`) and drives policy, while leaking **no raw address** — exactly the anonymity-vs-
  moderation sweet spot. Onyx Server has the DNSBL resolver (`dnsbl_resolver.zig`) but its verdict
  currently only *refuses/network-bans*; it does not feed the cloak or offer a mark path, and
  there is **no Tor detection at all** today (VERIFIED, grepped).
- **Maps to cloak.zig.** Add an optional origin-class field to `Geo` (or a sibling struct) and
  a label emitter alongside `appendGeo` (`cloak.zig:313-321`) — same insertion point, between
  the IP tokens and the `ip`/`ip6` marker, so the class is ban-able and geo-independent. The
  lookups themselves live in the daemon (`dnsbl_resolver.zig` + a new Tor-DNSEL zone).
- **Security tradeoff.** DNSBL/DNSEL lookups add a registration-time dependency — they **must**
  be async/bounded so a slow list never stalls the reactor (the resolver is already off the
  accept path — preserve that). Marking (vs. dropping) is the right default: it avoids
  collateral bans on shared Tor/VPN exits while still enabling policy.
- **Effort.** **M–L.** New Tor-DNSEL zone + classification + mark action + connect-class
  routing + the cloak label. Route config schema to `onyx-server-config`, async lookup path to
  `zig-coder`.
  *Named gap:* confirm the live Tor DNSEL zone/response codes against a real query before
  wiring — Tor has changed this service before (the `127.0.0.2` reply is SINGLE-SOURCE + blog,
  Moderate confidence). There is **no canonical VPN/datacenter DNSBL**; VPN/DC classification
  is ASN-based inference, not a list.

### P1-5 — Generalize rotation to key epochs + atomic mesh rotation signal

- **Improvement.** `previous_secret` already gives a *single* dual-match grace window
  (`prevKeyCloakHost`, `server.zig:5816`). Generalize to an **epoch ring** (N recent keys
  matched during overlap) and add an explicit **network-wide rotation signal** over the
  secured S2S leg so all nodes swap atomically, avoiding the "users join through bans" desync
  UnrealIRCd documents. Derive the shared cloak key from the mesh secret with a domain tag —
  the `deriveCloneKey` pattern (`server.zig:5837`) — so federation agreement is automatic.
- **Why.** Rotation is the primary mitigation for a leaked key *and* the P0-1 anon-epoch
  mechanism, but naive rotation nukes every ban and desyncs the mesh (VERIFIED — UnrealIRCd
  requires identical keys+prefix on all nodes). A proper epoch ring + atomic swap makes
  rotation a safe, routine operation instead of a break-glass event. (This *extends* the
  in-progress federation-key fix rather than duplicating it.)
- **Maps to cloak.zig.** `cloak.zig` is already epoch-agnostic (keys are opaque inputs); the
  work is in the key-management layer (`main.zig` derivation + `server.zig` WARD fallback loop
  over N keys instead of one) and the S2S control plane.
- **Security tradeoff.** More retained keys = a slightly larger window in which an old
  captured (IP→cloak) pairing still matches. Bound the ring (e.g. 2–3 epochs) and document the
  cadence as a **policy knob**, not a security constant (Moderate confidence — no authoritative
  interval exists).
- **Effort.** **M.**

---

## P2 — Worthwhile, lower urgency

### P2-6 — Make IPv4/IPv6 tier depth configurable; consider dropping the coarsest tiers

- **Improvement.** Onyx Server exposes **4 IPv4 tiers** (/32,/24,/16,/8) and **5 IPv6 tiers**
  (/128,/64,/56,/48,/32) — more than InspIRCd v4 (3 IPv4 tiers) or UnrealIRCd (3). Each extra
  coarse tier is additional subnet co-membership leakage and another (cheap) confirmation-
  oracle rung for marginal ban utility (a `/8` ban is a rare, blunt instrument). Make tier
  depth configurable and consider defaulting IPv4 to /32,/24,/16.
- **Why.** Shrinks the §1 oracle/leak surface at near-zero moderation cost. (INFERENCE on the
  cost/benefit; the tier counts are VERIFIED in `cloakIPv4`/`cloakIPv6`.)
- **Maps to cloak.zig.** `cloakIPv4` (`cloak.zig:180-209`) / `cloakIPv6` (`216-249`) emit a
  fixed tier set; parameterize the prefix list.
- **Security tradeoff.** Fewer subnet-ban granularities for ops. Keep it configurable so
  networks that rely on /8 or fine IPv6 bans can opt in.
- **Effort.** **S.**

### P2-7 — Harden the oracle *surface*, not just the hash

- **Improvement.** The historical de-anon wins came from side channels, not hash breaks
  (VERIFIED — oper WHOIS, DCC/CTCP IP leaks, SASL-before-join gaps, and services ban/unban
  enumeration oracles). Rate-limit bulk WHOIS/WHOWAS, keep WHOWAS carrying only the **cloaked**
  host (verified today: `whowas.zig` stores the visible host, not raw IP — preserve that), and
  audit any DCC/CTCP/services path that could pair a nick to an IP.
- **Why.** A perfect cloak with a leaky DCC or ban-enumeration path is still de-anonymizing.
- **Maps to cloak.zig.** None — this is command-surface hardening across the daemon.
- **Security tradeoff.** WHOIS rate limits slightly inconvenience power users/bots. Minor.
- **Effort.** **M** (spread across several command handlers).

### P2-8 — Activate the Guise `verified` provenance seam (domain-verified personas)

- **Improvement.** `guise.zig` already reserves `Source.verified` (`guise.zig:30`) but nothing
  populates it. Add DNS-TXT (or well-known) domain-control proof so a user can bind a persona
  to a domain they actually own. This gives a *cryptographically-grounded* apparent identity
  that reduces reliance on the IP cloak for trust.
- **Why.** Strengthens the "identity is the account/persona, not the host" direction that P0-1
  and P1-3 depend on. Provenance is already auditable (`Source.token`); this fills the one
  unused rung.
- **Maps to cloak.zig.** None — Guise + a verification helper.
- **Security tradeoff.** Verification adds a challenge/proof flow; keep it opt-in and
  oper-gated for the offer templates.
- **Effort.** **M.**

### P2-9 — Documentation guard: record the "keep the 64-bit token" reasoning

- **Improvement.** Add a note to `docs/reference/host-cloaking.md` explaining *why* the full
  token is 64-bit and must not be shortened "for privacy" (§1 myth: truncation does not defeat
  the online oracle and breaks ban precision), so a future optimizer doesn't regress it.
- **Effort.** **S.** Route to `doc-writer`.

---

## Prioritized summary

| # | Change | Priority | Effort | Primary win |
|---|---|---|---|---|
| P0-1 ⭐ | Auth-split: opaque+epoch-rotated anon cloak, stable account cloak logged-in | P0 | M | Retires forever-linkability + subnet leak for anon users |
| P0-2 | argon2id / full-entropy key + HKDF subkey separation | P0 | S–M | Removes offline key-brute-force path |
| P1-3 | Account-first bans + registration friction (SASL-before-visible) | P1 | M | Makes P0-1's weak anon handle safe |
| P1-4 | DNSBL/Tor-DNSEL `mark` + origin-class cloak label | P1 | M–L | Moderation signal without IP exposure |
| P1-5 | Key epochs + atomic mesh rotation | P1 | M | Safe routine rotation; federation agreement |
| P2-6 | Configurable / shallower tier depth | P2 | S | Shrinks oracle + leak surface |
| P2-7 | Oracle-surface hardening (WHOIS/WHOWAS/DCC) | P2 | M | Closes the real historical de-anon paths |
| P2-8 | Guise `verified` domain-proof personas | P2 | M | Identity grounded off the IP cloak |
| P2-9 | Doc guard: keep 64-bit token | P2 | S | Prevents a future regression |

---

## Named gaps / what could NOT be verified

- **Live Tor DNSEL zone/response** (`dnsel.torproject.org` → `127.0.0.2`) is SINGLE-SOURCE +
  blog — confirm against a live query before wiring P1-4.
- **No canonical VPN/datacenter DNSBL** — VPN/DC classification is ASN-based inference, not a
  list; if a commercial feed is acceptable, P1-4's design changes.
- **Epoch/rotation cadence** (P0-1, P1-5) — a privacy-vs-ban-continuity policy tradeoff with no
  authoritative "correct" interval; stated as Moderate-confidence guidance, not fact.
- **Confirmation-cost quantification** (256/65k/16M per tier) is INFERENCE from standard
  PRF-preimage math, not a measured benchmark.
- **UnrealIRCd "why exactly three keys"** — key-separation reading is INFERENCE from source
  structure; no official rationale found.
- The recommendations assume the P0-1/P1-5 epoch-salt hook can thread through `macTag`/`token*`
  cleanly — a code-level pass should confirm the signature change is non-invasive.

---

## Sources

**Onyx Server (primary, in-repo, current):**
- `src/proto/cloak.zig` — HMAC-SHA256 engine, token widths, tiers, opaque, account cloak (read directly).
- `src/main.zig:459-490` — `SHA256([cloak] secret)` key derivation + random per-boot fallback + `previous_secret`.
- `src/daemon/server.zig:5739-5844` — `applyVisibleHost`, `cloakGeo`, `prevKeyCloakHost`, `deriveCloneKey`.
- `src/daemon/guise.zig` — persona provenance incl. unused `Source.verified`.
- `src/daemon/warden.zig` — WARD facets (host/mask/account/realname/certfp).
- `src/daemon/dnsbl_resolver.zig`, `ip_reputation.zig` — refuse-only DNSBL + behavior reputation (no cloak feed, no Tor).
- `src/crypto/argon2_kdf.zig` — in-tree Argon2id (t=2, m=64 MiB).
- `docs/reference/host-cloaking.md` — current cloak reference.

**State of the art (primary vendor docs / source, triangulated):**
- InspIRCd v4 `cloak_sha256` — HMAC-SHA256, tiered /32,/24,/16, ≥30-char key — https://docs.inspircd.org/4/modules/cloak_sha256/ and source `modules/cloak_sha256.cpp`.
- InspIRCd `dnsbl` — `gline`/`zline`/`kill`/**`mark`** actions, connect-class routing — https://docs.inspircd.org/4/modules/dnsbl/.
- InspIRCd v3 deprecated MD5 cloak — `src/modules/m_cloaking.cpp` (truncated keyed-prefix MD5).
- UnrealIRCd 6 `cloak_sha256.c` — SHA256, three ≥80-char random keys, `gencloak`; brute-force-if-key-known warning; identical keys+prefix required network-wide — https://www.unrealircd.org/docs/Cloaking, https://www.unrealircd.org/docs/Set_block.
- Solanum `extensions/ip_cloaking.c` — unkeyed FNV obfuscation (no anonymity control).
- Libera.Chat cloaks — account-based `user/<account>`, SASL-before-visible, verified-email auto-cloak; Tor onion requires pubkey SASL — https://libera.chat/guides/cloaks, https://libera.chat/guides/connect.
- Tor Project — exit-list DNSEL changes (A `127.0.0.2`) — https://blog.torproject.org/changes-tor-exit-list-service/.
- DroneBL — reversed-IP `.dnsbl.dronebl.org` A-record lookup — https://dronebl.org/docs/howtouse.
- CVE-2004-0679 — UnrealIRCd weak IP-cloak hashing → brute-force host recovery — https://www.cvedetails.com/cve/CVE-2004-0679/.
- Prior art — "Uncloaking IP Addresses on IRC," Derek Callaway (DerbyCon) — identical cloak ⇒ identical source IP via WHOIS/WHOWAS — https://speakerdeck.com/decal/uncloaking-ip-addresses-on-irc.
- Community oracle-vector analysis — https://gist.github.com/maxteufel/1e2cf7ada079c271bd3c (B2 — community, not vendor).
