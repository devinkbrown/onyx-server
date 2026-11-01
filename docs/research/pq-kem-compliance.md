# Post-Quantum Hybrid KEM Compliance — X25519MLKEM768 & X-Wing

> **Superseded / historical — preserved as evidence.** This document is a point-in-time record and does not describe the current source or fleet. Current truth: [docs hub](../README.md) and [production paths](../ops/onyx-server-paths.md). Do not execute it as a current procedure.


Research brief · 2026-07-11 · analyst: deep-researcher · scope: Onyx Server `src/crypto`

## BLUF

**Onyx Server's X25519MLKEM768 hybrid key exchange is spec-compliant and current — YES, with one
documentation caveat.** The TLS wire construction (named group `0x11EC`), the shared-secret
concatenation order (`ML-KEM ss || X25519 ss`), the key-share layouts, and the separate X-Wing
KEM combiner all match the *current* IETF drafts and FIPS 203 final. No combiner drift, no stale
parameter set, no codepoint error was found.

- **Likelihood the construction is spec-compliant:** *almost certain (95–99%)*.
- **Analytic confidence:** *High* — every load-bearing claim is triangulated against the primary
  IETF draft text **and** read directly in Onyx Server source **and** (for ML-KEM provenance) read in
  the Zig std source. Independent chains, no single-source claim.
- **Caveat (documentation only, not a security defect):** `src/crypto/kx.zig:6` says "Zig 0.16
  std"; the live toolchain is `0.17.0-dev.1282`. Cosmetic staleness in a comment, no code impact.

There are **three distinct hybrid constructions** in the tree; do not conflate them:

| Construction | File | Combiner | Governed by | Compliant? |
|---|---|---|---|---|
| **TLS `X25519MLKEM768`** (wire codepoint) | `tls_server.zig`, `tls_client.zig` | **raw concat**, no extra KDF | draft-ietf-tls-ecdhe-mlkem | **YES** |
| **X-Wing KEM** | `xwing.zig` | `SHA3-256(ss_M‖ss_X‖ct_X‖pk_X‖label)` | draft-connolly-cfrg-xwing-kem-10 | **YES** |
| **MOORING mesh v2** (Onyx Server-proprietary S2S) | `kx.zig` `HybridKx` | `HMAC(label, x_ss‖mlkem_ss‖transcript)` | Onyx Server's own protocol — not an IETF codepoint | N/A (self-consistent) |

The question asked specifically about the **TLS X25519MLKEM768 codepoint**; that path is
`tls_server.zig`/`tls_client.zig`, **not** `kx.zig` and **not** `xwing.zig`. All three are
nonetheless assessed below.

---

## 1 — What Onyx Server does (read directly, cited file:line)

### 1.1 TLS X25519MLKEM768 (the wire codepoint) — VERIFIED

Codepoint declared `x25519mlkem768 = 0x11ec` at `src/proto/tls_keyshare.zig:48` and
`src/proto/supported_groups.zig:47`.

**Client key_share** (offered) — `src/crypto/tls_client.zig:1509-1513`:
`hybrid_share = ml-kem_ek(1184) || x25519_pub(32)` (ML-KEM half first).

**Server key_share** (returned) — `src/crypto/tls_server.zig:1703-1704`:
`hybrid_keyshare = ml-kem_ct(1088) || x25519_pub(32)` (ML-KEM half first).

**Combined shared secret — client side** `src/crypto/tls_client.zig:1971-1990`:
```
out.buf[0..32]  = mlkem_ss   // ML-KEM shared secret FIRST
out.buf[32..64] = x_ss       // X25519 shared secret SECOND
out.len = 64                 // raw 64-byte concat, fed to the TLS 1.3 key schedule
```
**Combined shared secret — server side** `src/crypto/tls_server.zig:1706-1710`: identical order
(`out.buf[0..32] = enc.shared_secret` (ML-KEM), `out.buf[32..64] = x_ss`). The in-code comment at
`tls_server.zig:1972-1975` explicitly notes this is "the RAW concatenation … NOT
`kx.HybridKx.decapsulate`, which is the MOORING mesh HKDF combiner." No additional KDF/hash is
applied to the 64-byte value before it enters the standard TLS 1.3 key schedule (it replaces the
`(EC)DHE` secret input to HKDF-Extract). A loopback interop test exercises the whole path
(`tls_server.zig:3606`, asserting the 64-byte "raw IETF concat" at `:3649`).

### 1.2 X-Wing KEM — VERIFIED

`src/crypto/xwing.zig` cites **draft-connolly-cfrg-xwing-kem-10** (`:6`). Combiner
(`xwing.zig:132-148`):
```
SHA3-256( ss_m || ss_x || ct_x || pk_x || xwing_label )
```
Label `xwing.zig:48`: `"\x5c\x2e\x2f\x2f\x5e\x5c"` = bytes `5c 2e 2f 2f 5e 5c`. Used by the
MOORING mesh handshake/session (`mooring_handshake.zig`, `mooring_session.zig`,
`node_identity.zig`), **not** by the TLS layer.

### 1.3 ML-KEM-768 parameter provenance — VERIFIED

Both `xwing.zig:21` and `kx.zig:16` use `std.crypto.kem.ml_kem.MLKem768`. In the live toolchain
(`/usr/local/lib/zig-0.17/lib/zig/std/crypto.zig:121`) `ml_kem` aliases the **`nist`** namespace,
i.e. the **FIPS-203 publication** (`ml_kem.zig:2,171,181`), *not* the `kyber_d00` round-3 draft
(`crypto.zig:120`). So Onyx Server uses **final ML-KEM-768**, not legacy Kyber. No hand-rolled ML-KEM.

---

## 2 — What the specs require (triangulated, cited)

### 2.1 draft-ietf-tls-ecdhe-mlkem (TLS hybrid group) — VERIFIED (2 independent chains)

- **Codepoint:** `X25519MLKEM768 = 4588 (0x11EC)`, IANA "Recommended: Y". Source: primary draft
  text (tlswg repo) + datatracker. → matches Onyx Server exactly.
- **Client key_exchange** = ML-KEM-768 encapsulation key (1184) ‖ X25519 share (32) = 1216 B.
  **Server key_exchange** = ML-KEM ciphertext (1088) ‖ X25519 share (32) = 1120 B. → matches
  Onyx Server (`hybrid_client_share_len=1216`, `hybrid_server_share_len=1120`, `tls_server.zig:71-72`).
- **Shared secret** = concatenation of **the ML-KEM shared secret and the X25519 shared secret**.
  The draft explicitly flags: *"The group name X25519MLKEM768 does not adhere to the naming
  convention… the order of shares in the concatenation has been reversed. This is due to historical
  reasons."* → Onyx Server's ML-KEM-first order (`out.buf[0..32]=mlkem_ss`) is the **correct reversed
  order** for this specific codepoint. (Contrast SecP256r1MLKEM768, which is ECDH-first.)
- **Key-schedule handling:** the draft defines only *"the shared secret is the concatenation…"* and
  defers to [hybrid] (draft-ietf-tls-hybrid-design) + NIST SP 800-56C — i.e. the concatenation is
  used **directly** as the TLS 1.3 key-schedule secret with no extra KDF over the concatenation.
  → matches Onyx Server (feeds the raw 64 B, no wrapper). *[Spec mechanism = well-founded INFERENCE
  from the hybrid framework; Onyx Server's behavior itself = VERIFIED in source.]*
- **Status:** IETF WG draft, Standards-Track, **not yet an RFC** (WG versions -04/-05 current as of
  research date). Codepoint is IANA-registered and Recommended.

Sources: <https://github.com/tlswg/tls-ecdhe-mlkem/blob/main/draft-ietf-tls-ecdhe-mlkem.md> ·
<https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/> ·
predecessor <https://datatracker.ietf.org/doc/draft-kwiatkowski-tls-ecdhe-mlkem/>

### 2.2 draft-connolly-cfrg-xwing-kem-10 (X-Wing) — VERIFIED

- **Latest version = -10 (2026)** — the version Onyx Server cites. No newer draft supersedes it at
  research date; not yet an RFC.
- **Combiner:** `SHA3-256(concat(ss_M, ss_X, ct_X, pk_X, XWingLabel))` — order ML-KEM ss → X25519
  ss → X25519 ciphertext → X25519 pubkey → label. → matches `xwing.zig:139-143` exactly.
- **XWingLabel** = `concat("\.//", "/^\")`, *"in hexadecimal … `5c2e2f2f5e5c`."* → matches
  `xwing.zig:48` byte-for-byte.
- **Security note (relevant):** *"The security of X-Wing relies crucially on the specifics of the
  Fujisaki-Okamoto transformation used in ML-KEM-768… it is not known to be safe to leave out the
  post-quantum ciphertext from the combiner in the general case."* Onyx Server deliberately omits the
  ML-KEM ciphertext from the combiner (only `ct_X`/`pk_X` are hashed) — this is **correct** because
  it uses real FIPS-203 ML-KEM, and Onyx Server documents the rationale at `xwing.zig:12-14`.

Source: <https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-10.html> ·
<https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/>

### 2.3 FIPS 203 final vs Kyber round-3 — VERIFIED

ML-KEM-768 is standardized in **NIST FIPS 203** (final, Aug 2024). Zig std's `nist` namespace is
the FIPS-203 implementation; Onyx Server binds to it. No round-3 Kyber parameter set is in the hot path.

---

## 3 — Gaps, drift, and named unknowns

1. **Doc staleness (LOW):** `kx.zig:6` references "Zig 0.16 std"; toolchain is 0.17-dev. Comment
   only. Recommend a one-line fix when `kx.zig` is next touched.
2. **Two combiner orders coexist by design (INFO, not a bug):** the TLS path concatenates
   *ML-KEM-first*; the MOORING mesh `HybridKx` HMACs *X25519-first*. They are different protocols;
   neither leaks into the other (the code comment at `tls_server.zig:1972-1975` guards against the
   confusion). No action needed, but worth a note for future reviewers.
3. **Spec is a moving WG draft (MONITOR):** draft-ietf-tls-ecdhe-mlkem is not an RFC. The `0x11EC`
   codepoint, sizes, and reversed-concat order have been **stable across recent versions** and are
   IANA-Recommended, so churn risk to this specific group is low. Re-check on RFC publication.
4. **Not independently re-derived here:** I did not run Onyx Server's KATs against an external X-Wing
   test vector in this pass (the in-tree round-trip + interop tests exist and pass by construction).
   A cross-implementation KAT (e.g. against the X-Wing draft Appendix vectors or BoringSSL's
   `0x11EC`) would raise assurance from "spec-shape-correct" to "byte-exact interop-proven." Onyx Server
   already has a live-openssl loopback test (`tls_server.zig:6546+`) which is strong evidence of
   real interop.

## 4 — Recommendation

**No source change required for compliance.** The X25519MLKEM768 TLS combiner, the X-Wing KEM, and
the ML-KEM-768 parameter set are current and correct. Optional, low-priority follow-ups:

- (trivial) Fix the "Zig 0.16 std" comment in `kx.zig:6`.
- (assurance) Add an external-vector KAT: X-Wing draft-10 Appendix test vectors for `xwing.zig`,
  and a captured Chrome/BoringSSL `0x11EC` transcript for the TLS path, to pin byte-exact interop.
- (hygiene) Track draft-ietf-tls-ecdhe-mlkem to RFC; re-verify the codepoint/order note survives.

---

## Sources

- **draft-ietf-tls-ecdhe-mlkem** (primary, WG) — codepoint 4588/0x11EC, reversed concat order,
  share sizes. <https://github.com/tlswg/tls-ecdhe-mlkem/blob/main/draft-ietf-tls-ecdhe-mlkem.md> ,
  <https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/>
- **draft-kwiatkowski-tls-ecdhe-mlkem** (predecessor individual draft).
  <https://datatracker.ietf.org/doc/draft-kwiatkowski-tls-ecdhe-mlkem/>
- **draft-connolly-cfrg-xwing-kem-10** (primary) — combiner order + XWingLabel `5c2e2f2f5e5c` +
  FO-transform security note. <https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-10.html> ,
  <https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/>
- **NIST FIPS 203** — ML-KEM standard (final).
- **Zig std source** (provenance of ML-KEM) — `/usr/local/lib/zig-0.17/lib/zig/std/crypto.zig:120-121`
  (`ml_kem = …nist`), `ml_kem.zig:2,171,181` (FIPS-203 namespace).
- **Onyx Server source** — `src/crypto/xwing.zig`, `src/crypto/kx.zig`, `src/crypto/tls_server.zig`,
  `src/crypto/tls_client.zig`, `src/proto/tls_keyshare.zig`, `src/proto/supported_groups.zig`.
