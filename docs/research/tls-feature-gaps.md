# Armor TLS/Crypto Stack — Prioritized Feature-Gap Brief

> **Superseded / historical — preserved as evidence.** This document is a point-in-time record and does not describe the current source or fleet. Current truth: [docs hub](../README.md) and [production paths](../ops/onyx-server-paths.md). Do not execute it as a current procedure.


Research brief · 2026-07-11 · analyst: deep-researcher · scope: Onyx Server `src/crypto`, `src/proto`, `src/daemon` + the `onyx-server` CLI

## BLUF

**Armor is a genuinely complete, modern TLS 1.3 core — not a toy.** It ships full TLS 1.3
client+server, opt-in TLS 1.2, DTLS 1.2/1.3, QUIC, ECH (now RFC 9849), 0-RTT with anti-replay,
RFC 9345 delegated credentials, RFC 7250 raw public keys, RFC 8879 cert compression, SCT/OCSP/CRL
handling, session resumption, kTLS offload, and an ACME issuance client. The gaps are at the
**edges of interop and breadth**, not the core, plus **one real TLS 1.2 security gap** and a
**near-total absence of an openssl-style operator CLI**. Nothing in the core handshake is
silently broken; the missing pieces are additive.

- **Likelihood this inventory is complete/correct:** *very likely (80–95%)* — every "present"
  and "missing" claim below was read directly in source (file:line). Residual risk: a feature
  wired under a name I did not grep for.
- **Analytic confidence:** *High* for what EXISTS (read the code); *Moderate–High* for the
  "modern standard" comparison (triangulated against IETF primary text, but the standards surface
  is large and moves — ECH became an RFC and the PQ-hybrid draft advanced during 2025–2026).

Two separable questions, answered separately:
1. **As a TLS 1.3 impl vs state of the art** → P0/P1/P2 gaps in §2.
2. **As an openssl-like toolkit** → the CLI is ~4 subcommands; §3 gives the highest-value parity subset.

---

## §1 — What EXISTS (VERIFIED, read in source)

**TLS versions / transports**
- TLS 1.3 client + server — `src/crypto/tls_client.zig`, `src/crypto/tls_server.zig` (both ~310KB).
- TLS 1.2 client + server, **opt-in, OFF by default** (`enable_tls12: bool = false`,
  `src/daemon/config_format.zig:667`) — `src/crypto/tls12_client.zig`, `tls12_server.zig`.
- DTLS 1.2 + 1.3 (`src/proto/dtls1{2,3}_*.zig`), QUIC handshake (`src/proto/quic_*.zig`).

**Cipher suites** — TLS 1.3: `tls_aes_128_gcm_sha256` (0x1301), `tls_aes_256_gcm_sha384`
(0x1302), `tls_chacha20_poly1305_sha256` (0x1303) — the full mandatory set
(`src/crypto/tls.zig:266`). TLS 1.2: ECDHE-RSA/ECDSA with AES-128/256-GCM, AES-CBC, ChaCha20
(`src/crypto/tls12.zig:64`).

**Key-exchange groups actually wired into key_share** (`src/proto/tls_keyshare.zig:46`):
`x25519` (0x001d), `secp256r1`/P-256 (0x0017), `x25519mlkem768` (0x11ec) PQ hybrid. The parse-side
`supported_groups.zig` enum additionally *names* `secp384r1`, `x448`, `ffdhe2048` — but there is
**no DH implementation** behind those in the keyshare path (only `ecdh_p256.zig` + std X25519 + std ML-KEM).

**Signature schemes** — exactly 5 in the registry (`src/proto/tls_signature_scheme.zig:33`):
`ed25519` (0x0807), `ecdsa_secp256r1_sha256` (0x0403), `ecdsa_secp384r1_sha384` (0x0503),
`rsa_pss_rsae_sha256` (0x0804), `rsa_pkcs1_sha256` (0x0401). Server *signs* with only ed25519 /
ECDSA-P256 / RSA-PSS-SHA256 (`tls_server.zig:2500-2514`).

**Extensions present** (`src/proto/tls_extension.zig:1`): server_name(0), status_request(5),
supported_groups(10), signature_algorithms(13), alpn(16), client_certificate_type(19),
server_certificate_type(20) [RFC 7250 raw public keys — `tls_client.zig:159`], compress_certificate(27)
[RFC 8879], record_size_limit(28), delegated_credential(34) [RFC 9345], pre_shared_key(41),
early_data(42) [0-RTT], supported_versions(43), cookie(44), psk_key_exchange_modes(45), key_share(51).
Plus **ECH** `encrypted_client_hello` (0xfe0d, `src/crypto/ech_seal.zig:42`), **SCT** delivery
(`src/crypto/sct.zig`), TLS 1.2 renegotiation_info (RFC 5746, `tls12_server.zig:646`).

**Handshake features** — 0-RTT / early_data server accept with a shared anti-replay guard, OFF by
default (`max_early_data_size: u32 = 0`, `tls_server.zig:173`); NewSessionTicket + PSK resumption
(`tls_psk.zig`, `tls_session_ticket.zig`, `tls_resumption.zig`); post-handshake KeyUpdate
(`tls_key_update.zig`); HRR; ECH accept_confirmation + HRR-ECH (`ech_seal.zig:238`).

**PKI** — full X.509 parse/verify (`x509.zig`, `x509_verify.zig`), OCSP must-staple recognition
(`x509.zig:1017`), OCSP client verify + server stapling (`ocsp.zig`, `daemon/ocsp_staple.zig`),
CRL (`crl.zig`), self-sign (`proto/x509_selfsign.zig`), ACME issuance (`daemon/acme_*`).

**Crypto primitives beyond TLS** — ML-DSA 44/65/87 and SLH-DSA with ACVP KATs
(`ml_dsa.zig`, `slh_dsa.zig`) — **present as libraries but NOT wired as TLS signature schemes**;
HKDF (TLS 1.3), Argon2 (`argon2_kdf.zig`); AEAD = AES-128/256-GCM + ChaCha20-Poly1305
(`aead.zig:47`); kTLS offload (`daemon/ktls.zig`).

**CLI subcommands (the entire operator surface)** — `onyx-server --check-config`, `--supervisor`
(Helix upgrade), `acme-issue`, `delegated-credential inspect|validate` (`src/main.zig:172-238`).
**That is all.** No `x509`, `req`, `genpkey`, `pkey`, `verify`, `s_client`, `s_server`, `ciphers`,
`ocsp`, `crl`, `dgst`, `rand`, `pkcs12`.

---

## §2 — TLS-protocol gaps (prioritized)

Legend: **effort** S ≤ ~1 day · M ~2–5 days · L > 1 week. Grades: VERIFIED-missing = read source, absent.

### P0 — security-relevant

**P0-1 · TLS 1.2 Extended Master Secret (RFC 7627)** — VERIFIED-missing.
The TLS 1.2 server writes only renegotiation_info / ALPN / status_request / record_size_limit
(`tls12_server.zig:641-667`); no `extended_master_secret` (ext 23) is offered or required.
Without EMS, TLS 1.2 is exposed to the Triple Handshake class of attacks and cannot be called a
hardened 1.2 profile. **Why P0 not higher-severity:** TLS 1.2 is opt-in and OFF by default, so the
default posture is unaffected — but any operator who sets `enable_tls12 = true` silently loses EMS.
*Spec:* RFC 7627. *Effort:* M. *Dependency:* none. *Fix shape:* offer+require EMS, bind it into the
PRF master-secret derivation, refuse non-EMS resumption.

### P1 — interop / breadth

**P1-1 · Additional PQ hybrid groups: SecP256r1MLKEM768 (0x11eb) + SecP384r1MLKEM1024 (0x11ed)** —
VERIFIED-missing (only X25519MLKEM768 wired, `tls_keyshare.zig:48`). The current
`draft-ietf-tls-ecdhe-mlkem-05` (Standards Track, May 2026, still a draft) defines **three**
hybrids; FIPS/CNSA-track and P-curve-only deployments (some USG/enterprise clients) negotiate the
SecP256r1/SecP384r1 variants. Missing them means no PQ hybrid with those peers.
*Spec:* draft-ietf-tls-ecdhe-mlkem-05. *Effort:* M (SecP256r1MLKEM768 reuses P-256 DH already in
tree; SecP384r1MLKEM1024 needs a P-384 DH — see P1-2). *Dependency:* P1-2 for the P-384 variant.

**P1-2 · Larger classical KX curves: secp384r1, secp521r1, x448** — VERIFIED-missing from key_share
(no DH impl; enum names some but keyshare supports P-256 + X25519 only). Some enterprise/government
peers require P-384 minimum. *Spec:* RFC 8446 §4.2.7 / RFC 7748. *Effort:* M (P-384), M (X448/P-521).
*Dependency:* none; P-384 also unblocks SecP384r1MLKEM1024.

**P1-3 · Broader signature-scheme coverage** — VERIFIED-missing: `rsa_pss_rsae_sha384/512`,
`ecdsa_secp521r1_sha512`, `ed448`, `rsa_pss_pss_*`. A leaf/CA cert signed with, e.g., RSA-PSS-SHA384
or ECDSA-P384-SHA384 for CertificateVerify cannot be produced (server signs SHA-256-only).
*Spec:* RFC 8446 §4.2.3. *Effort:* S–M (add schemes + hash wiring; verify side partly exists).

**P1-4 · Certificate compression beyond zlib (brotli, zstd)** — VERIFIED-partial. Only zlib is
*producible*; brotli/zstd are ignored because "Zig std has no brotli and zstd is decompress-only"
(`src/proto/cert_compression.zig:10`). Browsers commonly prefer **brotli** for RFC 8879, so the
optimization is frequently a no-op against real clients. *Spec:* RFC 8879. *Effort:* M–L (needs a
brotli encoder — vendor or port). *Dependency:* a brotli/zstd encoder.

**P1-5 · TLS ClientHello GREASE (RFC 8701)** — VERIFIED-missing (GREASE handling exists only in
HTTP/3, `http3_conn.zig`; the TLS ClientHello sends no GREASE cipher/group/extension values).
Absent outbound GREASE, Onyx Server's own TLS *client* (ACME, S2S dial, media) risks ossification and
is more fingerprintable/less "browser-like." *Spec:* RFC 8701. *Effort:* S. *Dependency:* none.

### P2 — convenience / forward-looking

**P2-1 · Post-handshake client authentication (`post_handshake_auth`, ext 49)** — VERIFIED-missing
(ext not in the enum; only KeyUpdate/NewSessionTicket are post-handshake). Low demand for an IRC
daemon; matters only for reactive client-cert re-auth. *Spec:* RFC 8446 §4.6.2. *Effort:* M.

**P2-2 · PQ signatures in TLS (ML-DSA / SLH-DSA CertificateVerify)** — VERIFIED-missing as TLS
wiring, though the **primitives already exist and are ACVP-tested** (`ml_dsa.zig`, `slh_dsa.zig`).
`draft-ietf-tls-mldsa` is still early; ecosystem certs are rare. High-value *later*, cheap relative
to the primitive work already done. *Spec:* draft-ietf-tls-mldsa. *Effort:* M (wire enum + cert path).

**P2-3 · Exported Authenticators (RFC 9261)** — VERIFIED-missing. Niche; needed for
post-handshake proof-of-possession outside the handshake. *Effort:* M. *Dependency:* none.

**P2-4 · ALPS / `application_settings`** — VERIFIED-missing. Only useful with HTTP/2-over-TLS
settings exchange; not relevant to IRC/WSS today. *Effort:* S–M.

**P2-5 · Revocation is fail-open + config-gated** — VERIFIED (by design): `checkCrlRevocation` and
the OCSP-staple client check are **fail-open** and opt-in (`tls_client.zig:2798-2839`). Defensible
for an outbound ACME/S2S client (soft-fail revocation, hard-fail forgery), but worth a documented
"hard-fail" mode for high-assurance operators. *Effort:* S (add a strict toggle).

---

## §3 — openssl-CLI parity (the big convenience gap)

Onyx Server exposes ~4 subcommands (§1). openssl(1) exposes ~50. Most operator pain for a self-hoster is
**cert/key lifecycle and TLS debugging**, and Onyx Server *already has the primitives internally*
(x509 parse/verify, self-sign, keygen, OCSP, CRL) — so exposing them as CLI is disproportionately
high-value for low effort. Recommended parity subset, ranked by value ÷ effort:

| Rank | openssl subcmd | Onyx Server value | Backing primitive already in tree | Effort |
|---|---|---|---|---|
| 1 | `x509` (inspect/convert/self-sign) | Inspect a cert, check expiry/SAN, self-sign a dev cert | `x509.zig`, `proto/x509_selfsign.zig` | S |
| 2 | `genpkey` / `ecparam` / `genrsa` | Generate ed25519/P-256/RSA keys without pulling in openssl | ecdsa/rsa/ed25519 modules | S |
| 3 | `req` (CSR create/inspect) | Produce a CSR for an external CA | x509 + selfsign encoders | M |
| 4 | `verify` (chain verify) | "Will this chain validate?" pre-deploy | `x509_verify.zig` | S |
| 5 | `s_client` (debug handshake) | Diagnose a TLS endpoint / print peer chain, ALPN, group, suite | `tls_client.zig` | M |
| 6 | `ciphers` (list/policy) | Show what this build negotiates | static from suite/group tables | S |
| 7 | `ocsp` (query/verify) | Manually check a leaf's OCSP status | `ocsp.zig` | M |
| 8 | `crl` (inspect) | Inspect/verify a CRL | `crl.zig` | S |
| 9 | `dgst` (hash/sign/verify) | Hash a file, sign/verify with a key | `hash.zig` + sign modules | S |
| 10 | `pkcs12` (bundle) | Bundle leaf+key for import into other tooling | x509 + key encoders | M |
| — | `rand` | Emit N random bytes | `random.zig` | S |
| — | `s_server` | Throwaway TLS server for client testing | `tls_server.zig` | M |

**Lower value for Onyx Server's audience (defer):** `enc`, `cms`, `ts`, `ca`, `asn1parse`, `speed`,
`srp`, `pkeyutl` — general-purpose crypto plumbing not tied to running an IRC node.

**Recommended CLI shape:** a single `onyx-server tls <subcommand>` (or `onyx-server x509 …`, `onyx-server s_client …`)
umbrella that dispatches into the existing crypto modules — mirroring how `acme-issue` and
`delegated-credential` already sit on `main.zig`. Ship subset ranks 1–4 first (all backed by
existing primitives, mostly S effort); they cover the self-host "make/inspect/verify a cert" loop
that today forces operators to install openssl anyway.

---

## §4 — Named gaps in THIS analysis (what I did not verify)

- I confirmed features by **presence in source**, not by running the handshake against a reference
  peer (e.g. BoGo, OpenSSL s_client). "Present" ≠ "spec-perfect"; a P0/P1 fix should still be
  BoGo-tested. (Memory indicates a BoGo suite exists — not re-verified here.)
- The "modern standard" side is triangulated against IETF *primary* text for the load-bearing,
  version-sensitive items (ECH → **RFC 9849**, published Mar 2026; ecdhe-mlkem → **draft-05**,
  May 2026), but the full IANA extension/group/sig registries are large — a second pass could
  surface a lower-priority missing extension I did not enumerate.
- I did not audit DTLS/QUIC feature parity against their own drafts; scope was TLS + toolkit.
- Effort estimates are INFERENCE from module size/shape, not measured.

---

## Sources

- Onyx Server source (read directly, file:line inline above): `src/crypto/tls*.zig`,
  `src/crypto/tls12*.zig`, `src/crypto/ech_seal.zig`, `src/crypto/{ocsp,sct,crl,x509,x509_verify}.zig`,
  `src/crypto/{ml_dsa,slh_dsa,aead,argon2_kdf}.zig`, `src/proto/{tls_extension,tls_signature_scheme,tls_keyshare,supported_groups,cert_compression,x509_selfsign}.zig`,
  `src/daemon/{config_format,tls_conn,ktls,acme_cli}.zig`, `src/main.zig`.
- TLS Encrypted Client Hello — **RFC 9849** (Mar 2026, was draft-ietf-tls-esni-25): https://datatracker.ietf.org/doc/rfc9849/
- Post-quantum hybrid ECDHE-MLKEM — **draft-ietf-tls-ecdhe-mlkem-05** (Standards Track, May 2026): https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/
- RFC 7627 (TLS Extended Master Secret): https://www.rfc-editor.org/rfc/rfc7627
- RFC 8446 (TLS 1.3), RFC 8879 (cert compression), RFC 9345 (delegated credentials),
  RFC 7250 (raw public keys), RFC 8701 (GREASE), RFC 9261 (exported authenticators),
  RFC 5746 (renegotiation_info) — IANA/RFC-Editor.
- openssl(1) subcommand surface — OpenSSL project man pages (openssl-x509, -req, -genpkey,
  -s_client, -verify, -ocsp, -crl, -dgst, -pkcs12).
