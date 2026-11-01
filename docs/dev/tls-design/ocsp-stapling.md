# Design spike: server-side OCSP stapling for Onyx Server's Zig-native TLS stack (TLS 1.3 CertificateEntry status_request + TLS 1.2 CertificateStatus), fed by an OCSP request builder, AIA responder fetch, and a cached/refreshed staple.

> **Superseded / historical — preserved as evidence.** This document is a point-in-time record and does not describe the current source or fleet. Current truth: [docs hub](../../README.md) and [production paths](../../ops/onyx-server-paths.md). Do not execute it as a current procedure.


Onyx Server already CONSUMES OCSP staples as a TLS client (tls_client.zig advertises status_request, parses the leaf CertificateEntry status_request extension, and verifyOcspStapleForLeaf authenticates the response against the issuer SPKI and fails closed on `revoked`). Nothing on the server side ever PRODUCES a staple. This spike designs the producer half: (1) an OCSP request builder in ocsp.zig (none exists today) that constructs a SHA-1 CertID from the leaf serial + issuer name/key; (2) x509.zig additions to extract the AIA OCSP responder URL, the issuer Name DER, the issuer public-key hash input, and an OCSP-must-staple flag; (3) a background daemon service (mirroring acme_renewal.Service) that fetches, verifies, freshness-gates, caches, and refreshes the response, publishing the bytes to the live config via the same reactor-0 atomic-swap path ACME reload uses; (4) wiring the cached DER into the TLS 1.3 leaf CertificateEntry (status_request extension) and the TLS 1.2 CertificateStatus handshake message, both strictly gated on the client having offered status_request so the wire stays byte-identical otherwise. The whole thing is opt-in via a new `[ocsp]` config section and degrades gracefully (no AIA OCSP URL → no staple), which matters because Let's Encrypt is retiring OCSP.

# Server-side OCSP stapling — design

## 0. What exists today (read-only findings)

**Consumer side (complete):**
- `tls_client.zig:868-870` advertises `status_request` in ClientHello: `ext_status_request: u16 = 5`, body `{1,0,0,0,0}` (status_type=ocsp, empty responder_id_list, empty request_extensions).
- `tls_client.zig:1246-1296` `parseAndVerifyCertificate`: for the leaf (count==0) it reads the per-`CertificateEntry` `status_request` extension, `parseCertificateStatusOcsp` (`:1806`) decodes `status_type(1)‖ocsp_response_length(u24)‖OCSPResponse DER`, then `verifyOcspStapleForLeaf` (`:1819`) does `ocsp.parse` → `ocsp.verifyResponseSignature(issuer_spki)` → `enforceOcspStatusForSerial` (`revoked` → error, `good`/`unknown`/no-match → soft pass).
- `ocsp.zig` parses a BasicOCSPResponse and verifies a **direct-issuer** signature only (`verifyResponseSignature`, `:158`; delegated id-kp-OCSPSigning responders are explicitly out of scope). It has **no request builder**.

**Producer side (missing):**
- `tls_server.zig` ClientHello extension loop (`:790-818`) ignores `status_request` (falls in `else => {}`).
- `tls_server.zig:1074-1089` `writeCertificate` emits every `CertificateEntry` with **empty** per-cert extensions (`appendU16(&list, 0)`).
- `tls12_server.zig` `parseClientExtensions` (`:441-497`) has no `status_request` case; `buildServerFlight` (`:519-577`) emits ServerHello→Certificate→ServerKeyExchange→[CertificateRequest]→ServerHelloDone with no CertificateStatus.
- `tls12.zig:57` `HandshakeType` has no `certificate_status = 22`.
- `tls_extension.zig:41` `ExtensionType` has no `status_request = 5`.
- `x509.zig` does not parse AIA (authorityInfoAccess), does not expose the issuer Name DER or raw public-key bytes, and has no must-staple flag. `hash.zig` has SHA-256/384/512 but **no SHA-1**.

**Wiring:**
- `tls_server.Config` (`tls_server.zig:79`) and `tls12_server.Config` (`tls12_server.zig:49`) are pure value structs that borrow `cert_chain`.
- Per-connection configs are built in `server.zig` `tls13Config` (`:3253`) and `tls12Config` (`:3277`) from `self.config.tls_*` fields.
- Cert hot-reload: background thread (`acme_renewal.Service`, `acme_renewal.zig:40`, uses `sleepInterruptible`) calls `requestAcmeTlsReload` → sets `acme_reload_requested` atomic (`server.zig:2755`) → reactor 0 polls `maybeReloadAcmeTls` (`:24334`) → `reloadTlsCertsLocked` (`:24363`) loads new material, swaps `self.config.tls_*`, frees the prior reload generation. This is the exact pattern to reuse for publishing a staple.
- Boot wiring in `main.zig:469-517` (`tls_certs.loadOrBootstrap`) and `main.zig:603-611` (start the ACME service).
- `http_fetch.zig` already does plain-HTTP + TLS GET with raw syscalls off the reactor thread and `parseUrl` handling `http://`/`https://` with default ports — the model for an off-reactor OCSP fetch.

---

## 1. OCSP request builder — `ocsp.zig` (new, additive)

Add a builder producing a DER `OCSPRequest` (RFC 6960 §4.1). Signature and nonce omitted (see below).

```
OCSPRequest ::= SEQUENCE { tbsRequest TBSRequest }          -- optionalSignature omitted
TBSRequest  ::= SEQUENCE { requestList SEQUENCE OF Request } -- version default v1, no requestorName/extensions
Request     ::= SEQUENCE { reqCert CertID }                  -- no singleRequestExtensions
CertID      ::= SEQUENCE {
    hashAlgorithm  AlgorithmIdentifier,   -- SHA-1 (1.3.14.3.2.26), params NULL
    issuerNameHash OCTET STRING,          -- SHA-1(issuer Name DER)
    issuerKeyHash  OCTET STRING,          -- SHA-1(issuer subjectPublicKey BIT STRING value, no unused-bits octet)
    serialNumber   INTEGER }              -- leaf serial (serial_der, verbatim)
```

Proposed API (fixed-size output, no allocation, mirrors the append/DER helpers already at the bottom of `ocsp.zig:807-847`):

```zig
pub const CertIdInput = struct {
    issuer_name_der: []const u8,      // full issuer Name TLV (SEQUENCE)
    issuer_key_bytes: []const u8,     // BIT STRING value minus the unused-bits octet
    serial_der: []const u8,           // leaf serial INTEGER contents
};
/// Writes a complete OCSPRequest DER into `out`; returns the used slice.
pub fn buildRequest(out: []u8, in: CertIdInput) error{NoSpaceLeft}![]const u8
```

Internals hash with **`std.crypto.hash.Sha1`** directly. **SHA-1 justification:** OCSP `CertID` is an *identifier* hash mandated by responders (Let's Encrypt and virtually all responders key their pre-produced responses on the SHA-1 CertID); it is not a certificate or protocol signature. The modern-only posture bans SHA-1 *cert signatures* — this does not conflict. Document this inline. (Optionally also offer a SHA-256 CertID, but it will miss most responders' caches; default SHA-1.)

New OID constants: `id-sha1 = 1.3.14.3.2.26` (already present as `oid_sha1`, `ocsp.zig:849`), and reuse `Oid.ocsp_basic`.

Tests (in `ocsp.zig`): `buildRequest` output round-trips through a minimal request reader (or byte-compares against a hand-built fixture); `issuerNameHash`/`issuerKeyHash` match known SHA-1 vectors; serial is threaded verbatim including a positive-serial sign-pad byte.

---

## 2. Cert introspection — `x509.zig` (new, additive)

The struct at `x509.zig:191` currently skips both `issuer` (`:469`) and `subject` (`:477`) and parses only SAN/BasicConstraints/KeyUsage/EKU/NameConstraints (`:548-558`). Add:

1. **Issuer material for CertID.** Capture the raw `subject` Name TLV of a cert into a new field `subject_raw_der` (set at `:477`, `= subject.raw`). To build a leaf's request you hash the **issuer cert's** `subject_raw_der` (== the leaf's `issuer` field, byte-identical) → `issuerNameHash`. Also add a helper `issuerKeyHashInput(spki_der) -> []const u8` that walks the SPKI to the `BIT STRING` and returns `value[1..]` (the same `bitStringBytesZero` shape ocsp.zig already uses at `:560`).

2. **AIA OCSP responder URL.** Parse extension `authorityInfoAccess` OID `1.3.6.1.5.5.7.1.1` = `{2B 06 01 05 05 07 01 01}`:
   ```
   SEQUENCE OF AccessDescription
   AccessDescription ::= SEQUENCE { accessMethod OID, accessLocation GeneralName }
   ```
   For `accessMethod == id-ad-ocsp` (`1.3.6.1.5.5.7.48.1` = `{2B 06 01 05 05 07 30 01}`) return the `accessLocation` URI (context `[6]` primitive, tag `0x86`, IA5String). Expose as a new field `ocsp_responder_url: ?[]const u8` (aliases the DER; `null` when absent) plus the parse branch in `parseExtensions`.

3. **OCSP-must-staple.** Parse TLS Feature extension (RFC 7633) OID `id-pe-tlsfeature = 1.3.6.1.5.5.7.1.24` = `{2B 06 01 05 05 07 01 18}`, value `SEQUENCE OF INTEGER`; set `must_staple: bool = true` when the list contains `5` (status_request).

Tests: extraction of the OCSP URL from an AIA fixture; `must_staple` from a tlsfeature=5 fixture; `subject_raw_der` / `issuerKeyHashInput` correctness against a known cert.

---

## 3. Wire emission — TLS 1.3 (`tls_server.zig`)

- **Config:** add `ocsp_staple: ?[]const u8 = null` to `Config` (`:79`), borrowed exactly like `cert_chain`. Bytes are the bare `OCSPResponse` DER (the service guarantees fresh/good; see §5).
- **Capture the offer:** in the ClientHello ext loop (`:790-818`) add a `status_request` case setting `self.client_offered_status_request = true`. (Add `status_request = 5` to `tls_extension.ExtensionType`, `tls_extension.zig:41`, matching the client's `ext_status_request: u16 = 5`.)
- **Emit on the leaf only:** in `writeCertificate` (`:1074-1089`), for the first entry (`count==0`), when `client_offered_status_request AND config.ocsp_staple != null`, replace the empty `appendU16(0)` with a per-`CertificateEntry` extension list containing one `status_request` (type 5) whose `extension_data` is a `CertificateStatus`:
  `status_type=1 (ocsp) ‖ ocsp_response_length(u24) ‖ OCSPResponse DER`.
  Build with a small `tls_extension.Builder` (already used at `:1058`). All other entries and the no-offer path stay byte-identical.
- **Resumption guard:** none needed — TLS 1.3 PSK resumption never sends Certificate.

Test: with `Config.ocsp_staple` set and a ClientHello that offers `status_request`, the in-repo `tls_client` (which already verifies staples) completes and accepts; with no offer, the Certificate message is byte-for-byte the pre-change output.

---

## 4. Wire emission — TLS 1.2 (`tls12_server.zig`)

- **HandshakeType:** add `certificate_status = 22` to `tls12.zig:57`.
- **Config:** add `ocsp_staple: ?[]const u8 = null` to `tls12_server.Config` (`:49`).
- **Capture the offer:** in `parseClientExtensions` (`:441-497`) add a `0x0005` case. Per RFC 6066 the body is a `CertificateStatusRequest` (`status_type(1)=ocsp ‖ responder_id_list ‖ request_extensions`); it is sufficient to record `self.client_offered_status_request = true` (bounds-check the body but otherwise ignore its content, as the client we ship sends the empty form).
- **Echo in ServerHello:** in `buildServerFlight` (`:531-550`), when we will staple (offer + `config.ocsp_staple != null` + full handshake), append an **empty** `status_request` extension (type `0x0005`, zero-length) to the ServerHello extension list. RFC 6066 §8 requires this echo, or strict clients reject the later CertificateStatus.
- **Insert CertificateStatus:** in `buildServerFlight`, immediately after the `Certificate` handshake message (`:563`) and before `ServerKeyExchange` (`:565`), write a `certificate_status` handshake message with body `status_type=1 (ocsp) ‖ ocsp_response_length(u24) ‖ OCSPResponse DER`. It is folded into the transcript automatically because the whole flight is appended at `:575`.
- **Resumption guard:** the abbreviated/resumed path (`tls12_server.zig` resume flight, no Certificate) must not staple — the gate is naturally satisfied since it doesn't run `buildServerFlight`, but assert it in a test.

Ordering on the wire: ServerHello(+empty status_request) → Certificate → **CertificateStatus** → ServerKeyExchange → [CertificateRequest] → ServerHelloDone.

Tests: ServerHello carries the empty status_request echo; a `certificate_status(22)` message appears in the right position; server Finished/transcript still verifies against the in-repo `tls12_client`; resumed handshake carries neither.

---

## 5. Fetch + verify + cache + refresh — `src/daemon/ocsp_staple.zig` (new)

A background `Service` modeled on `acme_renewal.Service` (`acme_renewal.zig:40`), off the reactor thread, using `sleepInterruptible` and raw syscalls (never the reactor's `Io`).

**Per cycle:**
1. Read current `config.tls_cert_chain`; `x509.parse` leaf (chain[0]) and issuer (chain[1], or self if len==1). If no issuer or no leaf AIA OCSP URL → no-op (log once).
2. Build `CertID` via `x509.issuerKeyHashInput` + issuer `subject_raw_der` + leaf `serial_der` → `ocsp.buildRequest`.
3. POST the request to the AIA URL with `Content-Type: application/ocsp-request`, body = DER. Responder URLs are almost always `http://` (responses are signed, so plain HTTP is correct and avoids a TLS bootstrap loop). **http_fetch.zig** currently exposes GET only — add a POST path (it already has plain-HTTP connect + `http1_client.buildRequest` which takes method+body), or a GET variant with base64url(request) in the path (RFC 6960 App. A; fine for short CertIDs, cache-friendly). Bound response size and connect/read timeouts as http_fetch already does.
4. `ocsp.parse` → require `response_status == successful` → `ocsp.verifyResponseSignature(issuer_spki)` → `statusForSerial(leaf_serial)` must be `good` → validate `thisUpdate <= now < nextUpdate` (with a small skew), using the daemon clock (`platform.realtimeMillis`), since the crypto engines are clockless.
5. On success: keep an **owned copy** of the raw OCSPResponse DER; publish it (below). On `revoked`: do **not** staple, log CRITICAL (our own cert is revoked), alert. On any fetch/verify/freshness failure: **keep the last-good cached staple** until it actually reaches `nextUpdate`; only then drop to un-stapled.

**Refresh scheduling:** next refresh at roughly `thisUpdate + (nextUpdate - thisUpdate)/2` (halfway, standard for stapling), with exponential backoff on failure and a floor/ceiling (e.g. retry in minutes on error, cap at hours). Re-fetch immediately after a cert reload (new serial invalidates the cache).

**Publishing (thread-safe, reuse the ACME pattern):**
- Add `config.tls_ocsp_staple: ?[]const u8 = null` to the server config and an owned holder + `ocsp_staple_requested: std.atomic.Value(bool)` on the server (mirror `acme_reload_requested`, `server.zig:2755`).
- The service stores the new owned DER into a server-owned staging slot under the existing publish mechanism and sets the atomic. Reactor 0 polls (add `maybeSwapOcspStaple`, alongside `maybeReloadAcmeTls` at `:24334`), swaps `config.tls_ocsp_staple` to the new generation and frees the prior one — only on reactor 0, so per-connection reads never race.
- `tls13Config` (`:3253`) and `tls12Config` (`:3277`) set `cfg.ocsp_staple = self.config.tls_ocsp_staple`.

**Config:** new `[ocsp]` section in `config_format.zig` (near `Tls`, `:459`): `enabled: bool = false`, `refresh_ratio`/interval knobs, `must_staple_strict: bool = false` (see risks). Wire the service in `main.zig` next to the ACME service (`:603-611`), only when `[ocsp].enabled` and a TLS listener is up.

Tests: freshness gate accepts good+in-window and rejects expired/future/revoked; keep-last-good on fetch failure; refresh-time math; publish/swap frees the prior generation exactly once.

---

## 6. Edge cases & correctness gates

- **Byte compatibility (hard requirement):** alter Certificate emission ONLY when the client offered status_request AND a staple is present (1.3: leaf entry only; 1.2: full handshake only). Every other path stays byte-identical to the deployed binary. Cover with "no offer ⇒ identical bytes" tests on both engines.
- **TLS 1.3 placement:** status_request rides `CertificateEntry.extensions` (RFC 8446 §4.4.2.1), not EncryptedExtensions — the client already reads it there.
- **TLS 1.2 echo requirement:** must send the empty ServerHello status_request echo or clients reject CertificateStatus.
- **Resumption:** neither 1.3 PSK nor 1.2 abbreviated handshakes carry Certificate; assert no staple leaks there.
- **Signing-key independence:** stapling keys off the leaf serial/identity, identical across Ed25519/ECDSA/RSA legs; the 1.2 leg may present a *different* (bootstrapped ECDSA) leaf than the 1.3 leg — the staple must match whichever leaf that engine actually presents. In practice the ACME leaf serves both legs; but when `tls12_cert_chain` differs (Ed25519 1.3 + minted ECDSA 1.2), the 1.2 leg's leaf has no real AIA/OCSP and simply won't staple. Gate the 1.2 staple on chain identity.
- **Delegated responders:** `verifyResponseSignature` only accepts issuer-signed responses; a CA using an id-kp-OCSPSigning delegated responder would fail verification → we cache nothing → no staple (safe, but no benefit). Fine for Let's Encrypt (issuer-signed); flag as a follow-up if a non-LE CA is used.
- **Nonce:** omit the OCSP nonce for stapling (responders serve pre-produced, cacheable, nonce-less responses; LE does not echo nonces). Document.

---

## 7. Files touched (summary)

- `src/crypto/ocsp.zig` — add `buildRequest` + CertID DER + SHA-1 hashing (additive).
- `src/crypto/x509.zig` — AIA OCSP URL, must-staple, `subject_raw_der`, `issuerKeyHashInput` (additive fields + parse branches).
- `src/proto/tls_extension.zig` — `status_request = 5` in `ExtensionType`.
- `src/crypto/tls12.zig` — `certificate_status = 22` in `HandshakeType`.
- `src/crypto/tls_server.zig` — `Config.ocsp_staple`, capture offer, staple leaf CertificateEntry.
- `src/crypto/tls12_server.zig` — `Config.ocsp_staple`, capture offer, ServerHello echo, CertificateStatus message.
- `src/daemon/ocsp_staple.zig` — new fetch/verify/cache/refresh Service.
- `src/daemon/http_fetch.zig` — add HTTP POST (application/ocsp-request) or base64url GET.
- `src/daemon/server.zig` — `config.tls_ocsp_staple`, atomic publish + reactor-0 swap, inject in `tls13Config`/`tls12Config`.
- `src/daemon/config_format.zig` — `[ocsp]` section.
- `src/main.zig` — start the service when `[ocsp].enabled`.

All crypto-layer changes ship with in-file Zig `test` blocks; the daemon service gets unit tests for gating/scheduling.

## Recommendation
Phase the work so each layer lands independently testable and wire-safe:

Phase 1 (pure crypto, no wire change): add `ocsp.buildRequest` + SHA-1 CertID to ocsp.zig, and the x509.zig introspection (AIA OCSP URL, issuer Name DER, issuer key-hash input, must-staple). Ship with Zig test blocks. Zero runtime impact.

Phase 2 (wire emission, gated): add `status_request=5` to tls_extension, `certificate_status=22` to tls12, and `Config.ocsp_staple` + offer-capture + emission to both servers. Prove byte-identical output when the client does not offer status_request or no staple is set, and round-trip the staple through the in-repo tls_client/tls12_client. This can merge while `Config.ocsp_staple` is always null in production (no behavior change).

Phase 3 (daemon service): add `ocsp_staple.zig` (fetch/verify/freshness/cache/refresh) copying the acme_renewal.Service shape, the http_fetch POST path, the `config.tls_ocsp_staple` field + reactor-0 atomic-swap publish (copy the acme_reload plumbing), and the `[ocsp]` config. Turn it on behind `[ocsp].enabled=false` default.

Key decisions to lock before coding:
- SHA-1 CertID is required and acceptable (identifier, not a signature) — document prominently.
- must-staple default: fail-OPEN (serve un-stapled + log loudly) unless operator sets `must_staple_strict=true`; failing closed on a responder outage would drop the whole IRCS port, which is worse than a soft-fail for most deployments.
- OCSP nonce omitted; delegated-responder verification deferred (issuer-signed only, which covers Let's Encrypt).

STRONG caveat for go/no-go: Let's Encrypt is retiring OCSP (removing OCSP URLs from issued certs and ending must-staple issuance). If this deployment's certs come from LE, newly-issued leaves may have no AIA OCSP URL at all, in which case this feature correctly no-ops and delivers nothing. Confirm the CA still publishes an OCSP responder URL in the leaf's AIA before investing in Phase 3; Phases 1–2 are low-cost and worth having regardless (they complete the symmetric client/server OCSP surface and are inert until fed a staple).

Effort: M — ~4-6 focused days. Phase 1 (ocsp.buildRequest + x509 AIA/must-staple/key-hash): ~1-1.5d. Phase 2 (both TLS engines' emission + byte-compat and round-trip tests): ~1.5-2d. Phase 3 (daemon fetch/cache/refresh service + http_fetch POST + reactor-0 publish + config): ~1.5-2d. Add ~0.5d for live verification against a real responder (openssl s_client -status) on the two nodes. Delegated-responder support and SHA-256 CertID are out-of-scope follow-ups.