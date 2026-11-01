# Design spike: integrate BoringSSL's BoGo protocol test runner against Onyx Server's Zig-native TLS (a `bogo_shim` executable + shim-config + CI wiring). Design only — no code written.

> **Superseded / historical — preserved as evidence.** This document is a point-in-time record and does not describe the current source or fleet. Current truth: [docs hub](../../README.md) and [production paths](../../ops/onyx-server-paths.md). Do not execute it as a current procedure.


Onyx Server already has everything a BoGo shim needs except a socket-driven front-end and an alert-emission layer. The server path is a clean pure-byte-transform (`src/daemon/tls_conn.zig` `TlsConn`: `onInbound`/`write`/`handshakeDone`, already 1.3+1.2 dispatch + record reassembly), the client path is `src/crypto/tls_client.zig` `Client` (`start`/`feed`/`encrypt`/`decrypt` + ticket/early-data/client-cert setters), and BoGo's own PEM cert/key files load directly via `src/daemon/tls_certs.zig loadOrBootstrap` → no new PEM code. A minimal `tools/bogo_shim.zig` (modeled on the existing `tools/quic_interop_server.zig` standalone-tool pattern) would parse BoGo's CLI flags, dial the runner's TCP port, drive the chosen engine over a small read→feed→write pump, then XOR-echo app data. The one real design problem: Onyx Server's engines return typed Zig errors on protocol violations and NEVER emit TLS alert records on the wire (verified across tls_server/tls_client/tls12_*), so the shim must synthesize alerts from a Zig-error→AlertDescription map to satisfy BoGo's `expectedLocalError` assertions. Scope is bounded by Onyx Server's modern-only capabilities: exclude TLS<1.2, DTLS/CID, CBC, renegotiation, static-RSA/DHE, SHA-1 sigs, and — a real conformance gap — HelloRetryRequest (server never sends it; client returns `HelloRetryRequestUnsupported`). In-scope: TLS1.3 + hardened TLS1.2 ECDHE-AEAD, cipher/curve/sigalg negotiation over the supported set (x25519/secp256r1, AES-128/256-GCM/ChaCha20, Ed25519/ECDSA-P256/RSA-PSS), 1.3 PSK + 1.2 RFC5077 resumption, 0-RTT, mTLS, ALPN/SNI, KeyUpdate, and alert-on-malformed negative tests.

## 1. How BoGo drives a shim (protocol recap)

BoGo is the Go test runner built from `boringssl/ssl/test/runner` (`go test`). Per test it spins up a Go TLS peer on a loopback TCP port and spawns the **shim** subprocess with a long `-flag [value]` argv describing the test. The shim always **dials** `127.0.0.1:<-port>` (TLS role is orthogonal to TCP role); newer BoGo revisions also pass `-shim-id <u64>` which the shim must write as the first 8 bytes (LE) on the raw TCP socket before TLS so the runner can correlate the accept.

- Role: `-server` ⇒ shim is TLS server; absent ⇒ TLS client.
- App-data contract: after the handshake the shim reads each record and writes it back with every byte XOR 0xff, until close_notify/EOF (modulated by `-shim-writes-first`, `-shim-shuts-down`, message-count flags).
- Resumption: `-resume-count N` ⇒ shim does N+1 **separate** TCP connections in-process, persisting the session between them, with `-on-resume-*` overrides on the later legs.
- Failure signaling: on error the shim prints an error string to stderr and exits nonzero. BoGo matches `expectedError` (regex) against the shim's stderr via the **`ErrorMap`** in `-shim-config`, and matches `expectedLocalError` against what its **own Go peer** observed on the wire (⇒ the alert the shim sent).
- Unimplemented: shim exits code **89** (confirm against the pinned revision) to signal "not implemented"; with runner `-allow-unimplemented` those tests report as skipped, not failed. The shim must recognize every flag it's handed — an unknown/unsupported flag ⇒ exit 89.

## 2. Onyx Server surfaces to reuse (verified)

- **Server engine (ready):** `src/daemon/tls_conn.zig` `TlsConn` is a pure byte-transform with exactly the shim's needs: `initDual(alloc, cfg13, cfg12)` (auto 1.3/1.2 dispatch from the ClientHello), `onInbound(bytes) → Outcome{handshake_bytes, plaintext}`, `write(plaintext) → ciphertext`, `handshakeDone()`, `negotiatedVersion()`, `selectedAlpn()`, `cipherName()`, `clientCertDer()`. It already frames/reassembles records across TCP reads (`completeRecordLen`, `consumePrefix`) and drains post-handshake KeyUpdate replies. No syscalls inside — the shim owns the socket.
- **Client engine (ready):** `src/crypto/tls_client.zig` `Client.init(Options{server_name, trust_anchors, alpn_protocols, now_unix_seconds})`, `start() → ClientHello`, `feed(stream) → {need_more | bytes_to_send}` (buffers records internally), `encrypt/decrypt/decryptApp`, `handshakeDone`, `setSessionTicket/takeSessionTicket`, `setEarlyData/earlyDataAccepted`, `setClientCert*ForTest`, `skipServerCertVerifyForTest`, `offerOnlyP256ForTest/offerOnlyAes256ForTest`, `initiateKeyUpdate`. The client has no `TlsConn`-style framing wrapper, so the shim frames app-data records itself (trivial 5-byte header parse — factor a tiny `records` helper or copy `completeRecordLen`).
- **Cert/key from BoGo's own files (ready):** BoGo supplies PEM `-cert-file`/`-key-file`. `src/daemon/tls_certs.zig loadOrBootstrap(alloc, io, .{cert_path, key_path})` returns `Loaded{cert_chain, key_kind, signing_key|ecdsa_p256_signing_key|rsa_signing_key}` — a direct feed into `tls_server.Config`/`tls12_server.Config`. Backed by `src/proto/pem.zig`, `src/proto/rsa_pkcs.zig` (PKCS8/PKCS1), `src/proto/ec_pkcs.zig`. **No new PEM/DER code needed.**
- **Standalone-tool precedent:** `tools/quic_interop_server.zig` + build.zig `addExecutable` importing the `onyx_server` module + a `b.step(...)`, with raw-syscall `writeAll`/`getrandom`/`/proc/self/cmdline` helpers (deliberately dodging Zig-0.16 args/Io API churn). The shim clones this shape.

## 3. Shim executable design — `tools/bogo_shim.zig`

```
main():
  flags = Flags.parse(argv)              // exit 89 on any behavior-changing unknown flag
  alloc = DebugAllocator                  // matches interop tool
  for conn_idx in 0 .. flags.resume_count:  // +1 total
     sock = dial(127.0.0.1, flags.port)
     if flags.shim_id: writeAll(sock, u64le(flags.shim_id))
     engine = flags.server
        ? Server{ TlsConn.initDual(cfg13, cfg12) }   // cfg from loaded cert/key
        : Client{ tls_client.Client.init(opts) }     // trust anchors / skip-verify
     runHandshake(sock, engine, flags) catch |e| { sendAlert(sock, mapErr(e)); exitError(errName(e)) }
     checkExpectations(engine, flags)     // -expect-version/-cipher/-alpn/... mismatch ⇒ exitError
     if conn_idx == 0 and resuming: saved_ticket = engine.takeSessionTicket()
     appDataEcho(sock, engine, flags)     // read → XOR 0xff → write, honor -shim-writes-first etc.
     close(sock)
  exit(0)
```

- **Handshake pump (server):** read → `onInbound` → `writeAll(handshake_bytes)`; loop until `handshakeDone()`. Any `plaintext` produced pre-completion is buffered 0-RTT early data.
- **Handshake pump (client):** `writeAll(start())`; then read → `feed` → on `bytes_to_send` `writeAll` it; loop until `handshakeDone()`.
- **App-data:** frame inbound records; `decrypt`/`onInbound`→plaintext; XOR 0xff; re-`encrypt`/`write`; write back.
- **Resumption:** conn 0 captures the ticket (1.3 PSK NewSessionTicket or 1.2 RFC5077 ticket — both supported); conn >0 client calls `setSessionTicket(saved, age)` (+ `setEarlyData` when `-enable-early-data`). Server resumption is transparent via a shared `ticket_key` + `ReplayGuard` held across the loop (see `tls_conn.zig` resumption tests for the exact shape).

## 4. The alert-emission problem (biggest finding)

Verified: `tls_server.zig`, `tls_client.zig`, `tls12_server.zig`, `tls12_client.zig` only ever **parse** inbound alerts (`content_type == .alert` ⇒ `error.TlsAlert`, client stores `last_alert`). On a protocol violation they return a typed Zig error and the daemon simply drops the TCP connection — **no alert record is ever emitted**. BoGo's `expectedLocalError` assertions require the Go peer to receive a *specific* alert; a bare EOF/RST fails those.

Design choice — the shim synthesizes alerts from a Zig-error→`AlertDescription` map (`src/proto/tls_alert.zig` `encode` already exists) and writes a `content_type=21` record before exit. Seed table:

| Zig error | AlertDescription (code) |
|---|---|
| BadHandshake / DecodeError | decode_error (50) |
| MissingExtension | missing_extension (109) |
| ProtocolVersion | protocol_version (70) |
| UnsupportedCipherSuite / UnsupportedGroup | handshake_failure (40) |
| illegal params (BadRecord in HS) | illegal_parameter (47) |
| FinishedMismatch | decrypt_error (51) |
| bad record MAC | bad_record_mac (20) |
| BadCertificate | bad_certificate (42) |
| UnknownCa | unknown_ca (48) |
| CertificateExpired / Revoked | certificate_expired (45) / certificate_revoked (44) |
| ALPN no overlap | no_application_protocol (120) |
| (default) | internal_error (80) |

Caveat to surface to the user: this is **shim-only scaffolding** — BoGo would be "validating" alert behavior the production daemon doesn't exhibit (pre-handshake alerts are unencrypted so the shim can emit them without engine keys; post-handshake alerts need the engine's write keys, so those cases either route through `engine.write()` of an alert-typed record or get DisabledTest'd). A cleaner long-term alternative is to make the engines emit alerts as a *real* robustness feature (peers today get a bare RST instead of a diagnostic) — worth a separate decision.

## 5. In-scope vs out-of-scope subset (tied to verified capabilities)

**Exclude (via `-shim-config` DisabledTests regex + exit-89):**
- TLS ≤1.1 / SSLv3 — modern-only; shim advertises min-version 1.2. (`*TLS1-*`, `*TLS11-*`, `*SSL3-*`, `-max-version 769/770`.)
- DTLS + DTLS-CID — no DTLS stack (`*DTLS*`).
- CBC / 3DES / RC4 cipher families — AEAD-only (`*CBC*`, `*3DES*`, `*RC4*`).
- Renegotiation — unsupported (`*Renegotiate*`).
- Static-RSA / plain-DHE / FFDHE key exchange — ECDHE-only.
- SHA-1 certificate signatures — `x509_verify` rejects them.
- **HelloRetryRequest** — real gap: server never sends HRR (doc: "intentionally out of scope"), client returns `error.HelloRetryRequestUnsupported` (`*HelloRetryRequest*`, `*HRR*`, and curve-mismatch tests that force HRR).
- P-384/P-521/FFDHE groups — only x25519 / secp256r1 / x25519mlkem768 exist.
- ECH, Channel-ID, delegated credentials, QUIC-transport-params-in-TLS, compression, multi-ticket count assertions (server issues a single NewSessionTicket).

**Include (modern-only, all backed by existing code):**
- TLS 1.3 full handshake, both roles; hardened TLS 1.2 ECDHE-AEAD, both roles.
- Cipher negotiation: TLS_AES_128_GCM_SHA256 / _256_GCM_SHA384 / _CHACHA20_POLY1305_SHA256, ECDHE-ECDSA/RSA-AEAD (1.2).
- Curve negotiation over x25519 / secp256r1 (hybrid x25519mlkem768 where BoGo knows the codepoint, else skip).
- Signature-alg negotiation: ed25519, ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256 (verify-only P-384 chains possible).
- Resumption: 1.3 PSK-DHE tickets, 1.2 RFC5077 tickets, `-resume-count`, `-expect-session-miss`.
- 0-RTT early data (1.3): accept/reject, replay-guard, `-enable-early-data`, `-expect-early-data-reason`.
- Client auth / mTLS (CertFP possession-proof model: any presented leaf accepted, empty-cert decline path).
- ALPN advertise/select/mismatch, SNI, KeyUpdate (both directions), SCT/OCSP-stapling presence.
- Record-layer negatives: oversize ⇒ record_overflow, unexpected content type, trailing bytes, wrong legacy version, records split across TCP reads (TlsConn reassembles), malformed handshake ⇒ decode_error/illegal_parameter/unexpected_message, bad Finished ⇒ decrypt_error.

## 6. `-shim-config` JSON (`tools/bogo/config.json`)

Two keys carry the integration:
- `DisabledTests`: `{ "<regex>": "<reason>" }` for every excluded family above (this is where the modern-only posture is encoded).
- `ErrorMap`: `{ ":BORINGSSL_CONSTANT:": "<onyx shim stderr substring>" }` so `expectedError` regexes match Onyx Server's error names (e.g. `":UNEXPECTED_MESSAGE:" → "unexpected_message"`, `":DECODE_ERROR:" → "decode_error"`, `":WRONG_VERSION_NUMBER:" → "ProtocolVersion"`). This map is the long-tail iteration surface.

## 7. Minimal production-code touches (surgical)

Only accessor additions, no behavior change, each with a Zig test in the touched file:
- `TlsConn`/`tls_server`/`tls_client`: `negotiatedGroup() ?NamedGroup`, `peerSignatureScheme() ?u16`, `serverName() ?[]const u8` — needed only for `-expect-curve-id` / `-expect-peer-signature-algorithm` / `-expect-server-name`. Alternative: DisabledTest those expectation flags and touch nothing. Recommend adding the three read-only accessors (small, generally useful for WHOIS/telemetry too) rather than blinding those assertions.
- Everything else (cert load, alerts, tickets, early data, client certs) already has a public/`ForTest` entry point.

## 8. Driver script + CI

- `tools/bogo.sh`: pin boringssl at a fixed commit into a cached `.bogo/boringssl` (BoGo tests drift — pinning is mandatory for determinism); `zig build bogo-shim` → `zig-out/bin/bogo_shim`; `cd boringssl/ssl/test/runner && go test -shim-path .../bogo_shim -shim-config .../tools/bogo/config.json -allow-unimplemented -num-workers $(nproc) [-test <regex>]`.
- `build.zig`: add `bogo-shim` step mirroring the `quic-interop-server` block (addExecutable importing `mod`, `link_libc = needs_libc`, `addInstallArtifact`). Keep it out of `zig build test` (it's a separate harness, not a unit-test module).
- `.github/workflows/ci.yml`: new `bogo` job — checkout, install Zig 0.16.0 (reuse the existing tarball step), `actions/setup-go`, cache the pinned boringssl, `zig build bogo-shim`, run `tools/bogo.sh`. Start `continue-on-error: true` (informational) until DisabledTests/ErrorMap stabilize, then flip to required.

## 9. Edge cases & risks

- **Alert scaffolding fidelity** (§4) — the headline caveat; shim invents alerts the daemon doesn't send.
- **No HRR / limited groups** — genuine conformance gaps, documented as exclusions; adding HRR later is a real server+client feature.
- **shim-id socket prefix** must match the pinned BoGo revision (some gate it, some always send) — verify against the checkout.
- **Zig 0.16 args/Io churn** — the shim parses many flags; prefer `std.process.argsAlloc` if stable in 0.16, else the interop tool's raw `/proc/self/cmdline` path. Cert loading needs an `std.Io` — thread one through like `tls_certs` callers do.
- **Single-ticket server** — disable BoGo tests asserting >1 ticket.
- **Client-cert setters are `...ForTest`** — fine for a test tool, but note they're not a production API.
- **Post-handshake alert encryption** — pre-handshake alerts are plaintext (easy); post-handshake alert cases need the engine write keys or DisabledTest.

## 10. Test plan

1. `zig build bogo-shim` compiles (both roles) under Zig 0.16.
2. Loopback smoke: a Zig test in `tools/` that (a) listens, (b) spawns the shim as **server**, feeds shim-id + a real ClientHello via `tls_client.Client`, completes the handshake, and asserts the XOR-echo; then the mirror with the shim as **client** driven by `TlsConn`. This validates the socket pump + shim-id + echo without BoGo.
3. Full: `tools/bogo.sh` against pinned boringssl; record pass/skip/fail counts; iterate `ErrorMap`/`DisabledTests` to 0 *unexpected* failures.
4. Wire the CI job as informational, then required once green.

## 11. Files

- New: `tools/bogo_shim.zig`, `tools/bogo.sh`, `tools/bogo/config.json`, (optional) `tools/bogo_records.zig` framing helper.
- Touch: `build.zig` (+`bogo-shim` step), `.github/workflows/ci.yml` (+`bogo` job), and — if adopting §7 — three tiny read-only accessors in `src/crypto/tls_server.zig`, `src/crypto/tls_client.zig`, `src/daemon/tls_conn.zig`, each with a test block.

## Recommendation
Build it as a standalone `tools/bogo_shim.zig` cloning the `tools/quic_interop_server.zig` pattern — reuse `TlsConn` (server), `tls_client.Client` (client), and `tls_certs.loadOrBootstrap` (BoGo's own PEM cert/key) so the shim adds only: flag parsing, a raw-socket dial+pump, the resumption loop, the XOR-echo, and the Zig-error→alert synthesizer. Encode the modern-only posture entirely in `tools/bogo/config.json` (DisabledTests for TLS<1.2, DTLS/CID, CBC, renego, static-RSA/DHE, SHA-1, HelloRetryRequest, non-x25519/P256 groups) plus an ErrorMap for the negative tests. Add the three read-only expect-accessors rather than blinding those assertions. Phase it: (1) shim binary + build step + loopback smoke test (no BoGo) → provable end-to-end; (2) pin boringssl, wire `tools/bogo.sh`, land a first DisabledTests/ErrorMap pass, get a green subset; (3) add the CI job as `continue-on-error` informational, iterate the config to zero unexpected failures, then make it required. Explicitly flag two things to the user for a decision before phase 2: (a) the shim-invents-alerts fidelity gap — decide whether to accept shim scaffolding or promote alert emission to a real engine feature; (b) HelloRetryRequest as an accepted conformance exclusion vs. a future feature. Keep the shim out of `zig build test`.

Effort: M–L, ~4–6 focused days. Phase 1 (shim binary + flag parsing + socket pump + cert/key load + alert map + build step + loopback smoke): ~M, 2–3 days. Phase 2 (pin boringssl, driver script, first DisabledTests/ErrorMap, green subset): ~1–2 days, with a long tail of config whack-a-mole. Phase 3 (CI job, iterate to zero-unexpected-failures, flip to required): ~0.5–1 day. Optional §7 accessors add well under a day. No production wire-behavior changes.