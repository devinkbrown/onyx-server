# RFC 8879 certificate compression for Onyx Server's TLS 1.3 server

> **Superseded / historical — preserved as evidence.** This document is a point-in-time record and does not describe the current source or fleet. Current truth: [docs hub](../../README.md) and [production paths](../../ops/onyx-server-paths.md). Do not execute it as a current procedure.


Design spike for RFC 8879 Certificate Compression in Onyx Server's Zig-native TLS stack. The server would negotiate the `compress_certificate` extension (27): the client lists compression algorithms it can decompress in ClientHello, and when it offers `zlib(1)` and the feature is config-enabled, the server compresses the Certificate message body and sends it as a new `CompressedCertificate(25)` handshake message in place of `Certificate(11)`. The whole thing reuses the in-tree `std.compress.flate` compressor in its `.zlib` (RFC 1950) container mode — I proved end-to-end (compress → RFC1950 stream → decompress round-trip + bomb-cap) against the deployed Zig 0.16 std, so no new compression dependency is needed. Only zlib is viable because std's zstd is decompress-only and there is no brotli in std. Wire compatibility is preserved by gating behind a default-off config flag; the deployed binary's bytes are unchanged until opted in, and even then it only triggers for clients that explicitly advertised support. Why: smaller Certificate flights (especially RSA chains with intermediates + embedded SCTs) cut handshake bytes and round-trip latency, and it is a modern, widely-implemented TLS extension consistent with Onyx Server's posture.

## RFC 8879 Certificate Compression — design (read-only spike, no code)

### 0. What exists today (survey results)

- **No certificate compression anywhere** — grepping `compress_certificate`/`compressed_certificate`/type 27 across `src/` returns nothing.
- **A reusable in-tree compressor exists.** `src/proto/permessage_deflate.zig` already drives `std.compress.flate` (Zig 0.16) for WebSocket permessage-deflate. That gives us the exact call pattern for `flate.Compress` / `flate.Decompress`. It uses the `.raw` container; RFC 8879 needs the `.zlib` container instead (2-byte RFC 1950 header + Adler-32 trailer), which `std.compress.flate.Container.zlib` supports.
- **std compressor availability (decisive for algorithm choice):**
  - `std.compress.flate` → **Compress + Decompress**, containers `.raw/.gzip/.zlib`. Maps directly to RFC 8879 `zlib(1)`.
  - `std.compress.zstd` → **Decompress only** (no compressor in std 0.16) → cannot be a *send-side* algorithm.
  - **No brotli** in std.
  - Conclusion: **zlib(1) is the only algorithm Onyx Server can *produce*.** I ran a throwaway `zig test` (Zig 0.16.0) proving `flate` `.zlib` compresses DER-like data smaller, emits the `0x78` RFC1950 header, round-trips byte-for-byte, and that `reader.allocRemaining(.limited(cap+1))` yields `error.StreamTooLong` when output exceeds the cap — the bomb guard primitive.

### 1. Send path today (the code we hook)

- `writeCertificate` — `src/crypto/tls_server.zig:1074`. Builds `body` = `[ctx_len=0][u24 cert_list_len][ {u24 der_len, der, u16 ext=0} … ]`, then `self.emit(out, .certificate, body.items)` at line 1088. **`body.items` is exactly what RFC 8879 compresses**, and `body.items.len` is the `uncompressed_length`.
- `emit` — `:1068` → `writeHandshake` (`:1741`) frames `type||u24 len||body` and `appendTranscript`s the exact wire bytes. **This makes the transcript automatically correct for compression**: emitting `.compressed_certificate` folds the type-25 message (not the original type-11) into the transcript, which is precisely RFC 8879 §5's requirement.
- Flight assembly — `buildServerFlight` `:718`; `writeCertificate` is called at `:738`, already gated on `!self.resumed` (`:736`). Resumption sends no Certificate, so no CompressedCertificate — nothing to special-case.
- ClientHello extension loop — `processClientHello` `:789–819`, a `switch (ext.typed())` over `tls_extension.Iterator`.
- Extension registry — `src/proto/tls_extension.zig` `ExtensionType` (named types 0/10/13/16/41/42/43/44/45/51, else `_`) + `isKnown`.

### 2. Negotiation

**Extension `compress_certificate` = 27** (RFC 8879 §3). ClientHello `extension_data`:
```
uint8  algorithms_length;      // = 2*n, wire range 2..254
uint16 algorithms[n];          // CertificateCompressionAlgorithm each; zlib=1, brotli=2, zstd=3
```
The server does **not** echo this extension in ServerHello/EncryptedExtensions (RFC 8879 only puts it in ClientHello and, for the mTLS/client-cert direction, in CertificateRequest). So no server-hello builder buffers change.

Add `compress_certificate = 27` to `tls_extension.zig`'s `ExtensionType` enum + its `isKnown` list (clean, matches the module's "named types" design; a raw `ext.ext_type == 27` match in the `else` arm is the alternative but reads worse).

New switch arm in `processClientHello`:
```
.compress_certificate => if (self.config.enable_cert_compression)
    self.cert_compression = pickCertCompression(ext.data),
```
`pickCertCompression` bounds-checks `algorithms_length`, requires even length, scans u16s, returns `.zlib` iff `1` is present (we ignore brotli/zstd we can't produce), else `null`. New Server field `cert_compression: ?CertCompressionAlgorithm = null` (`src/crypto/tls_server.zig:~234`). New `Config` field `enable_cert_compression: bool = false` (`:~79`) — **default off ⇒ byte-for-byte-identical handshake vs the deployed binary** until opted in.

### 3. Send: build CompressedCertificate

New `HandshakeType.compressed_certificate = 25` (server enum `:1418`; client enum `src/crypto/tls_client.zig:133`).

`CompressedCertificate` body (handshake type 25):
```
uint16 algorithm;                     // 0x0001 zlib
uint24 uncompressed_length;           // = plain Certificate-body length
uint24 compressed_length;             // vector length prefix
opaque compressed_certificate_message[compressed_length];   // zlib(body) via flate .zlib
```
`writeCertificate` change (surgical):
1. Build `body` exactly as now.
2. If `self.cert_compression == .zlib`: `compressed = deflateZlib(body.items)` (mirror `permessage_deflate` but `.zlib` container, `Options.level_6`, **no** RFC-7692 tail stripping — keep the full RFC1950 stream).
3. **Fallback guard:** emit compressed only if `compressed.len < body.items.len` (RFC lets the server send either form; this avoids pathological expansion on tiny Ed25519/ECDSA chains). Otherwise fall through to the unchanged `emit(out, .certificate, body.items)`.
4. Compressed form: assemble `algo(2)||u24(body.len)||u24(compressed.len)||compressed` and `emit(out, .compressed_certificate, cc_body)`. Sent inside the same encrypted flight, no other flight changes.

`CertificateVerify` (`:1091`) and `Finished` are unaffected — they hash the transcript, which now contains the type-25 message, exactly as the peer sees it.

### 4. Receive path + decompression-bomb guard (symmetric half)

The bomb guard lives on the **decompressor**. In the server-send-only slice, Onyx Server never decompresses (peers/browsers enforce their own guard), so shipping send-only adds a *compressor* with **zero untrusted-input parsing**. The guard becomes load-bearing the moment Onyx Server *offers* compression as a client or accepts compressed *client* certs under mTLS. Design it now:

- **Client offer:** in `writeClientHello` (`src/crypto/tls_client.zig:820–913`) add the extension via the existing raw-id pattern (cf. `const ext_status_request: u16 = 5;` `:1616`): `const ext_compress_certificate: u16 = 27;` then `ext_builder.add(ext_compress_certificate, &[_]u8{ 2, 0, 1 })` (len=2, zlib). `ext_storage` is `[4096]` — ample.
- **Client receive:** in `wait_certificate` (`:1115–1130`), if `msg.typ == .compressed_certificate`, parse `algorithm/uncompressed_length/compressed_length`, decompress → `parseAndVerifyCertificate(decompressed)`, then `appendTranscript(msg.raw)` (**the type-25 wire bytes**, never a reconstructed type-11).

**Guard (three layers — RFC 8879 §4/§5):**
1. **Reject `declared_uncompressed_length > max_cert_msg_body` before allocating** (new const, e.g. `65536` — covers RSA chains + SCT/OCSP staples with margin; RFC leaves the value to the implementor). This bounds the allocation an attacker can request purely by lying about the length. Reject `== 0` too.
2. **Cap actual output at the declared length:** `flate.Decompress.init(&in, .zlib, window)` then `reader.allocRemaining(a, .limited(declared_len + 1))`; `error.StreamTooLong` ⇒ decompression bomb ⇒ abort with `bad_certificate`. (Proven working in the spike.)
3. **Exact-length match after:** `decoded.len == declared_len` else `bad_certificate` (RFC 8879 §4).

Unsupported `algorithm` (brotli/zstd) on receive ⇒ `bad_certificate` (we only wire zlib decode; std has a zstd *decoder* if we ever want to accept zstd, but keep attack surface minimal and symmetric — zlib only).

### 5. Edge cases

- PSK resumption: no Certificate sent ⇒ no CompressedCertificate (already gated on `!resumed`).
- Client offers only brotli/zstd: `pickCertCompression → null` ⇒ plain Certificate (server MAY compress; not required — no interop break).
- Tiny cert where zlib doesn't help: fallback guard emits plain Certificate.
- `uncompressed_length` u24 overflow: `writeHandshake` already caps handshake bodies at `0x00ff_ffff`; real cert bodies are far below the 64 KiB policy cap. Guard the u24 build anyway.
- Malformed/odd-length algorithm vector, empty ext_data: `pickCertCompression → null`.
- **CRIME/BREACH:** N/A. RFC 8879 §6: the Certificate is fixed server data, not attacker-adjacent secret+chosen-plaintext, so compressing it is safe (unlike TLS record compression). One-line note in the module doc-comment.

### 6. Wire-compat & security posture

- **Deployed-binary safe:** `enable_cert_compression=false` default ⇒ identical bytes. When enabled, only clients that advertised `compress_certificate` receive a type-25 message — and by advertising it they guarantee they can decode it. No renegotiation, no downgrade surface; fully inside the encrypted flight.
- **Phase ordering minimizes risk:** ship **server-send-only** first (compressor only, no untrusted decode in Onyx Server); add the **client-offer + decompress + bomb guard** as a second increment.
- Modern-posture consistent: no CBC/renegotiation/legacy touched; TLS 1.3 only (1.2 path in `tls12_*` untouched — RFC 8879 is TLS 1.3-only anyway).

### 7. Test plan (Zig `test` blocks in touched files)

- `tls_extension.zig`: `compress_certificate` `fromInt/toInt/isKnown == 27`; Builder round-trips the new typed extension.
- `tls_server.zig`: `pickCertCompression` accepts `{02,00,01}`→zlib, rejects `{02,00,02}` (brotli)→null, rejects odd length + empty; loopback (existing harness at `:2311+`) where the ClientHello carries `compress_certificate` and the server emits a `compressed_certificate(25)` whose decompressed body byte-equals the plain Certificate body and whose Finished still verifies; fallback test (tiny cert ⇒ plain `certificate(11)`).
- `tls_client.zig` (phase 2): full round-trip loopback — client offers zlib, server compresses, client decompresses, handshake completes, CertFP unchanged; **bomb-guard** tests: declared_len > cap ⇒ `bad_certificate`; zlib stream that over-produces ⇒ `StreamTooLong` ⇒ `bad_certificate`; `decoded.len != declared_len` ⇒ `bad_certificate`.
- KAT: compress a fixed Certificate body, assert `0x78` RFC1950 header + `.zlib` decode recovers it (already demonstrated in the spike).
- Test wiring already covers these files via `src/crypto/root.zig` (`_ = tls_client; _ = tls_server;`).

### 8. Touch list

- `src/proto/tls_extension.zig` — add `compress_certificate = 27` + `isKnown`.
- `src/crypto/tls_server.zig` — `Config.enable_cert_compression`; Server `cert_compression` field; `CertCompressionAlgorithm` enum + `pickCertCompression`; ClientHello switch arm; `HandshakeType.compressed_certificate = 25`; `deflateZlib` helper; `writeCertificate` branch.
- (phase 2) `src/crypto/tls_client.zig` — offer extension; `HandshakeType` 25; `wait_certificate` decompress + 3-layer guard; `inflateCertBody` helper.
- Reference only (no change): `src/proto/permessage_deflate.zig` (call-pattern template).

## Recommendation
Implement in two phases. Phase 1 (server-send-only, recommended first ship): add `zlib(1)` via `std.compress.flate` `.zlib` container — proven working against Zig 0.16 std — gated behind `Config.enable_cert_compression=false`. Negotiate `compress_certificate(27)` from ClientHello, compress the existing `writeCertificate` body, emit `CompressedCertificate(25)` with a "only if it actually shrinks" fallback to plain `Certificate(11)`. This adds a compressor with zero untrusted-input decode surface in Onyx Server and is byte-for-byte wire-compatible with the deployed binary until enabled. Use zlib because std's zstd is decompress-only and there is no brotli in std; brotli-only clients simply fall back to uncompressed (no interop risk). Phase 2 (symmetric receive): have Onyx Server's TLS client advertise zlib and decode server CompressedCertificate, with the mandatory three-layer decompression-bomb guard — reject declared uncompressed_length above a fixed cap (~64 KiB) before allocating, cap actual output at the declared length via `allocRemaining(.limited(len+1))` (StreamTooLong ⇒ bad_certificate), and require exact post-decompress length match. Do NOT attempt brotli/zstd compression (no std compressor). Keep the whole feature TLS 1.3-only. Add Zig test blocks in each touched file plus a full loopback round-trip once both halves exist, and live-verify Phase 1 against a real browser (Chrome/Firefox both advertise zlib) before flipping the flag on the two production nodes.

Effort: M — ~1.5-2 days. Phase 1 (server send + negotiation + config gate + tests): S, ~1 day. Phase 2 (client offer + decompress + bomb guard + round-trip tests): S, ~0.5-1 day. Add ~0.5 day for live browser interop verification and staged rollout across both nodes.