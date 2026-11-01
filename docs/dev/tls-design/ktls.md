# Design spike: Linux kTLS (kernel TLS offload) for Onyx Server's Zig-native TLS stack — TX/RX offload, sendfile/zero-copy, and reconciliation with the USR2 live-session export

> **Superseded / historical — preserved as evidence.** This design spike recommended TX-only kTLS first; the shipped implementation admits TX+RX (`[tls] ktls = "txrx"`, deployed fleet-wide 2026-11-01) with both-direction KeyUpdate through the kernel control path. Current implementation: `src/daemon/ktls.zig`, `src/daemon/tls_conn.zig`, and [the TLS guide](../../guide/tls.md#kernel-tls-offload-ktls). Do not execute this spike as a current procedure.


Onyx Server terminates all client TLS in userspace: `src/daemon/tls_conn.zig` frames records and drives `crypto/tls_server.zig` (1.3) / `tls12_server.zig`+`tls12.zig` (1.2); the daemon's send path (`appendSecuredToConn` at server.zig:26530 → `t.write()` → `rawAppendToConn` → io_uring `submitSend` of `conn.send_buf`) encrypts every outbound record with a userspace AEAD, and `driveTls` (server.zig:6516) decrypts every inbound record. kTLS would move the AEAD into the kernel (`setsockopt(TCP_ULP,"tls")` + `SOL_TLS`/`TLS_TX`/`TLS_RX` with `tls12_crypto_info_*`), cutting a copy + the userspace AEAD on the hot path and unlocking `splice`/`sendfile` for bulk. The stated collision — kTLS moving keys+seq into the kernel vs Onyx Server's userspace `exportResume` snapshot across USR2 — largely dissolves once you notice kTLS state is *kernel socket state that survives execve*, and Onyx Server already carries client fds across execve (CLOEXEC cleared, re-attached in `adoptInheritedClient`). So the offloaded direction keeps working on the successor's inherited fd with zero key re-injection; the real work is a 1-bit "offloaded" marker in the snapshot plus reworking the send/recv seams, not extracting/reinjecting kernel keys. getsockopt(TLS_TX/TLS_RX) extraction is a viable fallback (returns key+salt+iv and the live TX rec_seq) but is fragile for RX (kernel-buffered partially-read records), so the recommendation is TX-only kTLS first, RX left in userspace, rolled out to the highest-throughput TLS surfaces (wss media/upload data-plane) before interactive IRC-line clients. S2S links are NOT TLS (Mooring/Undertow), so they are out of scope for kTLS — correcting the task premise.

## 1. Current architecture (what kTLS displaces)

**Userspace TLS termination, per client conn:**
- `ConnState.tls: ?*tls_conn.TlsConn` (server.zig:1910). Created in the accept path (server.zig:4859/4898) as `TlsConn.init` (1.3-only) or `TlsConn.initDual` (1.3+hardened-1.2).
- **Inbound:** `driveTls` (server.zig:6516) → `conn.tls.?.onInbound(chunk)` → `tls_conn.zig:171` frames complete records (`completeRecordLen`), feeds the handshake or `decryptRecord` → `Server.decrypt` (tls_server.zig:580) / `tls12` `openRecordAlloc` (tls12.zig:428). Decrypted plaintext → `feedBytes`/`driveWs`.
- **Outbound:** IRC/WS bytes → `appendToConn` (server.zig:26508) → `appendSecuredToConn` (server.zig:26530): `if (t.handshakeDone()) t.write(bytes)` (`tls_conn.zig:264` → `Server.encrypt` tls_server.zig:572 → `sealRecordAlloc`), then `rawAppendToConn` copies ciphertext into the fixed inline `conn.send_buf` (server.zig:1792); `armSendIfNeeded` (server.zig:6299) issues io_uring `submitSend` (server.zig:823, plain `IORING_OP_SEND`, seqno 0 flags). Handshake flights bypass the encrypt seam via `rawAppendToConn` directly (already-sealed records).
- **Record keys/seq live in userspace:** `Server.server_app_keys/client_app_keys` (TrafficKeys: 32B key + 12B iv, tls_server.zig:208) and `app_write_seq`/`app_read_seq` (tls_server.zig:291); TLS 1.2 in `tls12.DirectionKeys` + seqs.

**USR2 live upgrade (the crown jewel kTLS must not break):**
- Client fds are carried across `execve` (CLOEXEC cleared on carried sockets; re-armed at adopt, server.zig:14857). Kernel socket state therefore persists onto the successor's inherited fd.
- Per-conn TLS crypto is serialized through a sealed memfd arena: `TlsConn.exportResume` (tls_conn.zig:230) → `Server.exportResume` (tls_server.zig:632) carries **traffic secrets** (`client_app_secret`/`server_app_secret`, NOT raw keys — needed to re-derive keys and to run KeyUpdate), `exporter_master_secret`, `app_read_seq`, `app_write_seq`, and `pending_recv` (a buffered *partial inbound ciphertext record*). Serialized by `helix/tls_snapshot.zig` (secrets + seqs + pending_recv + pending_out + certfp). Successor rebuilds via `adoptTlsState` (server.zig:14867) → `TlsConn.resumeFrom` → `Server.resumeConnected` (tls_server.zig:650), which re-derives keys from the secrets and restores seqs.
- **Post-handshake:** TLS 1.3 KeyUpdate is fully supported (server.zig / tls_server.zig:607,671) and NewSessionTicket is queued post-Finished (tls_server.zig:500). These emit handshake-type records through `takePendingSend`/`rawAppendToConn`.

**S2S is not TLS.** `secured_s2s_link.zig` uses Mooring (PQ AKE, its own record framing); plain links use Undertow. Neither goes through `TlsConn`. **kTLS does not apply to mesh links** — the task's "S2S bulk links vs client-facing" split is moot; the only kTLS-eligible sockets are client-facing implicit-TLS (incl. wss-over-TLS).

## 2. kTLS attach mechanics (what we add)

Per connection, once the handshake is complete and all handshake-type records are flushed:
```
setsockopt(fd, SOL_TCP, TCP_ULP, "tls", 4);              // attach ULP (one-way, permanent)
setsockopt(fd, SOL_TLS, TLS_TX, &info_tx, sizeof info_tx);  // server->client encrypt
// (Phase 3) setsockopt(fd, SOL_TLS, TLS_RX, &info_rx, ...); // client->server decrypt
```
Constants we must define ourselves (not in Zig std): `SOL_TLS=282`, `TCP_ULP=31`, `TLS_TX=1`, `TLS_RX=2`, `TLS_1_2_VERSION=0x0303`, `TLS_1_3_VERSION=0x0304`, cipher types `AES_GCM_128=51 / AES_GCM_256=52 / CHACHA20_POLY1305=54`, and the `tls12_crypto_info_aes_gcm_128/256` and `..._chacha20_poly1305` C structs (packed).

**Mapping Onyx Server TrafficKeys → crypto_info** (clean, no new derivation):
- **TLS 1.3 AES-GCM:** `key = server_app_keys.key[0..klen]`; `salt = iv[0..4]`; `iv = iv[4..12]`; `rec_seq = app_write_seq` (8B big-endian); `version = TLS_1_3_VERSION`. (Kernel forms per-record nonce = static_iv XOR padded_seq — matches RFC 8446.)
- **TLS 1.2 AES-GCM:** `salt = DirectionKeys.iv[0..4]` (the 4B fixed IV, tls12 `fixedIvLen`), `iv = ` initial explicit nonce = `rec_seq`, `rec_seq = app_write_seq`, `version = TLS_1_2_VERSION`. Kernel picks the 8B explicit nonce per record; our `openRecordAlloc` already reads the explicit nonce off the wire (tls12.zig:451) so RX interop is unaffected if we keep RX userspace.
- **ChaCha20-Poly1305 (1.2/1.3):** `salt` len 0, `iv = ` 12B key iv, `key` 32B, `rec_seq` 8B.

**Attach point (TX):** at the `state → connected` transition in `driveTls`, *after* the server flight and — critically — after the queued NewSessionTicket is drained to `send_buf`. Sequence discipline: any handshake-type record (NST, KeyUpdate) must NOT be written as plaintext to a TX-offloaded socket (kernel would encrypt it as application_data). Options: (a) flush NST before attach and *disable server-initiated post-handshake sends* on kTLS conns; or (b) send control records via `sendmsg` + `TLS_SET_RECORD_TYPE=22` cmsg. Recommend (a) for Phase 1 (simplest; NST already fires pre-attach, KeyUpdate is server-initiated and rare — gate it off for kTLS conns).

**Send-seam change:** `appendSecuredToConn` gains a branch — if `conn.tls_tx_offloaded`, skip `t.write()` and `rawAppendToConn(conn, bytes)` the **plaintext** straight to `send_buf` (kernel encrypts on `send()`). WS text-framing and labeled-response capture happen *before* this seam (server.zig:26514–26522) so they are unaffected. io_uring `submitSend` is unchanged (still plain `IORING_OP_SEND` — see §5 re SEND_ZC). Bulk/disk-backed payloads can additionally use `IORING_OP_SPLICE`/`sendfile` into the TX-offloaded socket for true zero-copy.

## 3. The CRITICAL question: kTLS state vs USR2 export

**Finding: kTLS state is kernel `struct sock` state and survives `execve`.** Onyx Server carries client fds across execve, so a TX-offloaded socket keeps encrypting on the successor's inherited fd with the kernel's live keys+seq — **no extraction, no re-injection**. The collision the task worried about is specific to the *userspace* `exportResume` mechanism, which becomes partly redundant for the offloaded direction.

**Two ways to preserve a kTLS conn across USR2:**

**(A) Recommended — lean on execve persistence (no kernel key extraction):**
- Carry a 1-bit `tls_tx_offloaded` marker (+ negotiated suite + retained `server_app_secret` for possible future KeyUpdate) in `tls_snapshot`. Wire format already has an engine byte and secrets; add a flag byte — additive, back-compatible if versioned.
- `adoptTlsState` branch: for an offloaded conn, DO NOT rebuild a userspace TX path or call setsockopt again (kernel state already attached to the inherited fd). Just set `conn.tls_tx_offloaded=true` so the successor's send seam sends plaintext. RX stays userspace (Phase 1), so `app_read_seq`/secrets/`pending_recv` continue to carry exactly as today.
- **Net: TX seq never needs to be read from the kernel.** The kernel owns it; the successor never touches it.

**(B) Fallback / portable — getsockopt extraction:**
- `getsockopt(fd, SOL_TLS, TLS_TX, &info, &len)` copies out key+salt+iv and `cctx->rec_seq`. On modern kernels the TX `rec_seq` is the *live* per-record-incremented value (kernel bumps the same buffer via `tls_advance_record_sn`), so it is extractable and can repopulate `app_write_seq` before serialization — the existing `tls_snapshot` format then works unchanged.
- **RX caveat:** `getsockopt(TLS_RX)` returns the RX `rec_seq`, but if the kernel holds a record it decrypted-but-userspace-hasn't-fully-read, the seq and the userspace byte position desynchronize — extraction is not reliably exact. This is why RX offload is deferred.
- Use (B) only where fds can't be carried (e.g. hypothetical cross-host migration) or to validate (A). Guard behind a boot self-test that offloads a socketpair, pushes N records, and asserts `getsockopt` returns seq==N.

**Re-handshake fallback:** required only if a conn is kTLS'd AND (getsockopt liveness self-test fails on the deploy kernel) AND we chose path (B), or once RX offload lands and RX-seq reconciliation can't be made exact. It is the guaranteed-correct degradation (drop → client reconnects), gated behind the probe; it is NOT needed for the recommended TX-only + execve-persistence design.

## 4. Phased rollout

- **Phase 0 — probe + plumbing (no behavior change).** Boot-time capability probe: attempt `TCP_ULP="tls"` on a throwaway socket, then `TLS_TX` with each configured cipher; record which suites are offloadable. Add `[tls] ktls = off | tx | txrx` (default `off`). Add the getsockopt-seq liveness self-test. Define constants/structs in a new `src/daemon/ktls.zig` with Zig test blocks (crypto_info encoders, suite→cipher_type mapping, seq layout).
- **Phase 1 — TX-only on the wss data-plane first.** Enable TX offload for the highest-throughput TLS surfaces (browser wss media relay binary frames + any bulk/history replay), where the AEAD+copy cost and `splice`/`sendfile` zero-copy dominate. Send seam sends plaintext; disable server-initiated KeyUpdate/NST-after-attach on kTLS conns. USR2 via path (A). This is the smallest change that captures most of the benefit.
- **Phase 2 — TX-only broad rollout** to interactive IRC-line TLS clients once Phase 1 is proven live on the deploy kernel (mainly CPU/copy savings at scale; per-line syscall win is marginal for sub-MTU IRC).
- **Phase 3 (optional, later) — RX offload.** Only if profiling shows inbound AEAD is a real cost. Requires: `recvmsg`+cmsg (`TLS_GET_RECORD_TYPE`) to demux handshake/alert control records from app data; retiring the userspace `pending_recv` partial-record buffer (kernel reassembles); handling post-handshake KeyUpdate arriving as a control record (re-`setsockopt(TLS_RX)`); and solving the RX-seq/kernel-buffered-record export reconciliation. Highest risk — keep behind its own flag.

## 5. Kernel / cipher / io_uring constraints

- `CONFIG_TLS=y|m`; `modprobe tls`. **Verify the ircx.us deploy kernel** (local dev is 7.0.3, fine).
- Cipher availability by kernel: AES-GCM-128 TX 4.13 / RX 4.17; **TLS 1.3 5.1**; AES-GCM-256 5.2; **ChaCha20-Poly1305 5.11**. All six of Onyx Server's suites (1.2 + 1.3, GCM-128/256 + ChaCha) are covered by **kernel ≥ 5.11**. Probe per-suite and fall back to userspace for any the kernel rejects.
- **io_uring:** plain `IORING_OP_SEND` of plaintext works with SW kTLS TX. **`SEND_ZC` (zerocopy) is incompatible with SW kTLS TX** (kernel must copy plaintext to encrypt) — keep the current non-ZC send for kTLS conns; the `RingFeatures.send_zc` path (server.zig:638) must not be taken for offloaded fds. True TX zerocopy needs NIC-offloaded (device) kTLS, out of scope.
- `TCP_ULP` is **one-way** — once "tls" is attached you cannot detach. A conn that offloads is TLS-for-life; the re-handshake fallback means dropping the socket, not un-offloading.
- Record segmentation changes: kernel emits ≤16KB records and `splice` may coalesce differently than our 16KB `max_plaintext_len` chunking (tls_conn.zig:270) — still spec-compliant, but on-wire record boundaries shift (fine for any conformant client).

## 6. Edge cases

- **NST / KeyUpdate ordering** (see §2): must flush all handshake-type records before TX attach; gate server-initiated post-handshake sends off for kTLS conns (Phase 1).
- **mTLS unaffected:** client-cert capture happens during the userspace handshake (pre-attach); `clientCertDer`/certfp binding (server.zig:6523) is unchanged.
- **Channel binding / exporter:** `tls-exporter` (tls_conn.zig:161) is derived from `exporter_master_secret`, computed in userspace at handshake — unaffected by TX offload; keep the secret in the snapshot.
- **Partial `send_buf` at attach:** ensure `send_offset==send_len` (no in-flight ciphertext) at the attach instant, or the tail (ciphertext) plus new plaintext would mix. Attach only when the send queue is drained, else defer attach to the next drained point.
- **Reload/REHASH of certs** does not touch live traffic keys, so kTLS conns are unaffected.
- **Alert on close:** with TX offload the kernel can emit close_notify; ensure our close path doesn't also try to userspace-seal an alert.

## 7. Test plan

- **Unit (Zig test blocks in `ktls.zig`):** suite→cipher_type mapping; crypto_info byte layout for all six suites (golden vectors); TX seq big-endian encode; TLS 1.3 iv→salt/iv split; 1.2 fixed-iv→salt mapping.
- **Integration (loopback, gated by kernel probe / `SkipZigTest` when unsupported):** offload a real socketpair after a `tls_server`↔`tls_client` handshake; send via kernel, decrypt with the in-repo `tls_client` — assert plaintext round-trips for GCM-128/256 + ChaCha, both 1.2 and 1.3. RX-side (Phase 3) symmetric.
- **getsockopt seq liveness self-test:** push N records through the kernel, `getsockopt(TLS_TX)`, assert `rec_seq==N` — the gate that decides whether path (B) is available.
- **USR2 preservation e2e:** existing zero-drop upgrade test extended — establish a TX-offloaded client, trigger `systemctl kill -s USR2`, assert the client's record stream continues unbroken on the successor (path A: inherited fd keeps encrypting).
- **Interop:** live-verify against OpenSSL `s_client`, a browser wss client, and weechat over certfp (the known-good live clients) before/after enabling `[tls] ktls=tx`.

## 8. Risks

- **Kernel-version drift on ircx.us** — mitigated by per-suite probe + userspace fallback (default off).
- **NST/KeyUpdate double-encryption** if attach ordering is wrong — mitigated by attach-only-when-drained + gating post-handshake sends.
- **RX offload complexity** (control-record demux, KeyUpdate, export reconciliation) — deferred to Phase 3 behind its own flag; not on the critical path.
- **Silent seq desync on a buggy kernel** for path (B) — mitigated by preferring path (A) (kernel owns seq) and the liveness self-test.
- **Loss of `SEND_ZC`** on offloaded conns — acceptable; kTLS still removes the userspace AEAD + one copy and enables splice/sendfile.

## Recommendation
Do TX-only kTLS, rolled out to the highest-throughput client-facing TLS surfaces first, and preserve USR2 via execve-persistence rather than kernel-key extraction. Concretely: (1) Phase 0 — add `src/daemon/ktls.zig` (constants + crypto_info encoders + suite mapping, all with Zig tests), a boot-time per-suite capability probe, a `[tls] ktls=off|tx|txrx` config default `off`, and a getsockopt-seq liveness self-test; no behavior change. (2) Phase 1 — enable `TLS_TX` at the `connected` transition in `driveTls` after the NST/handshake flight is drained, add a `conn.tls_tx_offloaded` branch to `appendSecuredToConn` that sends plaintext, and gate off server-initiated KeyUpdate/NST for offloaded conns; target the wss media/upload data-plane first (bulk, where AEAD+copy and splice/sendfile dominate). (3) For USR2, carry only a 1-bit offloaded marker + retained `server_app_secret` in `tls_snapshot` and have `adoptTlsState` leave the inherited fd's kernel TX state untouched — the kernel keeps encrypting, so TX seq is never extracted or reinjected. Keep RX in userspace (unchanged `pending_recv`, KeyUpdate, exporter). (4) Phase 2 broadens TX to interactive clients after live proof. (5) RX offload (Phase 3) only if profiling justifies it, behind its own flag. Correct the task premise up front: S2S mesh links are Mooring/Undertow, not TLS, so they are out of scope. Answer to the crux: kTLS'd conns do NOT need re-handshake on upgrade — kernel socket state survives execve on the carried fd; getsockopt(TLS_TX) extraction is a viable fallback (live TX seq is readable) but RX extraction is fragile, which is exactly why TX-only is the first step. Do not edit code in this spike.

Effort: M–L. Phase 0 (ktls.zig + probe + config + self-test): ~2 days. Phase 1 (TX attach ordering, send-seam branch, wss data-plane rollout, USR2 marker + adopt branch, tests, live interop verify on both nodes): ~3–4 days. Phase 2 (broaden + soak): ~1 day. Phase 3 RX offload is a separate L effort (~4–6 days, higher risk) and is explicitly optional/deferred. Recommended committed scope now: Phases 0–1 ≈ 5–6 days.