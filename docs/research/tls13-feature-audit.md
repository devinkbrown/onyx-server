# Armor TLS 1.3 feature audit — RFC 8446 (+ 8446bis where stable)

Date: 2026-07-11. Scope: the TLS **1.3** core only — `src/crypto/tls_server.zig`,
`src/crypto/tls_client.zig`, `src/crypto/tls_record.zig`, `src/crypto/hkdf_tls13.zig`,
`src/crypto/tls_resumption.zig` and the 1.3-specific extension modules under `src/proto/`.
The hardened TLS 1.2 arm (`tls12*.zig`) is owned by a parallel effort and is only referenced
where RFC 8446 places a 1.3 obligation on it (downgrade sentinel).

Legend: **IMPLEMENTED** / **PARTIAL** / **MISSING**, each with `file:line` evidence and the
governing spec section. Line numbers are as of this audit's tree (which includes the
hardening fixes landed with it — marked **[fixed here]**).

## 1. Handshake core

| Feature | Status | Evidence | Spec |
|---|---|---|---|
| Full 1-RTT handshake (CH→SH→EE→Cert→CV→Fin, both roles) | IMPLEMENTED | server `tls_server.zig:1238` (`buildServerFlight`), state machine `:861–:996`; client `tls_client.zig:1830` (`tryConsumeServerFlight`) → `tryProcessPlainHandshake` | RFC 8446 §2, §4 |
| HelloRetryRequest (server emits, stateful) | IMPLEMENTED | `tls_server.zig:1600–1616` (decide before PSK/0-RTT), `buildHelloRetryRequest` `:1284–1305` (message_hash synthetic transcript) | §4.1.4 |
| HRR (client: retry, cookie echo, second-HRR fatal) | IMPLEMENTED | `tls_client.zig:1752` (`handleHelloRetryRequest`), second HRR fatal `:1724`, no-change HRR fatal `:1799`, cookie echo `:1620–:1626`, same random+session-id in CH2 `:401` | §4.1.4 |
| HRR transcript replacement (message_hash 0xFE‖u24‖Hash(CH1)) | IMPLEMENTED | server `tls_server.zig:1288–1295`; client `tls_client.zig:1817–1824` | §4.4.1 |
| CH1↔CH2 pinning: SNI unchanged | IMPLEMENTED | `tls_server.zig:1580–1585` (digest compare; cert pinned at CH1) | §4.1.2 |
| CH1↔CH2 pinning: suite unchanged | IMPLEMENTED | `tls_server.zig:1619–1621` (`hrr_suite` stamp) | §4.1.4 |
| CH1↔CH2 pinning: early_data MUST be removed in CH2 | IMPLEMENTED | `tls_server.zig:1615` (reject if kept) | §4.1.2 |
| CH2 key_share bound to the HRR group | IMPLEMENTED | `tls_server.zig:1622–1637` (other-group shares discarded; none left ⇒ fatal) | §4.1.2 |
| Client: SH-after-HRR MUST keep the HRR suite | IMPLEMENTED **[fixed here]** | `tls_client.zig` `hrr_suite` field + check in `parseServerHello` (was MISSING — a 0x1301↔0x1303 swap shares SHA-256 and would ride to Finished) | §4.1.4 |
| Client: SH key_share group MUST be one the CH offered / the retry group | IMPLEMENTED **[fixed here]** | `tls_client.zig` `parseServerHello` group check against `retry_key_share_group` / `offeredShareFor` (was MISSING) | §4.2.8 |
| Cookie (server-side stateless HRR) | MISSING (deliberate) | server HRR is stateful and sends no cookie; client echoes one if received (`tls_client.zig:1803–1807`, ≤512 B — RFC allows up to 2^16−1, an interop bound worth noting) | §4.2.2 |
| Middlebox-compat mode (CCS tolerate/emit) | PARTIAL | server emits CCS after SH (`tls_server.zig:1272`) and tolerates inbound CCS at every plaintext stage (`:862–:866`, `:903–:907`, `:938–:941`); client tolerates CCS (`tls_client.zig:1714`, `:1843`) but does **not** emit one before its Finished — legal (compat mode is optional) but a strict-middlebox interop note | §D.4 |
| Downgrade sentinel (DOWNGRD in server random) | IMPLEMENTED (in the 1.2 arm, out of this lane) | 1.2 server stamps it (`tls12_server.zig` `tls13_downgrade_sentinel`), 1.2 client enforces (`tls12_client.zig:35–:44`, `:629`); the 1.3 client only ever accepts `supported_versions == 0x0304` (`tls_client.zig:1933–1945`) so a 1.3→1.2 downgrade of *this* client fails closed outright | §4.1.3 |
| Post-handshake message discipline (fail-closed) | IMPLEMENTED **[fixed here]** | both `handlePostHandshake`s now reject zero-length fragments, unknown post-handshake types, and trailing partial bytes (were silently ignored/dropped); zero-length handshake records fatal in both flight drains | §5.1, §6.2 |

## 2. Key schedule & record protection

| Feature | Status | Evidence | Spec |
|---|---|---|---|
| HKDF-Expand-Label / Derive-Secret ladder, RFC 8448 KATs | IMPLEMENTED | `hkdf_tls13.zig:18–255`, KATs `:272–:443`; secrets flow through `Secret(T)` with `wipe()` on every path (`errdefer` chain `:219–:235`) | §7.1 |
| Per-record nonce = static IV XOR seq_be64 | IMPLEMENTED | `tls_record.zig:177–185` (`deriveNonce`), KAT `:379` | §5.3 |
| AAD = TLSCiphertext header; inner content-type; padding strip constant-time | IMPLEMENTED | `tls_record.zig:188–194`, `:234–261` (full-length CT scan, `ctNonZero`/`ctSelect*`) | §5.2 |
| Seq monotonicity, per-direction, reset to 0 on rekey | IMPLEMENTED | distinct `hs/app/early read/write` seqs `tls_server.zig:519–523`; reset after KeyUpdate server `:1203`/`:1225`, client `tls_client.zig:1073`/`:1130` | §5.3 |
| Seq exhaustion guard (2^64−1 MUST rekey/close) | PARTIAL (theoretical) | `seq += 1` everywhere (e.g. `tls_server.zig:1071`); u64 overflow is unreachable physically but would be illegal-behavior UB in ReleaseFast rather than a typed `NonceCounterExhausted`. LOW — document-only | §5.5 |
| Record length caps (2^14 plaintext / +256 ciphertext) | IMPLEMENTED | `tls_record.zig:15–16`, `parseCiphertext` `:197–213` (length, type, version all exact) | §5.1–5.2 |
| KeyUpdate: receive (both roles), update_requested reply, send | IMPLEMENTED | server `tls_server.zig:1182–1218` (+`initiateKeyUpdate` `:1118`), client `tls_client.zig:1060–1141`; reply sealed under OLD keys then rotate — correct ordering | §4.6.3 |
| KeyUpdate flood bound | MISSING | a peer may force unbounded HKDF work via back-to-back KeyUpdates; RFC permits rate-limiting. LOW (per-conn cost is one HKDF chain) | §4.6.3 |
| record_size_limit (RFC 8449) both directions + outbound fragmentation | IMPLEMENTED | negotiate `tls_server.zig:1534–1541` / `tls_client.zig:2020–2027`; fragment `tls_server.zig:1077–1088`, limits math + bounds `tls_record.zig:126–149` | RFC 8449 |
| Alert handling | PARTIAL | client parses alerts (`tls_client.zig:1001–1004`, `:1029`); server emits correct plaintext/encrypted fatal alerts (`takeAlert` `tls_server.zig:706`, tested `:5278+`) but `Server.decrypt` maps an inbound alert (incl. close_notify) to `error.BadRecord` rather than a typed close — fail-closed, but no graceful close_notify. MEDIUM-low (daemon treats either as teardown) | §6 |
| Exporters (RFC 8446 §7.5) + RFC 9266 channel binding | IMPLEMENTED | `hkdf_tls13.zig:175–193` with KATs; surfaced `tls_server.zig:721–735`, `tls_client.zig:775–789` | §7.5, RFC 9266 |

## 3. PSK / resumption / 0-RTT

| Feature | Status | Evidence | Spec |
|---|---|---|---|
| NewSessionTicket issue (server) / capture (client) | IMPLEMENTED | `tls_server.zig:987`, `:2388–2400`; client `tls_client.zig:1084–1106` (PSK = HKDF(rms, "resumption", nonce)) | §4.6.1 |
| Sealed self-contained tickets + key rotation (current/previous) | IMPLEMENTED | `tls_resumption.zig:123–248` (`openTicketWithRotation`), AEAD-sealed, version-tagged | §4.6.1 (format is local) |
| psk_ke_modes: psk_dhe_ke only; PSK must be last extension | IMPLEMENTED | client `tls_client.zig:1637`; server `tls_server.zig:1550`, PSK-last `:1568–1570` | §4.2.9, §4.2.11 |
| Binder verification over truncated CH, constant-time | IMPLEMENTED | `tls_server.zig:1741–1785` (`timing_safe.eql`); tamper-fallback test `:4240` | §4.2.11.2 |
| Ticket lifetime enforcement | IMPLEMENTED | `tls_server.zig:1733–1739` (expired/future ⇒ full handshake); test `:4455` | §4.6.1 |
| 0-RTT accept: early keys, byte cap, EndOfEarlyData required | IMPLEMENTED | `tls_server.zig:2435–2468` (cap vs `max_early_data_size`, EOED exact-match), gated on non-zero sealed limit `:1661` (test `:4620`) | §4.2.10 |
| 0-RTT reject path: trial-skip of early records | IMPLEMENTED | `tls_server.zig:893–894` + `:944–947` (undecryptable records skipped only when early data was offered-and-rejected) | §4.2.10 |
| 0-RTT anti-replay: single-use binder guard | IMPLEMENTED | `tls_resumption.zig:71–108` (bounded ring, shared, locked), wired `tls_server.zig:1656–1659`; replay test `:4528` | §8.1 |
| 0-RTT anti-replay: obfuscated_ticket_age freshness window | IMPLEMENTED | `tls_server.zig` (`ticketAgeWithinWindow`, `accepted_age_within_window`): reported age must fit `early_data_age_skew_ms`. As of 2026-09-30, missing clock, sealed issue time, age-add, or lifetime refuses 0-RTT before consuming a replay slot. Tests cover valid acceptance, skew boundaries, missing evidence, encrypted 1-RTT fallback, and a same-flight retry after restoring the clock. The binder ring covers one process; freshness alone does not stop replay across nodes. | §8.2–8.3 |
| Rejected-early-data skip bound | PARTIAL | `skipRejectedEarlyRecords` `tls_server.zig:2470–2483` skips without a byte cap (memory stays bounded per feed; CPU/window unbounded). LOW-MEDIUM; daemon conn limits mitigate | §4.2.10 |
| Client 0-RTT send + accept detection | IMPLEMENTED | `setEarlyData` `tls_client.zig:824`, EE `early_data` ack validated (only if offered AND PSK accepted) `:2016–2019`, `earlyDataAccepted` `:837` | §4.2.10 |

## 4. Extensions & negotiation surface

| Feature | Status | Evidence | Spec |
|---|---|---|---|
| supported_versions (only 0x0304 accepted) | IMPLEMENTED | client offers/enforces `tls_client.zig:1246`, `:1933–1945`; server requires `tls_server.zig:1576` | §4.2.1 |
| supported_groups / key_share: x25519, secp256r1, X25519MLKEM768 | IMPLEMENTED | server select `tls_server.zig:1491–1501`, `:1671–1721`; client build `tls_client.zig:1510–1530` | §4.2.7–4.2.8 |
| X25519MLKEM768 (0x11EC): ML-KEM-768 first, raw concat to key schedule | IMPLEMENTED | server encaps `tls_server.zig:1691–1720`; client decaps `tls_client.zig:1980–1998`; loopback test `tls_server.zig:3606`; compliance brief `docs/research/pq-kem-compliance.md` | draft-ietf-tls-ecdhe-mlkem |
| signature_algorithms (Ed25519, ECDSA-P256, RSA-PSS) | IMPLEMENTED | client `tls_client.zig:1496–1501`; server CertVerify verify paths `tls_server.zig:1034–1055` | §4.2.3 |
| signature_algorithms_cert | IMPLEMENTED **[fixed here]** | Extension type 50 modeled (`tls_extension.zig`). Client emits it OPT-IN (`Options.cert_signature_schemes`; byte-identical wire when null; re-emitted identically across HRR and in the ECH inner). Server parses + retains it (`client_sig_algs_cert`) and, gated behind `enforce_cert_signature_algorithms` (OFF by default ⇒ byte-identical when off), enforces that every non-self-signed chain cert's signatureAlgorithm is named by the effective list — the client's `signature_algorithms_cert` if present, else `signature_algorithms` (the §4.2.3 fallback) — fail-closed on any cert whose OID we cannot classify (`certChainConformsToSchemes`, `cert_sig_scheme.schemeForCertOid`). Covered by in-repo tests; the current bounded external BoGo baseline does not claim exhaustive coverage (§8). | §4.2.3 |
| SNI (RFC 6066) + per-SNI cert selection, pinned at CH1 | IMPLEMENTED | `tls_server.zig:1579–1585` (`selectSniCert`, digest-pinned across HRR; test `:5176`) | RFC 6066; §4.1.2 |
| ALPN | IMPLEMENTED | server select `tls_server.zig:1503`, `maybeSelectAlpn` `:1787`; client validates the echo is one it offered, single entry `tls_client.zig:2002–2015` | RFC 7301 |
| OCSP stapling (status_request, staple in leaf CertificateEntry) | IMPLEMENTED | server `tls_server.zig:1504`, `:3664` test; client parses + status decision `tls_client.zig:2110`, `:3953` test | RFC 6066/8446 §4.4.2.1 |
| SCT / Certificate Transparency (TLS-delivered + embedded) | IMPLEMENTED | client `ext_signed_certificate_timestamp` `tls_client.zig:2608`, capture `:2112–2115`; CT quorum in `sct.zig` | RFC 6962 |
| Certificate compression (RFC 8879, zlib, bomb-guarded) | IMPLEMENTED | client `tls_client.zig:2061–2070` (+unsolicited fatal `:1874`); server `tls_server.zig:1505–1508`; loopback `:5403` | RFC 8879 |
| Raw public keys (RFC 7250), server + client cert types | IMPLEMENTED | negotiation `tls_server.zig:1509–1533`; client EE validation (unsolicited fatal) `tls_client.zig:2032–2042`; byte-identical-off test `:5588` | RFC 7250 |
| Delegated credentials (RFC 9345) | IMPLEMENTED | client verify chain (`:4610+` tests: window, scheme pinning, tamper, no-clock reject); server presents-when-accepted `tls_server.zig:1552–1563`; byte-identical-off `:3946` | RFC 9345 |
| ECH (draft-ietf-tls-esni) | PARTIAL (deliberate, documented) | client seal + acceptance confirmation `tls_client.zig:1187+`, server open + inner transcript switch `tls_server.zig:872–882`; **retry_configs now IMPLEMENTED [fixed here]** — server emits its published ECHConfigList in EE on ECH-not-accepted (`Config.ech_retry_config_list`, `writeEncryptedExtensions`, byte-identical when unset), client captures it only on offer+reject (`ech_retry_configs` / `echRetryConfigs()`, authenticated by the public_name cert), tests: rejection-delivers-retry + accepted-exposes-none; **ECH×HRR is now FAIL-CLOSED ON BOTH SIDES [fixed here]** — client refuses on an HRR while ECH was offered (`tls_client.zig` `error.HelloRetryRequestUnsupported`), AND the server now aborts with `error.EchHrrUnsupported` (`tls_server.zig` `buildServerFlight` `.retry` branch) the moment an *accepted* ECH inner (`ech_accepted`) would require a HelloRetryRequest — previously it silently stood ECH down (used the CH2 outer, signalled ECH-not-accepted), a transcript/acceptance inconsistency + silent downgrade the peer only caught at Finished. Tests: `ECH×HRR: server FAILS CLOSED …`, `ECH×HRR: an ECH-active client FAILS CLOSED …`, and a scoping test proving a normal (non-accepted) HRR is unaffected. The re-seal ITSELF (a compliant ECH×HRR CH2) remains DEFERRED. NOT shipped because it cannot be externally validated here (see §8: no BoGo ECH harness — shim lacks ECH flag wiring + HPKE is ChaCha20-only vs BoGo's AES-128-GCM). Shipping a hand-rolled CH2 transcript without that oracle is worse than the refusal; no `ech_outer_extensions` compression | draft-ietf-tls-esni (RFC 9849) |
| Certificate / CertificateVerify (server auth, all three key types) | IMPLEMENTED | client verify `tls_client.zig:2072+` (chain cap 16 `:2104`, exact context strings), CRL/OCSP/CT hooks | §4.4.2–4.4.3 |
| certificate_request / mTLS (client Certificate, CV, possession proof) | IMPLEMENTED | server `writeCertificateRequest` `tls_server.zig:1251`, client-cert verify `:1023–1063` (failed proof clears the captured fingerprint); client `validateCertificateRequest` `tls_client.zig:4265` test | §4.3.2, §4.4.2.4 |
| Post-handshake client auth (post_handshake_auth ext) | MISSING (deliberate) | never advertised; a post-handshake CertificateRequest is now fatal on the client **[fixed here]** — correct per §4.6.2 when not advertised | §4.6.2 |
| max_fragment_length | MISSING | superseded by record_size_limit (implemented); RFC 8449 deprecates it. No action | RFC 6066 §4 |
| heartbeat | MISSING (deliberate — good) | — | RFC 6520 |
| kTLS param export incl. RX rekey continuity | IMPLEMENTED | `ktlsTxParams`/`ktlsRxParams`/`advanceRxKeyForKtls` `tls_server.zig:780–840` (seq 0 after rekey per §5.3) | — |
| Helix resume (exportResume/resumeConnected carries secrets+seqs) | IMPLEMENTED | `tls_server.zig:1130–1176`; test `:4146` | — |

## 5. Gap ranking (security value, high→low)

1. ~~**0-RTT obfuscated_ticket_age freshness window (§8.2–8.3)**~~ — **DONE (fixed here).**
   Sealed ticket bumped to v3 carrying `ticket_age_add` (v1/v2 legacy decode arms +
   cross-version test); `early_data` gated on |client_age − server_age| ≤
   `early_data_age_skew_ms` (default 10 s) via `ticketAgeWithinWindow`. As of
   2026-09-30, missing clock, issue time, age-add, or sealed lifetime refuses
   early data without consuming a replay slot; eligible 1-RTT remains available.
   The binder ring covers one process. Freshness alone does not stop replay
   across nodes.
2. ~~Client HRR→SH suite pinning (§4.1.4 MUST)~~ — **fixed here**.
3. ~~Client SH key_share group ∈ offered shares (§4.2.8 MUST)~~ — **fixed here**.
4. ~~Fail-open post-handshake message handling (both roles)~~ — **fixed here** (zero-length
   fragments, unknown types, trailing partial bytes all fatal; NST-from-client fatal).
5. `Server.decrypt` maps inbound alerts to `error.BadRecord` — no typed close_notify.
   Fail-closed but graceless; MEDIUM-low. Follow-up: a typed `TlsAlert`-style surface like
   the client's.
6. Rejected-early-data skip and KeyUpdate processing are unbounded (CPU, not memory).
   LOW-MEDIUM; candidate caps: skip ≤ `max_early_data_size`+slack bytes, KeyUpdates ≤ N/min.
7. ECH: retry_configs **DONE (fixed here)** — server advertises its ECHConfigList in EE on
   ECH-not-accepted, client captures it (public_name-authenticated). ECH×HRR is now
   **fail-closed on BOTH sides (fixed here)** — the client already refused an HRR under ECH;
   the server now also aborts (`EchHrrUnsupported`) when an *accepted* inner would require an
   HRR, instead of silently standing ECH down (the prior `signal_ech = ech_accepted and
   !hrr_sent` behavior emitted a downgrade the peer caught only at Finished). The compliant
   ECH×HRR *re-seal* and `ech_outer_extensions` compression remain follow-ups (gated on the
   BoGo ECH oracle); current behavior is fail-closed / fail-safe respectively.
8. Cookie length interop bound (client echoes ≤512 B; spec allows 2^16−1) and no
   server-side stateless-HRR cookie. LOW (stateful HRR is compliant).
9. `signature_algorithms_cert` absent — evaluated and DEFERRED here (always-on wire change +
   interop-risking enforcement for LOW value; sig_algs fall-back is spec-compliant). LOW.
10. Seq `+= 1` lacks a typed exhaustion error (2^64 unreachable). Document-only.
11. Client does not emit a middlebox-compat CCS. Interop-only note, not security.

## 6. Hardening landed with this audit (tests first, all green)

- **Client `parseServerHello`**: enforce HRR-committed suite (§4.1.4 MUST) and that the SH
  key_share names an offered group / exactly the HRR retry group (§4.2.8 MUST). New
  `hrr_suite` field; tests `TLS 1.3 ServerHello after HRR must keep the HRR cipher suite`
  and `TLS 1.3 ServerHello key_share group must be one the ClientHello offered`.
- **Both roles, post-handshake fail-closed**: zero-length handshake fragments fatal
  (§5.1), non-KeyUpdate (server) / non-KeyUpdate-or-NST (client) handshake types fatal
  (unexpected_message), trailing partial handshake bytes fatal (no cross-record
  post-handshake reassembly exists — silent drop was silent data loss). Zero-length
  handshake records also fatal in both handshake flight drains. Tests
  `TLS 1.3 post-handshake: …` in both files, including the still-accepted well-formed
  KeyUpdate after rejects.
- **`parseHandshakeMaybe` (both files)**: the completeness pre-check now honors `offset`
  instead of always reading the first message's header (previously safe only because
  `parseHandshake` re-bounds-checks; now correct by construction).

## 7. Follow-ups landed (this pass — tests first, all green)

- **0-RTT obfuscated_ticket_age freshness window (§8.2–8.3)** — the #1 gap.
  `tls_resumption.zig`: sealed-ticket format bumped to **v3** carrying `ticket_age_add`
  (`OpenedTicket.ticket_age_add: ?u32`); v1/v2 tickets still open via legacy decode arms
  for eligible 1-RTT resumption, but as of 2026-09-30 missing sealed freshness
  evidence refuses 0-RTT. `tls_server.zig`:
  `ticketAgeWithinWindow` un-obfuscates the client's reported age with the sealed
  `ticket_age_add`, compares to the server-measured `now − issue_time`, and refuses
  `early_data` (still resuming at 1-RTT) when the delta exceeds `Config.early_data_age_skew_ms`
  (default 10 s); `accepted_age_within_window` gates 0-RTT acceptance BEFORE the binder ring
  so a stale attempt consumes no ring slot. NST now seals the SAME `ticket_age_add` it
  advertises. Tests: in-window accept, reported-far-below / far-above reject, exact-skew ±1 ms
  boundary, and no-clock rejection with encrypted 1-RTT fallback and retry.
- **ECH retry_configs (draft-ietf-tls-esni §7.1)** — server emits its published ECHConfigList
  (`Config.ech_retry_config_list`) in EncryptedExtensions only when the client actually OFFERED
  ECH (`ech_offered` latched in `maybeOpenEch` from `locateOuterEch`) and ECH was NOT accepted;
  gating on `ech_offered` avoids sending an unsolicited extension to a plain client (which a
  compliant peer aborts on, RFC 8446 §4.2). Byte-identical when the retry list is unset; the
  EE-sized buffer grows with the list. Client captures it (`ech_retry_configs` /
  `echRetryConfigs()`) only when it offered ECH and the server rejected — i.e. authenticated by
  the public_name cert — and never applies it this connection. Tests:
  `ECH rejection delivers retry_configs the client captures`, `an accepted ECH handshake
  exposes no retry_configs`, and `a non-ECH client … is not treated as an ECH offer`.

Deferred (documented above, NOT half-implemented): the compliant ECH×HRR re-seal (ECH+HRR is
now a clean fail-closed refusal on BOTH sides — client `HelloRetryRequestUnsupported`, server
`EchHrrUnsupported` — see §7 item 7) and `ech_outer_extensions` compression.
(`signature_algorithms_cert` is now IMPLEMENTED — see row above.)

**ECH×HRR re-seal — gating prerequisite (why it stays fail-closed).** The draft-ietf-tls-esni
(RFC 9849) HRR rules are transcript-exact and unforgiving: CH2 reuses the *same* HPKE sender
context from CH1 (second seal at HPKE sequence 1) with an EMPTY `enc`; the HRR carries the
8-byte acceptance confirmation in an `encrypted_client_hello` extension under the
`"hrr ech accept confirmation"` label; and — the load-bearing trap — BOTH HRR-case
confirmation transcripts apply the RFC 8446 §4.4.1 `message_hash` substitution
(`0xFE‖u24(Hash.len)‖Hash(ClientHelloInner1)`, the INNER CH1) before hashing, with the 8
signal bytes zeroed. A naive `Hash(CH1inner ‖ HRR)` produces a wrong-but-plausible signal
that fails only at interop. Per the crypto mandate, "round-trips with itself is necessary but
NOT sufficient" — a self-consistent client↔server loopback can be self-consistently wrong, so
this MUST be pinned against an external oracle (BoGo) before shipping. That oracle does not
exist here yet (§8): the BoGo runner cannot exercise ANY Onyx Server ECH path — base or HRR —
because (a) `tools/bogo_shim.zig` has ZERO ECH flag wiring (`-ech-config-list`,
`-ech-server-config`, `-expect-ech-accept`, `-on-retry-expect-ech-accept`, `-expect-hrr`), so
those tests are skipped as unimplemented, and (b) `src/crypto/hpke.zig` supports only
ChaCha20-Poly1305 (AEAD `0x0003`) while BoringSSL's ECH tests generate configs under
AES-128-GCM (AEAD `0x0001`). The relevant BoGo cases are `TLS-ECH-Client-HelloRetryRequest`,
`TLS-ECH-Server-ECHInner-HelloRetryRequest`, and the negative
`TLS-ECH-Client-HelloRetryRequest-MissingServerHelloConfirmation`
(`ssl/test/runner/ech_tests.go`). **Gating follow-up (a separate project, out of scope for
the ECH×HRR task): build the ECH BoGo harness first** — add AES-128-GCM (and AES-256-GCM) to
`hpke.zig`, thread suite-agility through `ech_seal`/`ech_config`, and wire the ECH shim flags —
then enable `*ECH*` in `tools/bogo/config.json` and validate base ECH. Only once BoGo can
prove base ECH should ECH×HRR be implemented and validated against the three cases above.
Note: `ech_seal.acceptConfirmation` already implements both labels (`.server_hello` /
`.hello_retry_request`) and is unit-tested for determinism + label/transcript sensitivity;
the missing piece is the caller-side transcript assembly (the `message_hash` collapse + signal
zeroing) proven against BoGo — not the confirmation primitive itself.

## 8. External-peer interop status (BoGo)

The external BoringSSL BoGo runner (`tools/bogo.sh`) drives the Onyx Server TLS shim
(`tools/bogo_shim.zig`) against BoringSSL's reference test suite. It requires Go and a
network fetch of BoringSSL pinned to full commit
`5ac7567c234514157a504ff3fbedc0f5eddbf678`. The required CI lane is intentionally
bounded and non-vacuous: **24 exact passes, 3 explicit skips, 0 failures**, with pass/skip
identity drift and all-skip results rejected. The in-repo `zig build bogo-shim-test` remains
the deterministic self-test lane.

Do **not** read that baseline as full-corpus conformance. An honest exploratory run of the
pinned corpus currently produces **55 passes, 3,635 skips, and 157 failures**; serialized
TLS 1.3 candidates can also hit the runner's 15-second handshake timeout. The full
external-interop leg therefore remains open. `tools/bogo/config.json` retains the disclosed
modern-only exclusions; the required baseline does not weaken them to manufacture green.

**Not covered by BoGo: ECH (all of it, base and ×HRR).** `config.json` disables `*ECH*` and
the ECH-carrying `*HelloRetryRequest*` cases because the shim has no ECH flag wiring and
`hpke.zig` speaks only ChaCha20-Poly1305 while BoringSSL's ECH configs use AES-128-GCM (see the
ECH×HRR prerequisite note in §7). So Onyx Server's base-ECH accept/reject path is validated ONLY by
the in-repo client↔server loopback + confirmation-primitive KATs, and ECH×HRR is not
implemented (fail-closed). Standing up the ECH BoGo harness (AES-GCM HPKE + suite-agility + shim
ECH flags) is the tracked follow-up that must land before ECH×HRR — or any expanded ECH — ships.

Gate: `zig build test-tls` green; `zig build bogo-shim-test` green; `zig fmt --check src/` clean.
