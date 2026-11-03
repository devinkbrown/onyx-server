# TLS and STS

*Configure implicit TLS listeners and Strict Transport Security (STS) for a modern-only Onyx Server deployment.*

Onyx Server is modern-only: TLS is implicit on a separate listener, and there is no STARTTLS command path (`src/main.zig`, `src/main.zig`, `src/daemon/dispatch.zig`). A TLS-first deployment enables `[tls]` and usually `[sts]`, while still providing the currently required `[listen].irc` parser key.

## Production TLS card

Short operator checklist for a **single public node** (not mesh). Full ACME field
reference lives in `docs/reference/config.md` and `etc/onyx-server.reference.toml`.

| Step | Requirement |
|---|---|
| 1. DNS | `A`/`AAAA` for the public name (e.g. `irc.example.net`) points at this host. |
| 2. Ports | `6697/tcp` (IRCS) open to clients; for in-daemon ACME HTTP-01, either expose the challenge path on `80` (nginx → `[acme].challenge_port`) or place the node where LE can reach it. |
| 3. Paths | Write durable PEM paths under e.g. `/etc/onyx-server/tls/{cert,key}.pem` owned by the service account (mode `0640` / `0600` on the key). |
| 4. Config | `[tls] enabled = true` + `cert_path`/`key_path`/`dns_name`; `[acme] enabled = true` with `directory_url`, `domain`, `contact`; `[listen] ws_plain = false`; set a real `[network].server_name`. |
| 5. Preflight | `onyx-server --check-config /etc/onyx-server/onyx-server.toml` must print `config OK` before every cold start and every config change. Both packaged kits validate startup and reload; runtime checks still exercise different paths. |
| 6. Supervise and accept | Provision the host's [OpenRC/systemd kit](service-management.md); verify actual TLS/listeners and client participation after start. Helix reload requires an accepted compatible target; cold restart requires the runbook's custody and recovery steps. |

Minimal production sketch (fill host, email, and paths):

```toml
[network]
name = "Onyx"
server_name = "irc.example.net"

[listen]
host = "::"
irc = 6667          # optional plaintext; many operators drop it behind the firewall
ws = 8080
ws_plain = false    # browsers need wss for a public client

[tls]
enabled = true
port = 6697
cert_path = "/etc/onyx-server/tls/cert.pem"
key_path = "/etc/onyx-server/tls/key.pem"
dns_name = "irc.example.net"

[sts]
enabled = true
duration = 2592000
port = 6697

[acme]
enabled = true
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
domain = "irc.example.net"
contact = "mailto:admin@example.net"
# challenge_port = 14402   # loopback HTTP-01; reverse-proxy 80 → this port
```

**Do not** ship the quickstart (`ws_plain = true`, no `[tls]`) as a public deployment.
Self-signed bootstrap (no `cert_path`/`key_path`) is for local eval only — browsers
will not trust it for a production client origin.

Also ship quickstart packaging notes: [`packaging/README.md`](../../packaging/README.md#production-tls-card).

## TLS listener

```toml
[tls]
enabled = true
port = 6697
cert_path = "/etc/onyx-server/tls/cert.pem"
key_path = "/etc/onyx-server/tls/key.pem"
dns_name = "irc.example.net"
request_client_cert = false
enable_tls12 = false
```

Set `enable_tls12 = true` to also accept hardened TLS 1.2 (ECDHE-AEAD) clients on the same listener via version dispatch. It is **off by default** to preserve the TLS 1.3-only posture. With a configured ECDSA-P256 or RSA leaf, the 1.2 leg shares that material. With an Ed25519 default leaf, it bootstraps a separate ECDSA-P256 leaf, so verify which chain the intended TLS 1.2 clients actually receive before public use.

The TLS 1.2 profile **requires the Extended Master Secret (RFC 7627) by default**. A ClientHello that does not offer the `extended_master_secret` extension is aborted with `EmsRequired` — there is no silent downgrade to the weaker randoms-based master secret, which closes the RFC 7627 §5.3 triple-handshake / synchronized-session class of attacks (`src/crypto/tls12_server.zig`, `src/crypto/tls12_server.zig`). The requirement is a fixed engine default (`require_extended_master_secret = true`), not a config knob; it can only be loosened in-code for legacy interop, and even then EMS is still negotiated and used whenever a client offers it, and a TLS 1.2 ticket is only resumed for an EMS-negotiated session (the ticket carries an `EM12` tag) (`src/crypto/tls12_server.zig`, `src/crypto/tls12_server.zig`). The client engine offers EMS on every ClientHello and, with the same default, aborts if a server fails to echo it (`src/crypto/tls12_client.zig`).

When `[tls].enabled` is true, `main.zig` loads the configured cert/key or bootstraps a self-signed Ed25519 leaf using `dns_name`, then sets `server.Config.tls_port`, the certificate chain, the signing key, and the client-cert request flag (`src/main.zig`, `src/main.zig`, `src/main.zig`, `src/main.zig`). The server binds the TLS listener only when both certificate material and a signing key are present (`src/daemon/server.zig`).

Set `request_client_cert = true` when using SASL EXTERNAL. The TLS engine requests a client certificate (`src/daemon/server.zig`, `src/daemon/server.zig`), and the SASL bridge maps the presented certificate fingerprint to an account binding (`src/daemon/sasl_bridge.zig`).

Legacy clients such as WeeChat may use that binding for mesh-wide session resume
without implementing the `SESSION RESUME` command. After SASL EXTERNAL succeeds, an
exact account-and-requested-nick match attaches to the canonical logical session for
that identity across any number of secured mesh peers. When several distinct session
tokens still match (for example after a race minted one token per node before
replicas converged), selection is deterministic rather than fail-closed: live local
attachments beat live mesh attachment leases beat detached/portable replicas; within
a tier, newer signon/issued time and higher replica revision win. The first EXTERNAL
login proactively offers signed portable state to secured peers, and a resumed
attachment inherits the shared nick, channels, member modes, and message routing
without emitting another logical JOIN or derived operator-prefix grant. A configured
client certificate alone is insufficient: the connection must complete SASL EXTERNAL
successfully.

For WeeChat, configure every server profile that can reach the node. Profile
names are local identifiers: `ircx` and `ircx.us` are distinct profiles even when
both resolve to the same host.

```text
/set irc.server.ircx.us.addresses ircx.us/6697
/set irc.server.ircx.us.tls on
/set irc.server.ircx.us.tls_cert /path/to/client-cert-and-key.pem
/set irc.server.ircx.us.tls_verify on
/set irc.server.ircx.us.sasl_mechanism external
/set irc.server.ircx.us.sasl_username kain
/set irc.server.ircx.us.nicks kain
/set irc.server.ircx.us.username kain
/set irc.server.ircx.us.autoconnect on
/set irc.server.ircx.us.autoreconnect on
/save
```

On reconnect, WeeChat should log that it sent one client certificate, then show
SASL `900`/`903`, account `kain`, and `SESSION RESUME: certificate-authenticated
session restored` (or `mesh session restored` when the authoritative session was
reopened from the peer). Do not copy the issued session token into client config;
the EXTERNAL path deliberately proves possession again on each transport.

## Kernel TLS offload (kTLS)

`[tls] ktls` controls Linux kernel TLS offload for TLS 1.3 client
connections: `off` (default), `tx` (server-to-client encryption in the
kernel), or `txrx` (also client-to-server decryption). See
[production paths](../ops/onyx-server-paths.md) for fleet settings. Offload only attaches when the running kernel advertises the TLS ULP;
otherwise TLS stays in userspace. Peer KeyUpdate rotates both epochs through
the kernel control path without a reconnect, and WHOIS `671` shows the
actually attached directions as `[kTLS: TX]`, `[kTLS: RX]`, or
`[kTLS: TX+RX]`. TLS 1.2 is never offloaded. See
`docs/reference/config.md` (`[tls] ktls`) and `src/daemon/ktls.zig`.

## Protocol capabilities

Onyx Server ships a clean-room, pure-Zig TLS 1.3 stack, Armor (`src/crypto/tls_client.zig`, `src/crypto/tls_server.zig`). The IRC-over-TLS listener defaults to TLS 1.3 and can explicitly enable the hardened TLS 1.2 leg described above. TLS 1.1/1.0, STARTTLS, renegotiation and record compression are refused.

The hardened TLS 1.2 client and server engines live in standalone modules (`src/crypto/tls12{,_client,_server}.zig`) for interop where TLS 1.3 is unavailable. It is deliberately restricted to ECDHE key exchange with AEAD suites only — ECDHE-ECDSA/RSA with AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305 over secp256r1 — with no CBC, RC4, static-RSA key exchange, compression, or renegotiation. The TLS 1.2 PRF, key schedule, GCM (RFC 5288) and ChaCha20-Poly1305 (RFC 7905) record layer, and Finished message are all implemented and loopback-tested. Server-side ServerKeyExchange signing uses the configured ECDSA-P256 or RSA material; an Ed25519 default needs the separate bootstrapped ECDSA-P256 leg described above.

| Capability | Detail |
|---|---|
| Cipher suites | `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256` — the full RFC 8446 mandatory set; the key schedule is SHA-256/SHA-384 dual-hash. |
| Key exchange | X25519 and secp256r1 (NIST P-256). The client offers shares for both; the server prefers X25519 and falls back to P-256. |
| Server certificates | Ed25519, ECDSA-P256 or RSA signing material supported by `tls_server.Config` and the typed PEM loader. Select a chain and signature scheme compatible with intended clients; successful config parsing alone is insufficient. |
| HelloRetryRequest | The client handles HRR (cookie echo, RFC 5280 group rules, synthetic `message_hash` transcript, second-HRR-fatal). |
| Post-handshake KeyUpdate | Honored in both directions: the receiving side rotates its traffic keys and replies with its own KeyUpdate when requested. |
| Mutual TLS | The TLS 1.3 server verifies Ed25519, ECDSA-P256/SHA-256 or RSA-PSS-RSAE-SHA256 client possession proofs. A verified fingerprint can back SASL EXTERNAL; presenting a certificate alone does not establish account login. |
| Delegated credentials | TLS client/server consume RFC 9345 delegated credentials when explicitly configured/offered. The out-of-band helper `onyx-server delegated-credential inspect|validate` parses ready-made DC wire bytes and can validate the leaf signature, DelegationUsage, KeyUsage, and lifetime window against a leaf certificate. Minting/rotation is still not shipped because it needs production private-key loading and safe DC key-output policy. |

**TLS 1.3 handshake hardening (server):** the server side is fail-closed across the handshake state machine (`src/crypto/tls_server.zig`):

- **HelloRetryRequest is single-shot and pinned.** When a ClientHello offers no usable `key_share` but does advertise a supported group, the server sends exactly one HRR requesting that group. The cipher suite committed in the HRR may not change in the second ClientHello, and that ClientHello's `key_share` must supply exactly the requested group (`src/crypto/tls_server.zig`, `src/crypto/tls_server.zig`).
- **0-RTT freshness window.** On a 0-RTT resumption the server un-obfuscates the client's `obfuscated_ticket_age` with the ticket's sealed `ticket_age_add` and compares it against its own measured elapsed time; if they differ by more than `early_data_age_skew_ms` (default 10 s) in either direction, `early_data` is refused and the handshake resumes at 1-RTT. This is the multi-node age-window replay defense a single-process binder ring cannot provide, and it runs only for v3 tickets when a clock is configured (`src/crypto/tls_server.zig`).
- **ECH `retry_configs`.** A server with ECH keys emits `retry_configs` in EncryptedExtensions only in response to an ECH handshake, so a client offering a stale ECH config can recover without leaking a signal on non-ECH handshakes (`src/crypto/tls_server.zig`).

**Certificate validation (client):** chain-to-trust-anchor signature checks (RSA-PSS/PKCS#1, ECDSA P-256/P-384, Ed25519), SAN dNSName matching, validity-window enforcement when a wall clock is supplied (the live HTTPS and ACME paths pass one), ExtendedKeyUsage `serverAuth` on the leaf, `keyCertSign` plus basicConstraints on path CAs, and X.509 Name Constraints (permitted/excluded dNSName subtrees).

**Revocation and transparency:** clean-room parsers exist for OCSP responses
(`crypto/ocsp.zig`, RFC 6960), X.509 CRLs (`crypto/crl.zig`, RFC 5280), and
Certificate Transparency SCTs (`crypto/sct.zig`, RFC 6962). The `armor ocsp`
and `armor crl` commands now perform fail-closed offline signature/status and
freshness checks when given `-verify -CAfile`; they never fetch HTTP data. The daemon
can fetch/cache a configured server OCSP staple for requesting clients. That is
separate from a general client-certificate revocation policy: a parsed or
CLI-verified response does not prove that arbitrary client handshakes are
revoked. Inspect the actual configured worker and handshake policy before
claiming live revocation enforcement.

## Delegated credential helper

The helper is an offline inspection/validation path. It never starts the daemon,
binds a listener, loads the server's private key, or mints new credentials.

```sh
onyx-server delegated-credential inspect --dc dc.wire
onyx-server delegated-credential validate --dc dc.wire --cert fullchain.pem
onyx-server delegated-credential validate --dc dc.wire --cert fullchain.pem --time 1704067200
```

`--dc` is the raw `DelegatedCredential` extension payload. `inspect` validates
the wire framing and prints `valid_time`, `dc_cert_verify_algorithm`, outer
signature `algorithm`, SPKI length, and signature length. Supplying `--cert`, or
using `validate`, additionally checks the first certificate in the PEM/DER chain:
it must carry RFC 9345 DelegationUsage and digitalSignature KeyUsage, the DC
expiry (`leaf.notBefore + valid_time`) must be live, within the seven-day
remaining-lifetime cap, and before the leaf `notAfter`, and the DC signature must
verify under the leaf SPKI. The supported leaf-signature schemes are Ed25519,
ECDSA P-256/SHA-256, and RSA-PSS-RSAE-SHA256.

## `armor` — the crypto CLI

`zig build` produces a second binary alongside the daemon: `zig-out/bin/armor`, a standalone openssl-parity crypto toolkit backed by the same pure-Zig substrate the daemon uses (`build.zig`, `src/cli/armor_main.zig`). It is convenient for generating and inspecting the certificate material the `[tls]` block consumes without pulling in OpenSSL.

```sh
armor genpkey -algorithm ec -out key.pem            # ECDSA P-256 private key (file mode 0600)
armor req -key key.pem -cn irc.example.net -out csr.pem   # PKCS#10 CSR from the key
armor x509 -in cert.pem -text                       # decode/print a certificate
armor x509 -in cert.pem -fingerprint                # SHA-256 fingerprint + SPKI pin
armor verify -CAfile ca.pem cert.pem                # verify a chain against a CA bundle
armor ciphers                                       # list supported suites, groups, sig schemes
armor dgst -sha256 file                             # digest (HMAC key is read from a file, never argv)
armor asn1parse -in cert.der                        # dump a DER structure
armor ocsp -in response.der -inform DER -text       # inspect a stapled OCSP response
armor ocsp -in response.der -inform DER -verify -CAfile ca.pem
armor crl -in revoked.crl -inform DER -verify -CAfile ca.pem
```

The implemented operation set is `x509`, `genpkey`, `pkey`, `req`, `dgst`,
`verify`, `rand`, `ciphers`, `asn1parse`, `ocsp`, and `crl`; OCSP/CRL are offline
inspection/verification tools. `s_client` accepts options and has in-memory
handshake tests, but its CLI live transport returns `NotImplemented` (exit `3`)
without opening a socket. `s_server` and `enc` are also explicit stubs. Do not
use `s_client -connect` as evidence of listener reachability or verification.
Run `armor <cmd> --help` for
per-command options. Exit codes are scriptable: `0` ok, `1` operation failed,
`2` usage error, `3` not implemented (`src/cli/armor_main.zig`). Focused
coverage runs under `zig build test-cli`.

## STS

```toml
[sts]
enabled = true
duration = 2592000
port = 6697
preload = false
```

STS is advertised only when `[sts].enabled` is true and a TLS listener is live (`src/main.zig`, `src/main.zig`, `src/main.zig`). The advertised value is built from `duration`, `port`, and `preload` (`src/main.zig`, `src/main.zig`). If STS is enabled without a live TLS listener, the daemon logs that STS is not advertised (`src/main.zig`).

The capability table intentionally omits `sts` until a runtime policy exists, which prevents clients from being told to upgrade to a listener that is not available (`src/daemon/dispatch.zig`).
