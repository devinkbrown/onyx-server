# Testing guide

Onyx Server's test suite is large, so the build graph exposes several lanes. Use the
smallest lane that proves the change, then run a broader gate before pushing.

The lane names below are synchronized with `zig build --help` on 2026-11-03.

## Fast lanes

| Command | Use it for |
|---|---|
| `zig build check` | Fast semantic/type check without emitting a daemon binary. |
| `zig build test-mod -Dtest-filter="<text>" --summary all` | One focused library/module test filter. |
| `zig build test-exe -Dtest-filter="<text>" --summary all` | One focused executable-root test filter. |
| `zig build test-tls --summary all` | Armor TLS, mTLS, ECH, RPK, delegated credential, and record-size regressions. |
| `zig build test-server --summary all` | Threaded server, auth, CertFP, and daemon integration regressions. |
| `zig build test-exploit --summary all` | Adversarial exploit/attack corpus; `test-attack` is an alias. |
| `zig build test-config --summary all` | TOML parser, boot projection, and reference-config regressions. |
| `zig build test-ircx --summary all` | IRCX discovery, PROP, ACCESS/SACCESS, DATA, LISTX, and MODEX paths. |
| `zig build test-event-spine --summary all` | Event spine, IRCX EVENT, observe notes, policy events, and playback paths. |
| `zig build test-mesh --summary all` | Undertow mesh, S2S, repair frames, secured links, CONNECT/SQUIT, and mesh projection paths. |
| `zig build test-media --summary all` | Media, DTLS-SRTP, SFU, native media, WebTransport, RTP, and RTCP paths. |
| `zig build test-services --summary all` | Services, account auth, SASL, TOTP, WebAuthn, sessions, MEMO, and successor paths. |
| `zig build test-session --summary all` | Reusable-session, migration, replica, World restore, and Helix session paths. |
| `zig build test-helix --summary all` | Helix upgrade, migration, resume, capsule, and handoff paths. |
| `zig build test-dst --summary all` | Seed-replayable DST, simulator, and multi-reactor timer-guard paths. |
| `zig build test-cli --summary all` | The `armor` toolkit, including x509/ocsp/crl/s_client and key utilities. |
| `zig build test-smoke --summary all` | Inner-loop roadmap gate: `check` plus TLS/server/config focused suites. |
| `zig build test-roadmap --summary all` | Server-roadmap gate: `check` plus server/config/IRCX/event/mesh/services/TLS focused suites. |
| `zig build test-smoke -Doptimize=safe --summary all` | Optimized smoke gate for safety-checked release codegen paths. |

Every focused lane has a `-verbose` twin, for example
`zig build test-tls-verbose --summary all`. Use verbose lanes in CI, tmux, or
any long run where silence looks like a hang; they print each test name before it
executes, include per-test duration, and finish with the slowest tests.

For the smallest first compile, use the existing build filters:

```sh
zig build test-mod -Dtest-filter="mTLS:" --summary all
zig build test-media-record-leaf -Doptimize=safe --summary all
zig build test-message-relay-v2-leaf -Doptimize=safe --summary all
```

When iterating across several tests, compile once and select at runtime:

```sh
zig build test-cached -Doptimize=safe --summary all -- --test-filter="reusable session"
zig build test-cached -Doptimize=safe --summary all -- --test-filter="ACCESS" --test-filter="SACCESS"
zig build test-exe-cached -- --list-tests
```

Test modules, executable-root tests, CLI tests, and focused test leaves use the
static `+test` build stamp. The outer gate receipt binds the real source context
and command; suite evidence retains the emitted binary hashes. Documentation-only
commits and dirty/clean status changes therefore reuse the same test artifacts;
production modules and release binaries retain their real Git revision/version.

The initial cached build compiles every test in that root. Later selections reuse
that artifact when source, target, mode, and compiler are unchanged. Repeat runtime
filters form a union; each matching case runs once. Empty filters and selections
matching no tests fail. Lists print names without running tests. Summaries distinguish
discovered, matched, excluded, executed, passed, skipped, failed, leaked, and log errors.
Runtime filters select full names; anonymous import anchors do not bypass selection.
Keep `-Dtest-filter` for compile filtering on the original targets; it does not
limit `test-cached`, `test-exe-cached`, or the full parallel gate. Windows cached
roots fail before compilation; use the existing `test-mod[-verbose]` and
`test-exe[-verbose]` targets, which retain Windows compile shards and stack setup.

### Full suite runtime parallelism

```sh
zig build test -Doptimize=safe --summary all
zig build test-full-parallel -Doptimize=safe --summary all -- --logs=.zig-cache/full-safe-unique --workers=4
zig build test-serial -Doptimize=safe --summary all
```

Unfiltered `zig build test`, `test-verbose`, `all-checks`, and
`all-checks-verbose` use this bounded parallel runner on supported native POSIX
hosts. The release aggregates also run configuration compilation, WASM, bounded
fuzz replay, and BoGo self-tests; they share the same complete three-root test
dependency instead of launching an additional serial suite.
`test-full-parallel` invokes the runner explicitly. Compile-filtered
`zig build test -Dtest-filter=<text>`, Windows, and cross targets retain the reference
graph. `test-serial` always selects that reference graph, running cases serially
within each root. Both full graphs retain every module, executable, and CLI test.

The parallel gate compiles one complete artifact for each of the module,
executable, and CLI roots, then runs each artifact in at most four processes. On
the first run, stable hashes of complete test names assign cases to shards.
After a mechanically complete successful run of all three roots, the harness stores
an advisory timing profile keyed by mode, target, and root identity under
`.zig-cache/full-suite-profiles/`. Later runs assign the longest known cases first
across four workers, with deterministic ties and a fallback cost for new names.
Malformed or mismatched hints fall back to hash shards. A hint changes scheduling;
it cannot omit tests, relax assertions, or grant release acceptance. Before execution,
the harness proves the shard inventories are disjoint and cover the complete artifact inventory
exactly. Duration plans use exact full-name manifests, so prefix collisions cannot
select a second case. Duplicate, unknown, empty, or malformed selections fail before
execution. It checks actual terminal counts, propagates every failed process/test/leak/
log error, and retains inventories, binary hashes, per-shard logs, and aggregate counts
in the new log directory. Without `--logs`, it creates and prints a unique directory
under `.zig-cache/full-suite-runs/`; explicit paths must still be new. The final suite
summary includes all three roots and is parsed by the source-bound gate ledger without adding overlapping counts.
Reusing an existing log directory fails to protect evidence. Each shard has a
3600-second timeout (`--timeout=<seconds>`); timeout or interruption terminates
and reaps its own process group and records terminal failure. Progress every
30 seconds shows the latest test line. `--seed=<u32>` defaults to zero and is
recorded with exact shard arguments and log hashes in the JSON evidence.
All original tests and skips remain; this target accepts no test filter.

To reuse a retained successful suite from another context, first convert its
`suite.json` into a scheduling hint. Conversion verifies all three roots, terminal
counts, zero failures/leaks/log errors, and the retained raw log hashes. Supply the
mode and target from that suite's verified gate command/metadata:

```sh
python3 -B tools/parallel_tests.py --import-timings-suite=<retained-suite.json> --mode=debug --target=<recorded-target> --profile-output=<new-profile.json>
zig build test -- --timings-profile=<new-profile.json>
```

Ordinary later `zig build test` runs reuse local complete profiles automatically.
Failed, interrupted, partial, or hash-mismatched evidence cannot produce a hint.

On 2026-11-03, the complete Debug `all-checks` gate fell from 1,327.794 seconds
to 944.273 seconds (22.1 to 15.7 minutes, 28.9% lower elapsed time) after the
combined test changes. Independent review verified every previous test name plus
two new TLS controls: 11,236 passed, 313 skipped, zero failures/leaks/log errors.
This is a shared-host comparison, not an isolated scheduler benchmark. Cold
ReleaseSafe LLVM compilation remains expensive; cached runtime selection and
stable test metadata avoid repeating it for each filter or documentation commit.
See the [release and test-speed audit](../audit/release-and-test-speed-2026-11-03.md).


Run from the repository root: tests need `src/`, `etc/`, and `tools/bogo/` fixtures.
Linux resource inspection found ephemeral bound listener ports and process-local
signals/limits; heavyweight mesh tests already hold their cross-process kernel lock.
Keep those locks intact. The four-worker limit bounds host pressure. Runtime group
cleanup requires a supported native POSIX host/target; unsupported and cross targets
fail in the build graph before test compilation and retain the standard native gate. For a new
shared host resource, `--policy=conservative` runs the noncrypto remainder and TLS
transport fixtures serially while sharding source-audited crypto cases; `--workers=1` provides
the same inventory/count checks serially. Platform-native acceptance remains required.

Validate harness changes with the small compiled fixture:

```sh
ONYX_TEST_ZIG=/path/to/pinned/zig python3 -B tools/test_verbose_test_runner.py
ONYX_TEST_ZIG=/path/to/pinned/zig python3 -B tools/test_test_build_graph.py
```

The build-graph controls include a disposable Git checkout: initial clean build,
dirty documentation, and a documentation-only commit must preserve all three cached
test binaries byte-for-byte with unchanged modification times while the production
binary refreshes its real version stamp.

The blinded RSA PKCS1 stress case retains its baseline plus 25 independently blinded
signatures. Four arithmetic workers produce separate signature/error/verification
results; the parent joins every worker and checks all 26 verifications and 25 byte
comparisons. Assertions and the testing allocator remain on the parent thread.

The fixture covers filtering, empty selections, listing, deterministic exhaustive
shards, failures, skip counts, warm artifact reuse, and a full-inventory runtime
comparison. Its speedup measures scheduling overhead and concurrency; production
speedup must be measured on the real complete suite. Compare complete discovered,
executed, passed, and skipped counts across modes and against prior source-bound
full evidence before release acceptance. Use the existing gate ledger to reuse
unchanged successful evidence; diagnose unchanged failures before scheduling reruns.

## Broad deterministic lanes

| Command | Use it for |
|---|---|
| `zig build test --summary all` | Full module + executable-root + CLI tests; unfiltered native POSIX runs bounded runtime shards. |
| `zig build test-serial --summary all` | Full reference graph with serial execution within each root. |
| `zig build fuzz --summary all` | Bounded replay of coverage-fuzz seed corpora. |
| `zig build bogo-shim-test --summary all` | Self-driven BoGo shim parse/framing/subprocess smokes. |
| `tools/bogo.sh` | Pinned external BoringSSL runner: exact 207-pass/3-explicit-skip baseline; fails on drift, any unexpected failure, or an all-skip/vacuous result. Uses `.bogo/` or `BOGO_CACHE_DIR`, never `/tmp`. See [TCP TLS interop](#tcp-tls-interop). |
| `zig build all-checks --summary all` | Deterministic pre-push gate: `check`, WASM build, full tests, bounded fuzz, and BoGo shim self-tests. |
| `zig build all-checks-verbose --summary all` | Same gate, with per-test progress for the full suite. |

The remaining build-graph utilities are also intentional release tooling:
`zig build wasm`, `zig build ct-check`, `zig build bench`, `zig build bench-live`,
`zig build fuzz`, `zig build quic-interop-server`, `zig build quic-interop-wt-server`,
`zig build bogo-shim`, `zig build release`, and `zig build package`. Their exact
descriptions are kept in the [build guide](build.md).

`zig build ct-check` is intentionally separate. It is a timing/statistical
constant-time harness and should not be folded into deterministic CI gates.

## Runtime smoke lanes

These helpers run a real daemon binary, not only `test` blocks:

| Command | Use it for |
|---|---|
| `python3 tools/runtime_smoke.py zig-out/bin/onyx-server` | Cold-boot a loopback daemon, register a client, verify PING/PONG, and shut down cleanly. |
| `python3 tools/upgrade_smoke.py zig-out/bin/onyx-server` | Exercise Helix/SIGUSR2 hot-upgrade, inherited listener adoption, carried connection survival, WHOIS, NAMES, and post-upgrade registration. |

Run them after `zig build` or against a staged release binary when validating an
operator-facing change.

## TCP TLS interop

These lanes test Armor's TCP TLS stack against independent implementations.
They need external tools, so they stay out of `zig build test`.
`packaging/release.sh` can run them as opt-in gates (see below).

| Command | Peer | What must hold |
|---|---|---|
| `tools/bogo.sh` | BoringSSL `ssl/test/runner`, pinned commit | Exact pass/skip baseline in `tools/bogo/expected-baseline.txt` (207 pass, 3 skip). |
| `tools/bogo.sh -test '*'` | same | Exploratory full run, for triage. On 2026-11-07 it had no failures (see below). |
| `tools/openssl_interop.sh [onyx-server]` | system `openssl` 3.x, `s_client` and `s_server` | 34 cases pass and 1 is `KNOWN` (the ALPN mismatch, see below). With `ONYX_INTEROP_STRICT=1`, any `SKIP` counts as a failure. |
| `python3 tools/browser_tls_smoke.py [onyx-server]` | headless Chromium over `wss://` | The IRC session registers, and the NetLog shows TLS 1.3 with group `X25519MLKEM768` (4588). |

**BoGo.** The shim (`tools/bogo_shim.zig`) drives the daemon's `TlsConn`, the
1.3 server plus the hardened 1.2 server, through these runner flags:
`-resume-count`, `-expect-session-miss`, `-ocsp-response`, `-async`,
`-expect-hrr` and `-expect-no-hrr`. Server resumption therefore runs for real:
every connection in one invocation shares a ticket key. The shim turns on the
strict RFC 7301 §3.2 ALPN refusal (`alpn_mismatch_fatal`); the daemon
listeners leave it off. Any other flag exits 89, which the runner reports as skipped.

`DisabledTests` in `tools/bogo/config.json` lists three kinds of case:

- the deliberate modern-only posture: no TLS 1.0 or 1.1, no static RSA, no CBC,
  no SHA-1, no P-384 or P-521 signing, no ML-DSA, EMS required in TLS 1.2, and
  no session-ID cache;
- behavior that the RFCs leave optional, where BoringSSL happens to be strict;
- families the shim does not drive yet (0-RTT, client certificates, ECH,
  delegated credentials).

Genuine defects stay enabled. They are simply absent from the baseline.

Go is not vendored. Any Go toolchain new enough for the pinned runner works, for
example one unpacked into a scratch directory. `BOGO_CACHE_DIR` moves the
BoringSSL checkout.

**OpenSSL.** The script boots a private daemon with a temporary config, a
temporary CA, an ECDSA P-256 leaf and then an RSA-2048 leaf, all on loopback
ports. It then runs `s_client` for these cases:

- each TLS 1.3 cipher suite;
- each group: x25519, secp256r1 and X25519MLKEM768, skipped if the local
  OpenSSL lacks one;
- a HelloRetryRequest from secp384r1 to x25519, confirmed in the `-msg` trace;
- six TLS 1.2 ECDHE suites;
- TLS 1.3 and TLS 1.2 resumption with `-sess_out` and `-sess_in`;
- ALPN `irc`;
- an ALPN mismatch;
- `-status`.

Every handshake verifies the chain and carries `NICK`/`USER` through to `001`.

For the client direction, the script builds `tools/openssl_interop_client.zig`.
This is the daemon's real `http_fetch` outbound path: the TLS 1.3 client, with
the 1.2 fallback. It fetches from `openssl s_server -www` pinned to each suite,
group and version. The response page names the parameters that OpenSSL
negotiated.

Two server behaviors show up in the output:

- On an ALPN mismatch the daemon continues without selecting a protocol. RFC
  7301 §3.2 says a server SHALL send a `no_application_protocol` alert. The
  script records this deviation as `KNOWN`. It is never counted as `PASS`, and
  it becomes `PASS` once the engine sends the alert.
- With no OCSP responder configured, the daemon does not staple a response.

A group that the local OpenSSL lacks is recorded as `SKIP`. That passes in a
normal run but fails under `ONYX_INTEROP_STRICT=1`, which the release gate
sets. `INTEROP_KEEP=1` keeps the logs. Relative binary paths are resolved
against the caller's directory.

**Browser.** Chromium has no Ed25519 certificate support. The smoke therefore
issues an ECDSA leaf from a throwaway CA. It trusts that leaf only through
`--ignore-certificate-errors-spki-list`, and restricts host resolution to
loopback. A NetLog `SSL_CONNECT` result counts only when its socket connected
to the daemon's `wss` port. Exit 77 means chromium or openssl is missing.

**Constant time.** `zig build ct-check` is the dudect harness. It reports a
Welch |t| per primitive and gates at 10.

**Release gates** in `packaging/release.sh` are all off by default. Each one
fails closed when requested:

- `ONYX_RELEASE_CT_CHECK=1` runs `zig build ct-check` with the release's
  `-Dtarget` and `-Dcpu=baseline`, so it measures the shipped code generation.
  The host must be able to execute the target.
- `ONYX_RELEASE_INTEROP=1` runs the OpenSSL lane in strict mode, then the
  browser lane, against the absolute path of the freshly built artifact. The
  host must be able to execute the target.
- `ONYX_RELEASE_BOGO=1` runs `tools/bogo.sh`.

**BoGo triage (pinned runner `5ac7567c`, 2026-11-07).** The full
`-test '*'` run now gives 207 passed and 0 failed. The exact baseline is 207
PASS and 3 SKIP. The skipped cases are `CheckClientCertificateTypes`,
`ClientCertificateTypes` and `SendFallbackSCSV`. `tools/bogo.sh` runs in CI
(the `bogo` job). The GAP-K6 guard in `src/crypto/tls.zig`
pins the exact PASS count of the baseline file, so it must change whenever the
baseline is regenerated.

History: the audit started from 24 passing cases. Driving TLS 1.3 server
resumption and OCSP raised that to 121, with 80 genuine failures in the full
run. Wave 2b fixed every class of those failures in `tls_server.zig`,
`tls12_server.zig` and the shim (202 passed, 5 failed):

- TLS 1.3 CertificateVerify and TLS 1.2 ServerKeyExchange ignored the
  client's `signature_algorithms`;
- version negotiation (`legacy_version`, `supported_versions`);
- a TLS 1.2 client Finished spanning several records;
- a TLS 1.2 full handshake echoing the client's session_id;
- TLS 1.3 PSK failures falling back instead of aborting, and multiple PSK
  identities;
- loose ClientHello, ALPN, SNI and key_share parsing;
- an HRR instead of `missing_extension`;
- wrong alert codes;
- the shim could not see a received alert.

Wave 2c fixed the last 5 (`tls_conn.zig`): a first flight that is not a lone
ClientHello is now `unexpected_message`, not `decode_error`.

`DisabledTests` in `tools/bogo/config.json` holds 53 patterns. Most are the
modern-only posture described above. Some are RFC-optional behavior, for example
`DuplicateKeyShares-TLS13` and `Resume-Server-OmitAllPSKsOnSecondClientHello`.
The rest are features the shim does not drive yet: `*EarlyData*`,
`*ClientAuth*`, `*ECH*` and `*DelegatedCredential*`. Those families have no
BoGo coverage, so the unit tests and the OpenSSL lane are their only interop
evidence.

## Roadmap-change default

For daemon/TLS/server roadmap work, run:

```sh
zig build test-smoke --summary all
zig build test-roadmap-verbose --summary all
zig build test -Dtest-filter="<feature keyword>" --summary all
zig build test-smoke -Doptimize=safe --summary all
zig build all-checks --summary all
```

For deploy or Helix work, add:

```sh
zig build
python3 tools/runtime_smoke.py zig-out/bin/onyx-server
python3 tools/upgrade_smoke.py zig-out/bin/onyx-server
```

When config files changed, also run:

```sh
zig build run -- --check-config etc/onyx-server.reference.toml
```

Source of truth: `build.zig`, `tools/parallel_tests.py`, `tools/verbose_test_runner.zig`, the gate receipts linked by the [release audit](../audit/release-and-test-speed-2026-11-03.md), and the emitted suite inventories. Current installed fleet facts live in [production paths](../ops/onyx-server-paths.md); platform-specific tests retain their recorded scope.
