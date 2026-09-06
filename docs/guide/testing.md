# Testing guide

Onyx Server's test suite is large, so the build graph exposes several lanes. Use the
smallest lane that proves the change, then run a broader gate before pushing.

The lane names below are synchronized with `zig build --help` on 2026-09-06.

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
| `zig build test-smoke -Doptimize=ReleaseSafe --summary all` | Optimized smoke gate for safety-checked release codegen paths. |

Every focused lane has a `-verbose` twin, for example
`zig build test-tls-verbose --summary all`. Use verbose lanes in CI, tmux, or
any long run where silence looks like a hang; they print each test name before it
executes, include per-test duration, and finish with the slowest tests.

Focused filters are build options, not test-binary arguments:

```sh
zig build test-mod -Dtest-filter="mTLS:" --summary all
zig build test-exe -Dtest-filter="threaded server:" --summary all
```

Do not use `zig build test -- --test-filter ...`; that does not configure the
build graph and can accidentally run the broad suite.

## Broad deterministic lanes

| Command | Use it for |
|---|---|
| `zig build test --summary all` | Full module + executable-root tests. |
| `zig build fuzz --summary all` | Bounded replay of coverage-fuzz seed corpora. |
| `zig build bogo-shim-test --summary all` | Self-driven BoGo shim parse/framing/subprocess smokes. |
| `tools/bogo.sh` | Pinned external BoringSSL runner: exact 24-pass/3-explicit-skip baseline; fails on drift, any unexpected failure, or an all-skip/vacuous result. Uses `.bogo/` or `BOGO_CACHE_DIR`, never `/tmp`. |
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

## Roadmap-change default

For daemon/TLS/server roadmap work, run:

```sh
zig build test-smoke --summary all
zig build test-roadmap-verbose --summary all
zig build test -Dtest-filter="<feature keyword>" --summary all
zig build test-smoke -Doptimize=ReleaseSafe --summary all
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
