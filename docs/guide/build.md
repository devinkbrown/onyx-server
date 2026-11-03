# Build guide

*Build, test, and cross-compile the Onyx Server daemon with Zig.*

Onyx Server builds with Zig's build system and has no package dependencies in
`build.zig.zon`. Linux builds do not link libc; macOS and BSD targets link libc
only for the platform syscalls that require it.

## Requirements

- Zig `0.17.0`, the minimum declared by `build.zig.zon`. Use the exact
  compiler recorded by the release you are reproducing; the minimum alone
  does not establish compatibility with a different compiler distribution.
- A 64-bit daemon target. `build.zig` rejects 32-bit daemon builds at configure time.

## Common targets

The table below follows the current `build.zig` graph (reviewed 2026-11-03). Every focused
test lane has a `-verbose` sibling; verbose lanes print each test and timing.

| Command | What it does | Source |
|---|---|---|
| `zig build` / `zig build install` | Install the debug daemon and `armor` CLI into `zig-out/bin`. | `build.zig` |
| `zig build uninstall` | Remove artifacts from the selected install prefix. | `build.zig` |
| `zig build run -- <config.toml>` | Build/install, then run the daemon with forwarded args. | `build.zig` |
| `zig build test-mod [-Dtest-filter=<text>]` | Run only library/module tests. | `build.zig` |
| `zig build test-exe [-Dtest-filter=<text>]` | Run only executable-root tests. | `build.zig` |
| `zig build test-tls` | Armor TLS, mTLS, ECH, RPK, delegated-credential, and record-size tests. | `build.zig` |
| `zig build test-server` | Daemon/server integration and authentication tests. | `build.zig` |
| `zig build test-exploit` / `test-attack` | Adversarial exploit corpus; `test-attack` is an alias. | `build.zig` |
| `zig build test-config` | TOML parsing, boot projection, and reference-config tests. | `build.zig` |
| `zig build test-ircx` | IRCX, PROP, ACCESS, DATA, LISTX, MODEX, and SACCESS tests. | `build.zig` |
| `zig build test-event-spine` | Event Spine, EVENT, observe, policy, and playback tests. | `build.zig` |
| `zig build test-mesh` | Undertow mesh, S2S, repair, and secured-link tests. | `build.zig` |
| `zig build test-media` | Media, DTLS-SRTP, SFU, native media, WebTransport, RTP, and RTCP tests. | `build.zig` |
| `zig build test-services` | Services, account auth, SASL, TOTP, WebAuthn, sessions, and MEMO tests. | `build.zig` |
| `zig build test-session` | Reusable-session, migration, replica, World restore, and Helix session tests. | `build.zig` |
| `zig build test-helix` | Helix upgrade, migration, resume, capsule, and handoff tests. | `build.zig` |
| `zig build test-dst` | Seed-replayable DST, simulator, and multi-reactor timer-guard tests. | `build.zig` |
| `zig build test-cli` | `armor` crypto CLI toolkit tests. | `build.zig` |
| `zig build test` | Full module, executable-root and CLI test suite; native POSIX runs bounded parallel shards. | `build.zig` |
| `zig build test-smoke` | `check` plus fast TLS/server/config smoke suites. | `build.zig` |
| `zig build test-roadmap` | `check` plus focused server-roadmap suites. | `build.zig` |
| `zig build test-verbose` | Full suite with per-test progress output. | `build.zig` |
| `zig build test-*-verbose` | Verbose sibling for each focused lane, including smoke and roadmap. | `build.zig` |
| `zig build wasm` | Build browser CadenceVox/CadenceVis codec and transport WASM modules. | `build.zig` |
| `zig build check` | Type-check the daemon without emitting a binary. | `build.zig` |
| `zig build ct-check` | Opt-in dudect-style constant-time statistical harness. | `build.zig` |
| `zig build bench` | Offline parse, tag, fan-out, cross-shard, and accept-rate measurements. | `build.zig` |
| `zig build bench-live [-- --quick]` | Throwaway loopback daemon axes: TLS, shards, ring settings, JOIN/PRIVMSG RTT, RSS. | `build.zig` |
| `zig build fuzz` / `zig build fuzz --fuzz` | Bounded TLS-parser corpus replay, or coverage-guided mode. | `build.zig` |
| `zig build quic-interop-server` | Build standalone QUIC/HTTP3 interop server. | `build.zig` |
| `zig build quic-interop-wt-server` | Build standalone WebTransport browser interop server. | `build.zig` |
| `zig build bogo-shim` | Build the standalone BoGo TLS shim. | `build.zig` |
| `zig build bogo-shim-test` | Build and self-drive BoGo shim loopback exit-code smokes. | `build.zig` |
| `zig build all-checks` | Deterministic pre-push gate: check, WASM, full tests, bounded fuzz, BoGo self-tests. | `build.zig` |
| `zig build all-checks-verbose` | Same deterministic gate with full test progress. | `build.zig` |
| `zig build release` | Build an optimized, stripped `ReleaseFast` daemon. | `build.zig` |
| `zig build package` | Stage daemon, reference config and target-specific deployment assets. | `build.zig` |

`-Dtest-filter=<text>` compile-filters the original focused targets.
`test-cached` and `test-exe-cached` compile their complete root once and accept
`-- --test-filter=<text>` at runtime. Unfiltered native POSIX `test` and
`all-checks` use exhaustive bounded parallel shards; `test-serial` retains
the reference graph. See [testing](testing.md) for selection, retained logs,
timing profiles and coverage checks before choosing a lane.

## Cross targets

Pass `-Dtarget=<triple>` to choose a target; the build script uses Zig's
standard target options.

For example:

```sh
zig build -Dtarget=x86_64-linux
zig build -Dtarget=aarch64-linux -Doptimize=safe
zig build check -Dtarget=x86_64-linux
```

The daemon target must be 64-bit. The `wasm` step is the deliberate
`wasm32-freestanding` exception for browser codec and transport artifacts, not
for the daemon.

### OpenBSD runtime

OpenBSD uses the shared full daemon over a native kqueue completion backend.
Build output alone does not establish native OpenBSD acceptance. Run the
transport/session and upgrade probes below on the intended target, then
complete the [installed service-policy checks](../ops/openbsd-service-policy.md).
Cross-build with:

```sh
zig build -Dtarget=x86_64-openbsd -Doptimize=fast
zig build-exe -target x86_64-openbsd -O fast \
  -femit-bin=bench_x4_portable tools/bench_x4_portable.zig
```

Copy `zig-out/bin/onyx-server` and the benchmark to `/tmp` on the OpenBSD machine. A
minimal loopback config for local testing is:

```toml
[node]
id = 1
[listen]
host = "127.0.0.1"
irc = 16680
[limits]
max_clients = 128
chanlimit = 8
[io]
ring_entries = 32
sqpoll = false
```

Run `/tmp/onyx-server --check-config local.toml` before
`/tmp/onyx-server local.toml`, or `/tmp/bench_x4_portable /tmp/onyx-server` for the
four-client benchmark. Use a normal installation: the installer ramdisk can
serve IRC but may lack both `ps` and the `KERN_PROC` RSS query.

The shared OpenBSD daemon supports multiple reactors, account services,
durable history, TLS, WebSocket, mesh, media, metrics, and PROXY-header policy.
Wildcard IPv6 listeners have explicit IPv4 companions. TLS encryption stays
in userspace. OpenBSD confinement derives unveiled paths from the configured
runtime resources and preserves them across native Helix execution. A successor
must validate its complete checkpoint and existing identity before READY;
storage stays read-only until COMMIT. FreeBSD retains the separate minimal
portable runtime and its preflight feature guards. Select acceptance for the
actual platform and artifact rather than transferring an older benchmark or
Linux release result across targets.

Build the native acceptance executables with the same target and optimization
mode as the daemon:

```sh
zig build openbsd-probes -Dtarget=x86_64-openbsd -Doptimize=safe
```

This installs the Helix descriptor, confinement, and worker protocol probes in
`zig-out/bin`; execution requires an isolated OpenBSD guest. The worker probe
requires a temporary `198.51.100.77/32` alias on that guest's `lo0`, removed after
the run. Host-side runtime probes live in `tools/openbsd_runtime_smoke.py` and
`tools/openbsd_session_smoke.py`. Both require an expected daemon SHA-256 and
use explicit fixture paths and ports. The session probe also requires Python's
`cryptography` package on the host. The transport probe expects the daemon and IPv4/IPv6 SSH forwards already
running; the session probe owns its private three-node fixtures and forwards.
Their `--help` output documents the arguments.

To build complete unit-test runners for execution on the target machine:

```sh
zig build test-artifacts -Dtarget=x86_64-openbsd -Doptimize=safe
```

The installed runners are `onyx-server-module-tests`,
`onyx-server-daemon-tests`, and `onyx-server-cli-tests`. This step builds without
executing them on the build host; native execution is a separate gate. Run the installed runners from a writable
matching source checkout on OpenBSD: source-witness tests also read repository
files at runtime. Copying only the executables is insufficient.

For an unfiltered Windows target, the module runner is split into five files:
`onyx-server-module-tests-crypto`, `-daemon`, `-proto`, `-substrate`, and
`-wasm` (all with `.exe` suffix). Run all five for full module coverage. The
daemon and CLI runner names also get `.exe` on Windows. A filtered Windows
build still installs the single `onyx-server-module-tests.exe` runner.

## Optimization

Zig 0.17.0 accepts `-Doptimize=debug`, `safe`, `fast`, and `small`.
`safe` retains runtime safety checks; `fast` and `small` disable them.
Debug builds keep symbols; optimized daemon builds strip debug info. The
`release` and `package` targets select the optimized release artifact separately
from the default development install. Release scripts use `--release=fast`
and record the exact target, baseline CPU, compiler and source identity.

## Packaging

`zig build package` is the deployable bundle step. It is separate from the default
install so `zig build` stays a fast debug binary install. By default it stages under
`zig-out/`; use `--prefix <dir>` for a release staging directory:

```sh
zig build package --prefix /tmp/onyx-server-stage
```

The staged layout is:

| Path | Contents |
|---|---|
| `bin/onyx-server` | ReleaseFast stripped daemon |
| `etc/onyx-server/onyx-server.reference.toml` | Annotated reference config |
| `lib/systemd/system/onyx-server.service` | Linux systemd unit |
| `etc/init.d/onyx-server` | Linux OpenRC supervisor script |
| `etc/conf.d/onyx-server` | OpenRC first-install settings; preserve existing overrides |

Staging does not provision an account, choose node identity, install or enable
a service. Use [service management](service-management.md) and the
[runbook](../RUNBOOK.md) for installation, compatible reload and rollback.
