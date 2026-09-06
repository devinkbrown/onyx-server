# Build guide

*Build, test, and cross-compile the Onyx Server daemon with Zig.*

Onyx Server builds with Zig's build system and has no package dependencies in
`build.zig.zon`. Linux builds do not link libc; macOS and BSD targets link libc
only for the platform syscalls that require it.

## Requirements

- Zig `0.17.0-dev.1282+c0f9b51d8` or newer as declared by `build.zig.zon`.
- A 64-bit daemon target. `build.zig` rejects 32-bit daemon builds at configure time.

## Common targets

The table below is reconciled with `zig build --help` (2026-09-06). Every focused
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
| `zig build test` | Full module plus executable-root test suite. | `build.zig` |
| `zig build test-smoke` | `check` plus fast TLS/server/config smoke suites. | `build.zig` |
| `zig build test-roadmap` | `check` plus focused server-roadmap suites. | `build.zig` |
| `zig build test-verbose` | Full suite with per-test progress output. | `build.zig` |
| `zig build test-*-verbose` | Verbose sibling for each focused lane, including smoke and roadmap. | `build.zig` |
| `zig build wasm` | Build browser CadenceVox/CadenceVis codec and transport WASM modules. | `build.zig` |
| `zig build check` | Type-check the daemon without emitting a binary. | `build.zig` |
| `zig build ct-check` | Opt-in dudect-style constant-time statistical harness. | `build.zig` |
| `zig build bench` | Offline 0.7 parse, tag, fan-out, cross-shard, and accept-rate measurements. | `build.zig` |
| `zig build bench-live [-- --quick]` | Throwaway loopback daemon axes: TLS, shards, ring settings, JOIN/PRIVMSG RTT, RSS. | `build.zig` |
| `zig build fuzz` / `zig build fuzz --fuzz` | Bounded TLS-parser corpus replay, or coverage-guided mode. | `build.zig` |
| `zig build quic-interop-server` | Build standalone QUIC/HTTP3 interop server. | `build.zig` |
| `zig build quic-interop-wt-server` | Build standalone WebTransport browser interop server. | `build.zig` |
| `zig build bogo-shim` | Build the standalone BoGo TLS shim. | `build.zig` |
| `zig build bogo-shim-test` | Build and self-drive BoGo shim loopback exit-code smokes. | `build.zig` |
| `zig build all-checks` | Deterministic pre-push gate: check, WASM, full tests, bounded fuzz, BoGo self-tests. | `build.zig` |
| `zig build all-checks-verbose` | Same deterministic gate with full test progress. | `build.zig` |
| `zig build release` | Build an optimized, stripped `ReleaseFast` daemon. | `build.zig` |
| `zig build package` | Stage daemon, reference config, and systemd unit into the install prefix. | `build.zig` |

`-Dtest-filter=<text>` is a build option. Do not pass `-- --test-filter`; that
does not configure the build graph and can run far more than intended. See the
[testing guide](testing.md) for the recommended lanes.

## Cross targets

Pass `-Dtarget=<triple>` to choose a target; the build script uses Zig's
standard target options.

For example:

```sh
zig build -Dtarget=x86_64-linux
zig build -Dtarget=aarch64-linux -Doptimize=ReleaseSafe
zig build check -Dtarget=x86_64-linux
```

The daemon target must be 64-bit. The `wasm` step is the deliberate
`wasm32-freestanding` exception for browser codec and transport artifacts, not
for the daemon.

## Optimization

Use Zig's standard `-Doptimize=` modes. Debug builds keep symbols; optimized
daemon builds strip debug info.

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
| `lib/systemd/system/onyx-server.service` | systemd unit for production deployment |

See the [runbook](../RUNBOOK.md) for install, reload, and rollback procedures.
