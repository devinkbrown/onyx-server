# Contributing to Onyx Server

Onyx Server is a clean-room, Zig-native IRC daemon. Contributions are welcome, but the bar
is intentionally high: changes should keep the daemon source-backed, tested, and
operationally understandable.

Onyx Server is licensed under **AGPL-3.0-or-later**. By contributing, you agree that your
contributions are licensed under the same terms; see [LICENSE](LICENSE).

## Prerequisites

- Zig `0.17.0-dev.1282+c0f9b51d8` or newer, matching `build.zig.zon`.
- A 64-bit target for the daemon. The browser WASM artifacts are the only deliberate
  `wasm32` exception.
- Linux for full runtime testing. The daemon reactor uses `io_uring`; non-Linux
  targets are still useful for semantic/cross-build checks where supported.
- Python 3 for runtime smoke helpers in `tools/`.

## Source Of Truth

Use the current source before trusting older planning notes:

| Need | Source |
|---|---|
| Build/test/deploy commands | `zig build --help`, `build.zig` |
| Config schema | `src/daemon/config_format.zig`, `src/daemon/config_boot.zig`, `etc/onyx-server.reference.toml` |
| Live capability list | `src/daemon/dispatch.zig` |
| Command/module registry | `src/daemon/modules/manifest.zig`, `src/daemon/registry.zig` |
| Server behavior proof | `src/daemon/server.zig` tests and focused build lanes |
| Operator docs | `docs/guide/`, `docs/reference/`, `docs/RUNBOOK.md` |

Planning and research docs are historical design context. If they disagree with live
source, fix the reference/guide docs or the code, not the evidence.

## Build Commands

<!-- AUTO-GENERATED: build-commands -->
| Command | Purpose |
|---|---|
| `zig build` / `install` / `uninstall` | Install or remove the debug daemon and `armor` from the selected prefix. |
| `zig build run -- <config.toml>` | Build/install and run with forwarded daemon arguments. |
| `zig build check` | Fast semantic analysis without emitting a binary. |
| `zig build test-mod[-verbose]` | Library/module tests, optionally with per-test progress. |
| `zig build test-exe[-verbose]` | Executable-root tests, optionally with per-test progress. |
| `zig build test-tls[-verbose]` | Armor TLS, mTLS, ECH, RPK, DC, and record-size tests. |
| `zig build test-server[-verbose]` | Daemon/server integration and auth tests. |
| `zig build test-exploit` / `test-attack` | Adversarial fail-closed corpus and alias. |
| `zig build test-config[-verbose]` | TOML, boot projection, and reference-config tests. |
| `zig build test-ircx[-verbose]` | IRCX, PROP, ACCESS, DATA, LISTX, MODEX, SACCESS tests. |
| `zig build test-event-spine[-verbose]` | Event Spine, EVENT, observe, and playback tests. |
| `zig build test-mesh[-verbose]` | Undertow mesh, S2S, repair, and secured-link tests. |
| `zig build test-media[-verbose]` | Media, DTLS-SRTP, SFU, WebTransport, RTP, and RTCP tests. |
| `zig build test-services[-verbose]` | Services, account, SASL, TOTP, WebAuthn, session, MEMO tests. |
| `zig build test-session[-verbose]` | Reusable-session, migration, replica, and World-restore tests. |
| `zig build test-helix[-verbose]` | Helix upgrade, migration, resume, capsule, handoff tests. |
| `zig build test-dst` | Seed-replayable DST/simulator/multi-reactor timer-guard tests. |
| `zig build test-cli[-verbose]` | `armor` CLI tests. |
| `zig build test[-verbose]` | Full suite, with optional per-test progress. |
| `zig build test-smoke[-verbose]` | Fast semantic + TLS/server/config smoke gate. |
| `zig build test-roadmap[-verbose]` | Server-roadmap focused gate. |
| `zig build wasm` | Build browser codec/transport WASM modules. |
| `zig build ct-check` | Opt-in statistical constant-time harness. |
| `zig build bench` / `bench-live` | Offline and throwaway-loopback performance measurements. |
| `zig build fuzz` | Bounded TLS-parser corpus replay; add `--fuzz` for coverage-guided mode. |
| `zig build quic-interop-server` / `quic-interop-wt-server` | Build QUIC/HTTP3 and WebTransport interop servers. |
| `zig build bogo-shim` / `bogo-shim-test` | Build or self-test the BoGo TLS shim. |
| `zig build all-checks[-verbose]` | Deterministic pre-push gate, optionally verbose. |
| `zig build release` | Build a stripped ReleaseFast daemon. |
| `zig build package` | Stage ReleaseFast daemon, reference config, and systemd unit. |
<!-- /AUTO-GENERATED: build-commands -->

Use `-Dtest-filter="<substring>"` as a build option for focused work:

```sh
zig build test-mod -Dtest-filter="mTLS:" --summary all
zig build test-exe -Dtest-filter="threaded server:" --summary all
```

Do not pass `-- --test-filter`; it bypasses the build graph filters and can run far
more than intended.

## Runtime Smokes

After building:

```sh
python3 tools/runtime_smoke.py zig-out/bin/onyx-server
python3 tools/upgrade_smoke.py zig-out/bin/onyx-server
```

`runtime_smoke.py` cold-boots a loopback daemon, registers a client, checks PING/PONG,
and quits cleanly. `upgrade_smoke.py` exercises Helix/SIGUSR2 hot-upgrade and verifies
the listener and carried session survive the exec.

## Code Standards

- Pure Zig. Do not add C interop, vendored C shims, or runtime package dependencies.
- Preserve explicit allocator ownership and error handling.
- Keep protocol behavior source-backed and test-backed.
- Add tests with behavior changes. Bug fixes should carry regression tests.
- Prefer focused modules over catch-all files.
- Keep generated root imports current when adding/removing Zig source:

  ```sh
  ./tools/genroots.sh
  ```

- Source and script files need SPDX headers:

  ```zig
  // SPDX-FileCopyrightText: <year> <your name> <your email>
  // SPDX-License-Identifier: AGPL-3.0-or-later
  ```

## Documentation Standards

- Guides and references must document shipped behavior, not aspirational backlog.
- When a doc claims a command, capability, config key, or runtime behavior, ground it
  in current source or a passing test.
- Update `docs/README.md` when adding a new major guide/reference.
- Keep `docs/reference/config.md` and `etc/onyx-server.reference.toml` synchronized when
  config keys change.
- Keep `docs/guide/testing.md` synchronized with `zig build --help`.

## Pull Request Checklist

Before opening or merging a change:

```sh
zig build test-smoke --summary all
zig build test-roadmap --summary all
zig build test-smoke -Doptimize=ReleaseSafe --summary all
zig build all-checks --summary all
git diff --check
```

Also run these when relevant:

```sh
zig build run -- --check-config etc/onyx-server.reference.toml
python3 tools/runtime_smoke.py zig-out/bin/onyx-server
python3 tools/upgrade_smoke.py zig-out/bin/onyx-server
```

For TLS/crypto/S2S/auth changes, explicitly call out the security surface in the PR
description and include the focused lane used to prove it.

## Commit Style

Use conventional-style subjects:

- `feat:`
- `fix:`
- `test:`
- `docs:`
- `ci:`
- `refactor:`
- `perf:`
- `chore:`

Keep commits scoped. Do not mix unrelated roadmap, docs, and mechanical cleanup unless
the change is intentionally a broad synchronization pass.

## Reporting Bugs

Open a GitHub issue with:

- Onyx Server commit hash or VERSION output.
- Zig version.
- Redacted config.
- Reproduction steps.
- Relevant log excerpt.

Do not file public issues for security vulnerabilities. Use [SECURITY.md](SECURITY.md).
