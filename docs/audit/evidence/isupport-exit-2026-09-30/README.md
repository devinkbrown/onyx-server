<!-- SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com> -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# ISUPPORT boot-error cleanup follow-up

Follow-up to OpenBSD port commit `e83b2939`. The shared daemon now clears the
borrowed global ISUPPORT override and frees its vector and dynamic token strings
on return from `main`, after server teardown. The production change is limited
to `src/main.zig`. No protocol, native arena or descriptor changes are involved.

## Boot-error comparison

The same valid OCG2 fixture requests a pre-existing node key in an isolated
working directory where that key is absent. All compared executions terminate with
exit 1 and the expected `FileNotFound` error before server startup. No node key
is generated and no listener is started.

| Daemon | SafeAllocator leak records | Leaked bytes | Raw record |
|---|---:|---:|---|
| Pre-fix `e83b2939`, Linux Debug | 16 | 694 | `isupport-exit-baseline-missing-key.log` |
| Patched Linux Debug | 0 | 0 | `isupport-exit-debug-missing-key.log` |
| Patched Linux ReleaseSafe | 0 | 0 | `isupport-exit-rs-missing-key.log` |
| Original port artifact, native OpenBSD Debug | 16 | 694 | `isupport-exit-openbsd-baseline-missing-key.log` |
| Patched native OpenBSD Debug | 0 | 0 | `isupport-exit-openbsd-debug-missing-key.log` |
| Patched native OpenBSD ReleaseSafe | 0 | 0 | `isupport-exit-openbsd-rs-missing-key.log` |

The diagnostic is spelled `error(SafeAllocator): leaked [` in these Linux logs.
The 16 baseline `len:` values total 694 bytes. This reproduces the allocation
identified in the original native rejected-candidate acceptance log. This
follow-up executes Linux and native OpenBSD binaries against the isolated boot
error. This native check does not repeat the full mesh/transport acceptance
campaign. Exit status and post-run key absence are retained in
`isupport-exit-linux-fixture-receipt.log` and
`isupport-exit-openbsd-fixture-receipt.log`.

Compiler: Zig `0.17.0-dev.1282+c0f9b51d8`. Main source SHA-256 before:
`83e4700564ea13d98f75c6feb21cc725f372392772a3a59282ddd0450081909d`;
after: `2d36a08c511ffc5d18bd7a8542dd18878e252514ea3683218242c0f30d1c0975`.
Tested daemon SHA-256:

- Pre-fix Debug: `425f21c954072092cecef1ad4145e8b4dfa4491d8514a8dcf06ef5debd2ee3e7`.
- Patched Debug: `b545e691225f070327b9e624d9705d9b490394363489f8302c3443f703bc2576`.
- Patched ReleaseSafe: `a5dfbbf309b04c2c5260b7f61030a34f7cb580583b1740d0c5984abe52b08270`.
- Original native Debug port artifact: `8f45073cda5e75a8589e09d7c3590df0b2e667bdb4e91e4e678cc6b3d182269a`.
- Patched native Debug: `c512ae17cc0edc1ad10aa8cbb2d986b5850af202c0ec7cb43404c40c062dfd1e`.
- Patched native ReleaseSafe: `381eeae769ed185caa525d203736bd02e60bfedb8116ef5c210bd161d00dcc01`.

Build-time metadata identifies `e83b2939-dirty`; source hashes distinguish the
accepted follow-up. The baseline was built in a detached worktree at that commit,
then the worktree was removed. The fixture public authority is synthetic test
material generated from a repeated `0xb1` seed; no private key is configured.

## Commands and review

- Full Linux `zig build test --summary all`, Debug and ReleaseSafe: 8/8
  steps each, 8761/8785 tests passed, 24 skipped, zero failures, exit 0.
  See `isupport-exit-full-debug.log` and `isupport-exit-full-rs.log`.
- `zig build check --summary all`: 3/3 steps, exit 0.
- `zig build check -Dtarget=x86_64-openbsd --summary all`: 3/3 steps, exit 0.
- `zig build --summary all --prefix <debug-prefix>`: 6/6 steps, exit 0.
- `zig build -Doptimize=ReleaseSafe --summary all --prefix <rs-prefix>`: 6/6 steps, exit 0.
- Native builds in both modes: `zig build -Dtarget=x86_64-openbsd` with the
  corresponding optimization and prefix, 6/6 steps each, exit 0.
- Execute each binary with the absolute path to `fixture.toml` from a private
  directory containing no `onyx-server-node.key`; bound execution to 20 seconds.
  Expected refusal is exit 1, not a successful daemon boot.

Fresh read-only `/root/review_isupport_exit` verdict: **Approve**. The override
is cleared before free; later server and worker defers execute first. The
reviewer inspected the borrowed global slice and token destructor, and checked
formatting and diff cleanliness. The reviewer did not claim runtime execution.

Explicit `process.exit` and `_exit` calls bypass defers and retain their previous
process-lifetime allocation behavior. Partial allocation failure inside
`buildIsupportTokens` is also a separate baseline concern. The accepted fix
covers normal returns and the missing-key candidate error path.

Exact stdout/stderr is retained, with evidence-local log whitespace attributes.
The original OpenBSD port acceptance records remain frozen and retain their
original source/artifact pins. No production deployment or push occurs here.

Native host: isolated OpenBSD 7.9 guest. The exact temporary fixture files
were removed, with no generated node key and no remaining fixture daemon.
See `isupport-exit-openbsd-cleanup.log`.

Fresh evidence review verified all six allocation record counts, the daemon
hashes, the status receipts and both native build results. The reviewer did
not independently execute the guest cleanup; its receipt records the executing
agent's checks. Graceful shutdown completed, with the owned QEMU absent and its
SSH port closed. Source formatting and diff checks passed.
