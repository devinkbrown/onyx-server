# Replay fixture ownership follow-up

Frozen server SHA-256: `63bf1cb095faf88d1fb7dd575d273a340d393e81dfd1a5fe51bc4d0d40ef1aff`.
Production predecessor: `0323be5cfb568173b41fb8fc343356947cb62f83ef74e4c2efc6c4e403b8aa49`.
Only six test sections changed. All production bytes through the complete
LinuxServer struct are identical to 0323. Reversing those six sections reproduces
the entire 0323 source byte for byte. See `replay-owner-delta-proof.txt`,
`replay-owner-test-delta.json`, `replay-owner-before-source.zig` and
`replay-owner-final-source.zig`.

No production policy was relaxed. No commit, push, deployment, VM action, leaf
source edit or unrelated rollback by this writer. Root owns final independent
review and broad/full/native acceptance.

## Cause and bounded correction

The reviewed production owner contract rejects standalone ConnState fixtures
whose secured link pointer was never assigned. The legacy preflight test thus
kept cursor zero instead of replaying eight frames. Five adjacent fixtures had
the same missing association. The causal Debug gate at unchanged 0323 fails all
six: `replay-owner-before-debug.log`, **71/77**, six failures.

Seven standalone connections across those six tests now borrow their actual
established `pair.a` and assert `ownsActiveMeshLink`. Their buffered sink declares
`test_sendq_capture` instead of pretending a kernel SEND is armed. The pair owns
the link; each fixture still cleans its SendQ allocation. Capabilities, SendQ
filler/cap, cursor paging, allocator failure, decoded frame identity, snapshot
equality and existing platform guards are preserved. The preflight case also
asserts the outer AEAD send counter remains unchanged while the SendQ is full.

Changed test names:

- `session replica replay skips attachment leases for rolling-old peers without pinning burst`
- `session replica value replay completes 140 objects under continuous behind-cursor renewal`
- `session replica replay preflights SendQ before AEAD advance and resumes at eight frames`
- `session replica replay leaves no inner residue after outer record allocation failure`
- `session replica replay budgets actual ciphertext with one-frame progress exception`
- `maximum legal session replica fits the clamped server-link SendQ and progresses`

`replay-owner-fixture-audit.txt` records the bounded adjacent direct-helper audit
of 20 test sections. Other inspected callers already use registered, adopted or
declared standalone owners. Genuine retirement-negative cases remain unchanged.
The production consumer inventory remains pinned to 0323; its application to
63bf rests on the exact production/reversal proof, not a new inventory scan.

## Verification

Causal Debug command:

```sh
zig build test-mod --summary all \
  -Dtest-filter='session replica replay' \
  -Dtest-filter='session replica value replay' \
  -Dtest-filter='maximum legal session replica'
```

`replay-owner-before-debug.log`: exit 1, **71/77**, six failures, compile 5s.
The same filters plus adjacent conflicted-lease, mid-flight RESYNC, establishment,
burst and live-fanout controls pass **84/84**, compile 5s/run 5s:
`replay-owner-after-debug.log`.

Final combined command:

```sh
zig build test-mod --summary all \
  -Dtest-filter='same-IP mesh dial' \
  -Dtest-filter='deliverRelay binds sender nick to home' \
  -Dtest-filter='MESSAGE_V2 unknown home retries' \
  -Dtest-filter='E2EEGROUP mesh live path accepts once' \
  -Dtest-filter='NAMES' \
  -Dtest-filter='GAP-P0c remote LISTX' \
  -Dtest-filter='four-client reusable session and MARKREAD survive sequential Helix' \
  -Dtest-filter='session replica replay' \
  -Dtest-filter='session replica value replay' \
  -Dtest-filter='maximum legal session replica' \
  -Dtest-filter='session replica conflicted lease' \
  -Dtest-filter='session replica mid-flight RESYNC' \
  -Dtest-filter='session replica gates establishment' \
  -Dtest-filter='session replica burst' \
  -Dtest-filter='session replica live fanout'
```

Debug: `replay-owner-frozen-focused-debug.log`, exit 0, **145/145**,
compile 9s/run 35s. ReleaseSafe uses the same command with
`-Doptimize=ReleaseSafe`: `replay-owner-frozen-focused-release-safe.log`,
exit 0, **145/145**, compile 6m/run 18s. Both completed at unchanged 63bf.

`zig build check --summary all`: `replay-owner-frozen-check.log`, exit 0,
compile 8s. `zig fmt --check src/daemon/server.zig` and `git diff --check`: exit 0.

Root's independent `final-astra-owner-fixtures-review.txt` reports no blocking finding and
independently confirms exact six-section reversal to 0323 and preserved
assertions. Final broad/full/native waves at 63bf are separate root-owned work;
predecessor production runtime receipts must retain their original pins.

All writer-owned source, focused Debug/ReleaseSafe, check, fmt, diff, bounded
fixture audit and cache handoff work is complete. Source remains frozen 63bf.
