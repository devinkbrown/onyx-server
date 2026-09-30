<!-- SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com> -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# ISUPPORT partial-allocation cleanup

Follow-up to `67eceb46`. The token builder previously freed only its vector on
an allocation error; completed dynamic token strings leaked. Every vector slot
now starts as a borrowed immutable static token. The complete token destructor
can therefore free every owned string and the vector on any subsequent error
without reading an uninitialized slot or freeing static storage. Successful
values and token ordering are unchanged; the builder still never publishes a
global override itself.

## Regression evidence

The test-first Linux Debug record `isupport-oom-before-debug.log` reports 73/75
passed, two failed and 18 leaked allocations. The failures cover an early
completed dynamic token and the final optional-token failure. The baseline
production builder is from `67eceb46`; the runner adds the new regression tests.
Its binary hash is retained in `isupport-oom-before-debug-hash.log`.

Final filtered module runners pass **75/75** in Linux and native OpenBSD Debug
and ReleaseSafe, with no skips, failures or leaks. These runners contain four
named builder tests and namespace/import test entries. The new sweep covers all
eight NETWORKICON/VAPID/ACCOUNTRESIDENCE combinations. Each run forces remap
fallback to make allocation indices deterministic, then checks **308 induced
allocation failures, 308 same-allocator successful retries and eight final
successes**. It verifies allocation/byte conservation, borrowed static pointer
identity, unchanged previously published override and byte-identical retry
output. Existing tests cover configured length tokens and optional icon output.

The second new test fails the final optional entry, retries, then registers a
real loopback socket and receives complete `005` tokens including network, icon,
VAPID, residence and mode prefixes. Its first native Debug run exposed a
by-value Server stack overflow after the sweep had passed. That test fixture now
uses heap allocation and `initInPlace`, matching the daemon. The raw stack
failure and exit 139 receipt remain in `isupport-oom-native-before-heap-debug-*`.
Final native runs use the default stack limit and both exit 0.

| Final focused gate | Raw record |
|---|---|
| Linux Debug, 75/75 | `isupport-oom-focused-debug.log` |
| Linux ReleaseSafe, 75/75 | `isupport-oom-focused-rs.log` |
| Native OpenBSD Debug, 75/75 | `isupport-oom-native-debug-raw.log` |
| Native OpenBSD ReleaseSafe, 75/75 | `isupport-oom-native-rs-raw.log` |
| Native build, Debug and ReleaseSafe, 8/8 steps each | `isupport-oom-native-debug-build.log`, `isupport-oom-native-rs-build.log` |
| Whole daemon Linux check, 3/3 steps | `isupport-oom-check.log` |
| Whole daemon OpenBSD check, 3/3 steps | `isupport-oom-openbsd-check.log` |
| Selected server/services Debug and ReleaseSafe, 1017/1021 passed, four skipped, zero failures; 7/7 build steps each | `isupport-oom-named-debug.log`, `isupport-oom-named-rs.log` |
| Full Linux Debug and ReleaseSafe, 8763/8787 passed, 24 skipped, zero failures; 8/8 build steps each | `isupport-oom-full-debug.log`, `isupport-oom-full-rs.log` |

## Source and execution scope

Compiler: Zig `0.17.0-dev.1282+c0f9b51d8`. Native guest: OpenBSD 7.9.
Pre-fix production `src/daemon/server.zig` SHA-256:
`063206384e104ae256b0816c1d807c9918bff348539f4941770dc261a9d97849`.
Final source including regressions:
`b9dabd1970c0f3155c4ce814ae774129e4b717d23152095b0bbbc80f9da169db`.

Final native module-runner SHA-256:

- Debug: `a7ceec3b7dd593c52840816cc20dc1c6cd1495c37d4c6b4c002cfade64cc2fa2`.
- ReleaseSafe: `32d594e1891c895cbe9aceb8631cc0ca2cd4c3011ce2c8243be524496ac7b33a`.

Commands: `zig build test-mod -Dtest-filter=buildIsupportTokens --summary all`,
then repeat with `-Doptimize=ReleaseSafe`. Build native runners using
`zig build test-artifacts -Dtarget=x86_64-openbsd` with the same filter/mode,
then execute the module runner inside the isolated guest. Native exit status
and received binary hashes are retained in `isupport-oom-native-*-receipt.log`.
The native fixture and core dump were removed, no test/daemon process remained,
and the owned VM shut down gracefully. The cleanup log contains the pre-removal
file list and post-removal checks; the fixture SSH port is closed.

Fresh read-only `/root/review_isupport_oom` verdict: **Approve** the final source.
The reviewer checked initialized ownership, destructor coverage, unchanged
success-path values/order, publication after success and heap-fixture defer
ordering. No production code besides the builder cleanup changed. The reviewer
inspected focused evidence and did not claim independent VM execution.

The original full OpenBSD mesh/transport campaign remains pinned to its original
port artifacts. This follow-up verifies constructor failure/retry and live native
registration; it does not claim a repeated full native campaign. Explicit
process-exit calls still bypass normal-return defers. No deployment or push.

Some raw Zig logs include a `failed command` annotation before their final
successful summary. Gate results here use the final build/test counts and
recorded process exit status.

Both full Linux `zig build test --summary all` runs (Debug and ReleaseSafe)
completed with exit 0: 8710 module passes plus 53 CLI passes, 24 platform skips,
zero failures. Two added regressions account for the increase from 8761/8785
to 8763/8787. Build-time revision is `67eceb46-dirty`; the source hash above
identifies the final tested implementation and fixtures.
