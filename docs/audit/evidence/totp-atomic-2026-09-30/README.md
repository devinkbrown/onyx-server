# TOTP storage atomicity evidence

Starting commit: `95f75e0303eaf3f425b94833d4a227b9392b9d27`.
Status: complete; final source frozen, independently reviewed, all gates pass. No deployment or
push. This evidence concerns local durable account policy and opaque SASL
`sst_` token authority, separately from reusable mesh sessions.

## Behavior

One prepared, checksummed WAL transaction changes the raw TOTP policy row and
removes the account's current-token binding. Allocation and admission failures
preserve the previous live/durable policy, pending secret and replay guard; the
same TOTP confirmation can be retried. Runtime promotion/removal follows sync
without allocation. Ambiguous I/O rejects new authentication until store reopen
resolves the complete transaction. Existing attached clients remain attached.

Token issuance/rotation and forced password reset use the same transaction
primitive. Reset includes account password, durable SCRAM material and token
authority. Its cache candidate is reserved before commit. Backfill copies and
publishes while holding the Services shared lock, serializing with reset and
retaining the borrowed salt's lifetime.

## Compatibility and limits

Existing raw secrets and T1 token rows retain their format. The batch adds a
mandatory WAL/snapshot format guard: older binaries must refuse a store after
batch use, including after compaction. Cold downgrade to those older binaries
is unsupported. New code accepts existing stores.

Pending enrollment and the runtime replay guard retain their existing
process-local lifecycle. Email RESETPASS still consumes its code before password
admission; a failed admission needs a new code. Its password/SCRAM/token
mutation is atomic, but the entire email-reset workflow is not claimed retryable.
In-process live tests use actual parsing, dispatch, proof verification, Services
and send queues; they are not a new network or mesh/Helix acceptance campaign.
The original OpenBSD port's separate native transport/mesh acceptance remains
at its original source and artifact pins.

## Frozen source

| File | SHA-256 |
| --- | --- |
| `store.zig` | `e509b52f39e3deddac5f5d480086be2132c148443bcb23569e68268c227aedd5` |
| `services.zig` | `29fb8a1220a2e370ba9dfa2e9e461e2dc23d7e0ae2db531c87810ea8f0fe7449` |
| `scram_store.zig` | `795ebb7fe4069e3be83dd45200bde680f198f8c11510dd10483c8b1db2ad0f91` |
| `totp_auth.zig` | `2053019b7411fca8ba2c8d78bc68536b37b1d77972e2b17e37e9a82fb46b61aa` |
| `server.zig` | `eb597455d267d8168dc6860e68336c18d1040f67d1024ee6bd031b36a679048c` |

## Fault and review receipts

STORE Debug and ReleaseSafe gates each pass **113/113**, 8/8 build steps.
Services Debug and ReleaseSafe each pass **77/77**. The store tests cover every
torn append prefix, complete-write sync ambiguity, exhaustive allocation
failure with retry, compaction, guarded malformed replay, read-only staging,
sequence/feed publication, duplicate keys and worst-case retirement.

Services tests cover 42 allocation failures with immediate retry and cold reopen,
21 injected I/O outcomes, admission limits, prepared SCRAM rollback and a
deterministically paused real backfill/reset ordering. Handler tests preserve
pending state across seven enable and five disable allocation failures, validate
real SASL token authority and cached SCRAM proof rejection, and check nine
forced-password admission failures.

Independent initial reviews found two HIGH defects. `store-outer-red.log`
preserves two failures before the guarded EOF fix. `services-review-initial.md`
describes the stale backfill publication and borrowed-salt lifetime race. Fresh
store, auth leaf and integration reviewers approve the frozen source in
`*-review-final.md`.

Native Debug initially failed at the first new handler fixture's stack probe;
after converting eight new fixtures, the broader group exposed two existing
TOTP fixtures with the same issue. Both RED receipts are retained. All ten
fixtures now allocate Server on the heap; final native runs use the normal stack
limit, with no stack-limit workaround or removed assertions.

## Native OpenBSD final gates

OpenBSD 7.9 GENERIC.MP#449 amd64, two CPUs, 2 GiB RAM, default **8192 KiB**
stack. Debug and ReleaseSafe each pass **170/171 module tests**, one skip and
zero failures. The skipped existing GAP-D5 same-image USR2 test is explicitly
Linux-only. All new storage/authentication regressions execute. Daemon import
wrapper has zero tests; CLI wrapper passes 2/2. All three runner exits are zero.

Commands (same flags for both modes; add `-Doptimize=ReleaseSafe` for the latter):

```sh
zig build test-artifacts -Dtarget=x86_64-openbsd -Dtest-filter=STORE -Dtest-filter=TOTP -Dtest-filter=SCRAM --prefix .zig-cache/codex-resume/totp-atomic/native-debug --summary all
zig build check -Dtarget=x86_64-openbsd --summary all
```

Both artifact builds pass 8/8 steps; cross-target check passes 3/3. Each runner
was copied to and actually executed in the owned native guest fixture. Host
and guest hashes match. Execution receipts contain stack limit, kernel, hash,
counts and exit status; individual module logs retain every test result.

| Module artifact | SHA-256 |
| --- | --- |
| Debug | `ef941ba6fec1663b3c3e3b72e44a0ac267dfb63cd01edb4d3ad14d7714f94ce7` |
| ReleaseSafe | `69d18d6941f0fe5ea4ab713510717a59144449fea05131159165acf166653694` |

`native-*-artifacts.sha256` also pins daemon/CLI wrappers. The exact owned guest
fixture was removed and its QEMU guest shut down. Port 2225 is closed and the
pre-existing guest on port 2223 remains present; see `native-cleanup.log`.

## Linux broad gates

The named ReleaseSafe gate `zig build test-server test-services
-Doptimize=ReleaseSafe --summary all` passes 1032/1036 tests, four skips and
zero failures, 7/7 steps. Final Linux compile check passes 3/3.

The first named Debug execution passes Services 564/564 but fails the existing
`UPGRADE resume arena re-dials a carried mesh peer` readiness assertion. Its
failed receipt is retained. The integrator reproduced the test four times on
final source and three times on clean baseline `95f75e03`; all pass 72/72
(including import wrappers). The test and relevant redial/adopt functions are
byte-identical to baseline. Its 120 immediate LINKS replies can exhaust the
probe count before handshake scheduling, because receipt of 365 does not impose
a wait. No code or assertion was weakened. The full server Debug retry passes 468/472, four skips and zero failures,
4/4 steps. Together with Services Debug 564/564, all 1036 named Debug tests
are accounted for. The original failure remains recorded; focused runs alone
were not used to replace the broad gate.

Full Linux ReleaseSafe (`zig build test -Doptimize=ReleaseSafe --summary all`)
passes **8794/8818**, 24 skips, zero failures, 8/8 steps. The module runner
passes 8741/8765; the separate 53-test runner passes 53/53.

Full Linux Debug (`zig build test --summary all`) also passes **8794/8818**,
24 skips, zero failures, 8/8 steps, including module 8741/8765 and separate
53/53. All broad gates used the source hashes above. `zig fmt --check src/`,
`git diff --check` and both native/Linux compile checks pass. `SHA256SUMS`
pins every evidence file; `source.sha256` verifies the source from repo root.
Committed logs normalize trailing whitespace and final blank lines only; raw
execution logs remain in the ignored local gate directory.

| Final gate | Result |
| --- | --- |
| Linux full Debug | 8794 passed, 24 skipped, 0 failed; 8/8 steps |
| Linux full ReleaseSafe | 8794 passed, 24 skipped, 0 failed; 8/8 steps |
| Linux named Debug | Services 564/564; server retry 468/472, 4 skipped |
| Linux named ReleaseSafe | 1032/1036, 4 skipped; 7/7 steps |
| OpenBSD selected Debug | 170/171, 1 Linux-only skip; exits 0 |
| OpenBSD selected ReleaseSafe | 170/171, 1 Linux-only skip; exits 0 |
| Linux/OpenBSD compile checks | 3/3 each |

No production service changes, deployment or push. Unrelated saved roadmap
file is preserved. This closes the local authentication storage-fault slice;
it does not claim completion of other roadmap gaps.
