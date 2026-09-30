# GAP-P16 server integration receipt

- Owner: `/root/auth_integrator_finish`, sole writer of `src/daemon/server.zig`.
- Base: `114e1cd4fa365cdda65790530c4dbe0efa2a0575`.
- Frozen server SHA-256: `71221570d685a0c30a5d77ccfdc12094524d369f052fbf9bab119fafc62a1a3a`.
- Server diff: 1,153 inserted lines / 28 deleted lines. No leaf, documentation, commit, push, deployment, or VM changes by this writer.

## Live behavior

Authenticated MARKREAD SET stages the monotonic runtime position, owned immutable signed fact, per-key durable row, and independent signing-clock watermark before the WAL commit. The publication cut contains only no-fail runtime/fact/clock swaps. Authenticated SET replies and unsolicited updates reach every eligible physical account attachment once. Guests use a memory-only physical connection namespace and retire their entries on connection close; guest nick reuse cannot enter the account namespace.

The private `read.marker/` ENTITY_PROP namespace has dedicated verified-signature admission, timestamp-max merge, deterministic equal-position fact selection, canonical account/target/digest checks, and bounded future HLC validation. It bypasses generic property LWW and public PROP emission. Ordinary PROP set/delete/get/list/bulk deletion cannot read or alter marker facts. Only secured links with fresh negotiated marker capability can carry them.

The exact winning signed fact remains owned and durable after send. Establishment, capability negotiation edge, periodic repair, RESYNC, and post-Helix bursts replay that frontier without changing the origin signature. OOM or queue pressure preserves repair state. Cold restore stages and validates every durable fact and watermark before swapping markers/frontier/clock. Corrupt restore or ambiguous WAL write latches MARKREAD/JOIN marker/rewind unavailable until a successful cold restore.

Two existing threaded MARKREAD Server fixtures now use heap allocation/initInPlace. Assertions, skip handling, and default native stack limits are preserved.

## Acceptance coverage

- Real parsed MARKREAD SET/GET, account sibling fanout, physical guest isolation and retirement, ordinary PROP privacy.
- Opposed timestamp/HLC order; duplicate and stale facts; unsigned/forged/future facts.
- Local and remote admission allocation sweeps: 16 failures each, exact runtime/clock/WAL rollback and retry.
- Restore allocation sweep: 7 failures, complete frontier preservation and successful retry.
- Prepared write/short-write/sync faults: no runtime publication or sibling notice; cold reopen resolves a complete fact/position pair.
- Actual SecuredLink encryption/feed/drain under SendQ pressure and outer allocator failure, exact origin bytes and duplicate repair. The initial outer OOM regression exposed a root-owned adapter defect; root fixed reservation ordering, without relaxing the assertion.
- Actual socket A-B-C non-clique topology with distinct World/Services/OroStore, four same-token physical clients, parser/emitted reply checks, A-origin byte-identical signed frontier on B/C, remote author participation, private PROP checks, partition retained state and heal, fifth far-edge resume.
- Actual socket two-node sequential Helix upgrades preserve all four transports/tokens and MARKREAD GET/SET participation, followed by fifth opposite-edge resume.
- A test-only Linux/x86_64 ELF prints the exact frozen v4 reader token. The pinned reader gate rejects it with private queues/counters/fd flags/frontier unchanged. The public upgrade entry point's normal signed refusal audit transfers outer ciphertext to SendQ without altering private bytes; the secured receiver decodes the two original signed marker facts and one verified refusal audit. This distinguishes normal audit queueing from destructive handoff.

## Writer gates

1. `zig build test-mod -Dtest-filter='four-client reusable session and MARKREAD' --summary all`
   - Exit 0; 72/72 tests; selected live test plus 71 unconditional harness tests.
   - Compile 6s; run 6s. Source `441a7064aab7dc6a8a7a966cdf92246c3b1c373933ede333967ea4a4c09708a9`.
   - `integrator-live-helix-debug.log`.
2. `zig build test-mod -Dtest-filter='MARKREAD UPGRADE refuses a v4-only executable' --summary all`
   - Exit 0; 72/72 tests; selected executable refusal test plus 71 unconditional harness tests.
   - Compile 9s; run 185ms. Source `b06200df2e644f579dd062973e0d2e65e475e2543af957f9913bf9318ffd5689`, before the final test-only bouncer fixture update.
   - `integrator-refusal-debug.log`.
3. `zig fmt --check src/daemon/server.zig`, `git diff --check`: exit 0 on frozen source.
4. `zig build test-mod -Dtest-filter='bouncer rewind' --summary all`
   - Exit 0; 74/74 tests; three existing live history-policy cases plus 71 unconditional harness tests.
   - Compile 9s; run 292ms. Final frozen source. `integrator-bouncer-debug.log`.
   - The root broad gate's original RED is retained in `test-server-Debug.log` (465 passed, 4 skipped, 3 failed / 472). The three authenticated fixtures used a custom SASL verifier without account persistence. The shared fixture now supplies real temp OroStore/Services and heap Server; actual parsed MARKREAD SET and every rewind/history-policy assertion are unchanged. All marker preloads/call sites were audited; the two remaining helper calls deliberately use canonical `carol` account legacy/cold records, with no test nick preloads.
5. `zig build test-mod -Dtest-filter='bouncer rewind' -Doptimize=ReleaseSafe --summary all`
   - Exit 0; 74/74 tests; three existing live history-policy cases plus 71 unconditional harness tests. Final frozen source; `integrator-bouncer-release-safe.log`.

`integrator-refusal-model-red.log` preserves the initial modeling RED: copied ciphertext simultaneously occupied SendQ and outer, then the normal audit flush appended it. The corrected fixture gives each queue distinct consecutive records and verifies ownership by real secured decoding. There was no production defect in that refusal path.

`integrator-production-parity.txt` proves restoring only the baseline bouncer test fixture reconstructs exact `b06200df...` bytes, and additionally deleting only the new refusal test block restores exact earlier `441a7064...` bytes; no production delta followed that earlier source. Final combined MARKREAD Debug/ReleaseSafe, named/full Linux and native gates are owned by root and pending at this receipt. No writer self-review claim substitutes for the fresh reviewer.
