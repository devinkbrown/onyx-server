<!-- SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com> -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Final native fixture review

Independent read-only reviewer: `review_portable_bench`. Reviewed the frozen
OCG1 writer, native listener readiness test, expanded shared-server fixture
guards, CONNECT accept oracle, and configured boot-dial cursor fixture.

No blocking source finding remained after the following corrections:

- Native CONNECT retries only transient accept errors within five seconds and
  fails if the accepted operator command never establishes its connection.
- Native boot-dial cursor coverage reads kqueue queued changes; Linux retains
  its submission-queue check. All three cursor advances, remaining boot counts,
  attempted peers and absence of queued operations remain asserted.
- Native reuseport coverage bounds readiness retries and still requires both
  actual IPv4 and IPv6 connections. Debug and ReleaseSafe each passed 200 runs.
- Native OCG1 uses target-native open/write/close. Configured grant and webhook
  parent directories are present in the filesystem confinement plan.
- Both RESYNC resume tests use a shared fixture that previously called raw
  Linux socketpair. Its native branch preserves descriptor ownership and keeps
  both behavioral tests enabled. The reviewer traced all 346 expanded negative
  guards through shared helpers and found no additional call into the legacy
  Linux-only upgrade/arena helpers. The final ownership flag also closes the
  socket on allocation or adoption failure and detaches the borrowed mesh link
  before error teardown; the reviewer approved that custody correction.
- The pure-memory local-client helper now runs on OpenBSD. Native kqueue
  rejects its synthetic descriptor immediately, whereas Linux queued that
  invalid descriptor until a later completion. An explicit per-connection test
  capture flag retains output for the deterministic SendQ assertions. Its
  storage and branch compile out of daemon builds; real and untagged invalid
  descriptors keep the native validation path. The helper does not introduce reactor-wide
  quiescence or fabricate send ownership.

The OCG1 fixture proves a complete TSV write, cold reload and non-authoritative
compatibility grants. It does not force short writes or EINTR; handling of
those branches is supported by source review. Existing best-effort persistence
can leave a partial file on I/O failure, as its prior Linux implementation can.

Full native runtime and unfiltered unit results are recorded separately; this
review receipt makes no execution claim.

The expanded unfiltered native run led to a further independent review on
server source SHA-256
`063206384e104ae256b0816c1d807c9918bff348539f4941770dc261a9d97849`:

- WHISPER waits for the exact command, target and payload. A pending JOIN
  deterministically satisfied the old generic prefix without reading the
  receipt; the same injected JOIN fails before and passes after the repair.
  Positive delivery, negative 401 and DATA assertions retain their budgets.
- Queue-pressure setup uses distinct native timer tokens, preserving kqueue's
  duplicate-operation rejection. Linux keeps its original timer setup.
- The separately allocated EXTERNAL claimant explicitly captures SendQ output.
  Its owner pointer is reacquired after client-table growth, removing a stale
  ArrayList element pointer identified by the fresh reviewer.
- The sibling-close lifecycle fixture explicitly stages the SEND ownership
  whose cancellation completion it injects. It proves close/custody logic;
  real kernel cancellation is covered by separate native transport tests.
- GAP-P11 embeds the compiled source for its handler witness, removing the
  absolute Linux checkout dependency while preserving handler-scoped checks.
- The HTTPS shutdown test retains its sub-second join and zero reader calls.
  A measured transient AGAIN is retried within a separate one-second EOF/reset
  deadline after the dribbler stops; any response byte remains a failure.
- Memo resolution no longer returns a stack slice. Direct decisions borrow the
  caller input, and forwarded decisions borrow normalized store targets. The
  sole production caller already follows those spelling/lifetime semantics;
  pointer identity, repeated calls, mutation and allocation-free resolution
  regressions cover the corrected ownership contract.

No static blocker remains in these changes. Actual final gates are listed in
the evidence ledger rather than inferred from this review.
