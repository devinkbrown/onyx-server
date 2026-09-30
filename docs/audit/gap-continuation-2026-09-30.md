<!-- SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com> -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Gap continuation evidence — 2026-09-30

Local continuation from `15e09029` and the unfinished portable benchmark.
No production deployment, service change, or push was performed. This is verification of
the local source changes, not acceptance of every item in the gap roadmap.

## Changes and bounds

- Follow-up to `67eceb46`: free completed ISUPPORT token strings when any
  subsequent construction allocation fails. The previously published override
  remains unchanged, borrowed static tokens retain their pointers, and retry
  produces identical token bytes. Actual Linux/OpenBSD Debug/ReleaseSafe
  focused runners pass 75/75, with 308 injected failures and retries per run
  and live socket registration after retry. See
  [the allocation-failure evidence](evidence/isupport-oom-2026-09-30/README.md).

- Follow-up to full-port commit `e83b2939`: free boot-created ISUPPORT tokens
  on normal main returns after server teardown, clearing the borrowed global
  override first. The same missing-key refusal has 16 allocation records /
  694 bytes in Linux and OpenBSD Debug baselines, and zero in all four
  patched Debug/ReleaseSafe executions. Explicit process-exit calls still bypass defers. See
  [the follow-up evidence](evidence/isupport-exit-2026-09-30/README.md).

- GAP-K10: early data requires a server clock plus sealed issue time, age-add,
  and lifetime proof. Refusal does not consume a replay slot; eligible 1-RTT
  fallback completes and exchanges encrypted application data. The same
  ClientHello can be accepted after restoring the missing clock proof.
- GAP-D1/Helix: an identical canonical durable history image is an
  allocation-free, store-write-free no-op. Divergent images retain existing
  repair and compaction. Ordinary interleaved appends may have noncanonical
  ordering and still require reconciliation. The full OpenBSD port now performs
  that fallible synchronization at the predecessor seal boundary before
  checkpoint encoding; successor storage remains read-only before COMMIT.
- Restored full-gate fixtures: completion callback visibility, current
  handler-scoped GAP-P11 line witnesses, and IP SANs in the OCSP trust tests.
- GAP-X1/X4: corrected OpenBSD's six-component process RSS query and made failed
  measured cells return failure. A normal OpenBSD 7.9 guest passes native
  backend tests and the real daemon benchmark. See
  [the benchmark audit](bench-gap-x4.md).
- Initial portable runtime: suppressed SIGPIPE, set accepted descriptors nonblocking
  and close-on-exec, repaired poll/cancellation and registration ownership, and
  made queue-full/dual-poll allocation failure leave registrations unchanged.
  Connections and empty channels retire after completion processing; QUIT,
  nick collisions/reuse, client/channel limits, and slow-reader disconnection
  have regression coverage. Unsupported transport, metrics, and PROXY settings
  are refused by both preflight and boot. TLS, mesh, account services, and other
  Linux-only features were outside that initial slice. The subsequent full
  OpenBSD implementation uses the shared complete daemon; its current native
  acceptance is recorded in [the port record](../dev/openbsd-full-port.md).

Independent read-only review found no blocking defect in the modified TLS,
history comparison, benchmark, or OCSP fixture paths. Subsequent full-port
review approved predecessor history synchronization, strict candidate custody,
checked clocks, current-account token binding, and native probe cleanup.

## Verification

Compiler: Zig `0.17.0-dev.1282+c0f9b51d8`.
Logs are local build artifacts under `.zig-cache/codex-resume/`.

| Gate | Debug | ReleaseSafe |
|---|---:|---:|
| Focused early-data/PSK/K17/K18 | 88 passed | 88 passed |
| `zig build test-tls` | 817 passed, 1 skipped | 817 passed, 1 skipped |
| `zig build test-exploit` | 158 passed | 158 passed |
| Combined DPROP1/GAP-D1/GAP-P11 | 116 passed | 116 passed |
| History snapshot regression | 71 passed | 71 passed |
| OCSP tests | 72 passed | 72 passed |
| PortableServer lifecycle | 74 passed | 74 passed |
| Portable config guard | 72 passed | 72 passed |
| Linux-host kqueue checks | 77 passed, 5 skipped | 77 passed, 5 skipped |
| Native OpenBSD kqueue | 77 passed | 77 passed |

Native FreeBSD kqueue also passes 77/77 in Debug, and the patched daemon's
two plaintext benchmark cells pass on FreeBSD under Capsicum. The OpenBSD direct RSS ABI
test passes 1/1. The patched OpenBSD daemon passes actual chat, nick collision
and reuse, 64 unique JOIN/QUIT cycles, and persistent PING. Nine unsupported
configuration cases are refused in both CLI preflight and boot. Durable raw
logs are under [evidence/openbsd-2026-09-30/](evidence/openbsd-2026-09-30/benchmark.log).

All completed rows have zero failures and exit status 0. Focused counts include
the harness's supporting tests. Combined server gate:

```sh
zig build test-mod-verbose -Dtest-filter=DPROP1 -Dtest-filter=GAP-D1 -Dtest-filter=GAP-P11 --summary all
zig build test-mod-verbose -Doptimize=ReleaseSafe -Dtest-filter=DPROP1 -Dtest-filter=GAP-D1 -Dtest-filter=GAP-P11 --summary all
```

`zig build check --summary all`, touched-source `zig fmt --check`, and
`git diff --check` pass. Full `zig build test --summary all` after the original
repairs completed with **8,728 passed, 8 skipped, 1 failed out of 8,737**. The
remaining failure is intermittent missing delivery in the three-node reusable
session test. A repeated focused run isolated it to the resumed far-edge
attachment's second channel event after reconnect; the ACK barrier and its
first event had succeeded. The test also passes under scheduling perturbation. This is
not a green release gate. The subsequent full ReleaseSafe run passed
**8,734 of 8,745 tests, with 11 skips and zero failures** (8/8 build steps).
Repeated focused runs nevertheless reproduced the intermittent session failure:
the test's 1-second Mooring stall threshold expires before its 30-second
anti-entropy cadence. Captured dial state shows five failures, an open breaker,
and no A–B link; the current event is retained on B awaiting A. The fixture now
uses the existing production 60-second threshold. A simulated pre-cadence
assertion failed with the old threshold and passes with the repair, while the
aged-link breaker assertions still pass. Focused Debug and ReleaseSafe gates
pass 73/73; repeated three-node runs pass 50/50 with unchanged delivery deadlines
and assertions. The fixture also uses in-place heap construction to pass at an
8 MiB default stack. Independent review approved these changes. A later full Debug run compiled before the final QUIT fix
was deliberately stopped (exit 143) and is not acceptance evidence.

The earlier full run failed with six tests: stale OCSP/IP fixture, identical
history adoption writes, stale P11 line numbers, and three early-data fixtures
or policy assertions. Its result was 8,722 passed, 8 skipped, 6 failed out of
8,736. It is failure evidence, not a release gate.

The user subsequently requested the complete OpenBSD port. Its shared runtime,
native lifecycle work, ownership and acceptance matrix are tracked in
[the full-port plan](../dev/openbsd-full-port.md). Earlier native plaintext
results do not establish full runtime acceptance.

## Final full-port gates

Consolidated Linux Debug and ReleaseSafe each pass **8761/8785 tests,
24 skipped, zero failures**, with 8/8 build steps. The reproduced WHISPER
receive-fixture race is repaired; 200 consecutive ReleaseSafe repetitions also
pass. Final native Debug and ReleaseSafe each pass 8584/8732 module tests,
148 skipped, zero failed; CLI 51/53 with two skips and daemon zero tests. Native OpenBSD Debug and ReleaseSafe
each pass actual three-host secured session partition/rejoin, all three Helix
upgrades, fifth far resume, 51 accepted events / 243 bounded exact deliveries,
and cold WAL password plus opaque-token authentication. Final ReleaseSafe also
retains 40 mixed IPv4/IPv6 plain/TLS 1.2/TLS 1.3/WSS sockets after a rejected
candidate and two successful upgrades. See [the port record](../dev/openbsd-full-port.md)
for artifacts, native unit coverage and remaining shared mesh limitations.

## Next bounded gap

GAP-P16 read markers remain local-store state. A second attachment reading the
same store does not prove migration between distinct nodes. Authenticated
account-scoped relay and monotonic convergence after partition heal need their
own implementation and multi-node evidence. Live account-directory acceptance
and MESSAGE_V2 authoring activation are also unverified by this continuation.
