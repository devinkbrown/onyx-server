# Shared mesh lifecycle boundary: final writer receipt

Final server SHA-256: `0323be5cfb568173b41fb8fc343356947cb62f83ef74e4c2efc6c4e403b8aa49`.
Only `src/daemon/server.zig` changed by this writer. No commit, push, deployment,
VM action, leaf change or unrelated rollback. Root owns final gates/review/docs.
Earlier b060/3f59 full/focused/native receipts are predecessor evidence only.

## Coherent invariant

`meshAdmissionOpen` denies closing/dedup admission. `isActiveMeshPeer` additionally
requires protocol establishment; `ownsActiveMeshLink` requires the exact link
pointer. Occupancy stays with the slot iterator. Active routing, home/account/
membership authority, public roster projections, INFO, peer publication and
maintenance use this one allocation-free policy.

Every live frame-family drain takes the physical owner and checks it before
consuming. Both drivers revalidate after every family, so retirement inside an
earlier stage cannot publish MODE, consume later authority or encode SEARCH.
Identity transition publication gates before taking a queued transition and
before legacy local-membership folding. Direct session replica ACK encoding has
the same owner contract. Raw protocol identity is separate from active peer
name: dial-success credit uses active identity; SQUIT chooses an active survivor
before its explicit admitted named-handshake cancellation fallback.

Handshake, final-owned-flight drain/cancel/close, exact endpoint collision
transfer, genuine netsplit cleanup and strict checkpoint refusal remain separate.
Accepted signed Store custody survives loss of a transport. Cached peer identity
publication remains staged/OOM atomic, and its consumers never select a retiring
physical connection. The existing stats protocol-established gauge remains until
final close; INFO/LINKS/topology are active views.

SEARCH/KEYTRANS live wrappers require the real owner. Their isolated standalone
peer test bridges are test-only and call explicitly named admitted payload
implementations. The generic deferred-session encoder capture test is also an
isolated sink; runtime callers enter through guarded physical-peer scans.
Existing MARKREAD receiver, ACK, replica and RESYNC fixtures now supply their
actual owning ConnState/link association; no production guard is bypassed.

## Causal tests

- Corrected ten-case roster RED at c9153dc5: 71/81, all ten fail. The signed fixture
  now feeds actual B-signed encrypted membership through secured admission under
  its explicitly bounded residence verifier. It verifies node/account/trust and
  membership before signed MESSAGE_V2/E2EE tests, reverses slot order, and labels
  the home-only direct C seed as historical negative projection, not admissible
  signed wire. INFO adds the eleventh roster case.
- Plaintext expiration and pending-transition RED: 71/73. Retained loser wrongly
  pruned/folded away local membership. Fixed tests preserve its queued transitions
  and exact held tail, while active controls still produce PART and visible NICK
  using a fresh witness channel. Wrong-owner and dedup-only late ingress also deny.
- Mid-turn causal RED at `43e494f1721651c18b49f186651dcc3c249182927315c5e4a352aa7afaa5bbc3`:
  `lifecycle-stage-before-debug-5.log`, 72/74. Actual 256 signed unknown-home
  records fill deferred custody in one receive while the peer remains active;
  another signed MESSAGE_V2 plus MODE/SEARCH share the next receive. Overflow
  closes it, yet old code changes MODE bits12->28 and advances SEARCH outer
  counter7->8. Active control publishes the exact MODE and decodes reply id41.
  Earlier fixture compile/retry-expiry precondition failures remain diagnostic
  receipts, and are not called causal RED.
- Expanded selector causal RED at `c7f4407a976221c992a4588c927847c49d542eddf35c1b9a170beb7e7d003637`:
  `lifecycle-stage-selectors-before-debug.log`, 72/76, four failures. Adds retained
  endpoint breaker-credit refusal with legitimate active endpoint control and
  loser-first SQUIT survivor selection. Existing SQUIT named-handshake tests pass.

Exact causal sources and SHA files are retained beside these logs. New tests
heap-allocate Server and secured link fixtures, permit Linux/OpenBSD, and do not
raise stack limits or add platform skips for either supported runtime.

## Exact final commands and results

```
zig build test-mod --summary all -Dtest-filter='same-IP mesh dial' -Dtest-filter='deliverRelay binds sender nick to home' -Dtest-filter='MESSAGE_V2 unknown home retries' -Dtest-filter='E2EEGROUP mesh live path accepts once' -Dtest-filter='NAMES' -Dtest-filter='GAP-P0c remote LISTX' -Dtest-filter='four-client reusable session and MARKREAD survive sequential Helix'
```
Debug: `lifecycle-stage-frozen-focused-debug.log`, exit0, **132/132**, compile7s,
run28s. ReleaseSafe is the same command with `-Doptimize=ReleaseSafe`:
`lifecycle-stage-frozen-focused-release-safe.log`, exit0, **132/132**, compile6m,
run15s. Both final focused modes completed at unchanged0323.

Additional exact-source Debug gate selecting mid-turn/selector/squit/MARKREAD/
RESYNC: `lifecycle-stage-after-debug-2.log`, **108/108**, compile11s/run24s.
`zig build check --summary all`: `lifecycle-stage-check.log`, exit0, compile9s.
`zig fmt --check src/daemon/server.zig` and `git diff --check`: exit0.
Root unfiltered Debug `zig build test-artifacts --summary all` completed exit0
at unchanged0323; this covers unselected module/daemon/CLI test-body compilation.

Independent immutable-source review: `final-astra-stage-frozen-review.txt`,
no blocking finding at identical start/end server0323, snapshotc1c6, Pythonc993.
Runtime acceptance is separate and root-owned; final broad/full/native waves
were launched only after this review. Writer does not grade those gates.

## Consumer inventory and provenance

`lifecycle-consumer-inventory.md` and `lifecycle-consumer-classified.json` classify
286 functions from the explicit search plus caller union, including all raw
identity callers, every application family, exact-pointer output helpers and
custody/handshake/cache/Store/test-only exceptions. No unclassified entry remains;
a count alone is not a completeness proof. The inventory is writer evidence,
separate from the independent review.

`lifecycle-source-drift-receipt.md` preserves the bounded 2984 vs3f59 rollback
observation and exact two-delta reconstruction. No writer was identified. Current
0323 includes the restored approved owner guard/test additions, and every final
source check and compile has remained at this pin. Do not infer broader source
mutation or erase the preserved predecessor.

Final bounded Server function delta index: `lifecycle-stage-production-functions.txt`
(37 changed/added methods versus causal c7f source; other Server method text
unchanged). All writer-owned focused/check/fmt/diff work is complete. Parent
broad/full/native runtime acceptance remains outstanding when this receipt closes.
