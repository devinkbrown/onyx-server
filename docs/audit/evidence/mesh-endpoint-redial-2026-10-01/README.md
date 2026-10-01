# Shared-IP mesh lifecycle acceptance record

Status: final-source focused, full Linux, named and native acceptance complete.
Baseline: `d9991c00040a3c2623fb5fcf858f6e5127c62915`.
Final server candidate: `63bf1cb095faf88d1fb7dd575d273a340d393e81dfd1a5fe51bc4d0d40ef1aff`.
Exact source pins: `owner-final-source-pins.sha256`.
No deployment or push. The unrelated roadmap `.save` is preserved.

## Repair and reviewed source

Configured endpoint suppression requires a proven canonical destination, including
port and scope. Unknown inbound IP/name cannot supply that evidence. Reciprocal
collapse transfers the binding only between authenticated identical full secured
keys (plaintext compatibility uses peer identity), without changing initiator
or armed CONNECT storage. Helix validates carried endpoint size/family/port before
mutation and publishes bindings only after complete adoption commit. No schema change.

Collision retirement immediately revokes mesh admission and connection-backed
authority, while a five-second bounded drain retains the final handshake flight.
SEND completion, retained suffix, backlog and kernel custody determine retirement;
merely queuing SEND is insufficient. Pressure retries, faults, expiry and exact
receive-generation checks remain explicit. Helix refuses an incomplete drain.

The shared ConnState policy governs routing, roster reads, derived active views,
maintenance and replay/burst selection. Every application frame-family drain checks
the exact physical owner before consuming; drivers revalidate after each family.
Retirement during deferred MESSAGE_V2 admission cannot publish later MODE changes
or encode SEARCH replies. Dial-success credit and SQUIT selection use active peers.
Raw collision identity, final-flight custody, genuine netsplit cleanup, checkpoint
refusal and independently accepted signed stores retain their separate requirements.
`lifecycle-consumer-inventory.md` classifies 286 functions and their caller paths;
the count itself does not establish correctness. The existing protocol-established
transport gauge retains its original semantics; INFO/LINKS/topology use eligibility.

Fresh CLI reviews invoked with `--model gpt-6-astra`:
`final-astra-stage-frozen-review.txt` found no blocker at immutable production `0323`;
`final-astra-owner-fixtures-review.txt` independently reversed the final six test
sections to reproduce every byte of `0323` and approved the correction without weakened
assertions. All three source hashes matched at each review's start and end.
The latter reviewer cannot independently introspect its backend model identity;
the launcher explicitly requested gpt-6-astra. These are static source reviews,
not runtime grades. Claude OAuth was unavailable; no Claude pass is claimed.

The six replay fixtures now borrow their actual established link, declare a captured
SendQ instead of fabricating SEND ownership, and assert active ownership. Pressure
preflight also asserts no AEAD counter advance. Signed membership tests traverse
secured admission; residence verification is an explicit unit-test stub. Historical
foreign-home projection is labeled separately and does not bypass direct-origin rules.

## Gates

| Gate | Result |
|---|---|
| Final combined focused Debug | 145/145 pass |
| Final combined focused ReleaseSafe | 145/145 pass |
| Final check, formatting and diff | Pass |
| Unfiltered test artifact compile | Final Debug and ReleaseSafe passed as part of full gates |
| Full Linux Debug / ReleaseSafe | Each 8845/8869, 24 skipped, 8/8 steps, exit 0 |
| Named server/services/Helix/mesh Debug / ReleaseSafe | Each 2354/2365, 11 skipped, 13/13 steps; both commands exit 0 |
| Native OpenBSD Debug / ReleaseSafe module | Final each 108/109, one existing Linux-only arena skip, zero failures |
| Native selected daemon / CLI | Each 0 selected daemon tests; 2 CLI imports pass; empty selection is not daemon coverage |
| Actual native Debug and ReleaseSafe campaigns | Final artifacts accepted: each 47 events / 225 exact deliveries, all 3 execs, unchanged dials, sockets/tokens and cold auth |
| Second scratch VM cleanup | Pass: owned dirs/PIDs removed, port 2225 closed, two pre-existing VMs reachable; image retained |

The native campaign runs separate two-reactor processes on one existing loopback
IP with distinct ports and reciprocal dials. Appended logs provide cumulative dial
counts: settled 22-second baseline, unchanged after each exec, unchanged for another
22 seconds afterward. All original physical clients remain attached with stable
local tokens and equal msgid/time, followed by reusable fifth attachment and durable
cold password/token authentication. Final artifact hashes are:
Debug `17f174a9c40038a0c795f960b582476828fcc78e7553ac2df3b2aed30695f9a1`;
ReleaseSafe `f982f91c8f97e2a24ccc8aba5ab4511ad6e36c0b2190d2ae9fe4d0612f22a364`.
The final Debug artifact passed its fresh campaign. Final ReleaseSafe rebuild
succeeds and is byte-identical to the preceding accepted campaign artifact;
this is exact artifact reuse, not a second distinct campaign. Final artifacts
and runners are pinned in `owner-final-artifacts.json`.

`--same-ip-reciprocal` requires `--skip-partition`: alias PF rules cannot isolate
shared-address peers. Native socket tests separately prove close/reheal. Linux
in-process Helix, native TCP socket cases and native real fork/exec are distinct
scopes. Normal native stack is 8192 KiB. The skipped arena case is not native proof.

## Preserved causal failures and superseded evidence

- Original inbound-IP predicate suppresses a missing configured endpoint.
- Native delivery originally survived while reciprocal dials churned continuously.
- Collision teardown truncated plaintext HELLO and armed secured ciphertext.
- Immediate receive drive originally returned true after exact-generation retirement.
- Seven loser-first outbound routing cases originally admitted a draining duplicate.
- Ten corrected roster/projection cases fail under original selectors: signed
  MESSAGE_V2 is permanent, E2EEGROUP rejected, stale authority/views win. Early
  missing-neighbor-root and count-oracle setup failures are not causal admission proof.
- INFO counted retiring links; plaintext expiration/pending transitions removed
  live local membership. Active controls preserve legitimate maintenance behavior.
- A real full 256-entry signed deferred batch followed by MESSAGE_V2/MODE/SEARCH
  retired the connection yet changed world MODE flags and advanced SEARCH send
  counter 7 to 8. Two selector cases also credited/select the loser. Setup/compiler
  receipts before these preconditions succeeded are not causal proof.
- Broad replay preflight expected cursor 8 / found 0 because six fixtures omitted the
  link ownership association. Exact baseline focused 71/77 has all six failures;
  corrected 84/84 preserves preflight/OOM/budget/cursor/record-content assertions.

`stage-broad-interruption.txt` records the superseded `0323` broad groups: exit143,
no terminal pass counts, no named ReleaseSafe run. Earlier memo-source full Debug
and ReleaseSafe each passed 8826/8850 with 24skips; those are predecessor evidence.
Earlier native/review pins remain historical; they do not supersede the final gates.
One earlier baseline-identical reusable-session fixture produced a timestamp
mismatch; targeted Debug/ReleaseSafe repeated72/72 and later runs passed. Its cause
remains unproven; exact timestamp assertions were never relaxed.

The source-hash discrepancy is recorded in `lifecycle-source-drift-receipt.md`:
restoring only two known owned deltas reproduced3f59 byte-for-byte. No writer is
attributed without evidence; superseded builds/review do not count as acceptance.
`native-cleanup.log` concerns the first scratch-VM epoch only. `native-owner-final-cleanup.log` verifies the second VM and exact private
fixture children were removed, owned port closed and both other VMs remained reachable.
Private configs, tokens, passwords, WALs and raw protocol transcripts are not archived.

## Remaining scope

Far-only ordinary unbound nickname/WHOIS/direct-message routing remains open in
an A-B-C line. Shared reusable-session evidence does not establish that route.
This slice does not close all roadmap gaps. No production release was performed.
