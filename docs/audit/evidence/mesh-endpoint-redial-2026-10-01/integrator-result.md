Current test-only follow-up: `replay-owner-final-receipt.md`; frozen server
`63bf1cb095faf88d1fb7dd575d273a340d393e81dfd1a5fe51bc4d0d40ef1aff`.
The six-test exact reversal reproduces 0323; all production bytes are unchanged.
Final combined focused Debug/ReleaseSafe both145/145; check/fmt/diff exit0.
Production lifecycle receipt/inventory remain pinned to `lifecycle-final-receipt.md`
at `0323be5cfb568173b41fb8fc343356947cb62f83ef74e4c2efc6c4e403b8aa49`.
Earlier sections below preserve qualified predecessor evidence and are superseded
by the shared policy/stage-owner repair for final acceptance.

# Endpoint binding and duplicate handshake drain integration receipt

Baseline: `d9991c00040a3c2623fb5fcf858f6e5127c62915`.
Writer owns `src/daemon/server.zig` only. Frozen server SHA-256:
`0323be5cfb568173b41fb8fc343356947cb62f83ef74e4c2efc6c4e403b8aa49`.
No commit, push, deployment, VM mutation, or leaf source edit by this writer.
Parent owns snapshot comments, native Python campaign, all broad/native gates,
fresh review and commit. Preserve unrelated roadmap `.save`.

## Confirmed causes and reviewed lifetime repair

The old meshPeerLinkedByDial treated any established inbound connection from a
configured IP as that configured listener. C on the same IP suppressed a missing
B endpoint, despite a distinct port. Names alone also did not prove endpoints.

Removing that inference exposed another existing ordering defect. Plaintext
responder establishment queued its HELLO reply, then resolved collision before
copying that reply to SendQ. Immediate close shut the socket before the outbound
peer could establish or transfer its configured target to its inbound keeper.
Secured flush copied ciphertext and armed SEND but immediate collision teardown
still shut the socket before SEND submission/completion. The native final daemon
and original plaintext reciprocal test reproduced sustained losing dial churn.
The prior build timing hypothesis was ruled out by the exact final daemon RED.

## Production contract

The existing MeshDial token follows the duplicate survivor. The explicit known
flag guards every inline target address read. Outbound dial proves its complete
endpoint; reciprocal transfer/collapse requires equal full secured public keys,
never a name or IP. Mixed secured/plain and distinct keys cannot collapse or
transfer even with equal peer names. Plain compatibility requires equal node IDs.
Unknown inbound links supply no endpoint evidence. Matching checks family,
address, port and scope. CONNECT-owned address storage is never overwritten;
initiator direction remains unchanged.

Helix seals known targets in either direction. Malformed nonempty size/family or
zero-port input is rejected before allocation or FD mutation. Staged adopt does
not mutate dials; publishInheritedS2sLink reconstructs them only after the whole
adoption commit. Linux/native share these seal/publication paths.

A healthy collision loser now closes admission/routing immediately but retains
its final link output and SendQ until SEND completion. The collision-specific
5-second deadline bounds a blocked loser. Timer/SEND/close maintenance retries
retained suffixes; racing RECV/cancel cannot force early shutdown. Actual SEND
errors and delivery byte gaps keep immediate fault retirement. Every retirement
uses the existing exact kernel ownership protocol. Helix refuses an incomplete
drain rather than restoring this process-local latch as an ordinary route.
No new wire or capsule schema.

Fresh independent review found that synchronous drain finalization could retire
the active receive slot before driveClientBytes returned true. The driver now
returns whether the original full client generation still exists; handleRecv
and the proxy caller stop before touching the retired pointer. A causal RED
checks this boolean after a genuine zero-output collision. The test also drives
a real receive completion, reuses the slot and rejects its stale old token.

## Fifteen new tests, filter `same-IP mesh dial`

1. Unknown inbound C cannot claim configured B.
2. Equal names/different full keys cannot collapse or transfer; equal keys carry
   exact port onto an inbound survivor, retaining responder direction.
3. Malformed carried endpoint refuses before slot/dial/FD mutation.
4. Real secured three-node one-IP/distinct-port sockets: separate World,
   Services and OroStore; no B-C direct edge; A retains unrelated C while A-B is
   cut; only A can dial recovery; actual channel echo/msgid/time for all authors
   and two-hop traffic; reciprocal probe converges without subsequent collapse.
5. Actual plaintext driver, responder loser: final HELLO reaches a real peer,
   which establishes before ordinary slot teardown.
6. Secured responder loser: exact armed ciphertext reaches a real socket peer;
   full SendQ retains a second complete record byte-identically and retries after
   the first SEND completion. Linux also delivers a real positive RECV CQE while
   SEND is armed but unsubmitted, without truncating either queued record.
7. Blocked drain expiry retires its slot; partial Helix sealing refuses without
   pieces or carried FD publication and preserves the queued tail.

8. Zero-output initiator retirement propagates the absent exact generation to
   its receive caller. A real RECV CQE, slot reuse and stale-generation rejection
   accompany the direct driver-result oracle. A previously committed burst and
   normally collapsed repeated LINK audit keep this edge non-vacuous.

All fifteen are heap based and execute on Linux/OpenBSD. The plaintext/secured wire tests drive bounded submit/reap/poll loops: native
SEND occurs during completion processing, and an earlier control CQE cannot
leave a blocking EOF read hung. Exact byte and EOF assertions remain.

The three-node fixture's
in-process sequential A/B whole-adopt subsection is Linux-only because its arena
capture seam uses Linux memfd. Native partition/collision executes without skip;
actual native fork/exec preservation belongs to the parent Python campaign.

9-15. A retained, full-SendQ collision loser precedes its live authenticated
same-key survivor in the real client slab. MESSAGE_V2 replay, ACK, ACK_CONFIRM,
E2EEGROUP ACK, ACK_CONFIRM, Event Spine and legacy message fanout must leave the
loser's record counter, empty link buffer and exact held tail unchanged. The
survivor's encrypted SendQ is decoded by its actual secured counterpart and
contains exactly one matching origin wire, receipt or event. These are buffered
SecuredLink routing tests, distinct from the real socket tests above.

## Reviewed routing finding and bounded correction

Independent final review found that closing/dedup losers remained selectable
while their final handshake drained. Ordinary flush returned success for empty
link output before checking the exact connection, allowing new ciphertext to be
appended and then rejected without trying the survivor. Seven causal REDs show
this at `routing-before-debug.log`: 71/78 pass, all seven new cases fail. Exact
pre-guard server hash `3e932ff7f880c5b60ee1cb39e4d7e58cf4aeabfd59a1860dbe51dc91b2553fc5`
is recorded in `routing-before-source.sha256`; `routing-before-server.zig` keeps
the full test-first source. `routing-fixture-compile.log` preserves the initial
missing legacy identity fixture error.

Outbound selection/burst/replica paths now exclude closing/dedup connections
before selecting or encoding; TOFU availability/readiness uses live connections
while configured offline custody remains retained. Exact connection generation
and SecuredLink association are validated even with empty output in the ordinary
flush helper. The direct collision drain continues using its own retained-output
flush edge. Lifecycle seal/adopt, immediate-fault teardown and drain ownership are
unchanged. `routing-production-guards.txt` lists the 46 narrowly guarded
functions. The final extra guard is the mesh-search secured iterator; this is the
only difference between the preliminary 25511580 GREEN and final a08b freeze.

## Existing fixture changes

Collision fixtures now use the same full authenticated peer key on both legs;
assertions remain. CONNECT retry/inherited outbound fixtures initialize known.
The existing reciprocal sweep assertions remain exact; failure-only diagnostics
print endpoint provenance, bound token, ownership flags and full-peer equality.

LiveUpgradeTestNode successors use heap allocation. Its arena duplication uses
os_runtime.duplicate, retaining original arena custody on failure. After capture
and joined predecessor, only stopped CLOEXEC S2S listeners close, allowing the
successor to bind the same configured endpoint while preserving client/peer FDs.
The old four-client MARKREAD sequential test passed 80/80 in the earlier gate.

## Preserved causal and diagnostic receipts

All paths below are relative to `.zig-cache/codex-resume/mesh-endpoint-redial/`.

- `unit-before-debug.log`: old endpoint predicate RED 71/72; source
  `f59507ea0b1cc30010569d5b0f78d06b320a422a1ffed0e19da4039ae05ebac6`.
- Parent `selected-debug-endpoint-candidate.log` and/or `selected-debug.log`:
  original plaintext reciprocal assertion expected 1 collapse, observed 8.
- Parent `native-exec-debug-final-source.log`: exact pre-drain daemon RED under
  unchanged 22-second no-churn oracle; traffic proof passed but dial growth did
  not. Counts in `native-churn-final-source-counts.txt` (B31pre/6post,
  C42pre/5post). Earlier native filtered 75/75 GREEN is distinct evidence.
- `handshake-drain-before-debug.log`: deterministic socketpair RED 71/73,
  both plaintext backlog and secured exact ciphertext assertions failed. Source
  `75acb9bea679afb941460b53ad2273d8cda47451c6899d807b1b323056605565`.
- `handshake-drain-after-debug.log`: fixture custody RED; old borrowed fixture
  link was incorrectly destroyed through real teardown. Corrected to heap-owned
  links and real ownership; no production assertion weakened.
- `handshake-drain-after-debug-2.log`: initial drain repair GREEN 73/73.
- `drain-final-focused-debug.log`: GREEN 83/83, including pressure/race/expiry.
- `drain-frozen-focused-{debug,release-safe}.log`: prior cc24 source GREEN
  83/83 in both modes. These predate the reviewed lifetime fix.
- Parent `native-exec-debug-drain.log`: prior cc24 drain daemon GREEN all three
  actual native fork/execs, unchanged 22-second no-new-dial check, 47 events,
  225 exact deliveries, far-edge resume and cold authentication. Final-source
  native replay remains parent-owned.
- Parent `native-unit-debug-drain.log`: prior native unit hangs at plaintext
  test then is terminated. This is the fixture blocking-read assumption, now
  corrected with bounded portable submit/reap/poll driving.
- `receive-lifetime-fixture-compile.log` and
  `receive-lifetime-before-debug{,-2}.log`: fixture setup diagnostics, preserved.
- `receive-lifetime-before-debug-3.log`: causal RED 71/72, fails the driver
  false-result oracle after actual receive/generation assertions. Source
  `b1fc2a84e01ac003c7c21597d7aee610e6f6a5117395cd6ac337fb0fc5c47046`.
- `drain-diagnostic-qualification-{debug,check,release-safe}.log`: preserved
  compile errors for unqualified diagnostic helper; fixed mechanically.

Earlier fixture-only setup REDs remain (trust-root self entry, two-hop NAMES
assumption, CAP/SASL setup and listener AddressInUse). Their corrections preserve
actual echo, stable identity/time, topology and physical-socket assertions.

## Prior lifetime-only checks (3be5417b)

```
zig build test-mod -Dtest-filter='same-IP mesh dial' -Dtest-filter='reciprocal [mesh].connect survives redial sweeps' -Dtest-filter='secured establish collision' -Dtest-filter='secured collision scan' -Dtest-filter='UPGRADE canceled CONNECT' -Dtest-filter='inherited outbound' --summary all
```

Debug receipt: `lifetime-final-focused-debug.log`: exit 0, **84/84 pass**,
compile 8s / run 14s.
ReleaseSafe: same command with `-Doptimize=ReleaseSafe`, receipt
`lifetime-final-focused-release-safe.log`: exit 0, **84/84 pass**,
compile 3m / run 13s.
`zig build check --summary all`: exit 0 (`lifetime-final-check.log`), compile 5s.
`zig fmt --check src/daemon/server.zig` and `git diff --check` pass.
Parent subsequently ran native Debug and ReleaseSafe 79/79 and actual native
three-node exec with exact no-churn/47-event/225-delivery/cold-auth checks on that
prior production. These are prior-candidate receipts, not final routing proof.
The parent RS named gate had one real shared-session timestamp RED (2325/2337,
11 skip/1 fail), now recorded in
`named-final-release-safe-lifetime-candidate-interrupted.log`; it was not merely
canceled. Its test body is byte-identical to baseline d9991c00 (fixture SHA-256
9fb5411fdd95ce4f88dc8ba9c682cd176f073c8a8ceadfd00ed3e96670666723).

## Exact final routing freeze checks (a08b0e8a)

The command above selects all fifteen same-IP cases plus the existing reciprocal,
collision, CONNECT retry and inherited endpoint fixtures.

- `routing-after-debug.log`: preliminary seven-case Debug GREEN 78/78 at
  25511580870d8eafec0bb2365fd4e92c09106483920e900c554d5dd2443d9192.
- `routing-final-focused-debug.log`: preliminary combined Debug GREEN 91/91
  (13s compile/16s run), same 25511580 pin.
- `routing-final-check.log`: preliminary check GREEN, 12s.
- `routing-frozen-focused-debug.log`: exact a08b Debug GREEN **91/91**,
  compile 12s/run 18s.
- `routing-frozen-check.log`: exact a08b `zig build check --summary all`
  GREEN, compile 11s.
- `zig fmt --check src/daemon/server.zig` and `git diff --check`: GREEN.
- `routing-frozen-focused-release-safe.log`: exact a08b ReleaseSafe GREEN **91/91**,
  compile 9m/run 19s, exit 0.
- `shared-session-final-debug.log`: the unchanged shared-session test on a08b
  GREEN 72/72, compile 12s/run 2s; exact timestamp equality preserved.
- `shared-session-final-release-safe.log`: exact a08b targeted ReleaseSafe
  GREEN **72/72**, compile 9m/run 1s, exit 0. The earlier broad timestamp RED
  did not reproduce in either focused mode; no assertion or fixture change.
  Its exact cause remains unproven and final broad gates belong to the parent.

Parent fresh `final-frozen-review.txt` reports no blocking finding, with identical
start/end a08b server, c1c6 snapshot and c993 Python pins. The source review did
not claim exhaustive runtime fault coverage. Parent final native Debug selected
module run is GREEN 86/86 (all fifteen same-IP cases, zero selected daemon tests,
two CLI imports); actual final Debug exec campaign also passed the stronger settled pre/per-exec/post
no-churn oracle, all three execs, 47 accepted events, 225 equal-identity deliveries
and cold authentication. Final native ReleaseSafe/broad/full gates remain
parent-owned and pending. Parent owns final acceptance and commit.


## Final memo fixture correction (dfcd1a71; production identical to a08b)

Parent final a08b named Debug and ReleaseSafe each found the same fixture-only
GAP-D2 MEMO_PUSH RED, 2332/2344, 11 skip/1 fail. The shared-session timestamp
failure did not recur in either broad named run. Preserve `named-routing-debug.log`
and the parent ReleaseSafe named receipt. Focused `memo-fixture-before-debug.log`
reproduced the memo assertion RED 74/75 on a08b.

The old Linux-only synthetic fd=-1 peer deliberately set closing=true to keep
its ciphertext in link.outbound. Closing now correctly excludes it from routing.
This single test uses test_sendq_capture on an eligible peer and decodes its
actual copied SendQ ciphertext with the established SecuredLink counterpart.
Assertions still require nonzero queued wire, empty link output after paging,
live/non-dedup route state, exactly one decoded MEMO_PUSH and the precise
account/from/text fields, plus restored durable memo delivery/consumption.
No production guards or transport ownership changed.

`memo-fixture-test-only.diff` records the entire a08b->dfcd delta. Reversing that
one test delta reproduces the exact a08b SHA, proving production equivalence.
`memo-closing-fixture-audit.txt` records the bounded audit of all explicit closing
assignments in top-level tests. Collision publication, handoff and flood teardown
are intentional negatives/lifecycle coverage. The standalone routing helper's
closing loser also remains unchanged. No other obsolete retention fixture found.

```
zig build test-mod -Dtest-filter='GAP-D2' --summary all
zig build test-mod -Dtest-filter='GAP-D2' -Doptimize=ReleaseSafe --summary all
zig build check --summary all
```

- `memo-fixture-after-debug.log`: exit 0, **75/75**, compile30s/run1s.
- `memo-fixture-check.log`: exit 0, compile25s.
- `zig fmt --check src/daemon/server.zig` and `git diff --check`: GREEN.
- `memo-fixture-after-release-safe.log`: exit 0, **75/75**, compile8m/run1s.
- `memo-fixture-frozen-source.sha256`: exact dfcd frozen pin.

Parent owns fresh final-test-delta review and final full/named acceptance.

## Final test-only SESSION retry/JOIN correction (2026-10-01)

Prior frozen source dfcd named Debug failed the fifth attachment's required JOIN
assertion in the four-client sequential Helix test. Source order shows that the
claimant bootstrap is staged before the attachment notice. The helper reset its
collected output before every 250ms retry, permitting an earlier JOIN to be lost
before an already-attached response arrives on a subsequent attempt.

The new portable heap-backed LiveClient socketpair test sends JOIN only after the
first exact SESSION request, waits for the second exact SESSION request, then
sends ATTACHED. It uses bounded peer poll/read deadlines, joins its scripted peer
before inspecting peer state, and checks exactly two requests and one copy of
each reply. No fixture sleeps determine reply order. A returned ATTACHED with
missing earlier JOIN establishes that its preceding stream bytes were read and
then discarded; an unread preceding JOIN could not be bypassed on this stream.

Causal RED: server 31e3b44c39d5c09b675702a28a8ca57a270b5c311d6f3a2fe188945703800d81,
`join-retry-before-debug.log`, Debug 71/72, sole new regression expected JOIN count
1 but found 0 (compile 11s; exit 1). Old helper and all production remained intact.

Fix: reset once at helper entry and retain its accumulated prefix across retries.
Each of the four callers now awaits the same exact `JOIN #helix-mesh` through
existing deadline-based recvUntil before its unchanged assertion. The complete
fixture still proves all old physical attachments, stable token, required fifth
JOIN, MARKREAD, and exact stable msgid/time traffic. No production source change.

Final source b815280a0cc44db9e7f8a02dc7b86ae3cc665a0d343103ae360c27d05eccb708.
`join-barrier-test-only.diff` and `join-barrier-frozen-source.sha256` are saved.
Reversing only this test/helper delta restores dfcd1a71457ca43c093bbba2ee06a5fd5810c28d8b5e8070846eef31b0770f8b exactly.

Focused command (add -Doptimize=ReleaseSafe for the second mode):

```
zig build test-mod -Dtest-filter='same-IP mesh dial session resume retains JOIN received before a retry' -Dtest-filter='four-client reusable session and MARKREAD survive sequential Helix upgrades across secured mesh' --summary all
```

- Debug `join-barrier-focused-debug.log`: 73/73, compile 22s/run 10s, exit 0.
- `join-barrier-check.log`: check passed in 18s, exit 0.
- zig fmt and git diff --check passed.
- ReleaseSafe `join-barrier-focused-release-safe.log`: 73/73, compile 11m/run 6s, exit 0.

Parent retains prior dfcd full/named/native receipts separately and owns final
fresh review, full Debug/ReleaseSafe counts and exact-source native acceptance.


## Final retiring-roster authority repair

The independent b815 review found that retained established collision losers
still supplied frozen roster authority to inbound admission and projected views.
Twenty-two Server methods now exclude closing/dedup connections at 23 roster or
view scans. Ten divergent loser-before-survivor cases cover home/account/status/
membership, WHOIS, LIST/NAMES, channel metadata, active route-index count, signed
MESSAGE_V2 and signed E2EEGROUP. Signed admissions deliver once and then dedupe;
retained loser wire/SendQ remains unchanged. No lifecycle/drain/checkpoint/store
or counter-definition change. Exact consumer audit: `retiring-roster-audit.md`.

Corrected ten-case causal RED: 71/81 passed, ten failed, exit1. Source SHA-256
`c9153dc569990862a0b9d8228be0363adb27ef8af10b1e8742d0d3989478727e`;
`roster-corrected-final-causal-before-debug.log`. Restored final ten-case Debug
exits0: `roster-corrected-final-after-debug.log`.

Final frozen broader focused Debug: exit0, 124/124 passed, compile13s/run18s.
Log: `roster-frozen-focused-debug.log`.
`zig build check --summary all`: exit0, compile10s,
`roster-frozen-check.log`. `zig fmt --check src/daemon/server.zig` and
`git diff --check`: exit0.

Focused command (run both default Debug and `-Doptimize=ReleaseSafe`):
```
zig build test-mod --summary all \
  -Dtest-filter='same-IP mesh dial' \
  -Dtest-filter='deliverRelay binds sender nick to home' \
  -Dtest-filter='MESSAGE_V2 unknown home retries' \
  -Dtest-filter='E2EEGROUP mesh live path accepts once' \
  -Dtest-filter='NAMES' \
  -Dtest-filter='GAP-P0c remote LISTX' \
  -Dtest-filter='four-client reusable session and MARKREAD survive sequential Helix'
```
ReleaseSafe pending at receipt write; final result appended on completion.
Parent owns fresh final independent authority review and all final broad/full/
native checks. Earlier full-mode8826/8850 receipts are pre-authority evidence.
