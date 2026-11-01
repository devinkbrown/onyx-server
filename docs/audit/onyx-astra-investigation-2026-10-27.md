# Astra investigation — Onyx Server candidate

> **Superseded / historical — preserved as evidence.** This document is a point-in-time record and does not describe the current source or fleet. Current truth: [docs hub](../README.md) and [production paths](../ops/onyx-server-paths.md). Do not execute it as a current procedure.


2026-10-27 · independent read-only source investigation · release blocked

Astra inspected the current dirty 0.8.1 candidate and bounded evidence. It did
not edit files, run a daemon or execute reproductions. These source-verified
findings require dedicated regression tests and fixes even if the pending full
suite passes. No live service or configuration was changed by this investigation
or local work.

Audited source hashes:

- server: `a947f6bdba7a771f43fad0d0c6cbbfbd685aeadb3ffe12fcf0b8194c8a8f7876`;
- media plane: `679618409e72ad24ba0235e8bbb789d0f3a157ac88c3cc4b02f9402470556330`;
- media wake: `ca7107d5f0c997fe23f9a93ddbc9c47a7bfe9e3423a2b6d7b16dc46d5238f617`.

## HIGH: valid long identities bypass policy evaluation

`normalizeSuffix` permits a 179-byte suffix, producing a current v4 cloak of
about 230 bytes. A supported nickname can make the full `nick!user@host`
identity exceed a 256-byte caller buffer. `enforceServerAccess` treats that
formatting failure as “not denied,” skipping DENY/GAG. Empty-channel AKICK has
the same fail-open pattern; the IRCX lookup also returns no match on failure.
The default short suffix is not the triggering configuration.

Sources: [suffix validation](../../src/proto/cloak.zig#L303),
[SACCESS evaluation](../../src/daemon/server.zig#L23546),
[IRCX lookup](../../src/daemon/server.zig#L23570),
[AKICK evaluation](../../src/daemon/server.zig#L23591),
[prefix construction](../../src/daemon/server.zig#L76669).

Required response: audit all prefix consumers, derive shared capacity from the
supported identity limits, and ensure unexpected formatting failure cannot
grant admission. Regress valid long DNS suffixes/nicknames and DENY/GAG/AKICK
scope. Merely tightening the cloak suffix would hide the broader prefix issue.
Runtime reproduction is pending.

Follow-up review of the proposed capacity correction found a second route to
the same policy bypass: USER accepts `*` and `?`, while the observed-identity
validator rejects them. IRCX callers currently turn that validation error into
no match. The correction must therefore close query-error paths as well as
increase capacity, with a regression through the actual USER handler. Shared
capacity alone does not resolve this finding.

## HIGH: failed AKICK ADD changes durable policy

`Services.channelAkick(..., .add, ...)` writes the KV record before the command installs the
live `svc_akick` mirror. Duplicate, capacity or allocation failure in the latter
returns command failure after the durable mutation. A duplicate ADD with a new
reason can replace the durable reason while retaining the old live reason.
A 65th rule can persist despite the live 64-rule limit; strict cold replay then
rejects the overflow as `InvalidRecord`, potentially preventing restart.

Sources: [durable write](../../src/daemon/services.zig#L3599),
[live mirror installation](../../src/daemon/server.zig#L51105),
[duplicate rejection](../../src/daemon/svc_akick.zig#L152),
[strict cold replay](../../src/daemon/server.zig#L47410).

Required response: prepare all fallible live admission before durable commit,
then publish the live state without further failure. Define duplicate behavior
consistently. Cover duplicate reason changes, capacity overflow, allocation
failures and cold replay at command level. Preserve existing ambiguous-I/O
poison/cold-reopen rules; do not invent rollback after an uncertain commit.
Dedicated runtime/fault reproductions are pending.

## MEDIUM: exited media pump can keep accepting work

A readiness error exits `pumpLoop`; its deferred cleanup records worker exit,
but does not set `stop_flag` or close routing admission. Queue admission can
therefore accept new ordinals while an intact private wake handle has no live
consumer. Initialization proof is not steady-state supervision.

Sources: [wait-error exit](../../src/daemon/media_plane.zig#L2465),
[queue admission](../../src/daemon/media_plane.zig#L2221).

Required response: inject readiness failure and prove terminal admission
fencing, retained/exact queue settlement and bounded stop/Helix behavior.
Distinguish recoverable UDP conditions from fatal wake/descriptor failure.
Runtime reproduction remains pending; successful normal-path wake tests do
not establish fault-path behavior.

## HIGH follow-up: membership removal can retain media authority

PART and KICK suppress retirement errors, and `retireMediaPhysicalChannel`
itself suppresses protected-routing departure failure. AKICK and mass-kick
paths omit retirement. Clean QUIT removes World membership before close
enumerates that membership to leave media rooms, so cleanup can miss the rooms
even without an injected failure.

Native authenticated ingress and protected routing consult their independent
physical endpoint maps and current stamps; they do not recheck World channel
membership. Legacy transport cleanup alone therefore does not invalidate that
authority.

A private real-daemon campaign reproduced the clean-QUIT defect on the captured
optimized image `5850a26f80b9966e72dccedca2e1d2e6f1c267118bfeb56c87c635f7d06e5a5e`
(the earlier `af14549` source cut). After eight authenticated positive deliveries,
observed QUIT, a surviving client's PONG and the target's actual TLS EOF, a fresh
correctly authenticated target-to-survivor UDP packet still arrived. Normal PART
and KICK scenarios passed their fresh-media retirement and survivor checks.
Receipt: `.zig-cache/wave-7/media-retirement-smoke/captured-v2-result.json`,
with harness and helper hashes. This establishes local native QUIT failure on
that image; it does not establish fault-path, WebRTC, mesh or current-image
acceptance. Those campaigns and the corrected candidate remain required.

Sources: [PART](../../src/daemon/server.zig#L24395),
[KICK](../../src/daemon/server.zig#L25355),
[channel retirement](../../src/daemon/server.zig#L58128),
[room cleanup](../../src/daemon/server.zig#L58479),
[QUIT ordering](../../src/daemon/server.zig#L64790),
[native ingress](../../src/daemon/native_media_transport.zig#L234),
[protected routing](../../src/substrate/media_routing.zig#L1062).

Required response: strict retirement and retained failure enforcement across
all local membership/connection removal paths, with native and WebRTC packet
tests. Preserve the ownership of attachments transferred during Helix or mesh
migration. Local retirement does not establish mesh-wide policy replication.

## Integration and evidence limits

- IRCX channel ACCESS mutations remain local. Services directory reconciliation
  has unit-test callers but no demonstrated native daemon path. Current native
  ACCESS/AKICK scenarios install the rule at the receiving node; they do not
  establish mesh-wide rule availability. Server-local SACCESS scope must remain
  distinct from channel policy replication.
- Sixteen-row FIFO turns establish bounded scheduling, not audio priority,
  production WebTransport media or native UDP mesh forwarding.
- The [native chat report](../ops/live-chat-sqpoll-benchmark-2026-10-26.md) retains
  its limits correctly. The unexplained 5.74% sustained median difference remains
  outside the proposed acceptance budget and does not establish causality.
- Sequential multi-node session/Helix guarantees were not established by this
  investigation. Existing named evidence needs its own acceptance scope.
- Parent's baseline unfiltered `zig build test -j1` finished under
  `.zig-cache/wave-7/full-debug.{json,log}` with unchanged source: 10,420 passes,
  323 skips and six failures out of 10,749 tests. Its module artifact reported
  10,328 passes, 323 skips and six failures out of 10,657; executable and CLI
  artifacts passed 38 and 54 tests respectively. Five failures are S2S adoption fixtures; a
  separate read-only audit traced their obsolete 12-byte suffix removal to
  the current 14-byte layout. The reviewed fixture correction awaits runtime
  confirmation on the complete suite. The remaining native-media failure led
  to a forced real-pin race reproduction and a separately reviewed fixture
  correction. The promoted correction cohort passed 157 tests with two skips
  in both Debug and ReleaseSafe. No passing full-suite claim is made.

These findings do not shrink the 98-target roadmap. Fix the blockers, verify
with focused regressions and independent review, then complete the broader
release and roadmap acceptance gates.


## Follow-up privacy audit: public WHOWAS address disclosure

**Initial finding: HIGH — public WHOWAS address disclosure.** The correction
is now integrated into source; the acceptance update below records its scope.
`server.zig:recordWhowas` calls `whowasRecordedHost`, which prefers the real
host over the visible cloak. `handleWhowas` then copies this field to ordinary
numeric 314 replies without a privilege gate. The existing test
`GAP-P0c WHOWAS reply includes the account and the real host` explicitly expects
an ordinary requester to receive `203.0.113.10` instead of the visible cloak.
Address admission records the canonical effective kernel or trusted-PROXY
address independently of public cloaking, so this affects cloaked users too.

Public history must snapshot the explicit visible host and never fall back to
the real address when that snapshot is absent or invalid. Calling the existing
`session.host()` helper is insufficient: it itself falls back to real-host
storage. No additional privileged address-retention feature is required by
this correction. Preserve the historical public identity across later cloak
or account transitions and verify nonempty public replies after NICK/close.

Current WHOWAS records contain only one host field and cannot reconstruct an
old visible cloak from stored real-host data. Source inspection found no
WHOWAS checkpoint/export/adopt path: a process exec currently creates a fresh
ring. A new capture fix does not retroactively sanitize a still-running older
image's records, and no historical import or seamless history-retention claim
is made. The candidate must not introduce unsafe legacy reconstruction or
silently clear valid new history.

The bounded audit found privilege gates for local/remote WHOIS addresses;
SEARCH/history ingestion and the wider media/privacy corpus remain separate
verification work. This is not a claim that all other surfaces are leak-free.


A private native TLS baseline subsequently reached the specific
`WhowasHostMismatch` verdict on captured artifact873b after successful trusted
PROXY v1 admission, ordinary registration, valid current anonymous WHOIS cloak,
NICK confirmation, and exactly one WHOWAS 314 without an account numeric. This
proves public WHOIS/history host divergence; the source trace above identifies
the real-host selection. Fresh review verified pinned inputs and cleanup.
The run stops at that first failure, so account and QUIT runtime cases remain
unexecuted. Evidence:
`.zig-cache/wave-9/whowas-public-runtime-v3/baseline-01/result.json`;
report SHA-256 `697d7c476b47cb308edd9b00eb669b8c6cbddfe2980ea786ef6180e1dbbcabed`.
The visible-only candidate and identical-test baseline overlays are approved
for isolated compilation, with runtime acceptance still pending.


### WHOWAS source acceptance update

The reviewed four-file wave9 cohort is integrated. Native Safe artifact
`43d703c0466ad1945f43b8765e338f41c4339997eb791f72ecd5a91a646b9a81`
passes the unchanged TLS oracle's anonymous/account NICK and QUIT cases. Its
module gates pass 96/96 in Debug and Safe; executable gates pass 4/4 in both,
including private allocator failure checks. All 1,219 current source inputs
match the tested candidate after guarded promotion; whole-source formatting,
touched-file whitespace checks and the actual primary semantic build pass.

This resolves the identified WHOWAS capture leak in source. Older deployed
images retain their own behavior. The wider P10 privacy corpus remains partial,
and the previous full suite has eight failures requiring separate kernel-fixture
and native-crypto retirement work. No full release or deployment is accepted.


## Native wall-clock rotation follow-up, 2026-10-28

Native candidate `83733d1444ded3e8be826d22eac6a9f589d4f3df37b9c61615b9f6f6b376ad3f`
reproduces a remote-notification gap on two private secured processes using a
test-only two-second cadence. The ordinary remote observer receives no subject
CHGHOST during the twenty-second wait. Post-timeout diagnostics observe eleven
subject/local-peer notifications, and ordinary remote WHOIS reports a canonical
public host with a changed token and advanced epoch. Both nodes remain alive
and their secured mesh is healthy. Post-timeout observations do not establish
exact timing within the notification window.

The source explains this boundary: local host-change fanout resolves local
physical connections, while mesh reannouncement updates signed presence without
producing the corresponding remote client notification. A correction must
follow accepted authenticated presence changes, preserve the exact visible
subject and public identity, and retain notification custody through allocation
or delivery pressure. Relaying arbitrary CHGHOST text is insufficient.

Evidence: `.zig-cache/wave-13/terra-cloak-runtime-v6/run-01/result.json`.
All eight listener probes return connection refused; owned processes/groups,
listeners, drain threads and the private workspace are gone, and all pins remain
unchanged. Earlier v2/v4/v5 receipts are retained, including their distinct
reporting/cleanup limitations. The runtime oracle still fails on remote CHGHOST;
its later moderation and offline-return phases have not run. This is neither
P01/P03 completion nor release acceptance. The fourteen-day default is unchanged;
the short cadence belongs only to the private fixture.
