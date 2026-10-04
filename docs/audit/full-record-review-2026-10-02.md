# Full record review — 2026-10-02

User direction: continue the full OpenBSD port, use Astra to analyze it, no
bandaids, and review the entire record. The full roadmap objective remains open.
No deployment, publication or push is authorized by this review.

## Current verdict after record reconciliation

The complete port remains **open**. Historical runtime campaigns establish the
behavior of their exact frozen artifacts. Accepted source and native foundations
below do not establish the current combined daemon or installed service.

| Boundary | Latest evidence and review boundary | Remaining acceptance |
|---|---|---|
| Evidence custody | All 3,678 canonical inventory entries rehashed with zero mismatches | Integrity does not establish oracle correctness or runtime behavior |
| Native service N1 | Final6 OpenBSD Debug/ReleaseSafe 106 module + 2 CLI passes each, zero skips | Actual daemon consumer, service roles, helper, readiness and joined stop |
| Store/Physical S2 | Repaired OpenBSD Debug/ReleaseSafe 208 Store + 181 Physical + 2 CLI passes each, zero skips, normal 8192 KiB stack | Production owner lifetime, loans, seal and durable publication |
| Store complete publication | Exact source4 host Debug/ReleaseSafe each149/149; focused ten controls+import11/11 each; fresh Astra source and actual-result approval; zero skips, failures, leaks or log errors | Opaque Mail journal/schema and typed admission, cold uncertainty reconciliation, composed/native consumer acceptance |
| Native MAC32 primitive | Exact isolated host focused12/12 and full89/89 in both Debug/ReleaseSafe; all964 pins, actual logs/ELFs and fresh independent review verified | Directional key helper execution, actual endpoint issuance, real client capability support, configured callers and native acceptance |
| Protected media publication | Final header11 selected; exact SendQ2 host13/13 in both Debug/ReleaseSafe independently accepted; TLS/WS/Server caller integration remains unaccepted | Four actual caller failures, coherent protected-output/authority composition and critical/native gates |
| Protected WS output | Exact source4 host Debug/ReleaseSafe each11/11; fresh independent source and actual-result approval; unchanged production and original five tests, zero skips/failures/leaks/log errors | Actual caller, TLS/Domain authority composition and native acceptance |
| Media selector and full pump traversal | Exact repair4 host Debug/ReleaseSafe each80/80; real130 RTP and130 RTCP recipients per mode; independent Astra approval of bounded repair | Actual caller BEFORE3 reproduces four failures: native DTLS bypass, denied fingerprint output and unbound/foreign NACK; physical caller repair and whole media/native adoption remain open |
| Dormant Gate/Pool with GEO slot | Control/View leaf Debug/ReleaseSafe 37/37; 22 authority refusals plus one positive compile per mode; old constructor 72/79 with seven intended runtime failures | Owned construction and caller closure, actual main consumer and native execution |
| All-shard startup | Core5 independently accepted on OpenBSD7.9: Debug/ReleaseSafe 78 module + 2 CLI passes each, zero skips, normal stack | Complete main transaction, configured companions and daemon acceptance |
| Late native COMMIT | Exact repair independently accepted: native Debug/ReleaseSafe 72 module + 2 CLI passes each, zero skips; unchanged causal fixture | Full configured daemon adoption and attachment continuity |
| Companion continuity | Webpush source approved; actual History duplicate shutdown regression repaired in moving Debug iterations | Frozen composition, critical modes/native runs, full queues/caches, nested operations and main integration |
| Managed execution policy | Strict policy2 context/snapshot source approved; root host119/125 in both modes with6 native-only skips | Reply2/helper/main integration and actual executed-context/native acceptance |
| Installed OpenBSD service | Packaging source5 and policy compiler source2 freshly reviewed by Astra; latest frozen package/release16/16 under restrictive umask | Actual native policy publication/root helper/main, rcctl lifecycle and reboot |
| Ordinary mesh and durable authority | Far WHOIS/direct-message failures and cold custody obligations remain open | Actual production callers and multi-node acceptance |

The remaining sections preserve the progression of failed, pending and accepted
cuts. A statement of “pending” in an older checkpoint is superseded only by the
later exact receipt, not by a result from another composition.

## Reviewed record and verification boundary

- [Roadmap](../ROADMAP-GAPS-2026-09.md), all92 extracted primary acceptance
  outcomes and25 explicit cuts in the [requirements inventory](gap-requirements-2026-10-01.json).
  Inventory source SHA256 remains afd2b731f046ab9bbe8166f0e58c68487663ac5dcd538d42698a6b0b7d752328.
  The92 IDs are unique. These are requirements, not92 completed features.
- [Earlier continuation](gap-continuation-2026-09-30.md),
  [full OpenBSD record](../dev/openbsd-full-port.md),
  [transaction/presence chronology](mesh-presence-2026-10-01.md),
  immutable contracts, current source seams, failed and successful runs.
  Independent chronology and Astra architecture findings are being reconciled.
- Root independently rehashed all1810 previously indexed evidence files: no
  mismatch. Added native ABI diagnostic/source review and S2 failed-run evidence
  brings the canonical inventory to1823. Hash integrity establishes provenance,
  not the correctness of a test oracle or whole-product acceptance.
- Current dirty edits are preserved. No reset, unrelated process termination or
  borrowed acceptance from moving source.

This review reconciles the record. A fresh source/runtime acceptance audit of
every one of the92 requirements is still required; missing current evidence is
not converted into either a completed feature or a newly proved source defect.

## Findings

### 1. Historical runtime acceptance is specific to its frozen artifacts

The earlier port record contains substantial actual OpenBSD evidence: complete
shared server, native TLS/WSS, secured three-node session traffic, partition
healing, sequential Helix and retained original attachments. Those results remain
valid for the matching binaries and explicitly bounded observations. They do
not grade the current combined worktree with subsequent authority, Store, TLS
output, physical lifecycle and service changes.

The current continuation already states this distinction, but old headings and
summary counts can be read as a current full-port claim. Every new final gate
must identify its composition, source inventory, binary hashes, actual platform,
stack, skip identities, ordered outcomes and cleanup. A zero-test daemon runner
is compilation evidence. A cross-build is not native execution.

### 2. Native service leaves have no complete daemon/service integration

Current source has native_service and strict snapshot leaves in root harnesses.
The production main/Helix path lacks their service listener/lease integration.
At the initial review, build.zig unconditionally installed a systemd unit.
The later target-routing correction is recorded below; no installed OpenBSD
rc.d journey has been accepted.

N2 must join a real root helper, selected su-child identity, mandatory capsule
descriptor roles, retained operation state, sandbox authority and actual daemon
lifecycle. `main.zig:1603` starts the server before services hooks, plugins,
signal setup and WebTransport; it is not a sufficient ready boundary. Stop must
wait for `runThreaded` workers and all companion/server deferred cleanup.
At the initial review, the runtime pledge lacked the unix promise needed by this
route. The current `runtime_pledge` includes `unix`; that source correction does
not establish the complete native sandbox/helper consumer or installed service.
The root helper must recreate the fixed protected namespace after reboot because
/var/run is volatile. Nonroot descriptor validation must be possible while
endpoint/lease protection and ancestor/symlink checks remain strict.

N3 must supply target-specific packaging and real rcctl start/check/reload/stop/
restart/reboot acceptance. Broad PID matching and killing an uncommitted Helix
candidate do not establish service ownership.

### 3. The first actual native N1 run disproved host-only ABI assumptions

Final4 native Debug and ReleaseSafe each passed91/105, failed14, skipped0;
CLI2/2 passed. All14 failures occurred at a shared listener initialization check.
The original causal2 native failures occurred at the same precondition and were
not evidence for the two transport defects.

Actual OpenBSD7.9 probes returned listener option0/2 and named address length106
with sun_len106. Default soft NOFILE128 stopped at124 admissions with MFILE.
The same diagnostic with declared soft512 reached241 queued clients and bounded
CONNREFUSED, drained exactly241, then observed empty AGAIN; stack8192 unchanged.

Final5 fixes the production ABI checks and adds a real before-listen refusal,
after-listen acceptance and wrong-path refusal. Its bounded fixture changes
only the saved/restored test descriptor allowance. Root reviewed the complete
delta and verified both1559-entry source archives, nine host gates and106
ordered root Linux passes in each mode. The original failures are retained.
Actual final5 native acceptance is pending in the reserved test VM. The refined
OLD-transport causal3 has now reported72/74 native passes and two blocking-
listener failures; the connect baseline fails synchronously on this kernel,
as permitted by the declared bounded-failure oracle. Raw final receipts are
required before grading these reported outcomes.

### 4. Store/Physical foundation does not establish production ownership

Accepted S1 and opaque Coordinator native cuts are bounded foundations. New S2
adds actual private constructor authority, original resident/retiring census,
funded candidate preparation/abort and original backend teardown. Its lifetime
premises remain lexical; it does not have a live boot/adopt driver.

Frozen S2 final1 is Store518bf482/Physical0a7d0a3c,962-entry manifest26f713ed.
Root rehashed every source entry and all60 production probe result logs:
56 intended negative results,4 positive compile results. Store208 passes in
both host modes, check3 and native artifact builds pass; other gates retain
their own completion state. These do not activate a production driver.

Physical Debug180 passed, but ReleaseSafe179/180 passed with one crash. The
new retirement tamper test captured an array index before canonical plan sorting
and mutated the stale index afterward. Root independently confirmed the sort
and the real production mismatch validation before hold publication. A
test-only repair is authorized: choose/assert the actual retiring entry after
canonicalization, require refusal and unchanged accounting, retain valid retry,
and perform real cleanup if the expected refusal unexpectedly succeeds.
Final1 remains failed evidence. A new immutable cut and fresh gates are required.

S3 still needs construction-peak custody, actual backend/Io/directory owner
lifetime, joined callers/waiters, complete physical owner graph, ordinary caller
migration, strict hot/cold adoption and private claims/seal/publication joins.

### 5. Older next-step prose is stale, and qualifiers must survive summaries

The older continuation's final GAP-P16 sentence says markers remain local.
Later source and shared-session three-node/Helix tests cover durable signed
MARKREAD propagation. That older sentence must be treated as historical; those
later tests still do not establish independent-account directory authority or
the current combined-tree acceptance.

Independent chronology review also found startup controls with a64MiB stack
qualification omitted from a later audit summary. The raw qualification must
be retained. Those controls are not normal8192KiB acceptance.

### 6. Remaining roadmap outcomes cannot be collapsed into these two leaves

The ordinary far-node WHOIS401/no311 and empty direct-message failures remain
open. Shared-token resume evidence does not establish independent same-account
identities, original multi-hop presence or account-directory registration on one
node/authentication on another.

Cold retained RVL2 obligations after upstream acknowledgement, ambiguous/failed
durable append, Event Spine retirement across eviction/restart, partition beyond
90seconds, and joined authority publication require their own actual acceptance.
Interop/benchmark/platform cells, client-dependent outcomes, conditional research
items and the25 explicit cuts remain distinct. Existing safe configuration
refusal, OCSP verification or frozen transport acceptance must not be reopened
solely because historical roadmap text describes their previous state.

## Required continuation

1. Finish exact N1 native evidence and independent grading; preserve before-
   controls and clean only the owned VM and guest paths.
2. Repair the S2 test oracle, freeze the full joint composition, finish its
   Debug/ReleaseSafe/consumer/probe gates and fresh independent/native review.
3. Implement the complete N2/N3 daemon-to-installed-service path; use real
   readiness, inherited ownership and joined stop semantics.
4. Complete S3 physical ownership and durable authority/publication, then
   ordinary far presence/account/cold-custody acceptance.
5. Reaudit each roadmap outcome against current source and its stated observable;
   run fresh combined full Linux and native OpenBSD acceptance.

Independent full-record report addenda and pending raw outcomes will be appended
with exact source references. The review does not close the full port.


### Subsequent observed failures and bounded repairs

The final5 native writer reports actual Debug106/106+CLI2/2, but ReleaseSafe
105/106+CLI2/2 with the root-binder/nonroot-acceptor fixture failing BadDescriptor.
The child sent its reply and immediately exited before the parent's connected
peer/credential/read checks. Root independently inspected this unsynchronized
fixture. A test-only explicit sidechannel ACK after all parent checks is
authorized; the child must retain its actual accepted FD until that ACK. No
production credential or connected-state validation may be relaxed. New source
freeze, gates and native evidence are required; final5 is not fully accepted.

Astra has frozen the retirement-oracle test-only repair as S2 final2:
Physical3f2aa47b, unchanged Store518bf482,962-entry manifest95d314a8. Select the
actual retiring entry after canonical sorting, assert state/disposition, require
InvalidPlan and unchanged totals/all encumbrances, then restore and retry.
Unexpected successful admission is genuinely aborted before failing the oracle.
Its fresh gates remain pending; final1 ReleaseSafe RED remains preserved.


### All-shard preparation must precede managed native commit

Astra identified an additional concrete lifecycle seam. Root inspected
server.zig:8426–8466 and native_bootstrap.zig's READY/COMMIT boundary. After
main adoption commits, runThreaded still creates the cross-shard fabric and
spawns the worker pool. Either failure falls back to driving only reactor0.
For a successor inheriting physical clients on other shards, that fallback
does not prove every attachment remains serviced. The N2 design must stage real
dormant all-shard/companion resources before READY and release them without
fallible work after COMMIT, or prove equivalent all-shard recovery. A ready log
or suppressing early status publication does not solve this resource ordering.

A suspected WebTransport single-socket issue was refuted by actual source:
main's stale IPv4-mapped comment does not describe the OpenBSD implementation.
dualstack_udp.bindNative creates separate AF_INET6/AF_INET sockets on the same
port and selects the proper family. Configured QUIC/WebTransport hot-lifecycle
acceptance still needs its own evidence; TLS/WSS evidence cannot substitute.


### Coverage and evidence limits of the complete-record pass

The independent chronology reviewer read all1341 original audit lines, all249
port-record lines and all154 earlier-continuation lines, then the appended
changes; root reviewed all123 report lines and verified its16 observation pins.
Root read all92 primary acceptance texts and the explicit cut/ordering/cross-repo
contracts. Astra's312-line entire-record/N2-N3 architecture checkpoint is complete. Root
read every line and checked all30 observed source/document pins before this
appendix. Detailed dormant-worker API and cancellation design still require
review before production ownership expands.

The chronology memo is archived as
[evidence/mesh-presence-2026-10-01/record-readonly-review-2026-10-02--entire-record-observation-1.txt](evidence/mesh-presence-2026-10-01/record-readonly-review-2026-10-02--entire-record-observation-1.txt).
None of these reads substitutes for rerunning historical campaigns or a complete
current source audit of every one of the92 outcomes. Failed tests, obsolete
claims, missing callers and conditional acceptance remain visible.

The old final5 ReleaseSafe fixture was subsequently repeated twice using the
same frozen binary; both repeated runs passed106/106. The original105/106 run
stays failed evidence. This is an intermittent lifetime race, not a claim of
deterministic old failure. Final6's explicit peer-lifetime ACK still needs
its own new-cut gates and actual native acceptance.


The integrator's independent current-caller map a329992f confirms the absent
N1 production consumer, service FD roles, target-native packaging, sandbox
join and ready/stop lifecycle. Root read the full map and checked all10 source/
document pins; it is archived with the review evidence.

Configured WebTransport hot upgrades currently fail closed via
server.upgradeContinuityBlockerLocked; this is an explicit refusal, not silent
loss of its native UDP sockets. ACME and active-media cases also have explicit
continuity blockers. Complete configured transport/worker continuity remains
its stated product acceptance task.


### Completed independent Astra architecture checkpoint

The full312-line report45921355 and30-pin inventory are archived as
[the Astra architecture review](evidence/mesh-presence-2026-10-01/openbsd-n2-n3-entire-record-review-1.txt).
Root read all312lines and independently verified all30 pins. Its HIGH finding
is the post-COMMIT fallible all-shard resource setup. It supplies the complete
N2/N3 ownership boundary, true configured readiness/stop ordering, fixed root
namespace/helper/sandbox and mandatory service FD/capsule joins, before/failure
controls and actual installed rcctl/reboot journeys. This is a design review,
not a source grant, self-grade or current release acceptance.

Later S2 final2 writer receipt reports Physical180/180 in both modes, cross8/8
in both modes and all60 expected production probes. Store208 both/check3/cross8
both pass; final consumers/named Services gates and independent full S2 source
review remain separate. The original final1 failed run remains preserved.

N1 final6 host gates are all terminal green with106 ordered root passes in each
mode and zero skips/failures. Root verified the1559source/tar entries, nine raw
gate hashes and12 binaries and approves the test-only peer-lifetime repair for
bounded native execution. Its actual native result remains pending.

### Later independently verified results and additional lifecycle finding

The preceding pending statements describe their original checkpoints. N1 final6
native execution is now independently verified: Debug and ReleaseSafe each have
106 ordered module passes and2 CLI passes, zero failures/skips. Root checked
all four raw hashes and ordered outcomes, all eight1559-row source checks and
eight17-row artifact checks, nine original/preserved binaries and all75 evidence
inventory hashes. This accepts the bounded transport leaf, not installed-service
operation or the current combined daemon. Earlier failed runs retain their grade.

Root also independently observed the owned VM and pidfile absent, port2225 free,
runtime image idle, and all three foreign VMs unchanged by exact argv/starttime.
The journal places guest-directory absence before shutdown. Cleanup's exit1
remains recorded: its final observation read a pidfile already removed by QEMU.
Independent subsequent observations establish cleanup without rewriting that exit.

All S2 final2 writer gates are now terminal green: Store208/208, consumers374/374
and Services571/571 in each mode; Physical180/180 in each mode, all60 production
probes, check and OpenBSD cross-builds. Fresh paired source review and actual
native execution remain pending. These counts do not establish live activation.

Astra identified another actual lifecycle edge, independently confirmed by root
at native_bootstrap.zig:243–245: after receiving COMMIT and disarming descriptor
custody, the child waits for parent exit using the old pre-COMMIT deadline and
can exit124. A valid late COMMIT can therefore terminate the adopted child.
The coherent lifecycle change must eliminate this post-COMMIT cancellation edge
while preserving parent-exit ordering and proving delayed-COMMIT behavior.

The fresh independent paired S2 source review cd1e6fd6 approves its bounded
constructor/census/loan/abort/destruction foundation. Root read the full147-line
review, independently checked its artifact evidence and the staged962-file source
and exact12 native artifacts, and granted the reviewed native execution recipe.
Actual native results remain pending; S3/live publication is still unaccepted.

Astra's definitive659-line dormant runtime contract2, 0ccb9068, fixes the earlier
ambiguous local pool release: one main-owned opaque Gate owns every prepared
worker handle and releases all participants through one decision event after
the full ownership publication. Root verified all39 repository and3 SDK pins.
Production ownership is now assigned for the Gate/pool leaves and actual
main/Server/native-bootstrap transaction. Complete configured companion state,
listener transfer, pause/resume and service readiness remain part of that coherent
integration; these grants do not constitute implementation or acceptance.

The subsequent actual S2 native run fails the required combined acceptance.
Debug Store208/208 and CLI2/2 pass, but Physical's imported Server SESSION DROP
test crashes in stack_probe at the normal8192KiB stack, before the S2 controls.
ReleaseSafe completes Store208/208, CLI2/2 and Physical179passes/1skip/0failures
of180, including all15 named S2 controls. The skip is an existing explicitly
Linux-only active-client gauge test with raw Linux socketpair calls. Root read
the actual raw logs and both source bodies. This is not a proven S2 production
defect, but the required native Debug/ReleaseSafe scope remains RED. Preserve
both results; heap fixture ownership and actual gauge-test syscall portability
need reviewed fixes and a fresh frozen cut, without stack increases or filtering.

Root independently reviewed Astra's entire frozen Gate/Pool source and tests, all963 source pins,11 raw logs,8 artifacts and40 production probe source/log hashes and intended diagnostics. The bounded leaf source is approved: host Debug/ReleaseSafe85/85, check3/3 and OpenBSD cross8/8 each. Actual OpenBSD execution remains pending. The causal old/new controls demonstrate the injected second-spawn boundary; they do not establish full daemon preservation. Main configured-owner completeness, serialized coordinator use, whole-candidate abort/join before context destruction, single post-publication release, retained companion state and OLD pause/resume remain required integration obligations.

The six Server fixture repairs and actual socket portability fix now have host Debug/ReleaseSafe181/181 with zero skips. The earlier interrupted ReleaseSafe exit143 remains preserved; its distinct retry passes. Root source review confirms test-only ownership and exact inverse reconstruction of the old frozen Server. A repaired combined native package is being prepared; the original failed native acceptance remains RED until independently verified fresh native execution.

The renewed whole-record integration audit found another real owner omitted from contract2: geo_services.Service owns a lazy thread, FIFO and weather/news caches; Server creates it and command/MOTD paths start it. Its source and retained-state implementation are now assigned to the companion owner. Actual lazy-started versus unstarted state must be represented in the configured inventory, paused/captured or explicitly refused before COMMIT. Gate leaf tests cannot establish this completeness.

Root inspected the repaired S2 native operator and full recipe, independently verified962 frozen source hashes,962 tar member bodies and all24 original/preserved binary paths. The exact repaired native recipe is granted for the owned OpenBSD VM with immediate custody preflight, normal8192KiB stack, Store208/Physical181/CLI2 per mode, zero skips and verified cleanup. Execution and independent outcome review are pending; the previous native RED is retained.

The repaired S2 native cut now passes independently verified OpenBSD7.9 Debug and ReleaseSafe at8192KiB: Store208/208, Physical181/181 and CLI2/2 per mode, zero failures/skips. Root checked every ordered outcome, all original180 Physical names/order plus the extra adjacent two-reactor SESSION DROP, formerly skipped gauge actual OK in both modes,11544source proof rows,144binary proof rows and12payload proofs. Guest absence preceded owned shutdown; root independently verified PID/pidfile gone, idle image, free2225 and foreign3 unchanged. This approves the exact bounded repaired S2 foundation; it does not establish complete production/runtime acceptance.

Astra's fresh242-line full integration obligations review9c01b5c4 and28observed source/document pins are archived and root-read/verified. It adds source-backed ACME nested-child/publication closure, dynamic lazy-owner membership freeze and producer-before-consumer stop ordering to the existing late-COMMIT/current/typed-descriptor obligations. Current combined daemon/N2/N3 acceptance remains BLOCK pending those actual joins.

The corrected appended GEO Gate cut is independently source-approved (root6ee4fa95). Root verified all963source hashes, the complete single-file delta, every intended production API diagnostic, receipt log/probe inventories,12original/copied native artifacts and963tar bodies. Host Debug/ReleaseSafe87/87, check3/3 and OpenBSDcross8/8 both. Generic Actor threads verify GEO slot mechanics; actual geo_services and native execution remain separate. Initial test-pointer-coercion compile failures stay preserved.

A new actual OLD fabric control is RED71/72 with one intended failure: after real first fabric allocation OOM, runThreaded silently served41candidate bytes on its shard0 fallback. Root read the whole regression and production fallback, verified991source/log/binary. Its OLD control is a registered TCP client; candidate input is a separate actual socketpair, so full inherited attachment/OFD rollback is still unproved. Production transaction repair is with the sole integrator.

Webpush exclusive ownership transferred to Astra from its preserved uncompiled draft; reusable Pause and other companion owners remain with the companion writer. The source audit found a dropped404/410 outcome on allocation failure; the assigned fix reserves outcome custody before network attempt/removing a job. This is work in progress, not accepted delivery/state continuity.

### Root reconciliation of the latest core and causal fixtures

Root rehashed all 1,951 canonical evidence entries without a mismatch. The
inventory uses both repository-relative and inventory-relative paths; each was
resolved according to its recorded form. Historical failures were retained.

Root independently checked all 992 NEW core source pins (manifest e30ff020,
Server 0f864b31), read the production diff and verified the entire trailing
causal fixture is byte-identical to OLD (39ac594b). Its Debug result is 73/73.
The production change prepares complete fabric before workers, rejects startup
failure rather than running shard zero, and joins reactor workers before shared
semantic teardown. Main remains unintegrated. A latched activation flag must
also be joined to current run/stop authority before publishing service readiness;
this concern was sent to the integrator. No complete source or native grade is
issued from this narrow regression.

Root checked all 991 corrected late-COMMIT source2 pins (cec30d88), read its
actual nested-process fixture and confirmed the OpenBSD Debug artifact build
passes 8/8. Production still contains the OLD post-COMMIT exit124. The fixture
now gives the candidate its own bounded watchdog and requires a survival ACK;
the observer never sends a termination signal to an orphan PID. Its empty
legal descriptor set proves only the barrier, not full daemon adoption. Actual
native execution and the required raw exit124 before-control remain pending.

Root independently source-approved Webpush final1 (8aba2642 / 964-file manifest
9e0cde12). All source, 37 evidence files, five logs, eight intended production
probe outcomes and 16 original/copied artifact paths were checked. Host
Debug/ReleaseSafe each pass 89/89. Actual worker pause follows complete crypto
and guarded-resolution refusal; 404/410 custody is a direct helper test. Native
execution, remote delivery and main's OpenBSD enablement remain separate. The
source now preserves exact queued jobs on metadata admission OOM and retains
404/410 endpoint custody without a post-delivery allocation.

The actual OLD late-COMMIT barrier is now independently reproduced on OpenBSD7.9
at normal 8192 KiB: 71/72 module passes, zero skips, sole intended failure with
raw wait status 31744 (exit124); CLI2/2 passes. Root checked all 88 evidence files,
3,964 source proof rows and 12 binary proof rows with exact names/order. Guest
absence preceded shutdown; owned PID/image/port and foreign identities were
independently checked. The production post-COMMIT deadline termination has been
removed in the integrator's draft; unchanged-regression NEW gates/native
acceptance remain pending. This barrier fixture has an empty legal FD set and
does not establish full daemon adoption.

Root independently approves the exact late-COMMIT barrier repair: NEW manifest
952a0f49 / bootstrap8f75d5dd differs from OLD only by removing expired preparation
deadline termination after authenticated COMMIT. The entire process fixture and
72 ordered test identities are unchanged. Actual OpenBSD7.9 Debug/ReleaseSafe
both pass 72/72 module + 2/2 CLI, zero skips, normal 8192 KiB stack. Root checked
114 evidence files, 7,928 source proof rows and 48 binary proof rows, with actual
owned cleanup and foreign identities unchanged. This closes the specific
post-COMMIT exit124 defect; it does not establish full configured daemon adoption
or original attachment continuity.

## Latest custody and listener reconciliation

The N1 already-held lease join is independently source-approved at native_service
97601e67, full 991-entry manifest3f13d0ab. Root read the complete delta and actual
namespace walk, directory identity, lease exclusion and endpoint rollback. All
991 pins, seven terminal result/log pairs and eight artifact hashes/sizes match.
Host Debug/ReleaseSafe each pass109/109 under root, zero skips; ordinary runs
pass91/109 with18 root skips; OpenBSD artifact builds pass8/8 each. Failure
preserves the original namespace/lease descriptors and exclusion; success
consumes those same descriptors once. The positive fixture uses a unique
protected namespace through the private checked constructor. Fixed production
namespace, native execution, real helper/main launch and service readiness are
not established by it.

Core5 retains the production source of core4 and strengthens the allocation
failure control: every injected fabric failure retries successfully on the same
Server with its original listener, port, reactor identity and run authority.
Root rehashed all992 source pins and the three terminal logs: Debug/ReleaseSafe
78/78 and check3/3. The actual APIs separate resource preparation, parked workers,
publication, one Gate release and execution; current activation checks run/stop
authority and a successful backend turn on every shard. The standalone reactor
wrapper is not the full main/companion transaction. Actual main must serialize
stop against service status publication and settle companion producers before
reactor teardown. Native core5 acceptance is recorded below.

History's real IPv4/IPv6 retained-listener test found that NEW duplicate cleanup
called shutdown(RDWR), disabling OLD's shared socket. OLD iteration20 passes
87/88 and fails original SO_ACCEPTCONN. The sole saved source correction removes
shutdown from reference cleanup. NEW iteration22 passes88/88, including a real
authorized TLS GET on the resumed original listener after NEW abort and refusal.
Root checked both saved sources, logs and binary hashes. The successful binary
path was reconstructed from the compile artifact timestamp rather than captured
at execution; this limitation remains explicit. These moving Debug iterations
are not a frozen whole-companion or native acceptance claim.

The actual helper is now being implemented by Astra in its exclusive leaf files;
the integrator retains main and service ownership. The full installed service
journey, active media/TLS state continuity, ordinary far-node traffic and durable
authority remain open. All92 primary outcomes and25 explicit document cuts remain
in the requirements inventory; this record review does not claim a fresh current
acceptance audit of every outcome.

## Current review addendum: packaging and managed policy

Root repeated the complete canonical evidence hash check: the initial2,015
entries match. Twenty additional source manifests, receipts, failed builds,
causal controls and independent reviews bring the inventory to2,035. The roadmap
hash still matches the92-outcome requirements inventory, and all25 explicit cuts
remain represented. No full-port completion is inferred from this reconciliation.

Fresh Astra packaging review identified three concrete defects. Stock rc.subr
initialization evaluated flags before the script could reject them; the saved
causal control executes the marker before refusal. A restrictive umask installed
the helper without nonroot execute permission. Separate package reference
installers could race the permission finalizer, while the daemon's directory and
executable also retained masked permissions. Source5 repairs these through the
functions-only rc.subr import, explicit dispatch, one shared installer per artifact,
and final permission steps ordered after installation. Earlier failed source2/4
reviews and the source3 build error are retained.

The exact972-file source5 cut passes package and release together13/13 under
umask077. Root and Astra independently checked ten installed modes, four file
hashes and two actual nonroot execute-permission controls. The package contains
the OpenBSD rc.d script and no systemd unit. The25 dispatch controls are host
harness evidence using substituted primitives; they do not establish native
ksh/rcctl behavior. The binaries are cross-compiled historical helper9 artifacts,
not the moving Reply2/helper/main composition. No service.nscf provisioning or
actual installed lifecycle/reboot journey has been accepted.

Root separately source-approved policy2's mandatory managed execution context
and strict snapshot at993-file manifest eabae62edfb5. All source pins, seven
terminal result/log pairs and six cross binaries match. Root host Debug and
ReleaseSafe each pass119/125 with six OpenBSD-only helper skips. Actual executable
paths occur in the original build logs; original and retained bytes were rehashed
after terminal execution. Their hashes were recovered afterward, rather than
captured at execution time. This qualification survives the acceptance summary.
The codec joins selected policy to actual IDs, groups, routing table, working
directory identity and all nine limits, and refuses missing/old/truncated state.
It does not establish a production executed-context caller or service readiness.

Astra also identified that existing-owner service replies lacked the complete
selected policy identity. A separate Reply2 commitment and preparatory main cut
are now under implementation and verification. The accepted policy2 codec is
not borrowed as acceptance for those newer cuts.

The frozen companion candidate3 has terminal host/cross receipts, but fresh
independent source review and native/composed activation remain pending. A
separate bounded media DTO slice now preserves DTLS/SRTP replay, nonce, binding
and retransmission authority. Source inspection found no remote ICE password or
consent transaction/timer authority in the current endpoint. Restored addresses
must not acquire invented healthy consent state. Binding recency exhaustion
also requires a persistent fail-closed latch at both DTLS export paths. Active
transport refusal guards remain until real composed continuity is established.

The next acceptance boundary remains the complete main/companion/service
transaction, followed by actual installed OpenBSD lifecycle and retained active
transports. Durable failed/ambiguous append, cold recovery and ordinary far-node
presence/direct-message acceptance remain open. The owned VM is off and
unreserved; no deployment or push has occurred.

Core5 now has independent native acceptance for its exact bounded controls.
OpenBSD7.9 Debug/ReleaseSafe each pass78/78 module and2/2 CLI, zero skips, normal
8192KiB stack. Root rehashed119 evidence files, matched7,936 source proof rows
and48 binary proof rows with exact identities/order, and verified actual owned
VM3935496 cleanup plus all three foreign identities. Guest absence precedes
shutdown. Original physical-attachment handoff and the complete configured
main/companion/service transaction remain separate requirements.

Root added a separate OpenBSD helper build/install step to build.zig. It stages
the non-setuid helper in libexec with ReleaseSafe, stripping and required libc;
package includes that artifact only for OpenBSD and systemd only for Linux.
The default daemon install is unchanged. On the frozen historical helper
iteration9 plus only this build delta, the actual helper target passes3/3 and
the Linux target refuses with exit1 without installing a helper. Astra freshly
reviewed all968 source pins and the bounded build delta. This is build routing
acceptance, not current combined-source or full package/rcctl acceptance.

## Further record review: policy provisioning and terminal service lifetime

The pure-Zig policy compiler accepts strict, complete JSON and publishes
canonical NSCF with mode0600 through exclusive atomic publication. Unknown,
duplicate and missing fields fail; all nine limit rules are mandatory. Existing
files and symlinks are preserved. File syncing is implemented; directory
durability after power loss is not claimed. Frozen source2 has973 source pins.
Debug and ReleaseSafe each pass2/2 tests, including allocation failures and actual
publication/no-overwrite controls. Host CLI controls and the OpenBSD asset build
pass; the Linux policy target refuses. Fresh Astra review2 approves the bounded
compiler/build change. Root's package/release process43859 terminates0 with16/16
steps under umask077; all five installed file hashes and modes were recorded.
This cut composes historical helper14, not the later helper/main/stop-ACK
transaction. Actual OpenBSD policy publication and installed lifecycle remain
pending.

Root reviewed helper production and found a native test oracle race:
Child.deinit could reap the child before the test's second wait. Iteration15
uses an independently owned EOF/release barrier and checks the original absolute
deadline on every interrupted fixture receive. Production outside that exact
test block remains byte-identical to13. Root independently verified968 source
pins, seven terminal log/result pairs,12 original/copied artifact pairs and40
expected production probe outcomes. Debug and ReleaseSafe each pass80/86,
with six native-only skips. Root review2 approves native campaign preparation;
this is not target execution or whole-main acceptance. Historical failures and
the production-equivalent13 Services/sandbox results keep their original labels.

Managed-entry source5 has separate terminal preparatory-main and Reply2 gates.
Its source-derived policy commitment and executed-context validation do not
establish actual configured-runtime current publication or complete shutdown.
Root separately read the complete preparatory source5 delta and checked993
frozen source pins,12 terminal log/result pairs and12 artifact hashes. Main tests
pass5/5 in each mode; actual root N1 tests pass121/127 with six native-only skips
in each mode. The bounded preparatory change is approved for further integration;
this approval does not grade the future configured-runtime transaction.
Astra's terminal-stop design review identifies a lifetime seam: releasing the
endpoint before the helper receives stopped loses the result, while holding
the lease indefinitely deadlocks the helper. Selected NSAK1 joins the full
original stop request and selected policy without a new serial. Actual graph
cleanup/detachment must precede stopped; a separate outer control worker retains
the result, listener and lifetime lease through authenticated ACK. Helper
recovery retains the authenticated result before ACK and uses actual lease
exclusion under the original mutation lease/deadline. Implementation is assigned
to existing non-overlapping owners; the design is not runtime proof.

The media audit produced real causal failures: authenticated SRTCP duplicates
were accepted and DTLS1.2's75-byte final flight did not fit its64-byte cache.
Separate SSRC replay histories and a source-derived flight capacity are being
repaired and tested. Binding counter exhaustion needs a retained denial latch.
A certificate rebind can retain a stale verification verdict; actual mutual
handshake controls and a bounded repair are assigned. Existing live SRTP
stream/SSRC ownership LRU eviction also needs a replay/lifetime audit. These
discoveries do not close active transport continuity or permit removal of its
refusal guards.

Every primary requirement and explicit document cut remains represented.
Frozen source/build evidence, native bounded controls and whole configured
runtime/installed-service acceptance remain separate. Full-port acceptance,
durable failed/ambiguous append and cold recovery, ordinary far-node presence,
and remaining outcomes are open. No production deployment or push has occurred.


## Latest reconciliation: actual helper failure, stop ACK and media callers

Root rehashed all2,118 existing canonical records without a mismatch, archived
115 additional immutable records, then rehashed all2233 entries without a
mismatch. The requirements inventory still contains92 unique primary outcomes
and25 explicit cuts. This is record reconciliation; a fresh current-source and
runtime audit of each outcome remains open.

The bounded NSAK1 cut has993 verified source pins. Normal Debug/ReleaseSafe
runs pass73/74 with one root-only skip; actual root runs pass74/74 in both modes,
zero skips. Of these74,71 are import-only and three are substantive ACK
controls. Complete original/preserved executable hashes match the recorded
pre-execution hashes. Strict full-request/policy matching, real root credentials,
SCM disposal, duplicate ACK and held lease controls are covered. Actual graph
ready/stopped is still a test-only lifecycle fixture. The separate outer control
worker and real configured graph cleanup must be integrated before service-stop
acceptance; this codec does not establish that boundary.

The first actual helper15 campaign FAILED at actual-su-valid with InvalidWire.
The preceding spec-valid passed; every later helper, policy, allocation-failure,
module and CLI control was NOT EXECUTED. Root checked16 terminal status/log pairs,
the actual guest restoration receipt, public-only fetched archive and owned
VM3983317 absence. Temporary account/groups and login configuration were restored;
private backups were removed before guest deletion/shutdown. Foreign VMs retain
their exact identities. The failed campaign remains failed evidence.

Its root-owned payload executable files were mode0700; the runner only changed
containing-directory permissions. This blocks the selected nonroot child and is
consistent with the observed channel EOF. Child stderr is unavailable because
the helper redirects it to /dev/null, so a sole-cause claim still needs the
permission-only target control. Root reviewed the corrected retry: all1,963
payload entries and1,964 tar entries match; only runner permissions/access probes
and documentation change. All source/executable bytes remain identical. A stale
runner hash in the initial recipe was corrected with the superseded proposal
preserved. The literal selected-user access probe follows the official
[OpenBSD su argument contract](https://man.openbsd.org/su.1).
Astra alone received the exact isolated native retry grant. Copy/fullACK then
FAILED before campaign execution: the inner expected-SHA256SUMS still names the
original runner/documentation, although the outer manifest/tar correctly pins
the changed files. Root outer-hash review missed this inner-ledger inconsistency.
No run stage, temporary identity or login-class mutation occurred. Guarded pre-run cleanup is now terminal0: actual account/group/class and fixture
state absence were checked, the public failed-copy log was fetched, guest
absence preceded shutdown, and root independently checked VM3989657/pidfile
absence, idle image, free port2225 and all three foreign identities. Normal
post-run restoration markers were not fabricated for this state. A new permission3 preparation must
verify every inner ledger against its actual bytes before another grant.

Root independently confirmed two actual authenticated RTP/SSRC eviction failures:
72/74 controls pass, with replay of the first stream accepted after the ninth
stream and foreign ownership accepted after257 claims. The selected repair keeps
live ingress/ownership histories without eviction, authenticates tentative
state before publication and preserves state on refusal. Source-owned256-entry
storage is not proof of complete configured physical capacity.

Frozen active-media DTO final1 has964 source pins verified. Focused Debug and
ReleaseSafe pass104/104, check3/3, media Debug356/356, and both OpenBSD artifact
builds8/8. Media ReleaseSafe failed during compilation with DiskQuota; no runtime
or code acceptance follows from that failure. The complete ten-file source
review, aggregate/native transport continuity and active guard removal remain
unaccepted. The null-DTLS-key caller path can select plaintext, and DTLS1.3 owner
selection is missing there. A separate actual caller repair must synchronize
current offered fingerprints, refuse known/expected denied DTLS contexts and
preserve same-key replay histories across denial/reapproval. Its causal build
also encountered DiskQuota; no before/after runtime result is claimed yet.

Actual companion readiness/stop requires source-issued producer fences and real
worker/queue/inflight custody. Mail currently discards configured failure-journal
append errors. The selected repair retains the failed job, original error and
reserved failure identity until the journal outcome resolves, without SMTP
redelivery on a journal retry. Ambiguous append must reconcile or remain
fail-closed; it cannot be silently treated as durable success. These requirements
remain integration work, not completion from a queue snapshot or pause flag.

DiskQuota also stopped ACK18 and the first configured-runtime construction gate.
Their original raw failures are preserved. Root verified an exact proposed
cleanup and its result:3,639 owner-only compiler intermediate files removed,
306,181,034bytes reclaimed; all11 retained executable hashes unchanged. Aggregate
disk free space does not establish per-user quota headroom. No shared/global
cache purge or broad test retry is authorized by this receipt.

The next concrete acceptance path is configured-owner construction/publication,
producer fencing and joined drain/cleanup, authenticated terminal ACK lifetime,
then installed native policy/helper/rcctl start/check/reload/stop/restart/reboot.
Complete active transport/physical ownership, durable failed/ambiguous append and
cold recovery, ordinary far-node presence and every remaining roadmap outcome
retain their separate acceptance. Full-port acceptance remains open. No production
deployment or push has occurred.


## Continued execution: storage recovery and actual construction frontier

The previous record-review turn made concrete progress: failed campaigns and
cleanup were reconciled, preparation defects were identified, and canonical
custody was verified. The full objective stays open.

Root has now checked scoped storage recovery after execution:13 standalone TLS
compiler objects removed453,814,456bytes,1,791 StopAck intermediates removed
183,206,932bytes, and seven media objects removed67,066,752bytes. All20/4/90
respective original executable hashes are unchanged. Separately39 owned media
build drivers were compressed from1,058,467,720bytes to159,620,859bytes. Root
verified every compressed hash and full decompressed original hash/size;51
actual test/cross binaries remain raw and unchanged. No frozen source, log,
proof or shared/global cache was deleted. An initial empty compression proposal
used the wrong executable spelling; the corrected inventory is explicit and
both observations remain in the record.

This restores enough quota headroom to attempt one compiler at a time. A new
cold configured-runtime cut adds actual synchronous bind-failure/refund and
unrelated UDP ownership controls to the original dormant-construction tests.
The exact first source1 compilation failed DiskQuota without executing tests;
its record remains unchanged. New Debug verification is assigned the sole
compiler slot; configured-current, graph settlement and stopped publication
remain separate unaccepted production requirements.

The permission3 native preparation corrects exactly two top-level ledger
digests, with all runner/source/executable bytes unchanged. Its read-only design
checks all18 top rows,969 helper source rows,973 policy source rows and every
regular tar member against actual bytes and baseline source/artifacts. Semantic
validation runs before boot. Preparation may reuse immutable file storage with
separate ownership for changed metadata; no new VM grant follows from that.

Source inspection also confirms OCSP/Webpush trust-anchor containers in main
lose their owning ArrayList while workers borrow DER slices. The main integrator
will retain typed container ownership through joined cleanup and free every
DER/list on successful, disabled and failed construction paths. This is a
source-grounded future repair, outside the current cold-construction cut.

The prepared media fanout controls use130 real UDP endpoints, actual authenticated
ICE bindings and RTP/RTCP datagrams. Target descriptor allowances are observed,
saved and restored only by the fixture. The old bounded64 forwarding behavior
must fail at its intended observable before product traversal changes. Full
crypto/aggregate/consent/native continuity and all active adoption guards remain
separate. No release, deployment or push occurred.


## Entire-record reconciliation: current native and causal results

The scope remains all92 primary requirements and25 explicit document cuts. Root
rechecked the requirements inventory against its original roadmap digest and
rehashed all2,243 prior canonical entries with zero mismatches. Another176
immutable records now preserve actual construction failures, media causals, the
independent Astra snapshot finding and the latest native run. The canonical
inventory contains2,419 entries. This is a record review; fresh current-source
and runtime acceptance of each requirement remains open.

Permission3 fixes the two inner-ledger digests without changing helper15 source
or executable bytes. Actual guest checks pass18 artifact/top rows,969 helper
source rows and973 policy rows. Actual selected su identity, supplementary
groups, routing table, working directory, all nine limits, preflight allocation
failures and native policy publication/refusal controls execute successfully.
The module Debug runner completes85/86, zero skips, with InvalidWire in the
first lost-mutation-reply case. Clean control-channel EOF is classified as
malformed wire and bypasses the existing transport-loss recovery. Later cases
in that test, ReleaseSafe and project CLI runners are unexecuted. The separately
executed helper CLI control must not be confused with those project runners.
ACK18 already changes EOF classification but also adds NSAK recovery; it is a
different ungraded native candidate. Neither cut establishes the managed daemon
or installed rcctl lifecycle. Root independently verified real restoration,
guest absence before shutdown, owned VM3997220 absence, idle image/free port
and all three unchanged foreign identities.

Cold configured-runtime source2/3 fail compilation at explicit pointer/bind
fixture seams. Source4 executes74/80 with six failures: configured RDNS already
binds its Io in construction, then cold preparation repeats strict bindIo.
DNSBL has the same source seam. Strict bindIo remains strict. The source-owned
prepareIo correction confirms the exact userdata/vtable under its mutex only
while pristine; used pause epochs and actual entered/joined workers still
refuse. Its focused Debug passes75/75, including three new substantive controls.
Root rehashed all964 pins, actual log and original executable. Cold5 composition
and broader critical/native gates remain pending. Source4's306,037,781-byte
executed test is preserved by a verified hardlink to its original; the obsolete
root duplicate alone was removed with an explicit relocation receipt.

Media dispatch before2 executes72/77 with five intended failures. Three use
genuine mutual DTLS handshakes with the actual production selector: stale
current fingerprint remains ready, denied DTLS12 becomes not_dtls, and the
supported DTLS13 owner is ignored. These establish selector behavior, not
actual plaintext packet egress. Two complete UDP pump controls authenticate130
ICE bindings each and observe only64 byte-exact RTP/RTCP deliveries. Saved
NOFILE remains524288/524288 and is restored. Root verifies all964 source pins,
raw log and both original/preserved test hashes. Complete traversal and actual
encrypted/denied packet dispatch require corrected production gates.

Astra's independent complete2,909-line media DTO review blocks final1: retained
accepted ingress replay state is not joined to its exact same-peer SSRC owner.
Deleting or retargeting an owner passes snapshot validation by source inspection.
A genuine protected-packet before control remains required before this finding
is described as an executed failure. Outbound recipient histories need their
separate valid semantics. Active aggregate-adoption guards remain enforced.

Main's OCSP/Webpush trust-anchor container ownership draft retains each DER
and its ArrayList through worker stop/join and frees disabled/error paths. Root
read the full draft; the three focused ownership controls and combined gates
are pending. Actual producer fences, failed/ambiguous mail journal custody,
complete configured readiness/stop/Helix, installed native service/reboot,
active physical/transport continuity, durable cold recovery and ordinary
far-node presence/direct delivery remain open. No deployment or push occurred.

## Entire-record reconciliation: construction authority and actual ownership controls

Root rehashed all2,419 previous canonical records, then archived39 additional
immutable records and verified all2,458 entries with zero mismatches. The scope
remains all92 primary requirements and25 explicit cuts. This custody review
preserves failures and exact artifact boundaries; it does not establish fresh
current-source or runtime acceptance of every requirement.

Cold5's996-file composition fails in the build configurer with DiskQuota/ABRT;
no module or test runner executes. Read-only kernel quota inspection confirms
only2 KiB of per-user temporary byte quota remained despite aggregate filesystem
headroom. Scoped lossless compression of four terminal configurers and39 terminal
test executables restores1,144,166,400 bytes of quota headroom. Root independently
verifies every decompressed original hash and custody mapping. Original causal
executables, sources and logs remain preserved. The separate77-file failed-copy
archive also passes independent content, mode and size verification.

Astra's independent cold5 review blocks four concrete seams: Webpush's demanded
2 MiB thread stack differs from registered default options; failed candidate
teardown can stop a borrowed unrelated RDNS owner; retained Server/reverse aliases
expose release and destruction authority; and policy comparison omits security
and worker settings. Seven old-implementation causal controls are prepared but
not executed. The selected correction gives runtime construction ownership of
cold companions and immutable resolved policy, keeps Server inside a private
source-owned ManagedCore, and separates complete spawn/release/cancel/join/destroy
Control authority from borrowed opaque View observations. The actual main consumer
must use the factory. The coordinated implementation is underway and unaccepted.
Root's review additionally requires removing owner-pointer observations and
validating source-demanded reactor options before any pool mutation or spawn.

The Sfu ownership finding now has actual packet evidence. Before2 executes72/78
with six intended failures: four malformed restored graphs grant foreign
protected RTP/SRTCP ingress, and two orphan owners are accepted. Genuine original
foreign-peer denial precedes each malformed restoration. The exact one-file
repair joins accepted ingress replay state to the same peer's SSRC ownership in
both directions while preserving outbound recipient histories. Its unchanged
six causal controls and two additional roundtrip/rollback controls pass80/80 in
Debug and ReleaseSafe. Root verifies all964 source pins, both logs, original
executables and preserved same-inode hardlinks. This accepts the bounded Sfu join;
full media dispatch, aggregate adoption and native continuity remain open.

The complete packet-dispatch repair cut remains prepared and unexecuted. The
mail causal run executes72/74 with two intended failures after actual failed
append/no-row and actual sync-then-error/durable-row observations. Root verifies
all964 source pins, terminal log and original/preserved executable custody. No
mail production repair is accepted yet. These five additional records bring
the canonical inventory to2,463 entries, all rehashed with zero mismatches.
Native helper ACK18 also has a source-grounded query-send recovery concern;
its actual native recovery campaign remains unexecuted. Current daemon readiness,
joined stop, installed rcctl/reboot, active transport/physical adoption, durable
cold recovery and ordinary far-node delivery remain open. No deployment or push
occurred.

## Closed Gate/Pool authority: bounded acceptance

The amended Control/View leaf cut has independent root source acceptance and
actual Debug37/37 and ReleaseSafe37/37 terminal passes. Its explicit minimal
root harness excludes current Server/main/companion integration. Twenty named
Gate/Pool controls exercise release publication, real parked workers, cancellation,
exact handle joins, foreign authority, allocation rollback, identity exhaustion,
canceled unspawned rows and complete source-demanded reactor option validation.
Inherited imports and shard controls account for the remaining suite rows.

All996 baseline pins and23 explicitly added production probe sources are verified.
In each mode,22 probes fail at the intended inaccessible field/private function/
missing authority method and the legitimate operational caller compiles. Root
checks all46 raw diagnostic hashes and their specific failure reasons, plus both
original test executables and preserved same-inode hardlinks. These production
positives establish compilation; real worker behavior comes from the leaf tests.
The View returns neither owner pointers nor allocators/options. Pool validates
all source-demanded options before any state mutation or spawn. Only private
Control owns release, cancellation, join and destruction. Coordinator serialization
and owner lifetime remain mandatory.

Astra also independently approves the exact Sfu reciprocal ownership repair,
including actual six before failures and both80/80 repair runs. Final1's historical
BLOCK remains intact. Another138 archived records bring the canonical inventory
to2,601 entries; every entry is independently rehashed with zero mismatches.
The actual old-constructor seven-control attempt fails compilation solely at a
new test fixture's Linux child-exit symbol. No tests execute and no constructor
causal result is inferred; its corrected distinct test-only cut is next. Mail
retention and source fences, owned factory/private ManagedCore, actual main
consumption, full native current/stop/Helix and the complete92+25 scope remain open.


## Actual constructor failures and latest record reconciliation

Root independently verifies all996 source3 pins, the complete cache4 terminal
log, the executed original305,266,261-byte ELF and its retained same-inode
hardlink. The corrected fixture executes72/79, with zero skips, leaks or log
errors and exactly seven intended runtime failures. Enabled Webpush refuses
its actual demanded2MiB stack; failed candidate teardown stops an already-running
legacy RDNS worker and a foreign-Gate RDNS worker; independent Mail verification,
OCSP interval and Webpush subject policies are wrongly accepted; an ordinary
saved Server pointer releases the actual parked graph. The last control observes
the child exit71, raw status18176, after real stop/join. These are defects in the
old constructor, not repair acceptance. The earlier Linux fixture compile errors
and subsequent DWARF DiskQuota abort remain separate preserved failed attempts.

The selected repair remains owned cold construction, complete immutable resolved
policy, a private ManagedCore and non-escaping Control authority, consumed by
actual main. Accepted Gate/Pool leaf tests do not grade that uncompiled integration.
A separate outer service control worker must preserve the authenticated stopped
result and lifetime lease until NSAK acknowledgement, after complete graph stop,
join and detachment. Actual native helper query-send loss controls are prepared
against unchanged production; they have not executed on OpenBSD. New Webpush
Control/View and Mail producer-fence/retention drafts are source-only.

Storage recovery preserves exact evidence rather than deleting it indiscriminately.
The failed in-place RDNS write encountered ENOSPC and truncated the file. Its
exact frozen body was restored, then the reviewed reconstruction was published
through a detached inode. The frozen source remains unchanged. Subsequent source
writes use exclusive temporary files, fsync and atomic replacement. Scoped
terminal compiler-intermediate removal and lossless executable/configurer
compression retain original hashes, full decompressed-stream verification and
custody mappings; an invalid unexecuted partial ELF is explicitly labeled so.
Root checks the latest898/19/2677 exact removed sets, all retained Gate and
Sfu/Mail raw executables and the later compressed driver mappings independently.
No shared/global cache, foreign process or unrelated source was removed.

Another79 immutable records archive the failed and executed constructor attempts,
read-only quota observations, scoped recovery proposals/receipts, RDNS incident,
helper/Webpush preparations and Mail recovery design. All2,680 canonical entries
are rehashed with zero mismatches. Inventory integrity establishes custody; each
oracle and whole-runtime acceptance keeps its own status. The frozen packet
repair now has a separately recorded cache-location revision after temporary
quota preflight refusal; its Debug run is active in a new repository-local cache.
No test result is inferred while that runner remains active.

The complete92 primary outcomes and25 explicit cuts remain open as an overall
objective. Current configured factory/main/service readiness, complete joined
stop and Helix, installed rcctl/reboot, active transport/physical continuity,
source-owned durable Mail recovery after process death, retained RVL2 custody,
ordinary far-node WHOIS/direct-message delivery, and remaining interoperability,
platform and benchmark acceptance still require their stated evidence. No
deployment, publication or push occurred.


### Durable cold Mail witness and subsequent compile-only result

Astra identifies a concrete design gap in the proposed Mail recovery owner:
a RAM-only preattempt prefix/packet/full-Job witness cannot survive process death.
The83-line cold amendment preserves that earlier proposal and requires durable
full-Job admission, submitted/uncertain phase, failure intent and atomic terminal
disposition in the same configured OroStore. An uncertain SMTP outcome must not
trigger automatic redelivery. Typed actual Server admission, source-owned Store
receipts, cold schema/migration and full owner lifetime remain implementation
joins. This is a corrected design obligation, not an executed new source defect
or accepted recovery. Root reads the complete amendment; no schema/source grant
or production write follows from the review alone.

Packet repair1 terminates1 at two redundant local imports shadowing its file-level
srtp declaration. No tests execute. Root reads the complete diagnostic and verifies
all964 repair2 pins and its exact two-line removal; repair2 Debug is active,
with ReleaseSafe still pending. No moving companion/Mail source enters that cut.
Eight further immutable records preserve these commands, failure, pins and Mail
amendment. The canonical inventory now contains2,688 entries, all rehashed with
zero mismatches. Full configured/native/installed-service and92+25 acceptance
remain open.


Repair2 subsequently terminates1 before tests at the sole adjacent redundant
srtcp local import. Root reads the complete diagnostic. Its distinct repair3
removes that one line, retains all prior cuts and is running Debug with
ReleaseSafe pending. Four more command/pin/failure records bring the complete
canonical inventory to2,692, rehashed with zero mismatches. These remain
compile-stage results without media runtime acceptance.


### Final independent Astra frontier reconciliation

Root reads the complete140-line Astra frontier review and checks its28 observed
pins, with moving observations explicitly distinguished from frozen acceptance.
The memo preserves all92 outcomes/25 cuts, actual seven constructor failures and
independent root Gate/Pool acceptance. It identifies owned factory/main and durable
Mail custody as the immediate coherent priorities; whole owner/backend lifetime,
producer settlement, hot rollback, terminal ACK and actual native installed-service
acceptance remain mandatory. Mail uncertainty resolution is still an unselected
product policy in the proposal. The memo issues no new production or release grade.
[The archived Astra review](evidence/mesh-presence-2026-10-01/record-review-14--001--record-frontier-review-2026-10-02-2.txt)
and its pin/root-check records bring the canonical inventory to2,695 entries.
All2,695 are independently rehashed with zero mismatches. Full-port completion
and the overall92+25 objective remain open.

### Complete record reconciliation15: actual host passes and caller blockers

The complete requirements inventory still matches its roadmap source:92 unique
outcomes and25 explicit cuts. The full record has been reviewed for scope,
chronology, source ownership and evidence custody. This does not establish fresh
runtime acceptance for every requirement; the requirements inventory retains
that obligation. Older native receipts certify their frozen artifacts only.
Fourteen entries lack a separate explicit acceptance field: X3 specifies kernel
features by platform, and N1–N13 are research/product rows requiring concrete
acceptance criteria and a current audit. Their specification text remains intact;
they are not silently treated as completed or removed.

Exact Store source3 has now passed all146 tests in both Debug and ReleaseSafe:
144 Store tests and2 import roots, identical ordered names, zero skips, failures,
leaks or log errors. Its seven new complete-epoch controls also pass separately
as8/8 in both modes. All964 source pins are independently checked before/after.
The complete successor is written and synced before namespace publication;
the snapshot covers OLD state and only the NEW epoch header. The full proposed
packet remains independently retained after poison, and final RAM publication
does not append or allocate. Unknown torn input is refused. Ordinary Store
regressions pass. Publication fault controls establish whole OLD-or-NEW cold
selection at injected seams; they are not power-loss or process-death evidence.

Astra approved the production delta in source1; source3 preserves those bytes
and adds requested empty/repeated publication and same-length corruption tests.
Complete-mode namespace substitution and further fault-retry controls remain
follow-up obligations. The mechanical stage is not an opaque Mail authority,
own-tail repair, sync-only terminal adoption, current consumer or native grade.
Mail still needs durable full-Job admission before SMTP, submitted/uncertain
state, durable failure intent and atomic terminal disposition in the same
configured OroStore. A crash cannot preserve an uncommitted RAM error. Typed
Server admission, schema, bounded chunk activation, source-owned lifetime and
an explicit uncertainty resolution policy remain unresolved.

Media repair4 now has fresh actual host Debug/ReleaseSafe80/80 each, with130
RTP and130 RTCP recipients per mode. Root and Astra verify all964 source pins,
18 evidence hashes and actual executed artifacts. Eight substantive controls
plus72 imports establish the bounded selector and full pump traversal repair.
All five original causal bodies remain unchanged. This supersedes the older
compile-stage and fixture failures for that cut; every failed run is retained.
The repair4 stale-cache run is explicitly excluded. The actual ReleaseSafe run
followed a failed chosen headroom preflight; its sequencing qualification is
preserved separately from its verified terminal result.

Astra identifies two unchanged HIGH source-backed caller gaps that block whole
media acceptance: the actual native-to-WebRTC callback sends canonical RTP
without the DTLS selector, and unbound or foreign-channel NACK requesters can
access the global canonical retransmit cache. These are source counterexamples,
not newly executed failures. Actual UDP and authenticated publisher before
controls are being prepared, including the real Server bridge adapter. The
repair must join requester/publisher channel authority and pump-owned protected
output custody; encrypting an unauthorized response would leave the gap open.

The frozen owned factory checkpoint has16 uncompiled controls and is not a
whole dependency composition. Its fallible table setup removes a source-level
allocation panic seam, but neither the constructor nor current main is accepted.
The integrator subsequently identifies private owner pointers escaping through
public participant specs and is closing that API. This later source work remains
uncompiled. Producer/worker/journal API copies likewise remain source-only.
No stop, drain, ready, hot, NSAK, native helper, installed service or active
capsule/physical acceptance is inferred.

Store preparation mistakes are retained: cross-device hardlink refusal,
unsupported global-cache CLI option, and a full-regression attempt whose
removed private configurer remained referenced by a stale cache index. Distinct
corrected commands pass after invalidating only ROOT's unique terminal cache
indices. Scoped recovery preserves raw ReleaseSafe binaries. The two ROOT-owned
Debug binaries were verified as actual executed/original same-inode retained
artifacts, then compressed losslessly with full decoded SHA verification.
Their current custody is compressed; the earlier raw paths are no longer present.
No shared cache, unrelated source, foreign process or VM was removed or started.

Next structural work is secure media callers and complete factory ownership,
then durable Mail settlement and actual main lifecycle integration. Native
context/helper/NSAK and installed OpenBSD acceptance follow that composition.
Retained RVL2/ACK cold custody, ordinary far-node WHOIS/direct-message delivery,
directory/presence contracts, remaining interoperability/platform/client and
benchmark outcomes retain their individual acceptance requirements. The
full92+25 objective stays open. No deployment or push occurred.

The [independent213-line Astra entire-record review](evidence/mesh-presence-2026-10-01/record-review-15--110--record-frontier-review-2026-10-02-3.txt)
and [root reconciliation](evidence/mesh-presence-2026-10-01/record-review-15--112--root-entire-record-reconciliation-15.txt)
are archived with exact source, failed-run, accepted-run and compressed-custody
records in the [record15 map](evidence/mesh-presence-2026-10-01/record-review-15-archive-map.json).
Root checks all36 observed reviewer pins:35 match, and the current report changes
after its recorded cutoff. That moving-document observation is explicitly retained.
Another113 immutable inventory entries bring the canonical total to2,808, all
rehashed with zero mismatches. No whole-product completion follows from custody.

Post-review source checkpoint2 removes the public participant-spec output and
constructs its fresh Control/View internally. Root checks the two frozen source
hashes, but the replacement remains uncompiled and main is not rewired. This is
progress against the confirmed checkpoint1 escape, not a fresh accepted closure.
It requires an independent source review and actual production refusal probes.


## Record16: actual caller failures and full physical ownership selection

The [record16 reconciliation](evidence/mesh-presence-2026-10-01/record-review-16-archive-map.json)
archives377 additional inventory entries. Root rehashes all3,185 canonical entries
with zero mismatches. This includes the actual media caller failures, frozen
factory checkpoints/probes, source4 Store controls and custody transitions.

The [exact media BEFORE3 log](evidence/mesh-presence-2026-10-01/record-review-16--128--media-caller-gaps-before-3-debug.log)
executes72/76 with four intended failures,
zero skips and no leak diagnostic. Authenticated native ingress reaches the real
Server callback: canonical RTP bypasses DTLS; a failed fingerprint still emits
UDP. After authorized encrypted positive controls, unbound and authenticated
foreign-channel NACK requesters receive cached packets. Root checks all964 source
pins, the complete log/receipt and the actual executed b0125258 ELF's retained
same-inode identity. Earlier headroom refusal and compile-only local-name shadow
failure remain retained. These are reproduced caller defects; no fixed media
composition has yet passed.

[Astra's119-line source review](evidence/mesh-presence-2026-10-01/record-review-16--178--physical-offer-semantics-review-1.txt)
selects simultaneous physical media endpoints:
one current offer per(CallId, full ClientId, leg). Root reads the full review and
checks all14 observed pins with zero mismatches. Both actual channel-member
attachments may OFFER without MEDIA JOIN; a same-owner reoffer replaces only its
own leg, and departure revokes only that owner's credentials. The roadmap does
not literally specify a UDP endpoint count; the actual accepting caller and
physical-authority contract establish this selection. Nick-wide overwrite would
preserve the deficient implementation and narrow attachment participation.

The structural repair also needs per-incarnation native stream/MAC capability,
conditional authority indexes, staged profile publication and pump-owned protected
output custody. Native capability delivery uses a distinct caller-only
NATIVE-MACKEY reply through actual secure signaling authority; targeting alone
cannot prove TLS. The final paired ABI and TLS/output staging remain under source
review. These selections are not implemented or runtime acceptance.

Factory checkpoint2 has bounded independent source approval for closing its
participant-spec owner escape. Checkpoint3 has18 uncompiled controls and24
unexecuted production probes(22 refusals, two positives). Main remains unwired.
Store source4 appends three controls to unchanged accepted production: foreign
inode substitution, six publication-fault recovery paths and empty-coverage
authentication. It remains source-only until exact gate receipts are collected;
the clean NEW test uses mechanical promotion pieces, not opaque Mail authority.

Custody now differs from older receipts: Store source3 Debug/ReleaseSafe and
media repair3/4 executed binaries are retained losslessly compressed with decoded
SHA verification. Their historical raw-path/same-inode receipts describe the
original execution time. Actual media BEFORE3's raw causal ELF remains retained.
Exact immutable source dedup and terminal owned-cache recovery have separate
receipts; shared caches and unrelated work were preserved.

The full92 outcomes+25 cuts remain open. Combined daemon, native helper/NSAK,
installed OpenBSD lifecycle/reboot, full attachment/Helix continuity and ordinary
mesh/durable authority acceptance are still required. No deploy or push occurred.


## Record17: Store execution and publication boundary

Store source4 now passes the focused host Debug/ReleaseSafe gates11/11 each and
the full minimal-Store gates149/149 each:147 Store tests plus two imports.
All runs have zero skips, failures, leaks and log errors. Root verifies all964
source pins and the actual executed binaries' hashes and retained same-inode
identities. Four lossless archive copies pass decoded SHA/size checks; their
actual raw original/retained files remain in the unique ROOT-owned /tmp tree.
Astra independently approves the three substantive source additions and verifies
unchanged production and144 prior tests. Fresh result review is requested; these
host tests establish no composed daemon, Mail authority or native service grade.
Deterministic publication faults return at actual syscall boundaries; they are
not kernel-error or crash campaigns.

The semantic review is119 lines. Record16's initial125-line count is a reporting
error; its exact body/hash and physical-owner selection are unchanged and a
separate correction receipt is retained.

Media draft5 remains a draft. All credential-bearing transport replies need
source-proven protected output admission before endpoint publication, including
ICE credentials and legacy SRTP group keys. Current labeled ReplyCapture can
silently overflow and defers TLS/SendQ emission until after OFFER returns;
ordinary caller-targeted sendMediaEventReply is therefore insufficient.
The repair needs staged final labels/framing/protected output and an allocation-
free joined authority commit. Public negotiation may remain available on plain
IRC, while secrets require actual secure signaling. Additive native MAC32 helpers
have a narrow grant with byte-identical legacy equivalence tests; no native wire
version change or completed media repair follows from that grant.


[Record17 archive map](evidence/mesh-presence-2026-10-01/record-review-17-archive-map.json)
adds39 immutable entries; all3,224 canonical inventory entries rehash with zero
mismatches. The92 unique requirements,25 cuts and unchanged roadmap source hash
are freshly checked. Fourteen entries lack a separate acceptance field; their
specification remains retained, and no completed runtime grade is invented.
Final media header/direction and fresh Store result review remain pending at this
cut. No whole-port completion, deployment or push is declared.


## Record18: entire-record reconciliation

The [fresh176-line Astra review](evidence/mesh-presence-2026-10-01/record-review-18--004--full-record-independent-review-18.txt)
reconciles the complete current report, port/continuation records, all92 requirement
texts, all25 document cuts and the latest exact reviews and receipts. Root reads
the full memo and checks all39 observed pins: zero mismatches at that cutoff.
This is record reconciliation, not a fresh source/runtime acceptance audit of
every requirement. Historical native campaigns retain their exact artifact grade.
No evidence loss or unsupported overall completion claim was found.

The scope remains92 unique requirements. The25 cuts are deliberate exclusions
and constraints, rather than25 additional unfinished features. Fourteen rows
have `accept: null` (X3 and N1–N13); their specifications and conditional research,
client and release boundaries remain intact. The requirements JSON now explicitly
marks its old frontier string as extraction-era metadata and points to this
report. Before/after copies prove every requirement and document-cut body is
unchanged. Service work labels N1/N2/N3 remain distinct from roadmap GAP-N1/N2/N3.

Fresh independent Store4 actual-result review7f911a08 supersedes record17's
requested-review status. All32 review pins match. Its focused11/11 and full
minimal-Store149/149 in both modes remain bounded host acceptance; opaque Mail
schema, typed admission, cold uncertainty and current/native consumers stay open.
Actual seam fault returns do not establish power-loss or process-death recovery.

Header11 (116d2f88), under parent contract537de41f, is the selected design:
all final labels/framing/protected output are prepared before the shared cut;
current full physical identity and candidate revisions are revalidated; accepted
queue/TLS/WS-tail and endpoint/profile/JOIN state publish together without
allocation, metadata free or syscall. Cleanup and SEND arming follow unlock.
The Source-only SendQ retained-metadata seam has independent approval; sensitive
WS cleanup, same-FD TLS epoch validation and actual Server/media caller integration
remain uncompiled moving work. No joined caller or configured runtime is accepted.

The four actual BEFORE3 security failures remain RED. Preserve their original
oracles and eight prior packet controls. Native per-physical master32 and the
four fixed direction/purpose subkeys are selected policy, requiring real client
support before activation acceptance. Existing frame/ONFB layouts and browser
MACKEY remain unchanged; this is no claim of old-client compatibility. ONFBv1
permits bounded repeated authenticated NACK/PLI under current route authority;
its MAC supplies no invented feedback freshness guarantee. Physical funding,
source lifetimes/fences, strict active DTO and ICE consent remain open.

The isolated codec actually passes12/12 Debug, zero skips/failures/leaks/log
errors. Root and Astra verify all964 source pins, ordered raw log9d201b12 and
executed c4fdf80a ELF with retained same-inode identity. The raw executable also
has an archive hardlink. ReleaseSafe observes303,951,872 available bytes against
335,544,320 required and refuses before launch. Full codec and whole media are
pending; this refusal is neither a compiler failure nor a runtime result.

Physical filesystem free space and UID quota remain separate observations.
Store4 physical-only preflights do not promise general quota headroom; its actual
successful gates keep their grade. Scoped BEFORE3 recovery removes892 revalidated
terminal intermediates and preserves its configurer losslessly with decoded
SHA/size mapping. The b0125258 actual causal ELF remains raw. Shared/global
caches, unrelated sources and foreign processes are preserved.

Two stale current-state claims are corrected: runtime pledge includes `unix`,
and target-aware packaging stages OpenBSD rc.d/helper/policy assets. Actual
managed sandbox consumers and installed rcctl lifecycle/reboot remain unaccepted.
The complete factory/main/owner transaction, producer settlement, native helper
EOF/NSAK recovery, joined stop/Helix, active transport adoption, durable Mail/RVL2
cold custody, ordinary far WHOIS/direct delivery, directory authority and remaining
platform/client/interop/benchmark outcomes still require their own acceptance.

[Record18 archive map](evidence/mesh-presence-2026-10-01/record-review-18-archive-map.json)
adds87 immutable inventory entries. Root rehashes all3,311 canonical entries with
zero mismatches and unique paths. Subsequent report/JSON metadata edits are
intentional changes after the review's observed cutoff; prior snapshots and
correction receipts are retained. No whole-port completion, deployment or push
is declared. The full objective continues.


## Record19: entire-record review and current execution boundary

The [fresh198-line Astra review](evidence/mesh-presence-2026-10-01/record-review-19--003--full-record-independent-review-19.txt)
reconciles the complete1230-line prior report, port and continuation records,
all92 requirement acceptance/specification rows, all25 deliberate cuts and the
latest source, execution and custody records. Root reads the complete memo and
checks all85 exact observation pins with zero mismatches before this update.
Both independently rehash all3311 prior canonical entries with unique paths and
zero mismatches. The older1313-entry SHA256SUMS is a secondary inventory; its
preliminary mislabel and corrected canonical check are retained. This review
establishes record reconciliation, not current source/runtime acceptance of
every requirement. All92 requirements and25 exclusions/constraints remain intact.

SendQ source2 now has independent source and actual-result approval: host Debug
and ReleaseSafe each13/13, zero skips, failures, leaks or log errors. Twelve
leaf tests plus one root import cover the exact frozen seam. Source1's12/13
failure remains preserved: the new ordinary-cleanup fixture omitted required
control credit. The four-line test-only repair uses the actual reservation API
and preserves production, prior assertions and the retained-publication control.
All964 source pins and original/retained actual executable hashes and same-inode
joins are verified. These passes do not accept a live TLS or MEDIA transaction.

The native MAC32 codec now actually passes focused12/12 and full89/89 in both
host modes. Full89 includes imported hash/secret/TOML tests. All964 frozen pins,
raw ordered results and actual executed/retained artifacts match. The previous
ReleaseSafe storage refusal remains an unlaunched attempt. The newer directional
key helper has965 verified source pins and four prepared test blocks, but remains
uncompiled. Actual fresh entropy, endpoint stream issuance, secure key delivery,
current consumers and real client support stay open.

Astra finds a verification routing omission: isolated cadence_frame and
native_feedback edits selected no runtime gate. Cut3 now selects critical
full-module and media gates for both codecs and media_capability, retaining the
existing Store/Physical/output routes and media ReleaseSafe coverage. Its12
Python unit tests and toolkit validation pass. Fresh Python specialist review
independently approves the exact two-file routing change and repeats those
checks; root verifies its three source pins. This is bounded tooling acceptance;
the selected Zig gates have not thereby run.

WS source3 has independent approval for sensitive allocator cleanup and meaningful
growth/OOM test preparation. At Astra's cutoff it is unexecuted: proposal1 has
an unsupported build cache option; proposal2 corrects the environment but proposes
a lower storage floor and is rejected; proposal3 restores335544320 and observes
329625600, refusing launch. All proposals are retained. After that cutoff, two
historical Auth-owned terminal build configurers are retained losslessly compressed
with full decoded hashes, fsynced mappings before raw unlink and all24 product/test
ELFs unchanged. Root verifies both decoded streams again. A separate Debug-only
WS grant follows a fresh361283584-byte preflight; the resulting Debug campaign later terminates1:9/11 passes, two failed growth
controls, zero skips, one leaked test and five log errors. Root reads the full
raw log and verifies all996 source pins plus both actual/retained artifact pairs.
Actual11 comprises seven WS, three imported filtered SendQ tests and one root;
the proposal expected8 and provisional parser row count0 are incorrect and
preserved separately. The first failure is a growth-shape precondition; the
second is a growth-free assertion before fixture cleanup ownership, producing
leak diagnostics. SDK geometry and test cleanup are under independent review;
no production-cause or repair acceptance is inferred. ReleaseSafe is not launched.

Seven older terminal causal ELFs also have verified lossless compressed custody;
root fully decodes each and checks the current raw BEFORE3 and codec artifacts
remain unchanged. Historical raw-path receipts describe their original execution
time. No shared/global cache, unrelated source or foreign process was removed.

The four actual media BEFORE3 security failures remain RED. Whole physical
ownership/funding, final protected signaling and authority publication, source
FIFO/producer fences, joined teardown, strict active DTO and ICE consent remain
required. The actual factory/main/service transaction, native helper EOF/ACK
recovery, installed rcctl/reboot, durable typed Mail/uncertainty/cold recovery,
RVL2/EventSpine custody, far WHOIS/direct delivery, account directory and remaining
platform/client/research/interop/benchmark outcomes keep their own acceptance.
Historical native successes remain attached to their exact frozen artifacts.
The full port remains open; no deployment or push occurred.


[Record19 archive map](evidence/mesh-presence-2026-10-01/record-review-19-archive-map.json)
adds161 immutable inventory entries, including its map, after preserving all3311
prior entries. Root rehashes all3472 canonical entries with zero mismatches and
unique paths. Actual failed WS execution, its raw executed binary, cutoff review,
corrected routing, refused proposals and lossless custody remain distinct.
Current report/requirements metadata changes follow the review cutoff; their
prior and intermediate bytes are preserved. The full objective remains open.


The [91-line independent WS failure review](evidence/mesh-presence-2026-10-01/record-review-19-supplement--source-3-aftercut-failure-independent-review.txt)
now explicitly corrects the earlier132-line source review's SDK geometry. Root
reads all91 lines and checks all22 exact source/SDK/result pins. This target has
128-byte cache lines: initial line capacity413 and span capacity9. The chosen
412-byte line and six frames cannot prove their replacement. The allocation-
failure helper stops in its unlimited success census, before any injected index;
a success-path assertion before cleanup ownership produces the leak diagnostics.
Sensitive growth/OOM acceptance is BLOCKED. This run establishes fixture/oracle
errors and no production framing/wiping defect. A new test-only proposal is
prepared but unreviewed, uninstalled and uncompiled at this cutoff; retain every
semantic oracle and require distinct superseded buffer retirement before cleanup.

The [record19 supplement map](evidence/mesh-presence-2026-10-01/record-review-19-supplement-archive-map.json)
adds four immutable entries. All3476 canonical entries rehash with zero mismatches
and unique paths. No failed run, review limitation or original assertion is erased.


## Record20: entire-record review and exact WS result

The [fresh178-line Astra review](evidence/mesh-presence-2026-10-01/record-review-20--076--source-4-result-independent-review.txt)
continues the complete prior record review through the full current report delta,
roadmap, port, continuation, chronology, all92 requirement bodies/specifications
and25 deliberate exclusions. Root reads the entire memo and verifies all75 exact
observed pins before this update. Both freshly rehash all3476 prior canonical
entries with zero mismatches and unique paths. No unsupported current whole-daemon
completion claim was found. This is record reconciliation, not a fresh source
audit of all92 implementations or a rerun of historical native campaigns.

WS source4 now has independent actual-result approval: host Debug and ReleaseSafe
each11/11, zero skips, failures, leaks or log errors. All996 frozen source pins,
complete raw ordered logs and actually invoked/retained ELF hashes and same-inode
joins match. Seven WS tests, three filtered imported SendQ tests and one root
import make the11; this is no whole-daemon gate. The first11522bytes containing
production and the original five WS tests are unchanged. The test-only repair
forces actual413/801/144-byte retired backing witnesses before final cleanup and
executes the complete SDK allocation-failure sweep with independent retry. Raw
logs do not print its numerical allocation-index census; no count is invented.
Source3's9/11 failure and earlier SDK-geometry review correction remain preserved.
This supersedes its test BLOCK only for the isolated WS leaf.

The directional native key helper has independent94-line source approval and17
verified pins over965 frozen files. Its four prepared tests remain unexecuted.
Explicit HMAC/Keys-object wiping does not prove every SDK scratch/register/copy is
erased; strict feedback may fill caller scratch before rejecting a trailing byte.
Actual endpoint entropy, unique issued streams, real client support, authenticated
current routing and protected key delivery require their own acceptance.

Immutable media APIcheckpoint3 is95lines with five verified copied-file pins. It
adds WebRTC credential/departure candidates and a proposed complete physical-client
departure batch with one captured OLD revision and whole-leaf publication. These
four source leaves remain uncompiled and unreviewed; composed batch tests are
pending. They do not establish source-authenticated operations, bounded FIFO,
current pump/crypto association, physical address/SSRC/cache indexes, bridge/Server
joins, strict DTO, complete funding, consent or native acceptance. After the
independent review cutoff, the integrator saves source7 protected reply preparation
as a source-only snapshot; no endpoint/profile/bridge commit or handler activation
is reported. That newer snapshot receives custody, not a source/result grade here.
The four actual BEFORE3 security failures and eight previous packet controls remain.

Nine additional historical terminal build drivers (seven Auth, two Root) have
lossless compressed custody with decoded SHA/size mappings; actual test/product
ELFs and terminal receipts remain unchanged. Root independently decodes the latest
two streams and checks17 raw executables and8 terminal receipts. The unchanged
335544320-byte guard remains mandatory before every future compiler command. No
shared/global cache purge, foreign process termination, VM activation, deployment
or push occurred.

The actual factory/main/producer/ready/stop/Helix graph, native helper EOF/ACK
recovery and installed rcctl/reboot, typed same-OroStore Mail and submitted
uncertainty/cold recovery, RVL2/EventSpine custody, far WHOIS/direct delivery and
independent directory authority remain open. Client/platform/research/interop/
benchmark and release outcomes retain their exact conditional scope. Fourteen
rows lack separate acceptance fields; their specifications remain authoritative.
All92 requirement and25 cut bodies are unchanged; only the current-review metadata
anchor advances. The full objective remains active.

[Record20 archive map](evidence/mesh-presence-2026-10-01/record-review-20-archive-map.json)
adds 101 immutable entries, including its map and before/after document
snapshots. All 3577 canonical entries rehash with zero mismatches and unique
paths. Review observations precede these intentional report/metadata updates.


## Record21: entire-record reconciliation and new source blockers

Root freshly rehashes all3,577 prior canonical entries with unique paths and zero
mismatches. The roadmap SHA remains afd2b731; all92 requirement bodies,
specifications, global context and25 deliberate exclusions remain unchanged.
The14 rows without separate acceptance fields retain their specification scope.
This review reconciles the complete accumulated record; it does not claim a fresh
source audit of every implementation or a rerun of historical native campaigns.

The first actual directional key-helper focused Debug compilation fails on the
installed SDK's deprecated `std.meta.fields`. The distinct source2 compilation
also fails: four diagnostics require compile-time-known `fieldNames` iteration.
Both collected terminal results are exit1, with zero executed tests and no invoked
test ELF. Earlier source/mathematical reviews missed these compiler requirements;
their approval is superseded at this boundary, with all original reviews and raw
failures preserved. Source3 adds explicit `comptime` to all five field-name loops;
its manifest is ea134268 and leaf f9585c1e. Labels, vectors, wire bytes and
assertions remain unchanged. Source3 remains uncompiled and pending acceptance.
The335544320-byte guard was satisfied before source2 and remains unchanged.

Astra's170-line checkpoint3 source review identifies two concrete blockers:
legitimate zero-offer calls are rejected as exhausted identities, and seven
candidate preparation paths lose earlier detached allocations on a later failure.
These are source-grounded findings, not executed causal failures. Candidate1
repairs the count and whole-function unwind ownership; its independent review
blocks new fixture assertions that precede returned-candidate cleanup.
Candidate2's122-line expanded source review approves those repairs with a remaining
low-severity count-test setup cleanup limitation. It explicitly separates raw-codec
compatibility and complete-client departure drafts from the B1/B2 fixes.
Candidate3 adds immediate setup cleanup guards, but Astra finds a distinct fixture
blocker: the guard runs at function exit while an unchanged earlier assertion
requires zero pending candidates. The committed setup plan retains its pin until
deinit. This is a source-confirmed test custody error, not an executed failure or
production defect. A tightly scoped cleanup repair is pending; the zero-pending
oracle remains mandatory. Original causal controls and current BEFORE3 security
failures are preserved.

Server7's protected credential-output preparation remains a private definition
with zero callsites, uncompiled and unwired. Server8's complete physical departure
fragment remains pending installation at this cutoff. Actual authenticated packet
operations, physical indexes, owned FIFO/current pump, protected all-owner commit,
producer fences and joined stop, strict DTO, funding and consent remain open.
Accepted WS4/SendQ2/codec/Store and historical native cuts retain their exact
isolated scope. They do not grade this new composition.

The main/factory/native helper/service readiness and stop graph, installed
rcctl/reboot, typed Mail journal and submitted-uncertainty/cold recovery,
RVL2/EventSpine custody, far WHOIS/direct delivery and directory authority still
require acceptance. Client/platform/research/interop/benchmark outcomes retain
all original conditions. No deployment, push or VM activation occurred.


The [fresh157-line Astra reconciliation](evidence/mesh-presence-2026-10-01/record-review-21--090--full-record-independent-review-21.txt)
independently checks the full accumulated record at its fixed cutoff. Root reads
all157 lines and verifies all67 observed pins before these intentional document
and inventory updates. Newer candidate4 and APIcheckpoint4 remain separate
uncompiled, unaccepted drafts; no approval is backfilled into this review.

[Record21 archive map](evidence/mesh-presence-2026-10-01/record-review-21-archive-map.json)
adds101 immutable inventory entries, including before/after document snapshots
and its map. All3678 canonical entries rehash with zero mismatches and unique
paths. All92 requirements and25 cuts remain unchanged. The full goal stays active.
