# OpenBSD full-port continuation — 2026-10-02

The full port remains open. This continuation preserves the pre-existing dirty
tree and historical evidence. No deployment, publication or push occurred.

## Current frontier (latest receipt)

The isolated OpenBSD 7.9 VM is running under `.zig-cache/openbsd-isolated-vm-20261002`. Its own SSH endpoint is `127.0.0.1:2235`; other VMs were not modified. This is a test fixture, not a deployment.

- Shared journal cut3: host Debug and ReleaseSafe each94/94; native OpenBSD Debug and ReleaseSafe each94/94, root, normal8192KiB stack, zero skips. Prepared bound registration/Webpush mutations and actual lock/lifetime loans passed fresh source review; production Core/World installation remains open.
- Service-carry cut2: host Debug and ReleaseSafe each78passed/5protected-root skips. Native root Debug and ReleaseSafe each83/83, zero skips. Fresh source review passes minimum-descriptor and decoder allocation rollback repairs. This is close-only custody, not live service adoption.
- Lifecycle cut12: host Debug121/121; fresh source review passes actual nonblocking HTTP readiness and bounded real-connection cleanup. Native Debug121/121 passed in the isolated guest, root, normal8192KiB stack, zero skips. Cold UDP and paused WebTransport tests execute. Generic inherited UDP refuses unavailable inode identity; an opaque source-issued SCM_RIGHTS bridge remains required. Earlier cut9's two HTTP skips are retained in its own receipt.
- Core policy cut13: fresh source review passes the bounded private policy/install consistency scope. Its first frozen host build failed before tests: an invalid test defer assignment and a missing Services dependency overlay (the frozen Services was ffbe4b5c, not live9921b8bf). This is not compilation acceptance. Corrected cut14 uses Server11948f895 plus the exact shared-cut3 Services9921b8bf and Delivery37f5f855 dependencies. Host and actual native Debug124/124 each, zero skips, and fresh source review pass. Native execution uses root and normal8192KiB stack. Host and native ReleaseSafe124/124 each also pass. The complete four-mode baseline has zero skips.
- Broad cut6: check/config377/377. Services completes607/608 with an initial media-join timeout. Server's combined run timed out before a final count. Full host/native release suites remain open.
- Leased factory cut16: all four host/native Debug/ReleaseSafe modes136/136, zero skips. World scope cut18: all four modes142/142, zero skips, plus fresh source and independent evidence acceptance. Native rerun receipts record OpenBSD7.9, root,8192KiB stack, original binary hashes and exit0. Durable evidence is in `docs/audit/evidence/openbsd-continuation-2026-10-02/`.
- Channel stage cut19: host Debug147/147, zero skips, but SOURCE HOLD. The fresh reviewer found mutable payload custody, same-acquisition pointer invalidation and failed event-preparation refund defects. Owners are repairing opaque backing, placement validation and pre-scope/pre-Services refusal. No native/ReleaseSafe acceptance or positive channel transaction is claimed for this cut.
- Next production seams: prepared channel WAL/World transactions and strict cold projection, named adapters for raw Store access, active replay/history routing, Runtime/Controller/Main lifecycle and strict inherited transactions. The leased branch must refuse publication until those authority barriers close. Main is reserved by the parent and has not been changed.

Exact frozen compositions, hashes, failures and subsequent receipts follow below and in `openbsd-port-live-ownership-2026-10-02.md`. Earlier chronological notes are retained for evidence.

## Current work

`src/daemon/runtime_start_gate.zig` now provides creator-only
`Control.joinParticipant`. It rejects foreign/stale slots and an undecided gate
before touching handles or accounting. A regression retains a running consumer
while joining a producer, checks duplicate joins, and bounds failure waits.
The borrowed View still cannot join participants. Fresh read-only source review
approved the bounded-wait correction. Standalone Debug executes all 14 gate
tests; ReleaseSafe executes all 14 tests as well.
`View.requireReleased` reads only the atomic startup decision, allowing inline
workers to observe publication without racing creator-owned join counters.

The sole `server.zig` integrator is separating producer stop/join from media
settlement and reactor stop. Readiness, inline reactor lifetime and detached
cleanup require their actual owner facts. This source work is unaccepted until
focused gates and independent review finish.

## Verification frontier

At 2026-10-02T16:42:21Z, `df -B1 .` reported 319569920 available bytes, below
the preserved 335544320-byte compiler guard in
`docs/audit/full-record-review-2026-10-02.md`. No compiler was launched.
Existing caches and retained evidence were not purged or moved. Formatting and
whitespace checks for the gate change passed; these do not establish compilation.
Storage subsequently recovered to 10706288640 available bytes. Both actual
user-quota and quota-info queries returned ESRCH (no active user quota), so the
preserved compiler guard passed. Standalone gate execution then passed as above.

The first project module command (`zig build test-mod -Dtest-filter='selective
join' --summary all`) fails with five compilation diagnostics in existing media
drafts: duplicate `stun` import, shadowed `chunks`/`list` identifiers and two
unqualified media attachment constants. No project tests executed. The parent
removed the duplicate import; the integrator owns server-side repairs. Retain
the distinction between standalone gate acceptance and the combined project.

## Ordered remaining work

1. Verify selective joins and the Core producer/consumer stop split in Debug and
   ReleaseSafe, including real worker lifetimes, foreign authority, pressure,
   timeout, retry and inline cleanup. Run a fresh adversarial source/result review.
2. Complete `configured_runtime.Runtime` publication, activation, producer
   fencing, settlement and joined teardown. Preserve the private original graph
   and lexical Store/Io/directory owner lifetimes. A construction fixture is not
   a ready or stopped service receipt.
3. Connect that graph in `main.zig` with native service ownership and strict
   Helix descriptor/state custody. Exercise helper EOF/ACK recovery and actual
   configured daemon readiness, stop and sequential upgrades.
4. Complete secure media caller composition, same-Store typed Mail journaling
   and cold uncertainty recovery, RVL2/EventSpine custody, far-node WHOIS/direct
   delivery and independent account directory authority. The current audit
   records these separately; isolated leaf results cannot close them.
5. Run installed OpenBSD policy/helper/rcctl/reboot journeys and current combined
   native transport/mesh/Helix campaigns at the normal 8192 KiB stack. Record
   exact source/artifact hashes, ordered outcomes, skips and fixture cleanup.
6. Reconcile all 92 roadmap requirements and 25 deliberate cuts against actual
   current acceptance, then full host/native suites. Do not infer completion
   from historical artifacts or cross-compilation.

Initial focused commands after the storage/quota guard passes:

```sh
zig build test-mod -Dtest-filter='selective join'
zig build test-mod -Dtest-filter='selective join' -Doptimize=ReleaseSafe
zig build test-mod -Dtest-filter='managed core:'
zig build test-mod -Dtest-filter='managed core:' -Doptimize=ReleaseSafe
zig build test-mod -Dtest-filter='configured runtime:'
zig build test-mod -Dtest-filter='native service'
zig build check
zig build test-server
zig build test-services
zig build test-server -Doptimize=ReleaseSafe
zig build test-services -Doptimize=ReleaseSafe
```

Current frozen evidence: cut2 Core Debug passes 76/76. Configured Runtime Debug
passes 92/96 with four failing existing construction tests: two actual native
media cross-owner binding failures and two socket fixture failures. Runtime's
owner corrected socket family observation and the actual nonblocking fixture;
Core's sole writer owns the source-binding correction. No Runtime or Core
ReleaseSafe acceptance is recorded yet. Failed source cuts and raw logs remain
under `.zig-cache/openbsd-lifecycle-20261002-{1,2}` with all source pins. The cuts
contained one private SFU slice-iteration correction; that mechanical correction
has subsequently appeared in the live media owner's source. Project Webpush
lifecycle gates pass 74/74 in both Debug and ReleaseSafe, including two focused
tests; queued/dead/overflow custody still refuses terminal settlement.

Cut4 supersedes those construction failures with exact live source, zero private
overlays: Runtime Debug 96/96; Core Debug 77/77 including the added original
media registration/FIFO tampering control. Fresh read-only source review passes
those bounded changes. Runtime ReleaseSafe first attempt hit its 180-second
compile limit (exit 124), with no tests executed; it is not a passing gate.
The Webpush/Services all-account output-consumer slice is being integrated
separately and will require a new source cut and executed acceptance.
Current x86_64 OpenBSD daemon semantic check passes all three build steps on
cut4 (5-second compilation); this provides no native execution result.
Cut4 Runtime ReleaseSafe subsequently passes 96/96 (4-minute compile,
19-second execution). The OpenBSD Debug Runtime test ELF cross-build passes;
artifact SHA-256 is
`614f0722f447c91fd0b041a5dfa0a0641b4b910094242cb96713bb3fdeacfb24`.
It remains unexecuted on OpenBSD. Core ReleaseSafe is running on the same
preserved cut, independently of the new output-settlement source.

Fresh bounded review identifies two concrete native service prerequisites:
Main still constructs/runs the legacy raw Server and never binds production
Controller readiness or STOPPED to Runtime; strict Helix manifest has no service
listener/lifetime-lease carry. Cold construction correctly rejects inherited
state. Implement a real inherited factory and mandatory transfer rather than
clearing inherited fields or promoting snapshot/test fixture observations into
service authority. Retain the outer controller/listener/lease through exact
stop ACK after all original source work, joins, detach and disposal complete.

The server/services checks above were selected by the project gate selector
for the gate and server paths. They are pending, not passing results.

Cross-build and execute the matching runners on OpenBSD before grading native
behavior. The authoritative remaining boundaries are recorded in
`docs/audit/full-record-review-2026-10-02.md`,
`docs/audit/gap-frontier-2026-10-01.md` and `docs/dev/openbsd-full-port.md`.

Current receipt: exact cut6,980 byte-matching source files, no overlay.
Runtime Debug97/97; consumer Debug78/78; fresh independent review PASS.
Combined ReleaseSafe116/116 (44 focused plus72 imports), compile4m/run38s,
raw .zig-cache/openbsd-lifecycle-20261002-6/lifecycle-releasesafe.log.
Broader project gates and actual native OpenBSD execution remain pending.
configured_lifecycle owns only new delivery_authority.zig prerequisite;
integration remains sole server.zig writer and prepares seams privately.
Mail typed reservation is assigned to the older ROOT thread. EventSpine,
RVL2, retained outbox crash durability, pre-204 Webhook custody, shared Store
locking, and real Main/inherited service authority remain open.

Cut6 broader host Debug check + test-config passes6/6 build steps and377/377
tests, compile4s daemon/8s tests,29s execution; broad-check-config-debug.log.
Services/server Debug gates now running against same frozen source.
Webhook204 still acknowledges MPMC queue insertion before target-policy and
durable MESSAGE_V2 acceptance. ADS1 skips anonymous/untracked attachments;
strict refusal or real physical custody is required before acknowledgement.
HTTP delivery persistence alone cannot close send-and-forget peer fanout.

Fresh recipient audit: attachmentHasReusableSession (Server12050) and
prepareAttachmentDeliveryBatch (12224) skip untracked physical clients.
ADS1 itself accepts ClientId, but Helix adoption31339-31444 resolves retained
IDs only through HSSN and rejects unmapped IDs. Removing the skip alone is
unsafe. physical_lifecycle has Store binding, no connection/SendQ/spool owner.
Strict Webhook can honestly refuse whole admission before204 when recipients
are untracked, and propagate allocation/capacity failure, until actual physical
custody plus close/Helix relation is implemented. This is an explicit gap, not
a complete guest-channel solution.

Cut6 combined services/server Debug attempt hit300s external timeout124,
no final runner report/count. This is not a pass. Both verbose harnesses now
run with600s bound to expose the exact slow/failing case; original raw empty
log retained as broad-services-server-debug.log.

ACTUAL broad cut6 Services Debug failure309/608:
`threaded server: account logout and replacement retire old physical media authority`
FAIL TestTimeout22.382s, raw broad-services-server-debug-verbose.log. Runner
not yet final. This cut predates older Auth pending fullmedia-close repair;
please supply only independently accepted full E2EE DETACH/MEDIA LEAVE and
last-room transcript/bridge closure, with exactsourcepin. Parent will preserve
private writer ownership and sole live integrator; no incompletepatch install.

Cut6 full focused Services Debug verbose COMPLETED608:607pass,0skip,
1fail,0leak,0logerrors,512.351s. Only reported failure is initialMEDIA JOIN
in accountlogout/replacement physicalmedia testcase309 above. Server476
runner subsequently executes in same600s parentbound; its finalgate pending.

Repaired isolated DeliveryAuthority cut4 ac37f91efc45bb7eee094f821df9b5fdd4c8784e02420baf98ddb7000d4fc308
passes actual Debug85/85 (12 direct,73 imports), compile3s/run8s. Event staging
sweep36 failures, progress40, commit-validation1, exact original-source retry.
Independent source review passes the bounded private journal and fixture fix.
ReleaseSafe now running; no native execution or shared Services/World/peer/HTTP
transport/204/Helix/production rotation acceptance inferred.
Combined broader cut6 bound600s expired during Server case180/476; Services
completed607/608 with1fail above. Server has no final pass count.

Native evidence update: own OpenBSD 7.9 GENERIC.MP#449 amd64 VM booted from
the signed release installation. SSH uses only the fixture key and port2235.
Delivery cut4 actual root execution at the normal 8192KiB stack: ReleaseSafe
85/85 passes; Debug exits139 at contradictory typed-history adversarial test
in compiler_rt stack_probe after preceding tests pass. This is a real native
Debug failure, not acceptance. Author is moving large test-only History and
checkpoint locals to heap, preserving exact adversarial synced-row writes.
Raw delivery-openbsd-native-debug.log and delivery-openbsd-native-releasesafe.log
remain in cut4. ELF hashes: Debug22b4eda2d88ccddff119cc8cdf0a2ef172e972c64cb7852e226ef0d3191464f5;
ReleaseSafebbdb5dcf2cd6e99f42585dff03acaa796289f9719dbbe5e00c3b2db9d87c2b34.

Isolated service carry cut1 freezes lifecycle cut6 plus eight overlays, exact
composition.json, native_bootstrap97f2e6a21640679ad69c6610717de4370bb322e2ecc49f5c722730d77368d535.
Fresh independent review and host Debug campaign now run; protected tests may
skip on Linux uid1000, requiring actual root native execution. No production
service lifecycle adoption inferred from the carry prerequisite.

Cut5 journal d42b191bec16cf748a3d7a615a3fc31e5e751cbfbefbf1484a0a1271a78e9cfc
changes only adversarial-test large checkpoint/History allocations to actual
heap custody. Actual OpenBSD Debug now passes all85 tests, zero skipped, root
8192KiB stack, exit0. Raw native log kept in cut5. Shared Services seam may now
advance independently; production journal bytes unchanged by native stack fix.

Fresh service-carry97f2 review found a remaining valid presence-first boundary:
plain dup can yield0/1/2 when a standard descriptor is closed, then mandatory
row validation refuses that internally retained descriptor. Integrator owns
minimum3 duplication plus CLOEXEC and a genuine closed-standard-FD regression.
Frozen cut1 evidence remains useful but not accepted as the final source.

Actual root OpenBSD service-carry cut1 Debug executed all81 tests:79passed,
0skipped,2failed,2tests leaked memory,4loggederrors, exit1. Both protected
allocation-failure campaigns uncover capsule.decodeStream ownership leakage
when newly decoded capsule allocation succeeds but list.append fails. Parent
reported original raw log to the capsule owner; no final carry acceptance.
Host cut1 was77passed4skipped0failed, which did not exercise those root paths.

Journal cut5 host Debug85/85 and native Debug85/85 pass. Native Debug ELF SHA
1e380221f95b58c9e582f7b60e4cffb7334c06ddf65fec2b052b4bf09b9fe134.
Cut5 exact host ReleaseSafe starts now before native ReleaseSafe rebuilt proof.

Journal cut5 exact native ReleaseSafe now85/85, zero skips, exit0, root stack8192.
ELF SHA24f9227bd7892e78919f4a606b30a2213762629b306f7cc27dcb251be003f9ac.
Thus cut5 exact host/native Debug+ReleaseSafe each85/85 pass. Source shared
Services seam advances separately; this does not close peer/HTTP/204/Helix.
Carry cut2 freezes minimum3 retained FD and append-OOM cleanup repair: bootstrap
5a6b8ab7c5af450d6f1b6220853e5b1747bd4b5f6c2eb240f5a2521049bc5bd7,
capsule82cc256f4baba8662057c89a1da3fb5e26289fe068bde574bd148df2f970a4ad.
Eleven focused controls expected (nine previous plus host decoder sweep and
actual isolated child closed-standard-descriptor regression); review pending.
Parent next compiles exact lifecyclecut6 combined Debug ELF for actualOpenBSD
execution, not older artifact substitution.

Parent exclusively claims src/daemon/dualstack_udp.zig for actual newly found
OpenBSD socket-observation port repair and configured_runtime.zig ONLY the
ACME/OCSP test path portability repair. Existing delivery/services and Server
ownership unchanged. Exact lifecyclecut6 nativeDebug (only25 Runtime+5Core+72
imports; filters mistakenly omitted Webpush direct controls) completes99/102
with3fail, zero skips: unsupported stdIo dir-relative realpath in ACMEfixture;
InvalidSocket at Snapshot.validate587 in both WebTransport-enabled tests.
Official OpenBSD sys_socket.c soo_stat zeroes device/inode for sockets; sysctl
file kernel pointers are root-only, so no unprivileged OFD identity inferred.
Cold observations must preserve actual source-owned custody, and inherited
identity needs genuine source proof or explicit refusal, not fabricated inode.
Carrycut2 actualroot nativeDebug83/83 zero skips passes; fresh source reviewPASS.

Carrycut2 exact hostDebug/ReleaseSafe78pass5protectedskips0fail; actualroot
OpenBSD Debug and ReleaseSafe each83/83 zero skips, stack8192, exit0. Fresh
independent source reviewPASS. NativeRS SHA20e04fa9532019c0bb543a2792144f9c3d5c7168e03df679141ba6aeb2638b3d.
This accepts isolated close-only carry+decoder repairs, not productionREADY.

Sharedcut1 delivery9e121/Services030a hostDebug91/91 (18direct73imports),
but fresh reviewHOLD: strictServices Webpush mutation ordinaryput/delete has
post-sync RAM allocation failure boundary. Author repairing via preparedbatch
and meaningful mutationfaults. Testbounded actualThreadwait also required.

Lifecyclecut8 freezes parent dualstackUDP21da378bcee208f89a99de3bd00c3d0957d887917be6f233cbdfdbd21ecccd05
and test-onlyRuntime343c679c19b37995c7e3548506bc4c3f550ff1d50995b9a60218d611fa30e2d9.
Cold source-owned zero-inode observations are permitted; ordinaryinherited
adoption now explicitly refuses UnverifiableSocketIdentity after actualfield
checks, closes transferred references only. Actualclose+rebindsameendpoint
negative proves no forged original custody; nativepairtest retainsbothfamilies.
Genuine opaque UDP SCM_RIGHTS source/mandatory role join still remains open.
CorrectcombinednativeDebug filters now include25Runtime+6consumer+5reconcile+
3Worker+5Core+2UDP controls, expected118total incl72imports (verify count).

Correction: lifecyclecut8 actualnative118 completed116pass2SKIP0fail, but
the skips are the two Linux-only realHTTP consumer controls (acceptedsigned
overflow+malformed/truncatedreceipts), not UDP/kernel socket tests. Parent
asked soleServerwriter to port the actualprobe and guards for OpenBSD before
longer Coreseal work. NativecoldUDP and Runtimefaultpaths actually execute.
Hostcut9 ALL119 passes inclparent WebTransport refusal callerregression;
freshindependent source reviewPASS. Targetnativeexactcut9 stillpending.

Sharedcut2 frozen exactdelivery58aab3b3ff724b1c010c2cc5b4c50c2e803a4657ca3f6a276c06493eefa6c5dc
and Services9921b8bf643c6650e5582e60b02e59fa0b0f55d522ecfa703fd1ff315edc8ffc
(final delete mutation absentvalue fix). Preparedboundregister/Webpushstaging
OOM and actualfailed/short/sync/coldcontrols added; boundedthreadfailurecleanup.
Host Debug semantic/execution underway, freshreview required.

Sharedcut3 actualHostDebugALL94 passes. SourcefreshreviewPASS production
preparedmutation+boundedcallerfixes; coldfaulttest nowcheckedgeneration+1.
NativeDebug exactcut3 beingbuilt, then realroot execution, criticalRSneeded.

Lifecyclecut9 actualnativeDebug117passed2HTTPskips0fail/119, host119/119.
Nativekernel/pumpandcoldUDP testsallrun, onlytwoLinuxHTTPguards remain.
Fresh source review approved test-onlynativeWebTransportrefusal coverage.
HTTPcut10 frozenServer9a9e9b source reviewHOLD due blockingLinuxacceptafter
poll whenreadinessdisappears; solewriterrepairingprivatefixtureNONBLOCK plus
realafterpoll-drainactualjoinregression, preservingother productionchanges.

Storage retained: seven older OWN emittedELFs losslessly gziparchived, each
fullydecompressedSHA256+size verified before replacing originalfile witharchive.
Eachcut artifact-archive-receipts.jsonl records originalSHA/path/restoration.
Sources/logs unchanged; noforeigncache orartifact touched. Reclaimed149068774B.

Sharedcut3 source37f5/9921 acceptedboundedsourceReviewPASS; actualHostDebug
andReleaseSafe each94/94, actualOpenBSDDebug94/94 rootnormalstack8192
zero skips. NativeDebugSHA5c44bc96692daaf7aa5ad16335d2f1edb9f5c5a60e8fa2debc7da7ad2adfc18d.
ExactNativeReleaseSafe beingbuilt; productionbinding remainsuninstalled.

OwnfinishedLifecyclecut6 compiler object/binary cache has9additional large
files losslesslygziparchived, verifieddecompressedSHA+size for everyfile
before replacing rawfile, receipts/restoration in artifact-archive-receipts.jsonl.
No sources/logs/foreigncaches touched. Reclaimed1726580808B; restorethatcut
compiledartifacts fromexactarchives before rerunning historicalcut6 commands.
At latestguard2152546304Bavailable; gatework continues.
HTTPcut11 sourceHOLD for failure-onlyThreadjoincleanup whenNONBLOCK
deliberatelyregresses; solewriterrepairing actualwake andfaultregression.
No fullreleasegate/nativeinstalledservice acceptance claimed.

## Complete affected carry selection

The corrected source-derived selection covers every named capsule and handoff-manifest test, the exact section-10 enum test and all native service-carry controls. Host Debug completes101 cases:96 passed,5 protected-root skips,0 failures. Actual native root Debug completes101/101, zero skips, normal8192KiB stack. Exact filters and raw output are retained in `.zig-cache/openbsd-service-carry-20261002-2/carry-affected-complete-filters.json` and `carry-affected-complete-debug.log`. This expands the earlier incomplete88-case selection; ReleaseSafe for this expanded selection remains pending.

## Original World lock prerequisite

Parent owns `src/substrate/rwlock.zig`, as agreed with the sole Server writer. Final source SHA-256 is `f4fdcb002dbbb2729af6402844a7a154127d02c79c034b14836ca8286c22a940`. `requireExclusiveHeldByCurrentThread` records the actual caller only after successful exclusive acquire/try, clears validity before unlock, and refuses unlocked/shared/foreign-lock or foreign-thread use. It does not acquire World inside a Services callback or prove queued caller/join custody. Fresh independent source review passes. Host Debug/ReleaseSafe and actual native Debug/ReleaseSafe each execute4/4, zero skips, native root8192KiB stack. Exact logs/artifact hashes and cut1 test-API compilation failure are retained in `.zig-cache/openbsd-world-lock-20261002-{1,2}`. Production Core World-scope wiring remains open.

## Genuine leased Core factory checkpoint

Corrected cut16 composes Server `0be9a7ba83db95a29cbf9690c1d9da5d9864d89937673666840cb3eefb45a13f`, Delivery `7e84164ec2eecf55afb6eb11cfffa0457393ffc0dabe0aa34e3de61dc74e4d87`, Services `9921b8bf643c6650e5582e60b02e59fa0b0f55d522ecfa703fd1ff315edc8ffc` and accepted RwLock cut2. Host and actual native Debug136/136 each, zero skips; native root8192KiB stack and fresh bounded source review pass. Cut15 failed before execution on one fixture defer assignment; cut16 only fixes those braces. Five actual Core and two actual leaf controls cover private original ownership, cleanup refusal/retry, strict ordinary-WAL refusal, provisioning/recovery OOM and retained valid journal with explicit recovery. The leased branch refuses publication before resources, graph and thread creation. Host factory ReleaseSafe136/136 also passes; native factory ReleaseSafe136/136 also passes, zero skips, root8192KiB stack.

Parent RwLock cut3 adds actual-acquisition continuity diagnostics at SHA `2d9fe3ee06e4145bea6e2ee1086bc6b50371ec1f0a2d2d846b80bc0f31fd3dec`. Host/native Debug and ReleaseSafe each5/5, zero skips, normal native8192KiB stack, and fresh source review pass. Same-thread unlock/reacquire refuses an old capture; counter exhaustion never wraps and refuses new scope diagnostics while ordinary mutual exclusion remains usable. Only a genuine private Core/Plan scope may use those diagnostics; the number alone is not authority. Original World scope and active Guard/history/raw-adapter routes are next and remain unaccepted.

Additional own completed host artifacts were losslessly archived with decompressed SHA verification: cut12 reclaimed226454747B; cut14 reclaimed229037619B. Per-cut receipts include exact restoration commands; source/log/foreign artifacts were preserved.

## World scope review hold and repaired diagnostic

Frozen cut17 Serverc4292261/Deliveryd07854a6/Services9921/RwLock2d9fe3ee executes hostDebug140/140, zero skips. It was not accepted: fresh review found acquisition exhaustion permanently prevents the distinct cold cleanup path, retaining the original candidate/Services mutex/lease. The source remains a held historical cut, not a completed World integration. Parent also identified a filter omission: the new leaf test begins `delivery authority: original Core World`, rather than `genuine Core`. The next combined selection includes it. No test names from cut16 were removed; four matching new tests account for140.

RwLock cut4 repairs only the cold diagnostic at SHA `0dccc9e11dab0b211b4cd3be39d6afe3ca62276ab2e8ababd91920173aa1bf8b`. A previously valid private source scope is interrupted when a different actual held acquisition exists, or when permanent exhaustion proves a later acquisition without wrapping. Zero/future/unheld/unchanged cases refuse. Admission and ordinary abort remain refused after exhaustion. Actual host/native Debug and ReleaseSafe each5/5 plus fresh source review pass. Core integration and genuine MAX-boundary cleanup/recovery regression are pending.

Own completed cut16 and cut17 host artifacts were losslessly archived, with decompressed SHA and restoration receipts retained:198034632B and197315128B reclaimed respectively. Sources/logs and foreign artifacts remain unchanged.

## Repaired World scope cut18

Exact Server `b844ebbd4ecaac1bf7a9184a2a49f07f49ebba4a197efae0f80e4fab219ebf64`, Delivery `d07854a62763e1d3730bf2b407c45b6b2a9eec6aa6b5011c31634b7e28a47fb5`, Services `9921b8bf643c6650e5582e60b02e59fa0b0f55d522ecfa703fd1ff315edc8ffc`, RwLock `0dccc9e11dab0b211b4cd3be39d6afe3ca62276ab2e8ababd91920173aa1bf8b`. Fresh bounded source review passes exhaustion cleanup; host Debug executes142/142 zero skips. Filters explicitly include the original Core World leaf. Actual MAX-boundary control retains candidate/mutex on ordinary commit/abort refusal, cancels only through genuine unpublished cold cleanup, preserves journal bytes and exhaustion, and proves strict cold recovery plus single admission. Native/ReleaseSafe cut18 are pending. Logs/composition/argv are in `.zig-cache/openbsd-lifecycle-20261002-18`.

Own completed cut18 host binary was losslessly archived with decompressed SHA verification and restoration receipt, reclaiming197331509 bytes. Storage remains guarded; no foreign artifact or cache was removed.

Factory cut16 is now complete in all four modes: host/native Debug and ReleaseSafe each136/136, zero skips. Native ReleaseSafe artifact SHA-256 `0d8dab17fc042217f128ce46e090460d9d36dbf894051fe074c4bce07ef34031`; raw output retained in `lifecycle-openbsd-native-releasesafe.log`. These are frozen prerequisite tests; current production publication remains refused.

World scope cut18 actual OpenBSD ReleaseSafe completes142/142, zero skips, root8192KiB stack. Raw output and emitted artifact SHA retained in the cut18 directory; host ReleaseSafe is running and native Debug is pending. The first native compiler invocation had misplaced argv and exited before compilation; its raw usage/error log is retained separately. Corrected invocation built successfully.

World scope cut18 host ReleaseSafe completes142/142, zero skips. Native Debug is now compiling the same frozen142-test selection; host Debug and native ReleaseSafe already passed142/142 each. World channel stage and two original-Core binding methods are being implemented as a separate unaccepted source cut. Full publication remains refused.

World scope cut18 now passes all four host/native Debug/ReleaseSafe modes:142/142 each, zero skips, normal native8192KiB stack. Fresh bounded source review passes. Durable evidence and full926-file frozen source pins are retained in `docs/audit/evidence/openbsd-continuation-2026-10-02/world-scope-cut18/`. This closes the bounded World-acquisition/cold-cleanup prerequisite; channel staging/transaction/cold replay and active raw/Guard/history routes remain open, and leased publication remains refused.

Independent receipt audit matched all926 source pins, exact composition, artifacts and four ordered142-case logs. Native attribution initially lacked inline metadata, so both original binaries were actually rerun: each new log records uname, root identity,8192KiB stack, original SHA before142/142 tests and exit0. Logs/argv are now retained in world-scope-cut18 evidence. New cut19 composes World32ee/Server9451/Delivery3fba/Services9921;147 host Debug cases are executing, fresh bounded source review pending. Channel WAL/cold projection/command acceptance remain unimplemented.

## Channel stage cut19 source HOLD

Frozen World32ee/Server9451/Delivery3fba/Services9921 host Debug executes147/147, zero skips, but fresh source review rejects acceptance. First, a public mutable/copyable World payload can preserve its numeric identity while clearing its owned fields; binding/cold abort can then clear the fence while original RCU/resources remain live. Second, creating World stage before event prepare allows failed prepare cleanup to panic at the active-stage terminal fence. Owners are repairing with opaque source-owned backing and pre-scope/pre-Services active-stage refusal. No native or ReleaseSafe acceptance is claimed for this rejected cut.

Cut18 independent attribution review now passes both verified native reruns and21 evidence hashes: original binary SHA, actual OpenBSD7.9/root/8192 metadata, ordered142/142 and exit0 in each mode.

Fresh cut19 review adds a third finding: a real same-acquisition channel rename/remove/map rehash invalidates a borrowed map Channel pointer while readiness still passes. Repair must own canonical target/OID, validate actual current placement and RCU before durable action, and abort only original unpublished resources safely after graph changes. Opaque backing alone does not close this finding. Owners are implementing all three repairs; the147 passing host tests remain a rejected historical cut.

## Opaque channel repair cut20

Frozen composition Server `53f789d0c9822ef99fb09ec2f0cd391e07c976495d7972f7c13d2112d7653da1`, World `1fc704946a3199f0ff7afecf798fcaa25ccc75b8c85d4545f4af8b6897e3e307`, Delivery `3fbac9779ad013773bdc492f07edbb4d62cd09d1d085356057bac810992a8573`, Services9921 and RwLock0dccc. World handles and exposed registry fields are opaque; exact backing remains source-owned. Readiness validates original canonical target/OID/current placement and RCU before durable work; abort frees unpublished resources safely after a real graph conflict. Core source guards reject active World stage before scope allocation and ordinary Services entry. Six World tests plus one composed Core test give expected149 selection; host Debug is executing and fresh source review is pending. No positive channel WAL transaction, named login, strict cold channel projection, production budget rotation or Main acceptance is claimed.
