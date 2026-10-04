# Ordinary multi-hop presence and direct delivery

Status: source audit and causal regression in progress. No completion claim.
Baseline: `6b9759d9134873db49df751eb451616ddacc0205`.
This follows the accepted shared-IP lifecycle repair; it does not reopen that fix.

## Verified source seams

`src/daemon/server.zig` already authors local registered-client presence using
`~presence~` MEMBERSHIP in registration and local-client anti-entropy bursts.
The missing contract is not a missing registration announcement.

`src/substrate/undertow/s2s_peer.zig:verifiedPayload` verifies the embedded
signer's key against the authenticated adjacent peer. `applyMembershipPayload`
then requires `acceptsDirectOrigin(ev.origin_node)`. These are correct direct-owned
frame protections. `src/substrate/undertow/signed_frame.zig` explicitly documents
that original multi-hop signatures require retained per-fact origin bytes.

The daemon's `drainIdentityTransitions` applies direct identity deltas without
retaining or forwarding the original foreign membership wire. Local anti-entropy
bursts scan local clients. `findRemoteWhois` and nickname route lookup consult
active per-link rosters. B can know a C guest while A lacks its proven presence.

Direct delivery has a separate blocker: `handlePrivmsg` chooses token-bound V2
when it resolves a recipient session token; an ordinary unbound guest uses legacy
MESSAGE. Legacy `deliverRelay` performs local delivery without forwarding at B.
`message_relay_v2.ScopeKind.direct` and `validateSemantic` require a recipient
route ID. Removing that requirement would change the existing exact-session
contract and would permit a stale nickname to identify the wrong recipient.

The current native `--foreign-nick-proof` observer authenticates an account and
publishes tokens. It does not prove ordinary unbound guest behavior.

## Required end-to-end contract

- Original signed presence is retained and forwarded byte-identically, with full
  origin verification independent of the transport hop. No foreign re-signing.
- Stable non-bearer identity and incarnation distinguish live guests from later
  holders of the same nick, including cold restart and sequential Helix.
- Revisions, withdrawals/tombstones, rename and deterministic collision projection
  cannot resurrect stale nick routes or grant account/session authority.
- Admission, retention and route/WHOIS publication form an allocation-failure
  atomic cut. Unknown or equivocal origins, pressure and delayed repair remain
  fail-closed and retryable without poisoning replay state.
- Reconnect/RESYNC repairs retained original facts and withdrawals. Negotiation
  keeps old peers from receiving or interpreting an unsupported scope.
- A distinct signed ordinary-direct scope binds the accepted recipient identity
  and home; existing token-bound direct/whisper semantics remain intact.
- Forwarding follows proven routes. Unknown target traffic is never flooded.
- A-B-C real command tests use independent unbound guests, both directions and
  no shared session tokens. Verify WHOIS identity, exact DM delivery, rename/quit,
  nick reuse, partition/heal, pressure, origin forgery and sequential exec.

## Ownership and next evidence

The daemon integrator remains the sole `src/daemon/server.zig` writer, initially
adding causal regressions without production changes. Root owns this audit and
native probe changes. Protocol/store ownership remains bounded by the complete wire and lifecycle
contract. [Fresh Astra analysis](evidence/mesh-presence-2026-10-01/astra-analysis.txt)
blocks a presence-only fix and confirms both independent one-hop boundaries.
The roadmap audit runs read-only. No deployment or push is authorized by this slice.

The native probe now has a separate `--ordinary-presence-proof` mode. It creates
three independent guests without SASL, session-sync or token issuance, verifies
all-pairs WHOIS and both far directions' exact DM identity/delivery, excludes the
intermediate guest, and repeats on the original sockets after each real exec.
It explicitly requires `--skip-partition`; partition, rename/quit and nick reuse
remain additional required gates. This mode has passed Python compile/CLI checks
only; it has not passed native runtime acceptance on the current implementation.

No existing ordinary-client identifier is suitable for the new incarnation:
username is not identity, packed slot generations are remapped during Helix, and
mesh collision UIDs are display aliases. The public 128-bit incarnation
is fresh at registration/reconnect and explicitly preserved across Helix; it must
not reuse credentials or session tokens. Original signed presence proves identity,
not reachability: usable next-hop evidence requires its own authenticated bounded
loop-free lifecycle, withdrawal and repair contract.

## Proposed codec boundary for the next implementation step

A dedicated versioned record will bind operation (present or terminal quit),
full origin key, public 128-bit guest incarnation, monotonic subject revision,
stable nickname-claim HLC, signed issue/expiry times, nick/username/visible host/
realname and origin server name/description. All public fields are bounded and
validated against IRC line injection. Account, credential, real IP, certificate
fingerprint, session token and operator authority are excluded from this object.

The codec must decode without allocation, preserve exact original signed bytes,
reject unknown versions/operations/trailing bytes, and bind signatures to an
independent domain. Parsing, signature validity, approved full-origin admission,
clock eligibility, revision/equivocation handling and usable-path selection are
distinct decisions. A valid signature alone never publishes route authority.
Renewal changes revision/expiry but cannot improve nickname collision priority.
A quit incarnation cannot be revived by a subsequent PRESENT; reconnect has a
fresh incarnation. Replay and tombstone retention must outlive every admissible
older positive claim; capacity pressure must not discard that protection.

This is an implementation boundary, not a frozen deployed wire format. Transport
negotiation, complete store/path transactions and versioned Helix acceptance are
required before enabling any consumer.

## Current implementation evidence

- Added test-only real A-B-C fixtures in `server.zig`. Final focused Debug is
  **71/73, exactly two intended failures**: far WHOIS returns401 and parser DM
  has no far delivery. Direct-neighbor controls pass. The combined run includes
  the existing shared-session/MARKREAD Helix control and is **72/74**, still only
  the two new failures. Original daemon production and prior tests are exactly
  baseline-identical after reversing the added block. These are causal REDs,
  not acceptance. [Integrator audit](evidence/mesh-presence-2026-10-01/integrator-audit.md).
- New `src/proto/mesh_presence.zig` is exported for unit testing but has no live
  consumer. Allocation-free structural decode and separate origin signature and
  caller-configured lifetime checks bind all original bytes. Six new tests cover
  signature/domain/tampering/truncation, bounds, injection and clock boundaries.
  Final Debug and ReleaseSafe each pass **77/77 including dependencies**.
- Independent codec review found WHOIS field-grammar incompatibility. Root fixed
  nick/ident/server/host grammar and trailing controls, retaining valid IPv6 host
  syntax. Rendering a leading-colon IPv6 literal safely remains an integration
  requirement. Fresh review approves the corrected codec boundary. The codec
  does not grant origin admission, residence or routes.
- Independent Python review passed the native probe and causal target-matching
  correction; compile/help checks pass. Native runtime remains unproven.

Next: prepared retained subject store with irreversible tombstones/equivocation,
exact nick/WHOIS selection, authenticated loop-free path evidence, negotiated
transport and exact guest-message scope, then transactional daemon/Helix wiring.
No full new-slice test gate or new native acceptance is claimed while causal tests
remain RED. The goal and remaining roadmap scope stay open.

## Atomic retained store checkpoint

`src/daemon/mesh_presence_store.zig` now stages owned original bytes before
publication. Commit/abort is explicit under one external owner lock; only one
non-copied prepared handle may be outstanding. Fixed initial slot capacity keeps
commit allocation-free. Full approved origin keys, current approval at lookup,
signed lifetime and stable nickname claim clocks gate one deterministic winner.

The store retains signed equivocation evidence and irreversible terminal quit
state. Distinct accepted signatures over an identical signed body are duplicates;
original forwarding bytes remain unchanged. Renewals cannot improve collision
priority. Pressure never evicts a replay barrier. Allocation-failure sweeps prove
publication remains unchanged on failed preparation.

Fresh review produced and verified three corrections: dual-magic signature
duplicates; clock rollback revalidating identity eligibility; and delayed signed
QUIT invalidating a contradictory newer positive. The latter two failed causally
71/73 before correction. Final store Debug and ReleaseSafe each pass **81/81**
(ten store tests plus dependencies); daemon check passes3/3. Independent review
approves this development-only boundary.

No negative state is evicted yet. Renewable opaque incarnations cannot justify
terminal-barrier expiry; safe compaction requires origin epoch/counter identities
and an original signed complete active-ID frontier through a monotonic highwater.
Cold boot must advance the epoch durably, Helix must preserve it, and failed
counter reservations may be burned but never reused. One long-lived early client
requires active exceptions; a contiguous retired watermark alone is insufficient.
This frontier is separate from authenticated active-path evidence.

Expired signed negative evidence also needs a dedicated validated checkpoint/
repair admission path; generic live prepare deliberately rejects expired wire.
At this predecessor checkpoint, expired-negative restoration and retained
retirement/compaction were not implemented. Subsequent checkpoints below add
the frontier wire and RAM retention; durable restoration remains open.
Consequently the store is not enabled in daemon routing. The two real live
far-guest tests remain intentionally RED. The concrete
[integration contract](evidence/mesh-presence-2026-10-01/integration-api-contract.md)
records registration/rename/quit reservation, exact guest scope and inert Helix
publication requirements. All roadmap requirements remain in scope.

## Complete origin-frontier codec checkpoint

`src/proto/mesh_presence_frontier.zig` encodes original signed complete origin cuts:
full key, durable epoch, revision, counter highwater, issue time and strictly
sorted active-counter exceptions. Guest IDs in `mesh_presence.zig` now canonically
encode nonzero epoch/counter values. This refines the unpublished prototype; no
old deployed reader or live consumer exists for these new records.

A certificate retires only its exact full origin's older epochs or absent counters
within its complete prefix. It does not retire higher epochs or counters above
the prefix. Active exceptions prove neither liveness nor a usable route. A
complete set beyond4096 entries is rejected rather than truncated or converted
into a partial absence certificate. Long-lived counter1 can remain active while
later retired counters are compacted.

Comparison requires monotonic highwater within an epoch and forbids reintroducing
previously retired counters. Both arrival orders detect a contradiction; a late
older certificate can refute a newer resurrecting cut. Equal-body alternate
signatures are duplicates; same-revision different body is equivocation. Caller
retains conflict evidence and origin quarantine irreversibly. Historical
equivocation coverage is limited to retained evidence unless further witnesses
are stored.

There is no negative expiry. Signature/root approval and future-clock eligibility
are checked at initial admission; already retained retirement stays enforced
after clock rollback. Higher epochs reset counter/revision space only under the
future durable cold-boot issuance contract; Helix preserves epoch/counter state.

Current combined presence/store/frontier Debug and ReleaseSafe each pass
**93/93 including dependencies**; daemon check passes3/3. Fresh independent
review approves this codec/helper boundary. Earlier77/77 and81/81 receipts are
pre-frontier leaf checkpoints, not the current combined-source acceptance count.

Next is retained origin-frontier state and a prepared atomic cut that commits the
replacement proof before removing covered subjects. That cut must preserve
quarantine, survive cold/Helix restoration and reject all retired incoming
subjects before allocation/publication. Durable issuance, frontier retention/
compaction, active paths, transport, guest delivery and live daemon integration
remain open. The two end-to-end far-guest tests remain intentionally RED.


## Retained frontier RAM transaction checkpoint

`mesh_presence_store.zig` now owns bounded full-origin frontier slots and exact
original/conflict wires. Subject admission and winner selection consult these
permanent proofs; origin quarantine blocks all subjects and survives later epochs.
A same-origin contradictory cut is retained alongside the first original proof.
Duplicates and consistent obsolete cuts consume no quota or publication generation.

Preparation computes the final retained-byte cut and allocates all candidate
ownership before changing any state. Commit installs the replacement signed proof
before freeing covered records under the shared sole-owner lock, without allocation.
Only non-conflict subjects covered by the exact full origin are removed. Per-subject
conflict witnesses remain owned. The byte limit describes published ownership;
temporary prepared allocations may require additional memory and fail atomically.
This is a RAM transaction, not evidence of durable replacement before disk GC.

Debug and ReleaseSafe each pass **101/101 including dependencies**; daemon check
passes **3/3**. New cases exercise abort, first/replacement/conflict allocation
failures, both contradiction arrival orders, 40 retired counters around one
long-lived active exception, positive/QUIT replay after compaction, above-prefix
admission, foreign origins, permanent retirement across rollback/age, and unchanged
proof ownership under quarantine/pressure. Independent reviews are recorded in
this evidence directory when their terminal results arrive.

Durable epoch/counter issuance, durable proof retention and strict cold/Helix
restoration, expired negative repair admission, authenticated active paths,
negotiated guest transport and live routing integration remain open. The two
far-guest end-to-end tests still intentionally fail; this unused leaf is not
production activation or a full OpenBSD/all-gap completion claim.


## Signed claim transition convergence correction

The review CLI was launched requesting `--model gpt-6-astra`; the launcher header
records that request. The reviewer self-report says it could not switch models,
so this receipt does not independently attest an Astra backend. Its concrete
finding was reproduced: A/revision1/claim10 -> B/revision2/claim20 ->
A/revision3/claim30 fails at a receiver retaining only revision1 because the old
same-nickname rule falsely classifies the latest claim as a renewal. Causal Debug
passed101/102 with exactly this `InvalidClaim` failure.

The unpublished signed presence format now carries `claim_revision`: the origin's
signed declaration of which revision created the current claim. It is nonzero and
no greater than the record revision. Renewals preserve nickname, claim clock and
claim revision. A new declaration must postdate the receiver's last seen record
revision and increase its claim clock. That supports skipped rename-away/back
without permitting unchanged-declaration priority drift or retroactive transitions.
This is an authenticated origin declaration, not an assertion that every historic
transition is retained or that a dishonest origin cannot deliberately rename.

Debug currently passes **104/104**, covering the skipped sequence, signature and
claim revision bounds, forbidden drift/retroactive transitions and subsequent
renewals. Final ReleaseSafe/check and independent review receipts follow below
when terminal. The previous RAM retention review was bounded to compaction;
its101/101 source pin is a predecessor, not approval of this later claim correction.

Durable issuer source analysis also distinguishes reserved issuance highwater
from advertised frontier through: burning a reservation cannot accidentally retire
an ID before registration publishes. Persist epoch/highwater/frontier metadata and
original proof together using a dedicated OroStore transaction before a joint
World/presence/frontier publication. Helix must adopt the strict matching state,
never advance a cold epoch or infer authority by taking maxima. This is a next-step
proposal, not implemented durability evidence.


The independent review additionally found an adjacent exact-nickname priority
increase with no intervening rename and reversed-arrival contradictions of one
signed claim declaration. The final allocation-free pair-consistency helper
orients records by signed record revision before obsolete handling. It pins exact
nickname/HLC for one declaration; changes must postdate the older record and
increase HLC; returning to the same exact nickname needs at least two revisions.
The existing monotonic issue-time rule is checked in this same orientation.
Signed contradictions are retained and quarantine in either arrival order,
including later attempts to reset them. No renewal check was simply loosened.

Final Debug now passes **105/105** at store43c9981c and codecd02259fc. Abort and
allocation-failure sweeps cover cross-revision claim conflict as well as original
equivocation. Six contradictory pairs each exercise both arrival orders; valid
latest-only rename roundtrip and skipped different-name change still converge.
Final ReleaseSafe/check and fresh exact-pin review remain pending at this entry.

The proposed issuer requires an exclusive process writer lease and explicit
Helix custody transfer: OroStore's existing prepared serialization is per
instance, and inode/size checks during promotion are not a writer lease.
Its dedicated WAL parent must enter OpenBSD writable confinement independently
of optional SASL storage. These dependencies remain unimplemented.


Final exact-pin independent review approves this development-only boundary.
Terminal Debug and ReleaseSafe each pass **105/105**, daemon check **3/3**;
format/diff checks pass. Current receipt is `claim-final-review.txt` with
`claim-final-*.log`; the source manifest pins the reviewed bytes. No full ship gate
or new native acceptance is claimed. Far-guest causal failures remain open until
production routing/transport/Helix integration and durable prerequisites are real.


## Dedicated durable cold issuer

`src/daemon/mesh_presence_issuer.zig` now acquires an exclusive nonblocking kernel
lease on a stable canonical `.lock` inode before opening or repairing its dedicated
OroStore. Destruction closes the descriptor without explicitly unlocking shared
copies. This storage is separate from optional SASL account persistence.

Explicit first provisioning writes versioned full-origin metadata and an exact
signed empty frontier together in a prepared durable batch. Ordinary existing cold
open never defaults missing/malformed/partial state: it verifies the paired
original signature, digest, origin, epoch, revision and highwater, then durably
advances epoch before returning authorship. Counter and epoch exhaustion refuse
issuance without wrapping. A failed cold attempt may burn an epoch, never reuse it.

Reservations persist the issued highwater before returning an epoch/counter ID.
A failed registration burns that ID but does not enlarge the advertised retirement
prefix. Frontier publication stages a complete sorted physical active-prefix set
with metadata/proof in one batch, then synchronizes before scalar publication.
The caller must prepare its complete World/presence/frontier cut under the same
owner lock; the issuer cannot certify a partial World inventory by itself.
Ambiguous writes or sync failures poison further issuance until recovery.

Independent review approves the cold-only boundary. Debug and ReleaseSafe each
pass **115/115 including dependencies**, daemon check **3/3**. Coverage includes
constructor and reservation/publication allocation sweeps, strict missing/partial/
wrong-origin/malformed/digest states, signed pair replay after failed/short/sync
writes, overflow, prepared abort, duplicate last-close semantics and an actual
Linux forked independent-open contender denied twice before the owner closes.
No new native OpenBSD execution is claimed for this leaf.

Hot adoption is deliberately still absent: it must carry an explicit typed lease
FD, preserve issuer state without cold advance, keep candidate mutation disabled,
and transfer exclusive authoring only through authenticated COMMIT and predecessor
exit. Existing socket-only inheritance must remain strict. OpenBSD confinement
must admit the dedicated paths. Remote retained proof durability/restoration and
live registration/routing remain open; the cold issuer is not enabled in main.

## Expired negative repair admission

`Store.prepareQuitRepair` stages only independently verified, fully approved signed
QUIT records. It bypasses only the lease `Expired` error. Lifetime, invalid/future
clock, future claim, identity retirement/quarantine and pair consistency retain
all their ordinary checks. Expired positive presence never enters this API.
An admitted QUIT and any signed contradictory positive remain irreversible
terminal evidence. Generic live `prepare` still refuses expired wire.

Debug currently passes **118/118**. New tests cover exact expired proof retention,
rejection of later resurrection, all nonexpiry admission failures, covered-subject
refusal, and a late expired QUIT quarantining a still-valid newer positive. Abort
and both initial/retry allocation failures preserve its published live winner
until a complete terminal candidate commits. This is live negative repair, not a
trusted durable/checkpoint restoration bypass. Final ReleaseSafe/check and exact
review receipt follow when terminal.


Final negative-repair Debug and ReleaseSafe each pass **118/118**, daemon check
**3/3**, format/diff checks pass. Fresh exact-pin review approves the boundary
(`quit-repair-review.txt`); source manifest and checksum ledger pin the receipt.
Current combined118/118 supersedes the cold-only115/115 checkpoint. Neither
new live daemon/native acceptance nor full all-gap closure is claimed. The two
far-guest causal tests and all broader roadmap requirements remain open.


## Verified next durability contract

[retained-durability-next.txt](evidence/mesh-presence-2026-10-01/retained-durability-next.txt)
records source seams and required fault acceptance. Proposed source-owned stamps
must separately preserve admission time/mode/policy for every original and conflict
body. A local signed head authenticates those stamps and the complete image;
remote signatures alone cannot prove prior clock admission. Current approval gates
all visibility/output, while withdrawn-origin records remain dormant so reapproval
cannot clear old quarantine or retirement.

The image/head and issuer metadata/frontier must share the same leased OroStore
and one four-row durable batch. The integrated cold path must validate the entire
old package first and stage epoch advancement plus image/head as one cut; it cannot
call the current standalone cold constructor and then persist the image separately.
Hot adoption needs exact current durable head/issuer relations and typed lease
custody, with no cold epoch advancement. These aggregate APIs are not implemented.

The current winner has no memory of a previously observed expiry after wall-clock
rollback. Strong no-revival semantics requires a durable expiry observation floor,
kept separate from raw-wall future eligibility. This remains an explicit gap.
Whole-image allocation/write cost, configured client capacity versus complete
frontier bounds, and actual native/multi-node acceptance are mandatory gates before
activation. A locally signed image does not prove resistance to rollback of the
entire valid storage image without an independent monotonic anchor.

## Source-owned admission evidence

Every retained subject and origin frontier now has a mandatory `AdmissionStamp`.
Each retained conflict has its own stamp; replacing a record uses the new admission
decision, while duplicates, obsolete records and aborted preparation leave the
published history unchanged. Stamps record the admitted time, exact lifetime/skew
limits, full approved origin and versioned full-key roots/collision policy. They
record expired QUIT repair only when admission actually bypassed `Expired`; fresh
QUIT repair records an ordinary live decision.

The allocation-free 59-byte encoding rejects incomplete/trailing stamps, unknown
versions/modes/policies and invalid time/clock limits. Historical validation binds
the full origin, rechecks the original signature and applies the recorded clock
and claim checks. This does not authenticate a stamp or authorize current presence:
the complete image still needs its locally signed head and current root policy.
No generic trusted-restore flag or production restoration path was introduced.

`Store.comparePresence` now supplies the same pure, exact-subject signed-body pair
classification to network admission and future strict restoration. A saved
quarantine must carry a pair that actually classifies as contradictory in stored
order; an unrelated subject, duplicate, renewal or stale body is insufficient.
The future reader must authenticate stamps and verify both signatures before using
this classifier. Frontier comparisons remain in the original frontier codec.

Debug passes **123/123** including dependencies. Tests exercise separate original/
conflict history, abort and duplicate preservation, replacement stamps, all stamp
prefixes and malformed framing, actual versus fabricated expired admission, signed
pair classifications and historical signature/clock failures. Final ReleaseSafe,
daemon check and independent exact-pin review are recorded with the terminal
receipt. Durable image/head, aggregate WAL commit, strict whole restore, expiry
floor, hot lease custody and live far-guest routing remain open.

Final Debug and ReleaseSafe each pass **123/123**, daemon check **3/3**.
The independent [admission review](evidence/mesh-presence-2026-10-01/admission-review.txt)
approves the exact source pin. Mechanical reversal of this slice reconstructs
the previously approved store byte for byte. The
[next retained API](evidence/mesh-presence-2026-10-01/retained-api-next.txt) narrows
the image/head ownership and four-row transaction seam; it is a proposal, not
implemented persistence. No new native execution or live daemon acceptance is
claimed for these leaf changes.

## Locally authenticated retained envelope

`mesh_presence_retained.zig` implements a fixed signed local head under
`onyx-mesh-presence-retained-local-v1`. Its signature binds the full local key,
realm, durable store UUID, commit/image generations, previous-head digest, exact
image digest/length/count declarations, retained byte declaration, issuer row
digests and epoch/counter/frontier relationships, and expiry observation floor.
Verification uses the expected local key before parsing; realm and structural
head constraints are mandatory. Strict issuer pair validation was exported from
the existing cold issuer without changing its behavior.

`readCommittedEnvelope` requires all four rows and verifies image/issuer digest
bindings and signed issuer relationships. It authenticates opaque image bytes;
it does not validate image records or restore presence authority. Tests cover
every signed byte mutation, every truncated head prefix, trailing bytes, wrong
local key/realm, foreign signer, locally signed malformed fields, every missing
row, invalid issuer state despite matching signed hashes, and a stale head paired
with an advanced issuer counter. The standalone issuer is still not integrated
with retained state: aggregate mutation must update the head in the same durable
cut before activation.

Debug and ReleaseSafe each pass **127/127**, daemon check **3/3**. Independent
[head review](evidence/mesh-presence-2026-10-01/head-review.txt) approves this bounded
layer, with historical pins in `head-source-pins.sha256`. Canonical image parsing,
normalized frontier GC projection, exact count/accounting and whole-candidate
restoration are the next implementation. Current expiry-floor metadata is not an
implemented no-revival policy. A signed local head cannot detect rollback of an
entire valid disk image without an independent anchor. Hot expected UUID/head
relations, custody and live/native acceptance remain open.

## Atomic retained authority checkpoint

Strict canonical image and predecessor-bound package are complete as unused leaves. Aggregate Authority now owns one leased WAL and atomically provisions or advances all four rows, durably reserves counters, and records an expiry floor before irreversible expiry publication. Strict old-image restoration precedes cold epoch advance. Genuine quarantine and negative evidence survive; poisoned or inconsistent owners expose no positive winner.

Current corrected gates: Debug153/153 and ReleaseSafe153/153, check3/3, all terminal exit0. Independent aggregate-review.txt approves exact aggregate-source-pins.sha256. A floor-expired positive admission regression first fails71/72 (expiry-admission-causal-before.log), then passes72/72 after correction; combined final gates include the correction. Earlier image/head pin files retain historical checkpoints.

No live consumers were enabled. Far-guest production regressions remain two failures. Every append-prefix and process-crash package recovery, standalone-writer refusal, typed hot lease custody, joint physical/World lifecycle publication, paths/original repair/ordinary DM custody, capacity/performance and native execution remain open. No deployment or all-gap completion is claimed.

Legacy writer and aggregate recovery checkpoint: supported two-row Issuer provisioning/cold/reservation/frontier APIs now refuse whenever either mandatory retained envelope row exists, including partial/malformed state. Existing storage replay/repair may precede this authoring guard. Tests verify byte-identical complete WAL refusal and aggregate cold retry; malformed-state fixture creation is explicitly test-owned storage mutation.

Current bounded gates Debug157/157 and ReleaseSafe157/157, check3/3, all terminal exit0; independent legacy-prefix-review.txt and immutable legacy-prefix-source-pins.sha256. Every byte prefix of a real four-row negative frontier cut, including the complete append, strictly restores the whole prior/successor image/head/issuer and supports leased cold retry. Five modeled snapshot/truncate/sync cases preserve authenticated negative proof and expiry floor. The short-truncate hook fails before modifying the WAL; no actual destructive truncation or process-kill claim.

Actual Astra production and compound-lifecycle source contracts are archived in astra-production-contract.txt and astra-compound-contract.txt. Next implementation owns one virtual subject+frontier delta over exact predecessor, with a single no-fail RAM generation commit after durable four-row commit. Store leaf writer /root/presence_retained_image owns only mesh_presence_store.zig for that next slice; root owns image/package/authority integration, sole daemon writer remains /root/auth_integrator_finish, server frozen test-only.

Far-guest production causal gates still have two failures. Process crash/hot lease custody, World/physical mapping, path/repair/ordinary DM custody, capacity/performance and native acceptance remain open. No deployment, ship gate or all-gap closure.

Compound local lifecycle checkpoint: source-owned prepared subject+frontier delta over one unchanged predecessor, normalized final quotas, a shared validated projection for image/package, and one allocation-free RAM generation after the durable four-row batch. Full stores can publish registration or renewal with certified GC in the same cut. Terminal QUIT is fully validated before its complete frontier replaces the row; every conflict witness survives. Duplicate plans bind the exact subject even without a candidate. Authority binds current epoch/reserved counter/expiry floor and revalidates before WAL commit.

Debug172/172, ReleaseSafe172/172, check3/3 terminal exit0, fresh compound-review.txt and actual Astra astra-compound-review.txt. Tests include renewal/rename/skipped return/quit, full count/byte quotas, stale-before-WAL, exhaustive allocation failures, ambiguous write/sync, every compound QUIT append prefix, and four real Linux raw-prepared-packet write/fsync/SIGKILL boundaries. These process fixtures are serialized WAL recovery evidence, not daemon live receipt/custody acceptance.

OpenBSD ReleaseSafe filtered test-artifacts cross-build8/8 succeeded. Module artifact SHA256 f19d75af1b899b109aca7b1c665492a63fcf9325879e1e39d69e8964b3da40c1. Actual native module execution completed on OpenBSD7.9 normal8192KiB stack:
170passed,2Linux-onlyskips,0failed (172), terminalexit0; guest hash matches.
Independent compound-openbsd-review.txt approves bounded ReleaseSafe leaf acceptance.
Owned guest directory removed and scratchVM gracefully shut down;2225closed,
imagefusernone, pre-existing2222/2223listeners untouched.

The owning prepared plan is private and immutable during integration. Caller-supplied active inventory is not physical proof: graph owner must derive complete prepared physical mapping under the same lock, or a different live subject could be wrongly retired. Next typed lease/exact-head hot constructor, transactional World/physical mapping, original repair/path/ordinary DM custody, capacity/performance and actual three-node native routing remain open. Far production causal tests remain two failures. No deployment or all-gap closure.


Hot lease and adoption groundwork checkpoint: `HotCheckpoint` captures the exact
signed durable head, issuer state, realm, store UUID, generations and full lock
identity under the quiesced owner. `HotAuthorityStage` consumes inherited close
custody on entry, rejects independently reopened locks while the predecessor
holds its lease, strictly restores read-only state, and prepares promotion before
READY. Activation preserves epoch, expiry floor and quarantine and performs no
allocation, I/O or descriptor close. Its authenticated COMMIT and predecessor-exit
prerequisites remain the caller's integration responsibility.

The native manifest adds singleton role 7 without reducing existing descriptor
capacity. Regular-file validation precedes custody, classification is separate
from sockets, take-once ownership disarms exactly the lease row, and an unclaimed
lease prevents READY. A Windows cleanup ABI regression was reproduced and fixed;
Windows check passes 3/3. Source pins: `hot-source-pins.sha256`; independent static
review: `hot-review.txt`. A new Astra launch and resume were rejected by the agent
thread limit; no Astra review is claimed for this checkpoint.

Terminal combined Linux Debug and ReleaseSafe each pass 182/182, check 3/3.
Typed Linux tests each pass 82/86 with four OpenBSD-only skips. Actual OpenBSD7.9
ReleaseSafe execution at the normal 8192 KiB stack passes 180/182 presence tests
(two Linux-only skips) and all 86/86 typed native tests. Actual SCM_RIGHTS lease
custody, malformed/socket refusal and no-READY checks execute. Host and guest
artifact hashes match: presence `7a54da6079350f0941fa041aefbeff0a832d3e16248d2ab39d30f57ed8a0b8b8`,
typed `812e19930928552ffdcd7d3c75d5ed8d65bd265d7fc43f278f4fe3a62dafc11f`.
Each cross-build passes 8/8. The owned guest directory is removed and the scratch
VM is shut down; port 2225 is closed, image custody is released, and existing
2222/2223 listeners remain. Independent `hot-native-review.txt` approves the bounded native receipt and verifies all 16 source pins and host cleanup.

No live sender or daemon consumer is enabled. Mandatory capsule/lease relations,
total physical guest mapping, transactional World lifecycle, original repair,
authenticated paths, ordinary DM custody, configured capacity/performance,
native Debug and three-node routing remain open. The two production causal
regressions remain RED. This is a bounded groundwork checkpoint, not full-port,
release or deployment acceptance.

The next grounded contract is `world-presence-source-contract.txt`. Current registration queues welcome before fallible World registration; World registration can remove an old owner before a later allocation fails. The next slice needs prepared register/rename/remove with abort and no-fail commit, complete per-shard physical inventory, and held output before the durable Authority cut. This source map is a proposal, not implementation.

Prepared World lifecycle checkpoint (2026-10-01): source `world.zig` is frozen
at `8054b8106eb9a2fb9ffcba7b10202ddd633322149df0e54d4455427b20e318f7`.
A regression test first reproduced owner loss when registration removed the old
nick before a failed allocation (71/72 with a crash). Registration now uses a
prepared ticket; allocation failure preserves the old owner. Prepared physical
register/rename/removal and exact logical nick-owner transactions stage all
fallible work, abort without publication, and commit without allocation or error
under the World graph lock. Removal includes fallback and RCU aliases,
memberships, invitations, and proven-empty ephemeral channel cleanup.

Linux focused preparation passes 80/80; broader World Debug and ReleaseSafe each
pass 178/178, with check 3/3. Independent `world-review.txt` approves the frozen
code under the graph-lock and single-owner ticket contract. Source pins are in
`world-source-pins.sha256`; the historical hot checkpoint pins remain separate.

Actual OpenBSD 7.9 World execution at the normal 8192 KiB stack passes 175 tests,
skips three, and fails zero in BOTH Debug and ReleaseSafe (178 total each).
All nine new prepared World tests execute. The three skips are existing Linux
memfd World migration fixtures. Cross-builds pass 8/8 each. Artifact hashes:
Debug `5a296f0034c0b9cbde7d96386c970bb000232bf55a60539f5c33ebaadccdac1b`;
ReleaseSafe `848ab76ada4a17140a5522b7ad59f25b12035dede2e5ee2f1c5e4e11dc9fd9e4`.
The owned guest directory was removed before scratch VM shutdown; port 2225 is
closed and image custody released. Native receipts and independent review have
the bounded evidence; these tests do not establish live guest handoff.

Legacy `removeClient`/`unregisterNick` remain outside the prepared removal path.
The daemon still needs held welcome/rename/departure output, total immutable
physical identity, the joint Authority/World durable cut, mandatory hot capsule
and lease sender/adoption, repair/path/ordinary DM custody and complete configured
capacity. Full Debug handle 33160 finished with exit 1: 8971/9000 passed,
27 skipped, and two failed (6/8 build steps). The failures are the existing
far ordinary production WHOIS/DM cases; no full-gate pass is claimed here.
This gate compiled the World checkpoint before subsequent grouped leaf edits.
Astra completed the integration contract in `astra-lifecycle-architecture.txt`.
Its current source analysis identifies grouped durability, compound World
departure, transactional output custody, mandatory cold/hot ownership, signed
routing classes and configured capacity as required before activation. The bootstrap
source map `presence-daemon-owner-source-contract.txt` is readiness analysis,
not accepted implementation.

The full requirements extraction is
[gap-requirements-2026-10-01.json](gap-requirements-2026-10-01.json): 92 named
outcomes, 78 explicit acceptance blocks, 25 cuts, and nine global context blocks.
`gap-requirements-review.txt` verifies extraction fidelity. Requirement-by-
requirement current implementation/runtime acceptance remains open.

Grouped durable lifecycle checkpoint (2026-10-01): a real causal test reproduced
the partial cut from sequential single-subject changes. The second preparation
returned MutationActive; committing the first then rejecting the second changed
the durable head (71/72, one expected failure). The plural API now stages every
member against the unchanged predecessor, checks final normalized capacity,
and commits one frontier, image, generation and four-row WAL batch. Invalid,
duplicate, stale, foreign, unissued or conflicting members refuse the group.
Singleton wrappers retain defer-abort compatibility. Exact signed originals
remain owned until cleanup after commit, including compacted QUITs.

Pins: `group-source-pins.sha256`, Store `0ce03010…`, Authority `a549a595…`,
Image `79f3e7ba…`, package `c2b94253…`. Actual Astra's fresh `group-review.txt`
finds no blocking defect under the sole-handle external-lock contract. Commit
has no allocation, recoverable failure or explicit I/O after fsync; compaction
does free old allocations. Postcommit original ownership requires the copied
allocator to remain alive. No stronger reclamation or output guarantee is made.

Terminal Linux Debug and ReleaseSafe each pass 192/192, 4/4; check passes 3/3.
Grouped narrow Debug passes 82/82, singleton regression 80/80. Tests cover every
tested WAL append prefix, preparation OOM rollback/retry, allocation-free commit,
final-capacity replacement, tampered tickets and four actual SIGKILL boundaries.
Both OpenBSD cross-builds pass 8/8. Actual OpenBSD 7.9 Debug AND ReleaseSafe,
normal 8192 KiB stack, each pass 190/192 with two old Linux-only skips and zero
failures. All 11 grouped tests execute, including supported-POSIX SIGKILL.
Skipped fixtures are the old issuer contender and old single-lifecycle Linux
SIGKILL test. Module hashes: Debug
`0143177249cb6c34d4c1199c53715bbe47da68e15c9f5d97719dfc6d950ab768`, ReleaseSafe
`bd27d70075ee3f45799cf3a9cf16b857678d8916c3e5ec526fc3562af209f0cb`.
Actual Astra's `group-native-review.txt` verifies counts, hashes and cleanup.
Owned guest-directory absence was asserted before shutdown; handle 97791
returned exit 0. PID 3508234 and pidfile are absent, image idle, port 2225 closed;
existing 2222/2223 listeners remain.

Full Debug baseline remains 8971/9000 with the two known far WHOIS/DM failures;
it predates grouped edits and is not green. Complete physical inventory,
configured all-reactor capacity/performance, durable egress, daemon lifecycle,
class transitions, provisioning and mandatory Helix joins remain open. The
next assigned implementation is `world-compound-departure-contract.txt`: its
writer owns only World/RCU; these four grouped leaves stay frozen. Neither
native leaf acceptance nor a dedicated WAL completes the full port or roadmap.

### Compound physical departure and prepared output follow-up

The source-owned compound departure now prepares source removal, keeper union,
nickname disposition, fallback membership, RCU roots, name repairs and channel
lifetime as one World ticket. Astra independently found duplicate OID ownership
when repairing absent RCU names; the runtime causal fixture failed 71/72 before
repair. The repaired full fallback ownership check refuses both affected and
unaffected foreign collisions. Fresh review accepts only the bounded World/RCU
leaves at `bb5842f4` / `eff2a677`; Linux module Debug and ReleaseSafe each pass
178/178, with check 3/3. The same bounded module filter also passes all 178
tests on native OpenBSD7.9 in both Debug and ReleaseSafe at the normal 8192KiB
stack limit. These current receipts execute every compound departure test; the
filter excludes legacy daemon migration blocks tested in the earlier broader
World checkpoint. Owned scratch guest files were removed and the VM shut down.

Prepared output is a separate, necessary boundary. New root-owned SendQ, outbound
WebSocket framing and physical-attachment outbox leaves pass 81/81 in Debug and
ReleaseSafe (including mandatory module dependencies). They reserve a complete
raw batch, retain an uncommitted WS prefix on rejection, and own FIFO plaintext
by full origin, subject and generational physical ClientId. Fresh Astra review
approves the three bounded leaves at the archived pins. Actual TLS1.3 and TLS1.2 causal tests expose scratch loss and partial
sequence advancement on OOM: 80/84 before production repair. The TLS writer owns
only the two server engines and TlsConn adapter for that correction.

These are implementation checkpoints. The daemon still requires one held
registration/departure publication cut, transport coordination, all-output FIFO
ordering, aggregate limits, mandatory hot carry, strict signed routing classes,
durable owner startup and far-node routing acceptance. The two known ordinary
far WHOIS/DM failures remain open; no deployment or full-port acceptance follows
from the leaf receipts.

The TLS candidate repair now passes 95/95 focused tests in both Linux modes and
on native OpenBSD7.9 in both modes, at the normal stack limit. Existing TLS
compatibility gates pass 831 tests with one skip out of832 in each Linux mode.
Fresh Astra source review approves with explicit qualifications: the new limit
fixture injects100 after handshake, exhaustion can follow adapter descriptor
allocation, and the prepared lease covers TX under one exclusive owner turn.
The daemon writer is implementing the existing append-path transaction next;
the leaf receipts do not yet qualify that integration.

An additive OPRS2 codec now signs an explicit routing class and independent
class_revision, refuses unsupported fields/version/domain, and compares class,
nickname and terminal chronology without arrival-order authority. Its finite
oracle covers243 five-revision class paths and765 endpoint cases; other fixtures
cover signatures and terminal records. Linux Debug/ReleaseSafe and native OpenBSD
Debug/ReleaseSafe each pass81/81; frozen v1 control passes79/79 and check3/3.
Fresh Astra source review accepts the additive codec only. V1 and the four grouped
retention leaves remain unchanged. Required OPRI2/OPRH2 storage barriers, complete
physical mapping and hot schemas, negotiation and delayed-recipient binding are
still pending. No class default is inferred from an absent tracker or token.

Existing daemon TLS and WebSocket application output now prepares the complete
framed/ciphertext batch and exact SendQ capacity before advancing TLS sequence
or committing the outbound WS tail. At server pin9a5181a3, Linux Debug and
ReleaseSafe each pass107/107 focused tests and113/113 existing compatibility
tests. Native OpenBSD7.9 passes107/107 in both modes at8192KiB. Fresh Astra
review accepts this bounded integration with nits; outbox activation and the
held lifecycle publication cut remain pending.

The broader native113-test compatibility run exposed fixture stack failures:
Debug stops at labeled WHOIS (row70), ReleaseSafe at preframed WS media (row75).
The frozen Debug ELF proves a7,946,240-byte WHOIS frame calling a10,572,288-byte
by-value Server initializer; other selected WS frames reach25,263,136 bytes.
Production main already uses heap Server/initInPlace. A test-only candidate at
8e9a1848 moves19 affected fixture sections to owned heap objects, preserving
wire/assertions/platform guards and reversing exactly to9a. Its Linux Debug
compatibility passes113/113; fresh review and native retry remain pending. No
stack-limit increase or test exclusion qualifies this correction.

A complete isolated1755-file Debug snapshot remains running at9a, with manifest
7e1e2015; its source has not changed during subsequent fixture correction.
Retained OPRS2 cold migration design remains blocked on existing-lock no-create
and durable atomic publication of a complete WAL epoch. No schema migration or
full port acceptance is claimed.

The8e heap-fixture correction is now independently approved by Astra. Native
OpenBSD7.9 compatibility completes in both modes:110 passed,3 unchanged
Linux-only skips,0 failed out of113, at8192KiB. Focused transactional output
completes107/107 in both modes at the same pin. Owned guest files were removed;
the scratch VM exited, its image is idle, port2225 is closed and the two
preexisting VM ports remain listening.

The immutable9a full Debug snapshot completed exit1:9,045/9,074 passed,
27 skipped and exactly2 failed. The failures are the deliberate ordinary
far-nickname WHOIS and direct DM A-B-C causal tests. This is complete current
production-source Debug evidence with explicitly open routing gaps; it does
not accept the full port or substitute for final source/hot/live acceptance.

Fresh Astra review approves the retained V2 cold-recovery design at
contracta5441727 (review28a9661b), after refuting three defects: existing
lock creation on refusal, partial authoritative epoch publication, and valid
dual-coverage rejection. One writer now owns the five schema leaves and bounded
store recovery helpers. Existing lease custody precedes captured replay; schema
authentication precedes repair. Atomic full epoch replacement retains complete
OLD-map snapshot coverage and appends only on the owned replacement FD. This is
design acceptance; future source and crash/OOM/native evidence remain required.

Retained V2 implementation began with two causal runtime tests before semantic
repair: module71/73 passed,2 expected failures (overall73/75 with CLI2). Old
Authority created a missing lock and advanced cold state; old Head retained the
v1 signing domain. The old production plus exact new tests and emitted binary
pin are preserved separately from the eight-file pre-test source baseline.

TLS schema3 remains unimplemented. Astra's source contract identifies missing
peer limits/exporter, offload guard/state coherence and inaccurate legacy
capability advertisement. Root's subsequent source/specification check found
an additional prerequisite: TLS1.3 encrypted flight and NewSessionTicket are
sealed as single records, so a new negotiated64 client test must also verify
protected-record fragmentation and receiver enforcement. RFC8449 section4
(https://www.rfc-editor.org/rfc/rfc8449.html#section-4) covers protected handshake
records, excludes unprotected messages, and distinguishes TLS1.2/TLS1.3 record
limits. No low-limit production client option or schema shortcut was introduced.

Astra's fresh held-lifecycle review (`184690d5`) refutes the earlier map as a
complete activation contract. It identifies unlocked boot/redial slot publication,
missing complete SessionStore staging, cross-WAL account revocation, output
custody/budget, strict hot joins, and renewal/capacity ownership. The subsequent
537-line SessionStore batch contract (`1f4f8b38`) was read and accepted by root as
a bounded proposed leaf design; no SessionStore writer has started. Server remains
frozen at `8e9a1848`. These design artifacts do not certify daemon activation.

Root's four outgoing TLS consumer files now use owned fatal alert batches, preserve
queued KeyUpdate order, and drain normal SMTP control replies. Fresh review exposed
an unbounded ACME fatal-write dependency and post-request HTTP fallback/replay.
The shared terminal socket writer now uses nonblocking sends with one absolute
one-second deadline; HTTP permits TLS1.2 fallback only before the application
phase. An actual loopback POST fixture checks the decrypted request, protocol
failure, terminal socket output and absence of a second connection. Actual SMTP
readChunk/sendBytes exercises KeyUpdate response and subsequent new-epoch NOOP.
An allocation-index sweep covers pending control and plaintext ownership; its
earlier aggregate-counter harness failure was not a proven production leak.

The corrupted POST response also supplied an actual causal MAC-alert RED: 71/72
passed, one expected failure, zero leaks/log errors, exact AEAD-opened fatal50
versus required20. RFC8446 sections5.2/6.2 require bad_record_mac for deprotection
failure. The TLS owner now distinguishes RecordAuthenticationFailed from framing
BadRecord; the unchanged wire oracle passes in root Debug-8:80/80, nine actual
new named fixtures and71 existing zero-filter import rows. Root check-3 passes3/3;
current ReleaseSafe/native acceptance and fresh final MAC review remain separate.
The prior consumer review (`65b18485`) accepts the earlier repaired deadline/POST
cut; it predates the exact fatal20 fixture. Concurrent TLS7 and retained6 are
still active and have not received a final source or native grade.

Root consumer freeze2 now passes Linux Debug/ReleaseSafe80/80 each and check3/3.
Fresh MAC review (`c8c32d1c`) independently verifies exact fatal20 and preserved
request/error custody. Native consumer artifact compilation has begun; runtime
evidence is pending. Retained6 is frozen at candidate pins and Astra is actively
refuting its full authenticated cold-recovery implementation; its broad gates
remain owned by the writer. These results still do not close full TLS7/hotSchema3,
held lifecycle, ordinary far WHOIS/DM, or full OpenBSD product acceptance.

Root consumer freeze3 now passes actual OpenBSD7.9 Debug80/80 and
ReleaseSafe80/80, zero skips, with unchanged normal8192KiB stack. The first
native attempt exposed a fixture portability assumption: OpenBSD accept inherits
listener NONBLOCK. Only the accepted test socket is normalized to blocking mode;
production is unchanged. The first failure, corrected fixture pins, both final
binary hashes and complete native logs are preserved. Guest cleanup and owned VM
shutdown are verified; prior ports2222/2223 remain untouched and2225 is closed.
This certifies the frozen consumer cut, not the concurrent TLS engine repairs.

Astra's retained candidate review (`7c7ea69f`) found three concrete blockers:
checkpoint capture accepted modified cached signed image/provenance, durable
publication could synchronize the wrong parent for nested/absolute paths, and
blocking no-follow opens could hang on FIFO namespaces. Seven capture/parent
causal tests failed on old production; three bounded FIFO cases failed separately.
The six-file owner has repaired canonical capture, actual destination-parent
custody and nonblocking regular-file acquisition across cold validators. Fresh
final-source review and broad gates are in progress; passing narrow tests alone
does not accept the repaired candidate.

Astra's TLS prerequisite review (`24fe8f10`) blocks the seven-file candidate:
TLS1.3 replied to authenticated peer fatal alerts, shared TLS1.2 protected-open
errors used incorrect fatal codes, and adapter errors could omit earlier
unpublished handshake flights. The writer now also owns the narrow shared
TLS1.2 decoder seam (eight files total). The adapter repair must retain owned
flights before engine consumption, publish them once in order, preserve terminal
cause through allocation retry, and discard unpublished output on peer fatal
alerts. Historical Debug/ReleaseSafe880/881 (one existing skip) and check3/3
remain evidence for the prior candidate, not approval of this repair. Server
remains frozen at8e9a1848; mandatory hotSchema3 is still outstanding.

Root also captured two Session lifecycle causal failures in a separate immutable
949-file source snapshot: allocation failure in legacy detach changed the OLD
attached row, and reusable bootstrap admission lacked an exact stable attachment.
The baseline is71/73, exactly two expected failures and zero leaks/log errors;
all949 source pins remained unchanged through the run. Live sessions.zig remains
unchanged. These failures support the complete prepared-batch contract rather
than isolated patches to legacy calls; no live Session writer has started.

The repaired retained candidate remains unaccepted after the follow-up review
found the same parent-sync issue reachable through ordinary threshold compaction.
Root explicitly expanded Store ownership to its shared syncDir helper and hot
existing-file acquisition: readonly WAL open, snapshot/WAL replay, and writable
promotion reservation. Required behavior is nonblocking no-follow regular-file
acquisition, replay bound to the original held WAL, full device/inode/size custody,
and synchronization of the actual destination parent. Decoder tolerance, optional
snapshot absence, and strict hot no-write staging remain unchanged. This shared
seam must pass causal tests and fresh review before the retained slice is accepted.

TLS adapter disposition distinguishes unpublished owned flights from output
already returned to the caller. A peer fatal alert discards this call's unpublished
ledger and generates no reply. Cancellation of already caller-owned queued bytes
is a separate Server lifecycle policy obligation; it is not certified by the eight
TLS leaf repair while Server8e remains frozen.

Fresh independent consumer native review (`644518fc`) accepts the bounded
consumer freeze3: exact fixture-only diff from approved production freeze2,
both local artifact hashes matching guest receipts, 80/80 sequential native
results in each mode with zero skips and normal8192KiB stack. It explicitly
does not certify an immutable complete TLS dependency-source cut or the eight
concurrent TLS files. VM/image/port cleanup is archived; the guest cleanup log
is empty, so that archive alone is not a separate directory-absence receipt.
A later whole-source native snapshot is required for final integrated acceptance.

The actual live Authority threshold-compaction causal run now reaches all26
SIGKILL epoch boundaries. Prefixes1..24 cause exactly24 authenticated cold
restart refusals; empty and complete25-byte epochs restore OLD successfully.
The baseline is71/72 (one aggregate expected failure), harness73/74. This proves
the availability gap is reachable through ordinary authority preflight, not
only a synthetic malformed WAL. Complete atomic replacement remains in progress.

Root also confirmed current hot ResumeState/capsule paths omit negotiated peer
record limits. Until strict schema3 carries them, export must refuse noncanonical
peer raw values (TLS1.3 other than16385, TLS1.2 other than16384), including valid
high offers that would otherwise lose exact state. Ordinary64..65535 negotiation
remains supported. The temporary containment (`26471fd6`) is an invariant guard,
not completion of the every-attachment hot-upgrade requirement.

The complete retained replacement now passes the actual live compaction crash
matrix: all26 epoch-write cuts recover OLD, with additional publication and
successor packet cuts. Astra independently approved the six-file source
(`d2f3e3d4`). Linux mesh gates pass196/196 in both modes, and Store172/172 in
both modes. This closes the reproduced destructive epoch replacement defect;
native acceptance of this final source remains outstanding.

The corrected eight TLS files are frozen and independently source-approved
(`82f7e144`). Debug and ReleaseSafe each pass906/907 with one existing skip;
check passes3/3. A further causal test found pending old-key KeyUpdate output
could be omitted by direct resume export. The corrected export guard and owned
flight retry tests pass73/73. These leaf results do not certify schema3 or
preservation of every live attachment during hot upgrade.

The first combined immutable OpenBSD build reproduced a native ABI compiler
error in Store's new openat call: its variadic mode argument required an explicit
fixed-size type. The only repair is `@as(std.posix.mode_t, 0)`; Astra approved
the exact delta (`a13c4505`), and isolated Linux Store gates again pass172/172
in both modes. A new961-file immutable source cut composes the previous verified
whole source with this exact retained overlay. Active Session edits are excluded.
Both native build modes are running against that cut; the failed first builds
remain archived as causal evidence.

Root's real Linux7.1.3 kernel probe passed three fragmented TLS1.3 KeyUpdate
cases using AES128 RX offload. It verifies record-end flags, EKEYEXPIRED,
the live key/IV/sequence getter, reinstalling the same old tuple to consume the
remaining fragment, and receiving a record after a new tuple is installed.
This is a kernel primitive experiment with public fixture keys. It does not
prove authenticated TLS/HKDF, other cipher suites, Server integration, or hot
capture. Astra's complete schema3 contract must include partial control state,
kernel cursors, TX control ordering, and gating ordinary plaintext reads while
a KeyUpdate is incomplete.

Session lifecycle implementation is now active under sole sessions.zig ownership.
It follows the complete prepared-batch contract, including owned affected rows,
one OLD discovery pass, explicit bounds, journals, validated preview and a
nonfallible retained commit. The two legacy causal failures remain historical
evidence; their singleton APIs have not been patched to conceal the missing
transaction. Full contract tests and independent acceptance are still pending.

Astra's definitive453-line whole-chain contract (`87dc1f5a`) is archived.
The integrator now owns its complete nine-file engine/adapter/kernel/Helix/Server
implementation boundary. Before editing, it captured1,944 source/build/test/tool/
documentation files and verified all19 contract pins against copied and live
source. The mandatory nondestructive capture inventory includes caller bytes
and unexposed owned engine flights exactly once, with matching epochs; temporary
export refusals remain until the complete paired consumer is implemented.

A separate real Linux TX primitive experiment passed five KeyUpdate splits1..5.
Typed handshake sendmsg pieces authenticate under the OLD key; full TLS_TX
getters report exact next sequence, and a new tuple produces decryptable
application data at sequence0. Astra independently approved this bounded
evidence (`de196aa6`). Each deliberately chosen piece was accepted in full:
partial syscall acceptance, backpressure, authenticated TLS/HKDF and Helix
remain explicit implementation gates. The production daemon is unchanged by
either Python experiment.

Both native artifact builds succeeded8/8 against the composed961-file cut.
Runtime Debug then failed at row561 in the stack probe at normal8192KiB,
in a previously by-value Server exploit fixture. The integrator isolated20
native-enabled exploit fixtures to heap allocation with initInPlace, preserving
all production bytes and test assertions; independent review is pending.
Runtime ReleaseSafe reached all1133 rows:1102 passed,13 skipped,18 failed.
Seventeen new Store causal fixtures failed at unsupported realPathFileAlloc
before exercising their assertions; the owner is making those path/FIFO helpers
execute natively. The remaining TLS audit failure was missing tools/src files
in the guest working directory. The next run must carry the exact frozen source
files as well as its artifact. Neither failed native run is acceptance.

The corrected frozen cut's Linux broad gates are terminal: Helix789/797 with
eight skips in both modes, exploit158/158 in both modes. All961 source pins
remain unchanged after those gates. Standard Helix output omits individual
skip names; the aggregate is not a claim of complete physical upgrade coverage.

The final Store native fixture correction (`6bcf4b3e`) replaces descriptor
realpath with supported getcwd plus the documented testing temporary path.
Independent safe opens of the derived and held directories must match full
device/inode identity before use. Astra approved the test-only delta
(`7c930f19`), and isolated Linux Store again passes172/172 in both modes.
Actual FIFO creation, child execution and watchdog assertions are unchanged.

The20-fixture native Debug rerun passed the original row561 but then reproduced
the same stack-probe failure at row565, SESSIONTOKEN's by-value Server fixture.
The owner audited all selected Server names and converted six additional
native-enabled fixtures, including mTLS and DTLS, for26 total. Astra verified
exact reversal to the original8e source and correct cleanup/join lifetimes
(`3f437709`). Five remaining selected by-value fixtures have explicit pre-existing
Linux-only guards. The next composed961-file source cut uses this913a fixture
overlay and final6bcf Store. Guest source hashes match all961 host pins; Debug
is running at8192KiB and ReleaseSafe is building. The failed earlier cuts remain
historical evidence, not accepted final binaries.

The whole-chain implementation also identified an additional mandatory state:
software-TX KeyUpdate backpressure needs a typed deferred plaintext tail behind
the existing ciphertext prefix. It must be reserved/counted by the SendQ owner
and carried separately with its barrier phase in schema3. Root, integrator and
Astra are specifying that complete consumer boundary before queue edits;
plaintext is never relabeled as pending ciphertext to fit the older shape.

The final source5 native union is terminal GREEN in both modes:1120 passed,
13 skipped,0 failed of1133 sequential rows, OpenBSD7.9 normal8192KiB stack.
All961 host and guest source hashes match before and after both runs. The
original18 ReleaseSafe failures are eliminated without reducing the1133-row
inventory; the earlier Debug stack failures and their immutable cuts remain
archived. The complete receipt distinguishes this frozen TLS8/retained6 cut
from concurrent Session/TLS3 development. Fresh native evidence review is active.
Owned guest directories were explicitly witnessed absent; owned QEMU3601195
is dead, its pidfile absent, the image idle and2225 closed. Existing2222/2223
remain open and untouched.

The definitive258-line queue/schema amendment (`5e80f3fb`) carries a mandatory
typed deferred tail, barrier phase and explicit27-byte software/5-byte kernel
reply credit. Empty input chunks are no-ops; stored zero-length envelopes are
rejected. Credit counts against the physical cap and never becomes armed data.
This prevents a full deferred tail from starving its required reply. Root has
read the complete contract and owns the next SendQ implementation; the integrator
owns all engine/adapter/Server/capsule consumers. Schema3 remains unaccepted
until those consumers and actual physical upgrade gates pass together.

The integrator's first real state/codec development gate is73/73, after the
old71/73 causal failures for negotiated64 and omitted exporter. It is explicitly
partial evidence: mandatory tail fields, kernel cursors/control ordering,
strict capability advertisement and full physical capture/adopt remain active
work. No deployment or whole-port completion follows from the leaf result.

The final source5 native proof received fresh Astra APPROVE (`b6ea962b`):
all961 source pins, sequential1133 rows, identical13 platform skips, artifacts
and owned cleanup were independently checked. This remains a frozen TLS8/retained6
prerequisite cut, separate from current Session/TLS3 development.

Root implemented the complete typed queue reservation boundary in SendQ, final
source `b1a41075`: reply credit and deferred future-ciphertext charges count
against physical capacity while only actual wire bytes arm output. Positive
plaintext chunks retain owned length envelopes; complete tail replacement and
reserved control reply commits are allocation-free after preparation. Exhaustive
reservation allocation failures preserve prior wire, credit, tail and ownership.
Astra found that borrowed payload/descriptor slices could be invalidated by tail
growth. An actual test failed against the first implementation; the repair rejects
self-borrowed input before metadata allocation or buffer growth. The identical
causal test then passed; fresh source review approved the repaired lifetime boundary.

Final immutable961-source SendQ-only composition passed Linux Debug90/90 and
ReleaseSafe90/90, check3/3. Native OpenBSD7.9 Debug90/90 and ReleaseSafe90/90
passed without skips at the normal8192KiB stack; host and guest binary hashes
match and all961 host source pins remain unchanged. These counts include import
rows; the direct queue module has10 tests. Owned guest queue directory absence
was witnessed; QEMU3624472 is dead, pidfile absent, image idle and2225 closed.
Existing2222/2223 are untouched. Fresh native review is active. Full TLS3
consumer, capture/adoption, fleet budget and upgrade acceptance remain pending.

Astra blocked the first complete Session batch on four actual defects: same-token
reconnect omitted retirement of the displaced physical attachment; chained
account rebind merged mutable FINAL instead of immutable OLD; included sentinel
rows could hide duplicate ClientIds outside the folded closure; private copied
lookup work was quadratic and unmetered. Five causal tests failed against the
frozen candidate, including8256 old-group comparisons for129-token one-observation
work. The owner is repairing complete retirement, canonical OLD/FINAL generation,
global duplicate validation and owned indexed candidate lookup. No daemon
activation follows from the earlier leaf counts.

The integrator's coherent production capture/adoption check is now3/3. Actual
authenticated requested/split KeyUpdate fixtures require a narrowly owned TLS
client test seam; it must seal with negotiated keys, validate positive fragment
shapes and rotate only after the whole owned batch is prepared. Complete software
and kernel mode tests and strict physical joins remain required before capability
activation. No deployment or full-port completion is claimed.

Fresh Astra native SendQ review APPROVE (`b70b1ef6`) independently verifies the
complete961-file immutable composition differs from accepted source5 only in
SendQ, both actual ordered90-row native runs, all10 queue tests, artifact hashes
and exact owned VM/pidfile/image/port cleanup. The bounded queue grade is accepted;
full TLS3 consumer and hot physical integration remain active and ungraded.

The Session owner strengthened the B2 causal receipt with a direct OLD-derived
portable-state assertion: the frozen algorithm fails71/72 independently of
canonical hashing. The repaired immutable iteration now passes102/102 module
tests, including all five causal cases and75 allocation-failure sites. Owned
private key/token indexes bound the129-token case to129 group lookups instead
of8256 linear group comparisons. Final targeted coverage, named gates, source
freeze and fresh Astra regrade remain pending; this iteration is not activation.

Sessions repaired candidate31557759 is now freshly source APPROVED by Astra
(`222fd9ce`): all B1–B4 closed after full planner and33 test review. The immutable
961-file composition overlays ONLY Sessions onto accepted source5; legacy bodies
remain insertions-only. Named Linux Session Debug789/789 and check3/3 are terminal
green. Broader server Debug remains469pass4skip2fail/475, reproducing the exact
known secured A–B–C ordinary WHOIS/DM defects. This is not a full green gate.

Root ran both actual OpenBSD7.9 Session module binaries at8192KiB:104/104 each,
zero skips/failures,33 lifecycle tests plus71 import rows. Both native executions
exercise83 mixed allocation failures and35 same-token allocation failures before
success; those counts may differ from the75-site Linux iteration. Host/guest
binary hashes match, all961 source pins are unchanged, and ordered test names
match between modes. Owned guest directory absence and QEMU3630204 shutdown/PID
death/exact pidfile removal/image idle/2225 closure are witnessed;2222/2223 remain
untouched. Fresh native audit is underway. Outer World/cross-WAL/Server/Helix/far
activation remains mandatory and separate.

TLS owner iteration74/74 is terminal green on an immutable2050-entry source cut
(`b22fb881` manifest; root independently verified every copied file and symlink).
The new fixture uses51 genuine negotiated authenticated connections:
AES128/AES256/ChaCha across four software/kernel RX/TX combinations and four
KeyUpdate fragment splits, plus one-byte kernel receives per suite. Peer old-key
reply decryption, HKDF secret equality and new-epoch bidirectional plaintext are
asserted. Current kernel tuple checks compare sequence counters; complete
byte-exact key/IV/cipher/sequence assertions are being added on the live owned
path. Full Server queue barriers, backpressure/races, paired nondestructive
capture/adopt/OOM/tamper and strict capability joins remain pending. The74-test
historical cut is not overwritten.

Final Session leaf gates are all terminal on the same31557759 composition:
named Session789/789 Debug and ReleaseSafe; services570/570 Debug and ReleaseSafe;
check3/3. Server both modes retain469pass4skip2fail/475, exclusively the ordinary
far WHOIS/DM failures. Final owner receipt (`5e42e58a`) pins six named gate logs,
binaries, commands and unchanged961-file source;33-test matrix is06f28add.
Fresh native review APPROVE (`2d8e55cf`) independently confirms both104-row runs,
all33 actual lifecycle tests,83 mixed and35 same-token allocation failures,
matching artifacts, immutable source and exact owned VM cleanup. Source315 remains
frozen; this closes the bounded Session leaf, not daemon activation.

Next Astra task derives a complete implementation-ready physical registry/global
outbox/mandatory snapshot contract from the earlier B1/B4/B5/B6 findings. Root's
proposed next file set is physical_lifecycle.zig, lifecycle_output.zig and
helix/physical_lifecycle_snapshot.zig; no new production edit begins before the
complete exact interface/ownership contract. The Session owner separately traces
Services account-WAL DROP/recovery and Presence WAL revocation joins, so a durable
account deletion followed by failed presence append cannot leave serving stale
positive/private attachment authority. That mapping is read-only until ownership
and a complete recoverable protocol are assigned. The sole server writer continues
the full authenticated TLS3 transport/physical hot integration.

Astra delivered the complete1058-line physical registry/global outbox/mandatory
hot contract (`e77f539d`), with38 inspected source/contract pins. It separates
preregistration carrier RowId from published signed subject, includes explicit
auth/provider/account-incarnation provenance, allocation scopes/linear quota
transfers, active/held/retired equations and strict bidirectional joins. Required
activation extensions include supported total above4096 with versioned frontier/
FD/manifest capacity, complete held-client codecs, durable A/P account recovery
and exact original-egress journal embedded in the authenticated four-row Presence
image/head. A RAM-only outbox cannot close cold custody; negative-frontier dominance
alone does not preserve exact normalized-out QUIT wire. Root has not yet begun the
three-file implementation; full normative read is required first.

The read-only318-line revocation proposal (`4f5b42ab`) identified existing ordinary
DROP as account-only deletion. Actual five causal tests now reproduce the gap
on an immutable961-file source5 cut with test-only Services append:71 import rows
pass, five tests fail, zero skips/leaks. Cached and cold actual SCRAM credential
callbacks with original-password StoredKey proof and CertFP/EXTERNAL lookup survive
durable DROP and its real status predicate. SASL token denial remains a control.
A real changefeed allocation failure after append+sync reports DROP error even
though RAM and cold-WAL account are absent; companions remain. This is callback/
status proof, not a full transport SASL exchange. Root independently verified
all18 inventory copies,961 causal copies, unchanged518815 production-prefix bytes
and actual binary/log hashes. Earlier CertFP absence-denies inference is explicitly
corrected. Durable typed tombstone/intent and complete cohort/cleanup/reuse recovery
remain proposed, not implemented or approved.

TLS owner actual software Server barrier iteration passed75/75; paired inert
adoption iteration76/76 and codec86/86 remain bounded proofs. The new real armed
SEND/CQE fixture exposed a separate production bug: a whole TLS batch could enter
overflow with empty inline storage, and armSendIfNeeded returned without arming.
Actual78/79 RED and exact pre-fix source4589 are preserved. Central owner refill
only after unarmed ownership release fixes it; unchanged actual armed assertions
then pass79/79 across three suites, including genuine Linux partial completions.
The entire2050-entry tested cut is immutable (`60d5ade8` manifest), all copied
files/symlink independently checked by root. Capability remains unactivated.

Root then traced a funded kernel-TX FIFO concern in that immutable source. Actual
authenticated causal test11374 confirms it:71/72, first AES128/softwareRX/kernelTX
unarmed-inline case observes KU reply before any previously accepted128-byte
plaintext prefix. The complete24-case intended matrix has not all run against
OLD because this first case fails. Source2e4e and binary78d1d933 are retained.
Astra is specifying a mandatory old-prefix cursor in the single kernel plaintext
FIFO; the integrator owns the coherent producer/SEND/CQE/codec/capture/adopt change.
No discard, rejected accepted output, optional kernel tail or whole-FIFO wait
substitutes for that cursor. No corrected kernel grade or full-port acceptance
is claimed at this checkpoint.


### Full registry contract and first shared budget implementation

Root read all 1058 lines of the physical lifecycle contract `e77f539d` and accepted its complete three-file boundary and mandatory outer activation dependencies. Root owns the new physical registry and physical snapshot modules plus `lifecycle_output.zig` and narrow root exports. Only the output accounting foundation has been written so far. The registry, strict codec, whole fanout reservation, external buffer ownership transfers, typed streaming routes, durable original-egress journal, account authority joins, and full daemon activation remain required. Historical standalone Outbox callers were searched: only root export/harness references exist; no live consumer was converted or bypassed.

The new metered allocator pre-funds tracking metadata, records actual requested capacity plus alignment padding, shares fleet and physical-row limits, preserves resident plus candidate peak charges, and keeps wire liability in checked receipts. Allocator context is heap-stable; bookkeeping callbacks allocate no metadata. Publication has a final fallible validation/seal and a trusted allocation-free commit. This accounts for capacity; it does not yet authenticate semantic payload contents or establish whole-transaction rollback.

Fresh Astra review of immutable source1 (`5e1a57da`, 961 files) blocked two real defects: public ticket owner retargeting between components with matching counters, and cancellation depending on another settlement serial at exhaustion. Root preserved the original source and ran three actual causal tests: terminal handle 55710 exited 1 with 77/80 passing and exactly those three failures. The repair binds every scope, settlement and receipt to fleet, burned component serial and physical row; cancellation now refunds an unsealed empty preparation directly without minting a serial. The same three assertions then passed, terminal 72255, 80/80.

Immutable source2 output `a175f918` and all 961 source hashes were verified after testing. Linux Debug handle 29489 and ReleaseSafe handle 68077 both exited 0 with 82/82 tests (11 direct foundation cases plus 71 imports). Compile check 48837 exited 0, 3/3 steps. Additional cases cover cross-fleet scope retargeting, OOM serial burn, construction/publication exhaustion, exact abort refunds, retained alignment/resize charges, copied partial wire receipts, publication tampering, and exhaustive component-construction allocation failures. Source2 fresh Astra review is pending. No native runtime or full port result is attributed to this new foundation.

Root also read the complete 401-line kernel-prefix amendment `10250b19`: one kernel plaintext FIFO, mandatory old-prefix cursor, strict schema minima 226/164, exact submitted-span/CQE accounting, held-prefix retry and overflow scheduling, and terminal custody. Integrator reports full 24-case real authenticated TCP prefix/reply/suffix coverage and six same-FD double phase2 adopt cases passing; these remain bounded reported gates on a moving TLS3 source, with whole-chain review/native/hot acceptance still open.

Root read all 341 lines of Astra account revocation review `49e3e0a1`. The central durable account-intent → Presence-negative → joined-ACK architecture and all five actual old credential/WAL causal failures are accepted. The implementation-ready handoff remains blocked on six mechanical contracts: incarnation/provider proof and final admission CAS; joined resource acquisition and old-reader refusal; exact locks/phases/poison/ACK liveness; mandatory versioned durable original-egress journal and acyclic commitments; complete conditional companion cleanup with aggregate four-row capacity; and universal maintenance/private/hot authority joins. The account owner is writing the complete amendment, with no production file grant yet. Cache deletion or name-only gates do not close these defects.

Artifacts, exact source manifests, raw logs, reviews and receipt are under `docs/audit/evidence/mesh-presence-2026-10-01/physical-custody-budget-*`; the full kernel amendment and account design review are archived alongside them. No deployment, push, capability activation, goal completion or full OpenBSD acceptance occurred.

Fresh Astra source2 review `e0fe8433` subsequently approved the bounded foundation; root read all 137 lines. Both ticket and cancellation blockers are closed. All 961 source hashes and the unchanged three causal tests were independently checked. The review preserves the mandatory outer work and stable owner lifetime requirements.

Source2 was then cross-built for OpenBSD in both modes, 8/8 steps each (handles 28598 and 89827, terminal 0). On the owned OpenBSD 7.9 GENERIC.MP#449 VM, the module binary ran 82/82 tests in Debug and 82/82 in ReleaseSafe, zero skips, normal 8192 KiB stack, both SSH commands terminal 0. Debug binary SHA-256 is `3b64f16ea88738093b641f8609ef0e28da0ef24de7f21a24c798526a8715ebeb`; ReleaseSafe is `4730c16d78a5263c77be2738ba32dcd7dc2a184fb213d4cd6f137e71e537c2fa`. The full 961-file source manifest matched before and after each run, four complete native check logs. CLI/daemon artifacts were compiled but not executed. This is native foundation evidence, not full OpenBSD daemon acceptance. Fresh native receipt review is queued after the mandatory whole-budget contract work.

Owned VM PID 3651765 was shut down after removing and verifying absence of `/tmp/onyx-physical-custody-20261001`. Root verified PID exit, exact pidfile absence, idle qcow2 image, closed port 2225, and unchanged unrelated VM listeners on 2222/2223. All 566 archived evidence files passed SHA256SUMS verification. No owned VM or root test handle remains running. Next root implementation is the mandatory all-participant transaction reservation and linear external-capacity/wire transfer, then typed streaming output and the full registry/strict snapshot, under the accepted contract.

### Geometry, whole-resource admission, and corrected account startup evidence

Fresh Astra native review `809b7ca0` approved the budget source2 native receipt at its bounded scope: OpenBSD 7.9, 82/82 in both modes, normal stack, exact source and artifact hashes, and verified owned VM cleanup. Exact executed command transcriptions are separately qualified as transcriptions, not additional executions. The foundation still does not establish whole-daemon OpenBSD acceptance.

Root read all 537 lines of the mandatory whole-resource ABI `dd14efc9`. It requires a pre-funded planning workspace, stable allocation homes, atomic funding of all participants, exact OLD/FINAL ownership and external transfers, an allocation-frozen seal, and publication that permits only predeclared frees. The previously approved independent component budget is a foundation; it cannot publish a daemon lifecycle by itself. The unchanged SendQ b1 preparation and shape-free behavior require a detached candidate and an explicit publication phase, not merely a budget wrapped around live buffers.

Transport geometry now derives positive record cuts from the actual TLS family, negotiated limit, producer boundary and physical capacity. An actual TLS adapter test exposed a 22-byte undercharge: a 32768-byte plaintext crosses the adapter's 16384-byte producer boundary and needs one more TLS13 record than a flat-length plan predicted. Immutable before-source terminal handle 36690 failed exactly that test (75/76). The repair preserves the adapter boundary and the same assertion passes. Tests use actual sealed/decrypted TLS12 and TLS13 records and actual large WebSocket frames. They do not constitute negotiated-handshake, kernel or daemon activation evidence.

Geometry immutable source2 `d4dc5e10`, manifest `e45703ab` (961 files), explicitly names the kernel TLS13 control bound and selects software control cost by TLS family. TLS12 KeyUpdate is refused; actual TLS12 alert lengths are checked for all three suites. Linux Debug 78392 and ReleaseSafe 77009 both exited 0 with 112/112; check 91412 exited 0, 3/3. Fresh Astra review `0f7cf8f8` approves the bounded source delta. There is no native geometry runtime claim.

The first whole-funding admission layer is in `physical_lifecycle.zig`. It precharges its own requested metadata capacity and planning workspace before backend allocation, checks complete fleet/category/row sums before publishing any hold, refuses duplicate or stale owners, and cancels the last valid transaction serial without minting another. It exposes no allocator, seal or publication method. This is the positive-new admission stage; exact OLD retire/move credits, participant loans, stable allocator homes, typed wire claims, the full registry, mandatory snapshot and daemon activation remain unimplemented.

Astra found quadratic component lookups and duplicate detection in immutable first-source `8fcfb07b`. Root replaced recipient lookups with validated slot/serial handles and duplicate scans with burned transaction stamps. The second source includes an actual 5001-component reverse-order admission test with backend allocation disabled after bootstrap, exact fleet/category/row sums, canonical order, and full OLD refund. Direct Debug passes 8/8; immutable project harness gates and the independent second-source review are tracked in the checkpoint until terminal.

The account review's configured-account BadRecord-to-OAuth continuation premise was disproved by actual OLD startup and exact `main.zig` source. `dprop_requested` is automatically true whenever that account opener is reachable, so account failure returns before OAuth/listener setup. Astra explicitly retracts that premise in correction `b0b580e4`; the original review is retained alongside it. Missing-WAL creation before snapshot refusal and exclusion of already running legacy owners remain separate issues. The worker's actual first-argument barrier matrix passes 30/30; its corrected legacy startup matrix reports 5/5, including missing-WAL mutation and provider-only true/false controls. Those moving worker results await complete frozen receipt review, and the proposed activation marker has not been implemented in production.

No deployment, push, capability activation, full-port acceptance or goal completion occurred. The next implementation must connect this admission stage to exact allocation and source-owner custody, rather than introduce an independently publishable shortcut.

Final admission source3 `716b52f8`, manifest `497af017` (962 files), removes the sparse-row sweep with a fully precharged unique touched-account list. The first iteration exposed actual double funding (expected 130, observed 260, followed by cleanup ABRT) because adding a hold erased its listed flag; its exact source and raw failure are preserved. Keeping that flag closes the defect with unchanged expectations. The final sparse retry test covers 5001 configured row slots, two components on one physical row, exactly three touched accounts, late category refusal, same-plan retry and OLD refund. This is distinct from 5001 active clients.

Immutable source3 Linux Debug 50868 and ReleaseSafe 68660 both exited 0 with 80/80 (nine direct admission tests plus 71 imports); check 24153 exited 0, 3/3. All 962 hashes matched after the gates. Fresh Astra review `dd4e880f` approves the bounded admission source and both work-bound repairs. Root read its complete 128-line review. No root build or VM handle remains active. Stable allocation homes and all subsequent dd14 phases remain the next implementation, with no public settlement shortcut.

The account owner has now frozen the full 1112-line amendment `1d804626` and OLD execution receipt `cc6c6abc` for fresh B2/dd14 review. Root has not yet read or accepted that entire latest amendment and has granted no production write scope. The TLS integrator separately froze a 956-file transport candidate `6cc7d603` after real authenticated prefix/control/terminal/pressure and parser retirement cases. Its fresh review and final mode gates remain owner work; no acceptance is borrowed from the resource admission cut.

### Stable funded allocation homes and native execution

Root extended the accepted admission coordinator with heap-stable allocation homes. Each component consumes only the byte/slot envelope funded by the complete transaction. Nine bootstrap allocations, including all record and pointer-index tables, are priced before backend allocation. A borrowed scope's allocator points at its stable home. Requested allocation capacity plus alignment padding is tracked without double-counting actual allocations into the already reserved preparation envelope. Allocation serials burn on backend OOM and never wrap. The bounded pointer index uses backward-shift deletion; its actual collision test deliberately wraps a live chain across bucket zero and checks neighbors through 100 reuse rounds.

Whole abort now refuses while ANY funded home retains candidate memory, before changing any home or refunding any account. Tests cover alignment and in-place resize, unchanged OLD bytes/identity on failed allocate-copy growth, OLD+NEW overlap, unplanned scopes, tracking exhaustion, final allocation serial, copied scope retargeting, and every one of the nine bootstrap plus three candidate allocation failures. The new source has no resident/retiring allocation transition or publication API; exact OLD/FINAL moves, persistent participant receipts, typed claims, seals and all live consumers remain mandatory next work.

Immutable homes source1 leaf `81d5245e`, 962-file manifest `80c8ab1e`, passed Linux Debug 4449 and ReleaseSafe 75632, 88/88 each (17 direct funding/home tests plus 71 imports); check 44431 passed 3/3. OpenBSD cross-builds 4377/97380 each passed 8/8. Fresh Astra review `ac2c8b41` approves the bounded preparation-only source. Two earlier test-fixture attempts recursively compared an AllocationId's coordinator pointers and aborted in the test assertion; another used the deprecated Zig reflection API. These are preserved fixture errors, not causal allocator defects. The final identity test compares every field and owner pointer without recursive graph traversal.

Actual owned OpenBSD 7.9 GENERIC.MP#449 execution then passed 88/88 in both Debug and ReleaseSafe, zero skips, normal 8192 KiB stack, both SSH commands terminal 0. Debug module SHA-256 is `cd8095905751331b51bd8fa5c92b903850c4f63508cc4ce1506a7fa6d044cca0`; ReleaseSafe is `fd03a60aa62f0f099f11cba7f8360517796abed3fcdc7ce3bbe07126c91b9367`. All 962 source payloads matched before and after EACH native run, four complete logs; host pins matched afterward. CLI and daemon test artifacts were cross-compiled only. No whole-daemon/native hot/physical integration grade follows from these module tests.

The exact two native SSH invocations and staging/cleanup argv were saved before execution. Host build recipe `91ad300b` is explicitly an after-execution transcription of the exact tool calls, with source cwd/filter/prefix/redirection and terminal handles; it is not a rerun. Native receipt `f9aadae2` retains that provenance boundary. Root removed `/tmp/onyx-whole-homes-20261001` and captured an actual absence marker before shutdown. Cleanup SSH 45502 exited 0; PID 3670749 exited, its pidfile is absent, the image is idle and port 2225 is closed. Unrelated VM listeners on 2222/2223 remain owned by the same PIDs. Fresh native receipt review is pending at this paragraph.

Root read all 1316 lines of selected account amendment `b79e12bb` and all 130 lines of fresh Astra review `45e46544`. The selected sequence prepares/seals the whole cut, installs denial, appends/syncs A intent, P, and A ACK while still SEALED, then performs ONE resource publication and all no-fail RAM commits. ACK commits the recoverable FINAL logical closure; it never claims RAM was already published. Any failure after the first A attempt retains the entire recovery owner, allocations, loans and denial. This resolves the earlier `20bb60bf` design blocker; implementation and causal recovery remain required.

Root granted the account owner only the new independent `account_authority.zig` identity/reference and strict schema/hash/signature/Merkle foundation, and added its root import/test hook. Services, Store chain, Session/private, World/RCU cohort, Server, startup, managed launch and migration consumers have not been granted to that leaf. Its source is moving and not accepted or activated by the homes source cut.

Root read all 174 lines of frozen TLS transport review `d111abe0`. Its earlier 956-file candidate remains BLOCKED despite 150/150 narrow gates: activation could dispatch buffered authenticated commands without World exclusion, and normal software close could destroy retained phase3 plaintext after retryable allocation failure. The sole integrator has reported actual causal failures and fixes, plus a strict kernel RX phase defect, on later moving source. The fresh repaired cut and mode/native review remain open; earlier green counts cannot close the new failure cases. All original full-port, far WHOIS/DM, account/egress and all-attachment continuity gates remain intact.

Fresh Astra native review `deb61df1` subsequently approves the bounded homes receipt; root read all 104 lines. Reviewer independently verified the exact 962-file source/tar/checksum inventory, all four complete native checks, both artifact hashes, sequential 88 OK rows in both modes with all 17 direct test names and zero skips, 7.9/8192, and actual host/guest cleanup. Recipe `91ad300b` retains its explicit transcription qualification. Immutable receipt `f9aadae2` remains unchanged. No root process or VM remains active; the next ownership transitions must extend this exact tested foundation and retain all full-port dependencies.

Astra native review wording addendum `682f3b69` preserves the accepted homes receipt and qualifies scale precisely: 5001 component entries share one physical row; the sparse test configures 5001 row slots and uses two components. These are not 5001-client runtime tests.

Root read the complete 160-line fresh repaired TLS review `5a6eff04`. The exact 957-file composition `603926fd` remains BLOCKED: terminal parser failure can retain undrainable control/deferred output, and draining a held control can dispatch a buffered command after closing was latched. World exclusion and kernel control phase repairs passed source review. All five frozen gates terminated at a captured unready account leaf compile error, so this composition has no new runtime pass. The integrator preserves it and is adding actual encrypted causals before repair.

### Production independent settlement API removed

The historical independent `lifecycle_output.custody` API is now `legacy_test_only`, compiled as an empty namespace in production. There is no `custody` alias. Historical same-file tests retain their exact assertions and the real output/geometry primitives remain available. Source call-site inventory found no live users. This enforces the mandatory API boundary before full coordinator publication; it does not activate new lifecycle ownership.

Immutable barrier output `0c37ef32`, manifest `04c7ad9c` has exactly the accepted homes962 source paths with only output changed. Debug39974 and ReleaseSafe94492 both terminate0 with82/82; check3/3. An actual production compiler probe can name old PreparedSettlement before the change (exit0), and the identical probe fails after (exit1, missing custody). Separate compile-time absence assertions plus positive geometry access pass Linux/OpenBSD Debug/ReleaseSafe. These are compiler probes, not native execution. Test-only import wrappers sit outside the962-file source manifest. Initial direct-module fixture attempts failed outside-module-path and are preserved. An initial manifest included copied build caches; the corrected source-only manifest was verified before acceptance. Receipt `ad44e454` records these qualifications; fresh Astra review is pending.

Fresh Astra barrier review `de2ac9d5` APPROVES the bounded production API removal; root read all70 lines. The independent historical body and tests reverse byte-exactly to the accepted baseline, with no live alias or settlement path.

### Fresh runtime coordinator identity and next ownership design

Root read all334 lines of Astra next ownership contract `2ddba118` and all32 lines of normative instance addendum `18883c0b`. The additive design preserves original allocation homes while adding private ownership states, cross-home owner lists, complete census/disposition records, simultaneous moves and exact seals. No fake census or durable completion receipt can enable publication. Runtime coordinator identity must be freshly issued on every create/restore/adopt/rebuild and remains distinct from durable logical fleet identity. Actual registry issuance/adapters/remapping remain mandatory implementation work.

Root implemented required nonzero supplied FleetInstance on all resource handles. Actual FBA destroy/reset/recreate gives the identical coordinator address and identical slots/serials/revisions; stale OLD component admission succeeds on homes81d and is refused by the new identity checks. The initial causal failed the intended assertion then crashed in missing early test cleanup (88pass/1crash). The preserved second causal adds only builder cleanup and reports88/89 exactly1failure, exit1. Repaired source checks stale row/component/builder/plan/transaction/scope, unchanged counters, and successful fresh allocation/free/abort. Zero instance refuses before backend allocation.

Immutable Fleet leaf `1cd289f2`, manifest `3e3295e0` passed Debug79044 and ReleaseSafe63695,90/90 each; check33752 3/3, OpenBSD cross57743/91447 8/8 each, allterminal0. No native runtime is attributed to this identity delta. Fresh Astra source review `c071aa25` APPROVES the bounded change; root read all87 lines. Actual registry freshness and borrowed raw allocator lifetime remain explicit conditions. This Fleet snapshot contains historical output; barrier approval is a separate cut. Combined962 source `a69399c8` includes both exact approved leaves and is now running its own gates.

The combined root962 Debug40871 subsequently terminated0 with131/131 selected physical tests, and check4277 terminated0 with3/3. ReleaseSafe73654 remains actively compiling (owned compiler confirmed consuming CPU); no terminal pass is claimed. Root archived and verified all718 evidence files. Root has no running VM.

Root read all128 lines of fresh account foundation review `b7a74e96`, BLOCK on a real Intent self-manifest cycle. The owner has authority to replace the five-root Intent field with a typed four-submanifest field; the Head keeps five activation roots. A real D4→chunks→D5 construction, signed causal rejection, isolated repaired gates and fresh review are required. The new structural schemas still mint no live account authority. TLS final2 explicitly composes stable account checkpoint with accepted SendQb1/Session3155 after preserving failed incomplete-dependency cuts; its review/runtime remain separate owner work.


### Exact OLD allocation declarations and current final gates

The combined resource snapshot `a69399c8` completed ReleaseSafe73654 with131/131, exit0. Its Debug131/131 and check3/3 also terminated0. Fresh Astra review `710e692d` approves that precise combination; root read all40 lines.

Root then added complete private OLD owner lists, exact allocation declarations, independent original homes and logical destinations, simultaneous per-account move admission, real free-slot checks, and all-owner candidate-held abort refusal. Retirement supplies no peak credit, incoming move headroom supplies no NEW allocator allowance, and all account checks precede OLD encumbrance. Test fixtures own actual allocations but cannot serve as daemon census authority. No ownership moves, retirement or publication are executed by this admission cut.

Ownership source1 `c5224560` passed98/98 both modes and check3/3. Astra approved with one LOW: zero declaration workspace charged nonexistent alignment slack. Source2 requires positive workspace before backend allocation; its new first-allocation-failure test proves InvalidPlan/zero backend calls. Exact source2 leaf `88fd017f`,962-entry manifest `2c20ade1` (including11 historical pyc files), passes99/99 Debug and ReleaseSafe, check3/3, and both OpenBSD cross builds8/8; all five processes terminated0. Fresh Astra delta review `449f166b` approves, root read all48 lines and complete historical source1 review159 lines. These are compile-only OpenBSD results; prior native homes88/88 acceptance does not grade this later delta. Original fixture count failures and all immutable cuts remain preserved.

Account codec source4 `58d35ac0` closes the signed Intent self-root cycle and separate aggregate reassembly-limit defect with preserved one-failure causals. It passes93/93 both modes and check3/3, all terminal0; fresh Astra review `434cc5ea` approves the bounded codec. Root read all111 lines plus the historical source3 blocking report100 lines. This supplies no live AccountOwner, durable multi-WAL cut or native account acceptance. The Store/Presence owner is conducting a read-only concrete durable-chain audit before a production grant.

TLS final2 `6108b996`,963-entry manifest `0c718281`, passes focused157/157 both modes, fullTLS944/945 both modes with one existing GAP-K6 interop skip, and check3/3, all terminal0. Fresh Astra review `98a6100a` approves, root read all127 lines; final receipt `6ba8a9f7` records the terminal results separately from the review cutoff. Actual native OpenBSD gating exposed three test fixture variadic fcntl trailing-zero ABI errors at compile time. The sole server writer owns exactly three c_int casts; immutable final3 `a26fa855` reverses exactly to final2 and preserves production bytes. Its Debug cross build8/8 has terminated0; native runs and ReleaseSafe remain owner work. VM PID3702510 is reserved exclusively by that owner, with normal8192KiB stack. No native pass or cleanup is claimed before its receipt.

The next boundary declares all NEW retain/discard roles before preparation, computes separate complete preparation and publication placement envelopes, and binds actual candidates exactly once. Complete participant loans, source-owned semantic views, output claims, ownership seal, mandatory A→P→AACK durability and one publication, strict registry/snapshot joins, and far WHOIS/DM still require implementation and acceptance. No deployment, push, capability activation or full-port completion occurred.


### Mandatory NEW destinations and complete placement envelopes

Root read Astra's complete221-line NEW-role accounting contract `859a5806`,29-line label clarification `115ef2eb`, and270-line participant/claim/private-seal ABI `37ce33f3`. NEW `P` is the original home's shared preparation ceiling; `F` is its shared retained ceiling across every destination. Separate complete preparation and publication placement vectors bound physical peak. At eventual publication, unused envelopes become nonspendable audit data, with actual retained capacity charged at its receiver and actual discard scratch charged until real free; no independent release API exists.

Root implemented mandatory copied retain/discard plans, stable full-instance RoleIds, canonical duplicate labels through prefunded index sorting, sort-bounded original-home/account contributions, overflow-safe shared P/F caps, and exact candidate binding/counts. Binding freezes candidate shape; free debits role/shared counts once through its original home. Plans with positive NEW work and no roles refuse before allocator exposure. Every surviving candidate must bind before the future private seal; transient unbound preparation storage may be actually freed. Existing historical tests explicitly create local roles through a test-only helper; no production fallback was introduced.

Frozen role source1 leaf `b5a2a250`,962-entry manifest `9bceaa94` differs approved ownership source2 only in the physical leaf. Eight new direct tests cover missing/duplicate/foreign roles, tight cross-category reciprocal NEW placement, real scratch overlap, shared F and u64-max role sums, bound shape/counters/free/reuse, exhausted identifiers/workspace, actual OLD outgoing versus retirement, and every new allocation failure. Debug49596 and ReleaseSafe35373 each pass107/107 (36direct+71imports); check42085 passes3/3, both OpenBSD cross builds45841/91582 pass8/8. All five handles terminated0; all962 source pins and live physical leaf match after gates. Fresh independent review is pending; no native role run yet. Iteration1 retained a collision-fixture FBA exhaustion when excessive default test workspace consumed its fixed arena; explicit8-role capacity for its four-component fixture closes that fixture issue without changing collision assertions. Iteration4 fixture-signature compilation failure and original sources/logs are preserved.

Root also read the complete Store/Presence durable-chain407-line handoff `4387213a`,100-line clarification `2730ca67`, and197-line independent Astra review `7786802e`. Approved G1 grants only Store's source-owned ordinary-compatible table/private exact FINAL patches, bounded tombstones/probes/detached rebuilds, and exact OLD backing/capacity abort. The owner must preserve actual OLD causal evidence and ordinary semantics; no fake loan, deferred joined publication, caller trust flag, parser weakening or live revocation grant exists. Full source-owner loans, claims, seals, authenticated WAL transcripts/private receipts, whole RecoveryHold and one A→P→AACK publication remain mandatory.

TLS final4 fixture overlay `937bc66c`,963-entry manifest `58199d85`, preserves production final2 byte-for-byte and corrects only three variadic casts plus the nonblocking server half that actual accept establishes. It reports actual OpenBSD module921/945 in both modes,24 explicit skips,0fail; CLI2/2 both. The prior native armed-SEND fixture stall is preserved as an interrupted143 causal. Bounded Linux TLS3 passes100/100 both modes, check3/3 and both cross builds8/8. These are owner-reported results pending root receipt/source/cleanup review; independent native evidence review remains due. No port completion or deployment is claimed.

Fresh Astra NEW-role source review `45d5d52e` APPROVES the exact bounded source1. Root read all153 lines; all962 inventory hashes remain matched. Final source receipt now records all five terminal gates, pre-execution command hash and every OpenBSD artifact SHA. No native role acceptance or source-owned semantic seal is inferred.

Root read the complete TLS final4 JSON/TXT and host cleanup receipt. Independently rehashed all963 source entries and six executed artifacts; mechanically reversing exactly three c_int casts and one fixture nonblocking line reproduces full final2 server6108. Root archived96 raw native/command/receipt artifacts; the evidence inventory now853 files. TLS cleanup is complete. The native owner now has a separate test-only assignment for exact NEW-role source1, using its already pinned OpenBSD artifacts and a newly preflighted exclusive VM reservation. No source edits are granted to that native owner. Astra native review remains its independent acceptance record.

Store G1 owner preserved a real OLD capacity failure: at six live entries in capacity8, preparePut grows the live backing to16, then record allocation fails. Published values/WAL/sequence/feed stay OLD, but capacity/backing differ. Immutable causal963, raw71/72 one-failure/no-leak execution17518 and exact source/binary receipt are retained. The repair is scoped to Store ordinary prepared table custody, preserving immediate ordinary write semantics; it is not a substitute for joined durable activation.

Fresh Astra TLS/native review `431c70a6` APPROVES the precise final4 fixture/source/evidence; root read all164 lines. It independently reconstructs both945-row logs and exact24 skip identities,12×963 guest checks, six hashes, four-change reversal, and actual owned cleanup. Native executes >=3 sends and full FIFO; the observed-partial-CQE assertion remains Linux-only and is not OpenBSD partial-CQE proof. The native gnutls row skips at its non-Linux guard before attempting interop. Kernel/native exec-upgrade/full-current-tree acceptance remains outside this bounded grade.


### Native NEW-role acceptance and participant ownership repair (2026-10-02 local)

Exact source1 NEW-role artifacts passed native OpenBSD7.9 at the normal8192KiB stack: Debug15323 and ReleaseSafe4133 each terminated0 with107/107 module tests (36 direct, including8 NEW-role cases, plus71 imports), and separate CLI2/2. Daemon selected0 remains compile-only. Root independently rehashed962 frozen source entries,12 original/copied artifact pins, all8 guest source-check logs and all4 actual native test logs. Receipt `37547888` and raw commands/logs are archived with prefix `physical-roles-native-`. Owned guest cleanup31183 terminated0, removed the test directory before shutdown, and independently proved VM3718268 off/image idle/2225 free with other VMs preserved. Fresh Astra native review is pending; this bounded result does not grade participant integration or the whole moving workspace.

Root read the244-line participant bookkeeping contract `4c1a8147`: complete fixed catalog-home coverage, copied participant plans, one-time loans, inactive funded homes until loan issue, private actual-source abort accessors, and whole reservation refund only after every issued loan is released. The physical leaf writer now owns that bounded implementation; root has no overlapping leaf edits. Production typed owner adapters, semantic claims/seal, durable publication and source lifecycle joins remain mandatory subsequent work. A stable raw std.Allocator cannot encode stale-copy generations across home reuse; source-owned quiescence/lifetime is required and is being clarified explicitly. No public trust flag or caller-built abort receipt is authorized.

Store G1 continues from its preserved capacity8→16 allocation-failure causal. Disk exhaustion was resolved by reclaiming only1234 aged main-cache compiler intermediates (.o/.bc/.ll),30.02GiB, after confirming no host compiler/test was running. Exact removed paths and bytes are retained in `compiler-object-reclamation-2026-10-02.json`; source snapshots, executed binaries, receipts, logs and VM images were preserved.

Fresh Astra native review `321da36c` APPROVES the bounded NEW-role execution evidence. Root read all114 lines. Astra independently verified98 native evidence entries, exact962 source/tar path sets, six original/preserved binaries, both107+2 result sequences, all8 guest checks and actual cleanup. It expressly excludes daemon, current participant implementation and full-port acceptance.

Root also read all65 lines of allocator lifetime clarification `4301a877`, preserving the244-line contract unchanged. Private release must observe actual source borrow/ticket quiescence, not merely zero heap counts. Stale typed scopes/loans are checked across reuse; raw copied allocators sharing one stable home cannot identify their issuance after later reactivation. Real source adapters must enforce that lifetime before production enrollment is available. The writer is implementing that precise boundary.


### Store G1 frozen source and mandatory verification selection

Frozen Store G1 `14dd9684`,963-entry manifest `c5bb9634`, differs accepted account-final4 only in Store. Root independently verified all963 pins, exact sole-file delta, live Store and all five terminal log hashes. Focused Debug40894/ReleaseSafe37670 each pass84/84; full Store Debug42016 passes185/185; check13708 passes3/3, all terminal0. Remaining broad ReleaseSafe, consumer and OpenBSD compile gates are separately owned and pending; native Store G1 is not accepted. Fresh Astra refutation is active. Historical full Store iteration5 exposed SnapshotCoverageMismatch error compatibility and compile check exposed leaked Overflow; repairs and RED logs are retained. Ordinary calls meter algorithmically bounded work with maxu64, not a funded root allowance; private finite plans enforce cumulative preparation/revalidation ceilings.

Root read all338 lines of the proposed Store participant bridge `966e0073` and independently verified its six captured design inputs `0a96ee6a`. It requires actual opaque Store custody, race-free borrow/exclusion identities, complete original-backend census and lifetime, and joint real-loan abort-only preparation. Draft observations are explicitly ungraded; no source grant or production factory follows from this design alone. Actual managed publication, signed durable cuts and complete boot/adopt catalog remain mandatory.

The verification selector formerly emitted only compile/diff checks for Store and physical lifecycle paths. Root added mandatory module Debug+ReleaseSafe; Store additionally selects Services consumers in both modes. All8 selector regressions and toolkit validation (10skills/9Codex/12Claude) pass. Claude mirrors share the same inode. This fixes future gate selection; it supplies no current whole-module pass or release grade. Fresh read-only tooling review is queued.

Fresh Astra refutation found two grounded G1 candidate defects before acceptance. Detached backing validation seals payload bytes but omits exact key/value allocation locators, allowing an equal-byte distinct allocation substitution; finite detached rebuilt-byte work is charged after allocation/initialization. Candidate14dd remains unaccepted. The Store owner has an exact freeze lift to preserve both actual RED controls, bind detached allocation identities and precharge finite rebuild work before backend allocation. Historical14dd terminal/active gates stay attached to14dd and cannot grade the forthcoming repaired cut. No broader source or joined-durability grant follows.

All three Store review findings now have actual frozen14dd causal execution: handle56490 terminated1,71/76 with exactly5 new failures and no reported leaks. Put/Batch adopted equal-byte foreign value allocations across the WAL cut; a finite rebuild limit still increased backend allocation index1→2; max table revision Put/Batch changed WAL896→25 through compaction before refusal. Root checked all963 causal source pins, the executed preserved binary `4912b81f`, raw log and explicit leak-safe custody cleanup. The repair source is being gated separately; root additionally requires KEY-twin cases and later-family Batch revision controls before acceptance, without attributing them to the original five REDs.


### Participant final1 and repaired Store final3 gates

Participant leaf `609af2e7`, manifest `1ef1c3c0` (962 entries), has five terminal successful gates: Debug and ReleaseSafe each123/123, check3/3, and both OpenBSD artifact builds8/8. Root independently verified raw logs/counts, all six artifact hashes/sizes, both preserved causal binaries and final receipt `232faffd`. Ten production API negative probes refuse the intended private/missing APIs; the inert positive compile succeeds. Fresh Astra source review `42bd79c7` approves this bounded foundation. Production source adapters, enrollment, claims, sealing and settlement remain unavailable. Root granted the owner native execution of these frozen artifacts after exclusive preflight; no participant native result is yet accepted.

Store final3 `7ca19afb`, manifest `a669b1fb` (963 entries), repairs all three initial Astra findings and adds equal-byte KEY-twin controls for both APIs plus later-family Batch revision exhaustion. Focused tests pass92/92 in both modes, full Store193/193 in both modes, check3/3, and both OpenBSD artifact builds8/8. The Services consumer ReleaseSafe run reports terminal374/374; Debug remains active with its owner. Fresh Astra source review `e49a2d44` approved the bounded repair. A newly raised internal Batch kind/count selector join question is being independently assessed before further acceptance; no arbitrary field-tamper guarantee or new source edit is inferred. Native Store execution remains serialized after participant cleanup.

Fresh Astra tooling review `43b936bb` approves the two verification selector scripts; root read all63 lines and rechecked both source hashes. Root archived participant causal/gate/probe receipts and both source reviews, then verified all1037 evidence inventory entries. This checkpoint does not grade full OpenBSD operation or the complete moving workspace.

Store final3 consumer gates are now terminal: Debug83645 and ReleaseSafe64160 each374/374. Root checked complete final receipt `b9a04e33`, all nine log hashes/counts and six artifact hashes; archived both consumer logs and final receipt. No owned compiler/test handles remain for Store. The new Batch selector question is still independently assessed before source acceptance advances.


Astra independently grounded a further MEDIUM final3 prepared-Batch validation omission: entry.kind/count are publication selectors not completely joined to the validated table edits. Changing an existing-row PUT entry to delete can schedule the still-table-owned OLD key for retirement; count0 skips entry cleanup/feed despite table publication. No supported ordinary caller corruption path or external exploit is established. The prepared-candidate exact-custody approval is reopened; all valid-input final3 gates remain historical evidence. Root granted only Store immutable before causals and exact count bounds/one-to-one all-family edit coverage/kind-value joins before WAL, with positive and negative regressions and fresh final4 gates/review. Native final3 is deferred. No general arbitrary-RAM integrity promise or substitute source ownership seal follows.


Participant final1 now has actual native evidence: Debug74389 and ReleaseSafe87295 each terminated0, module123/123 and separate CLI2/2, zero skips/fails at normal8192KiB/OpenBSD7.9. Native receipt `ff45d29f` and116-file evidence inventory `d95a2c69` are preserved. Root read the complete receipt and independently verified116 evidence hashes,962 source entries,12 original/copied artifact hashes, four actual test row counts, and all11×962 guest source checks. Neither daemon artifact ran: Debug has zero selected rows; optimized ReleaseSafe omits the table symbol, so no daemon runtime count is inferred. Guest cleanup81807 terminated0 and proves absence before shutdown. Root additionally checked current owned PID3755474/pidfile absent, image idle,2225 free, and all three unrelated VM argv/starttimes unchanged. Archived104 native command/log/receipt files; evidence inventory now1153. Fresh independent Astra native review remains due. This grades neither production adapters nor complete platform operation.


The Batch selector omission now has actual final3 controls: immutable final3 plus only two appended Store fixtures, handle55811 exit1,71/73 exactly2 failures and no reported leaks. Changing PUT kind committed and scheduled the still-table-owned OLD key for retirement; count0 committed two map rows but omitted both independent owned feed events. Root verified all963 source pins, sole appended Store delta, executed binary `413262b0`, raw log `0cf255f8` and precise cleanup: remove only the erroneous live-key retirement; free only the two lost event allocations while preserving actual published map ownership. This is a source-private field substitution control, not a supported caller exploit. Exact repair and positive restored retries remain next; native Store waits for the repaired freeze.

Fresh independent Astra participant native review `a0fa7f5e` APPROVES the bounded cut. Root read the complete report; reviewer checked every source tar member, all116 evidence hashes, exact123+2 ordered rows and names in each mode,11 complete unique-path checks, real pre-execution journal and fresh host-only cleanup. All52 physical direct tests plus71 import rows are preserved. The5001 fixture counts components/participants on one row, not live clients. Production source registration, source census, claims/seal/settlement and full daemon/port acceptance remain open.


Store final4 is frozen at `ab6fddf2`,963-entry manifest `926ace9e`; root verified every entry, sole Store delta from final3, complete production diff and repair addendum `b7cf3799`. Focused tests pass95/95 in both modes; full Store196/196 each, check3/3 and both artifact builds8/8 now have owner terminal0 confirmation. Consumer ReleaseSafe is terminal while Debug continues; root observed its actual test PID3767655 working at~72% CPU after9minutes, without restart. Fresh Astra source review `9319ba6c` APPROVES the exact bounded validation repair, preserving prior assertions and byte-identical actual before/after controls. Native full Store196 preparation is allowed without boot; root may separately grant frozen native execution after exact artifact preflight while explicitly retaining unfinished consumer acceptance. No S1 source write or whole seal follows yet.

Root read all292 lines of Astra's S1 design `a5157369`: Store-only private opaque owner, actual guarded reads/exclusion and complete original allocation census. Owner-box and metadata allocations count; borrowed directory/Io/backend fixture lifetimes are explicit and real boot-owner pins remain mandatory. No public raw Store consumer, manually issued cell, managed loan or allocator injection is permitted. S2 must jointly implement actual root authority and loan preparation; complete S3 boot/adopt ownership and durable claims/seals remain mandatory.

The265-line native service packaging contract `def7413e` is source-grounded in17 unchanged pins, all independently rehashed by root. Current OpenBSD package staging installs systemd and lacks an authenticated committed service-owner control/readiness/stop path. Native successor argv persists; broad matching selects an uncommitted candidate alongside its predecessor. Proposed closure is an actual local service-control owner transferred through native commit before native rc.d support, with explicit source/sandbox/descriptor joins and real service journeys. Astra is reviewing the minimum coherent implementation boundary; no script, source implementation, VM service acceptance or deployment is inferred from this proposal.


All Store final4 gates are now terminal0: focused95/95, fullStore196/196 and consumers374/374 in both Linux modes, check3/3, OpenBSDcross8/8. Actual OpenBSD7.9 Debug96732/ReleaseSafe54561 each pass196/196 module (125Store direct+71imports) and separate CLI2/2, zero skips/fails, normal8192KiB. Root read complete Linux and structured native receipts, then independently verified all123 native inventory hashes,963 source entries,12 original/copied binaries, exact ordered row names/outcomes, all125 source-declared Store tests and11 complete unique963-path checks. Neither daemon binary ran. Cleanup75331 exit0 proves guest absence before shutdown; root current observation confirms3778116/pidfile absent,imageidle,2225free and three unrelated VMs' exact argv/starttimes unchanged. Receipts `7a92221b` and `bb55aa40` plus native command/log evidence are archived; all1286 evidence entries were rechecked. Fresh Astra native review remains due before the next Store owner write grant.

Astra service review `cb68d210`,all393 lines read by root with21 live source hashes verified, selects root-bound protected Unix seqpacket endpoint and distinct inherited lifetime flock lease. OpenBSD peer credentials describe the binder, so root-bound listener inheritance is not accept-time daemon-UID proof. Protected namespace and actual FD lineage authenticate this local service without a new bearer-key/PKI layer. Explicit helper-backed rc action dispatch avoids stock stop's busy-check success and TERM/KILL fallback. Reconnectable serial/nonce operation results preserve accepted reload custody; real reactor readiness and final cleanup outcomes remain required.

Root granted only N1's new `native_service.zig` and `helix/native_service_snapshot.zig` to the native integrator, with root reserving two harness exports. Strict codecs, actual owned FD/rootnamespace/lease/bootstrap inspection and operation state are allowed; production current-ready publication remains unavailable until actual N2 main/server adapters. No main/server/bootstrap/manifest/capsule/pledge/helper/build/rc/source activation grant follows. N2 must perform all strict native descriptor/lifecycle joins, then N3 target packaging and actual installed native service journeys. This source foundation cannot be left as the final service implementation or graded as full-port support.

Fresh Astra Store final4 native review `a6f815cf` APPROVES the exact bounded evidence. Root read all150 lines and rehashed/archived observation `86633682`. The reviewer independently checked source/artifact inventories, all196+2 rows in both modes, the11 complete source checks and current host cleanup. Root has now granted Store-only S1 to the Store owner: actual heap-stable opaque owner, controlled read/iterator/feed leases, synchronized exclusion and complete original allocation census. Managed preparation, control cells, root loans and allocator injection await joint S2; production enrollment awaits complete S3 boot/adopt ownership. Native service N1 proceeds under its separate two-file grant. Astra is analyzing the closed joint S2 construction path; no production activation or full-port acceptance follows from these grants.
### 2026-10-02: source custody and real coordinator boundary

Store S1 is frozen at `17f0e225`, with the same 963-entry dependency inventory and only Store changed from accepted final4. Fresh independent Astra review `0a5ab230` approves the bounded opaque owner, actual read/exclusion and complete original allocation census. Root read all 157 review lines and independently verified all eleven raw gate logs and six OpenBSD artifacts. Debug and ReleaseSafe each pass focused81/81, full Store206/206, consumers374/374 and Services590/590; check passes3/3 and cross builds8/8 each. The thirteen production escape probes fail for their intended private, absent or const APIs. These results do not activate production ownership or funded preparation.

Root granted serialized native execution of the frozen full206 and CLI2 artifacts in both modes at the normal8192KiB stack. The owner checked the image idle, port2225 free and unrelated VM identities immediately before boot. Native results remain pending; daemon artifacts are compile-only.

That native run is now terminal: Debug17155 and ReleaseSafe97508 each pass206/206 plus CLI2/2, zero skips, including all ten S1 controls and both real thread tests. Receipt `d562ce99` is archived. Root independently checked all121 evidence hashes,963 frozen source entries and exact963 tar members,12 original/copied binary hashes, four ordered successful raw row sets and eleven complete unique963-path guest checks. Guest absence preceded shutdown66434 exit0; root refreshed PID absence, image idle, port2225 free and all three unrelated VM argv/starttimes. A fresh reviewer who did not write Store remains required before native evidence acceptance. Neither daemon artifact executed; this does not establish full-port operation.

Fresh independent Store S1 native review `cd8161bd` now APPROVES that bounded native evidence. Root read all95 lines and archived the report, verifier and current host observation. The reviewer independently inspected every source/tar/evidence/artifact/checksum row, actual ten S1 controls, copy ordering and cleanup, without source edits, rebuild or VM access. Source and native S1 acceptance are separate from still-unimplemented S2/S3 ownership and complete OpenBSD operation.

The real coordinator conversion is frozen at `5dc6ed30`,962-entry manifest `9e3c851c`. Root independently reversed only the representation changes and found every historical nonblank production and test assertion line exactly equal to the accepted609 baseline. New representation checks cover opaque owner references and the charged single original backing allocation. Final gate/probe results and the independent source verdict remain pending.

The completed conversion gates pass124/124 in Debug and ReleaseSafe, check3/3 and OpenBSD cross8/8 each. Root checked all five logs and six binary hashes, all64 probe input/log pins and all48 intended negative diagnostic causes, and read all distinct probe inputs. Root's fresh independent source verdict `aa723a60` APPROVES only this representation closure. Actual source constructor/enrollment is still absent. Serialized native124+CLI2 execution is now assigned; no result is inferred. Astra is separately updating the S2 implementation plan against the actual opaque source rather than the earlier cache projection.

Opaque coordinator native execution is now independently accepted for this bounded cut. Debug20828 and ReleaseSafe27968 pass124/124 plus CLI2/2, no skips at8192KiB. Root's fresh native review `eae47cca` verifies all121 evidence hashes,962 exact source/tar entries,12 original/copied binaries, eleven unique962-path guest checks and four ordered raw successful row sets. Removing only the new representation test preserves the previous123 native names/order exactly in both modes. Copy acknowledgments precede execution; guest absence precedes shutdown37010 exit0. Root refreshed owned PID absence, image idle, port2225 free and unchanged unrelated VM argv/starttimes. Daemon artifacts remain compile-only; actual S2 source enrollment and whole-port operation remain open.

Fresh independent N1 service source review `bec42c89` BLOCKS the frozen service `f73c4eda` on two medium defects: connect runs before nonblocking mode is enabled, and inherited listener validation omits nonblocking status while accept4 flags apply only to the accepted descriptor. Historical host gates pass91/102 with eleven explicit root-only skips; this is not102/102. Root read all152 review lines and granted only the exact source fixes with preserved before controls, fail-closed shared-listener validation, bounded connection admission and real native regressions. Namespace/rights/custody and opaque lifecycle requirements remain mandatory; no service native or N2/N3 activation grant exists.

Astra's compiled S2 controls establish two actual language defects in the original proposal: ordinary callers can construct or mutate the public Coordinator struct, and an empty generic opaque owner can deduplicate across different namespaces. The corrected cache-only type projection captures the namespace and rejects the intended eleven API escapes, but does not implement enrollment. Root verified all963 proof input hashes,960 unchanged dependency hashes,17 compiler logs and17 object hashes; no object executed. The proof addendum `c7e23bb1` preserves both successful old bypasses and the failed unbranded attempt.

Astra now owns only the real `physical_lifecycle.zig` opaque Coordinator/private backing conversion. It must preserve all existing accounting, allocation failure, copied-handle, abort, role and quiescence assertions, charge the actual single backing allocation and expose no mutable backing pointer. Fresh independent review remains required. Store remains frozen; actual S2 construction, complete R/T enrollment, heterogeneous backend lifetime, finite funded work, candidate allocation custody and source-owned abort remain unimplemented. S3 boot/adopt custody and complete OpenBSD operation remain open.

The subsequent S2 implementation agreement is now complete: root read the 332-line real-source plan `879e664d`, 156-line private-witness amendment `35ab7f93`, 137-line Store readiness memo `60202ed1` and all 247 lines of joint ABI2 `1756b2f2`. Both writers confirmed the exact ABI against accepted Store `17f0e225` and Physical `5dc6ed30`. Root granted the complete two-file S2 implementation: Astra owns only `physical_lifecycle.zig`; the Store owner owns only `store.zig`. Original allocation origins remain immutable, six distinct candidate homes cover seven actual uses, and work is finite and shared across families. Construction refusal must destroy actual pending ownership; registered teardown validates before each actual free and releases embedded locks before their containing boxes. One private physical phase controls registration. No public constructor driver, arbitrary census, callback authority or production caller activation is granted. A composed source freeze, actual failure controls, Debug/ReleaseSafe gates and independent review remain required; S3 boot/adopt lifetime ownership remains open.

N1 transport controls reproduce all three defects on Linux: 71/74, exactly three failures, zero skips. The repaired production source uses nonblocking mode before connect and refuses inherited blocking listeners without changing their shared flags. Actual root execution of repaired cut `6295dda9` reaches 104/105 in both modes with zero skips; the three new transport controls pass. The remaining failure exposed an older fixture whose root umask made its namespace unsearchable by the nonroot child, hiding both socket-mode and peer-credential checks. Root granted only explicit mode0755 on that test's owned namespace FD, with an actual mode assertion and both original rejection assertions preserved. Final3 `972e674b`, manifest `4c336b25`, contains only that four-line test delta; root verified all 1559 frozen source pins. Final gates and native execution remain pending. This does not establish installed service operation or complete OpenBSD support.

Final3 host gates are now terminal: actual sudo-root execution passes105/105 in both modes, zero skips. Root verified all105 ordered successful raw rows and the executed binary hashes. Normal nonroot focused runs report91/105 with14 explicit root-only skips; check passes3/3 and Linux/OpenBSD artifact builds pass8/8 in each mode. Fresh independent root source review `2cdd9668` approves the bounded repair. Root additionally verified every source and exact tar member for both refined before-control and final3 freezes,1559 entries each, and all six final3 OpenBSD binary hashes. Native execution remains separately pending; daemon artifacts are compile-only. The original source BLOCK and all actual failing controls remain preserved.


### Entire-record review and actual native listener failure (2026-10-02)

The user requested review of the entire record and no temporary fixes. Root
checked all92 named acceptance outcomes and25 explicit cuts in the requirements
inventory; its source hash still matches the roadmap. Independent chronology
and complete service integration reviews are underway. This is not92 completion
claims. Root rehashed all1810 previously indexed evidence files with no mismatch.

N1 final4 actually failed14/105 native module tests in each mode (91 passed,
zero skipped); CLI2/2 passed. All14 failures occurred in the same listener ABI
precondition. The old-transport causal2 failures shared this setup defect and
therefore did not demonstrate either transport defect on OpenBSD. Actual kernel
probes observed SO_ACCEPTCONN0 before listen and2 afterward, and a106-byte named
sockaddr_un with sun_len106 despite a59-byte bind input. Default NOFILE128 hit
MFILE after124 queued clients. The same diagnostic at an explicitly scoped soft
limit512 reached241 queued clients, bounded CONNREFUSED, exact241 drain and
empty AGAIN, with normal8192KiB stack. All10 diagnostic file hashes were checked
and archived with the failed runs; evidence inventory is now1822 entries.

Frozen final5 service fdaa3d52 corrects the production ABI checks while retaining
exact full pathname/padding, family/type/NONBLOCK and identity checks. Its fixture
saves, verifies and restores the original soft/hard descriptor limits, requires
hard>=512, and uses bounded256 clients/512 descriptor observations. It changes no
production descriptor policy, kernel backlog or stack. A real bound nonlistener
refusal, listening acceptance and wrong-path refusal is added. Root independently
read the full delta, verified all1559 frozen source pins and all1559 members of
both final5 and causal3 archives, nine successful raw host gates, all12 binaries,
and106 ordered passing rows with zero skips/failures in both root Linux modes.
Source review3f8b156f approves bounded native execution. Exact final5/causal3 native
runs are authorized on the uniquely reserved test VM; results remain pending.
Causal3 preserves OLD transport production with only the required ABI/fixture
preconditions repaired. A native bounded CONNREFUSED baseline is permitted for
the connect case; actual blocking-listener RED remains required.

Joint S2 final1 is separately frozen: Store518bf482, Physical0a7d0a3c,962-entry
manifest26f713ed. Owner evidence reports Physical180 focused passes, including
2050 replayed values/4105 original roots; Store208 passes in each host mode,
check3 and both native artifact builds.56 intended negative and4 operational
positive production compile probes are reported. Consumer and remaining Physical
gates, fresh independent source review and actual native verification remain
required. No S3 production owner lifetime/construction-peak/boot-adopt driver,
claims/seals, joined durable publication or full combined-tree acceptance follows
from these bounded results. N2 daemon/helper/capsule readiness/stop wiring and N3
OpenBSD packaging/installed service journeys remain mandatory. No deployment or
push has occurred.


S2 final1 Physical ReleaseSafe is now terminal RED:179/180 pass, one crash,
exit1. The all21-retirement-slots test changed a retiring ownership declaration
from keep_retiring to keep after plan completion; beginTransaction unexpectedly
admitted it, and failure cleanup then encountered Busy. Debug180 and Store208
in each mode do not override this result. The frozen cut and raw failing log
remain preserved; Astra is investigating whether the mode-dependent cause is
in production validation or fixture construction before any repair. S2 source
and native acceptance remain BLOCKED.


Entire-record independent chronology review01285e9c read every original1341
audit line plus subsequent additions, the249-line port record and154-line
earlier continuation. Root read the full123-line report and verified all16
observed source/document pins before adding annotations. The [full review](full-record-review-2026-10-02.md) reconciles current evidence and required work.
The five corrected legacy startup controls summarized earlier used64MiB stack
(legacy_startup.py:24, amendment:1247); they are startup-order evidence, not
normal8192KiB acceptance. The future-tense opaque conversion paragraph following
its accepted native receipt is a displaced historical planning note; subsequent
opaque acceptance and S2 agreement determine current status.
The older continuation's local-only MARKREAD frontier is historical: later
shared-session relay/Helix tests exist, while independent directory and current
composition acceptance remain open.5001components and4105allocation roots do
not close the completeactive frontier's4096limit or physical-client capacity.
