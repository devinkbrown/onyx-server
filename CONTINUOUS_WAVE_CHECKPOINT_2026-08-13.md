# Onyx Server continuous-wave checkpoint — 2026-08-13

## Repository state

- Branch: `main` at baseline `bbeb30e`.
- This wave is intentionally uncommitted and undeployed.
- Preserve all current modifications and untracked protocol modules. Do not reset the tree.
- `.zig-global-cache/` is generated local cache state, not source acceptance evidence.

## Accepted work

### Executable Onyx client contract v2

- Canonical contract: `docs/reference/protocol/onyx-client-contract.v2.json`.
- Checker: `tools/check-client-contract.py`.
- Checker tests: `tools/test_check_client_contract.py`.
- Current evidence: 23/23 checker tests pass; canonical and mirrored-contract validation pass.

### Group encryption delivery and policy

- `src/proto/e2ee_device_directory.zig`
- `src/proto/e2ee_group_delivery.zig`
- `src/proto/e2ee_policy.zig`
- Runtime integration in `src/daemon/server.zig`

### Node-local observational key transparency

- `src/daemon/key_transparency.zig`
- `src/daemon/key_transparency_store.zig`
- `src/daemon/services.zig`
- Runtime/query integration in `src/daemon/server.zig`
- Atomic prepared property mutation in `src/proto/ircx_prop_store.zig`

Sol final architecture acceptance: PASS on current bytes.

Load-bearing invariants:

1. Remote `ENTITY_PROP` stages every SET and LWW-clock allocation before mesh-HLC admission.
2. Prepared SET commit is allocation-free and owns its payload and normalized lookup bytes.
3. Rejected allocation-failure paths preserve props, entity count, full entity clock, mesh HLC, and key-transparency length/root.
4. Stale key-transparency prepare markers clear only when they exactly match the immediately preceding committed event, checkpoint, and reconstructed root; mismatch and too-old markers fail closed.
5. Public KEYTRANS semantics remain explicitly observational and node-local, not authoritative current account state.

## Verified gates

- Debug KEYTRANS: 181 passed, 0 failed.
- ReleaseSafe KEYTRANS: 181 passed, 0 failed.
- ReleaseSafe PROP: 113 passed, 0 failed.
- `zig build check`: pass.
- `git diff --check`: pass.
- Contract checker: 23 tests pass; canonical validation passes.

No live dual-node test, crash-injection test, deployment, commit, or push was performed.

### OroStore prepared durability prerequisite

`src/daemon/store.zig` now provides an opaque, store-owned prepared-put lane
whose successful publication performs no allocation. The prerequisite passed
independent Terra review after the following recovery boundaries were proven:

- snapshot coverage validates either the intact old WAL prefix or the planned
  rotated epoch prefix and fails closed on short, missing, wrong, or
  digest-mismatched coverage;
- the durable-snapshot/empty-WAL crash window reconstructs only the
  precommitted rotated epoch;
- genuinely headerless pre-epoch WALs use a deterministic authenticated legacy
  identity, including equal-width mutation records and torn-tail recovery;
- checksum-valid zero-length records return `BadRecord` before meta dispatch;
- ordinary, prepared, and replay sequence exhaustion remain checked and
  publication retirement remains allocation-free.

Current focused evidence: STORE Debug 98/98 and ReleaseSafe 98/98; `zig build
check -Doptimize=Debug`, `zig fmt --check src/daemon/store.zig`, and `git diff
--check` pass. This store packet is accepted as the DPROP1 durability
prerequisite. It is not deployed or live-wired.

## Active massive server wave

Sol-corrected P1 (superseding the older broader credential packet): implement the standalone, I/O-free
`src/daemon/durable_credential_props.zig` codec and transactional state for the
single later integration value `dprop1:snapshot`.

1. Persist only locally signed `e2ee.device.*`; reject `identity.key.*`, residence, remote-origin facts, and general IRCX props.
2. Store canonical signed LWW facts and tombstones with HLC, origin node, origin public key, and signature.
3. Validate/sign/prepare first, then perform the durable one-record write, then no-fail publish, then observational KEYTRANS append and mesh notification.
4. Restore strictly before serving; corrupt or non-canonical state is startup-fatal.
5. Keep Helix merge as the last fallible action and preserve allocation-failure atomicity.
6. Add cold-restart, corrupt-snapshot, stale/tombstone, replay/equivocation, allocator sweep, and Debug/ReleaseSafe tests.

The exact P1 envelope is deterministic DPROP1 framing around canonical signed
`ENTITY_PROP` events, strictly sorted by account and full property key, capped
at 8,192 facts, 64 facts per account (including tombstones), and 8 MiB. Its
checksum is BLAKE3-256 over
`"onyx-server-dprop1-snapshot-v1" || 0x00 || envelope_without_checksum`.
`State` and decode require a nonzero immutable `local_origin_node` and reject
any other event origin. Prepared updates must build
the complete replacement state and snapshot before a no-fail swap. No store,
server, services, Helix, KEYTRANS, mesh, or runtime activation edits belong in
P1. Remote node-signed facts are excluded entirely; any future quarantine is a
separate non-exportable subsystem. Canonical remote account authority remains
a security HOLD.

### P1 acceptance

The standalone leaf is now package-reachable through a compile/test-only export
in `src/daemon/root.zig`; this does not wire it into server startup, stores,
services, KEYTRANS, or mesh behavior. Sol and Terra independently PASS the
superseding device-only/local-origin contract.

Exact evidence:

- Debug verbose: 85/85, including all 16 named DPROP1 tests, zero leaks and log
  errors.
- ReleaseSafe filtered: 87/87.
- Debug and ReleaseSafe `zig build check`: pass.
- `zig fmt --check src/daemon/root.zig src/daemon/durable_credential_props.zig`:
  pass.
- `git diff --check`: pass.
- Full server Debug after the accepted store work: 8,036 passed, 4 skipped out
  of 8,040.

P1 is accepted but unwired. P2 must freeze startup recovery and the sole local
writer transaction before touching runtime paths. Remote facts, identity facts,
deployment, commit, and push remain outside the accepted boundary.

### P2 substrate acceptance

Sol froze P2 as one atomic five-packet activation. Packets 1-3 are now accepted;
server and startup activation remain on HOLD until Packets 4-5 pass together.

1. `src/daemon/durable_credential_props.zig` exports the exact store key,
   checked maximum OroStore payload/WAL-record sizes, and bounded canonical
   `factAt` iteration. Debug and ReleaseSafe DPROP1 gates pass 86/86. Sol PASS.
2. `src/daemon/services.zig` owns the exclusive prepared transaction:
   canonical account/owner admission, DPROP prepare, OroStore prepared put,
   durable cut, allocation-free DPROP publication, then observational
   KEYTRANS. Failed/short/sync ambiguity, poison/reopen, undersized-record, and
   KEYTRANS-failure cases are covered. Debug and ReleaseSafe focused gates pass
   77/77. Sol PASS at SHA-256
   `287519a748cbcb876bfba7fa8b685eb8680242b981767a81bf288bdcbe8d47dd`.
3. `src/proto/ircx_prop_store.zig` supports 128 user properties while preserving
   channel/member 64 defaults, allocation-complete copy/stale-safe delete and
   user-prefix purge tickets, and serialized prepared SET/channel-clone
   ownership. Destructive lifetime misuse is loud in every build; generation
   exhaustion fails closed rather than wrapping. Debug and ReleaseSafe module
   gates pass 45/45. Fable PASS at SHA-256
   `68ca464fc3065d718dd4894d254c396b3d7add80668255c422dfaa12b284207d`.

Packet 4 implementation in `src/daemon/server.zig` now provides canonical
SASL-only local device-fact authoring, strict node signing,
allocation-complete live PROP/clock staging before the Services durable cut,
no-fail publication afterward, and first-line quarantine of every remote user
`e2ee.device.*` fact before signature, HLC, PROP, clock, KEYTRANS,
notification, or rebroadcast effects. Generic user PROP and E2EEKEY enumerate
the full 128-row capacity; channel/member capacity remains 64. The numeric,
operator-override, exact tombstone, full 128-row, ambiguity/restart, and injected
prepublication failure matrices are present. The capacity test fills exactly
127 ordinary rows plus one reserved device row; it proves all 128 PROP rows,
E2EEKEY STATUS/LIST completeness, and atomic CLEAR refusal while preserving
both ends of the directory and the reserved row. Root Debug and ReleaseSafe
DPROP1 gates pass 99/99 with zero failures, leaks, or log errors;
Debug/ReleaseSafe server lanes pass 415 with four intentional skips;
formatting and diff checks pass. Sol final verdict: PASS at SHA-256
`7aaf31e5e6f538be486901ffd451dcff1d6ec0936bd3e60b78c337420ddd8ecb`.

Packet 5 startup work is underway:

1. `src/daemon/durable_credential_props_boot.zig` restores the exact DPROP row
   from an already-open OroStore using the store's authoritative admission
   limits, treats a missing row as empty, and fails closed on corrupt,
   foreign-origin, invalid-signature, oversized, or allocation-failure input.
   Debug/ReleaseSafe filtered gates pass 73/73; SHA-256
   `6c96f516545df401c9c46db40a2fb3dfb5347f63e88e0cf8392f820e0d138e0b`.
2. `src/proto/ircx_prop_store.zig` now has the parameterless boot-only
   `prepareGlobalDevicePropPurge()`. Its exact `e2ee.device.` prefix is frozen
   internally so callers cannot widen a global deletion. It purges folded and
   malformed device-namespace rows from every user while preserving
   channel/member, near-prefix, broader/narrower, and unrelated rows. OOM,
   copied/stale ticket, terminal generation, zero-match, counters, and every
   prepared-lane serialization path are covered. Independent Sonnet review:
   PASS. Debug/ReleaseSafe global gates pass 73/73 and prepared-lane gates pass
   129/129; SHA-256
   `bbd2c1ba57b749afb15a017050507d779f8e84135df55dc8810c16e258b052db`.
3. `src/daemon/helix/prop_checkpoint.zig` now builds a fully-owned
   DPROP-authoritative candidate from the inherited/cold PROP and clock image.
   It globally purges folded and malformed user device rows/clocks, preserves
   channel/member/near-prefix/unrelated state, overlays present DPROP facts as
   `.user` PROP plus exact clock and tombstones as clock-only, validates the
   configured state origin even when the state is empty, and recomputes the
   maximum HLC from the final image. Ownership-transfer and prepared-ticket
   cleanup survived exhaustive allocation-failure testing after that sweep
   caught and corrected a moved-store cleanup panic. Independent Sonnet final
   review: PASS. Debug and ReleaseSafe candidate gates pass 73/73. The final
   error-boundary correction maps both PROP capacity limits to
   `CapacityExceeded`; current SHA-256
   `2327c7662c00d3c982065794cd39fdbbed57c5a66f729836dc3be04ed2c0c335`.
   The allocation-free `State.localOriginNode()` authority seam is in
   `src/daemon/durable_credential_props.zig`, SHA-256
   `500b56e875d9829857c53a4189c22cc9a432bb6df9d24b4a566bfd41a9ddf611`.
4. Atomic server/main startup wiring has completed implementation and writer
   verification. Production distinguishes inactive and strict authoritative
   boot; requesting DPROP makes missing/invalid identity, store, load, or
   authority fatal before serving. Cold and hot restore build a purge-first
   candidate before checked HLC observation. The final no-fail edge takes the
   MeshClock lock before swapping the PROP triplet, then publishes the staged
   clock/epoch and unlocks. Hot reconciliation reports
   `DurableDeviceActivationFailed` with the underlying error identity rather
   than misclassifying it as handoff corruption. The matrix covers carried
   PRPC conflict with DPROP authority winning, future-poisoned device-clock
   purge before HLC, unrelated future-clock rejection, late rollback with an
   exact causal-triplet/MeshClock comparison, missing PRPC, OOM, and an
   allocation failure armed at the final publication edge.

   Writer gates: DPROP1 Debug and ReleaseSafe 107/107; Debug and ReleaseSafe
   build checks; formatting; diff check; zero leaks/log errors. Exact current
   SHA-256 values: `src/main.zig`
   `0ab35ad0c20328c3b1fdadc9c89174e5ab3e01de661cf0b4ebf601e18d8ee61f`;
   `src/daemon/server.zig`
   `a5f3c3fe6b648f94b54ddae6170ae0e1dfb467d73210702f163af5f7ba1f4295`.
   Sol final acceptance verdict: PASS on the pinned bytes. Packet 5-D and the
   five-packet startup activation are accepted as source/runtime evidence.
   This is not deployment or live multi-node proof.

### Next server authority wave

Packet 5-E is now the active architecture frontier: remote identity injection
and operator-grant safety. Freeze canonical authority, replay/equivocation,
future-clock, rollback, and non-exportable quarantine boundaries before any
runtime edits. Preserve the accepted local-only DPROP durability contract and
do not broaden it into a remote-fact persistence channel.

Terra's read-only threat review found two P0 boundaries for Sol arbitration:

- OPER grant verification authenticates the immediate peer signature but does
  not yet bind a distinct operator-mint authority, the signed issuer identity,
  bounded issue time/TTL, or cross-issuer incarnation semantics. An admitted
  Byzantine peer can therefore attempt arbitrary privilege mint/revocation and
  long-lived cross-issuer pinning.
- Sensitive remote identity properties retain a documented cold-node
  first-observation gap, including legacy unsigned ingress. A secure design
  needs an independent account-to-home authority; node self-signature alone
  cannot prove account authority under the Byzantine-admitted-node model.

No runtime edit is authorized from that review alone. Sol must freeze whether
account-home authority is root-certified or deterministically assigned, the
full-key identity policy, OPER mint policy, bounded RAM-only quarantine, and
upgrade/cold-restart high-water rules before writers begin.

Sol has now frozen Packet 5-E around a Byzantine-admitted-node threat model:

- Remote self-signed or first-observed `identity.key.*` and
  `identity.residence.*` can never establish account authority. Sensitive
  remote identity namespaces are first-line rejected, never burst/exported,
  and legacy identity residence is non-authoritative; exact-token
  `SESSION_REPLICA_V2` remains the only remote online residence proof.
- One explicit realm-wide Ed25519 operator authority replaces transitive OCG1
  trust. Only a locally configured authority oper may mint OCG2; runtime opers
  cannot delegate and received records are forwarded byte-for-byte, never
  re-signed.
- OCG2 exports only bounded moderation privileges, uses canonical signed
  records with a five-minute future bound and 24-hour grant TTL, and persists
  per-account revision/digest/tombstone/equivocation floors in a dedicated
  OroStore subsystem. OCG1 may be counted but never authorizes.
- Session oper provenance is recomputed across login, expiry, revoke, restart,
  and Helix adoption. Ambiguous durability is fatal to privilege serving.

Landing order is frozen: (1) identity quarantine/export suppression/hot purge;
(2) inactive OCG2 codec/policy; (3) durable authority; (4) configured root;
(5) session provenance; (6) transactional grant/revoke/expiry; (7) secured
mesh ingress/anti-entropy; (8) Helix seal/recompute; (9) full fault/restart/
mesh/DPROP matrices. The first identity-boundary implementation slice is now
active. No OCG2 runtime may activate before steps 1 through 6 are complete.

Step 1 implementation is complete and awaiting Sol final acceptance. Remote
folded user `identity.key.*` and `identity.residence.*` facts now enter one
first-line quarantine path shared by plaintext and secured drains before
signature, HLC, PROP/clock, KT, residence authority, observer, notification,
or rebroadcast effects. Both burst branches suppress these namespaces. Legacy
replicated residence trust was removed while exact negotiated
`SESSION_REPLICA_V2` token proof and downgrade protection remain. Hot candidate
construction globally purges folded sensitive rows and clocks before max-HLC;
only canonical, exact configured-local-origin signed tuples may survive.
Near-prefix and member/channel behavior, local DPROP durability, and remote
device quarantine remain intact.

Writer gates are green for E5E1 Debug/ReleaseSafe, ENTITY_PROP, residence,
full server, full module, formatting, and diff checks. Exact current SHA-256:

- `src/daemon/server.zig`: `bc1e3a2cf64381e64353a8b2d0b31be511740083dc7710764562653ba77ebc63`
- `src/proto/account_identity.zig`: `721d94039c6ff4112f0961fd5d183cd862b609104246800dda4fd2274754b5b5`
- `src/proto/ircx_prop_store.zig`: `09c3b3151aafc4e7d6ff150b0967ab293651f0a11dcb12c0f3531caebe043b8b`
- `src/daemon/helix/prop_checkpoint.zig`: `a6cbca7d994081d430a62d1812a0d8116dc3c876978ea05f8fa8b8c01423b1c9`

Do not begin OCG2 runtime activation. Sol final Step 1 review is active.

Sol's first Step 1 review found two remaining export/authority gaps: local
identity commands could still reach live peer announcement, and hot
preservation bound only a 64-bit node ID. Both are corrected. USER reserved
identity keys now return before plaintext or secured link iteration, with a
real-link ADD/RESIDENCE/DEL regression proving zero peer output while local
clocks remain. The exact configured 32-byte public key is now threaded through
the boot authority/candidate contract; preservation requires exact public-key
equality plus short ID, canonical tuple, and valid signature. Missing-key and
purge-only modes conservatively purge.

Corrected evidence: E5E1 Debug 76/76; ReleaseSafe; ENTITY_PROP; residence;
full server and module gates; formatting and diff checks. Superseding hashes:

- `src/daemon/server.zig`: `d370656dd2a3af8db1988d034465292fa8599eb418ab07de09b99c3439ce5890`
- `src/daemon/helix/prop_checkpoint.zig`: `d171ad0ec0342ccf47c740931552db108b27a1034bcabb55af7fd9fb076554bc`

The other two file hashes remain unchanged. Sol final rereview is active.

Sol final E5E1 verdict: PASS on the pinned corrected hashes. Step 1 is accepted
as source/runtime security evidence. Step 2, an inactive OCG2 canonical
codec/policy with no runtime consumer, is now the active server packet.

Step 2 is now accepted after one Sol-blocked correction aligned canonical OCG2
accounts with durable Services exactly: 1–32 lowercase `[a-z0-9_.-]`. Both
authoring and receiver verification reject maliciously authority-signed empty,
uppercase, forbidden-punctuation, space, and 33-byte identities; exact 32 is
accepted. All other domain, framing, full-key/node binding, text, revision,
export-mask, time, tombstone, signature, trailing-byte, OCG1-metrics-only, and
replay/equivocation contracts pass. The codec remains inactive and isolated to:

- `src/proto/oper_cred_share.zig`: `e821f0721b00eaa51bd8df6cc530922932446e98cf5ed28b713d9bd0e82d1711`
- `src/daemon/oper.zig`: `216e790107c1d042ada1804c986c511f0574e4a7f94ab9dc6db35d0f9b805d9c`

Evidence: OCG2 Debug 74/74, ReleaseSafe, both focused modules, full module,
formatting, and diff checks. Step 3 durable authority state/strict boot is now
active; no runtime grant path is authorized.

Step 3 implementation is complete and under Sol review. The inactive durable
authority subsystem retains exact signed OCG2 wire bytes, canonical sorted
snapshots, full authority key/ID, revisions, digests, grant/tombstone kind, and
equivocation state. Merge is permutation-independent; tombstones and revision
floors are indefinite; expired grants remain retained but ineffective. All
allocation/state/snapshot/store preparation precedes the durable cut, publish
is allocation-free, ambiguous/fatal outcomes make privilege state sticky
unavailable, and revision allocation is returned only after commit. Strict
boot requires a consistent initialization marker/snapshot and exact authority.
No runtime consumer exists.

Focused Debug 79/79 with zero leaks, ReleaseSafe, module, formatting, and diff
checks pass. Full module completed 8,082 passed, 4 skipped, 3 failed in earlier
KEYTRANS/Helix allocation-atomic lanes outside the Step 3 allowlist. Sol
independently reproduced those failures: two KEYTRANS tests still used remote
reserved identity properties that E5E1 now correctly quarantines, and one
Helix sweep exposes an actual OOM-versus-capacity error-taxonomy defect in the
PROP preparation path. Focused OCG2AUTH reran 79/79.

Sol Step 3 verdict: PASS with the explicit broad-unrelated evidence boundary.
Step 3 is accepted, but the full module suite is not globally green. A bounded
cleanup packet is active to update the stale KEYTRANS atomicity inputs without
weakening quarantine and to preserve allocator OOM distinctly from true PROP
capacity. Exact Step 3 SHA-256:

- durable state: `8ea0c61b065dadaf391f9745fe100781253d7af08669ee694030906fbc41dd0a`
- boot: `f5a94b47375f9ae711a5ba92684b1e4e3bd8e59eaf5427066b4e6d095f0d2ff1`
- Services: `e147a4b8cc7954c93c1ce267eb1e9496f6fe63dcaba8d622b00668607b56a658`
- daemon root: `dc16f52119f7a8f756093da981bd33d35df358033ce870dfa5483bbe400d2afc`

The broad cleanup is now accepted. Stale KEYTRANS allocation tests use an
ordinary nonreserved remote property while explicit reserved-identity
zero-effect tests retain E5E1 coverage. The new allocation-aware PROP SET and
global purge paths preserve allocator OOM distinctly from deterministic
capacity; the legacy per-user prefix API deliberately retains its historical
OOM-to-`LimitReached` wrapper. Helix translates only true capacity to
`CapacityExceeded` and lets OOM remain OOM.

Final evidence: full module 8,087 passed, 4 skipped, 0 failed; build summary
4/4; ReleaseSafe exact KEYTRANS/fresh-server/Helix filters pass; DPROP 121/121;
E5E1 76/76; formatting/diff checks pass; independent review found no blocker.
Final cleanup SHA-256:

- `src/daemon/server.zig`: `61ec1563df134ee71d82cd9fd65bf638ef6fb55521b882ba29c196c0a0cb9f29`
- `src/proto/ircx_prop_store.zig`: `e2aa417eb87d2a0add6100332442b4385dc36f864034a7b1775e24edf5b949ab`
- `src/daemon/helix/prop_checkpoint.zig`: `24c1999efbfb28d618b4f4c421d58924ecabb974ebb578d10742d0649bd38939`

Step 3 hashes above remain unchanged and are accepted. Nonblocking future
coverage: max-props-per-user true capacity, aware-SET existing-entity allocation
sweep, and a suitable nonquarantined successful KT rollback seam.

No deployment, commit, or push was performed.

## Step 4 / DPROP / KICK / D2 acceptance checkpoint

Step 4 OCG2 configuration and boot wiring is accepted. Explicit configured
file read or parse failures are fatal; `[oper.ocg2]` accepts only the frozen
public schema; authority node IDs support the full `u64` domain through quoted
exact 16-hex syntax; and no runtime grant/session/mesh/Helix command consumer
was introduced. An independent final review returned ACCEPT with no findings.

The connected D2 prerequisite failures were also corrected at their actual
server boundaries. Wire ODD1 validation remains exact and case-sensitive,
while already-canonicalized durable property keys compare only the derived
device-ID component ASCII-insensitively. The regression proves durable commit,
folded PROP/LIST visibility, OroStore close/reopen, and server restoration. The
KICK builder body is now framed exactly once at the server send boundary with
`\r\n`; focused and threaded tests prove actor/target delivery precedes a
separate NAMES reply and that the kicked member is absent. Independent KICK
review returned ACCEPT with no findings on this exact server hash:

- `src/daemon/server.zig`: `c58a8f62dc2e11ebd678fa95bac6c5039f9b0ce1ec866897a2175242d5ed2774`
- `src/daemon/config_format.zig`: `f75b85e8586e5ba1f150759561de4a8f9f52323254cafebf64eb1984ddcea7f8`
- `src/daemon/config_boot.zig`: `eb418f968dc9fc66632451bed97cbd33f117d05f89e5791de60ac79442301073`
- `src/main.zig`: `07973165a2a9d4cda0484428bfb5252ac50afa33d9ca189c341cc62a65ca4051`
- `src/proto/e2ee_policy.zig`: `1af7c7627127c3e84a2342aa32e9c9bd8b28f31e075c60725cc3a628a1f5a595`
- `src/daemon/durable_credential_props.zig`: `a6b60a48da724784fecea02b1002153142a7703016b863b5989237838705837b`
- `src/daemon/helix/prop_checkpoint.zig`: `90a7407e820c9598a506a55372a485d9cfc74c16914977bba58d591c1b5475bc`
- `src/daemon/services.zig`: `f5250d985edbfcdba2d4cc030e95b6b790a7675639745db439fa1e4fb8a195ab`
  (current shared Step 5 tree; not the earlier isolated Step 4 services hash)

Final post-KICK/current-shared-tree evidence: `zig build test-mod --summary
all` completed 4/4 with 8,101 passed, 4 skipped, 0 failed (8,105 total),
Debug compile success, 17-minute test duration, and 621 MiB maximum test RSS.
Owned-file `zig fmt --check` and `git diff --check` both pass.

The production-client connected acceptance is complete at
`/home/kain/onyx/.work/d2-connected/2189014-1786613122639`: the browser test
passed 1/1, the artifact secret scan passed, the server started and was cleaned
up, and `summary.json` reports no blocker. `actor-evidence.json` records
`connected-through-kick`, memory-only private keys, and no activation or
session-applied claim. This is local connected evidence only; it does not lift
the OCG2 runtime-activation HOLD and no deployment, commit, or push occurred.

## Account-switch operator-authority ratchet closure

A standalone pre-OCG2 security correction is accepted at the server boundary.
Every successful account authentication is now an authority replacement:
`elevateOperFromAccountTo` clears before lookup, applies one exact configured
local replacement through the typed provenance contract, and never unions or
retains the prior account's privileges. Legacy OCG1 remains explicitly legacy;
this packet does not activate OCG2.

The correction also closes the connected wire projection, not only internal
state. One centralized de-elevation transition cuts authority first, then emits
the exact `-o` plus any formerly-derived `-a`/`-j`, publishes `USER DEOPER`,
and retracts derived `+Y`. Account-wide REVOKE/mesh tombstone clears every
physical attachment without per-attachment prefix output, then resolves display
nicks once and emits exactly one `-Y` per distinct rendered nick/channel. The
prefix dedup state now replaces its remembered direction so a real
`+Y,-Y,+Y` sequence is never suppressed as a relink duplicate.

Focused regressions cover standard SASL, IRCX AUTH, oper A to plain, oper A to
oper B with B's exact non-unioned grant, same-account policy recomputation,
anonymous login, logout, internal privilege/class/title/mode clearing, raw
`-o/-a/-j`, `USER DEOPER`, and shared plus distinct multi-attachment display
nicks. Independent security rereview returned ACCEPT with no findings on:

- `src/daemon/server.zig`: `617d78887b34ad86d344efaa09b810093ba491252eeafbbb9e1164b823208097`

Evidence on the reviewed shared tree: ratchet Debug 71/71; ratchet ReleaseSafe
71/71; mesh-GRANT multi-attachment 70/70; oper-prefix dedup 70/70; broad oper
307 passed, 1 skipped, 0 failed; Debug and ReleaseSafe `zig build check` 3/3;
server format and repository diff checks pass. Current paired (concurrent Step 5,
not owned or independently accepted by this ratchet packet) contract hashes at
integration time were:

- `src/daemon/dispatch.zig`: `3bc83f777cc92c6de458d4ea0a5e8e0b120f7f344ba688a5184338508e864a6d`
- `src/daemon/oper_session_provenance.zig`: `1191b9a3b2928adb3c60c0590ff90c65300b75a46d9b184a100dfa2b5d856ffa`

Post-ratchet full-module evidence is green on the accepted server hash:
`zig build test-mod --summary all` completed 4/4 with 8,107 passed, 4 skipped,
0 failed (8,111 total), Debug compile success, 16-minute test duration, and
622 MiB maximum test RSS. No deployment, commit, or push was performed.

## OCG2 Step 5 sealed session-provenance closure

Step 5 is accepted after foundation review, server-integration review, two
review-driven corrections, and a narrow final hash-delta review. Session
authority is now projected through one sealed visitor path. A configured-local
projection requires a capability derived from the live `OperRegistry` and is
revalidated synchronously before application. Account changes revoke before
recompute. Detached-session and direct Helix inherited-client restoration clear
carried authority and recompute only from the successor's live configured
binding.

The runtime boundary remains deliberately narrower than the completed
foundation: server reconciliation passes durable authority as `.disabled`.
`Services.inspectDurableOperAuthority` is not a production session consumer,
so an OCG2 record cannot yet grant `+o`, privileges, class/title, `+a`, `+j`,
or derived `+Y`. Legacy OCG1 GRANT/REVOKE, disk restore, mesh merge, and Helix
registry carry remain compatibility telemetry only. They cannot authorize JOIN
prefixes, NAMES/WHOIS operator rendering, KICK immunity, reserved DATA tags,
or lifecycle events, and inactive GRANT/REVOKE no longer publish false
`oper_up` events.

Independent foundation rereview returned ACCEPT with no findings. Independent
server integration rereview initially rejected residual OCG1 consumers and a
Helix configured-local restore downgrade; both were corrected. The final
independent server rereview returned ACCEPT with no severity findings. A final
one-line test-only delta (`*kain` to `!kain`) received a narrow ACCEPT: restore
correctly clears a test-only oper projection when no live configured binding
exists. This is not a prefix-rank decision.

Accepted SHA-256:

- `src/daemon/server.zig`: `eb893fc58ffc21e8245417085a2026ba0e6556da57f907b0bf70af289e38206a`
- `src/daemon/dispatch.zig`: `75b603f93088bf1db67b104deee32ac764083f85a26ad38ff9757b53996cc6fc`
- `src/daemon/oper_session_provenance.zig`: `9cb63edbdd9bbd5539d0a2469a0d35499dba265f651f418d09392ddf534d99c4`
- `src/daemon/services.zig`: `73a47184ec9037b00c12abe9e7e80d9b8e33d4bd3e05a4344276aca029389361`

Final evidence on those bytes:

- OCG2PROV Debug and ReleaseSafe: 84/84 each.
- Account-switch Debug and ReleaseSafe: 71/71 each.
- Legacy GRANT/non-authorization: 77/77.
- Migrated-profile/Helix preparation: 72/72.
- Broad oper matrix: 304 passed, 1 skipped, 0 failed.
- Exact EXTERNAL restore regression: 70/70 Debug and 70/70 ReleaseSafe.
- Debug and ReleaseSafe `zig build check`: 3/3 each.
- Final `zig build test-mod --summary all`: 8,111 passed, 4 skipped,
  0 failed (8,115 total), 16-minute test duration, 622 MiB maximum test RSS;
  compile succeeded in 14 seconds with 1 GiB maximum RSS.
- `zig fmt --check src/daemon/server.zig` and server/repository diff checks pass.

No deployment, commit, push, or OCG2 runtime activation occurred.

## Step 6 architecture-only packet — transactional grant/revoke/expiry

Status: **DESIGN HOLD**. This packet defines the next review boundary; it does
not authorize implementation or activation.

### Required command and authority boundary

1. Only a currently authenticated configured-local authority oper may mint an
   OCG2 record. A durable OCG2 projection, legacy OCG1 record, remote roster
   claim, carried snapshot bit, or runtime-granted account may never delegate.
2. Canonical account, bounded exportable privileges, class/title, record kind,
   issue/expiry time, and authority identity must be validated before revision
   allocation or signing. Revocation is an OCG2 tombstone, never deletion.
3. `allocateDurableOperRevision(account)` is the only revision allocator. A
   revision is usable only after its prepared snapshot crosses the OroStore
   durable cut; exhaustion, ambiguity, poisoned store, or unavailable state
   fails closed and produces no signed/transmitted/session-visible record.
4. The authority signs exactly one canonical OCG2 grant or tombstone using the
   committed revision. `commitDurableOperRecord(wire, now)` must durably commit
   that exact signed wire before any mesh transmission, session reconcile,
   prefix/mode change, success reply, or observer event.
5. After durable commit, reconcile every matching local attachment through
   `configuredLocalBinding` plus the freshly re-inspected durable result.
   Configured-local authority retains precedence. One account-wide transition
   owns `+Y/-Y` dedup; individual attachments own exact `+o/-o`, `+a/-a`, and
   `+j/-j` consequences.
6. Expiry is a reconciliation input, not a best-effort timer mutation. The
   timer scans durable records, re-inspects under Services' lock/crypto/recheck
   contract, and clears expired projections fail closed. A later replay cannot
   resurrect an expired, tombstoned, lower-revision, or equivocated record.
7. Store ambiguity or impossible post-durable publication mismatch marks
   durable authority unavailable and requires restart/recovery. It must never
   fall back to OCG1, cached session privilege, or a predecessor OCG2 record.

### Transaction sequence

`authorize configured root -> prevalidate -> durably allocate revision ->`
`canonical sign -> durably commit exact wire -> re-inspect -> reconcile local`
`attachments -> emit one wire/event transition -> transmit exact bytes`

No externally observable success or authority effect may precede the second
durable cut. Replay/stale inputs are idempotent no-ops; same-revision divergent
bytes persist equivocation and disable privilege serving for that account.

### Required Step 6 acceptance matrix

- grant, narrowing, replacement, revoke, and expiry across zero/one/multiple
  attachments, shared and distinct display nicks, and multiple reactors;
- configured-local precedence over active/tombstoned/expired/equivocated OCG2;
- preadmission OOM/capacity/busy/exhaustion and every store-failure phase, with
  proof of zero wire/session/event/mesh effects before durable commit;
- crash/reopen after revision allocation and after exact-wire commit, proving
  monotonic floors, no reuse, and correct grant/tombstone recovery;
- stale/replay/equivocation, future-time, expired-at-arrival, privilege-mask,
  account/class/title, signature, authority-key, and exact-wire tamper cases;
- Helix adoption and cold restart recompute, timer expiry during upgrade, and
  concurrent login/logout/account-switch during grant/revoke;
- secured-mesh transmission assertion that the committed exact bytes are sent
  only after durability, without OCG1 fallback or re-signing.

Step 6 implementation remains blocked until Sol architecture review accepts
this ordering, error surface, event ownership, and test matrix explicitly.

## Step 6 S6-A1 inactive durable-clock and transaction foundation

S6-A1 is accepted after an independent review rejected the original
security-time calculation, a bounded correction, and a fresh independent
read-only rereview that returned **ACCEPT** with no concrete security or
correctness findings. This acceptance lifts only the S6-A1 durable foundation
slice. The transactional issuer, command authorization, session reconciliation,
expiry scheduler, mesh transmission, Helix adoption, and the remaining Step 6
acceptance matrix above remain on **HOLD**.

The corrected snapshot is strict version 3. It persists a durable
`security_floor_ms`, a separate `reserved_until_ms` horizon, and an explicit
reservation-authorization flag under the v3 checksum domain. Strict v1 and v2
images decode unavailable and unauthorized; generic re-encoding preserves that
state. Only `prepareSecurityTimeReservation(raw, horizon)` followed by the
Services OroStore durable cut authorizes the image. Failed or ambiguous cuts
mark the authority unavailable and advance its availability epoch.

The process-local clock anchors are deliberately not serialized. During one
process, effective security time is the maximum of the previous effective
value, checked `boot_effective + monotonic_elapsed`, and current realtime, and
it may not exceed the durable horizon. A successful reservation advances the
next restart's durable floor to that horizon while retaining the live process's
lower in-memory anchor. Reopen therefore fast-forwards to the prior horizon and
must reserve the next interval before advancing, preventing a clock rollback
from resurrecting an expired authority record. Checked-add and exact
`maxInt(u64)` boundary tests fail closed on overflow.

Reservation state cloning, canonical encoding, OroStore preparation, and all
allocation occur before the store cut; checked in-memory installation is
allocation-free after it. Tests cover allocation failure, failed/short writes,
ambiguous sync, and reopen resolution: failed and torn candidates recover the
prior inactive image, while a fully written ambiguous sync recovers the exact
candidate. Exact copied grant, tombstone, and equivocation identities include
canonical account, full authority tuple, BLAKE3 digest, SHA-256 signed-wire
identity, conflict digest, and exact signed bytes. One stable relinearization
retry is permitted; a second same-account instability fails unavailable.

Accepted SHA-256:

- `src/daemon/durable_oper_authority.zig`: `f84ff5113f9ca9952e133dcedb274748b17fbf6669f328e71f8d2f0af2b34b59`
- `src/daemon/services.zig`: `414b5892715776686b9322cb9de1bca170ad2ee870bf44783edf789b30c731c7`

Unchanged boot/root context at acceptance:

- `src/daemon/durable_oper_authority_boot.zig`: `f5a94b47375f9ae711a5ba92684b1e4e3bd8e59eaf5427066b4e6d095f0d2ff1`
- `src/daemon/config_boot.zig`: `eb418f968dc9fc66632451bed97cbd33f117d05f89e5791de60ac79442301073`
- `src/daemon/root.zig`: `4e88bc4417b731cd0c6d8329a0904909499734a984b810cf4a0a9fd8deec24ee`
- `src/main.zig`: `07973165a2a9d4cda0484428bfb5252ac50afa33d9ca189c341cc62a65ca4051`

Focused acceptance evidence on those bytes:

- OCG2CLOCK Debug and ReleaseSafe: 76/76 each.
- OCG2TXN Debug and ReleaseSafe: 70/70 each.
- OCG2AUTH Debug and ReleaseSafe: 80/80 each.
- OCG2PROV Debug and ReleaseSafe: 84/84 each.
- Underlying prepared-store matrix Debug and ReleaseSafe: 80/80 each.
- `zig build check` Debug and ReleaseSafe: 3/3 each.
- Broad `zig build test-services --summary all` Debug and ReleaseSafe passed
  during the fresh independent rereview.
- Final current-shared-tree `zig build test-mod --summary all`: 8,119 passed,
  4 skipped, 0 failed (8,123 total), 17-minute test runtime, 623 MiB maximum
  test RSS; Debug compilation succeeded in 18 seconds with 1 GiB maximum RSS.
- Owned-file `zig fmt --check` and repository `git diff --check` passed.

Nonblocking gaps after S6-A1 acceptance are the still-held Step 6 issuer,
session, expiry, mesh, Helix, multi-reactor, and connected multi-node matrices.
No runtime privilege consumer reads this foundation: main only restores and
attaches the inactive image, and server reconciliation still supplies durable
authority as disabled. No commit, push, deployment, or activation occurred.

## Step 6 S6-A2 inactive transactional issuer acceptance

S6-A2 was produced by the explicitly assigned **Grok 4.6** main-writer lane.
The final writer handoff identified the hashes below; this senior acceptance
lane independently resolved the repository paths and reproduced every digest
from the current shared-tree bytes:

- `src/daemon/ocg2_authority_issuer.zig`:
  `024e55491c26647bb1f8440c9be48bce94f2707d024c5a94d2634fa8bd620237`
- `src/daemon/root.zig`:
  `4cc0115e1665b5db7fe556cf756399cad7cf1f140f2e28345fc23034e245c4a1`
- `src/daemon/services.zig`:
  `ecb8617bd34f8486a2217a2a92aa5e022258671cdc5e1fa4544c375382a3e8df`
- `src/proto/oper_cred_share.zig`:
  `8072b55b4309ca3933e2ddd3508ab2a4491d83a3ad946520019c911f96a0f28d`
- S6-A1 dependency `src/daemon/durable_oper_authority.zig`:
  `f84ff5113f9ca9952e133dcedb274748b17fbf6669f328e71f8d2f0af2b34b59`

Final current-byte evidence:

- OCG2ISSUER Debug: 87/87 passed, 0 skipped, 0 failed; test runtime 1s.
- OCG2ISSUER ReleaseSafe: 87/87 passed, 0 skipped, 0 failed; test runtime
  914ms.
- Independent unfiltered `zig build test-mod --summary all`: exit 0;
  8,137 passed, 4 skipped, 0 failed (8,141 total). The build-reported test
  runtime was 16 minutes with 622 MiB maximum test RSS; Debug compilation took
  17 seconds with 1 GiB maximum RSS. The enclosing POSIX shell timer recorded
  exact totals of 1,034.096s real, 1,118.571s user, and 119.914s system.

Independent senior verdict: **ACCEPT S6-A2 INACTIVE ONLY**. The issuer slice is
accepted as an isolated transaction/signing foundation. It remains on explicit
runtime-activation **HOLD**: there is no production command, session, expiry,
mesh, Helix, or other runtime privilege consumer of this issuer. No deployment,
commit, push, live wiring, or activation was performed or authorized. Later
Step 6 packets must separately satisfy the held authorization, reconciliation,
expiry, transmission, restart, and connected multi-node acceptance matrices.

## Step 6 S6-C1 inactive session-provenance leaf acceptance

S6-C1 was implemented by the explicitly assigned **Grok 4.6** main-writer
lane. The initial Sol architecture/security review returned **REJECT** with two
blocking findings:

1. provenance construction did not bind through the canonical stable
   `OperRegistry` identity;
2. inline length fields were sliced before their declared bounds were proven.

The leaf was corrected to use the canonical stable `OperRegistry` binding and
to validate every inline length before slicing. Sol's final independent review
then returned **ACCEPT** with no findings.

Final accepted SHA-256, independently reproduced from current bytes:

- `src/daemon/oper_session_provenance.zig`:
  `bbc69636dd11a9224641bafc1e83b0cdaed58a82cb6fd20fbd9fb743994f7ce0`
- `src/daemon/ocg2_authority_issuer.zig`:
  `4ff00acd10455ecaa4b46303e0780547a1306a920084313e608aec7fc9df4535`
- `src/daemon/root.zig`:
  `7770a7323e85fdba2de67264a48914bc33de7fa2b07239c7f5991e4ed6728b1e`

Final evidence on those bytes:

- OCG2PROV Debug and ReleaseSafe: 91/91 each.
- OCG2ISSUER Debug and ReleaseSafe: 95/95 each.
- Combined independent focused matrix Debug and ReleaseSafe: 117/117 each.
- `zig build check` Debug and ReleaseSafe: 3/3 each.
- Owned-file format checks, repository diff checks, and the recorded static
  scans are clean.

Independent verdict: **ACCEPT S6-C1 INACTIVE LEAF ONLY**. No unfiltered full
`zig build test-mod` suite was rerun after S6-C1, and this entry makes no such
claim. There is no runtime consumer or activation and no server, main,
Services, protocol, mesh, Helix, or transmit wiring for this leaf. No deploy,
commit, push, live integration, or privilege activation occurred or was
authorized. All later Step 6 runtime and connected acceptance boundaries remain
on explicit **HOLD**.

## S6-C3 — Inactive OCG2 Reconciliation Schedule — ACCEPTED

Grok 4.6 implemented the allocation-free schedule leaf, then corrected two
Sol findings before admission: the canonical five-minute future issue bound is
now enforced against the caller security clock (not the record's own issue
time), and the module surface is sealed to exactly six declarations with no
borrowed account accessor. The correction also removed a dangling-slice hazard
from the test/helper path.

Accepted SHA-256:

- `src/daemon/ocg2_reconcile_schedule.zig`:
  `e94c4042bfb844d3a1362571a1beacecb4204b0dd9f12a4318465e75ac9eced7`
- `src/daemon/root.zig`:
  `a276b3470b935130515a8216ec43432d4915c1883255ae8f8d17bdf07ac1a27c`

Evidence:

- Fresh isolated OCG2SCHED Debug: 94/94 pass.
- Fresh isolated OCG2SCHED ReleaseSafe: 94/94 pass.
- `zig build check` Debug and ReleaseSafe: 3/3 each.
- Format and diff checks: pass.
- Sol independent rereview: ACCEPT, no severity findings.
- Fresh unfiltered module suite on the accepted C3 bytes: 8,193 pass,
  4 skip, 0 fail, 8,197 total; 17 minutes.

This remains an inactive advisory schedule foundation. It has no production
caller, no runtime authority or session effect, and no mesh, Helix, event,
transmit, deployment, commit, or push claim. S6-C4 workset planning is a
separate in-flight packet and is not admitted by this entry.

## S6-C4 — Inactive Reconciliation Workset + Two-Node Deploy — ACCEPTED

Grok 4.6 added an allocation-free O(n) reconciliation workset planner. It
converts acknowledged C3 baselines and fresh schedule hints into advisory stale
work only; it has no commit API, authority, runtime caller, or network effect.
Sol independently accepted the exact eight-declaration surface, full validation
before writes, six-way alias rejection, failure atomicity, canonical merge, and
runtime HOLD.

Accepted SHA-256:

- `src/daemon/ocg2_reconcile_workset.zig`:
  `d2364dc1bff36351200563a6f39d2536c0e2132a0da5d015a9c1677106ded347`
- `src/daemon/root.zig`:
  `9af90753a9840ce51233b9fdab2debf59be5e3a1b7cc576ff513c6c18f169410`

Acceptance evidence:

- OCG2WORK Debug and ReleaseSafe: 100/100 each.
- OCG2SCHED 94/94, S6C2 85/85, and OCG2PROV 91/91 in both modes.
- Both compile checks, format, and diff checks: pass.
- Sol independent review: ACCEPT, no blocking findings.
- Fresh unfiltered module suite: 8,224 pass, 4 skip, 0 fail, 8,228 total.

Release and deployment evidence:

- ReleaseFast static stripped candidate version: `0.5.8+bbeb30e`.
- Candidate SHA-256 on build, local live image, and remote live image:
  `5d833209f2fe81c53d306e86e9b740fa9787dd5053f87712bfd82efd4d33e0ca`.
- Hardened Helix candidate smoke: all checks passed, including multi-shard,
  TLS, WSS mid-frame, session token, modes, MONITOR, SILENCE, channel, and PING.
- Local rollback binary: `/home/kain/onyx-server-run/onyx-server.rollback-20260813-pre-bbeb30e`.
- Remote rollback binary: `/home/trev/onyx-server-run/onyx-server.rollback-20260813-pre-bbeb30e`.
- `eshmaki.me` Helix reload retained PID 828697, adopted four listeners,
  reattached six clients and the secured mesh link.
- `ircx.us` Helix reload retained PID 1245448, reattached three TLS clients
  and the secured mesh link.
- Both nodes: service active/running, peer up=1, partitioned=0, quorum true,
  exact live image hash, IRC registration numeric 001, and PING/PONG pass.
- Local `.meshpass`, `.cloaksecret`, and VAPID key were hardened to mode 0600
  without reading contents. Remote VAPID key is 0600; the other two named files
  do not exist at the remote run path.

S6-C4 runtime activation remains explicitly on HOLD despite deployment of its
inert compiled leaf. No commit or push was made.
## 2026-08-13 final two-node deployment

- Release commit: `1156eb3` (`feat: advance durable identity reconciliation`).
- Static stripped musl artifact: Onyx Server `0.5.8+1156eb3`, SHA-256 `9ec9e48dc2523b6461288ba1b0a1ad1e00895960fc7b882c78373729f3dabaac`.
- Local config and peer config both passed `--check-config` with the staged artifact before replacement.
- Local Helix upgrade: PID `828697` preserved; rollback `/home/kain/onyx-server-run/onyx-server.rollback-20260813-2327-5d833209f2fe`; six carried clients and the secured mesh link restored.
- Peer Helix upgrade: PID `1245448` preserved; rollback `/home/trev/onyx-server-run/onyx-server.rollback-20260813-2325-5d833209f2fe`. The first attempt safely refused with `SessionReplicaConverging`; the second succeeded after convergence and restored three carried clients plus the secured mesh link.
- Both nodes' installed files and `/proc/<pid>/exe` hash to the exact artifact above; both units are active.
- Final gates: S6-C5 84/84 Debug and ReleaseSafe; services 512/512 both modes; unfiltered module suite 8,238 pass / 5 skip / 8,243 total; ReleaseFast build; runtime smoke; multi-shard Helix smoke; dual-node Era 2 acceptance; metrics `links_active=1`, `peers_up=1`, `partitioned=0`, `tcp_active=1` on both nodes; bidirectional cross-node PRIVMSG smoke.
- Sol accepted S6-C5 as runtime-inactive source. C5 caller wiring and OCG2 runtime activation remain strict HOLD and were not enabled by this deployment.
