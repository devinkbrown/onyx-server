# Roadmap acceptance inventory

This inventory preserves every numbered target from the [integrated roadmap](../ROADMAP-2026-10-26.md). It is a work queue, not a completion certificate. Current source and tests must prove each full acceptance criterion before an item becomes accepted. Client source and external deployment remain outside the present repository evidence.

Status: **accepted** means the listed criterion is proved for the recorded source/platform/artifact; **partial** means narrower related work is proved; **open** means full acceptance has not been established. Acceptance does not certify a deployed release or later source changes. See [wave evidence](roadmap-wave-execution-2026-10-26.md) for scope, commands and remaining limits.

| ID | Requirement | Status | Required acceptance |
| --- | --- | --- | --- |
| P01 | Fourteen-day default anonymous rotation, configurable and wall-clock consistent. | accepted | Online rotation and offline return behave consistently across nodes; explicit old settings are identified. |
| P02 | Versioned epoch/cadence provenance for public anonymous cloaks. | accepted | Historical matching has bounded work, authenticated address inputs, and no real-address disclosure. |
| P03 | Automatic moderation continuity across rotations. | accepted | `+b/+e/+I/+Z`, ACCESS, SACCESS, AKICK, and WARD retain original nick/ident/address scope. |
| P04 | Collision-resistant account-cloak encoding with safe compatibility. | accepted | Permitted punctuation, long names, case folding, and crafted lookalikes cannot share privileges. |
| P05 | Fail-closed configured key derivation and validated cloak settings. | accepted | Primary or previous-key failure does not silently generate a replacement; secrets are never printed. |
| P06 | Uniform direct, trusted-PROXY, IPv4, and mapped-IPv6 identity. | accepted | Equivalent addresses have equal policy results, clone counts, and reputation handling. |
| P07 | Privacy preview before applying a persona, login, or network change. | open | The client explains public visibility and account linkability without displaying moderation internals. |
| P08 | Moderation impact preview. | open | An operator can inspect whether a proposed rule matches representative authorized subjects and its expiry. |
| P09 | Legacy-rule migration audit. | accepted | Exact verified migrations preserve issuer/expiry/order; ambiguous old opaque masks are reported rather than guessed. |
| P10 | Privacy leak regression corpus. | accepted | WHOIS, WHOWAS, search, events, errors, media offers, and diagnostics expose only permitted identity fields. |
| W01 | Welcome, purpose selection, and profiles: private mesh, community, media, and existing network. | accepted | Profiles are explicit sets of schema values; changing a profile shows the resulting diff. |
| W02 | Keyboard-first full-color interface with progress, help, search, back, and review. | accepted | `NO_COLOR`, dumb terminals, narrow terminals, screen readers, and redirected output remain usable. |
| W03 | Resume an interrupted setup from a private draft. | accepted | No secret appears in terminal history or a world-readable draft; cancel leaves live config untouched. |
| W04 | Hostname, listener, address, port, and reachability checks. | accepted | Checks explain observed versus unknown results; they do not open production listeners. |
| W05 | Guided account and operator authentication. | accepted | No default password, secret echo, or irreversible privilege change during preview. |
| W06 | Certificate, mesh identity, cloak secret, and permission setup. | accepted | Secure generation, provenance, expiry, and exact storage permissions are reviewed before commit. |
| W07 | Join an existing mesh through an expiring enrollment workflow. | open | Node role and authority are reviewed; replay, wrong network, and revoked enrollment fail closed. |
| W08 | Voice/video port and transport assessment. | accepted | UDP, relay needs, advertised addresses, and constrained-network fallback are explained truthfully. |
| W09 | Capacity estimates and resource limits. | open | Estimates name their benchmark basis; memory/CPU/network limits become explicit config values. |
| W10 | Service-manager detection and installation plan. | accepted | OpenRC, systemd, foreground/container, and supported portable paths share config validation. |
| W11 | Validate, dry-run, show diff, commit, and recovery instructions. | accepted | Failed validation or allocation leaves the old configuration and secrets intact. |
| W12 | Upgrade and maintenance mode using the same wizard. | partial | Compatibility, backup, expected client impact, and rollback are shown before a supervised action. |
| Q01 | Actionable structured failures with a short next step. | open | Permission and privacy failures do not become channel or account existence oracles. |
| Q02 | Searchable help derived from command and capability definitions. | partial | Examples parse, argument names match handlers, and unavailable commands identify missing support. |
| Q03 | Understandable channel creation and permission presets. | open | The resulting access rules can be inspected and modified; presets do not hide extra privileges. |
| Q04 | Permission explanation for self and authorized operators. | partial | Effective permission traces identify the rule and expiry without exposing private policy to others. |
| Q05 | Undo for explicitly reversible moderation changes. | open | Undo is a new authorized event with conflict detection, not deletion of audit history. |
| Q06 | Expiring restrictions and reminders. | open | Expiry is consistent mesh-wide and survives restart; affected people see only authorized details. |
| Q07 | Safe configuration hot-reload preview. | open | Startup-only, reloadable, and restart-requiring changes are clearly distinguished. |
| Q08 | One redacted diagnostic bundle. | partial | Version, capabilities, counters, and bounded traces are useful without including credentials or raw private identity. |
| Q09 | Guided reconnect and device recovery. | open | Users retain drafts and context while the server accurately distinguishes attached, detached, and revoked sessions. |
| Q10 | Quiet maintenance experience. | open | Routine cloak changes and healthy route repair do not produce repeated alarming client notifications. |
| T01 | Document each credential's issuer, scope, lifetime, and replay domain. | accepted | Local resume, portable reclaim, replica, media, and oper credentials are never treated as interchangeable. |
| T02 | Keep local reusable tokens stable across sequential Helix upgrades. | accepted | Four existing attachments remain connected and a fifth resumes after A then B upgrade. |
| T03 | Remove unnecessary reissue and retransmission. | partial | Counters distinguish required credential rotation from duplicate publication; retries remain idempotent. |
| T04 | Indexed lookup and bounded per-token work. | accepted | Operation counters prove work follows the selected token group rather than all accounts/sessions. |
| T05 | Bounded validation memoization for immutable signed objects. | accepted | Cache keys bind exact bytes, key generation, authority, and expiry; revocation cannot be hidden by a hit. |
| T06 | Fair batching of dirty replica and projection work. | accepted | One failing group cannot starve others; queue limits and retry cursors survive the required boundaries. |
| T07 | Device-facing session inventory and revocation. | partial | Revoking one attachment or one logical session has the selected scope and is not inferred from a nickname. |
| T08 | Token secrecy and at-rest protection review. | open | Logging, diagnostics, clipboard handling, crash artifacts, and drafts do not reveal bearer credentials. |
| T09 | Recovery without credential churn. | partial | Reconnect storms do not allocate replacement identities or burn valid tokens before commit. |
| T10 | Efficient revocation and tombstone retention. | open | Stale replicas cannot resurrect revoked authority; memory bounds and anti-entropy remain explicit. |
| V01 | Pre-call soundcheck shared with the setup wizard. | open | A user can test microphone, output, permission, level, and transport without entering a public room. |
| V02 | A clear join state machine: requesting, authorized, connecting, audible, recovering. | open | UI never reports a connected call merely because signaling or TCP succeeded. |
| V03 | Runtime codec negotiation across native and browser legs. | partial | Encoded payload compatibility is demonstrated; no unsupported codec is advertised. |
| V04 | Stable device changes and audio-focus behavior. | open | Unplug, permission loss, sleep/wake, and output switches do not create ghost publishers. |
| V05 | Voice-priority pacing and congestion response. | partial | Audio remains timely during video congestion without starving control traffic. |
| V06 | Coordinated jitter, NACK, FEC, and late-packet policy. | partial | Recovery helps useful frames; late retransmissions do not consume a congested link indefinitely. |
| V07 | Speaking, mute, deafen, push-to-talk, and stage permissions. | open | Authoritative room state and local device state cannot silently disagree. |
| V08 | Private room invitations and audience changes. | open | Revoked participants stop receiving the selected media; key and route changes are transactional. |
| V09 | Call continuity through mesh repair and upgrades. | open | Existing transports and permissions survive the promised boundary, or the client explicitly recovers. |
| V10 | Accessible conversation controls and optional captions contract. | open | Keyboard and assistive use work; any transcription is opt-in with explicit processing and retention. |
| V11 | Network health explanation in plain language. | open | Loss, jitter, fallback, and microphone faults are distinguished without exposing peer addresses. |
| V12 | Consent-led recording lifecycle. | open | Recording is visible, permissioned, stoppable, and retention-limited; E2EE boundaries are honest. |
| C01 | Camera preview and explicit publishing consent. | open | No camera or screen frame is transmitted before the selected action and room authorization. |
| C02 | Efficient per-receiver simulcast/layer selection. | open | Slow receivers receive appropriate layers without lowering every participant's quality. |
| C03 | Stable adaptation with hysteresis and resource budgets. | open | Bandwidth oscillation does not cause a quality-selection storm or endless keyframes. |
| C04 | Screen-content priority distinct from camera motion. | open | Text remains readable at constrained bandwidth; configured frame-rate and latency tradeoffs are visible. |
| C05 | Reliable source switching and renegotiation. | open | Camera/share switches preserve track identity correctly and retire old routes and capabilities. |
| C06 | Speaker, grid, presentation, and audio-only client layouts. | open | Subscription intent drives forwarding; hidden tiles need not consume full-resolution bandwidth. |
| C07 | Bounded keyframe, feedback, retransmission, and decode pressure. | partial | Malicious participants cannot force unbounded encoder or SFU work. |
| C08 | Native/browser transport interoperability matrix. | partial | Actual payloads, timing, feedback, and encryption are verified for every advertised combination. |
| C09 | Explicit encryption and recording boundaries. | open | Relay encryption, server-visible media, and end-to-end encrypted media are labeled accurately. |
| C10 | Pause/resume around backgrounding and device limits. | open | Saved resources do not leave stale speaking or publishing state. |
| C11 | Relay and constrained-network fallback. | open | Capability negotiation chooses a permitted path and reports the quality/cost tradeoff. |
| C12 | Sustained-call endurance and leak gates. | open | Long runs include join/leave churn, device changes, loss, and key updates with bounded memory. |
| M01 | A capability/topology view with established-link semantics. | accepted | TCP activity, secured links, peer health, partition, and service readiness are distinct. |
| M02 | Adaptive bounded anti-entropy scheduling. | open | Quiet nodes send less repair traffic; active nodes converge without starving client traffic. |
| M03 | Delta and digest reconciliation before full repair. | open | Missing state and deletions converge; malformed or divergent summaries fall back safely. |
| M04 | Route selection using measured service cost. | open | Hysteresis prevents flapping; authenticated origin authority is unchanged by the selected route. |
| M05 | Separate control, chat, replay, and media scheduling budgets. | open | Slow history or video consumers cannot block essential heartbeats, moderation, or session repair. |
| M06 | Efficient media distribution between nodes. | open | A shared upstream stream is reused where valid; per-room encryption and audience boundaries remain intact. |
| M07 | Backpressure that crosses node boundaries. | open | Bounded queues, explicit retry, and durable admission preserve accepted events under pressure. |
| M08 | Recovery after node loss, partitions, and clock skew. | open | Deterministic resolution, exact-once acceptance, tombstones, and signed bytes survive non-clique paths. |
| M09 | Config and cloak compatibility diagnostics. | partial | Operators learn which mismatches break identity/policy before changing either live node; no secret hashes are made public. |
| M10 | Maintenance drain and session-preserving upgrade plans. | open | Every physical attachment is accounted for; incompatibility explicitly blocks a seamless-upgrade claim. |
| M11 | Larger topology campaigns. | partial | Start with A-B-C and diamonds; expand to 8/32/128-node simulations plus distinct-host representative acceptance. |
| M12 | Workload-aware admission and recovery quotas. | open | Reconnect storms and failed peers cannot consume every CPU or verification slot. |
| A01 | Reproducible musl builds for supported x86_64 and aarch64 targets. | partial | Compiler, target, CPU baseline, flags, source revision, and artifact digest are recorded. |
| A02 | A supported compiler/toolchain bootstrap. | open | Native older-CPU execution is tested; emulated compiler workarounds are explicit and never confused with native daemon acceptance. |
| A03 | OpenRC supervision with config preflight. | accepted | Service starts in foreground under its supervisor, invalid config refuses start, and restart limits prevent loops. |
| A04 | Alpine package and config/state/log layout. | accepted | Private keys and state have correct ownership; upgrade scripts do not overwrite operator config or generate an unrelated identity. |
| A05 | Service-manager adapter shared by wizard and doctor. | partial | OpenRC, systemd, container, and foreground modes report equivalent meaningful readiness. |
| A06 | Minimal non-root runtime images. | partial | Runtime dependencies are explicit, root filesystem can be read-only, mutable state and secrets are mounted deliberately. |
| A07 | Alpine-native network and descriptor acceptance. | partial | DNS, TLS trust, IPv6, UDP media, WebTransport, limits, and reopen/upgrade work on the actual runtime. |
| A08 | Kernel capability probes with portable fallbacks. | accepted | io_uring support is probed; missing features do not silently disable required service or force unsafe settings. |
| A09 | Bounded logs and diagnostics under Alpine supervision. | accepted | Journald is not assumed; useful metadata survives rate limiting without collecting private message content. |
| A10 | Native Alpine release CI and recovery drill. | partial | Cold boot, crash, config rejection, backup restore, rolling mesh upgrades, and rollback are exercised. |
| E01 | A compact task handoff: objective, owners, changed files, invariants, evidence, risks. | accepted | A new agent can continue without rereading the entire transcript. |
| E02 | One owner and one investigation per bounded seam. | partial | Delegate independent work; reuse a previous investigator for related questions. |
| E03 | Targeted source reads and bounded search output. | partial | Search excludes giant evidence trees by default and reads relevant declarations before full files. |
| E04 | Persist complete build logs and return concise outcomes. | accepted | Reports include exact command, exit, pass count, relevant failure excerpt, and log location. |
| E05 | A gate ledger keyed by source cut and command. | accepted | Repeat a gate only when a changed dependency, failure, or unresolved concern invalidates its evidence. |
| E06 | Reuse public task context, never secrets. | open | Cache/history summaries redact credentials and retain the necessary security invariants. |
| E07 | Review after a bounded writer has stopped. | partial | Fresh reviewers receive a precise diff and threat model, not every unrelated repository file. |
| E08 | Track useful-work efficiency. | partial | Compare accepted/tested work per input/output token and wall-clock minute, including rework. |
| E09 | Low-noise progress reports. | partial | Summarize changed conclusions and next uncertainty; do not narrate routine polls. |
| E10 | Preserve evidence through compaction. | partial | Ownership, source cut, exact commands, deploy state, and unresolved tests survive handoff. |


W05 is accepted for the Linux setup workflow on captured artifact
`6a4d8a807f99c2e452866bef0382eae6be0e23b418a8905523c5f54448782318`.
Fresh workflow and loader-cleanup reviews, 21/21 ReleaseSafe tests (allocation
indices 0–221 and clean success at 222), 20 Debug representatives, 28 native
setup cases and 20 native authentication cases establish the stated criterion.
The public authentication harness explicitly selects and hashes the binary;
its final input-bound ledger is unchanged and green. Native checks execute
PLAIN/SCRAM, server proofs, bad-proof denial, exact privileges, cold restart,
private secret input and preview/cancel/EOF flows. This does not accept the
entire wizard, later retirement-policy code, or a production release.

T01 has a [reviewed source contract](../reference/credential-domains.md) for
credential issuers, scope, lifetime and replay domains. A final independent audit
confirmed the inventory and the separate wired local/portable, replica, media
and operator authorization paths. T01 is accepted within this documentation
criterion; recovery, revocation, transport/media and other token implementation
gaps remain separate. Live SRM1 reuse and current SRM2 restore/redirect behavior
are distinguished from codec-only mechanisms. This is current-source review,
not a new runtime or deployment claim.

V05 now includes a native physical-UDP prerequisite: reliable enqueue wake and
bounded FIFO send turns, with real UDP latency/ingress/pause tests in Debug.
This is not audio-over-video scheduling, rate admission, WebTransport media or
native mesh forwarding. Those requirements and optimized validation remain open.


T02 now has [private two-node TLS sequence evidence](private-helix-sequence-2026-10-27.md):
four held application attachments survive A then B handoffs and a fifth resumes,
with stable tokens and 38 events / 184 exact deliveries. This is a captured
pre-format same-image, SIGUSR2, legacy-portable result. Historical-version,
SRM2, operator-triggered and deployed acceptance remain
unproved; the historical source also has an explicit
[compatibility constraint](upgrade-compatibility-2026-10-27.md). T02 remains
partial and no additional target is accepted from this pilot.


T02 and M11 now also have reviewed private A–B–C evidence with no A–C link:
four held attachments survive A then B same-image handoffs and a fifth resumes
on C, with 38 events / 184 exact deliveries, unchanged accepted socket custody,
secured links 1/2/1 and adoptions 1/1/0. See the
[three-node extension](private-helix-sequence-2026-10-27.md#three-node-non-clique-extension).
This is the same pre-format captured artifact. Larger topology simulations,
distinct-host operation and the other listed upgrade boundaries remain open;
no additional acceptance target is marked accepted.


P10 now includes a reviewed visible-host-only WHOWAS correction integrated into
source. The identical native TLS harness fails on artifact873b and passes all
four anonymous/account NICK/QUIT cases on artifact43d703. Unit coverage also
includes trusted-PROXY IPv4/IPv6/mapped input, rotation snapshots and invalid
visible-host fallback. The wider search, event, media, error and diagnostic
privacy corpus remains unproved, so P10 is partial.

M09 now includes the tested [offline configuration comparison](doctor-cloak-comparison-2026-10-27.md)
for fixed cloak categories, with actual human/JSON CLI and allocation-failure
checks. Validated trusted-proxy literals now reject unusable CIDR/malformed
entries with value-redacted diagnostics. Running-peer verification and the
broader configuration compatibility matrix remain open. Both changes use the
four-file source-promotion receipt under `.zig-cache/wave-9/source-promotion/`;
this does not accept a deployed release or the separate wave10 crypto draft.


The later current-source artifact43d703 repeats the diamond result successfully,
closing the post-format runtime gap for that bounded scenario; the six-check
wizard PTY/save/resume/redirected pilot also passes on the same artifact.
Independent review accepted both and cleanup. See the
[current-source confirmation](private-helix-sequence-2026-10-27.md#current-source-confirmation).


P05 is accepted for native candidate `83733d1444ded3e8be826d22eac6a9f589d4f3df37b9c61615b9f6f6b376ad3f`
and its matching promoted source. Either configured key-derivation failure
aborts before the random-key fallback; the fallback remains intentional only
when no key is configured. Present malformed parser values and unknown resolved
modes fail closed. Audited cloak configuration/derivation diagnostics contain
field/error names rather than secret values. Evidence includes 89 module tests
and 7 executable tests in each of Debug and Safe, the unchanged native CLI
oracle's baseline failure and candidate 39-call pass, and fresh independent
source/evidence review. The previous-key failure test injects a derivation error;
the primary-key test exercises real Argon2 allocation failure. CLI tests do not
execute boot KDF failure. Bare date/time atoms retain parser-string semantics;
missing-file tests exercise missing paths, not permission denial. This accepts
the audited cloak paths, not repository-wide log secrecy or memory wiping.
Receipts: `.zig-cache/wave-11/cloak-types-native-candidate/` and
`.zig-cache/wave-11/source-promotion/`. Cross-platform checks are compile-only.
The complete suite and release acceptance remain open.

The 2026-10-28 evidence audit accepts W03 for the native Linux choice-only draft
workflow at source manifest
`c9b5cd81463825bb7dbdec5e47b1ed9b46d238b86db16dfeb0453584dfd4c4d3`.
The matching merged executable passed all 32 native/headless/PTY setup cases,
including save/resume parity, legacy drafts, private exclusive publication,
unsafe draft refusal, cancellation and EOF cleanup, and secret omission.
Drafts carry choices rather than generated credentials; live configuration is
untouched by cancellation. Source review and the executable oracle establish
this bounded workflow; client GUI and other-platform runtime behavior remain
separate. Receipts: `.zig-cache/wave-19/wave20-merged-setup-smoke-v1.{json,log}`.

E04 and E05 are accepted for the recorded source-bound execution workflow.
The gate ledger retains literal commands, source-cut comparisons, exits,
complete logs and log hashes. The wave evidence reports pass/skip/failure
counts and relevant failures, and distinguishes completed gates from live
jobs. Repeated gates in these waves follow changed source, concrete failures,
integration concerns or the explicitly repeated performance campaign; unchanged
foundation evidence is reused. Examples include the failed ordinary-stop
baseline, its passing candidate, combined Debug/Safe receipts and the two
alternating token benchmark pairs under `.zig-cache/wave-19/`. The full Debug suite subsequently passed 10,615 tests with 324 skips at
the recorded c9b source cut; later deltas retain their focused evidence. The
structured-count parser also passed 14 private and 14 actual Python tests.

W04 and W06 now have proven native validation/material-review slices, while
full reachability and secure-generation failure acceptance remain incomplete.
A05 now has a shared tri-state marker detector and explicit-selection
preservation, with passing setup/doctor executable comparisons. Actual
supervision/readiness across all named service modes remains incomplete.
OpenRC now has a passing isolated Alpine guest gate with effective 5/3/60
policy, four real kills within 18 seconds, explicit restart-budget exhaustion,
supervisor termination, recovery PONG and cleanup. This exposed and corrected
the shipped conf.d default precedence; existing operator files are preserved.
Receipt: `.zig-cache/wave-21-openrc-qemu-v10.json`. This does not prove rolling
mesh/Helix, TLS or every service mode, so A05 and A10 remain partial.

A03 is accepted for the recorded Alpine 3.24.3/OpenRC 0.63.2 guest and pinned
artifact `bad7618a17493e348ff91a7a7ff416f2c74a4deb0492033636a455c53d78edc3`,
service `c7d409bd2962b2eb3136124273a6d7476460f47e77907d252af39ab10bcc354e`
and conf.d `07615e4bd87d0256b51a455dd3f105d27ee39e96c2f1c024c823257ce9810d1f`.
Fresh independent review checked receipt/log hashes and the executed oracle:
invalid config refuses start; the foreground daemon has the expected supervisor,
UID and exact physical identity; effective restart policy is 5/3/60; four real
kills occur within 18 seconds; budget exhaustion requires explicit OpenRC failed
state and disappearance of the exact supervisor and last child; explicit
recovery answers PING; stop and VM cleanup complete. Evidence:
`.zig-cache/wave-21-openrc-qemu-v10.{json,log}`. The validated conf.d bytes are
integrated. Broader A05/A10 and release acceptance remain incomplete.

E08 now has two real aggregate goal-usage samples in
`.zig-cache/efficiency-accounting.jsonl`. The interval records one newly accepted
criterion, 537,600 aggregate goal tokens and 5,525 goal seconds, with overlapping
test evidence kept separate and known failed/reworked gates included in cost.
This is an observation, not a demonstrated efficiency improvement; criterion
complexity varies and per-model/input/output attribution remains unavailable.
E08 remains partial until the fuller comparison is supported.

W08 now has a shared setup media assessment in interactive review, headless text,
and additive JSON `media_assessment`. Twenty Debug and twenty Safe tests passed;
a pinned native Debug artifact passed four PTY/headless parity cases covering
media zero/custom ports, disabled profiles, color/NO_COLOR, terminal widths and
cancellation without artifacts. The four source/tool files are integrated, and
the combined actual daemon check plus 29 executable-root setup tests passed.
This establishes presentation of generated configuration facts and explicit
unknowns. It does not assess an existing configuration, configure or verify
relays/browser fallback, or prove NAT/firewall/public media reachability. W08
remains partial. Evidence: `.zig-cache/wave-38/actual-integration.json`,
`native-media-v1.json`, and `actual-check-setup-debug-v1.json`.

T09 now includes a private native owner-level reservation test. Real loopback IRC
registration supplies an actual OrdinaryGuestWitness; the source durably reserves
GuestId/counter 1 before the lease and binding image cross a fresh exec. Two
same-ticket retries preserve that GuestId, epoch and issued-through value; a
separate genuine successor witness reserves counter 2 in the same epoch.
Independent source review, explicit executable/input pins and the successful
native receipt establish this narrow behavior. The fixture does not establish
production capsule/latch integration, original client-FD continuity, reconnect
storm behavior, or session/auth bearer-token reuse. T09 remains partial.
Evidence: `.zig-cache/wave-46/binding-native-v1.json`.


Q02 now includes bounded static help search through the existing HELP/HELPOP
handler: case-insensitive topic/text matching, eight-result and 64-byte query
limits, numeric framing, invalid-input explanations and allocation-failure
cleanup. Thirteen Debug and thirteen Safe leaf tests, the daemon compile check
and independent review passed; guarded source promotion preserved the other
1,235 inputs. This does not derive help from live command/capability definitions,
prove every example parses, or establish client palette integration. Q02 remains
partial. Evidence: `.zig-cache/wave-50/actual-integration.json`.


T01's source inventory now also covers email verification and password reset,
bot authorization grants, TLS delegated credentials and the inactive internal
migration HMAC codec. Independent review confirmed the live versus library-only
boundaries and corrected expiry/consumption details. Two recovery-policy gaps
remain explicit: durable VERIFY bypasses RAM's failed-attempt accounting, and a
valid password-reset code is consumed before password admission, including on
admission failure. No behavior fix is claimed. A second reviewed inventory now also covers WebAuthn,
recovery codes, TOTP, OAuth, webpush and inactive TURN framing. It distinguishes
RAM TOTP replay state from normal verification, which does not reset that state.
Recovery-code CLEAR and webpush unsubscribe can report success despite fallible
store errors; these revocation gaps and earlier end-to-end transport/media policy
boundaries remain open.
See [credential domains](../reference/credential-domains.md). T01 remained partial
at that inventory stage; final acceptance below closes its specific criterion.


T01 final acceptance: independent completion review confirmed that issuer,
scope, lifetime and replay domains now include durable passkeys and reusable
password/SCRAM/CERTFP authority, in addition to the earlier families. Inspected
active-handler guards separate local/portable resume, replica, media and operator
credentials. This closes T01's stated inventory/domain criterion and does not
claim the known recovery-policy defects fixed or the remaining token roadmap
complete. Receipt: `.zig-cache/credential-inventory/t01-acceptance-2026-10-29.json`.

E01 is accepted for the 2026-10-29 continuation entry point `.zig-cache/CURRENT.json`. An independent Terra reader recovered the actual source cut, live gate without restarting it, exact writers, pending source compositions, next safe actions, all 98 statuses and deployment restrictions using only the compact entry point and targeted receipts. A second compact-only check confirmed continuation without the transcript; exact filters, gate acceptance and guarded promotion are explicit. Complete prior evidence remains in the linked history. This accepts the handoff criterion, not implementation or release readiness.

W01 is accepted on the 2026-10-29 reviewed Linux source: typed private/community/media profiles and effective diffs (W58), plus the explicit existing-network validation/review journey (W59v5), passed Debug35+check, Safe35 and49 actual CLI/headless/PTY cases. Independent Sol review confirmed the full named criterion, including retry/back/cancel/EOF, conflicting-option rejection, source/material byte preservation and secret omission. W07 enrollment and W02 terminal usability remain separate. Guarded four-file integration preserved the other1,232 inputs; actual source manifest `.zig-cache/actual-source-after-existing-network-wizard.json` (`54def3e7`).

W02 is accepted for the reviewed 2026-10-29 Linux source/artifact after W60v3 Debug39+check, Safe39 and59 native/headless/PTY cases, fresh Astra source and full-row review, and source-preserving promotion. Ordered labeled `--linear` text has no ANSI/cursor controls; keyboard help/search/back/review and textual stages are tested. Interactive width support starts at20 columns; narrower and redirected contexts have a headless alternative. NO_COLOR/dumb suppression has source/unit evidence and PTY linear cases. Legacy preinteraction/emergency stderr may exceed terminal width. Particular screen-reader software or hardware compatibility is unverified; acceptance concerns the inspectable linear interface, not named-device certification. Actual manifest `.zig-cache/actual-source-after-linear-wizard.json` (`431512e1`), setup guide separately hashed in the integration receipt.

W04 and W08 are accepted for the reviewed 2026-10-29 Linux source after W61v3 and exact composition with W56: Debug43+check, Safe43, composed Debug43/check/install,65 native setup cases and four media PTY cases. Fresh Astra full-row review verified syntax/configured fields, pre-done IRC/TLS review, existing and generated media/native UDP ports, advertised host, STUN/WebSocket settings and qualified relay/fallback explanations. DNS, ownership, port availability, NAT and public reachability remain explicitly unmeasured; no production listener or implicit probe is opened. Parent verified every source/mode/log, linked binary, guide hash/mode and terminal ownership before nine-file promotion. Actual manifest `.zig-cache/actual-source-after-network-media-assessment.json` (`445771af`), guide separately bound in integration receipt. The test-only allocator correction controls remap rejection/relocation paths and exhaustive OOM cleanup; it does not claim to identify the earlier failure historically. No release/deployment acceptance.

W11 is accepted for the reviewed Linux new-artifact publication workflow at W61v3: typed validation, artifact-free previews/effective diffs, explicit atomic no-replacement publication and recovery instructions. Fresh Astra full-row review tied these to43 Debug/Safe tests and65 actual native cases, including existing-file/directory/symlink refusals, byte/secret preservation, cancellation/EOF, deterministic allocation cuts, short-write and sync failure cleanup. This does not authorize active-configuration overwrite or deployment. W06 remains partial because headless material review before publication needs its own lifecycle; W64 is implementing that separately.

W06 is accepted on the reviewed Linux W64v4 composition: interactive and headless callers inspect actual node/certificate identity, expiry/self-signed provenance and observed private modes before explicit publication. Headless bundle mode requires JSON review on stdin; a fresh invocation-specific review ID binds the acknowledgement to the held stage. Fixed custody checks reject changed/missing/extra/replaced/symlink/FIFO material and pathname substitution. Cancellation/precommit errors preserve existing artifacts; output failure after commit retains the published bundle and reports nonzero status. Fresh Astra full-row review and parent guarded nine-file promotion followed44 Debug/Safe/current composed tests, source-scoped full fault evidence, current compact5, TLS6 categories and auth20. Actual manifest `.zig-cache/actual-source-after-headless-material-review.json` (`bc156b9b`), guide hash/mode separately bound. Same-UID concurrent mutation after the final check remains outside private-owner custody guarantees; no release/deployment claim. W11 preservation was independently reconfirmed.


P01 is accepted on reviewed Linux W66v1 source: 97 targeted Debug tests plus
check and 97 Safe tests passed, including actual two-node secured transports,
online CHGHOST, QUIT retirement plus ordered local/mesh observation barriers,
and genuine offline returns on both nodes after the sole wall-clock advance.
The returned cloaks agree with the fourteen-day epoch and differ from the
neighboring epoch. Existing doctor coverage identifies default, daily, disabled
and custom cadence settings. Fresh Astra reviewed both production v8 and exact
composition, preserving all 1,199 existing daemon tests and current W56 fixture
helpers. Guarded server-only promotion preserved 1,241 inputs including the
reviewed benchmark driver. Receipt `.zig-cache/wave-66/actual-integration.json`;
actual manifest `34a9a30aa277906fbff6e78685074201f3914d4b574a4d836dc7dc695856d531`.
P03/P04 and broader mesh-pressure independence remain partial; this is neither
a full-suite nor release/deployment certificate.


W10 is accepted for the reviewed Linux planning interface at W67v2. Shared
structured template facts cover executable/config argv, identity, working
directory, preflight, restart and logging for OpenRC, systemd, foreground and
container guidance. Setup and doctor use the same plan and configuration
validation; marker observations never prove supervisor or daemon readiness.
Interactive review shows the selected plan or auto alternatives before done.
Headless material acknowledgement remains material-only; final JSON includes
the service plan. This accepts planning, not installation, running supervisors
or native execution of portable platforms. Debug setup46 and doctor/service98
passed; Safe exe48 plus module101/1 unrelated optional media skip passed; the
current W66/W65 composition passed check/install, 69 actual setup cases and
doctor fixture categories. Fresh Astra approved source and evidence reuse;
guarded eight-file promotion preserved 1,236 source inputs. Receipt
`.zig-cache/wave-67/actual-integration.json`; manifest
`8abd0d98c4aae3fab2a0e2977b060bbc644bc0434e555c065e39e3ef42cc8923`.
A05 remains partial: meaningful live supervision/readiness across all named
modes still needs actual runtime acceptance. No release/deployment acceptance.


A08 is accepted for the reviewed Linux capability/fail-closed startup contract
at W68/W71. The actual Ringlane initializer probes mandatory kernel opcodes;
missing, malformed, denied, resource-limited and unavailable results refuse
startup. Existing optional copy/one-shot fallbacks and requested SQPOLL settings
remain intact. Debug98 and Safe98 passed without skips, including a real kernel
probe. The composed daemon then passed a real strace syscall-fault campaign:
healthy one/two-shard controls, three errno families, two malformed/truncated
tables, missing SEND, later-shard refusal, SQPOLL refusal without unsafe retry,
and healthy recovery. Event-ordered successful closes prove ring/listener
cleanup before process exit; ports rebind. Fresh Astra verified source, logs,
artifact and empty terminal ownership before guarded two-file promotion.
Receipt `.zig-cache/wave-71/actual-integration.json`; manifest
`0010c95280cc700a092ec2fec82e6b676c9b2f127a125d1d3d8c4957c625be53`.
This does not establish new kqueue/IOCP execution, every-op native fault
injection, or dedicated missing-MSG_RING coverage. Full release remains separate.


T04 is accepted for indexed selected-token APIs at reviewed W70v3. Bind, exact
attachment rebind and bootstrap attachment traverse the necessary folded-account
restore closure rather than unrelated accounts. Fixtures with512 unrelated
accounts prove selected-key/row visits of4/2,6/4 and4/4 respectively. That closure
can contain several tokens; whole-store discovery, maintenance and lifecycle
physical census retain their explicit global scope. The owned canonical index
is updated transactionally across ordinary creation/removal, retained bootstrap
tickets and lifecycle commit/abort/finish; case-variant representative retirement
and exhaustive allocation failures preserve coherence and authority.

Full sessions894/894 Debug and Safe passed on the unchanged lifecycle/index cut.
Fresh Astra approved reuse with final bootstrap95/95 Debug/Safe, current composed
check/install and actual native host/session adoption on three original sockets.
Parent verified every source/mode/log and terminal cleanup, then promoted only
sessions.zig, preserving1,244 inputs. Receipt
`.zig-cache/wave-70/actual-integration.json`; manifest
`5f774f052df2bf8ab020ec38ee2fcd52624f0c8b449d11991d6611dd6370823d`.
No token-wire changes, token-only lifecycle claim, full release or deployment
acceptance follows.


M01 is accepted on reviewed W69v4 Linux source. Ordinary operator MESH reads
one reactor-0-published owned snapshot across reactor shards, separating TCP,
canonical establishment, transport security and negotiated session capabilities.
Before first publication facts remain unknown; allocation failure preserves
previous owned facts as stale, and age also marks them stale. Existing health
details and privileged subcommands remain. Actual nonzero-shard SASL operator
readers, real secured mesh plus pending TCP, ordinary-user481, positive remote
chat, exhaustive publication allocation cuts and independent reader copies pass
90/90 Debug and Safe with no skips/leaks/log errors. The compatibility fixture
now enters genuine reactor-0 ownership before publication; original assertions
are retained. Fresh independent Sol approved production and fixture-only fix.
Guarded server-only promotion preserved1,244 inputs; receipt
`.zig-cache/wave-69/actual-integration.json`, manifest
`0a8c2cdaa202835caab8ecf56595b9242f0161ac3e70993b49110265f708e967`.
Production S2S remains constrained to reactor0; this proves readers on other
shards, not support for mesh connections owned by those shards. No release or
deployment certification.


P10 is accepted for the recorded Linux eight-surface corpus at W74v6. A real
secured two-node mesh and trusted-PROXY canaries exercise WHOIS/WHOWAS, SEARCH,
ordinary CHANNEL/MEMBER/MEDIA events, denied requests, media offers, offline and
online doctor output and generated exports. Positive replies and causal event
receipts precede absence checks; all ordinary transcripts exclude other subjects'
raw addresses and all four offer credentials. Exact own338 and source-defined
own320 address fields are permitted only after positive self queries; every
other byte and the complete credential scan remain intact. Diagnostic schemas
are recursively allowlisted and actual consumed secrets are tested.

The final identity-bound campaign passed19.063s, log
`9190e920b760810f108882ca1d49c78977e2d8a4ba2e709a2bea52c3b3802009`,
on current artifact `5dcde963c58c7576421a7350c56e33fee96c79dc3025889975a49ec4c9d5222c`.
Fresh Astra verified all1,245 inputs/modes, source/binary/log hashes, terminal
cleanup and empty private scratch. Guarded promotion added only the fixture;
manifest `6aacd71f2e74c9252e83779bf860642c2386163b3a7dad7f2175795d51938259`.
This is the named regression corpus, not exhaustive privacy or release proof.
The existing setup helper's final-output capture still has a posthoc cap. Scoped
reuse after the separately reviewed two ACCESS-clock assignments is approved:
this corpus installs no ACCESS rows and covered serializers remain unchanged.


P03 is accepted on reviewed W73v6 Linux source. Twelve real two-node native
cases cover channel+b/e/I/Z, independently authored ACCESS/AKICK/SACCESS and
signed WARD, online rotation and offline return on both nodes, exact nick/ident/IP
negative controls and mapped IPv6. Physical EOF and live local/remote roster
retirement precede identity reuse. Original rule scope, issuer/order/metadata
and supported expiries retain their meaning. SACCESS duration is metadata-only;
Q06 remains open and no new deadline enforcement is claimed for that store.

The expanded matrix exposed an actual expired-ACCESS authorization defect. Both
World-held authorization lookups now sample current configured wall time rather
than waiting for maintenance. Deterministic actual-command checks prove expired
auto-VOICE, DENY and invite-only override behavior without a timer or ACCESS read;
rows remain for ordinary reclamation. Debug87 deterministic plus90 native/caller
cases passed; the final full Safe selection passed101/101 without skips/leaks/log
errors in402.048s (log9b153e22b9ba907ab9055bd61074288773ef825746a2953448009b26407d14ba).
Unchanged non-ACCESS Debug cases reuse the preserved earlier matrix under fresh
Astra approval; original failure evidence and all denial assertions remain.
Guarded server-only promotion preserved1,245 inputs, including the privacy
corpus. Receipt `.zig-cache/wave-73/actual-integration.json`; manifest
`2a90f6d79718124d34d9aeaeb51572aaa6d183e08fdfc8293e12f02b53bcaca6`.
Full suite, release and deployment remain separate.


P02 is accepted for the reviewed versioned opaque-v4 Linux path at W75.
Canonical epoch/cadence labels select at most the primary and previous key; no
epoch-history scan or address history is retained. A counter compiled out of the
public production call proves0/1/2 derivation attempts and2,048 attempts across
1,024 extreme-epoch rules. Debug50/50 and Safe50/50 passed without skips. Counts
measure attempts, not completed HMAC operations or identical Debug machine cost.

An actual accept fixture proves trusted-PROXY identity, an untrusted forged
header retaining canonical kernel identity (`localhost` for loopback), and
ordinary controls before and after; timeout is never success. Fresh Astra
verified this evidence alongside kernel-address capture, configured proxy trust,
established secured remote roster/origin/prefix/account checks and retained
P03/P10 evidence. Guarded four-file promotion preserved1,244 existing inputs;
receipt `.zig-cache/wave-75/actual-integration.json`, manifest
`c926b04217b48ff89dce41e9ccb2c5ddcc52a484d418e489187b73de74b757cb`.
This does not resolve ambiguous legacy opaque-rule migration (P09), add a new
wire format, or certify a release.


P04 is accepted for the recorded account corpus and supported HPR compatibility
path at W77v2. Actual private TLS REGISTER/IDENTIFY, observed WHOIS and real
ACCESS VOICE/NAMES/moderated speech cover punctuation-only accounts,32-byte
shared-friendly-prefix names, canonical placeholder and digest-shaped lookalikes,
and case-equivalent login. Seven observed hosts across five policy pairs yield
six allowed and four explicitly404-denied messages with independent barriers.
No codec, server or wire change was needed.

Fresh Astra verified all1,248 current inputs/modes, native receipt/log/binary and
terminal cleanup. Existing50/50 cloak Debug/Safe and supported three-socket
production HPR repair/refusal remain relevant because those functions are
unchanged; earlier1,016-pass/87-skip caller gates remain disclosed. Only the new
fixture was promoted, preserving1,248 inputs. Receipt
`.zig-cache/wave-77/actual-integration.json`; manifest
`0bde5ec09c372c433c3bf33d52a18022f0bb51a54bb935f25a6a21c741bbd5a8`.
P09 ambiguous legacy-rule migration is not resolved by this acceptance; no
release/deployment certification follows.


## W78 canonical address and reputation acceptance

P06 is accepted for current canonical identity paths. Admission and trusted
PROXY addresses use the same normalized identity for clone limits and
reputation. UNREJECT now normalizes both hexadecimal and dotted mapped IPv6
operands before clearing the IPv4 penalty; native IPv6 stays distinct and
malformed operands are rejected. The global reputation key and checkpoint
format are unchanged. Previously persisted raw mapped-IPv6 rows are not migrated.

Debug87/87 and Safe87/87 passed. The actual daemon matrix proves direct/PROXY
clone equivalence, IPv4/mapped clone equivalence in both directions, three
reputation refusals, two mapped UNREJECT forms and two successful recoveries.
QUIT followed by physical EOF proves original clone retirement before recovery.
The initial fixture timeout was traced to IRC trailing-parameter framing; the
corrected wire encoding retains the original expected replies and recovery
assertions. Both failed receipts and their diagnoses remain preserved.

Fresh Astra accepted the full current-identity criterion with retained P03/P02/P10
evidence. Guarded two-file promotion preserved1,248 existing inputs. Receipt
`.zig-cache/wave-78/actual-integration.json`; manifest
`5aa77dacd5b13267d775d6cce41ea29658fb45353b65e167905305aa13e7cf54`.
This does not certify a full release or deployed image.


## W79 feedback-pressure integration

C07 is partial after the reviewed keyframe/NACK pressure controls were
integrated in the actual routing paths. Fixed1,000ms windows admit one keyframe
request per source and four per publisher, plus128 NACK packet units per source
and512 per publisher. Sources bind the call, full physical client ID and media
leg. Authentication and current source/target authority precede preview; only
successfully queued requests or retained retransmissions consume quota.
Same-physical re-offer preserves windows. The bound owners' awake Io clock is
used without introducing C interop; unavailable, changed or regressing clocks
fail closed. HXMG3 carries windows through strict graph restore; Windows v22
exact capability negotiation rejects older state readers before transfer.

Debug144/Safe144 cover quota/routing behavior. New caller/restore gates passed
90/91 respectively, with four Windows-only control tests skipped on Linux.
The six-peer aggregate/refill gates passed88/88 in both modes, through real
HMAC-STUN-bound legacy-group routing. They prove publisher limits, denied-source
quota preservation, another publisher's same-window headroom, NACK refill,
partial queue charges and nonzero window remap/restore. The exact composed
Windows daemon semantic check also passed. Fresh Astra approved five-file
integration, preserving1,245 source inputs. Receipt
`.zig-cache/wave-79/actual-integration.json`; actual manifest
`63e4d3d559b8d471143faf52f4149eaea5935ac89508a8ec1ab44c59365381e7`.

These are fixed-window packet-count bounds, including boundary bursts; they
are not adaptive byte pacing or decoder protection. Full DTLS/SRTP pressure
acceptance, Windows live Helix and coordinated-identity fairness remain unproved.
At the W79 cut, multi-action RTCP compounds and multi-target FIR were refused.
The W81 integration below supersedes that restriction; C08 remains partial. Linux active-media Helix still requires pristine media.
Full C07 and release acceptance remain open.


## W81 normalized compound-feedback integration

C08 remains partial after legitimate multi-action RTCP and multi-target FIR
handling replaced W79's blanket refusal. The live parser constructs bounded
owned actions and deduplicated NACK sequences. Every target is authorized under
the routing lock before any output. Queue callbacks re-derive the selected
action from the held authenticated ingress; they reconstruct target-specific
feedback instead of forwarding additional raw actions. Sequential quota checks
charge only accepted output, including retained partial retransmissions.
Existing source limits can intentionally yield partial multi-target output.

Actual WebRTC/native legacy-group tests passed93/93 in Debug and Safe, including
recipient-direction HMAC checks, mixed RR/PLI/NACK, deduplication, missing-target
rejection, quota limits and partial output. The malformed later-member, padding,
FIR and65-distinct-sequence corpus now exercises the live parser and passed87/87
in each mode. Its obsolete test-only parser was removed. Exact composition
passed Linux check/install and Windows semantic checks. Fresh Astra verified
all1,250 inputs/modes and approved scoped reuse and three-file promotion,
preserving1,247 inputs. Receipt `.zig-cache/wave-81/actual-integration.json`;
manifest `8ebddc8bd7a61922ce5386c8d77ba20feb340b25b1a07e4ed792a31f3b6599c6`.

RR/TWCC members are forwarded separately, changing compound order/packaging.
This does not establish full browser/DTLS/SRTP interoperability, Windows live
handoff, or release acceptance. The current98-item inventory stays24/24/50.


## W84: sequential upgrade and issuer carry acceptance

T02 is accepted for the reviewed Linux composition integrated on 2026-10-29
(source manifest `ed306e87fa32`, 1,255 inputs). This supersedes the earlier T02
pilot limitations for the recorded criterion. The ordinary production daemon
passed a secured non-clique A–B–C journey: four original TLS attachments retained
their shared token and participation through A then B same-PID exec upgrades;
a fifth resumed on C afterward. The final cumulative oracle checked 55 accepted
events and 407 exact recipient deliveries, stable guest hosts, fresh guest
registration after each upgrade, and pre-cut acceptance witnesses.

The mandatory issuer/host checkpoint carries the live lease, ticket frontier
and full physical connection relations transactionally. Debug and Safe each
passed all 185 distinct adoption allocation cuts and subsequent normal adoption.
A separate 106-case Safe gate covered schema, descriptor ownership, alias
rejection and cleanup. Actual-exec evidence separately proved nonempty owned
output custody and refusal of an incompatible successor before exec. Independent
Astra review accepted the criterion and the exact guarded composition; Linux
production build and Windows semantic checks passed.

Evidence: `.zig-cache/wave-84/actual-integration.json`,
`.zig-cache/wave-83/three-node-session-issuer-native-v3.json`, and
`.zig-cache/wave-76/issuer-adopt-cuts-{debug,safe}-pool-v20.json`.
Windows runtime acceptance, expanded published-guest namespace support,
predecessor availability after failed successor exec, and full release gates
remain separate. No deployment is certified. Inventory: **25 accepted,
23 partial, 50 open**.


## W88: native Alpine diagnostic suppression prerequisite

A09 advances to partial after guarded integration of the two reviewed diagnostic
fixture files. Five Python oracle tests and a 12.834-second non-root Alpine/musl
native run passed against the exact W84 daemon. The native fixture observed
401 accepted diagnostic events and 944 suppressions, a fresh nonzero summary
on subsequent admission, required metadata, bounded capture, and absence of
its private QUIT and preregistration PRIVMSG canaries. Independent review
verified all 1,255 candidate inputs, log hashes and terminal process/scratch
cleanup. Production diagnostic code is unchanged.

The counter delta is cumulative across delayed processing from burst attempts;
it does not establish an exact 128-per-window cap or attribute every event to
a single burst. Actual OpenRC logger delivery, syslog retention and authenticated
all-command redaction remain unproved. Evidence:
`.zig-cache/wave-88/actual-integration.json`,
`.zig-cache/wave-88/alpine-diagnostics-oracles-v1.json`, and
`.zig-cache/wave-88/alpine-diagnostics-budget-native-v1.json`.
Current inventory: **25 accepted, 24 partial, 49 open**.


## W85: retry fairness across upgrades accepted

T06 is accepted for the reviewed Linux composition (manifest `3b9339c638e2`,
1,257 inputs). A mandatory SRHC checkpoint envelope carries the optional orphan
retry cursor and unchanged SRSTv3 authority under the same capture/adopt cut.
Missing, old, duplicate and malformed families fail closed; staged adoption
restores both prior Store and cursor on failure. Exact capability checks reject
an incompatible successor before transfer. A cursor can validly name an absent
row: it is an ordering boundary, not current membership authority.

Independent review retained the existing exhaustive dirty/projection selector,
uncleared-failure rotation, retained-ciphertext queue and drain/refusal evidence.
The new native test passed in 7.176 seconds: seventeen orphan groups, persistent
failure of the earliest group, cursor boundaries eight and sixteen across two
real execs, natural wrap and recovery, live/foreign negative controls, retained
signed bytes, queue-admission allocation pressure and secured-peer convergence.
No cursor resets, tombstone pruning, queue resets or authority weakening were
used. Physical sockets/cookies and current mapped connection identity remained
consistent through legitimate numeric ID remapping.

The semantic gates passed 95 Debug and 95 Safe tests, each with one Windows-only
skip; Windows semantic checking passed. The exact composed production binary
then passed the ordinary secured A–B–C journey in 149.298 seconds: 55 accepted
events, 407 exact deliveries, four original TLS attachments through A then B
upgrades and a fifth resume on C. All A09/W87 changes were preserved.

Evidence: `.zig-cache/wave-85/actual-integration.json`,
`.zig-cache/wave-85/replica-cursor-two-exec-native-v4.json`, and
`.zig-cache/wave-85/replica-cursor-ordinary-three-node-v4.json`.
Scope is Linux actual exec and queue-admission allocation pressure, not Windows
runtime or saturated-kernel throughput. Full release validation remains pending.
Current inventory: **26 accepted, 23 partial, 49 open**.


## W89/W90: Alpine logging accepted and publication retries improved

A09 is accepted for pinned Alpine 3.24.3 x86_64 under KVM. The exact composed
binary and shipped OpenRC service ran as a nonroot account, with verified
stderr-pipe identity to the default error logger and BusyBox syslog. The final
25.144-second proof observed 200 accepted diagnostic events, 344 suppressions
and one fresh `daemon.err` summary, with the private canary absent. Deltas are
cumulative across the two bounded burst attempts, not an exact per-window
measurement. Typed accounting and bounded history precede sink admission;
OpenRC/syslog delivery does not assume journald. Existing W88 adversarial and
native privacy/budget evidence remains applicable. Scope does not certify
arbitrary operator retention policies or exhaustive command redaction.

The canonical tool is `tools/alpine_logger/driver.py`, with adjacent `guest.sh`.
It requires an explicitly supplied expected binary SHA-256 and rehashes the
source, copied and final artifact. This avoids a tracked-source binary-pinning
cycle as build metadata changes. The VM has no NIC, exposes only read-only
fixture input, and changes no host service. Guest config parent traversal and
preflight are checked under the actual runtime identity. Exact source manifest:
`b02d852a23a6`, 1,259 inputs.

T03 advances to partial. In the no-declared-cohort dirty-lease-retry path,
an already accepted local OFFER is reused only when its current authority,
attached session snapshot, inventory and expiry remain eligible. Genuine
mutation, renewal, expiry, signing change and withdrawal require the appropriate
new authority. Store bytes remain the source of truth; there is no new general
signature-validation cache. Ten fixed-cardinality reason counters distinguish
tracking-row creation, mutation/renewal/retry publication, reuse, lease acceptance,
retry attempts/completion, fanout and retained replay. They reset with the Core
image, including Helix, and never control authorization.

All 99 focused Debug and 99 Safe tests passed. The real secured-peer proof
passed in 5.196 seconds: the peer initially lacked the target OFFER, fanout and
lease allocation failed together, retry retained the same canonical OFFER,
and normal SEND/CQE processing delivered the exact OFFER and lease. Socket,
attachment, bearer and current physical identity remained stable. A local
accepted OFFER or lease alone is not proof of peer receipt. Cohort reuse,
account-SST and mesh-envelope counter completeness remain outside this slice.

Linux check/install, Windows semantic checking, full source formatting and the
final combined Alpine proof passed. Evidence:
`.zig-cache/wave-90/actual-integration.json`,
`.zig-cache/wave-89/actual-integration.json`,
`.zig-cache/wave-90/publication-focused-{debug-helper,safe}-v4.json`, and
`.zig-cache/wave-90/combined-alpine-openrc-logger-v4.json`.
Current inventory: **27 accepted, 23 partial, 48 open**. Full release gates,
Windows runtime and deployment remain pending.


## W94: offline legacy-rule audit integrated; P09 partial

The `cloak-audit` operator command accepts private ACCESS/SACCESS checkpoints
and explicit historical derivation witnesses. It verifies complete old literal
hosts before proposing current cloaks, preserves nick/ident scope and reports
ambiguous or unsupported evidence without guessing. Keys use exact 64-digit
hex inside the private witness file. Reports expose ordinal/classification only;
optional checkpoint output is private, create-only and detached from live policy.

ACCESS keeps issuer, absolute expiry, clocks, origin, tombstones and physical
order. SACCESS remains byte-identical and reports its unavailable metadata.
The CLI refuses symlink/hardlink, FIFO, broad-mode and non-private-parent inputs,
and cannot overwrite existing output. Report and output-write failures leave no
published artifact. This does not install policy or authorize mesh publication.

Evidence: 15 tests in each of Debug and Safe, Linux check/install, Windows
semantic compile, and 44 native child processes with independent metadata,
privacy, custody and failure-atomicity checks. Fresh independent review approved
these scopes and the exact integration: three changed files, five added files,
1,256 existing inputs preserved. Source manifest `32ead7fa4f09`, 1,264 named
inputs; `.zig-cache/wave-94/actual-integration.json` links the retained receipts.
Wrong-owner/sync-failure injection and hostile same-owner mutation are not
covered by the native campaign.

P09 remains partial: AKCK/WARD, relation-aware World lists and their enforcement
comparisons remain. No full-suite result exists for this promoted cut; the
ongoing W91 suite belongs to its older frozen baseline. No deployment occurred.
Inventory: **27 accepted, 24 partial, 47 open**.


## W97: AKICK/WARD offline audit integrated; P09 remains partial

The operator CLI now accepts `--kind akick` and `--kind ward` alongside ACCESS
and SACCESS. Verified replacements preserve issuer, absolute expiry, physical
precedence and checkpoint metadata; unsupported facets and missing provenance
remain explicit unchanged rows. No live application is performed.

The typed policy leaf passed 10 Debug and 10 Safe tests; the expanded CLI passed
16 in each mode, Linux build and Windows semantic checks. The original 44-case
native campaign passed on the new binary. Another 16-case native campaign
proved independent expected checkpoint bytes and actual AKICK/WARD matcher
behavior before, at and after expiry, including overlapping rules and unchanged
nick/ident scope. Source custody and create-only output refusal passed.

Independent reviews preceded guarded promotion: three changed files, four new
files, 1,261 other inputs preserved. The 1,268-input manifest is `192edd5cf8d3`;
`.zig-cache/wave-97/policy-actual-integration.json` links the evidence. World
relation-aware auditing and broader migration acceptance remain; P09 stays
partial. Inventory remains **27 accepted, 24 partial, 47 open**. Full release
and deployment are pending.


## W101: relation-preserving World audit integrated; P09 remains partial

The operator CLI now accepts `--kind world` for detached HWC2 images. An exact
baseline rebuild preserves physical memberships, same-nick distinct clients,
member modes and invited-only clients before any proposal is prepared. Verified
host replacements retain list setter/time and channel metadata; canonical
encoding may reorder masks while World’s any-match semantics stay unchanged.
Extended bans and missing witnesses remain explicit unchanged rows.

The World leaf passed 56 Debug and 56 Safe tests. The expanded CLI passed 66 in
each mode, Linux check/install and Windows semantic checks. All 71 native cases
passed on the World-enabled binary: 44 ACCESS/SACCESS, 16 AKICK/WARD and 11 World,
including correct-host/wrong-nick/ident negatives and mask-only undo to the exact
original relationship image. Fresh independent review approved the seven-file
promotion, preserving 1,265 other inputs. Manifest `c76b6fc103a9`, 1,272 inputs;
receipt `.zig-cache/wave-101/actual-world-integration.json`.

P09 remains partial while raw Services K1/W1/S1 records and their provenance
boundaries receive public audit coverage. This command does not apply live
policy or rewrite signed route facts. Inventory remains **27 accepted,
24 partial, 47 open**. No release or deployment is claimed.


## W102/W103: Core corrections and first green composed suite

The closing-session logical-handoff and cross-shard introduction defects are
corrected in the integrated source. Focused Debug and Safe each passed 153
tests, with no skips, failures or allocator leaks. The composed source manifest
`85deac57b1e52cea568e63eb542f86c7fc525ed63a180453d8ce46b801442c2d`
then passed the full Debug suite: **10,887 passed, 330 skipped, zero failed or
crashed**. The log hash, all 1,272 named input hashes/modes, and terminal
supervisor cleanup were verified; no GPA leak markers were present.

Receipts: `.zig-cache/wave-102/actual-core-production-integration.json` and
`.zig-cache/wave-103/full-debug-verification-v1.json`. This closes the original
nine baseline failures for this source cut. The private raw Services audit and
strict Alpine startup changes are excluded. Final release evidence and
multi-node acceptance remain outstanding; inventory stays **27 accepted,
24 partial, 47 open**. No deployment occurred.


## W107: raw Services audit integrated

The public detached audit now accepts `akick-record`, `ward-record` and
`saccess-record`, alongside the five checkpoint kinds. K1/S1 records retain
original bytes and report metadata gaps. A witnessed W1 substitution preserves
all other value bytes and explicitly reports required storage-key migration
and missing collection-order proof. No live Store edit is authorized.

Independent review approved the five-file delta, preserving 1,269 other
inputs. CLI Debug/Safe passed 67/67, durable leaf 7/7, Linux build and Windows
semantic checks passed, and all 25 updated native cases passed. Unchanged
71-case checkpoint compatibility evidence remains scoped to the shared
runtime contract. Receipt `.zig-cache/wave-107/actual-raw-durable-integration.json`;
manifest `2fec834e852a`, 1,274 inputs. The earlier full green suite belongs to
parent `85deac57`; a final composed full gate remains. P09 remains partial;
inventory remains 27 accepted, 24 partial, 47 open. No deployment occurred.


## W108: P09 detached migration audit accepted

Fresh independent review found no remaining audit-specific blocker on source
`2fec834e852a`. All eight input kinds are covered. Exact verified checkpoint
proposals preserve supplied issuer/expiry/order and World physical relations;
ambiguous opaque masks and raw metadata gaps remain unchanged and are reported.
Raw W1 value proposals explicitly require storage-key migration and collection
order proof, so they do not claim ready-to-apply collection migration.

This satisfies P09's migration **audit** requirement. Live Store application,
key reindexing and signed publication are separate work; adding them to P09's
closure would expand the agreed row. Closure review:
`.zig-cache/wave-108/p09-audit-row-closure.json`; implementation receipt:
`.zig-cache/wave-107/actual-raw-durable-integration.json`. This is scoped source
acceptance, not release, full-suite or deployment acceptance. Current inventory:
**28 accepted, 23 partial, 47 open**. Keep P09 closed absent relevant contradictory
evidence or changed dependencies.


## W109: shared capability help integrated

HELP lookup and bounded search now use the same 47 capability definitions as
live negotiation. The extraction preserves enum ordinals, names, values, policy
flags and ordering; per-client negotiation gates remain unchanged. Capability
help directs clients to CAP LS for actual connection availability. No second
capability catalog is maintained.

Independent review, 96 Debug and 96 Safe tests, and Linux/Windows semantic
checks passed. The guarded three-file promotion preserved 1,272 other inputs:
`.zig-cache/wave-109/actual-q02-cap-help-integration.json`, source manifest
`2e0e3e3dd1f7`. Q02 remains partial pending command-derived syntax, parsed examples
and client integration; no full-suite, release or deployment claim follows.
Current inventory remains 28 accepted, 23 partial, 47 open.


## W111: A04 Alpine package and strict identity startup accepted

The integrated package delegates credential validation to the daemon's typed,
read-only service-identity checker under the actual service account. Startup
uses that same retained config/identity snapshot and refuses missing or invalid
keys. Helix retains strict startup and only the environment bindings actually
resolved by config; reconfiguration swaps their owned snapshot transactionally.

Fresh signed APKs on Alpine 3.24.3 x86_64 passed installation/upgrade, trust
refusals, operator config/key byte and ownership/mode preservation, and OpenRC
start/status/stop. Real registered clients stayed connected through four Helix
self-execs using file, inline, environment and referenced-file credentials.
PID/start identity, both physical socket inodes, strict arguments, exact env
carry, one welcome and pre/post PONG were verified. Key, realm and env drift
refused with specific error classes while the predecessor kept serving clients;
ordinary exact source repair allowed the subsequent upgrade. Fourteen typed
credential refusals and the bounded positive identity-source probe passed.

Focused Debug/Safe: boot policy 11/11, identity 64/64, entrypoint 3/3, server
90/90. Linux musl builds and Windows/OpenBSD semantic checks passed. Native
client captures, artifact/log hashes and terminal cleanup were independently
verified in `.zig-cache/wave-110/alpine-native-verification-v14.json`.
Guarded integration: `.zig-cache/wave-111/actual-foundation-integration.json`;
source `d1f36eb323a0`, 1,287 inputs, preserving 1,269 existing inputs.

This accepts A04 for that source/platform scope. The final composed full Debug
gate is running; production trust distribution, release and multi-node
deployment acceptance remain separate. Current inventory: **29 accepted,
22 partial, 47 open**. No deployment occurred.


## W111 completion: integrated foundation full Debug green

The full suite completed on the integrated foundation: **10,893 passed of
11,223 total, 330 platform skips, zero failures or crashes**. All 1,287 named
input hashes/modes match both the actual worktree and frozen run context. The
log hash and terminal supervisor cleanup match, and no GPA leak markers were
present. Receipt `.zig-cache/wave-111/foundation-full-debug-v1.json`; independent
verification `.zig-cache/wave-111/foundation-full-verification-v1.json`.
This supersedes the earlier parent-only full result for foundation source
`d1f36eb323a0`; preserve both records and do not repeat this unchanged cut.

Future media expiry and ACCESS EXPLAIN candidates are excluded. Reproducible
release artifacts, full release acceptance and deployment remain separate;
inventory remains 29 accepted, 22 partial, 47 open. Nothing was deployed.


Q04 now has integrated, read-only `ACCESS <#channel> EXPLAIN [nick]` for
existing-channel direct JOIN policy. Debug discovery and Safe228 cover policy,
privacy and labeled replies; a native TLS campaign passed21 checks with four
held clients, plus Linux musl build and Windows/OpenBSD semantic checks.
Actual manifest: `.zig-cache/actual-source-after-q04-explain.json`
(`9e4435be`). This remains partial: other permission operations are not covered,
legacy SACCESS expiry is unknown, and forwarding/clone outcomes are conditional.
The parent full suite10893/330/0 belongs to foundation `d1f36eb3`; it does not
certify this later composition. Current inventory: **29 accepted,23 partial,
46 open**. No deployment occurred. Integration evidence:
`.zig-cache/wave-117/actual-q04-explain-integration.json`.


V06 is partial after integration of the reviewed bounded retransmission-age
policy. Cache lookup, queued dequeue and pre-send paths reject expired or
unknown-age packets under a strict1000ms awake-time ceiling. Retained duplicate
sequence replacement preserves its original deadline. Debug90 and Safe132 with
one Windows-only skip pass; composed Linux musl and Windows builds and OpenBSD
checks pass. Actual manifest `.zig-cache/actual-source-after-media-age.json`.
Codec-aware jitter/FEC coordination, native Windows mixed-version refusal and
exact retained-handle/cache proof remain incomplete. This is not full V06 or
release acceptance. Current counts:29 accepted,24 partial,45 open. No deployment.


T05 is partial after integration of the bounded signature-only OFFER memo for
legacy and current inventory offers. Exact signed bytes, full public key,
cohort epoch/roster digest and expiry bind each entry. Existing current-peer,
issuer, Store lifetime/revocation/quarantine checks remain mandatory on hits.
Process-local saturating work counters are owner-serialized observations, cold
and wiped with the memo, and excluded from checkpoint authority. Final composed
Debug102 and stats Safe89 pass, backed by server Safe97 and inventory Safe88.
Native receiver observation, throughput measurement and public metrics wiring
remain incomplete. Actual manifest `2c2432ce` matches the running full121 gate;
that gate is not yet accepted. Current counts:29 accepted,25 partial,44 open.
No deployment occurred.


T05 is accepted for the recorded Linux signed-OFFER implementation after
requirement-by-requirement audit in `.zig-cache/wave-128/t05-row-closure-v1.json`.
The full signed transcript, signature, public key and current cohort epoch/roster
bind the four-slot hint; current authenticated peer and issuer authorization is
rechecked before each use, and lifetime/revocation/quarantine remain mandatory
on hits. Focused Debug/Safe and allocation-failure controls pass. A fresh
canonical Claude security review traced all three scoped source files and
returned no findings. The current ordinary daemon also passed secured A-B-C,
A then B same-PID upgrades, four held TLS attachments and a fifth resume on C,
with55 accepted events and407 exact deliveries. Source/artifact/log/cleanup
were verified. Separate direct-leaf measurements confirm counter-observed
cache reuse and equal Store state. Public cache metrics and broader throughput
measurements are not claimed. Other credential domains remain uncached rather
than sharing replay or authorization decisions. Full release and native Windows
acceptance remain separate. Inventory: **30 accepted,24 partial,44 open**.

### W12: existing foreground maintenance integrated

W12 is partial after guarded integration of the existing-runtime maintenance
wizard and the ISUPPORT line-budget correction. The 13-file source promotion
preserved the other 1,284 inputs and matches the 1,297-input candidate manifest
`53572ce82150d35abd4bb7aa9411b4c0e5e3e1bc39f1245a68fcc6f6c679f63f`.
The wizard requires an exact review ID, revalidates inputs, checks backup age
and private restore evidence, retains recovery references, and reports action
custody separately from application readiness. Dynamic compatibility remains
the running daemon's final decision.

Focused maintenance Debug/Safe and grammar checks, ISUPPORT Debug94/Safe94,
Linux musl Safe build, Windows/OpenBSD compile checks, independent source
reviews, and ten helper controls support this slice. The final native campaign
passed ten checks across two existing same-user Linux foreground runtimes:
successful same-PID exec and a realm-change refusal, with four original TLS
connections retaining both client-side and exact server-side socket identities
and responding afterward. Recovery artifact hashes, journal checksum, backup
and restore-drill witnesses were checked. The TLS listener may be recreated;
the IRC listener and established client sockets are separately witnessed.

Earlier failed campaigns remain recorded: a real oversized ISUPPORT reply was
corrected; an inherited 4 MiB fixture limit was replaced by a bounded 64 MiB
wizard limit with artifact-size rejection; the socket witness now distinguishes
listener replacement from attachment loss and has negative controls. No failure
was converted into a pass by removing client-custody or wire-budget assertions.

Evidence: `.zig-cache/wave-131/actual-integration-v1.json`,
`maintenance-native-verification-v3.json`, and
`maintenance-helper-controls-v4-parent-verification.json` in that directory.
The [setup guide](../guide/setup.md#maintenance-for-an-existing-foreground-runtime)
describes supported use. Supervisor-managed services, other-user runtimes,
environment profiles, other platforms, full-install restore and automatic
rollback remain unfinished. This is source integration, not a full release or
deployment. Inventory: **30 accepted,25 partial,43 open**.

## Muse continuation 2026-10-31 — waves 1–10 evidence

Twenty-five bounded slices were integrated on the uncommitted tree and both
full suites pass on the host: Debug and ReleaseSafe each **10,996 passed,
330 skipped, 0 failed** of 11,326 (`zig build test`, exit 0; logs
`.zig-cache/full-debug-muse5.log`, `.zig-cache/full-safe-muse2.log`).
No status below is promoted: full acceptance still requires the native,
client, or distinct-host evidence named in each row.

- CAPACITY (mesh trust pins): 32 configured roots were silently truncated
  to 16 at three layers. Pins are now 4096-capped, allocator-owned, and
  fail-closed on duplicate/overflow in the leaf and both daemon builders.
- Q02: every help topic's usage line parse-tested (42 parse; SACCESS and
  WEBAUTHN exempt with pinned TooManyParams reason). Derivation from live
  dispatch and client palette remain open.
- E06: checkpoint audit now fail-closed secret-scans CURRENT and history
  (19 Python tests; live audit clean). Process criteria remain partial.
- T03: SessionStore counters separate required portable-token rotation
  from suppressed duplicate publications; rendered as Prometheus gauges.
  Attachment-lane and lifecycle paths are not instrumented.
- T10: tombstone tests prove revoke-before-stale-upsert cannot resurrect,
  the cap fails closed without eviction, and TTL needs both clocks.
  Mesh anti-entropy wiring remains the open half.
- V03: SDP gains opus/vp8 tags with PT 111/96; daemon bridge maps them,
  and RTP→native forwarding refuses gateway payloads without a negotiated
  cadence counterpart (no mislabeling/transcoding). Browser proof open.
- V05: PriorityPacer (audio > control > video, bounded video debt) is
  wired at media admission; FIFO ordinal custody unchanged.
- V06: RecoveryPolicy gates cached-retransmit serving; late packets are
  dropped and counted. Jitter input is the named 1000 ms cap today.
- C07: per-SSRC FIR/PLI budget (4/1000 ms, 8 SSRCs, fail-closed) wired in
  both feedback branches; dropped count is a Prometheus gauge.
- Q08: doctor JSON exports a fixed 8-name local-config capability summary
  (peer-live explicitly false) and bounded diagnostics with canary-secret
  absence tests. Live peer capabilities remain open.
- P08/Q01: `ACCESS PREVIEW` is live behind the channel-manage gate using
  the production matcher; replies state cloak/precedence are not
  evaluated. Denial help topics carry conditional next-step lines.
- Q07: config field classification plus `--check-config --against`
  preview (field names and classes only, never values; unclassified
  fields explicitly not counted).
- M02: periodic anti-entropy re-burst uses adaptive per-connection
  backoff toward a 60 s bound; first periodic burst per connection and
  stale peers are never gated (GAP-A11 preserved).
- M04: mesh_topology gains caller-supplied link cost with hysteresis
  (default cost = hop distance, so current behavior is identical until a
  measured-cost caller exists). Cross-snapshot flap needs prior-selection
  input when such a caller lands.
- Q06: hourly issuer-only ACCESS EXPIRY reminders from the pure
  expirySweep leaf; first maintenance turn only arms the cadence.

Full-suite fixes en route: bridge codec ordinal conversion (with a
compile-time assert), per-connection M02 gate, deterministic pacer test,
squit fixture pin-slice initialization, and the Q06 first-tick arm.
Inventory remains **30 accepted, 25 partial, 43 open**.
