# Roadmap acceptance inventory

This living work queue preserves all 98 numbered requirements from the
[integrated roadmap](../ROADMAP-2026-10-26.md). The table carries the last
reviewed status and full acceptance criterion unchanged: **30 accepted,
25 partial, 43 open**. Documentation cleanup does not close an open item or
extend a recorded witness to a new source, platform or deployment.

**Accepted** means the criterion was proved for its recorded source/platform;
**partial** means narrower related work was proved; **open** means complete
acceptance has not been established. The source and tests remain authoritative.
Client implementation and external platforms require their own evidence.

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


## Current implementation and verification entry points

| Requirement area | Canonical documentation |
| --- | --- |
| Privacy, identities and rule migration | [Cloaking](../reference/host-cloaking.md), [operators](../guide/operators.md), [credential domains](../reference/credential-domains.md) |
| Setup and maintenance | [Setup](../guide/setup.md), [diagnostics](../guide/diagnostics.md), [service management](../guide/service-management.md) |
| Sessions and mesh | [Mesh](../guide/mesh.md), [Helix](../guide/upgrade.md), [commands](../reference/commands/accounts-services.md) |
| Media and client contract | [Media architecture](../architecture/03-media.md), [media commands](../reference/commands/media.md) |
| Alpine, packaging and recovery | [Alpine](../guide/alpine.md), [persistence](../guide/persistence.md), [packaging](../../packaging/README.md) |
| Development and gates | [Build](../guide/build.md), [testing](../guide/testing.md), [release runbook](../RUNBOOK.md) |

The retired wave diaries and status progression remain in the exact
[pre-cleanup ledger](https://github.com/devinkbrown/onyx-server/blob/3fa6e95021601c92d2a2b68869d8fa9f4047d391/docs/ops/roadmap-acceptance-ledger-2026-10-26.md)
and its linked source/evidence at that Git revision. They are provenance,
not instructions to resume an obsolete job or rerun an unchanged gate. The
[2026-11-03 release audit](../audit/release-and-test-speed-2026-11-03.md)
is the current daemon/service-kit/test-speed closeout; it does not claim every
roadmap requirement was completed.

## Changing a status

Bind new evidence to the exact input source, target, compiler, command and test
inventory. Record the complete criterion, negative controls and unresolved scope,
then obtain fresh independent review before changing its row. A codec unit test
does not establish live multi-node behavior; a planned fixture does not establish
native runtime acceptance. Preserve skipped/platform exclusions and existing
partial/open boundaries. Release and deployment acceptance remain separate gates.
