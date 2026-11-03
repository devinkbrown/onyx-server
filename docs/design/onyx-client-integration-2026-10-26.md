# Onyx client integration change outline

Requirements baseline: 2026-10-26; reviewed for scope on 2026-11-03. Proposed
client work, not a statement of deployed client behavior. Companion to the
[integrated delivery roadmap](../ROADMAP-2026-10-26.md)

This outlines the client changes needed to deliver the requested quality of
life, privacy, setup, session, voice/video, throughput, and mesh improvements.
Client source has not been inspected in this repository. Items describe the
desired behavior and integration contracts, not an assertion that an existing
client lacks a feature. No client repository is changed by this document.

The [next wizard and client wave](https://github.com/devinkbrown/onyx-server/blob/3fa6e95021601c92d2a2b68869d8fa9f4047d391/docs/design/wizard-client-next-wave-2026-10-27.md) turns
setup, recovery, accessibility, media readiness, and host-change continuity into
concrete user flows and acceptance criteria. These remain proposed client work.

## Implemented server candidates to integrate first

The integrated offline `cloak-audit` command is an operator tool. Client-facing
operator UI must keep witness keys and addresses in private local files, show
only redacted audit classifications by default, and distinguish a proposed
checkpoint from applied policy. Missing historical provenance and SACCESS
metadata gaps must remain visible. An audit result does not authorize a client
to rewrite bans, grants or signed mesh facts. ACCESS/SACCESS/AKICK/WARD and relation-aware World lists are implemented
for offline checkpoint audit. Raw Services records and client runtime
integration remain pending.


At the 2026-10-28 source cut, local guest-binding preparation and explicit
offline issuer provisioning are integrated server operations. Linux upgrade
carry is now accepted for the T02 journey described below; expanded guest
namespace publication remains pending. Clients must enable features through actual
negotiation and use authoritative account/session identities rather than
rotating public hosts as stable identifiers. The migration-token optimization
preserves complete encoded frames, so its performance improvement requires no
client token-schema migration. Client runtime acceptance remains outstanding.

The integrated ISUPPORT correction splits the complete `005` inventory across
multiple replies at registration and after `VERSION`. Client parsers must merge
all of those replies for the connection, preserve token values, and accept
repeated inventories without duplicating controls. Decode ISUPPORT value
escapes before displaying network names or using advertised URLs; a decoded
space belongs to its value and does not create another token. Do not assume one reply or
one socket read contains the full inventory. Keep this information separate
from negotiated `CAP` state. The server correction passes focused Debug and Safe
tests for maximum-length registration, actual VERSION output, lossless token
order, and escaped values. The Linux mixed-version native journey also verifies
a spaced network name on the new image, registration and VERSION decoding, and
five retained TLS attachments through an actual upgrade. This is scoped runtime
evidence; full release and client runtime acceptance remain pending. Client
acceptance must include fragmented and
coalesced reads, multiple `005` lines, repeated VERSION requests, and a fresh
connection whose inventory differs from the previous connection.

The accepted bounded session-offer validation memo is internal to the server.
It changes neither client credential encoding nor resume/revocation authority.
Clients should retain valid reusable credentials through supported upgrades
and continue to honor authoritative revocation and expiry responses. A faster
server validation path does not permit the client to reuse another credential
type or infer that a previously accepted credential remains authorized.

Operator interfaces can consume the shared `service_environment` observations
from setup and doctor. Present manager-marker evidence and explicit unknown
states separately from daemon, mesh and media readiness; retain the operator's
explicit service choice when automatic guidance is ambiguous.

The [session-control supplement](../reference/protocol/onyx-session-control.v1.json)
records the candidate wire contract for `SESSION LIST MESH` and
`SESSION REVOKE group=<id>`. It distinguishes logical group IDs, physical
attachment IDs, local DROP SIDs and bearer credentials. The device view must
keep these types distinct, show unknown/partial observations honestly, and
retain a monotonic pending-revocation state until the server confirms complete
roster receipts. Selecting the current logical group can disconnect the client;
status can be reacquired from another authenticated attachment. Publishing
inventory does not grant portable resume authority. A device appearing in this
view does not establish that a certificate or raw local credential can restore
it on another node; portable authority requires the explicit token or verified
source promotion workflow. The pagination candidate returns bounded pages
and opaque continuation nonces: continue even after a zero-row incomplete
page, display the page observation time, and restart on `STALE_LIST`. An end
page does not establish atomic global freshness or completed revocation.
Lost-reply retries retain the original page observation and receive the current
command label. Pagination integration acceptance is still pending, so this
candidate is not scale-accepted.

The server also has [setup and bundle workflows](../guide/setup.md) and
[redacted JSON diagnostics](../guide/diagnostics.md). A client/operator interface
should consume their explicit settings, checks and unknown-readiness states,
instead of parsing colored presentation or treating a process check as a
successful voice/video connection. Diagnostic `report_build_version` identifies
the reporting binary, and missing numeric observations remain unknown; neither
field proves the remote endpoint's version or client participation. Generated self-signed material needs an
explicit trust/pinning journey; it is not public-CA enrollment.

The reviewed Linux setup changes integrated on 2026-10-29 give operator
interfaces a typed `effective_profile` and an explicit comparison baseline.
Show the resulting values after overrides; do not substitute static profile
defaults. Existing-network purpose validates and reviews the supplied
configuration without enrollment or network contact. Preserve that distinction
in the client, and leave configuration and secret material unchanged on
back, cancellation, or validation failure. W01 acceptance covers the server
workflow, not an implemented client screen.

The integrated `service_plan` is shared by setup and doctor. Render the
selected template's `start_argv` and `preflight_argv` as argument arrays, with
its executable/config paths, runtime identity, working directory, restart and
logging guidance. Keep the separate container template visible. These are
shipped template facts: `host_paths`, `runtime_identity_access`,
`manager_status`, `daemon_readiness`, `network_reachability` and
`resource_ceilings` explicitly remain unknown until separately verified.
Interactive setup reviews this plan before completion; headless material
acknowledgement covers identity material and the final JSON includes the plan.
Client tooling must not treat that acknowledgement as service installation
or a running supervisor. W10 accepts the Linux planning contract; A05 live
service acceptance remains partial.

The terminal wizard now provides textual stages, complete help/search, wrapped
review and a sequential `--linear` interface without ANSI or cursor controls.
Interactive support starts at 20 columns; narrower or redirected contexts have
a headless alternative. Client interfaces should consume JSON rather than
parse terminal styling. W02 acceptance covers the reviewed Linux artifact;
particular screen-reader software/hardware remains unverified, and legacy
preinteraction/emergency diagnostics can exceed terminal width.

The shared network/media assessments are now an integrated, reviewed Linux
setup contract. Present the configured hostname, addresses, IRC/TLS and media
ports, advertised host, STUN and WebSocket settings alongside the explicit
unknown operational checks. Configuration alone does not prove DNS resolution,
address ownership, port availability, public reachability, relay operation or a
working call. Cancellation and configuration review must preserve the source
and private material. Both generated and existing configurations follow this
contract; native acceptance includes their pre-completion review paths.

The accepted privacy corpus distinguishes permitted self/operator WHOIS
address fields from ordinary observers: self338 and the exact self320
`actual address` note are deliberate visibility, not a channel event.
Client diagnostics and shared exports should preserve that distinction.
Never broadcast those privileged replies or private media credentials when
rendering ordinary participant or event views.

Moderation continuity is now accepted across online/offline cloak rotation
and both mesh nodes for the recorded policy surfaces. Keep nick/ident/address
scope and rule expiry visible; do not rewrite rules merely because a cloak
changes. The server now evaluates ACCESS expiry at each authorization read,
so a stale client-side preview cannot grant permission after its deadline.
SACCESS duration metadata still lacks deadline enforcement; do not display it
as a guaranteed timed restriction until the Q06 server contract is implemented.

Maintenance interfaces must honor the server's mandatory host-provenance
compatibility checks. Supported generated hosts are repaired transactionally
behind previously accepted output. An image whose historical intent cannot be
proved refuses the upgrade before exec and retains the source connections.
Surface that incompatibility rather than automatically choosing a cold restart.
This is server upgrade evidence, not deployment or client-runtime acceptance.

Doctor now exposes `established_links` and retains the legacy nullable
`secured_links` field as unknown instead of deriving security from that count.
The established-link counter also counts plaintext links. A client health view
must retain unknown security, freshness and service readiness until it receives
distinct authoritative observations. The complete reactor-safe operator status
view is still pending daemon integration; the local doctor fixture does not
prove live peer health or remote endpoint identity.

The integrated ordinary operator `MESH` view now consumes one owned published
snapshot across reactor shards. Present its freshness separately from TCP,
established links, secured/plaintext transport and negotiated session
capabilities. First-publication unknown and retained-stale results are explicit;
a failed refresh is not an empty healthy topology. Service readiness remains
distinct from a connected link. Existing detailed health rows and privileged
subcommands remain available. M01 acceptance includes real nonzero-shard
operator readers; mesh connections themselves remain owned by reactor0.

Headless material publication now requires `--bundle <target> --json
--review-stdin`. Read the first compact JSON review line, inspect the actual
identity, certificate and storage facts, and retain that review before sending
`{"action":"publish","review_id":"<current review_id>"}`. Cancellation
uses the same invocation's review ID and `"action":"cancel"`. Successful
publication returns the ordinary final JSON plan; ordinary previews retain
their existing JSON interface. The ID is public process-local correlation,
not a session or authentication credential, and cannot approve another process.

Distinguish precommit cancellation from result-output failure after successful
publication. The latter exits nonzero while preserving the reviewed bundle;
inspect the destination against the retained review before retrying. Do not
remove existing identity material as an automatic recovery step. Linux native
acceptance covers both blocked-output phases, tampering and replay rejection,
TLS and account setup. This is an integrated server CLI contract; a client
implementation remains proposed.

The [credential-domain reference](../reference/credential-domains.md) records
issuer, scope, expiry units and replay boundaries for the audited server paths.
Current SRM1 credentials support reuse within their TTL. SRM2 recovery UI must
follow the live restore/redirect path; codec countersignature and consume tests
do not establish an active client confirmation workflow. The reference keeps
its remaining credential families and policy gaps explicit.

Mapped IPv6 operands in operator commands must use proper IRC parameter
encoding: the wire form `UNREJECT :::ffff:198.51.100.153` supplies the address
`::ffff:198.51.100.153` to the server after the trailing-parameter marker is
removed. Prefer a structured command encoder over concatenating user input.
Current server acceptance covers equal direct/PROXY clone and reputation
policy, including hexadecimal and dotted mapped UNREJECT recovery. Existing
raw mapped-IPv6 reputation checkpoint rows are not automatically migrated.

Windows daemon compilation now rejects the Linux-only staged permission-review
path explicitly with `SetupPermissionReviewUnavailable`. Operator interfaces
must not display Unix mode bits or claim ACL verification from Windows file
attributes. This does not provide a Windows transactional setup bundle.

The integrated media routing controls coalesce keyframe work and bound NACK
retransmissions per physical source and publisher. Clients should coalesce
repeated recovery requests and tolerate a request producing no immediate
response; control transport activity does not prove a recovered frame. The
current implementation normalizes bounded multi-action RTCP and multi-target
FIR into target-specific packets. Quotas can admit only part of a request;
RR/TWCC members are forwarded separately, changing compound packaging/order.
Full browser/DTLS/SRTP interoperability remains unverified. Do not present fixed packet-count limits as negotiated throughput,
decoder protection or a seamless active-call upgrade promise.

## Delivery handoff by roadmap wave

Use the [complete R0–R6 assignment](../ROADMAP-2026-10-26.md#complete-delivery-assignment)
for completion scope. The client maintainer receives a sealed server contract
and fixtures before enabling each capability. No client source cut is available
in this repository; the following handoffs are specified, not client acceptance.

| Wave | Client delivery and roadmap IDs | Contract fixtures and compatibility checks |
| --- | --- | --- |
| R0 | Quiet host continuity and privacy-safe identity, P01–P06/P10 | CHGHOST retains one participant/conversation; old/current cloak forms are presentation, never authorization IDs; redacted WHOIS/events/exports. |
| R1 | Accessible full-color setup/review, W01–W11 | Typed plan/check/unknown facts, private resume, cancel/EOF, NO_COLOR/headless equivalence, rejected config and unavailable enrollment/media. |
| R2 | Privacy/moderation preview and dependable recovery, P07–P08, Q01–Q06/Q08–Q10, T02–T10 | Capability-gated errors and session control; logical group versus physical attachment versus bearer credential; stale/partial pagination, revoke pending/complete, reconnect/replay and unsupported-server behavior. |
| R3 | Soundcheck, voice and device controls, V01–V08/V10–V12 | Authoritative room permission and local device state, actual audible flow, codec/transport negotiation, mute/deafen, device loss, audience removal and opt-in recording/caption limits. |
| R4 | Camera/screen layouts and adaptation, C01–C12 | Consent before publish, subscription intent, real payload/feedback compatibility, slow receivers, background pause, keyframe limits, encryption and recording labels. |
| R5 | Recovering mesh and understandable health, M01–M08/M11–M12 | Secured-link versus TCP facts, bounded retry/backpressure, stable origin/event deduplication, route repair and loss of a media path without false success. |
| R6 | Maintenance and upgrade experience, W12/Q07/V09/M10/A07/A10 | Impact preview, drafts/read markers retained, every attachment participates after sequential upgrades, explicit incompatibility/rollback and media recovery boundaries. |

Each handoff names the client owner and repository/source revision, the server
source/artifact, negotiated schemas/capabilities, representative encoded fixtures,
old/new unsupported cases, and actual runtime results. Client and server reviewers
must agree on enum/state transitions and bounds. UI controls stay unavailable
when authority or transport support is absent. Server-only fixtures cannot certify
browser capture, native device behavior, accessibility or client token storage.

## Shared contracts before screens

| Contract | Server responsibility | Client responsibility |
| --- | --- | --- |
| Capabilities and limits | Advertise actual supported operations, negotiated transport, bounds, and versioned payload schemas. | Enable controls from negotiated support; handle older peers and unsupported features explicitly. |
| Identity | Keep address, public host, account, persona, session, and attachment authority distinct. | Present a stable account/device identity without using host strings as user IDs. |
| Permission decisions | Authorize each command and supply bounded reason codes where safe. | Explain failures and previews; never infer permission from a visible role badge alone. |
| Configuration plans | Use the same validator, defaults, and diff model as startup. | Render reviewable plans; keep dangerous application separate from editing and preview. |
| Session lifecycle | Preserve reusable local tokens and independent attachments; provide scoped recovery/revocation semantics. | Store credentials securely, recover deterministically, and avoid unnecessary reissue or duplicate attachments. |
| Event delivery | Stable message identity, accepted ordering metadata, explicit retry/replay boundaries. | Deduplicate by event identity and preserve drafts/scroll position during replay. |
| Media state | Authoritative room membership, publication, audience, negotiated profiles, and route status. | Keep permission, device, signaling, media flow, and render states distinct. |
| Diagnostics | Redacted structured facts and bounded trace exports. | Give useful explanations with an explicit inspect/export flow and sensitive-field exclusion. |

Prefer a generated or validated contract fixture shared by server tests and
client tests. Proposed new operation or capability names require a protocol
design before use; this document does not reserve wire names.

## 1. First-run and setup experience

- Offer connect to an existing Onyx network, recover an account/session, or
  configure an owned server. Do not mix account creation with server ownership.
- Reuse the server wizard's profile labels, validation explanations, port/media
  assessment, and plan review when displaying an operator setup interface.
- Build a progressive full-color experience with visible progress, back,
  contextual help, accessible focus order, reduced motion, and high contrast.
- Preserve a resumable private draft without embedding credentials in URLs,
  browser history, analytics, or ordinary exported settings.
- Explain certificate, identity, and trust failures with a specific safe next
  step. Do not make disabling TLS validation the normal recovery workflow.
- Finish with verified connection, account state, optional soundcheck, and a
  clear distinction between working chat and working media.

**Acceptance:** a novice can complete the supported path, leave and return,
correct a validation error, and understand the resulting connection without a
raw-command reference. Keyboard and assistive paths have equal functionality.

## 2. Privacy and identity controls

- Show the public identity as a preview, with account/persona state and a short
  explanation of anonymous rotation. Avoid alarming host-change popups.
- Group a routine CHGHOST with the existing participant identity; do not create
  another user, reset conversation history, or emit a false disconnect.
- Explain that account cloaks reveal account continuity and anonymous cloak
  rotation does not erase a nickname or an observer's existing knowledge.
- Let users inspect what authorized roles can see. Never request or display
  other users' real addresses merely to explain a cloak.
- Keep account settings, persona selection, and network/account trust separate
  from cosmetic display-name editing.
- Add a privacy check before sharing a diagnostic bundle, screen, recording,
  invitation, or account/device information.

**Acceptance:** cloak rotation and login do not corrupt participant identity;
ordinary UI and exports contain no unauthorized address/certificate/token data.

## 3. Session tokens, devices, and recovery

- Provide a device/session view with account, device label, current attachment,
  last activity, and explicit revoke-this-device versus revoke-this-session.
- Preserve a valid local token across reconnect and sequential upgrades; token
  rotation is a protocol event with a reason, not a generic retry strategy.
- Store bearer credentials using the platform's appropriate protected storage
  and lifecycle. Never log tokens or place them in navigation/query strings.
- Coordinate tabs/windows so retries do not create uncontrolled credential or
  attachment churn. Do not collapse intentionally independent attachments.
- Model reconnect as offline, retrying, authenticating, restoring state, then
  ready. A connected socket does not establish recovered membership or history.
- Preserve drafts, selected channel, read markers, and pending-send identity.
  Reconcile acknowledged sends before retrying them.
- Explain expired, revoked, wrong-network, incompatible, and temporarily
  unavailable credentials separately without leaking account existence.
- Give a verified recovery flow with a clear scope and revocation consequence.
- Keep an entered password-reset code in protected transient state after an
  invalid-password or temporary admission failure. Clear it after server
  success, expiry or cancellation; never put it in draft history or logs.
  Storage-recovery failures require the server's recovery path; repeated client
  submissions cannot repair poisoned storage.
- Confirm recovery-code deletion and push-subscription changes only after the
  server acknowledges accepted persistence. On failure, preserve the prior UI
  state and offer a bounded retry instead of claiming that access was revoked.
  Keep push endpoints, authorization secrets and malformed stored state out of
  user-facing diagnostics.

**Acceptance:** four attachments remain independently usable through rolling
server upgrades; a fifth can resume at another node; accepted messages appear
once; a revoked device cannot return through stale local state.

## 4. Messaging and everyday usability

- Searchable command palette and contextual help using server capabilities.
- Channel creation and moderation presets with an understandable resulting
  permission view, expiry, and access scope.
- Draft persistence, explicit send status, replay-safe outbox, and clear
  temporary-failure recovery without duplicate messages.
- A consistent notification center separating direct mentions, system health,
  permission requests, and optional operator events.
- Quiet routine maintenance and automatic recovery, with details available on
  demand instead of repeated connection banners.
- Explain failed joins or sends with an actionable safe remedy and the
  permission data the server allows the user to see.
- Keyboard navigation, screen-reader descriptions, localization, readable
  timestamps, reduced motion, and configurable density.
- Efficient history navigation, stable scroll anchors, search progress, and
  cancellation of work no longer relevant to the visible view.

**Acceptance:** long history, many channels, frequent presence changes, and
reconnect replay do not freeze the interface or lose the user's place.

## 5. Voice: one coherent call experience

- Pre-call microphone/output/permission/level soundcheck shared with setup.
- Distinct joining, authorized, connecting, audible, muted, deafened, and
  recovering states; show the difference between local and enforced mute.
- Device selection and switching without leaving the room, including unplug,
  permission revocation, sleep/wake, and headset/audio-focus changes.
- Push-to-talk, accessible mute/deafen controls, speaking indication, and
  stage/request-to-speak UI driven by authoritative room permissions.
- A live quality explanation distinguishing local microphone/device issues,
  receiver overload, loss, jitter, bandwidth, and relay fallback.
- Automatic safe quality adjustment and a deliberate audio-only fallback.
- Invitation, private-room, audience-change, and participant-removal feedback
  that agrees with actual forwarding permissions.
- Consent-based captions and recording controls only when the required
  processing and retention contracts are supported.

**Acceptance:** a user knows whether they can be heard, by whom, and why a call
is degraded; native/browser calls recover from supported route/device changes
without ghost participants or unauthorized delivery.

## 6. Video and screen sharing

- Private local preview and explicit camera/screen publication consent.
- Camera and screen sources are separate tracks with clear ownership and
  stop indicators; source changes retire old publication state.
- Grid, active-speaker, presentation, pinned-track, and audio-only layouts.
- Translate viewport and layout into subscription intent where negotiated, so
  hidden tiles do not demand full-resolution streams.
- Show adaptive quality, bandwidth limits, and battery/data-saving settings
  without exposing implementation jargon as a normal call control.
- Prioritize readable shared text separately from camera motion; provide a
  clear indication when a constrained connection changes quality.
- Bound decode/render queues and discard obsolete video work; retain audio
  responsiveness and keyboard controls under video overload.
- Label transport encryption, server-visible media, and supported E2EE
  accurately; never imply an encrypted connection is end-to-end encryption.
- Recording indicators and audience changes remain visible in every layout.

**Acceptance:** multiple publishers, source switches, slow receivers, loss,
backgrounding, and supported server upgrades preserve privacy and bounded cost.

## 7. Mesh visibility and operator integration

- Present healthy service, degraded service, recovering service, and partition
  accurately. A green socket icon must not imply a converged secured mesh.
- Give ordinary users a concise service explanation; keep topology, identities,
  keys, and privileged incident details behind server authorization.
- Add an operator workspace for node readiness, secured links, repair queues,
  capacity, media pressure, configuration drift, and supported upgrade plans.
- Reuse server-side operation plans for config previews, moderation impact,
  maintenance drain, rollback, and network rehearsal.
- Distinguish measured live facts from predictions and incomplete checks.
- Render redacted diagnostics with timestamps, bounded history, and explicit
  export controls. Exported secrets are never an ordinary troubleshooting step.
- When connected to an Alpine host, use the server's detected OpenRC/container/
  foreground adapter. The client must not run ad hoc shell commands itself.

**Acceptance:** the same incident has consistent status and reason codes in
the client, terminal wizard, and doctor; a prediction cannot silently execute a
production action.

## 8. Throughput, CPU, memory, bandwidth, and AI efficiency

- Establish rendering and interaction budgets on representative low-end and
  mobile hardware, with named device/browser versions in evidence.
- Virtualize long message/member lists without breaking search, focus,
  selection, scroll anchors, or assistive use.
- Batch compatible state updates with bounded wait time; prioritize input,
  audio controls, and visible message delivery over background reconciliation.
- Move expensive permitted crypto/media work off the main interaction path
  using the appropriate platform facilities; preserve secure key ownership.
- Deduplicate subscriptions, cancel obsolete requests, and bound every replay,
  pending-send, thumbnail, decode, and diagnostic queue.
- Reuse immutable state and exact token/attachment indexes rather than
  rescanning every channel and account on a small update.
- Subscribe to media quality appropriate to the visible layout and user
  settings, with explicit behavior for background tabs and battery constraints.
- Measure server/client costs together: bytes accepted, bytes forwarded,
  rendered deliveries, CPU, memory, and p95/p99 latency at equal useful quality.
- If AI assistance is offered, scope context to selected authorized content,
  use compact structured summaries and reuse non-sensitive context where
  supported, bound output, support cancellation, and show cost/consent clearly.
- Treat client AI as optional and separately authorized. The server roadmap
  does not authorize uploading messages, audio, video, or credentials to a model.

**Acceptance:** efficiency gains improve useful throughput and responsiveness,
with no weakened encryption, lost history, hidden media degradation, or
unconsented disclosure. Publish before/after evidence, not estimated speedups.

## TLS and application-token integration

The portable server candidate now prefers ChaCha when its compiled AES backend
is software, while accelerated builds retain AES preference and AES remains a
fallback. Use standard TLS negotiation rather than an Onyx-specific cipher
selector. The [matched study](https://github.com/devinkbrown/onyx-server/blob/3fa6e95021601c92d2a2b68869d8fa9f4047d391/docs/ops/tls-cipher-policy-benchmark-2026-10-27.md)
records the bounded observed benefit; it is not a client or mesh benchmark.

Keep TLS ticket/PSK storage, account `SESSIONTOKEN`, and logical-session resume
credentials separate. A TLS full-handshake fallback must not itself replace,
revoke or discard a valid Onyx resume credential. Let the relevant application
protocol resolve attachment, expiry, rotation and revocation. Record transport
resumption and application resume outcomes separately in redacted diagnostics.
The [credential-domain contract](../reference/credential-domains.md#tls-resumption-tickets)
explains why a transport ticket is neither account login nor session restore.

Certificate-based login needs an explicit recovery path: current ticket-only
resumption does not restore CERTFP. When certificate authentication is needed,
provide a bounded full-handshake retry rather than an endless SASL retry or
unnecessary logical-token replacement. Verify current/previous ticket keys,
IRC/WS transitions, a saved differently preferred cipher suite, and HRR
fallback with real certificates and application credentials. Server source
currently has optional certificate collection, not a mandatory-mTLS mode.

Do not infer replay-safe application operations from TLS 0-RTT acceptance.
Commands affecting accounts, sessions or moderation need their own replay-safe
admission contract before the client sends them as early data. Cold storage,
resume storms, sequential upgrades and offline return still require client
source and end-to-end tests; this outline is not evidence that they are done.

## Dependency and rollout order

| Phase | Client work | Server prerequisite |
| --- | --- | --- |
| 0 | Audit current client implementation against this outline. | Agreed source cut and fixture contracts. |
| 1 | Capability handling, structured errors, participant identity, safe CHGHOST handling. | Cloak and compatibility slice accepted; bounded explanation semantics. |
| 2 | Session/device inventory, replay-safe reconnect, accessible everyday controls. | Scoped inventory/revocation contracts and exact session acceptance. |
| 3 | Setup/maintenance views and operator workspace. | Shared config plan/schema, detected supervisor, safe diagnostics. |
| 4 | Soundcheck and robust voice journey. | Supported native/browser media negotiation, telemetry, actual-call acceptance. |
| 5 | Adaptive video and screen sharing. | Layer/subscription contracts, bounded feedback, encryption/audience model. |
| 6 | Mesh rehearsal, advanced recovery, measured efficiency work. | Authorized planning endpoints, fault campaigns, representative baselines. |

Deliver useful phases incrementally. Client and server deploy in negotiated
compatibility order; unsupported controls stay understandable. A rolling
upgrade matrix must include old/new clients, old/new capabilities on current
server schemas, multiple devices, offline return, and interrupted operations.

The final client implementation plan should list actual files and components
only after the client repository is available and audited. That audit should
retain existing working features and assign explicit ownership rather than
assuming a rewrite.


## Verified privacy and operator integration contracts

WHOWAS rows should render the recorded public host as a historical identity,
including an old cloak retained through later rotation. The source correction
and native anonymous/account NICK/QUIT corpus now validate that behavior; account
330 retains its current public meaning. Client UI should preserve the event's
recorded identity and timestamp while displaying current identity separately.

Local operator tooling now has
`doctor <config> --peer-config <peer-config> --json`, with fixed cloak mismatch
categories and unknown runtime readiness. An operator UI adapter can display
those already-redacted results from an authorized local workflow. Private file
loading remains inside the privileged local configuration process; the result
provides categories without secret values, fingerprints or sample cloaks.
This is a verified local CLI contract. A remotely accessible operator bridge
and the client UI remain proposed work, and no network capability for this
comparison is advertised from the local CLI tests.


## Cloak notification candidate under validation

The current server candidate uses existing CHGHOST and signed mesh presence;
it introduces no new client wire capability. A capable client should update
the subject's current username/host while preserving prefixes already recorded
in history. A remote collision UID is a distinct public subject: its legitimate
CHGHOST must not be applied to the local user whose preferred nick collided.
The server retains notifications for each physical connection under output
pressure, and orders departure output behind already accepted host changes.

Existing ban and access masks keep their operator-visible text. The client
should not rewrite them on CHGHOST: server policy matching preserves the tested
old-cloak scope across rotation. Native two-node tests now separately check
old-mask speech denial, fresh JOIN denial after rotation, same-USER/different-IP
admission, and recovery after ban removal. Those tests use injected clock
boundaries and TCP clients. Full release, successful Helix carry of the new
state, client implementation, and TLS client acceptance remain separate gates.

## Proposed physical media ownership contract

The [physical media owner design](https://github.com/devinkbrown/onyx-server/blob/3fa6e95021601c92d2a2b68869d8fa9f4047d391/docs/design/media-physical-owner-namespace-2026-10-27.md)
addresses a confirmed cross-node ambiguity when separate physical attachments
reuse the same signed client envelope. Proposed qualified handshake, group-key,
and retirement messages would distinguish each physical owner and generation;
clients would match crypto state and departures using that qualified identity.
Capability activation, legacy isolation, receiver ordering, client implementation,
and concurrent two-node media tests remain required. The local collision guard
alone does not establish this mesh contract, and no new wire names are advertised.

### Operator onboarding media assessment

A client onboarding surface that consumes server setup JSON should display the
optional `media_assessment` explanations consistently with the server wizard.
The fields are `enabled`, `socket`, `native_socket`, `candidate`, `network`, and
`fallback`. Treat them as display text; do not derive call authorization, codec
capabilities, or a connected state by parsing those strings. An absent field or
an existing-configuration preview means unknown. Actual negotiated transports,
room permissions, and media readiness continue to come from their authoritative
protocol state. This is an outline for the client; no client source was changed.


## Accepted Linux sequential-upgrade session contract

The W84 server composition retains four physical TLS attachments and their
shared reusable token through upgrades on A then B in a secured A–B–C mesh;
a fifth client resumes on C afterward. Clients should keep valid credentials
and existing transports during this supported upgrade path, identify devices
by physical attachment identity, and use negotiated session authority rather
than rotating public hosts. No client token-format change is required.

This server acceptance does not establish client implementation, Windows live
upgrade support, or recovery of a predecessor after successor exec failure.
Keep unsupported-capability and reconnect failures explicit. The independent
server journey checked 55 accepted events and 407 exact recipient deliveries;
full release and deployment acceptance remain pending.


Diagnostic consumers must retain event counters separately from emitted log-line
counts. The native Alpine fixture now proves suppression and a later nonzero
summary on the reviewed daemon; a quiet sink does not imply no events occurred.
Do not display this as proof of OpenRC/syslog delivery or retention. Wizard and
doctor readiness must continue to distinguish those unknown observations.


Background replica retry progress now survives supported Linux upgrades. A
persistently failing early group does not restart the orphan scan ahead of later
groups after each exec; signed repair authority and the cursor are restored
together. This is transparent to clients and requires no token-format change.
Continue to show revocation as pending until authoritative completion receipts;
local queue admission or repair scheduling alone does not prove peer completion.


## Publication retry and Alpine operator integration

The integrated no-cohort lease retry can retain an already accepted OFFER and
finish its lease without minting another OFFER revision. The native proof keeps
the bearer, attachment and socket stable, including when the first peer fanout
fails. This requires no client token-format change. Cohort reuse and other
credential families are not covered by this optimization.

Operator views can consume the fixed, unlabeled `onyx_session_*_total` counters:
tracking-token creation, OFFER mutation/renewal/new retry/reuse, lease acceptance,
retry attempts/completion, live fanout and retained replay. These counters reset
on a new Core image, including same-PID Helix. A reset is not credential churn;
local acceptance or queue admission is not a peer completion receipt.

A node withdrawing its own replica advertisement is distinct from permanently
revoking a device or logical group. A newer authorized advertisement may replace
an origin withdrawal. Client revocation state must follow the explicit group or
attachment authority and completion receipts, not an origin advertisement count.

Actual Alpine/OpenRC acceptance now verifies the shipped nonroot daemon and
stderr logger through BusyBox syslog, suppression metadata and private-marker
exclusion. Operator flows should check config traversal and preflight as the
service identity: a root-readable config and a supervisor marked started do not
prove that the application can read its configuration or is ready. Keep kernel,
process, HTTP, mesh and media readiness distinct; an unavailable observation
remains unknown. The fixture's bounded capture is not a promise about arbitrary
operator log-retention policy.


Raw persisted Services records need a separate migration preview. K1 and S1
lack metadata needed to authorize an automatic replacement, so the integrated
adapter retains their original bytes and reports a metadata gap. A witnessed
W1 value replacement must also migrate its pattern-derived storage key and
prove collection order: overlapping Warden rules use first-match semantics.
The report exposes `key_migration=required order_proof=missing` for
such proposals. Operator UI must keep application unavailable until both
requirements are satisfied; a verified individual host replacement alone is
insufficient. The detached raw-record adapter is integrated; live storage-key migration and
collection-order authorization remain unavailable.


Capability HELP topics and search now derive from the live server's capability
metadata. Clients can offer these explanations without maintaining another
catalog. Use the actual connection's CAP LS response to determine availability;
a known help topic does not mean that configuration or transport permits it.
Command syntax/examples and the client palette remain separate integration work.


The Alpine installation workflow now supports existing file, inline,
environment and referenced-file identities without generating a replacement.
The wizard/operator tool can run `--check-service-identity PATH` as the service
account for a read-only credential check. A compatible Helix target must retain
strict identity startup and the config's resolved environment bindings. An
identity/realm/environment drift refusal leaves the existing process and
attached clients serving; the client should not treat that refusal as a reason
to discard valid session credentials or reconnect. Four credential-mode native
upgrades verified one welcome and uninterrupted PONG on the same sockets.


The integrated permission query is `ACCESS <#channel> EXPLAIN [nick]` after
registration and an `IRCX` command (`ISIRCX` queries the current state). Clients
can correlate concurrent responses using negotiated `message-tags`, `batch`
and `labeled-response`, plus an `@label` request tag. Use connection CAP
negotiation to determine support. Keep direct JOIN decisions separate from
connection context such as SACCESS GAG. Self queries redact private policy
fields. Another subject requires `audit_read`; hidden-channel visibility also
requires `oper_spy`, and individual policy sources retain their read checks.

Treat expiry as typed data: `absolute_unix_seconds` is an absolute Unix time,
while `absolute_store_millis` belongs to the policy store's clock domain and
must not be displayed as Unix UTC. Preserve `unknown`, `permanent` and
`none_recorded` distinctly. Nonzero legacy SACCESS durations have unknown
expiry; null/zero may report permanent when authorized. Do not invent a
countdown from an unknown or uncalibrated clock. Forwarding, cloning and final
transaction availability remain conditional. This query covers existing-channel
direct JOIN without a supplied key, not a general permission simulator.


The integrated media recovery policy imposes a strict1000ms awake-time cache
age ceiling. Expired or unknown-age packets are not retransmitted; retained
duplicate packets do not restart that deadline. Client loss recovery must allow
missing old frames to expire rather than expect indefinite replay. This server
resource ceiling is not a negotiated playout delay or a codec-aware jitter/FEC
policy. Windows active-media checkpoint layout now requires HXWA version2;
older layout is rejected. Until native mixed-version evidence is available,
operator and client maintenance views must leave seamless Windows media upgrade
compatibility unverified. No downgrade-preservation promise is established.
