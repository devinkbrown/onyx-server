# Roadmap wave execution

The [integrated roadmap](../ROADMAP-2026-10-26.md) is delivered in parallel
tracks with bounded acceptance slices. A wave is a coordination unit, not a
claim that all of its features have shipped. Preserve the existing source and
release evidence; deployment requires its own acceptance.

The [acceptance inventory](roadmap-acceptance-ledger-2026-10-26.md) retains every
numbered target and its full acceptance criterion. Partial implementation does
not close an item; missing client, topology or runtime evidence remains open.

| Wave | Work grouped for integration | Next acceptance boundary |
| --- | --- | --- |
| 1 — installation and session efficiency | R1 setup preview; T04/T06 indexed retry selection; A03 isolated OpenRC contract; E04/E05 evidence ledger | Shared startup validation, truthful readiness output, bounded token work, focused Debug/Safe tests and independent review. |
| 2 — recovery and operations | Guided session inventory/revocation, redacted diagnostics, cloak legacy-rule audit | Authorized device scopes; durable revocation; no secret output or guessed legacy grants. |
| 3 — interactive setup | Color navigation, private drafts, profiles, transactional config export, service-plan adapters | Interrupted setup and headless equivalence; no live mutation before explicit commit. |
| 4 — coordinated voice and video | Codec capability truth, pacing/control budgets, layer selection, device/transport recovery | Real encoded payload and impaired-network native/browser acceptance; audience isolation. |
| 5 — distributed scale | Fair repair quotas, digest/delta repair, media distribution, topology rehearsal | Non-clique secured convergence and measured resource curves; exact accepted delivery. |
| 6 — release integration | Native Alpine recovery, client contract matrix, reproducible artifacts, supervised rolling acceptance | Every physical attachment participates across nodes and upgrades; independently accepted release evidence. |

These group related work to reduce repeated investigation. Each item still
needs a clear owner, a bounded diff, tests and a fresh review. One wave can
contain several accepted changes; large unrelated diffs are not the goal.
Client implementation remains outside this repository; use the
[client contract outline](../design/onyx-client-integration-2026-10-26.md).

## Current product-wave assignment

The [R0–R6 completion matrix](../ROADMAP-2026-10-26.md#complete-delivery-assignment)
assigns all 98 targets exactly once, with dependency contracts, gate ownership,
client handoffs and performance gates. The numbered implementation cuts below
are historical slices that may advance several product waves. They are not
additional acceptance targets or competing release schedules.

At the 2026-10-30 checkpoint, the inventory is **27 accepted, 24 partial,
47 open**. The roadmap plan is fully allocated; implementation remains in progress.
The acceptance inventory is authoritative for status; earlier numbered cuts below
retain their original evidence and limitations.

### Continuation and retry discipline

Resume from `.zig-cache/CURRENT.json`, then read only the receipts for the active
contracts. Keep at most three unfinished acceptance contracts, each with an owner,
a sealed source manifest and a specific remaining proof. Accepted contracts stay
closed unless new evidence contradicts their accepted behavior.

Before retrying a failed gate, record its exact failure, the diagnosed cause and
the changed source or precondition. Retain the original assertions and failed
receipt. Run the affected cases first; reuse unchanged, source-bound evidence
when an independent reviewer approves its relevance. A repeated unchanged
failure goes to independent diagnosis while another lane continues.
Before a new native fixture runs, require a bounded failure report identifying
the current operation and physical client, with fixed response classifications
and sanitized helper status. Generic timeout or disconnect reports must not
discard the observations needed to distinguish an oracle error from a daemon
failure. Never print credentials or raw private transcripts for diagnosis.

For every active contract, record one next action, its owner, the files that owner
may change, and the evidence that will end the slice. A failed gate changes the
next action to diagnosis; it does not reopen the roadmap or every prior gate.
Consult `tools/gate_ledger.py decision` before repeating a completed command.
Changed context must include a relevant correction, not unrelated source drift.

Move integrated slices out of the active queue immediately, retaining their
acceptance receipt and limitations. Keep an in-flight full-suite source frozen;
continue independent implementation in private candidates instead of repeatedly
invalidating the release check. Status updates should identify new code, new
evidence or a specific blocker; elapsed work and repeated plans are not progress.

Refresh checkpoints without replacing active owners or jobs with historical
state. Record running handles and terminal results; an expired observation is
not a reason to launch a duplicate job. Acceptance requires the specified native
behavior and review as well as module tests. Release and deployment evidence
remain separate.

## First implementation cut

- **Setup:** `onyx-server setup <config> [--service auto|openrc|systemd|foreground] [--json]`
  previews installation using the startup configuration model. Readiness remains
  unknown until runtime acceptance. This starts W02/W10/W11; it does not finish
  interactive navigation, config creation, private drafts or installation.
- **Session work:** dirty publish/projection token selection uses one traversal
  of the existing token index and cached dirty counts, with bounded caller
  storage and separate circular cursors. Token authority, lifetime, strength,
  and physical attachment identity remain unchanged. This advances T04/T06.
- **Alpine:** `PYTHONDONTWRITEBYTECODE=1 python3 tools/alpine_openrc_smoke.py`
  checks preflight failures, private directory permissions and the native
  OpenRC shell adapter with an intercepted launcher. Actual supervisor
  crash/respawn and service readiness remain VM/container acceptance gates.
- **Engineering evidence:** the gate ledger below advances E04/E05. It records
  evidence relevance and preserves complete logs without changing model settings.

### Evidence and remaining boundaries

Session gates passed **206/206 in Debug and ReleaseSafe**. The final expanded
operation-count test also passed in ReleaseSafe (**81/81 including imported
root tests**). Its independent numeric oracle exercises 22 cursor positions,
33 output capacities and both lanes: 1,452 combinations over 19 token groups
with 323 attachments. Each nonempty-capacity collection visits exactly 19 index
candidates and zero physical rows, with allocation failure armed. Selection
still scans all token groups once and shifts a bounded candidate array; this
is operation-count evidence, not a measured daemon throughput improvement.
The session delta received independent approval. Exact gate receipts are in
`.zig-cache/token-wave-evidence.json`.

The isolated Alpine contract passed **10/10 without skips** on this host, and
the ledger invalidation tests passed **8/8**. Separate tool invocations proved
ledger run/status reuse. The native setup CLI smoke passed five scenarios,
including secret and terminal-escape omission, invalid inputs and unchanged
candidate/working directory. Review found and corrected configuration-derived
diagnostic leakage through a per-call quiet loader shared with startup.
Setup rendering includes allocation-failure retry coverage.
The setup executable gate passed **20/20**, including the six focused setup
tests. Quiet-loader projection/rejected-input parity passed **81/81 in Debug
and ReleaseSafe**, including imported root tests. The final reviewer approved
the fix contingent on the ReleaseSafe pass, which is now recorded.

Retained setup, executable, OpenRC and ledger logs live under
`.zig-cache/wave-1/`. Focused counts overlap imported tests and must not be added
as unique tests. Earlier full-release evidence predates this wave; this cut
does not claim a fresh full-suite or live multi-node release gate. Production
services and client source have not been changed by these wave implementations.

## Second implementation cut

- **SESSION command safety:** full grammar validation precedes inventory,
  credential and selector-cache changes. Unsupported scopes and extra selectors
  cannot partially drop an attachment or consume the credential-preservation
  latch. LIST keeps existing notice prefixes and identifies its local physical
  scope. Debug and ReleaseSafe each passed 118/118, including 22 invalid
  commands under both latch states, zero-allocation failure guards, exact
  unchanged-state assertions, and real threaded multi-client participation.
  Independent review approved the delta. Logs:
  `.zig-cache/wave-2/session-parser-{debug,safe}.log`.
- **Media payload interoperability:** both live browser-to-native fanout and
  public RTP rewrap extract the codec payload after CSRC/extension headers and
  before padding. Malformed lengths and invalid padding fail before delivery.
  The regression sends one packet containing every optional header field and
  verifies exact codec bytes and sequence/timestamp/stream metadata. This fixes
  transport corruption; it adds no codec or transcoding capability. Debug and
  ReleaseSafe each passed 99/99 (19 bridge tests plus imported root tests),
  with independent approval. Logs: `.zig-cache/wave-2/media-bridge-*-final.log`.
  Header/padding extraction follows the payload boundaries described in
  [RFC 3550 sections 5.1 and 5.3.1](https://www.rfc-editor.org/rfc/rfc3550.html#section-5.1).
- **Redacted diagnostics:** doctor produces shared typed text/JSON checks,
  suppresses resolved-config diagnostics, omits private paths/URLs, rejects
  invalid count gauges, and reports partition state independently from TCP
  handshake symptoms. Readiness remains unknown. Core Debug/Safe each passed
  85/85, including exhaustive allocation failures with deterministic allocating
  fallback. Core and CLI delta received independent approval; native CLI
  acceptance passed within the setup tranche's 21 native/headless/PTY cases. See the
  [diagnostic contract](../guide/diagnostics.md).
- **Native Alpine recovery:** a copied explicit artifact ran as a non-root
  user through three real daemon boots, IRC registration/PONG, SIGKILL restart,
  and offline backup restoration, preserving owned mode-0600 identity and
  unchanged config. The container layout now places private config and its
  adjacent node key under writable `/data`, with numeric UID/GID 10001. Native
  evidence uses artifact SHA-256
  `6cecf0e931e8e173e6430b791e1d5b95ea6b941dc912bb5d386f023990c3728d`;
  it does not cover subsequent source changes. No container engine was present,
  so image/read-only-root acceptance remains open. Independent review approved
  the layout and harness; [Alpine guidance](../guide/alpine.md) records limits.
- **Interactive setup:** private/community/media profiles generate ordinary
  TOML passed through the same typed loader and static startup checks. The
  bounded line interface supports help, search, back, review, cancel, and
  explicit export/save. Choice-only versioned drafts are private, owner-bound,
  and resumed through held-object Linux metadata checks that reject FIFOs,
  symlinks, hardlinks and oversized/unknown input before reading. Export is
  atomic mode-0600 create-only and refuses replacement. Native acceptance
  passed 21 cases, including four real PTY flows, no-public-listener profiles,
  color/NO_COLOR, FIFO fail-fast, artifact refusal, resume and redacted doctor
  JSON. Logs: `.zig-cache/wave-r1/native-smoke-accepted.log`. See
  [setup guidance](../guide/setup.md) for the Linux publication dependencies and
  remaining identity/TLS/enrollment, transport assessment, resource planning,
  existing-config diff/update and upgrade workflows. These remain partial W
  requirements; the full wizard is not certified complete.
  Final focused ReleaseSafe passed 12/12 with unchanged-source ledger evidence;
  native acceptance is bound to both the exact binary and smoke script in
  `.zig-cache/wave-r1/native-accepted.json`. Independent review approved the
  held-object draft lifecycle and the final terminal delimiter correction.

The next SESSION acceptance boundary is broader than syntax safety: existing
LIST/DROP scope is node-local physical attachments. Logical-session revocation
needs account-authorized group authority, retained mesh tombstones/retries
staged before local destruction, remote lease enforcement and account-scoped
inventory of verified remote attachment identities. The existing origin-only
signed remove path, deliberately suppressed while local token siblings remain,
does not establish that contract. T07 remains partial.

## Third implementation cut (integration in progress)

Setup now accepts hostname, literal listen address, IRC/TLS/media ports, node ID
and client capacity in both interactive settings and headless flags. Private
versioned drafts contain settings only. A create-only bundle stages canonical
node identity, a self-signed TLS certificate/private key, a random cloak secret
and an ordinary configuration with final absolute references. Interactive
publication reviews the actual public identity, certificate expiry, provenance
and observed file modes before an explicit publish choice; cancel/EOF removes
the unpublished stage. This does not establish public-CA enrollment or
power-loss durability of directory entries; the guide states the boundaries.

The native setup tool passed **25 real headless/PTY cases**; focused ReleaseSafe
passed **16/16**. A separate real daemon fixture negotiated **TLS 1.3**, completed
IRC registration/PONG with the locally pinned generated certificate, rejected a
wrong hostname, retained a healthy sibling IRC service, and preserved all five
bundle files. It ran as UID 1002 with artifact SHA-256
`558a6b402b17cf1ba9809176dc72ff44a3cebf016e6f08ca5d9d7c29ad75eb9b`.
Ledgers: `.zig-cache/wave-3/setup-native-redacted.json` and
`.zig-cache/wave-3/setup-tls-sibling.json`. The TLS fixture keeps one registered
sibling socket alive across the rejected handshake and verifies its subsequent
PONG. Two failure-path regressions also prove captured stderr/PTY secrets do
not enter harness diagnostics (`setup-diagnostic-secrecy.json`). Reproduce with
`tools/setup_smoke.py` and `tools/setup_tls_smoke.py` and an explicit artifact.
These receipts do not cover later mesh source changes.

The root component gate passed **252 tests with 2 Windows-only skips** in both
Debug and ReleaseSafe. It covers all SessionStore and media-plane tests plus
the new durable group-fence adapter: prepared WAL writes, ambiguous-outcome
cold reopen, first-fact account binding, strict trusted cold restoration,
read-only Helix fence verification, and allocation-failure atomicity. Inventory
dirty marking reuses the existing indexed retry lane without issuing portable
credentials. Media admission reserves bounded feedback/audio headroom before
video fills the shared queue, preserving existing FIFO custody and ordinals.
At capacity 64, video admission stops at 62 rows and audio at 63; feedback can
use the last slot. This is admission protection, not a playout/latency guarantee.

T07 mesh integration is still in progress. Its current design uses the existing
live replica Store, permanent bounded group fences, indexed physical inventory,
canonical current transport, strict checkpoint/link versions, and signed
receipts bound to the validated full-roster digest and activation epoch.
Independent review caught and corrected an expired cross-account index leak;
targeted tests also reproduced and corrected a RESYNC negotiation-proof reset.
Leaf tests do not certify the unfinished complete client/three-node workflow.
The inventory-versus-resume authority finding now has independent approval at
the frozen server cut `a382b616`: mandatory signed eligibility, empty private
nickname/snapshot fields, no private-to-legacy publication downgrade, and exact
signed provenance checks at EXTERNAL and legacy cache restoration. The real
A–B–C certificate test denies private-group restore before promotion, then
accepts explicit source EXTERNAL or MTOKEN promotion. All three daemon
bootstrap insertions mint a physical attachment ID. The broader gate passed
**505 tests with 16 platform skips out of 521 in both Debug and ReleaseSafe**.
The skips require root privileges (seven), OpenBSD (two), or Windows (seven);
they are not passing runtime evidence. Exact source, command, count and skip
receipts are retained with the frozen security snapshot. This is a candidate acceptance milestone,
not a full release result.
The same review also identified media authority outside IRC line processing:
native UDP endpoints, coalesced WS binary ingress and same-shard local binary
delivery require an explicit revocation cut before a durable-denial receipt.
The media authority finding now has a bounded independent approval: exact
physical Domain endpoints are fenced before row removal and ACK9, with atomic
WS ingress/delivery guards. The 81/81 Debug native gate uses three real UDP
sockets, valid directional MACs and actual server durable revocation; it proves
revoked producer/recipient denial while the socket remains open and unaffected
participants continue. Valid-MAC WS tests cover coalesced self-revocation plus
binary ingress and same-owner recipient denial. The combined 521-test Debug/ReleaseSafe cohort is now green as recorded above;
full release gates remain pending. This approval does not cover the separate
EXTERNAL eligibility finding.
The current durable trust policy also requires historical fence issuers to
remain verifiable in the configured full roster. Retiring an issuer without
an authority migration can reject cold startup; deleting permanent denials is
not an acceptable workaround. Historical-authority migration and bounded public
inventory continuation remain open integration requirements.

### Current diagnostic and physical-identity slice

The attachment-aware EXTERNAL bootstrap API preserves the supplied physical ID
in the locked restore preview, committed row and attachment index. It rejects
zero IDs and global collisions before publication; abort and allocation failure
leave the prior rows intact. The legacy API retains its explicit null-ID path.
The leaf and the redacted doctor extension received bounded independent review.
Their combined gate passed **93/93 in Debug and ReleaseSafe**, including the
bootstrap allocation-failure sweep. These results do not certify daemon caller
wiring or the separate certificate-authentication mesh workflow.

Doctor now includes the reporting binary's build version and a fixed numeric
observation set. Its single-pass bounded parser supplies both health checks and
JSON counts; malformed, overflowing and duplicate counts remain unknown, and
unrecognized names/labels are omitted. Readiness remains unknown. See the
[diagnostic contract](../guide/diagnostics.md).

## Reusing gate evidence

`tools/gate_ledger.py` wraps a command with a private complete log and a small
JSON record, including conservative scoped test counts when a recognized
summary is unambiguous. It does not skip commands automatically or approve a
release. Record a gate after its writers stop:

```sh
export PYTHONDONTWRITEBYTECODE=1
export TMPDIR="$PWD/.zig-cache/cloak-tmp"
python3 tools/gate_ledger.py run \
  --record .zig-cache/wave-1/session-debug.json -- \
  /tmp/zig-017/zig-x86_64-linux-0.17.0/zig build test-mod \
  -Dtest-filter=daemon.sessions --summary all
python3 tools/gate_ledger.py status \
  --record .zig-cache/wave-1/session-debug.json
```

The default source and execution directory is the repository containing the
helper, regardless of the invoking shell's directory. Use `--root /absolute/path`
for both `run` and `status` when testing a private context. The receipt records
that root and binds it into the source digest. If using the actual helper with a
private root, explicitly include the helper's absolute path among `--input`
dependencies. Use absolute receipt paths to make the evidence destination clear.
The explicit-root CLI and cross-root invalidation checks passed with all 16
Python tests; earlier receipts remain supported.

The defaults hash the full `src`, `etc`, `tools`, and `packaging` trees plus
both build files, executable bytes, command, platform, working directory, and
an aggregate hash of the environment (excluding the volatile orchestration
identifier `CODEX_TOOL_CALL_ID`; gates must not depend on that identifier).
Changes, added/deleted files, nonzero
exit, source changes during the command, and altered logs invalidate evidence.
Symlink inputs are refused. Records and logs are exclusive-create and mode
0600. Use a new record name on reruns. Review counts/skips in the retained log.

Explicit repeated `--input` values replace defaults. They are an expert
dependency declaration: include every transitive source, script, configuration
and external toolchain/dependency input relevant to the gate. The default
snapshot does not establish external dependency immutability, kernel state,
network topology, or live-service health. Do not use a current record to
substitute for release-time full or live acceptance gates. A change reverted
between snapshots is also outside this tool's detection; freeze writer work
before running gates.

Command arguments are stored verbatim; never put credentials in them. Keep
credential-bearing output out of evidence, even though logs are private.
Environment values are hashed together and not written into the record.
Environment changes can conservatively invalidate an otherwise usable result.
Actual model token billing is unavailable here; no percentage savings is
claimed. Useful efficiency measures are accepted changes, repeated gates,
review rework, complete retained evidence, and elapsed time.


The next inventory tranche bounds both output and source traversal. Limiting
output to 32 rows while scanning the entire account does not bound a World
turn. The planned indexed cursor has a hard work budget, account binding,
structural-generation invalidation and explicit continuation; chat snapshot or
lease refresh must not starve it. Page custody and labeled-response acceptance
must commit before the public cursor advances. Implementation is in progress.

Native diagnostic harnesses now include a reviewed Alpine connection-log
fixture (four adversarial tests and a real QUIT-redaction milestone on the
prior accepted artifact), plus a reviewed doctor CLI/HTTP fixture (two
adversarial tests; native execution awaits the current executable). These
fixtures retain bounded private captures and static failure diagnostics.
Actual Alpine supervision, rate exhaustion and log retention remain separate
acceptance requirements.


W05's account-provisioning candidate received independent workflow review and
passed **21/21 ReleaseSafe** tests after the allocation sweep exposed and
corrected an operator-binding slice leak in configuration loading. Every
allocation index before clean success at 222 was injected. The obsolete Debug
run used the known defective pre-fix artifact and was deliberately terminated;
it is not passing evidence. Post-fix Debug authentication/storage-fault checks
and one current native artifact are the next gates. Native checks will execute
PLAIN, SCRAM-SHA-256 and SCRAM-SHA-512 exchanges, including server proof checks,
wrong-proof denial, exact operator privileges and cold restart. Prepublication
checks resolve durable SCRAM tuples; they do not execute a wire exchange.

The bounded inventory leaf passed **198/198 Debug** tests and fresh review:
32 rows and 64 indexed origin/row work units, no full signed-object decode per
page, account-bound structural generations and allocation-failure rollback.
Chat revisions, lease refreshes and other accounts do not invalidate traversal.
Daemon output custody, labels, nonce retries, reset boundaries and ReleaseSafe
remain integration gates before accepting public continuation.


The current native doctor fixture passed all seven checks on artifact
`6a4d8a807f99c2e452866bef0382eae6be0e23b418a8905523c5f54448782318`:
offline unknown observations, exactly one bounded HTTP GET, numeric counters,
private-input omission, duplicate-count invalidation, partition failure and
absence of generated state. This uses disposable metrics, not live mesh or
media readiness. The same captured artifact is used for setup authentication
acceptance; later retirement-policy source changes are outside that artifact.

[Permanent fence retirement](../design/session-fence-retirement-v1.md) now has a
reviewed design and an implementation in progress. Exact signed-fact pins stay
separate from active roots and receipt authority; required-group coverage
applies to cold and strict Helix staging. A final retirement export requires a
quiesced issuer and atomic private publication. No live membership transition
has been performed.


W05's post-fix Debug representative gate passed **20/20**; its global source
ledger records concurrent unrelated changes, so it is not an unchanged-tree
certificate. Native acceptance on the captured `6a4d8a807f99…82318` image passed
**28 setup cases** and **20 authentication cases**. The promoted public
`tools/setup_auth_smoke.py --binary <artifact>` binds the selected image by
before/after hash, verifies generated-certificate trust and hostname before
sending credentials, and tests actual PLAIN/SCRAM proofs, corrupt proofs,
permissions, cold restart and preview lifecycle. Its final ledger
`.zig-cache/wave-4/auth-public-verified.json` is green with unchanged inputs;
it supersedes the earlier cached harness's omitted environment selection.
Fresh review approved workflow and cleanup; public harness review nits were
corrected and exercised in that final native run. W05's specific criterion is
accepted for this Linux artifact. Other wizard and release targets remain open.


The next integrated cut adds shared 2-MiB configuration limits, exact retired
signing-fact policy, restart-only pin changes and prospective Helix roster
validation. The configured cohort now gates inner positive session signers
before mutation, including relayed and retained state. Fresh review closed the
signer-authority finding and the signal/deferred-upgrade bypass findings;
the latter cut passed 87/87 Debug tests. Optimized acceptance remains pending.

The closed managed fence bridge passed 85/85 Debug tests and independent
review, contingent on ReleaseSafe. It fetches sealed policy internally and
keeps private storage behind validated source/World custody. This does not
activate the experimental managed backend; its broader lifecycle guards remain.

A captured native image, SHA-256
`eea8f4bb50ac0b79170644b7a79e34e190ace7ece884419ee37403dea87bb5d4`,
passed all seven doctor checks. It includes the new offline retirement export
command. Its first native export fixture failed with `SignalStateBusy`, before
publication; the guard's 82/82 Debug module checks do not establish CLI success.
The native failure is retained and integration diagnosis continues.

The SQPOLL experiment completed all 72 cells and more than 2.7 billion exact
CQEs. Its opt-in 10-ms idle window cut burst CPU about 96%, with a measured
wake-latency cost; see [the benchmark report](sqpoll-idle-benchmark-2026-10-26.md).
SQPOLL remains disabled by default. Shared configuration projection and bounds
passed 135 tests with seven platform skips in Debug, with independent review;
the final combined ReleaseSafe gate remains pending.

Native cloaking acceptance is now exercising actual TCP and secured mesh
connections. It exposed a real PROXY-v1 receive-boundary defect: the driver
counted coalesced registration bytes against the header limit. A deterministic
regression reproduced it; the bounded driver correction and real transport
acceptance are in progress. Component checks alone do not close those targets.


The native export integration failure is now corrected. Lease notifications
use separately owned `SIGRTMAX` through per-file `F_SETSIG`; Zig's SIGIO
cancellation handler and its mask/pending state remain untouched. All **82
Debug tests** passed, including 19 isolated kernel scenarios and refusal after
a discarded break notification. Independent review approved the change.

Captured artifact
`80c8152491bdba86485aa393e41bb49a645bd48bc732f4982fa6a41c36892d20`
then passed **10 native export controls**, with unchanged harness/artifact inputs
recorded in `.zig-cache/wave-4/retirement-native-rt-controls.json`. These prove
empty-baseline export, exact typed refusal reasons, private create-only output,
no existing writer or symlink admission, successful retry, native configuration
above 1 MiB and refusal above 2 MiB. The original failing evidence remains.
Nonempty signed-fact native export, combined ReleaseSafe and deployment remain
separate gates. The command requires a trusted, quiesced issuer and private
baseline; it does not establish global finality or directory crash durability.


The first native cloaking cut passed **121/121 Debug checks**, with no skips,
failures, leaks or logged errors. Frozen server SHA-256:
`c5da81ebb65368f4a3d92512881ae7e07ba1577d3bb10e4d05ec5a7390150386`.
Raw log: `.zig-cache/wave-5/cloak-native/combined-debug-final.log`.
It uses three actual TCP clients, two native secured mesh nodes, trusted PROXY
admission and ordered positive/negative barriers. It proves same-epoch
stability, fourteen-day boundary rotation, historical channel
ban/exemption/quiet behavior,
and invite exceptions on an already established channel.

The native tests exposed and now cover three production defects: coalesced
PROXY-v1 application bytes being counted as header bytes; automatic self host
notifications lacking send arming; and redundant voice mode changes triggering
a server assertion. Notification delivery also now survives fallible watcher
fanout or poisons the owner on its own queue failure. Independent reviews
approved those bounded source changes. The shared Debug run includes fragmented
and malformed PROXY controls, a 16-case voice matrix, actual command dispatch,
129-watcher allocation failure and a full notification queue.

This is narrower than P01/P03/P06 acceptance. Native ACCESS/SACCESS/AKICK/WARD,
complete clone/reputation equivalence and the larger reconnection matrix remain
open. An earlier remote-only invite/channel-mode ordering failure is retained
as a separate unresolved mesh seam; the passing invite journey establishes
local channel membership and verifies actual mode readiness first. Combined
ReleaseSafe is now running on frozen source, with predecessor test-name coverage
to be checked before accepting the result.


Fresh fixture review found that the native owner's generic CHGHOST wait could
be satisfied or flushed by another participant's concurrent rotation. Therefore
the 121-check cut does **not** independently establish timer-origin self
notification. That claim is withdrawn pending an exact-self assertion with
remote rotation isolated. Production notification source review remains
approved; strengthening this acceptance fixture follows the frozen Safe gate.


The combined frozen **ReleaseSafe** gate completed successfully in 643.633 s:
**699 passed, 34 skipped, zero failures, leaks or logged errors**. All 521
predecessor named tests are retained, with 212 additions (733 total). Skips are
25 Windows-only, two OpenBSD-only and seven requiring root. Source/tool inputs
remained unchanged. Receipts and raw output:
`.zig-cache/wave-5/combined-security-safe.json`,
`combined-security-safe-counts.json` and `combined-security-safe.log`.
This covers the current session, paging, retired-fact, configuration, managed
bridge, baseline guard, Ringlane and bounded cloak changes. It does not close
the independently identified self-notification fixture gap or establish a full
release gate. That test correction follows without changing the reviewed
production behavior unless new evidence requires it.


The fixture correction received independent approval and passed its native
Debug execution (1.249 s): separate clocks and an idle SendQ gate isolate the
exact owner notification before the remote rotation. The full Debug selection
finished **698 passed, 34 skipped, one timeout**, with no leaks/log errors.
The unchanged three-node reusable-session/MARKREAD journey timed out after
27.495 s; the exhausted caught-parse error trace did not identify a phase.
No timing cause is inferred. The failed full result is retained in
`.zig-cache/wave-5/cloak-native/isolated-full-debug.{json,log}`. An isolated
unchanged retry and focused optimized check follow; neither can retroactively
make this full Debug run green.


The unfiltered executable-root **ReleaseSafe** gate also passed **38/38**,
with no skips, failures, leaks or logged errors, unchanged inputs and 156.87 s
elapsed. This includes the new retirement CLI tests and current setup/account
allocation-failure and storage-fault workflows. Receipt/raw output:
`.zig-cache/wave-5/retirement-cli-safe.{json,log}`. It is separate from the
module-root security gate and the unresolved three-node selection failure.


Nonempty offline export now passes **five native cases** on the existing
captured `80c8152491bd…92d20` CLI image, with a production-encoder fixture
artifact SHA-256
`74f825cbbe14f1e6c58fed0a5dd33bae10633a4387a75287bb69eb05716e356e`.
The baseline contains two selected-current-issuer facts, one other active
issuer's fact and one pinned prior-retired fact. The canonical export contains
exactly the selected two; all baseline WALs remain byte-identical after every
attempt. Four exact typed refusals cover retired selection, missing required
groups, altered retained facts and a newly signed retired group. Account/raw
16-byte token/hex token omission and the exact summary schema are checked;
two adversarial subprocess tests exercise the privacy oracle. Fresh review
approved the final tool/build delta.

Reproduction (Linux, non-root):

```sh
zig build test-session-retirement-cli -Dretirement-cli-binary=/absolute/captured/onyx-server
python3 tools/test_retirement_nonempty_smoke.py
```

Omit the binary override to test the built daemon artifact; neither path starts
a daemon. The helper is available only through named build steps and is never
installed or packaged. Receipt/raw log:
`.zig-cache/wave-5/retirement-nonempty/native.{json,log}`; inputs unchanged,
7.367 s. This establishes offline fixture acceptance, not complete live mesh
retirement or parent-directory crash durability.


The EXTERNAL selector's causal lease correction passed **105/105 in Debug and
ReleaseSafe**, with no skips, failures, leaks or logged errors. The deterministic
red case proves an older still-unexpired lease could rank a newer detached
group alongside a genuinely live group. Each witness now binds to its own
origin's current trusted, eligible, unexpired offer, the same signer and a
strictly newer lease revision. Other origins and subsequent reattachment remain
valid; private and retired positive authority stay excluded. Fresh review
approved the bounded production change. Safe elapsed 391.985 s; test runtime
3.995 s. Evidence: `.zig-cache/wave-5/cloak-native/causal-evidence.json` and
`causal-fixed-external-{debug,safe}.{json,log}`. Earlier native mismatch causality
is still unproven; the earlier full Debug failure remains recorded. A current
full selected Debug rerun follows this production correction.

T01 gained a reviewed [credential-domain source contract](../reference/credential-domains.md).
Review corrected two overclaims: current SRM1 resumes remain reusable within
TTL, and SRM2 codec countersigning/consume replay mechanisms are not activated
by the live restore/redirect path. The main requested credential families are
traced; additional credential inventories and policy gaps keep T01 partial.


The combined media/policy Debug cut passed **749 tests with 36 skips**, zero
failures, leaks or logged errors (785 named tests). Every predecessor name from
the 734-test cut remains, with 51 additions. All four native moderation
scenarios pass after fresh review strengthened SACCESS GRANT authoring and
public-buffer privacy assertions. All four new media-pump tests executed:
private-wake coalescing, idle enqueue delivery, bounded FIFO/ingress progress,
and deterministic pause-after-boundary scheduling. The implementation preserves
FIFO row ordinals and terminal authority checks; no full priority or mesh-media
claim is made. Count receipt/raw output:
`.zig-cache/wave-6/combined-media-policy-debug-counts.json` and
`combined-media-policy-debug.log`; total elapsed 211.195 s.

Cross-compilation checks for Windows and OpenBSD pass. The first Windows check
found two Linux-only WebTransport callbacks attempting a portable-descriptor to
raw socket type conversion. The sole server writer added compile-time
`Unsupported` guards matching their existing Linux-only Controller contract;
Linux behavior is unchanged. Root independently reviewed the six-line routing
delta. These are compile checks, not native Windows/OpenBSD runtime acceptance.
The combined ReleaseSafe cut is running on the frozen corrected source.

The [optimized native chat comparison](live-chat-sqpoll-benchmark-2026-10-26.md)
completed nine cells and 1,804,032 exact deliveries. It supports substantial
idle/burst CPU reduction for 10 ms versus 1000 ms, but the continuous median
rate is 5.74% lower and the proposed unexplained-regression budget remains
open. SQPOLL off remains default and most CPU-efficient in this workload.


## Wave 8: measured TLS work and retirement validation

The first Terra TLS record-allocation draft remains unpromoted. A matched
three-pair AB/BA/AB study used two captured Safe musl artifacts differing only
in the TLS source. All eight cases, including two correctness pilots, passed;
the six full cases delivered exactly 1,202,688 messages. Continuous median
throughput fell from 9,244.164 to 8,600.998 deliveries/s (6.96% lower), while
median daemon CPU per delivery rose from 88,653.564 to 95,062.256 ns (7.23%
higher). The result rejects this draft for promotion. Record microbenchmarks
improved in one run, but do not explain or supersede the daemon regression.
Raw cases, artifact hashes, environment limitations and decision are in
`.zig-cache/wave-8/throughput-terra/study-01/`.

A separate private correctness pilot observed TLS 1.3 AES-128-GCM on all four
clients using the unchanged portable artifact and default client cipher offers.
This is negotiation evidence, not proof that a different policy improves daemon
throughput. The compiled software-AES backend motivates a separately versioned
ChaCha preference experiment with AES fallback; accelerated builds retain the
existing AES preference. No policy draft has been promoted or deployed.

Terra identified, and Astra independently confirmed in source, a pre-existing
HelloRetryRequest/PSK exact-suite defect. The baseline regression fixture uses
a sealed ticket and client-generated binder: the server accepts an offered
same-hash ticket suite different from its HRR commitment, then the client rejects
the resulting flight. The focused Debug run passed 81 named tests, including
this positive defect witness, with no skips, failures, leaks or logged errors.
This pass reproduces the defect; it does not certify the fix. Evidence:
`.zig-cache/wave-8/throughput-terra/hrr-reproduce-debug.log` and the immutable
`suite-policy-v1/reproduce.zig` fixture. A candidate must preserve exact HRR
commitment, safely decline incompatible tickets, retain valid resumption, and
pass broader crypto and interoperability gates before promotion.

The scoped media-retirement draft remains unpromoted. Its fourth isolated
Debug cohort produced 126 passes and seven failures out of 133 tests, with no
skips, leaks or logged errors. All four new AKICK command tests and six scoped
routing leaf tests passed. All seven packet/WS cases failed during initial
media offer setup before retirement assertions. The common failure is being
investigated; these results provide no packet-retirement acceptance. Evidence:
`.zig-cache/wave-7/retirement-scoped-v2-04-debug.log`. The earlier captured
artifact's authenticated packet-after-QUIT defect remains a release blocker
until a corrected executable passes the real transport harness.

These bounded findings leave all 98 roadmap targets in the acceptance inventory.
No additional target is accepted from these experiments, and no live service,
configuration, release tag or remote repository was changed.


The first fixed TLS candidate passed the named Debug gate with **1,007 passes
and 37 skips** (1,044 tests; no failures, leaks or logged errors). The expanded
v4 portable Safe gate completed with **1,005 passes, 37 skips and two failures**.
Both failures were adapter fixtures assuming AES-128 despite a negotiated
ChaCha suite. The HRR, policy and existing 0-RTT cases passed. A separate,
reviewed test-only overlay now verifies the actual negotiated kernel ABI, exact
key/IV/sequence, and a genuine client-generated KeyUpdate while retaining the
allocation-failure custody assertions. Its focused Debug gate passes **84/84**;
portable Safe execution remains pending. The matched performance snapshot is
unchanged by this test overlay. Evidence: `suite-policy-v3-tls-debug.log`,
`suite-policy-v4-tls-safe.{json,log}`, and `suite-policy-adapter-debug.{json,log}`
under `.zig-cache/wave-8/throughput-terra/`. No full Safe green is claimed.

The wizard now displays effective nonsecret choices in structured sections,
including profile changes with capacity overrides applied on both sides,
service selection, destination/action and readiness unknowns. Terminal control
bytes in displayed values are escaped, color can be disabled, and field output
is bounded to 38 columns. The parser/help corrections and review renderer are
applied in the primary source. The executable-root gate discovers both new
regressions: **4/4 pass**, including two root import tests, with no skips,
failures, leaks or logged errors; the non-test daemon semantic check also
passes. Immutable source hashes and receipts are under
`.zig-cache/wave-8/terra-wizard-review-v3/`. This verifies a bounded review
improvement; PTY interaction, the complete narrow-terminal flow, screen-reader
acceptance and the remaining wizard roadmap criteria are still unproved.


The [matched cipher-policy study](tls-cipher-policy-benchmark-2026-10-27.md)
completed all eight cases successfully. On the captured portable musl workload,
median continuous throughput rose 19.52%, daemon CPU per delivery fell 19.56%,
and p99 latency fell 16.76%; all three paired directions improved. Independent
review verified artifact and report hashes, the 1,218-input comparison and exact
delivery totals. The reviewed TLS source and suite-aware adapter tests are now
integrated in the primary tree; its non-test semantic check passes. These
workload-specific results do not certify general capacity, mesh performance or
release readiness. The earlier full Safe result remains recorded with its two
fixture failures; the corrected cases pass in focused Debug and portable Safe.
Fresh combined release gates remain required.

The review renderer now obtains Linux terminal width with a native ioctl and
uses bounded environment/default fallback on other paths. Its five-test
executable-root gate passes without skips, failures, leaks or logged errors;
the non-test daemon semantic check passes as well. This covers 20/38/80-column
review output, escape-token integrity, effective values and parser options.
The full banner/help/material-review flow and PTY/accessibility acceptance
remain outside that evidence. Receipts:
`.zig-cache/wave-8/terra-wizard-width/primary-{debug,check}.{json,log}`.


The client suite-offer seam now forces AES-128 explicitly in tests; previously
an alleged AES-128 helper left all suites offered and could negotiate ChaCha
under the new portable preference. New checks inspect the actual one-entry
ClientHello offer, the selected suite on both peers, and authenticated traffic
in both directions. The full selected TLS-client namespace passes **185/185**
in Debug and portable Safe, with no skips, failures, leaks or logged errors.
The source is integrated; its primary non-test check passes, and a separate
non-test compilation proves the new offer function is absent and its test flag
has `void` type. The patch also includes 49 explicitly reviewed compiler-format
enum-builtin rewrites; it is not described as a purely textual test-only delta.
Evidence: `.zig-cache/wave-8/throughput-terra/aes128-test-offer-v2/`.
The server's requested-versus-negotiated helper assertion remains pending.

A genuine baseline CLEAR dispatch reproduction fails all three new cases:
literal reasons lose their delimiter, empty reasons become a default command,
and oversized reconstruction can execute a truncated valid prefix. The first
fix draft did not compile because it addressed the underlying parser type
rather than the daemon's nested parser. Its initial source approval was
withdrawn after that finding. The corrected draft must retain explicit trailing
metadata in the actual live parser, preserve literal reasons, reject overflow
before planning, and pass the same dispatch and media packet tests. No CLEAR
fix or broader retirement draft is promoted from these failed runs.


The corrected retirement/CLEAR candidate now passes the complete selected
Debug gate: **139/139**, no skips, failures, leaks or logged errors, with
unchanged inputs (151.752 s total). It uses a fresh capture of all 1,219 current
source/build/tool inputs and exactly five candidate overlays. All seven native
cuts, seven ICE-bound RTC cuts, queued delivery, allocator faults, held-egress
survival, signed WS control/media, actual TOKEN-to-RESUME sibling isolation,
four CLEAR dispatch/parser regressions and three-suite helper contracts execute.
The initial combined run's sole WS failure was a fixture passing WS-framed
bytes to an IRC parser. The final fixture validates complete text frames,
reconstructs delimiters, reserves storage before credential copying and wipes
its temporary credential buffers; the existing issuance and resume paths and
all packet/authority assertions remain intact.

Receipt: `.zig-cache/wave-7/retirement-current-v2-13-debug.{json,log}`.
The exact cohort's native Safe gate is running; neither portable combined
acceptance nor real-daemon ingress, full DTLS/SRTP, mesh or release acceptance
is inferred from this local gate. The five source overlays remain unpromoted
pending Safe and integration checks. A guarded promotion plan preserves the
current baselines and requires explicit parent GO; afterward the real TLS/UDP
QUIT/EOF harness and complete ship gates remain required. All 98 acceptance
inventory targets remain intact.


### Wave 8 verification checkpoint — 2026-10-27

The exact five-file retirement/CLEAR cohort subsequently passed **139/139**
native Safe tests and was promoted under guarded baselines. A formatting-only
Domain follow-up passed its selected namespace in Debug and native Safe
(**107 passed, one Windows-only skip** each). The captured native Safe artifact
`873b31540f4e0f512679a9612444656f767874c9ffefbd97a11aad4f6481d094`
also passed the unchanged real TLS/UDP PART, KICK and QUIT regression harness;
the baseline reproduced post-QUIT packet delivery. These checks have their
local physical-endpoint and bounded observation scope; they do not establish
mesh-global media revocation or full DTLS/SRTP acceptance. Evidence:
`.zig-cache/wave-7/retirement13-promotion-plan/` and
`.zig-cache/wave-7/media-retirement-smoke/candidate13-v2-result.json`.

The later compiler-format migration changed 186 files under a reviewed token
audit. Whole-tree formatting and the primary semantic check pass. Its first
literal full Debug run ended with SIGTERM and empty ledger/log, with cause
unknown; it is incomplete evidence. A fresh literal full gate is running under
an independently reviewed process monitor. No complete current-source suite
count or release acceptance is claimed until its completed ledger is inspected.
Evidence: `.zig-cache/wave-8/compiler-format-audit/` and
`.zig-cache/wave-8/full-gate-supervisor/run-01/`.

Terra 6.1's PTY acceptance helper passed against the captured artifact above:
review sections at actual terminal widths 20/38/80, private draft save/resume,
and redirected behavior. This is not whole-wizard accessibility or post-format
runtime acceptance. Evidence: `.zig-cache/wave-8/wizard-pty/run-01/result.json`.
A separate private three-node non-clique pilot failed during account setup,
before any upgrade phase; it provides no three-node upgrade acceptance.
Evidence: `.zig-cache/wave-8/linux-helix-nonclique/run-01/result.json`.
All 98 acceptance targets remain in scope.


The three-node diagnostic localized the failure to the helper's accepted-socket
census, after accounts and session resumes succeeded. A reviewed tcp6-aware
correction retained exact tuple/inode/process-owned-FD requirements and passed
six parser tests. The subsequent private A–B–C pilot passed all four phases:
38 events / 184 exact deliveries, final links 1/2/1 and adoptions 1/1/0, including
a fifth resume on C and retained physical attachments. Astra independently
accepted the bounded result and cleanup. Evidence:
`.zig-cache/wave-8/linux-helix-nonclique-v3/run-01/result.json`.
The stronger wizard v2 pilot also passed independent dumb-terminal and
NO_COLOR checks and actual use beyond 38 columns at width 80; independent
review accepted those bounds. Evidence:
`.zig-cache/wave-8/wizard-pty-v2/run-01/result.json`.
Both runs use captured artifact873b before the compiler-format migration;
current-source, historical-upgrade and release acceptance remain unproved.


### Wave 9: diamond continuity and privacy correction

A private four-node diamond passed six participation phases, including
sequential A/B/C/D same-image handoffs and original-portable fifth resume on D:
**56 events / 266 exact deliveries**, two secured link establishments and one
adoption per node, retained client and daemon-owned accepted socket identities.
Fresh review accepted the bounded result and completed cleanup. Its initial
preflight failure was a helper self-trust duplicate; neighbor-only trust roots
fixed the fixture while preserving the full relay roster and all validators.
Evidence: `.zig-cache/wave-9/linux-helix-diamond-v2/run-01/result.json`.

A separate privacy audit found a real public WHOWAS address disclosure:
`whowasRecordedHost` records realHost, and numeric 314 exposes it to an ordinary
requester despite a visible cloak. The existing test explicitly expects this
leak. This is a source-proven release blocker; a visible-host-only correction
and nonvacuous regression corpus are staged separately, not yet integrated or
runtime-accepted. See the [follow-up audit](../audit/onyx-astra-investigation-2026-10-27.md#follow-up-privacy-audit-public-whowas-address-disclosure).

The new offline doctor cloak-comparison candidate passed fresh source review
for isolated compilation after adding a scoped wiping allocator for failure
paths. Its CLI harness passed independent review and three pure sanitizer mock
tests; actual CLI and Zig allocation-failure gates remain pending. No current
runtime peer compatibility or new M09 acceptance is inferred. Actual source
remains frozen while the literal full Debug gate continues.


### Wave9 source integration and subsequent full-gate findings

The monitored literal full Debug gate completed on the preceding source cut:
**10,473 passed, 323 skipped, eight failed / 10,804 total**, with unchanged inputs
in 2,880.331 s. The module root contributed 10,376 passes, 323 skips and eight
failures; executable and CLI roots passed 43 and 54 respectively. Receipt:
`.zig-cache/wave-8/compiler-format-audit/full-debug-observed.json`.
This supersedes the incomplete SIGTERM attempt; it is a complete red gate.

Two failures occur in fixture setup before openat2/Landlock/seccomp assertions;
`/tmp` has zero available bytes while the project-private temporary directory
has capacity. Exact fresh-process indexed replays reproduce both failures.
Five media failures are now traced to native crypto attachments lacking the
browser-only channel binding used by retirement, suppressing required DETACH
notifications. The fresh project re-handshake gate locates the fifth failure
at MEDIA LEAVE. A sixth WS fixture lacks the real Domain membership required
by the new admission guard. These findings require separate fixes; timeouts,
security assertions and authority guards are retained.

The wave9 privacy/configuration cohort subsequently passed **96/96 module tests
in both Debug and Safe**, **4/4 executable tests in both**, and the non-test
semantic build. The initial positive configuration fixtures missed required
node IDs; fixture-only corrections retain all assertions and production logic.
Native artifact43d703 passes all four unchanged WHOWAS TLS cases against the
older artifact's specific baseline mismatch, plus the actual cloak-comparison
and proxy-validation CLI harnesses. Fresh independent review accepted the
pinned receipts and cleanup.

All four source files were then promoted under exact old/new hashes and modes;
the other 1,215 input entries remain unchanged. Primary whole-source formatting,
touched-file whitespace checks and semantic build passed after promotion.
Receipts: `.zig-cache/wave-9/source-promotion/` and
`.zig-cache/wave-9/combined-candidate-v2/`. P10 and M09 advance to partial.
The current source has not yet passed a new complete suite. Wave10's dedicated
crypto provenance and funded publication-obligation draft remains unpromoted;
Windows mandatory transfer state and pending-notification ordering require
independent review and runtime gates. Release and deployment remain pending.


The integrated current-source artifact43d703 also passed the unchanged diamond
and wizard PTY pilots. The diamond retains 56 events / 266 exact deliveries
through all four sequential same-process handoffs and original portable fifth
resume; PTY checks retain all six width/color/private-draft/redirect assertions.
Fresh review accepted pins and cleanup. These replace the earlier pre-format
runtime qualification only for the tested private same-image and wizard-review
scopes; full release, historical compatibility and active media remain open.


### Configured cloak validation acceptance

The next config-only promotion rejects wrong parser types in cloak settings,
unknown resolved modes, and failed references with value-redacted field errors.
Omitted settings and the fourteen-day default are preserved. Native candidate
`83733d1444ded3e8be826d22eac6a9f589d4f3df37b9c61615b9f6f6b376ad3f`
passed 89/89 module and 7/7 executable tests in both Debug and Safe, the non-test
check, and 39 offline CLI invocations. The identical CLI oracle fails against
artifact43d703 at the first numeric-secret fixture. Windows, OpenBSD, and
ARM64-musl checks pass at compile scope. Fresh review accepted P05 for the
audited configuration and key-derivation paths, with the detailed limits in the
[acceptance ledger](roadmap-acceptance-ledger-2026-10-26.md).

The one-file promotion verifies all 1,219 source/build inputs against the tested
candidate; the other 1,218 byte/mode entries remain unchanged. Evidence is under
`.zig-cache/wave-11/`. No live configuration, deployment, commit, or push occurs.
The media cohort remains separate: its local collision guard does not establish
mesh-wide ownership of a reused signed attachment envelope. Global closure
requires a versioned physical-owner contract or serialized ownership authority,
plus a real concurrent two-node regression. The full release gate remains open.


The [physical media owner proposal](../design/media-physical-owner-namespace-2026-10-27.md)
chooses signed owner-qualified messages for that mesh gap. It defines physical
incarnations, targeted key wraps and retirements, strict transfer state, explicit
compatibility boundaries, and partition/merge falsification requirements. This
is a design artifact, not implemented wire support or V09 acceptance.


### Media source integration, 2026-10-28

The reviewed nine-file cohort is now in source: eight existing files changed,
one dedicated crypto-scope module was added, and the other 1,211 input entries
remain unchanged. The complete 1,220-file inventory matches manifest
`65c8cb8794b8433843ede63650cfd70b55a901719fac673caca0fb4802debd98`.
The sole integrator executed the reviewed hash/mode-guarded promotion with eight
private backups. Kernel mode remains `0600`. The actual-tree semantic check,
whole-source formatting, and touched-file whitespace checks passed.

The cohort separates physical crypto provenance from browser routing, retains
funded lifecycle-publication obligations after connection removal, acknowledges
only accepted publication, and preserves per-channel ordering with bounded
fair retries. Original post-WAL geometry preparation can still allocate and
retry under the existing denial fence; this is not an assertion that every
allocation or signature runs outside World. Local duplicate-tuple admission
and Windows snapshot validation reject ambiguous crypto ownership. ASCII
channel identity now agrees across all ten media room metadata maps, cleanup,
and snapshot cross-links, while participant suffixes and stored spelling remain
byte-exact. Conflicting snapshot aliases fail before restore publication.

Focused evidence is **244 passed / 2 expected platform skips / 0 failed** in
both Debug and Safe, plus **123/123** narrow tests. The eight earlier full-suite
failures are covered and pass in this focused gate. Native, Windows, OpenBSD,
and ARM64-musl semantic checks pass; cross-checks are compile-only. Windows
mandatory transfer state uses HXMG2/private process v21. Linux active-media
inheritance and historical compatibility remain unaccepted.

Captured native artifact
`fa0e5f0be52286f2fba3c6eba0a3d1904fbd58a866a77a51cf4a5ab4672eabcb`
passes the unchanged TLS/native-UDP PART/KICK/QUIT oracle, four WHOWAS TLS cases,
the six-check wizard PTY pilot, and the existing doctor/proxy/cloak CLI harnesses.
The unchanged four-node diamond preserves 56 accepted events / 266 exact
recipient deliveries through all four same-image execs and original-credential
fifth resume. This is private same-host legacy-portable evidence; it does not
prove SRM2, old-image migration, active media handoff, or deployment.

The packet harness itself exited zero with all three cases passing. A separate
wrapper incorrectly expected a boolean where its existing schema records
`"eof"`; both original reports are retained, and the corrected validation checks
that exact marker precedes fresh UDP. No runtime oracle was changed or rerun.
Receipts and pinned artifacts are under `.zig-cache/wave-14/`.

Fresh independent review approved source integration only. The literal full
Debug suite finished red after 2,915.943 seconds: **10,521 passed, 324 skipped,
five crashed / 10,850 total**. Module counts are 10,423 passed / 324 skipped /
five crashed; executable and CLI roots passed 44 and 54 tests. The terminal
ledger records unchanged inputs and exit 1; its log hash is
`83801926dec0b47b0667dc9fa367920ab10907f2bb99b84a77cf3618828acc18`.
The supervisor has no remaining owned processes, and the parent independently
checked process exit and all 1,220 source hashes/modes. Evidence is under
`.zig-cache/wave-14/actual-full-debug.{json,log}` and the reviewed supervisor.

The five crashes are teardown failures in the node-identity media handshake
fixture and four protected MEDIA complete-departure fixtures. Fresh source
review identified manually installed browser bindings without matching routing
custody in the server's actual Domain; the last three traces explicitly refuse
that inconsistent census. A private fixture correction is being prepared with
the strict retirement check and existing departure, sibling and OOM assertions
retained. The first two causes still require focused confirmation. This full
run supersedes the earlier focused green result for release readiness.

Work is split across GPT-6 Astra for independent security review, GPT-6.1 Sol
for integration, and GPT-6.1 Terra for bounded leaf changes. A separate private
migration candidate replaces a second equivalent token signature with an owned
clone; its isolated Debug gate passed 104/104 tests, including independent
original-frame equivalence and exhaustive preparation allocation failures.
The initial absolute-path ledger invocation tested the unchanged baseline
(103/103); that record is preserved and is not candidate evidence. The corrected
candidate run uses the ledger helper inside the isolated snapshot. Safe testing
then finished red: 103 passed / one failed / 104 total, with no leaks or log
errors. The existing case-variant migration replacement OOM campaign reported
`NondeterministicMemoryUsage`; the new equivalence test and preparation OOM
campaign passed. The matching original-source Safe run passed 103/103; the candidate replay
repeated its failure. A private diagnostic distinguishes the target and origin
sweeps before any corrective change. All reports are retained; this candidate
is unaccepted and no speedup is claimed.

Remote CHGHOST and cross-node crypto ownership remain separate open contracts.
No production configuration, service, binary installation or Git operation has
occurred.

The first reviewed media fixture repair confirmed the native-handshake case in
focused Debug testing, then exposed orphaned actual-Domain credits in the next
fixture. The fixture had used live admission to populate metadata but retired
those rows against a separate test Domain. A second private correction stages
validated owned metadata directly; strict production census and destruction
checks remain unchanged. This second candidate passed 85/85 focused tests in
both Debug and Safe, including all five original crashes. The reviewed
single-file correction is applied: all 1,220 files match manifest
`a0f6ba12939c870f7f1c552bbbc814689c65ae98a6145d0423fe50f636854eaf`,
with only the server fixture file changed. Parent formatting, whitespace and
actual semantic checks passed. The fresh literal full Debug run finished red
after 2,831.045 seconds: 10,525 passed / 324 skipped / one failed / 10,850 total,
with no crashes. All five earlier crash cases are resolved. The remaining
failure is the four-client reusable-session/MARKREAD test across sequential
secured-mesh Helix upgrades. The log does not identify its phase; stale
`ParseFailed` frames are not a cause diagnosis. The exact test is being replayed
with recorded seed `0x5d0896e8` before any correction. Inputs stayed unchanged,
log hash is `31ede1935265e74a071dd1ed6456a42d8d90deb8cb6b39de13e5517dfb9be2b0`,
and supervisor/ledger/test processes exited with no remaining owned rows.
Evidence remains under `.zig-cache/wave-15/full-gate-supervisor/run-01/` and
`actual-full-debug-after-fixture-v2.{json,log}`. No live binary, configuration,
service or Git operation occurred.

The private signed guest-membership foundation passed 221/221 Debug tests after
a mechanical local-variable rename. Coverage includes manifest/chunk signature
and canonical-name validation, v3 presence binding, complete-set assembly,
allocation failures, allocation-free equivocation revocation, aggregate and
peak budgets, simultaneous prepared transactions, and existing World tests.
The same snapshot passed 221/221 Safe tests, with no skips, failures, leaks or
log errors in either mode. These modules remain private and unadvertised: live
owner callbacks, transactional authoring, transport/notification custody and
mandatory Helix continuity are not implemented or accepted. Remote common-
channel CHGHOST remains open.

The subsequent private guest owner and independent fault pair passed 106/106
narrow Debug tests, then 245/245 combined owner/membership/World tests in
both Debug and Safe, with no skips, failures, leaks or log errors. Independent review caught and corrected an omitted
future-skew check on claim HLCs before these gates. The module owns signed v3
originals, checked policy and transaction identities, real World-lock cuts,
allocation-free conflict revocation and a funded FIFO of identity transitions.
Tests exercise existing FIFO preservation across C-transition OOM, exact signed
endpoint dependencies, policy/local-shadow changes, interrupted-plan cleanup
and counter exhaustion. This remains private: live producer, dependency pins,
recipient selection, delivery, settlement/GC and strict Helix carry are open.
It does not fix remote common-channel CHGHOST yet.

The remaining full-suite Helix matrix failure passed an unchanged focused
81/81 replay and an 82/82 native-handshake-plus-matrix replay with the recorded
seed. Those successes do not explain or waive the full RED. A cache-only
phase/error/resource-count diagnostic is being prepared without changing the
matrix assertions or deadlines.

The reviewed matrix diagnostic passed 82/82 focused-pair tests in Debug and Safe.
Entry counts in this focused context are four descriptors (including its own
counting directory) and one task. A completion marker precedes cleanup and is
not independently a passing verdict. The instrumentation preserves all 49
original target assertions and all timing, retry, drain and capture statements.
It is now the only subsequent actual-source change: manifest
`a1aa92d7469a654302fa6dd3b8379594d35a05c81a197093773cf5652a5c65c8`,
1,220 files. Formatting, whitespace and actual semantic checks passed. The
actual full suite replayed seed `0x5d0896e8` and passed after 2,840.501 seconds:
10,526 passed / 324 skipped / 10,850 total, with zero failures or crashes.
The module root passed 10,428 with 324 skips; executable and CLI roots passed
44 and 54. Source stayed unchanged; log hash is
`15c38ffe8f621b0842a47ee9ca2d4276182ea9449e4c5659474e30d2634ae81e`.
Supervisor/ledger/test processes exited with no owned rows; parent independently
verified process exit, log hash and all 1,220 current source hashes/modes.
Evidence is under `.zig-cache/wave-17/full-gate-supervisor/run-01/` and
`actual-full-debug-helix-diag-seed5d0896e8.{json,log}`.
The matrix entered with 211 descriptors and one task, versus four descriptors
in its focused diagnostic context, and passed all assertions and cleanup.
Diagnostics do not explain or fix the previous full-context failure. The prior
RED remains retained and unexplained; resource counts are not causal/leak proof.
No live binary/configuration/service or Git operation occurred.

The next private physical-classification pair passed 94/94 tests in Debug and
Safe. It combines a complete account-independent SessionStore census with a
Core-owned lexical witness that rechecks actual reactor/World ownership,
physical generation, registration, account and transition/DROP state. Three
independent fault cases are included alongside internal tests. The model
fixtures do not prove network registration, issuer publication or live V3
activation. A private structural mesh-probe codec separately passed 84/84 tests
in both Debug and Safe. Neither candidate is promoted or advertised.

The execution cohort in `.zig-cache/execution/cloaking-wave/` now combines the
previously tested owner, physical witness and probe code with a durable local
guest binding implementation. Configuration explicitly opts in through
`[guest_presence] issuer_path`; offline provisioning uses
`--initialize-guest-issuer <config.toml>` and never starts listeners. Missing
configured state is not silently initialized. Exact-generation retirement
reclaims unpublished rows without refunding durable identity counters.
Independent bounded review found no blocker in these stable leaves, the
provisioning command or configuration mapping. Live registration and lifecycle
integration is still being written; the combined cohort has not compiled or
been promoted. Mesh publication, moderation continuity and strict upgrade
acceptance remain required before claiming the cloak workflow complete.

The combined registration checkpoint passed 103/103 Debug tests with zero
skips, failures, leaks or log errors. Review caught and the checkpoint fixed
two integration defects: deferring existing admission policies behind optional
binding preparation, and retaining superseded captured facts indefinitely.
Real parser regressions cover WARD/DNSBL/SACCESS/class refusal and recovery
after NICK with a burned reservation and exactly one welcome. Broader guest and
presence campaigns, Safe verification and executable provisioning tests remain
pending; this focused pass does not establish mesh publication acceptance.

The changed cohort subsequently passed 183/183 Safe tests, and the Debug
executable passed all six offline provisioning smoke groups. A later review
found that binding-lock contention during close could strand a quiet physical
attachment. An explicit owner-timer retry now retains close custody and uses
the existing teardown fences. The revised checkpoint passed 104/104 Debug
tests, including forced contention for reserved and committed states followed
by maintenance with no client traffic. The final retry delta then passed 87/87
Safe tests, unchanged, in 268.134 seconds. The final Debug executable rebuilt
and passed the six provisioning smoke groups again.

The 19-file cloaking cohort (eight new files) is now integrated into actual
source alongside the separate migration-token improvement. Independent parent
verification checked all 1,228 inputs against the expected baseline plus these
changes, preserved all other contents/modes, and passed formatting/whitespace
checks. Source manifest:
`e70629a26a8a5b25a55afdff327a942f0365d1f19b57a4993c8b631da719e9f3`.
The actual combined cloak/token selection passed 129/129 tests in Debug and
Safe (13.755 and 290.779 seconds), unchanged, with zero skips, failures, leaks
or log errors. Receipts and complete logs are under `.zig-cache/wave-19/`.
This closes the focused integration gate, not the full roadmap, mesh
publication, strict upgrade carry, reproducible release or deployed acceptance.

The controlled migration-token baseline and clone candidate each passed 105/105
Safe tests with the same allocator wrapper (161.798 and 165.307 seconds,
respectively). This characterizes that allocator path; the original candidate's
allocation-sweep failures remain recorded. The transparent-allocator
microbenchmark passed 81/81 Safe tests for both variants. Five measured batches
of 32 preparations yielded median wall times of 9.026 ms for the baseline and
4.822 ms for the candidate (46.57% lower), with identical complete-frame hashes.
Allocation calls fell from 2,502 to 2,406; peak requested live bytes remained
21,150, with zero retained bytes after cleanup. This is a focused preparation
benchmark, not daemon capacity or RSS evidence. A second alternating
baseline/candidate pair also passed 81/81 Safe tests for each variant. Across
ten measured batches per variant the median was 9.546 ms versus 4.823 ms
(49.47% lower), again with identical complete frames and zero retained bytes.

Fresh review accepted the harness correction: declining resize/remap makes
growth take explicit injected allocation paths while retaining rollback, retry
and balance assertions. The original nondeterministic sweep failures remain
recorded. The production clone change and corrected harness are now integrated
into actual `src/daemon/helix/migration_relay.zig` at
`a2759855b391eacfe2b969f76c46ef2b79417d04323a6beb99c7b7a29c33f615`;
actual-source Debug passed 105/105 tests in 10.982 seconds, unchanged, with zero
skips, failures, leaks or log errors. The earlier full green result
applies to its recorded baseline, not this subsequent source change.

The next private execution wave joins shared service-environment reporting with
ordinary-stop descriptor custody. Setup and doctor use one bounded marker
detector; explicit operator service choices remain authoritative and marker
evidence does not imply daemon readiness. Its Debug fixture passed 87/87 tests.
Executable checks caught and corrected an ordinary-doctor renderer bypass and
a stale PTY prompt trigger; all 32 setup smoke cases and the doctor smoke now
pass. Native Alpine runtime acceptance remains separate.

The real io_uring baseline reproduced an uninstalled accepted socket remaining
open after ordinary teardown (87 passed / one failed); its Helix control passed.
The candidate drains exact original ACCEPT completions before destroying their
storage, closes every positive result, and retains strict Helix behavior. All
four real-ring cases passed in Debug, including forced one-shot, probed
multishot, full-SQ cancellation retry and complete copied-batch closure. A joint
shutdown/guest selection passed 107/107 tests in both Debug and Safe (11.706
and 348.769 seconds), unchanged, with zero skips, failures, leaks or log errors.
The merged cohort then passed 108/108 Debug tests, rebuilt its executable and
passed all 32 setup cases plus the doctor smoke again. Its eight files (one
new) are now integrated into actual source. Parent independently verified all
1,229 inputs against the expected baseline plus these changes, preserving all
other bytes/modes and passing formatting/whitespace checks. Manifest:
`c9b5cd81463825bb7dbdec5e47b1ed9b46d238b86db16dfeb0453584dfd4c4d3`.
Actual combined verification passed 134/134 Debug tests. The subsequent full
Debug gate at this exact source passed 10,615 tests with 324 skips out of
10,939, with zero failures or crashes, in 2,841.833 seconds. Module counts were
10,517 passed / 324 skipped / 10,841 total; executable and CLI roots passed
44 and 54. Seed: `0x5d0896e8`. Parent verified all 1,229 input hashes/modes,
the matching log hash, terminal supervisor ownership and process cleanup.
Evidence: `.zig-cache/wave-20/actual-full-debug-seed5d0896e8.{json,log}`;
log SHA-256 `ca1e3991937c02e1ac3d283cc95642b54ca364c0b6d70d673c2ff168b3ab7ab4`.
The matrix entered with four descriptors and one task, and completed all its
original assertions. The descriptor count is descriptive; neither it nor this
pass establishes the cause of the earlier full-suite failure. Reproducible
release and deployed multi-node acceptance remain separate.

Subsequent actual-source changes include receipt tooling: optional scoped
test-count evidence in `gate_ledger.py`, with 14 private and 14 actual Python
unit tests passing. The original full-gate receipt and exact source cut are retained. These
independently tested Python changes do not require a native suite rerun.

The pinned merged artifact also passed native Alpine non-root startup, IRC
registration/PONG, SIGKILL restart with stable identity, backup/restore, private
key ownership/mode and immutable-config checks. Its native diagnostic smoke
passed real IRC/PONG/QUIT, private-log redaction, event metadata and bounded-line
checks. These do not establish actual service supervision, complete log-rate
exhaustion, TLS/DNS/IPv6/UDP/WebTransport or mesh runtime acceptance. Receipts:
`.zig-cache/wave-21-alpine-runtime-v1.json` and
`.zig-cache/wave-21-alpine-diagnostics-v1.json`.

The reviewed mesh record optimization is now integrated in two production
files. It authenticates into owned receive storage, copies accepted plaintext
into the decoder, wipes consumed plaintext, and prevents further use or capture
after a failed record attempt. Its focused Debug and Safe gates each passed
110 tests with one opt-in benchmark skipped; actual-source `zig build check`
also passed. Matched native-SMP measurements used two runs per variant, two
warmups and seven samples per run, with identical wire hashes. Median CPU time
fell 5.33% for 64-byte records and 13.06% for 1,048,556-byte records, while
outer record allocations fell to zero. This measures authenticated opening and
inner unknown-frame decoding, not network or daemon capacity. Evidence:
`.zig-cache/wave-21-record-benchmark-summary.json` and
`.zig-cache/wave-21-mesh-actual-check-v1.json`. The latest 1,229-input manifest
is `46de20fa35a10be17eaf2938e29614e4768a84dd9954ec9d4ca43aa08c2e4de3`;
the earlier full-suite pass applies to its recorded source, with these later
changes supported by their focused checks.

The isolated Alpine 3.24.3/OpenRC 0.63.2 guest exposed a packaged policy bug:
Alpine global defaults populated the variables before the init script's shell
defaults, yielding an effective 2-second delay, five respawns and 1,800-second
period. The shipped conf.d asset now explicitly sets the intended 5/3/60
service policy; operators customize those values in their service conf.d file.
Existing operator files must be preserved during upgrades. No live file was
changed. After independent review, the candidate passed real OpenRC supervision
in a network-isolated QEMU guest with host CPU passthrough: invalid config
refusal, exact supervisor/child identity and ownership, IRC readiness, four
actual kills at guest uptime 8/14/20/26 seconds, explicit budget exhaustion and
supervisor termination, explicit restart/recovery PONG, and stop cleanup.
All copied input pins remained unchanged and QEMU was reaped. Receipt:
`.zig-cache/wave-21-openrc-qemu-v10.json` (41.988 seconds). The validated conf.d
bytes are now integrated; latest manifest:
`c7849a27686830f04bdc73130c8faa2fc1f7581232bc58c54703d7e8e58e564a`.
This uses the pinned c9b native artifact and establishes service supervision,
not newer mesh source runtime or rolling mesh/Helix acceptance.

Wave22 remains private. Its combined Debug selection passed 309 tests with
one opt-in benchmark skipped (68.988 seconds); the additional identity-order
selection passed 91/91. Fresh review confirmed native old-cloak fresh JOIN
denial, same-USER/different-IP admission under a wildcard-nick mask, and unban
recovery. The combined Safe selection passed 312 tests, skipped that benchmark,
and timed out in the existing reusable-session participation test. That failure
remains a release blocker. The isolated Safe diagnostic version passed with all
66 original waits and 49 assertions retained; it does not explain the failed
ordered suite. Evidence: `.zig-cache/wave-22/combined-{debug-v2,safe-v1}.json`,
`identity-order-debug-v1.json`, and `session-mesh-safe-diagnostic-v1.json`.

The next private carry components are also bounded evidence: physical-ID
relation and presentation snapshot codecs passed 97/97 Safe tests together.
An additive `test-helix-carry-leaf` target imports only those leaves and the
native socket identity validator, preserving the default integration/release
graph. All 18 tests passed in Debug (3.331 seconds) and Safe (28.567 seconds),
including actual duplicated/SCM_RIGHTS socket aliases, distinct sockets, bounded
malformed input and allocation cleanup. The broader-root two-codec Safe gate
took 181.2 seconds and includes unrelated module initialization; these are
different scopes, not equivalent integration gates or daemon throughput claims.
The build step and leaves are not yet promoted. Core physical seal/adopt
integration is underway; presentation/frontier, typed delivery registry,
departure images, retained ingress and local issuer carry remain required
before claiming successful Helix preservation. Receipts are under
`.zig-cache/wave-24/`; original-artifact ordered replay remains separate from
validation of the newer diagnostic source.

The presentation and physical carry integration now passes the broader private
Helix Debug gate: 1,094 passed, 77 platform skips, zero failures, leaks or log
errors (1,171 total), with unchanged source. This includes the unchanged native
two-node sequential capture/adopt case that previously failed on retained remote
presentation. Receipt: `.zig-cache/wave-27/helix-debug-v1.json`. Safe verification
is pending. Accepted output under backpressure, pending ingress and local issuer
custody remain open; this is not full pressure or release acceptance.

The public WHOIS identity formatter fix is integrated in the working source
after 29 Debug and 29 Safe tests and fresh independent review. It preserves
accepted non-ASCII nick/host bytes while retaining existing ASCII exclusions
and bounds. Private test build changes were not promoted. Receipt:
`.zig-cache/wave-30/actual-integration.json`.

The W27 broader Safe gate also passed: 1,094 tests, 77 platform skips, no
failures, leaks or log errors, unchanged source (702.038 seconds). After fresh
aggregate review, 14 physical/presentation carry and cloak notification files
were promoted into the working source; the newer WHOIS fix and all unrelated
source bytes/modes were preserved. Touched-file formatting passed. The combined
actual-source build check is pending. This does not remove the remaining
pressure/ingress/issuer capture refusals or certify a release. Receipts:
`.zig-cache/wave-27/helix-safe-v1.json` and
`.zig-cache/wave-33/actual-integration.json`.

The actual combined-source daemon build check passed in 10.995 seconds with
unchanged inputs; supervisor cleanup was complete. W32 issuer custody also
passed its first private focused Debug gate: 246 passed, 69 platform skips,
zero failures/leaks/log errors, including six real hot-custody/fault tests.
Those tests cover exact epoch/frontier preservation, old-writer retirement,
reopened lease refusal, stale generations, allocation ownership, poisoned
source refusal, and unchanged WAL bytes after rejected staging. Its Safe gate
and cross-exec Core integration remain pending. Evidence:
`.zig-cache/wave-33/actual-check-v1.json` and
`.zig-cache/wave-32/issuer-debug-v1.json`.

The issuer leaf is integrated after both 246-pass/69-skip Debug and Safe gates
and fresh review. A combined actual-source Debug gate passed 131/131 tests,
including WHOIS, issuer custody and the real two-node sequential upgrade.
`.zig-cache/wave-33/actual-combined-debug-v1.json` records that exact source.

Private spool barriers passed 89/89 focused Debug tests and 111/111 Safe tests
(the latter includes all 25 spool tests plus unrelated initializers). The
additive isolated harness ran the same 25 spool test names plus its root in
3.640 seconds Debug and 32.537 seconds Safe, versus 166.048 seconds for the
broader Safe graph. These are one recorded run per graph with different
integration scopes; full gates remain required. Only the additive target and
root are integrated; the barrier implementation awaits coherent Core wiring.
Evidence: `.zig-cache/wave-37/scope-comparison.json` and
`.zig-cache/wave-37/actual-integration.json`.

The binding carry gate exposed a stale test-local DeltaStub enum missing the
identity variant already handled by production. The sole server writer added
that variant without changing assertions or production; independent review
approved it. The corrected private binding gate passed 62/62 Debug tests,
including retired-owner cleanup, duplicate lease lifetime and fault tests.
Successful cross-exec owner activation and Core latch associations remain open.
Evidence: `.zig-cache/wave-34/binding-debug-v2.json`; the original compile
failure is retained as `binding-debug-v1.json`.

W40 fixes actual Helix descriptor custody after `recvmsg`: errors close received
rights, EINTR reuses the funded body, and truncated payloads fail closed. Seven
Debug and seven Safe tests passed, using real SCM_RIGHTS and pipe EOF to detect
leaked received writers. The source and additive leaf gate are integrated; the
actual daemon check plus seven actual-source tests passed. EINTR is reviewed
in source but not signal-injected. Receipt: `.zig-cache/wave-40/actual-integration.json`.

W38 integrates the shared media assessment into interactive setup review,
headless text, and additive JSON. Twenty Debug and twenty Safe tests passed.
The original Safe allocation-count failure is retained; an indexed diagnostic
measured remap-dependent allocation variation, and independent review approved
a test-only deterministic backing allocator while preserving the original
callback and every allocation cut. This does not establish the exact cause of
the original artifact failure or change the production allocator.

Native Debug artifact `223080d1a66b1170ac2d23b03b444fa22c4cceec0397f21fa76e428372cccb0c`
passed four PTY/headless parity cases in 2.574 seconds with unchanged inputs and
complete process cleanup. The four source/tool files are integrated; the combined
actual daemon check plus 29 executable-root setup tests passed. These are
configuration explanations, not media reachability or full W08 acceptance.
Evidence: `.zig-cache/wave-38/native-media-v1.json`, `actual-integration.json`,
and `actual-check-setup-debug-v1.json`.

The private W36 live departure owner now passes 111/111 focused Debug tests,
including exact CHGHOST→QUIT retry output and six plain/WS/TLS/WSS combinations.
A missing QUIT found in the preceding 110-pass/one-failure run was corrected by
servicing newly installed images at the end of the existing retry pass; no output
assertion or deadline changed. Generic publication, fabric predecessors, and full
pressure-state checkpoint carry remain open. This Core candidate is not promoted.
Evidence: `.zig-cache/wave-36/departure-debug-v3.json`; earlier REDs are retained.

W39 now has a successful real fresh-exec owner fixture: the original signed
issuer metadata/frontier, owned binding bytes and actual SCM_RIGHTS lease pass
to a fresh successor; predecessor retirement/reclamation and process exit occur
before successor activation. The retained unreserved ticket, stale generation
refusal and lease continuity assertions passed. Initial runs failed before IPC
because the helper constructed the large Core by value; bounded private stderr
logs identified that path, and final-address heap initInPlace corrected it.
The original failed receipts remain. This is fixture-controlled owner transfer,
not production capsule authentication, actual client FD mapping/latch carry,
or witness-backed reserved-GuestID acceptance. Receipt:
`.zig-cache/wave-39/binding-native-v3.json`.

The real maximum-253 SCM_RIGHTS success boundary passed eight-test Debug and
Safe leaf gates, then the appended test was integrated and the actual eight-test
Debug target passed. It checks exact payload, valid distinct delivered FD
numbers, writes through every deliberately aliased endpoint, and final pipe EOF.
Production receiver code is unchanged by this test delta. Receipt:
`.zig-cache/wave-40/actual-max253-integration.json`.

W44 World batching passed 58/58 in Debug and Safe. The first composed W45
publication runtime gate passed 114 and failed three new cases; omitted fixture
authorization/startup hooks were diagnosed rather than bypassed. Independent
review also found a real retained-publication deadlock on duplicate-link
replacement. The private Core remains blocked from promotion while that
ownership lifecycle and the remaining integration cases are corrected.
Evidence: `.zig-cache/wave-45/publication-debug-v2.json`.

W46 extends the successful cross-exec binding fixture with actual Core witnesses
from real loopback IRC registration and durable reserved GuestIds. The original
reservation survives fresh exec and repeated same-ticket reserve calls without
advancing epoch or counter; a distinct successor witness receives the next
counter. The inherited lease, original issuer image and controlled predecessor
retirement/reaping remain checked. Source review and build passed; the native
fixture passed with input hashes unchanged and owned processes cleared. This
is owner/counter stability under trusted fixture control, not production client
socket migration or bearer-token recovery. Receipt:
`.zig-cache/wave-46/binding-native-v1.json`.


W45's v5 private composed gate passed 118 and failed two of 120 tests,
with unchanged inputs and no leaks or log errors. The remaining failures cover
legacy establishing-owner admission and duplicate-link predecessor retirement.
Fresh review also identified a capture/adopt admission gap for a refused
final-flight connection with retained reply bytes. The Core candidate remains
unpromoted. Evidence: `.zig-cache/wave-45/publication-debug-v5.json`.

W47's isolated HPC2 physical-owner role codec passed four Debug and four Safe
tests and independent leaf review. It rejects HPC1, malformed/unknown roles and
role substitution against independent expected owners. The codec is overlaid
only into private integration contexts. Caller-derived canonical admission,
transactional capture/adopt, exact capability evolution and real continuity
remain integration gates; the leaf does not establish those properties.
Evidence: `.zig-cache/wave-47/physical-debug-v1.json` and
`.zig-cache/wave-47/physical-safe-v1.json`.


W48 integrates additive throughput reporting: phase p95 and per-client negotiated
TLS version/cipher, with unknown/partial/mixed observations retained. The existing
exact delivery ledger, barriers and timing boundaries are preserved. All 24
offline tests passed under the input-bound supervisor; fresh review approved the
two tool files, and guarded promotion verified every other source input unchanged.
No daemon performance gain is inferred. Evidence: `.zig-cache/wave-48/offline-v1.json`
and `.zig-cache/wave-48/actual-integration.json`.


W49 integrates the redacted `cloak_anon_cadence` doctor check. Text and JSON
identify the effective fourteen-day, daily, custom or disabled anonymous cadence
and account-cloak configuration; daily settings request an operator migration
decision. Valid choices do not become validation failures, and the check changes
no settings. Independent source review, 88/88 Debug tests, 88/88 Safe tests and
the daemon compile check passed. Allocation-failure cleanup and secret omission
are included. Guarded promotion verified the other 1,235 inputs and modes unchanged.
P01 remains partial: this diagnostic does not prove cross-node rotation or
moderation continuity. Evidence: `.zig-cache/wave-49/actual-integration.json`.


W45 v7 passed 154/155 Debug tests; v8 passed 152/155 after additional transition
provenance coverage. Both are private candidates with unchanged gate inputs, no
leaks or log errors, and retained failed receipts. Independent review established
that final candidate roster state cannot prove an earlier queued transition; v8
therefore captures immutable authenticated origin/HLC/token provenance and wipes
the copied token on destruction. Review confirmed those earlier counterexamples
closed, then found a stale PART across replacement that still needs routing
authority preservation. Runtime also found extra MODE output and a real-socket
predecessor-wire timeout. These remain promotion blockers; passing the separate
HPC2 rejected-peer regression does not accept the full continuity candidate.
Evidence: `.zig-cache/wave-45/publication-debug-v7.json` and
`publication-debug-v8.json`.


W50 integrates HELP/HELPOP `?query` search over the existing static help
database. Queries are literal and bounded to 64 bytes; replies use fixed SEARCH
numerics, at most eight results, and safe framing with long-prefix fallback.
Queries are not echoed. All 13 Debug and 13 Safe leaf tests passed, including
invalid input and allocation cuts; the daemon compile check and independent
review passed. Guarded promotion preserved all other 1,235 inputs. Q02 advances
to partial; generated command/capability documentation and client integration
remain open. Evidence: `.zig-cache/wave-50/actual-integration.json`.


W45 v9 passes all 156 selected tests in both Debug and Safe on unchanged
private source, with no failures, leaks or log errors. The cut restores the
admitted predecessor's dominating direct-origin route state into the unadmitted
candidate before paused-frame retry; immutable transition provenance then
reconciles stale publication without losing newer PART/rejoin boundaries. New
allocation cuts retain the exact waiting generation and predecessor authority.
The mixed-owner fixture accounts for every real source SEND completion and
decrypts its ciphertext before capture, preserving the exact successor-wire
assertion. Fresh Astra review approved this bounded source change.

Debug took 36.183 seconds; Safe took 413.028 seconds, including approximately six
minutes of compilation with 5 GiB peak compiler RSS. These are gate costs, not
daemon performance measurements. Broader Helix/server and real upgrade acceptance
remain required; this private Core cohort is not promoted. Failed v1–v8 receipts
remain retained. Evidence: `.zig-cache/wave-45/publication-debug-v9.json`,
`publication-safe-v9.json`, and `composition-v9.json`.


The broader W45 v9 Helix Debug gate ran 1,176 cases: 1,096 passed, 77 skipped
and three failed, with unchanged input hashes and no leaks or log errors. The
run includes passing sequential reusable-session, same-IP mesh repair and live
TLS reattachment cases, but the gate remains red. Independent fixture review
identified an S2S capsule paired with a client-shaped physical owner and two
shared RESYNC fixtures sealing newly armed I/O without quiescence. Their fixes
must obtain genuine Core admission, quiesce through real completions outside
World, and preserve exact ciphertext, counters and FD custody. The canonical
owner guard is not relaxed. Evidence: `.zig-cache/wave-45/helix-debug-v9.json`.


W45 v10 corrects the three older preserved-link fixtures using genuine Core
admission and actual quiescence before capture. The property admission source
is a separate Core without restored property rows, preserving the meaningful
post-adoption owner/HLC/key/signature assertions. Residence checks, grants, quiet
RESYNC behavior, exact ciphertext and FD cleanup remain enforced. Fresh review
approved the fixture/helper changes and one explanatory comment; production
guards are unchanged.

All 89 narrow tests passed, followed by the complete selected Helix Debug gate:
1,099 passed, 77 skipped, zero failures/leaks/log errors across 1,176 cases.
Inputs remained unchanged and supervised processes cleared. Broader Safe is
running; full server/pressure-state acceptance and promotion remain separate.
Evidence: `.zig-cache/wave-45/admission-fixtures-debug-v10.json`,
`helix-debug-v10.json`, and `composition-v10.json`.


The W45 v10 broader Safe gate also passed: 1,099 passed and 77 skipped across
1,176 cases, no failures/leaks/log errors, unchanged inputs and complete owned
process cleanup. The 717.694-second gate includes approximately eleven minutes
of compilation at 7 GiB peak compiler RSS; test execution took 30.435 seconds.
These are compiler/gate costs, not daemon footprint or throughput measurements.
Evidence: `.zig-cache/wave-45/helix-safe-v10.json`.

W45 v11 combines that Core cohort with the already integrated doctor, help,
maximum-descriptor test and benchmark-tool updates. Guarded composition verified
exactly nine authored cohort files over the current actual-source manifest,
preserving the other 1,227 inputs and modes. Core production source is unchanged
from v10. This remains a private candidate undergoing broader server verification.
Evidence: `.zig-cache/wave-45/composition-v11.json`.

W51 has a verified old-code ordering defect: after a genuine signed PART installs
the existing output barrier, accepted queued fabric bytes appear after the next
CHGHOST instead of before it. The final test-only reproducer reaches exact wire
equality, failing with 86 passing cases and one failure, without leaks/log errors
or changed inputs. Earlier setup and pause-mechanism failures are retained but
are not counted as proof of this defect. Evidence:
`.zig-cache/wave-51/old-production-reproducer-debug-v3.json`.

The isolated finite-prefix queue/fabric helpers pass 90/90 in Debug and Safe,
including four new target tests for claimed/unpublished positions, wrap, partial
drains and post-cut retention. The remaining cases are shared initializers;
counts overlap and are not added as unique tests. Independent review approved
the bounded API. Dequeue progress is explicitly distinct from retained-message
completion, and this helper result does not accept the mutable Core pressure fix.
Evidence: `.zig-cache/wave-51/fabric-leaf-debug-v1.json` and
`fabric-leaf-safe-v1.json`.


On the coherent W45 v11 cut, broader server Debug passed 542 tests with six
skips across 548 cases, including the real two-node cloak-rotation policy-scope
case. The daemon compile check also passed. Inputs stayed unchanged and owned
processes cleared. These results supplement the earlier v10 Helix evidence;
they do not accept the separate, still-private W51 pressure implementation.
Evidence: `.zig-cache/wave-45/server-debug-v11.json` and `daemon-check-v11.json`.

W51's first Core Debug gate passed 100 and failed two of 102 cases. The old-code
exact FIFO reproducer now passes, but the unrelated-client fixture was not fully
registered and terminal poison retained a pooled reference. Independent Astra
review also found incomplete ordinary PART/QUIT fencing, per-broadcast budget
pinning and late-producer Helix custody omitted after preflight. The v2 source
is sealed with targeted corrections and regressions; gates and fresh review are
pending. The original failed receipt remains:
`.zig-cache/wave-51/generic-output-debug-v1.json`.

A separate read-only credential audit and independent review extended the T01
reference to verification/reset codes, bot grants, delegated TLS credentials and
the inactive migration HMAC codec. It records two confirmed recovery-policy gaps
without pretending to fix them: durable verification bypasses RAM attempt limits,
and reset-code consumption precedes password admission. The inventory remains
partial; no source behavior or acceptance status changes from this doc update.


W51 v4 received bounded Astra source approval after excluded-recipient and idle
metadata fixes. Its gate exposed test setup issues; the fixture-only v5 then
passed all 109 selected Debug cases. Independent review required an additional
host-cut test with genuine unrelated pooled retention, rather than ADS custody
alone. That v6 test proves both healthy host changes progress while the unrelated
pooled reference remains live, then recovers its exact FIFO. The expanded run
passed 109 and failed one of 110: the final global ADS reclamation check found
179 bytes. This remains unresolved, so no Safe/promotion claim is made. Earlier
failed/aborted receipts are preserved. Evidence:
`.zig-cache/wave-51/generic-output-debug-v5.json` and `generic-output-debug-v6.json`.

The second reviewed credential inventory covers WebAuthn/recovery/TOTP, OAuth,
Web Push and inactive TURN framing. It records that recovery-code CLEAR and
Web Push unsubscribe can report success despite fallible store errors. TOTP's
replay counter is RAM-only, but normal verification preserves it; this is not
a per-login reset. These source facts update the existing reference, without
claiming behavior fixes or complete token-roadmap acceptance.


T01's final source/document completion audit accepted its specific credential
inventory and domain-separation criterion. Durable passkey and password/SCRAM/
CERTFP lifecycle omissions were corrected; separate active local/portable,
replica, media and operator authorization guards were inspected. The inventory
is now seven accepted, 39 partial and 52 open. Known recovery/transport/media
implementation gaps remain; no new runtime or deployment result is inferred.
Evidence: `.zig-cache/credential-inventory/t01-acceptance-2026-10-29.json`.


W51's genuine pooled-host case exposed a test cleanup omission: the original
pressured observer correctly still owned PART (59 bytes) and two CHGHOSTs
(59 + 61 bytes), totalling 179 bytes. The test now verifies that exact owner,
strict sequence and payload, restores its physical capacity and drains normally,
retaining the final global zero check. Producer tracing establishes the mixed
record kinds: ordinary PART uses `prepareOutputBatch`'s plaintext OutputRecord;
CHGHOST uses `prepareOwnedBatch`'s IRC record. Earlier uniform/reversed kind
assumptions and their failed gates remain retained.

The isolated final case passes 87/87 Debug cases; the previous expanded run
passed every other native-format/old-publication/pressure case. This is not an
aggregate unique-test count. A coherent W51 v11 cut now includes all five accepted
actual-source updates and exactly eleven authored cohort files over the actual
manifest, preserving the other 1,225 inputs and modes. Its broader Debug gate
uses the complete OR-union of both named Helix/server filters, all prior
publication filters, and the pressure/native-format selectors: 48 literals,
overlapping cases executed once. Matching module/target/optimization/runner
settings were independently checked. Separate executable, leaf-root, armor,
compile-time and full-suite gates are not replaced. Evidence:
`.zig-cache/wave-51/retained-host-debug-v10.json`, `composition-v11.json`, and
`combined-module-scope-v1.json`.


W51 coherent v11 passes its complete selected module Debug union: **1,609 passed,
83 skipped, zero failures/leaks/log errors across 1,692 cases**. Exact inputs
remained unchanged and owned processes cleared. This runs both named Helix/server
filter sets plus the complete previous publication and new pressure/native-format
selectors in one artifact; overlapping cases are counted once. The same source
and 48-selector scope are now running in Safe. This does not replace separate
executable, leaf-root, compile-time or full-suite/release acceptance. Evidence:
`.zig-cache/wave-51/combined-module-debug-v11.json`.

W52 is a separate bounded follow-up on that exact baseline: recovery-code CLEAR
and Web Push mutation paths must not report success after failed persistence.
The writer is using existing strict Services APIs, preserving old authority on
failure and leaving dead-endpoint retries separate. Source/tests are still being
prepared; no fix acceptance or new runtime claim is made yet.

### W51 combined Safe and W52 fresh review (2026-10-29)

The coherent W51 v11 48-selector module union passed Safe: **1,609 passed, 83 skipped, zero failures/leaks/log errors**, matching Debug. Receipt `.zig-cache/wave-51/combined-module-safe-v11.json`; 881.988 seconds; log SHA-256 `d81bee6c7b9095c4b8028ec7969dc375e364227fb649bce67e25eae3aeef2b74`. Parent reverified all 1,236 source hashes/modes, unchanged inputs and terminal supervisor with no owned processes. This is module-union evidence; executable, separate roots, native pressure/upgrade and full release gates remain.

Fresh Astra blocked W52 v1: permissive subscription decoding permits a persisted four-row list to be truncated on an absent-endpoint UNSUBSCRIBE, falsely acknowledging removal. Sol is correcting strict mutation-load semantics and adding malformed-state regressions before gates. No roadmap target closed from this review or test run.

### W51 guarded integration; W52 Debug (2026-10-29)

Fresh Astra confirmed no remaining blocker in the reviewed W51 paths and identified the blanket historical promotion prohibition as stale. Guarded promotion integrated the 11-file cohort into the actual working tree: output spool, queue/fabric, World and mesh publication, daemon integration and strict HPC2 Helix relations. All 1,236 hashes/modes now equal coherent manifest `589dd917ea71529a00fd6f8b89ddc4cec0d4390e140d4f00cc7300e37208af16`; the other 1,225 inputs were unchanged. Evidence: `.zig-cache/wave-51/actual-integration.json`. Pending pressure-state Helix carry still refuses before exec; no full-suite, native upgrade, or release claim follows.

W52 v2 corrected malformed-state validation and received fresh Astra source GO. Its Debug fault/adjacency scope passed **107 tests, one skipped**, zero failures/leaks/log errors, in 77.647 seconds with unchanged input and terminal ownership cleanup. Receipt `.zig-cache/wave-52/revocation-debug-v2.json`, log `7ed9c10394cc90f1357ef808f7f2bae5641c4b70bdef956223b73846fc6a2820`. Safe remains pending. W53 separately addresses reset-code consumption before password admission.

### W53 source review and compact continuation (2026-10-29)

The separate W53 candidate retains a valid reset code until Services accepts the password, SCRAM and session-authority change under the existing World lock. Invalid-password and allocation rejection preserve the exact pending code and durable state; ambiguous I/O keeps the existing Store poison contract. Fresh Astra approved the leaf and integration source; runtime tests remain queued after W52 Safe. Evidence: `.zig-cache/wave-53/composition-v1.json` and `independent-source-review-v1.json`.

The active continuation pointer now omits repeated completed-wave detail while retaining the complete linked history. Independent Terra recovered the actual source, current gate and process identity, ownership, exact candidate inputs, deployment restrictions and next actions without the transcript, then confirmed the compact entry point alone was actionable. E01 is accepted for that handoff criterion; all 98 targets remain: **8 accepted, 38 partial, 52 open**. E10 exhaustive preservation and product/runtime acceptance are separate. Receipt `.zig-cache/continuation-inventory/e01-acceptance-2026-10-29.json`.

The integrated cohort passed whitespace checks, but pinned `zig fmt --check` identified formatting drift in `physical_connection_relation.zig`. Formatting is queued after the active frozen gate; it must be synchronized into the final source manifest before release checks.

### W52 integration and W53 runtime gate (2026-10-29)

W52 Safe passed **107 tests, one skipped**, zero failures/leaks/log errors in 401.450 seconds; receipt `.zig-cache/wave-52/revocation-safe-v2.json`, log `d7cb6e713fa1424fb8abbad40ad0d7a3e88148dbf8f71ab8d49a6cce383aafd4`. Parent verified both mode receipts, log hashes, unchanged full source and terminal ownership cleanup before promoting only `server.zig`; the other 1,235 inputs/modes stayed unchanged. `.zig-cache/wave-52/actual-integration.json` records that integration.

Pinned formatter migrated five enum conversion builtins in the physical relation leaf. Fresh Astra confirmed the migration preserves the u8 role values, structural rejection and owner checks; actual and W53 copies match. W53 v2 includes those four leaf regressions alongside password-reset tests in its Debug scope. The client outline now describes preserving a reset code through rejected admission and waiting for durable acknowledgement before presenting recovery-code deletion or Web Push changes as successful. Client source is still outside this evidence.

W53 v2 Debug passed **105/105**, no failures/skips/leaks/log errors, 27.959 seconds. All 1,236 hashes/modes, log hash and terminal ownership cleanup were independently verified. Receipt `.zig-cache/wave-53/reset-debug-v2.json`; log `95a7aea9b5033613f4eae94160a2ab2b3e8594cdac07194ffad966451d2c526a`. Matching Safe is active; W53 is not yet promoted. All feature source and the formatter enum migration have fresh independent approval.

### W53 guarded integration and full candidate suite (2026-10-29)

W53 Safe passed **105/105** in 273.367 seconds, zero failures/skips/leaks/log errors; log `8aff70001c241fef2b4c5d53f031d99f7163d70e6c72114b8d4afda009a5fdbc`. Parent verified receipts, log hashes, all source hashes/modes and terminal ownership cleanup before copying only `server.zig` and `password_reset.zig`; the other 1,234 inputs/modes stayed unchanged. Actual source now equals manifest `23ad7758765bdf88f10be8e7e48231cc1b393ea348ce65f569cee48cf087b248`. Receipt `.zig-cache/wave-53/actual-integration.json`.

The actual source is frozen for the unfiltered full Debug suite, including module, executable and CLI artifacts. Fresh independent coverage review confirms full Debug and Safe runs cover the affected named suites without duplicate runs; separate roots, compilation/constant-time checks, native and packaging acceptance remain. W54 independently authors the coupled production issuer/binding/reserved-ticket/physical-latch handoff in a private context. No deployment or release claim follows.

W54 fresh leaf review blocked LGI1 v1: a valid signed frontier could retire a carried guest that the wrapper accepted as a binding or reservation. The private v2 correction must reject both contradictory forms, preserve active exceptions and counters above the frontier, and add nonempty allocation-failure coverage. No W54 source is promoted. Separately, independent P01 audit retained partial status: actual cross-node offline-return comparison is still missing; the roadmap queue now names that exact native oracle.

W54 wrapper v2 received fresh source approval after rejecting retired carried bindings and reservations, including allowed active exceptions and nonempty decode allocation sweeps. Its allocation-free lease descriptor census remains structural only; Core must still validate semantic state and descriptor authority. Source hash `be3fb2a7484a7a52bc3b97e45bae6b63d0371a8af09e4acd8756b18951b0ff15`; receipt `.zig-cache/wave-54/leaf-review-v2.json`. Runtime remains pending. Positive production adoption must use fresh exec because process-global incarnation ownership correctly rejects same-process duplication; the existing W46 trusted leaf fixture cannot substitute for the production Core handoff. Private helper/harness/build ownership is explicit; actual source stays frozen in the full Debug gate.

### W55 priority cloak identity correction (2026-10-29)

Independent P04 audit found a HIGH candidate bug: registration permits punctuation-only account names, while account-cloak sanitization rejected them before hashing. Initial login could share the IP fallback cloak; account replacement could retain the previous account’s host, so exact host grants could cross account boundaries. The old candidate full Debug run was intentionally cancelled at 899 seconds because this confirmed finding requires a source correction. It is incomplete, not a failed assertion or passing full suite. Partial log and cancellation reason are retained; parent verified all supervisor/ledger/build/test PIDs gone and all 1,236 actual inputs/modes unchanged. See `.zig-cache/wave-53/full-debug-cancel-{reason,cleanup}.json`.

W54 production carry is frozen at its explicit incomplete checkpoint while W55 takes priority. Fresh source review approved the W55 leaf’s fixed friendly placeholder plus existing account digest for every permitted empty-label account, preserving canonical and prior nonempty lossy encodings. Server positive-grant isolation and account-replacement regressions remain separately owned and ungated; P04 stays partial.

### W55 privilege proof, integration and W56 provenance (2026-10-29)

Exact old W53 production plus authored test overlays failed both real SACCESS privilege assertions: **86 passed, two failed**, 12.953 seconds, no leaks/log errors. Owner grants improperly exempted another punctuation account and survived canonical-to-punctuation replacement. The fixed W55 scope passed **194/194 in both Debug and Safe**, including existing native cloak/moderation cases. Safe took 443.972 seconds, log `18779a860fab63160d3ec984fbdde605d80a3e9e23862290b5fa70d7ea6cfbfe`; Debug log `44dc508548161e113a09d3a6d77c2e2804f95d80e756b158728905e2fb8dd0fa`. Parent verified unchanged source/modes, log hashes and terminal ownership before guarded two-file promotion; actual manifest is `b627086cab5fd6c9b9527973de48b8913a4223ac47f06cbae5839d095ab9ad54`, other 1,234 inputs unchanged.

P04 stays partial: a historical image can carry an already-wrong host, and old snapshots omit explicit host-source intent. W56 introduces mandatory physical host provenance and stages supported generated-host corrections before activation. Missing historical intent cannot be guessed from host syntax or durable Guise alone. Unknown registered account state must refuse transactionally, preserving the source. The new codec preserves the existing high-byte host contract; no extra UTF-8 restriction is introduced.

The isolated issuer leaf gate first stopped on an incomplete harness setup, then found a nominal struct type mismatch before runtime. Both receipts remain. The wrapper correction is a single explicit `mesh_presence_lease.Identity` annotation; the wire, validation and tests are unchanged. W54 Core remains at its separate incomplete checkpoint.

### Earlier feedback and parallel verification (2026-10-29)

The issuer leaf passed **65/65 in Debug and Safe**; Safe took 286.134 seconds, log `422cbce7fbef93b2d1965a0655a8b0205fbbb4848eb28e44aef93873e29520db`, with all 1,240 source hashes/modes unchanged and terminal ownership cleanup. The host-presentation codec passed **4/4 in Debug and Safe** (three substantive tests plus its import root); Safe took 24.080 seconds, log `a06abeae315dec68fd8abbdc4603d3bb161f33afde6be2ee39646bd65d45223a`. This is leaf evidence; neither production handoff is accepted from it.

Engineering feedback now uses immutable compile checkpoints while authors continue elsewhere. The first daemon check returned two errors in 11.371 seconds; its correction passed in 11.081 seconds. Independent reviews ran against archived checkpoints and caught rotation/resume provenance loss, counter exhaustion, native prefix admission and transcript false positives. Superseded checkpoints are skipped before gate launch. A 1.324-second isolated compiler probe proved the custom runner must use a named dependency to the same tested module, preventing duplicate file ownership. These timings describe engineering feedback, not daemon throughput.

Current W56 code remains private. Final review still requires WHOIS exhausted-result rejection and nonwrapping publication, followed by complete focused and native original-socket/order/privilege/refusal/allocation acceptance. No roadmap acceptance count or deployment status changes from these intermediate checks.

### Independent wizard delivery lane (2026-10-29)

W58 fixes a real review error: static profile defaults could claim 128→1024 clients even when an override kept the effective value at512. Candidate generation, human/colored/NO_COLOR review and JSON now share typed effective values and a clear baseline. It passed **32 Debug tests plus compile check, 32 Safe tests, and38 actual native/headless/PTY cases**. Safe43.761s log `02756e1e2a6bbfbb0adf04444929bdba0710ff1cda0f719be0dd47d493a4e2d0`; native4.475s log `3a0b67adeaf65b3ac1feda52b928c09a39b6f4c9c1ee0f13fcd87882b40afe42`, binary `f193ce123de94c87c5337c3581da8f3b19bceb51b7a2039b9eae4297ae942b52`. Fresh source review and parent full source/mode/log/ownership checks preceded guarded five-file promotion, preserving the other1,231 inputs. Actual source manifest `e0ffe4efd7f713e495e3324334d076fd502ebcd6d50959ff7626f95ea2f662b2`.

W01 remains partial after independent completion audit: its named existing-network purpose workflow was absent. W59 now implements that explicit read-only validation/review path, preserving configuration and secrets and explaining that no enrollment/network contact occurs. Its source/readiness correction and actual interactive gates remain pending. This lane advances independently of W56 upgrade work.

W56 v11 reached100 passes and one wire-progress timeout, with no leaks/log errors. Actual adoption state, rotation, SESSION RESUME, malformed-family and allocation rollback cases passed. The remaining fixture submitted the first SEND but did not reap its CQE to release later spool receipts. Its v12 correction drives genuine owner completions and exact reads with a shorter deadline; FIFO, reclamation and no-duplicate assertions remain. No W56 promotion follows.

### W56 focused and actual exec acceptance progress (2026-10-29)

The corrected owner-completion fixture passed **101/101 Debug tests**, no leaks or log errors, in 46.232 seconds. Log `aa137e091506f6a95fbb7973a4d8f9509041868a1b691a75ce4db07e360c1216`. Actual production exec then passed supported repair and unsupported-source refusal with three original sockets, ordered output and privilege checks in 14.351 seconds. Log `90c3b0e65724d68cb7303e8c4fa2566707521d0c31cc253cc3a42c65c24e9456`, binary `1f225c128172f4dc94fb5613a5fcc708e617679e5c4702bcbb261de9050d23c7`. Parent verified unchanged inputs, matching log hashes and terminal empty ownership. Safe verification remains pending; W56 stays private and P04 partial.

W56 focused Safe also passed **101/101**, zero skipped/failed/leaked/log errors, in470.053 seconds; log `543f773468ed69ba98f37e914dac616ba18c199f9fe04b25a57e5f1333d204c0`. Broader mandatory-state/caller coverage remains pending.

The parent relaxed its own single-gate scheduling rule after measuring40 CPUs, about86GiB available memory, load5 and a roughly one-CPU/4GiB Safe compile. At most two independently supervised gates may run on different immutable contexts; isolated wizard checks may overlap server verification. Two socket/mesh/Helix runtime campaigns must not overlap. Each gate retains separate source/log/ownership evidence. W59 Debug now runs independently of W56 caller coverage. This changes engineering scheduling, not daemon throughput or acceptance.

W59v5 passed **35/35 Debug plus check** (90.786s, log `addec5867d99191b0f410e112d6b59c49a5a1bcf2b85c0764fa095fa99f050eb`) and **35/35 Safe** (45.975s, log `2819aeb66f2dc65673ea0777ce29369d9b74a7a87218384ef4708e6431638002`). Native actual-interaction acceptance remains pending.

W56 broad caller Debug is RED: **1,007 passed,87 skipped,nine failed/1,103**, no leaks/log errors,145.334s, log `be71b6e251e52a67a61fef89673f2c299b20e4c127843a1a98667b63232f796a`. Two stale enum/schema assertions and seven adoption/presentation failures require investigation; their causes are not assumed to be fixtures. Source stayed unchanged and supervisor ownership is empty. W56 is not integrated. Independent W57 actual offline cross-node cloak test is authored and sealed but ungated.

### W59 existing-network wizard accepted and integrated (2026-10-29)

The actual executable passed **49 CLI/headless/PTY cases** in6.723 seconds, log `326efc1915ee1b758cb9d842ef3846728cefbefbf0dbc1499d6a6e226e35d71f`; binary `2591637038115d196a1e04e79ccb823f39b633dc9c56d5d25e2d598d24d86f76`. Parent verified every source/mode, all four gate/log receipts and terminal empty ownership. Independent Sol review proved the whole W01 row on Linux, including typed profile values/diff, actual existing-config summary, retry/back/cancel/EOF/conflict handling, no enrollment/contact, source/material byte identity and secret omission. Guarded four-file promotion preserved1,232 other inputs. Actual manifest `.zig-cache/actual-source-after-existing-network-wizard.json` SHA `54def3e730dee4d67e6579b9cd10e1de918a820ebcdc4d6fc4f48cb9ff8d2884`. **9 accepted,37 partial,52 open**; W02 andW07 remain separate. No full-suite/release/deployment claim.

W60 narrow/linear terminal work is independently authored and reviewed. Astra blocked prompt adjacency, whitespace corruption in paths and unwrapped postinteraction diagnostics before gates; v3 corrected those with stronger PTY oracles and received static GO. Debug/check is running. Preinteraction/emergency diagnostics remain legacy and actual screen-reader hardware compatibility is unverified.

### W60 terminal wizard integrated (2026-10-29)

W60v3 passed **39 Debug tests plus check**,67.878s, log `32a2c4466ac73f05c67f60f10e946ced36546ba7a779793575dc1533df333789`; **39 Safe**,44.249s, log `64e410f9b99e5923e372443c9428dc1ef4ff37436e96c1d50d4f354e80bf4760`; and **59 actual native/headless/PTY cases**,5.945s, log `fae8ff2a60bb2979bd1f02c38f300a54911f1bc3bffea5ac1c458877dbce8be6`. Binary `649879ab818115bf0868ef5f29e639b42c0f69d2848836c1f685c2998a9f4544`. Parent verified complete source/modes, logs, terminal empty ownership and archive receipt; guarded five source files plus setup guide promotion preserved1,231 other source inputs. Manifest `.zig-cache/actual-source-after-linear-wizard.json` SHA `431512e1702295504298b947ba83a71f01f24d137889a2f68358ef955088a656`; guide SHA `86042fddc19b6ced7c1a9e7c11067954fea4791b190873d36f456b1cc4ee2a2e`.

Fresh Astra full-row review accepts W02 for this Linux source/artifact: keyboard navigation/search/help/progress/review, color and linear equivalents, narrow20/38-column actual completion/failure/path fidelity, and redirected/headless alternatives. Interactive widths below20 use fallback; preinteraction/emergency stderr can remain unwrapped; particular screen-reader hardware/software is unverified. **10 accepted,36 partial,52 open**. No release/deployment claim.

W57 first actual offline-return gate is RED86pass1FAIL/87: the same-node control QUIT appeared twice before the clock boundary. The exact-once assertion remains; source versus test collection is under investigation. W61 final shared network/media assessment is authored and independently reviewing/gating; its early partial compile passed12.839s only, not runtime acceptance.

### W56 caller closure and W61 allocation diagnosis (2026-10-29)

W56v13 fixed all nine earlier caller failures: minimal reproduction passed103/103+check. Fresh fixture review found an indirect legacy queue-reset helper; v14 replaced it with direct Services dispatch and actual native SEND/CQE drains. Fresh review approved v14; production is unchanged. Broader Debug then passed **1,016 with87 skips/1,103**, zero failures/leaks/log errors,142.558s, log `6ba03492431eac52b0ed213e53816ba3abe246b7ed7337feccaf3bfcd45cea40`. Source and terminal ownership verified; Safe caller closure remains pending.

W61v2 corrected human optional-null presentation and missing pre-done TLS fields. Fresh source and full-row review conditionally approve W04/W08, but acceptance is withheld: Debug42+check passed67.532s (`4a11aa8c544abdceb5c64111fef3f823e2d6a2276054456eb4a4bfaf03afcf63`), while Safe41+1 failed an existing private-bundle allocation sweep with NondeterministicMemoryUsage. That test is byte-identical to W60; its actual divergence is still unproved. A separate immutable numeric-only allocator trace is running; no retry-until-green or weakened sweep is accepted. Native linked binary `ec3e7c6015e67eff6e4b312574aa21a5d16ccbbde5633c9230a8c8378a53f56a` already passed65 setup cases,6.411s (`bb4c3c5c3b7aee366638de36e703777ddc70dc6a8d26cd9ea5939db1d6ffe094`); separate media cases remain pending.

W57 duplicate QUIT is confirmed in production: broadcastQuit loops common channels and broadcasts independently, yielding two physical deliveries to an observer sharing two channels. A new private W62 fix must deduplicate full-generation recipients while retaining every channel state withdrawal/history and pressure semantics; exact-once assertions and post-retirement observation barriers remain.

W61v2 media harness also passed its four real PTY cases,2.655s, log `86068b08f632b06279cb1fb416265ddb64d095f8b48801873660d5660f6ed247`. Both native harnesses and binary linkage are verified; this does not waive the failing Safe allocation sweep. A separate transparent allocator trace with32 campaigns did not reproduce the failure (34.308s runtime); that is not a repair. Direct-allocator diagnostic v4 now retains the original standard sweep and probe across32 campaigns to avoid the extra allocation wrapper. W56v14 broader Safe is running independently.

### W56 host provenance integrated; W61 deterministic harness (2026-10-29)

W56 broader Safe passed **1,016 with87 skips/1,103**, no failures/leaks/log errors,725.427s, log `e73b320f26519ff338261a7e57d71a3714ef6054421eeac725fa1c97b5edd9b6`. Fresh final integration review approved the unchanged production and fixture corrections. Exact composition with current wizard source passed check/helper build24.429s (`2d867de8363d7fdfdb0b70a3e55989e09d1cf741cdbbf289f8983a83fea2bcae`) and actual supported repair/refusal on three original sockets14.027s (`77e1ddea4271b3980b6442bf77a0e8710cbd2e98d53b3507d59cb5e4dc585f73`), helper `6f6c7aad43af50e745164542f8eca95d15ff9fd2a6cc08675d5ed6c1c2705d55`. Parent verified every source/mode/log and terminal ownership, then promoted10 reviewed files, preserving1,229 existing inputs and adding3. Actual manifest `.zig-cache/actual-source-after-host-provenance.json`, SHA `a186da267011d535db5749fd5f0f71e8574685076a944f9d99ffd21ac29e10a3`. P04 remains partial; missing historical intent refuses before exec. No release/deployment claim.

W61 isolated and full-context diagnostics did not reproduce the earlier allocation failure. Source inspection independently established that SafeAllocator remap may succeed or require fallback allocation, changing standard failure-injector counts. Fresh Astra review approved v3 test-only controlled remap-reject and relocation-success policies, preserving real crypto, complete fallback cuts, byte ownership/leak checks, per-attempt stage cleanup and validation refusal. This controls the identified mechanism; it does not claim historical attribution. Revised **43 Debug plus check** passed69.562s (`bd8f73efc6ea9decdea8ead44c40a1a1b7aad7345d538a613544f5c094fc2e44`) and **43 Safe**46.145s (`c92e92c04e2fc36febe522fcd193cd4f99dbdea500251cdc1acaa73e61e7a47f`). Combined W56+W61 source is now gating before promotion.

### Implementation resumed with bounded acceptance work (2026-10-29)

The user resumed the complete R0–R6 implementation after finalizing the roadmap.
The specification remains fixed at 98 targets; implementation remains 14 accepted,
32 partial and 52 open until a complete criterion is independently proved.
Current lanes are W66 QUIT delivery integration (sole daemon writer), W67 shared
wizard/doctor service plans (setup owner), and W65 benchmark compatibility (parent).

Each lane keeps one owner, an explicit criterion, one frozen candidate and its
remaining gate list. Reuse successful checks when their bound dependencies match.
Before retrying a failure, retain its fingerprint, diagnosis, relevant source or
harness change and original assertions. An unchanged failure requires bounded
independent analysis rather than another run. Continue independent work while a
lane is blocked. Promote the reviewed delta after its gates; do not reopen its
accepted seam without new contradictory evidence. Planning, repeated inspection
and partial helper coverage do not count as accepted implementation.

W65's original optimized run actually completed all three repetitions with exact
counts, but benchmark output and gate receipt used the same path, corrupting the
formal JSON receipt. Its intact log is retained; it is not a valid gate receipt.
One replacement measurement uses distinct report/receipt paths. The candidate
benchmark driver passed all 24 offline custody/delivery tests. No capacity,
performance improvement, full-suite, release or deployment claim follows.

W65 is now integrated: the retained benchmark uses the reviewed setup material
handshake and checks the actual staged certificate before acknowledging publish.
The single separated-output replacement gate passed three complete optimized
repetitions on artifact `eb4d403982f915a97375a953a7b616281550b058077130e1905a76093bcae15a`.
Each continuous phase authored 65,536 messages and delivered exactly 196,608;
observed rates were 9,847, 10,324 and 10,498 deliveries/second. All 24 offline
custody/delivery tests passed. Fresh Astra review approved the bounded driver.
Guarded promotion changed only `tools/bench_live.py`, preserving 1,241 inputs;
receipt `.zig-cache/wave-65/actual-integration.json`, source manifest
`454266785111634730089f63e4aa371d547b3f86cad3c0617b8a0e945120d0ed`.
This repairs benchmark compatibility and establishes a bounded measurement;
no production optimization or sustainable capacity claim is made. W09 stays open.


W66 is integrated and P01 accepted. Exact composition passed 97/97 Debug plus
check (51.667s, log `1e388096c13e0770cf92f03b64772cb7858b061ef49abd903765e09752eb2982`)
and 97/97 Safe (396.942s, log `08aba1585cd017ed33d6120a2cb79e28c233369a06b847a14b76ba37afa86936`),
with no skips, failures, leaks or log errors. Fresh Astra reviewed v8 production
and the exact composition, including strengthened real cross-node offline proof.
Parent verified source/modes, logs and terminal empty ownership, then promoted
only server.zig, preserving the W65 driver and all 1,241 other inputs. Manifest
`34a9a30aa277906fbff6e78685074201f3914d4b574a4d836dc7dc695856d531`;
receipt `.zig-cache/wave-66/actual-integration.json`. Inventory is 15 accepted,
31 partial, 52 open. P03/P04, broader pressure independence, full release and
deployment remain unaccepted. W69 MESH snapshot/dispatch is the next daemon task.


W67 is integrated and W10 accepted for the Linux planning interface. Setup and
doctor share additive structured service templates; interactive review includes
them before done, headless final output includes them, and actual readiness
remains unknown. Debug setup46/check/build and doctor98 passed; Safe exe48 and
module101/1 unrelated optional media skip passed in428.057s (log
`fb6e98dfaccf4fbbdddcd0f95e8d4d3d478a1a588980adaf29b104d52d943329`).
Exact current W66/W65 composition passed check/install28.245s and 69 native
setup cases plus doctor fixtures145.740s (log
`98c5af35b1e16348e076ff992a27e8a25903be32030d538a41b0e9cde4de9de5`).
Fresh Astra approved unchanged dependency reuse and parent verified every
source/mode/log and terminal cleanup before guarded eight-file promotion.
Manifest `8abd0d98c4aae3fab2a0e2977b060bbc644bc0434e555c065e39e3ef42cc8923`;
receipt `.zig-cache/wave-67/actual-integration.json`. Inventory16accepted,
30partial,52open. A05 live supervisor acceptance, full suite and release remain
unproved. No service installation, deployment or push occurred.


W68/W71 kernel startup compatibility is integrated; A08 accepted for Linux.
The real kernel probe passed Debug98/Safe98 with no skips; current composed
check/install passed29.867s. Actual syscall injection then passed11 control/fault/
recovery cases in38.940s, proving main-level refusal, generation-aware explicit
ring/listener cleanup including an earlier shard, and no unsafe SQPOLL retry.
Campaign log `68c59aa47637c96e9d770209ac344733197d92249478df85247535275944bb73`;
binary `37196724f30ac0a9b5ce7b04236065c69e3601d48f1b2fdcf8c11fe40809f3b4`.
Fresh Astra full-criterion review and parent guards preceded promotion of only
Ringlane and the fixture, preserving1,241 inputs. Manifest
`0010c95280cc700a092ec2fec82e6b676c9b2f127a125d1d3d8c4957c625be53`.
Inventory17accepted,30partial,51open. Portable-backend execution, dedicated
missing-MSG_RING faults, full release and deployment are outside this evidence.

W72 removes a measured iteration bottleneck with additive SessionStore/Ringlane
leaf test targets. All nine named bootstrap cases match the broader root gate
in Debug and Safe; Safe elapsed26.092s versus156.772s on this host, about6x faster.
All eight named Ringlane module cases also match; its leaf Safe took24.461s.
The root's four additional server integration cases remain covered separately
by the unchanged98-test Debug/Safe gate. Anonymous import tests differ by
construction; neither leaf replaces caller, integration, native or release gates.
Fresh Sol reviewed additive build wiring; parent verified all four receipts,
case lists and terminal cleanup before promoting only build.zig and two roots.
Manifest `d57788027a3ccdc61708c3baa4aced189e37c475d9421b07a9223793de7cd545`;
receipt `.zig-cache/wave-72/actual-integration.json`. The canonical selector now
prints pinned `-Doptimize=safe`, avoiding an obsolete compiler argument; selection
rules stay unchanged. Its18 regression tests and toolkit validation passed,
with fresh review. These figures measure engineering iteration, not daemon speed.


W70 is integrated and T04 accepted. The complete session gate passed894/894 in
Debug170.233s and Safe668.545s; final bootstrap delta passed95/95 Debug20.892s
and Safe156.772s. Fresh Astra approved unchanged lifecycle evidence reuse after
reviewing the bounded bootstrap delta. Exact current composition, including the
new kernel guard and leaf build wiring, passed check/install/helper build and
actual native exec/adoption on three original sockets. A first native attempt
failed before launch because the requested scratch parent was absent; it was
created0700 and one corrected-precondition run passed. Original red evidence is
retained. Parent verified all hashes/modes/logs/terminal cleanup and promoted
only sessions.zig, preserving1,244 inputs. Receipt
`.zig-cache/wave-70/actual-integration.json`; manifest
`5f774f052df2bf8ab020ec38ee2fcd52624f0c8b449d11991d6611dd6370823d`.
Inventory18accepted,29partial,51open. Work counters measure selected folded
account closure, not token-only lifecycle or actual throughput. No release or
deployment claim. M01 remains the sole unfinished current product contract.


W69v4 MESH publication is integrated; M01 accepted. Final actual composition
includes T04 and kernel startup changes. All90 selected cases passed Debug13.532s
and Safe372.558s with no skips/failures/leaks/log errors. Safe log
`445848a9cc6900251c34fa622dc69fd8c81e19dc11d5829168a7fb705771c894`.
The original GAP-O2 failure was a missing maintenance owner in the inert fixture;
seven fixture-only lines enter/restore reactor0 and positively verify publication
before unchanged assertions. Independent Sol approved this delta and source-scoped
production-check reuse. A current daemon was built17.849s, artifact
`5dcde963c58c7576421a7350c56e33fee96c79dc3025889975a49ec4c9d5222c`.
Parent verified exact source/modes/logs and terminal ownership before server-only
promotion, preserving1,244 inputs. Manifest
`0a8c2cdaa202835caab8ecf56595b9242f0161ac3e70993b49110265f708e967`.
Inventory19accepted,28partial,51open. S2S ownership remains reactor0; full suite
and release/deployment remain unaccepted. Next R0 contracts are P03 moderation
continuity and P10 privacy corpus, authored in isolated contexts.


W74v6 privacy corpus is integrated; P10 accepted for the eight named Linux
surfaces. V2 first passed narrower controls; v5 correctly failed its address
scan because self-WHOIS also legitimately exposes ownIP via320. A diagnostic
role was misleading after cleanup overwrote a local variable; source tracing
identified the exact self-only320 formatter. V6 positively requires that actual
reply and exempts only its own-address token, never a whole window, retaining
raw credential scans. All strengthened event/diagnostic controls passed19.063s
on current daemon5dcde963. Fresh Astra full-criterion review verified inputs,
artifact/logs and terminal cleanup. Only tools/privacy_corpus_smoke.py was added;
manifest6aacd71f2e74c9252e83779bf860642c2386163b3a7dad7f2175795d51938259.
Inventory20accepted,27partial,51open. The corpus found no established Witness
leak; the separate P03 ACCESS-clock authorization defect remains pending its
full Safe gate before promotion. No deployment or full-release claim.


W73v6 is integrated; P03 accepted, including the real ACCESS expiry fix.
Twelve native matrix cases preserve exact rule scope across online/offline
rotation and both nodes, with genuine negative tuples, metadata and supported
expiry checks. A MODE no-op fixture error was corrected without weakening
assertions. The subsequent real stale-authorization-clock defect was fixed at
both policy reads; deterministic87 and native/caller90 Debug checks passed,
then the complete current Safe selection passed101/101 in402.048s, no skips,
failures, leaks or log errors. Fresh Astra reviewed every bounded correction
and approved reuse of unchanged earlier Debug cases. Runtime artifact
`bdb970570785a0c0f393252a03629a849152b6be7b4c22f43353a52a622d65af`
was built from the fixed source. Parent verified source/modes/logs/cleanup and
promoted server only, preserving1,245 inputs. Manifest
`2a90f6d79718124d34d9aeaeb51572aaa6d183e08fdfc8293e12f02b53bcaca6`;
receipt `.zig-cache/wave-73/actual-integration.json`. Inventory21accepted,
26partial,51open. SACCESS deadline semantics remain Q06 work. No release or
deployment occurred. Next contracts are P02 explicit bounded-work evidence and
recovery of the parked issuer/session Helix integration.


W75 is integrated; P02 accepted. Existing v4 wire semantics are unchanged.
Test-only compile-time instrumentation proves bounded derivation attempts,
including hostile extreme epochs; all50 leaf cases passed Debug3.727s and
Safe26.811s. A real accept-level trusted/untrusted PROXY campaign passed with
positive canonical-kernel controls. The loopback oracle was corrected to the
source-defined localhost presentation before native execution. Fresh Astra
full-criterion review verified source, receipts, remote provenance and prior
privacy/moderation evidence. Parent promoted only build.zig, cloak_match.zig
and two new leaf/proxy files, preserving1,244 existing inputs; manifest
c926b04217b48ff89dce41e9ccb2c5ddcc52a484d418e489187b73de74b757cb.
Inventory22accepted,25partial,51open. Parked issuer carry now advances as W76
under a separate mandatory native schema5; Core/OOM/native/four-attachment
acceptance remains unproved and no release/deployment claim follows.


W77v2 account authority corpus is integrated; P04 accepted. Real REGISTER/login
and WHOIS public hosts feed actual moderated ACCESS VOICE tests across five
principal pairs, seven hosts, six allowed and four404-denied messages. A fixture
PING-token self-match was corrected before native execution; all original
authority controls remain. Fresh Astra full-criterion review verified current
inputs, native/log/artifact hashes, cleanup and retained codec/HPR evidence.
Only tools/account_cloak_policy_smoke.py was added; manifest
0bde5ec09c372c433c3bf33d52a18022f0bb51a54bb935f25a6a21c741bbd5a8.
Inventory23accepted,24partial,51open. No codec/wire redesign, P09 migration
resolution, full-suite/release or deployment claim. W76 issuer/session carry
remains under focused Core/native/OOM verification, below T02 acceptance.


## W78: canonical address and reputation integration

The two-file fix closes P06 for current canonical identities. Focused Debug and
Safe each passed87/87, and the reviewed actual-daemon matrix passed in15.262s
with direct/PROXY clone equivalence, two IPv4/mapped clone checks, three
reputation refusals, both mapped UNREJECT forms and two recoveries. Binary
SHA-256: `40910a13a68c76cdf67079e9f01d2dd0c20d91904c997d2043e132b42d430875`.
The fixture's initial timeout was isolated with diagnostic phases, then corrected
by encoding the IPv6 operand as an IRC trailing parameter. No timing, penalty
or success assertions were relaxed. Legacy raw mapped checkpoint rows remain
unmigrated. Full source, logs, review and promotion evidence is retained in
`.zig-cache/wave-78/actual-integration.json`; current inventory24/23/51.


## W80: Windows permission-review compile boundary

The Windows daemon semantic gate exposed an existing Linux-mode assumption in
setup's staged material JSON. The main-only fix explicitly refuses that
permission-review path on Windows before metadata or acknowledgement. Bundle
staging and transactional custody were already Linux-only; the fix neither
fabricates Unix permissions nor treats a readonly attribute as a verified ACL.
Linux behavior is unchanged. Linux semantic check passed in13.194s; the
Windows semantic check with the pending media-pressure/capability composition
passed in14.734s. Fresh Astra approved the guarded single-file integration,
preserving1,249 inputs. Receipt `.zig-cache/wave-80/actual-integration.json`.
Windows native runtime, media handoff and setup feature acceptance remain
separate. This maintenance fix does not change the24/23/51 inventory.


## W79: integrated media feedback pressure

The reviewed five-file media change now runs in the actual source. It bounds
keyframe and NACK work per physical source and publisher, charges retained
output, preserves windows on re-offer and carries them in HXMG3 under exact
Windows v22 compatibility checks. Gates and limitations are recorded in the
[acceptance inventory](roadmap-acceptance-ledger-2026-10-26.md#w79-feedback-pressure-integration)
and `.zig-cache/wave-79/actual-integration.json`. The current inventory is
24 accepted,24 partial,50 open; C07 advanced from open to partial. No full C07,
C08, Windows live handoff or release claim follows from these bounded gates.


## W81: normalized compound feedback

The actual source now supports bounded normalization of multi-action RTCP and
multi-target FIR, replacing W79's blanket refusal. Complete target validation
precedes output; canonical packets carry only the authorized target/action,
and accepted custody drives quota charges. Native/WebRTC legacy-group wire
gates passed93/93 in Debug/Safe; live-parser malformed corpus gates passed87/87.
Linux and Windows semantic composition checks passed; fresh review approved
the exact three-file promotion. `.zig-cache/wave-81/actual-integration.json`
records source, artifacts, logs and remaining interoperability limits. C08 is
still partial and the inventory remains24 accepted,24 partial,50 open.


## W84: issuer carry and sequential session upgrades integrated

The exact reviewed 1,255-input composition is integrated; T02 is accepted for
Linux, advancing the inventory to 25 accepted, 23 partial, 50 open. The ordinary
secured A–B–C production journey retained four original TLS attachments and
shared tokens through A then B exec upgrades and resumed a fifth on C. It
verified 55 events and 407 exact deliveries in 140.437 seconds. Debug and Safe
passed all 185 adoption allocation cuts; the critical Safe suite passed 106
cases. Mandatory checkpoint schemas, descriptor census, alias protection,
nonempty owned-output custody and incompatible-successor refusal were reviewed.
Linux production and Windows semantic builds passed. See the acceptance ledger
for evidence and platform limits. Release and deployment remain pending.

W85 now targets the orphan-revoke retry cursor across Helix. Its eight-item
retry page already advances past failures; checkpoint carry is the missing
boundary. The next proof must retain fairness through repeated upgrades under
queue pressure, with a persistent early failure and progress for later groups.
It must preserve the retryable failed authority and converge after recovery.


## W88: native Alpine diagnostic budget proof

Existing production diagnostic accounting precedes sink rate limiting. The two
integrated fixture tools now test real suppression, a subsequent fresh nonzero
summary, metadata and canary exclusion under non-root Alpine/musl execution.
Five Python oracle tests passed; the native run passed in 12.834 seconds.
Observed deltas were 401 accepted and 944 suppressed events across delayed
burst processing. This advances A09 to partial, not full OpenRC/syslog or exact
per-window acceptance. The inventory is 25 accepted, 24 partial, 49 open.

The active W85 source checkpoint has independent source review, 95 Debug and
95 Safe passes (each with one Windows-only skip), and a Windows semantic check.
Its separate native fixture now awaits review and execution of two real execs,
seventeen orphan groups, persistent first-token failure and secured-peer
queue-admission pressure. T06 remains partial until the full boundary is proved.


## W87: completed-gate retry decisions

The two reviewed gate-ledger tools are integrated after 21 Python tests and
independent review. `decision` gives read-only continuation guidance: inspect
matching success for reuse, diagnose unchanged failure, investigate damaged
evidence or unstable inputs, or identify the relevant correction when context
changed. It neither runs a command nor grants acceptance. The roadmap execution
skill requires this check before repeating completed gates. The exact failed
W85 native record returned `diagnose/unchanged_failure_do_not_repeat`; its
fixture lifecycle contradiction was then established statically, without a
second diagnostic execution. Toolkit validation passed for 10 skills, 9 Codex
agents and 12 Claude agents.

The W86 full Debug attempt reached its 2,400-second supervisor deadline without
a final count; it is not green evidence. The deadline was too short compared
with the recorded prior 2,841.833-second run. Retain the failed receipt and run
the next full gate only after this wave's source is frozen, preserving the test
and count oracles with an adequate budget. No release or deployment is accepted.


## W85: fair retry cursor integrated after actual exec proof

T06 is accepted for the recorded Linux scope. Guarded promotion changed only
six existing files and added the helper/tool, preserving all 1,249 other inputs
including the A09 and W87 tool changes. The SRHC envelope binds the retry cursor
to unchanged SRSTv3 authority; capabilities refuse incompatible targets.

Independent review verified the existing dirty/projection fairness evidence and
new 95 Debug/95 Safe semantic cases, Windows semantic check and actual two-exec
seventeen-group proof. A persistent earliest failure did not strand later
pages; natural recovery retained canonical signed bytes and avoided revision
churn under queue-admission allocation pressure. The corrected native fixture
uses ordinary authenticated detachment and physical retirement; its earlier
contradictory setup remains recorded as failed evidence.

The new composed daemon also passed the ordinary non-clique A–B–C TLS journey:
four original attachments, A then B same-PID execs, fifth C resume, 55 events
and 407 exact recipient deliveries. Inventory: 26 accepted, 23 partial, 49 open.
The full-suite timeout is still not a release pass. W89 continues the remaining
actual OpenRC-to-syslog delivery proof on this same binary in a disposable VM.


## W89/W90: integrated Alpine logging and no-cohort retry reuse

The six-file composition is integrated with 1,253 existing inputs preserved.
A09 is accepted on the recorded Alpine 3.24.3 KVM platform; T03 advances to
partial. Inventory: 27 accepted, 23 partial, 48 open.

The current binary passed actual nonroot OpenRC-to-BusyBox-syslog delivery,
verified stderr/logger pipe identity, rate suppression, a fresh summary,
private-canary exclusion and cleanup. The canonical driver requires an explicit
expected artifact digest, preventing source edits after every binary build.

The token slice reuses a current accepted OFFER after a split OFFER/lease
failure without losing replay custody for an unaware secured peer. Debug99,
Safe99 and the coupled-peer proof passed. Mutations, renewal, expiry, withdrawal
and authority changes retain strict treatment. Cohort and other credential
families remain outside this bounded optimization. Reason counters are fixed
and reset per image; queued or locally accepted work is not a remote receipt.
Linux build, Windows semantic composition, full formatting and final combined
VM acceptance passed. The earlier full-suite timeout remains failed evidence;
the next full gate uses a frozen source and at least 4,800 seconds.


## W94: verified audit integrated without blocking on the baseline suite

The reviewed ACCESS/SACCESS `cloak-audit` slice is integrated, advancing P09 to
partial. It passed 15 Debug and 15 Safe tests, Linux build, Windows semantic
compile and a 44-process native campaign. Independent review approved the leaf,
module ownership, native evidence and exact eight-file promotion. All 1,256
other existing inputs were preserved. Evidence and limits:
`.zig-cache/wave-94/actual-integration.json`.

The suite running in W91 retains its original frozen W90 context and immutable
manifest. It is baseline evidence only; integrating W94 does not change or
restart that job. The final composed release still requires its own full suite.
Current work is the separate AKCK/WARD audit leaf and the signed Alpine package
startup diagnosis. Existing ACCESS/SACCESS proof and A09 logging stay closed.
Inventory: 27 accepted, 24 partial, 47 open. No deployment or publication.


## W97: policy audit promoted; completed scopes removed from the work queue

The reviewed four-kind offline CLI is integrated. Debug/Safe counts are 16/16,
Linux and Windows checks pass, and native campaigns passed 44 compatibility
cases plus 16 AKICK/WARD cases using the production matchers. Promotion preserved
1,261 other inputs; receipt `.zig-cache/wave-97/policy-actual-integration.json`.
P09 remains partial pending the relation-preserving World adapter.

The signed Alpine existing-file-key profile also passed native acceptance
(`.zig-cache/wave-95/alpine-signed-native-v9.json`). Broader A04 remains partial
until configured credentials reuse a prepared identity through strict startup.
The baseline suite's two leaf fixture failures are corrected; seven isolated
Core failures remain. No unchanged full-suite retry is scheduled.

Completed source-bound proofs stay closed. A failed gate needs a recorded cause
and relevant correction before retry; active handles and owners are recorded in
`.zig-cache/CURRENT.json`. Inventory remains 27 accepted, 24 partial, 47 open.


## W99/W101: verified Core fixtures and World audit promoted

Five more baseline Core fixture failures are corrected and integrated after
Debug groups of 120/87/87 and one combined Safe gate of 122 tests. The latter
uses supported repeated test filters to share compilation. Production behavior
is unchanged by these fixture repairs. Receipt:
`.zig-cache/wave-99/actual-five-fixture-integration.json`.

The World checkpoint audit is also integrated after leaf 56/56, CLI 66/66,
Linux/Windows and 71 native cases. Independent review verified physical
relations, custody and exact artifact pins. Receipt:
`.zig-cache/wave-101/actual-world-integration.json`. These scopes stay closed;
raw Services record coverage is the remaining P09 slice.

The two remaining baseline failures exposed production defects: a closing
session could not retry logical handoff while SEND pinned its physical storage,
and cross-shard introduction incorrectly inferred a recipient shard from the
calling reactor. Both fixes pass focused Debug; their combined source passed
153 tests with no skips, failures or leaks. Its Safe gate also passed all 153 tests. Both production fixes are integrated.

The composed source then passed the full Debug suite: **10,887 passed, 330
skipped, zero failed or crashed**. Receipt:
`.zig-cache/wave-103/full-debug-after-core-fixes-v1.json`; source and log hashes
and terminal cleanup verified in `full-debug-verification-v1.json`. This closes
the nine original baseline failures on source manifest `85deac57`. The private
raw Services audit expansion and Alpine startup changes are outside that proof.
No deployment occurred.


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


## W111: strict Alpine startup integrated; final composed suite running

A04 is accepted for the recorded Alpine x86_64 package/identity workflow after
fresh signed artifacts, four real held-client Helix upgrades, three specific
drift refusals, typed negative credential checks, custody and file preservation.
Native proof: `.zig-cache/wave-110/alpine-native-verification-v14.json`.
Integration: `.zig-cache/wave-111/actual-foundation-integration.json`.

Current source `d1f36eb323a0` includes all accepted raw-audit, capability-help and
Alpine changes. Full Debug is running on a byte-identical frozen 1,287-input
context. Keep that gate's handle; the earlier green suite covers parent source
only. Future media deadline work has its own private context and is excluded.
Inventory: 29 accepted, 22 partial, 47 open. Nothing has been deployed.


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


Wave118: integrated a read-only checkpoint audit with ten synthetic controls,
including terminal jobs mislabeled running, completed receipts, malformed
supervisor documents, duplicate ledger rows and parent/current source confusion.
The real audit reports no issues or unknowns. It does not infer process liveness,
restart jobs or accept gates. CURRENT now archives historical waves and retains
active contracts and exact handles. Q04 scoped integration is partial; current
counts are29 accepted,23 partial,46 open. T05 and media source remain private;
no release or deployment occurred.


Wave119 private token work: current mesh cohorts use signed inventory offers,
which the initial memo bypassed. The reviewed extension admits those immutable
signatures under the same exact bytes/key/authority/expiry binding and retains
all Store revocation and quarantine checks. Composed Debug99 passed with no
skips, failures, leaks or logged errors. A strict-validator fixture failure in
v1 is preserved; v2 clears only the nonresumable fixture's nick and snapshot.
Safe gates remain active in CURRENT. Native runtime counters do not yet expose
receiver signature work, so neither throughput improvement nor T05 acceptance
is claimed. The change remains private and does not advance inventory counts.


Wave120/121: integrated the reviewed five-file media-age change, then the
reviewed dual-musl release scripts and target-specific build-metadata controls.
The five script tests are synthetic; the actual dirty-tree release guard also
refused safely without creating output. Reproducibility and native aarch64
acceptance remain unproved. Corrected source-bound token gates passed server
Safe97, inventory Safe88 and final stats/composed Debug102. Stats Safe remains
active. One new full Debug gate runs on final composition manifest `2c2432ce`
(1292 inputs), combining Q04, media and token code with current release tooling.
No unchanged parent-full rerun, no deployment, commit, tag or push occurred.


Wave122/123: private help syntax v2 passed all15 help module cases plus86
imports (101 total), including the actual SESSION parser test-only import.
CHATHISTORY, CHANNEL and SESSION displayed examples are lexer/parser-backed.
A private ReleaseFast benchmark then passed nine cases/36 timing rows with
actual memo work counters and byte-equal retained Store state. Warm fitting
working sets1/4 showed paired median speed ratios28.921/28.201; set8 thrashed
the four-slot cache with ratio0.996. This measures direct leaf processing only.
The benchmark remains private; current full source stays `2c2432ce`.
Wave124's first hermetic build refused before compilation because Zig cache
bootstrap needed an application cache location. The corrected, independently
reviewed v3 gives each build a private XDG cache while preserving independent
local/global caches and every source/ELF/equality check. Failure is retained,
not retried unchanged. Four real builds are active. W12 maintenance implementation
is private, split between wizard/controller and Linux backend owners.


Wave121 full Debug completed in3022.702s with10929 passed,330 skipped,
one failed and no crashes (11260 total). All1292 actual/frozen inputs and log
`f9b3f5ec` were verified. The sole failure was the existing spatial-authorization
fixture waiting through two700ms negative UDP polls under the new1000ms age
ceiling. Wave127 freezes only that fixture's cache clock; all real UDP and
policy assertions remain. Debug88 includes the real queued-expiry control;
Safe87 covers the repaired fixture. Both pass with no skipped/failed/leaked
cases or logged errors. Guarded one-file promotion preserved1291 inputs;
actual manifest is now `8c96bc41`. Production code is unchanged. The failed
full result remains failed; another full run awaits the next coherent batch.
A current-artifact secured A-B-C/rolling-Helix regression is running because
the new memo changed the live received-OFFER and Server lifecycle paths.
