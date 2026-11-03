# E2EE group authority activation and custody

E2EEGROUP transports opaque client control records through a signed, replay-checked
mesh authority. Its activation barrier is separate from MESSAGE_V2 authoring.
Use [production paths](onyx-server-paths.md) for the accepted image and
[the release runbook](../RUNBOOK.md) for authorized rollout and recovery.

## Operator controls and readiness

A registered operator can inspect the process-local barrier:

```text
E2EEGROUP STATUS
```

`E2EEGROUP OFF` disables new locally authored controls on that node;
`E2EEGROUP ON` resumes them only when every required direct peer is established
with current E2EEGROUP capability. A mesh-enabled node with no current peer
does not incorrectly become ready at `0/0`. These commands require an operator
session before any barrier/status observation and return count-only metadata.
They never expose relay IDs, public keys or opaque payloads.

The startup value is `[e2ee].group_authoring_enabled`. A successor config with
that value false does not quiesce a still-running predecessor. Before an operation
that requires an authoring barrier, apply OFF to every relevant running node
and verify the actual runtime state. One local OFF is not a mesh-wide barrier.

The count-only Prometheus surfaces are:

| Gauge suffix after `onyx_e2ee_group_` | Meaning |
| --- | --- |
| `local_authoring_enabled` | Whether this process admits new local controls |
| `current_capable_peers` / `required_peers` | Established current peers versus required direct peers |
| `activation_ready` | Current-capable peers satisfy the required set |
| `hop_custody` | Exact signed hop wires awaiting peer ACK |
| `ingress_receipts` | Metadata receipts awaiting ACK_CONFIRM from their ingress peer |
| `pending` | Exact relay identities with unsettled custody or receipts |

Peer readiness is a local direct-neighbor observation. A multi-hop deployment
must establish the barrier/readiness condition on every participating node;
one neighbor's success does not certify hidden nodes or client encryption.

## Retention and restart boundaries

Hop custody retains exact origin-signed wires in RAM. Pending identities retire
without allocation when their final custody/receipt settles; continuous partition
can still exert bounded-capacity backpressure. Ingress receipts persist until
authenticated ACK_CONFIRM and do not expire as a substitute for completion.

The EGRG checkpoint carries replay state, unsettled exact identities and
metadata-only ingress receipts. It never carries opaque payloads or live hop
wires and refuses sealing while custody is outstanding. Current Helix requires
the exact `e2ee-group-authority-v2` authority together with the rest of its
mandatory capability/state contract; a compatible individual marker alone is
insufficient. Missing/malformed mandatory state refuses transactionally.

Cold boot does not recover this RAM delivery authority from the account WAL.
Before a planned cold stop, hold the required producer barrier, observe custody,
receipts and pending on every affected node, and apply the runbook's explicit
custody/recovery contract. Quiet counters without a held producer boundary do
not fence future work. MESSAGE_V2 custody needs its separate checks as well.

## Compatibility and acceptance

Current E2EEGROUP uses the `onyx-xcap-e2ee-group-2` probe/reply. It does not bridge
controls to a pre-current peer. Do not permit authoring across a mixed-generation
fleet simply because TCP or secured S2S has connected. If an old predecessor
cannot enforce the required barrier, a coordinated outage may be required before
any new-generation process starts. Determine the path from the actual images;
never replay an old release-specific restart recipe against a later topology.

After a compatible rollout, require current-peer readiness, secured mesh health,
real authorized control delivery and audience isolation before enabling authorship.
The accepted daemon's general chat/session smoke does not substitute for live
client group-crypto acceptance. Rollback must preserve the current authority and
full mandatory Helix contract; do not hot-downgrade into a decoder that cannot
accept them.

Focused implementation checks, followed by the complete release gates:

```sh
zig build test-mod -Dtest-filter=E2EEGROUP --summary all
zig build test-mod -Doptimize=safe -Dtest-filter=E2EEGROUP --summary all
```

Source of truth: `src/daemon/e2ee_group_mesh_authority.zig`,
`e2ee_group_outbox.zig`, `e2ee_group_replay_guard.zig`, `server.zig`
(`handleE2eeGroupOperatorControl`, `e2eeGroupPeerReadiness`,
`writeE2eeGroupPrometheus`), `src/daemon/helix/live.zig` and
`src/substrate/undertow/s2s_peer.zig`.
