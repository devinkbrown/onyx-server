# Account read-marker mesh continuation

Starting commit: `114e1cd4`. Status: implementation and local acceptance complete; no deployment
or push. GAP-P16's local cold-restore proof did not demonstrate another node.

The continuation stages runtime marker updates before durable admission, retains
one durable row per account/target with its exact original signed fact, and keeps
a separate durable marker clock. Marker positions merge by maximum validated
UTC timestamp; generic property arrival/HLC order cannot move them backwards.

The transport reuses signed ENTITY_PROP envelopes under the reserved private
`read.marker/` namespace, with explicit PING/PONG support negotiation. Old peers
that merely echo probes must never receive these facts. The daemon accepts them
only over established secured links, verifies the original signature and canonical
account/target/digest, and does not expose them through ordinary PROP paths.
Retained winning facts repair on capability appearance, reconnect and RESYNC.

New guest markers are memory-only and keyed by physical connection identity.
Authenticated markers use the canonical Services account. Legacy untyped owner
rows remain local-only and are never automatically signed or exported; an explicit
authenticated SET authors a new fact. Account-directory activation is a separate
roadmap item; the marker origin signature certifies the mesh node's assertion.

Owners: root owns `read_marker_store.zig`, `marker_durable.zig`, S2sPeer, link
adapter leaves and Linux/native Helix reader capability gates; `onyx-server-integrator` alone owns `server.zig`. Review is read-only.

Acceptance exercises distinct A-B-C stores and secured links, actual SET/GET,
partition/heal with timestamps ordered opposite to HLC, preserved origin bytes,
cold restart with no originating client, allocation rollback and same-input retry,
ambiguous I/O refusal, guest isolation and unsupported/unsigned/malformed peers.
The completed Linux gates are check, mesh, Helix, server and Services in Debug and
ReleaseSafe plus the full test gate. Native OpenBSD selection runs on the default
8192 KiB stack. Final source pins and independent leaf/integration reviews are recorded in
[evidence](evidence/read-marker-mesh-2026-09-30/README.md). Full Linux Debug and
ReleaseSafe each pass 8811/8835 with 24 skips and zero failures. Focused marker
tests pass 94/94 in both modes. Final native OpenBSD selected runners pass 91/94
with three explicit Linux-only skips; CLI 2/2 and daemon zero selected tests.
All affected named gates also pass in both modes, with counts and command
timings in the evidence record. Work was accepted locally on 2026-10-01; no
production release or native live multi-host campaign is claimed for this slice.

Two independent review findings were repaired before final acceptance. Private
secured sends now reserve the outer encrypted record and inner signed frame
before plaintext publication: outer OOM leaves both queues empty and the retained
fact available for retry. Existing unrelated inner output is preserved and causes
a retryable refusal. Linux and native Helix require `read-marker-mesh-v1` in the
current reader contract before handing off live descriptors. Frozen predecessor
contracts remain forward bridges into this reader. A hot downgrade cannot inherit
already queued private frames and treat them as public user properties.

The initial OpenBSD Debug run exposed stack overflow in two existing threaded
MARKREAD fixtures. Their large server fixtures now use the test allocator; all
original assertions remain. The rerun uses the unchanged 8192 KiB native stack.
Guest markers remain physical-connection memory state and do not claim process
restart continuity. Account-directory mesh activation remains a separate gap.

Privacy assumes that operators provision the canonical Services account namespace
consistently across participating nodes. Independently created same-name accounts
share a marker bucket; this slice does not establish globally unique account
ownership. Original signatures authenticate the node's assertion. The separate
account-directory activation gap must be closed before claiming that stronger
identity contract.
