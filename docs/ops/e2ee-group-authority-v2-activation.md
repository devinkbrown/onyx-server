# E2EE group authority v2 activation (EGRG)

**Status:** first production activation is a **planned cold restart of both dual-node
units behind a mesh-wide E2EEGROUP authoring quiesce/activation barrier**. Live Helix
USR2 adoption of EGRG is **not** the first-rollout path.

## Current truth (authority model)

| Fact | Behavior |
|------|----------|
| Pending exact | Exists **only** while outgoing hop custody **or** an ingress receipt is unsettled for that `RelayId`. Settled local traffic never consumes pending capacity. Code **retires** pending when custody and receipts settle for that id; pending retirement itself is implemented, not an open policy gap. Continuous partition is **operational backpressure** (capacity / hop pressure), not unresolved retirement semantics. |
| Ingress receipt | Metadata-only (`peer`, `RelayId`, retry/attempts). Persists until the original ingress peer authenticates **ACK_CONFIRM**. Does not expire or rotate. |
| Hop custody | RAM-only exact origin-signed wires per direct peer. Never sealed into Helix. EGRG encode **fails closed** while custody is outstanding. |
| Cold boot | Starts **empty**. Does **not** adopt EGRG from disk/capsule on this first rollout path. Any RAM custody/receipts/pending die with the process. |
| EGRG seal | When custody is empty: RVG2 + pending exact (unsettled only) + ingress receipts. Opaque payloads and live custody wires are never checkpointed. |
| Capability | Helix upgrade token marker `e2ee-group-authority-v2`. Predecessors without the exact token refuse the target **before** exec. |
| S2S negotiate | E2EEGROUP current path is xcap-probed (`onyx-xcap-e2ee-group-2`). A v2 peer **does not** negotiate the current extension with a pre-v2 peer and **does not** send E2EE_GROUP to peers lacking `peer_supports_e2ee_group_current`. |

## Mixed-fleet hazard (why naive one-node restart is blocked)

A plain **one-node-at-a-time cold restart without a mesh-wide authoring barrier** creates
an interval where one dual-node unit runs E2EEGROUP **v2** while the peer still runs
pre-v2 (**v1** authority path / no current xcap).

During that mixed interval:

- The upgraded node will not complete current E2EEGROUP negotiation with the old node.
- The upgraded node will not send E2EE_GROUP frames to the still-v1 peer.
- Controls **authored on the still-old node** can be accepted locally (or only among
  pre-v2 peers) and **never hop-retained** onto the upgraded node.
- Controls authored on the upgraded node are likewise not mesh-forwarded to the old peer
  under the current extension.

That is a **deployment blocker**: first activation must not allow any E2EEGROUP authoring
or mesh hop while the dual-node pair is version-split. One-node-at-a-time **process**
restart remains the only allowed restart order (Helix USR2 is not the first path), but
only **after** mesh-wide authoring is already fail-closed and only until **both** nodes
are upgraded **and** current E2EEGROUP is negotiated on the secured link.

## Fail-closed mesh-wide E2EEGROUP authoring quiesce / activation barrier

**Before the first node restarts**, establish a mesh-wide barrier that:

1. **Quiesces E2EEGROUP authoring** on **every** dual-node unit (no new origin-signed
   E2EEGROUP controls admitted for mesh hop while the barrier holds).
2. Remains **fail-closed**: if the enforceable control is missing, misconfigured, or
   only partial (one node quiet, the other still authoring), **do not start** activation.
3. Stays held through:
   - drain of hop custody / acceptance of cold-drop for receipts on the node about to die,
   - cold stop/install/start of node A,
   - mesh health restore (`links_active`, secured S2S),
   - cold stop/install/start of node B,
   - re-establishment of secured S2S **and** successful current E2EEGROUP xcap negotiate
     (`peer_supports_e2ee_group_current` both directions on the dual-node link).
4. Is **released only after** both units run the v2-capable image **and** the current
   E2EEGROUP extension is negotiated mesh-wide for the dual-node pair (no remaining
   pre-v2 E2EEGROUP peer in that pair).

There is no supported “author on the old node while the new node catches up” path: v2
does not bridge controls to v1 peers.

## First rollout (cold restart, barrier first, then one node at a time)

Live Helix USR2 from a pre-marker / pre-EGRG binary will refuse this image
(expected). **First mesh activation is cold restart only**, under the barrier above:

0. **Activate mesh-wide E2EEGROUP authoring quiesce** (fail-closed). Prove neither dual-node
   unit will admit new E2EEGROUP origin controls for the duration of activation.
1. **Drain** MESSAGE_V2 hop custody on the node about to restart (no outstanding
   V2 retry obligations that must survive process death).
2. **Drain** E2EEGROUP hop custody and prove unsettled ingress receipts are
   acceptable to drop (cold boot does not restore them). There is **no**
   durable adopt of EGRG on this path.
3. **Stop** `orochi.service` on **one** node only.
4. Install the new binary/config, then **start** the node.
5. Confirm mesh health (`links_active`, secured S2S). **Do not** lift the authoring
   barrier. The peer is still pre-v2 for E2EEGROUP current; mixed authoring remains forbidden.
6. Repeat stop/install/start for the second dual-node unit after the first is healthy.
7. Confirm secured S2S **and** current E2EEGROUP xcap negotiate on the dual-node link.
8. **Release** the mesh-wide E2EEGROUP authoring quiesce only after step 7.

**No rollback** past an image/arena that already requires EGRG recognition:
predecessors that cannot parse EGRG must reject the arena. Do **not** attempt
mixed live Helix re-exec between pre-`e2ee-group-authority-v2` and post-marker
images for first activation.

Cold-boot truth is unchanged: first rollout does **not** adopt EGRG from disk/capsule;
RAM custody, receipts, and pending die with each process.

## Later Helix path (not first rollout)

A later rollout may seal/adopt EGRG under Helix with the
`e2ee-group-authority-v2` capability. That path **requires** EGRG + capability
parity on both sides and is out of scope for the first cold-restart wave.

## Pre-deploy implementation blockers

Until the following land (or are proven present in the image under activation),
**do not** run first production activation:

| Blocker | Why |
|---------|-----|
| Enforceable mesh-wide E2EEGROUP authoring quiesce | Without a real operator control that fail-closes authoring on **all** dual-node units for the full barrier window, mixed v1/v2 authoring can still occur between restarts. Doc-only discipline is not enough. |
| Custody/receipt observability | No dedicated first-class operator metric or control command today for E2EEGROUP hop-custody depth (peer+`RelayId`) or unsettled ingress receipt ledger (count / peer / `RelayId` / due ACK). Drain proofs need that surface (or already-shipped internal debug hooks of the running image—do not invent ad-hoc metrics/IRC commands). |

### Instrumentation note

Treat **custody/receipt observability** as a pre-deploy instrumentation blocker for
confident drain proofs. Operators must not invent ad-hoc metrics or IRC commands; prove
drain from whatever internal debug hooks the running image already provides, or land
explicit instrumentation before production activation.

### Not a pending-retirement blocker

Pending exact retirement when custody and receipts settle is **implemented**. Continuous
partition is operational backpressure on capacity/hops; it is **not** an open “pending
retirement policy” product gap for this activation.

## Other production truths (not open policy blockers)

| Item | Truth |
|------|-------|
| No pre-EGRG rollback | Rolling back past EGRG-aware images against a sealed EGRG arena is fail-closed by design (later Helix path). First cold path never adopts EGRG, so each cold start is empty. |
| Continuous partition | Backpressure only; settle (ACK + ACK_CONFIRM) retires pending. Plan capacity/ops under long partitions separately from activation. |

## Verification (post-install, offline gates)

```bash
zig fmt --check src/daemon/e2ee_group_outbox.zig src/daemon/e2ee_group_replay_guard.zig
git diff --check -- src/daemon/e2ee_group_outbox.zig src/daemon/e2ee_group_replay_guard.zig docs/ops/e2ee-group-authority-v2-activation.md
zig build test-mod -Dtest-filter=E2EEGROUP
zig build test-mod -Doptimize=ReleaseSafe -Dtest-filter=E2EEGROUP
```

## Related code

- `src/daemon/e2ee_group_mesh_authority.zig` — admit cut, custody + receipt + pending
- `src/daemon/e2ee_group_outbox.zig` — hop custody + ingress receipt ledger
- `src/daemon/e2ee_group_replay_guard.zig` — EGRG v2 pending exact + receipt seal
- `src/daemon/helix/live.zig` — `e2ee-group-authority-v2` capability marker
- `src/substrate/undertow/s2s_peer.zig` — `onyx-xcap-e2ee-group-2` probe/reply; send gated on `peer_supports_e2ee_group_current`
