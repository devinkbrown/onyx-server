# E2EE group authority v2 activation (EGRG)

**Status:** first production dual-node activation **completed** (2026-07-28) via cold
restart of both units under a coordinated full outage (both `0.5.6` predecessors
stopped before any `0.5.7` successor started). Deployed predecessors did **not**
expose the v2 operator control/metrics; `group_authoring_enabled=false` was
prepared and validated as the **v2 successor startup barrier**, not as an active
quiesce of the still-running old processes. Live Helix USR2 adoption of EGRG
remains **not** the first-rollout path and is still out of scope for that
completed cold wave. Detailed inventory and post-activation metrics:
`docs/ops/release-v0.5.7-e2ee-group-control.md`.

## First production activation record (2026-07-28)

| Item | Fact |
|------|------|
| Path | Coordinated full outage first (both `0.5.6` predecessors stopped together before any successor start); `group_authoring_enabled=false` prepared/validated as **v2 successor startup barrier** only; install only after both down; both v2 units started under that barrier; authoring later via current-version rolling restart |
| Units | `onyx-server.service` on `eshmaki.me` and `ircx.us` |
| Banner (both) | `Onyx Server 0.5.7+b457c33` |
| Artifact SHA-256 (identical both) | `a867fa71afaaeeda6c6f25b024a995ab8b1436e6b7f9d8b2541f6a1d32d28ed4` |
| Config | `group_authoring_enabled=false` prepared for successors; validated on both nodes after install (both predecessors already down) before authoring release |
| Authoring release | After both v2 units were up and secured mesh xcap readiness for current E2EEGROUP; enabled later with a current-version rolling restart |
| Per-node post metrics | `local_authoring_enabled=1`, `current_capable_peers=1`, `required_peers=1`, `activation_ready=1`, hop_custody=`0`, ingress_receipts=`0`, pending=`0` |
| Mesh health (both directions) | `links_active=1`, `peers_up=1`, `partitioned=0`, `tcp_active=1` |

Not claimed here: client live OGC1 send/receive, browser encryption, or a GitHub
Release asset.

The sections below preserve the authority model, mixed-fleet hazard, and the
cold-restart procedure as executed for this first rollout (both predecessors
down before install) and as operator guidance for any later cold re-activation
under mixed-version risk.

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
or mesh hop while the dual-node pair is version-split. The **executed first cutover**
avoided a live mixed pair by a **coordinated full outage**: stopping **both**
`0.5.6` predecessor processes **before any** `0.5.7` successor started, installing
the v2 image only after both were down, then starting both v2 units under a prepared
`group_authoring_enabled=false` **successor startup barrier** (Helix USR2 is not the
first path). Deployed `0.5.6` did **not** expose that control; it did not quiesce the
still-running predecessors. Authoring was released only after both nodes ran v2
**and** current E2EEGROUP was negotiated on the secured link (later enabled with a
current-version rolling restart).

## Fail-closed version-transition outage + v2 successor authoring barrier

For the **executed first cutover** (`0.5.6` → `0.5.7`), two distinct facts must not be
collapsed:

1. **Transition protection (actual fail-closed):** a coordinated **full outage** —
   both predecessor processes stopped **together** before any successor start. That
   is what prevented a live mixed-version authoring window. Deployed predecessors
   lacked the v2 operator control/metrics, so no config key could actively quiesce
   them.
2. **Successor startup barrier (prepared/validated):** production config carried
   `group_authoring_enabled=false` so **v2** units start authoring-disabled until
   mesh/xcap readiness and a later current-version rolling enable.

For **future** cold re-activations where **both** dual-node units already run an
image that **does** expose the operator control, establish a mesh-wide authoring
barrier that:

1. **Quiesces E2EEGROUP authoring** on **every** dual-node unit via the enforceable
   control (no new origin-signed E2EEGROUP controls admitted for mesh hop while the
   barrier holds).
2. Remains **fail-closed**: if the enforceable control is missing, misconfigured, or
   only partial (one node quiet, the other still authoring), **do not start** activation.
3. Stays held through (first production cutover order, adapted when the control is
   live on both sides):
   - drain of hop custody / acceptance of cold-drop for receipts on **both** nodes,
   - cold **stop of both** predecessor `onyx-server.service` processes **together**,
   - install of the validated v2 binary **only after both** predecessors are down,
   - cold **start of both** v2 units (still under the authoring barrier),
   - re-establishment of secured S2S **and** successful current E2EEGROUP xcap negotiate
     (`peer_supports_e2ee_group_current` both directions on the dual-node link).
4. Is **released only after** both units run the v2-capable image **and** the current
   E2EEGROUP extension is negotiated mesh-wide for the dual-node pair (no remaining
   pre-v2 E2EEGROUP peer in that pair). First cutover released authoring later via a
   current-version rolling restart.

There is no supported “author on the old node while the new node catches up” path: v2
does not bridge controls to v1 peers.

## First rollout (cold restart; both predecessors down before install)

Live Helix USR2 from a pre-marker / pre-EGRG binary will refuse this image
(expected). **First mesh activation is cold restart only**, under the coordinated
full outage + successor barrier truths above. This procedure was executed for
dual-node production on 2026-07-28 (`0.5.7+b457c33`; see activation record above).
It was **not** a one-node-at-a-time first cutover.

0. **Prepare and validate** production config with `group_authoring_enabled=false`
   as the **v2 successor startup barrier**. (On the executed first cutover, deployed
   `0.5.6` did **not** expose this control or its metrics — do **not** treat the key
   as having quiesced the still-running predecessors.)
1. **Drain** MESSAGE_V2 hop custody on **both** nodes about to restart (no outstanding
   V2 retry obligations that must survive process death).
2. **Drain** E2EEGROUP hop custody and prove unsettled ingress receipts are
   acceptable to drop on **both** nodes (cold boot does not restore them). There is
   **no** durable adopt of EGRG on this path. (Pre-v2 images may lack the v2 gauges;
   operators use the instrumentation available on the running image.)
3. **Stop** both predecessor `0.5.6` `onyx-server.service` processes **together**
   (coordinated full outage — fail-closed protection for the version transition).
4. **Only after both** predecessors are down: install the validated `0.5.7+b457c33`
   binary/config on both nodes (config includes the successor authoring barrier).
5. **Start** both v2 units (they come up under `group_authoring_enabled=false`).
6. Confirm mesh health (`links_active`, secured S2S) **and** current E2EEGROUP xcap
   negotiate on the dual-node link. **Do not** lift the successor authoring barrier
   until this readiness is proven.
7. **Release** authoring later with a **current-version rolling restart** (both nodes
   already on the v2 image; not a mixed-version window).

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

## Pre-deploy implementation blockers (historical gate for first activation)

For the **first** production activation these were required gates. They were
satisfied for the 2026-07-28 dual-node cutover as follows: coordinated full
outage of both `0.5.6` predecessors (the transition protection, because those
images lacked the v2 control/metrics); `group_authoring_enabled=false` prepared
and validated as the **v2 successor startup barrier**; custody/receipt/pending
gauges observed zero **post-activation** on the v2 image as recorded above. They
remain the operator checklist for any **future** cold re-activation that
reintroduces mixed-version risk (where both sides already expose the control):

| Blocker | Why |
|---------|-----|
| Fail-closed transition + enforceable authoring barrier | First cutover: coordinated both-stop (predecessors had no v2 control). Future same-generation cold work: a real operator control must fail-close authoring on **all** dual-node units for the full barrier window — doc-only discipline is not enough. |
| Custody/receipt observability | Source exposes count-only Prometheus gauges: `onyx_e2ee_group_hop_custody`, `onyx_e2ee_group_ingress_receipts`, and `onyx_e2ee_group_pending`. They are snapshotted under the E2EEGROUP authority mutex and disclose no payloads, relay IDs, or keys. On images that expose them, prove all three gauges are zero on both nodes before each cold stop; the first `0.5.6`→`0.5.7` cutover recorded zeros after v2 start. |

### Instrumentation note

Treat the three E2EEGROUP gauges as the required pre-stop drain proof. Operators must not
invent ad-hoc metrics or IRC commands: before each cold stop, prove all three gauges are
zero on both nodes from the installed image.

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
