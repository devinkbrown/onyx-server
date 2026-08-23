# Exact session resume durability rollout

**Status:** deployed and accepted on 2026-08-14.

## Release identity

| Item | Value |
|---|---|
| Server source commit | `3e455ba` (`fix: make exact session resume durable`) |
| Server version | `0.5.8+3e455ba` |
| ReleaseFast musl SHA-256 | `10fd8f945ce8b211382279d6fd96b7d128677d782724c92e026a65f8b5c5c2af` |
| Client source commit | `bda92b58` |
| Client service-worker release | `onyx-shell-20260814-203916-bda92b58` |

## Delivered behavior

- `SESSION TOKEN` issues an attachment-scoped `srm2l` credential and `SESSION
  MTOKEN` issues a signed attachment-scoped `srm2m` credential when
  `[sessions].resume_composite_issuance = true`.
- Exact resume selects one physical attachment, moves its durable delivery spool
  transactionally, and leaves same-token siblings untouched.
- Legacy bare and SRM1 credentials remain create-new compatibility paths and do
  not consume a ghost attachment or its spool.
- HSSN v4 carries the stable attachment ID across Helix. A v3 predecessor may
  upgrade into this reader; a v4 predecessor refuses rollback to a v3-only
  target before inherited descriptors are exposed.
- At-cap E2EE clients receive a bounded resume-only hold instead of losing exact
  authority. Peer signer/name snapshots are copied under synchronization and
  update immediately on establishment, collision resolution, and teardown.
- Account `DROP` drains the requester's final success notice before closing it.

## Verification before release

- Authoritative module gate: 8,380 passed, 4 platform skips, 0 failed, 0
  leaked, 0 log errors (`zig build test-mod-verbose --summary all`).
- Session suite: 741/741 passed.
- Mesh suite: two independent runs, each 482 passed, 2 platform skips, 0
  failed.
- ReleaseSafe coverage included exact selector/spool transfer, E2EE at-cap
  hold/expiry, v3-to-v4-to-v4 AID preservation, legacy non-consumption, Helix
  capability forward/rollback checks, peer lifecycle, and cross-reactor DROP.
- `zig build check`, `zig fmt --check`, and `git diff --check` passed.
- A fresh independent review found no release blocker after the fixes.

## Two-phase production activation

Both nodes first received the exact reader binary with composite issuance left
at its default `false`. Each exact live TOML passed `--check-config`. Helix then
rolled one node at a time, preserving the systemd MainPID, clients, sessions,
and the secured mesh link. Only after both readers and cross-node chat were
accepted was `resume_composite_issuance = true` added to both `[sessions]`
sections, revalidated, and activated one node at a time through Helix.

| Node | MainPID before/after | Installed and running SHA-256 | Activated config SHA-256 |
|---|---:|---|---|
| eshmaki.me | `828697` | `10fd8f945ce8b211382279d6fd96b7d128677d782724c92e026a65f8b5c5c2af` | `3921497b7e9201db7255b1bb12b30f8487adb5714956c2dc19005190e496ff3d` |
| ircx.us | `1245448` | `10fd8f945ce8b211382279d6fd96b7d128677d782724c92e026a65f8b5c5c2af` | `7d8f1f77a50cb703ee582f697c844dbe88aa65d4511504cd2099c779cce03e63` |

Post-activation acceptance proved on both nodes:

- `links_active=1`, `peers_up=1`, `partitioned=0`, `tcp_active=1`;
- ERA2 unit/version/artifact/mesh acceptance passed;
- bidirectional cross-node `PRIVMSG` passed;
- a live `srm2l` credential was issued, detached, resumed exactly, and remained
  byte-identical afterward;
- a live `srm2m` credential produced an authenticated redirect on the trusted
  peer and then resumed the exact attachment on its named origin.

The client was deployed separately through `/home/kain/onyx/deploy.sh`.
`https://eshmaki.me/app/` returned HTTP 200, the public service-worker stamp
matched the release above, and the deployed entry chunk was byte-identical to
the local build.

## Rollback

Pre-release binaries and configs are retained on each node as
`onyx-server.pre-3e455ba` and `onyx-server.local.toml.pre-3e455ba`. The previous
binary SHA-256 is
`db4a9c4a40a25117cdfee912dddad7e2432c0ac3200bb8cb9e2be90634aa5b53`.

Do not hot-roll the current sessions-v4 process back to that v3-only binary: the
Helix capability barrier intentionally refuses it. A safe operational rollback
keeps the current reader binary, restores the pre-release config (which disables
new composite issuance), validates it, and reloads one node at a time. Existing
SRM2 credentials remain readable. A binary rollback would require a planned
cold transition that accepts session loss and must not be used while SRM2
credentials are expected to resume.
