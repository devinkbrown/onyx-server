# Mesh deployment acceptance checklist

Use this checklist together with the [release runbook](../RUNBOOK.md), not as
a replacement for its gates, rollback capture or cold-restart custody contract.
[Production paths](onyx-server-paths.md) owns the current host, init-system,
artifact, config and listener inventory. Deployment requires explicit approval.

1. Select one clean verified release commit and its independently reproduced
   artifact. Record full source/compiler/build inputs and artifact SHA-256;
   strings present in a binary do not prove readiness or test coverage. Preserve
   full test inventories/counts and critical Debug/ReleaseSafe evidence.
2. Capture the previous executable/config hashes and exact supervisor definitions,
   overrides, account, working directory and resource limits on both hosts.
   Preserve node identity, active MESSAGE_V2 mode/epoch/roster digest and persistent
   state. Retaining an old executable does not authorize replaying an older WAL.
3. Stage the same verified artifact and intended node-specific configuration on
   both hosts. Run candidate `--check-config` as the actual service identity from
   its working directory. Never substitute a template identity or print secrets.
4. Validate changed kit behavior and the actual target sandbox before restart.
   The [native kit probe](../guide/service-management.md#isolated-kit-checks)
   catches certificate-loader/kernel-policy failures that a parser-only unit
   check or config preflight can miss. Preserve public-feed umask overrides.
5. Review the exact Helix token and process-owned continuity guards. The current
   accepted topology uses a planned cold boundary because of its WebTransport
   configuration. Follow the runbook's custody and producer-boundary requirements;
   a quiet interval or acknowledged prefix alone is not global empty-custody proof.
6. Operate one node at a time through its actual supervisor. After each node,
   verify service state, running executable identity/hash, all intended listeners,
   CA/hostname-verified TLS, secured links and recovery with a token issued before
   the cold stop. Stop progression and restore the compatible predecessor if an
   acceptance condition fails. Do not restore an older database/WAL by default.
7. Require both-node health and exact-event/reusable-session acceptance. Check
   message IDs/timestamps and missing/duplicate deliveries with multiple clients;
   distinguish local exact attachment restore from peer redirect/origin restore.
   Check fresh public JSON files through their actual reader endpoint.
8. Update documentation from the accepted result, then publish GitHub changes.

Run the repository health probe from the build checkout:

```sh
MESH_SSH_PEER=trev@ircx.us python3 tools/mesh_health_smoke.py http://127.0.0.1:9130/metrics
```

Expect both sides to report established links and peers, with no partition.
`tcp_active` counts open TCP slots; `links_active` requires established Mooring.
Neither the aggregate link gauge nor a successful TCP connect alone proves
secured authentication, whole-network convergence or client delivery.

For a supplementary CA/hostname-verified cross-node chat smoke:

```sh
MESH_SMOKE_A=eshmaki.me:6697 MESH_SMOKE_A_TLS=1 \
  MESH_SMOKE_B=ircx.us:6697 MESH_SMOKE_INSECURE_TLS=0 \
  python3 tools/mesh_chat_smoke.py
```

Chat smoke supplements exact-event/session acceptance; retain the bounded receipt
and clean up only the accounts/channels created by that fixture. The latest
accepted release's scope and rollback results are in the
[release audit](../audit/release-and-test-speed-2026-11-03.md).
