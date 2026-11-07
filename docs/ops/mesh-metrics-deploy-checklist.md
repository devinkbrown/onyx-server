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

Metric families added in 0.10.0, useful when you diagnose a slow or diverging
link:

| Family | Meaning |
|---|---|
| `onyx_relay_v2_resend_*`, `onyx_relay_v2_stalled_peers`, `onyx_relay_v2_*_shed_total`, `onyx_relay_v2_deferred*` | Paced MESSAGE_V2 resends to slow neighbours and per-origin admission backpressure. A rising shed or stalled count means a neighbour is not ACKing. |
| `onyx_route_peer_cost`, `onyx_route_rank_*`, `onyx_route_eligible_peers` | Measured next-hop cost and hysteresis decisions (promotions, demotions, held, refused). |
| `onyx_output_class_{admitted,deferred,shed,overflow}_total` | Per-class SendQ budgets (control, chat, replay, media). |
| `onyx_session_credential_*` | Credential reuse versus fresh mint, rotations and the churn budget. `..._table_overflow_total` replaces `..._table_evictions_total`. |
| `onyx_session_offer_retry_*` | SESSION_REPLICA OFFER retry decisions (reused cohort, required rotation, duplicates). |
| `onyx_session_replica_{entries,tombstones,...}` | Replica table and tombstone occupancy against their caps. |
| `onyx_resource_*` | `[resources]` memory budget and refusals. |

## Helix refused for "remote visible identity"

`UPGRADE refused — remote visible identity and physical notification frontiers
has no exact Helix checkpoint` covers four separate conditions. Builds after
0.11.0 log one more line that names them, followed by up to four
`UPGRADE continuity non-IRC output client=… encoding=… owner=…` samples:

```text
onyx-server: UPGRADE continuity detail: local_quit_captures=N (recipients=N) pending_remote_host_records=N (unattached=N) departures=N (records=N) spool_barriers=N (clients=N: attached=N closing=N detached=N) spool_non_irc=N (plaintext=N preframed_secure=N; attached=N closing=N detached=N)
```

`UPGRADE PLAN` prints the same detail. These `/metrics` gauges carry the
counts without World-dependent attached/closing/detached classification:

| Gauge | Blocks Helix when non-zero |
|---|---|
| `onyx_helix_continuity_local_quit_captures` (`…_local_quit_recipients`) | A local QUIT still owed to physical recipients |
| `onyx_helix_continuity_pending_remote_host_records` | CHGHOST or split records not yet in a SendQ |
| `onyx_helix_continuity_departure_images` (`…_departure_records`) | Peer netsplit images not yet received by every recipient |
| `onyx_helix_continuity_spool_barriers` | Output barriers held for those images |
| `onyx_helix_continuity_spool_plaintext`, `…_spool_preframed_secure` | Diverted output not yet in a SendQ |
| `onyx_helix_continuity_remote_visible_blocked` | 1 when any of the above holds |

These should return to 0 within a few sweep intervals (`[limits] sweep_interval`,
2s on both nodes). If they stay up, `owner=closing` means that a connection
which is already closing still holds diverted output. The maintenance timer now
finishes that close. `owner=attached` that persists for longer than the
kernel's 60s TCP user timeout is a bug to report, along with the detail line.

For a supplementary CA/hostname-verified cross-node chat smoke:

```sh
MESH_SMOKE_A=eshmaki.me:6697 MESH_SMOKE_A_TLS=1 \
  MESH_SMOKE_B=ircx.us:6697 MESH_SMOKE_INSECURE_TLS=0 \
  python3 tools/mesh_chat_smoke.py
```

Chat smoke supplements exact-event/session acceptance; retain the bounded receipt
and clean up only the accounts/channels created by that fixture. The latest
accepted release's scope and rollback results are in the
[release record](../audit/release-0.10.0-2026-11-06.md).
