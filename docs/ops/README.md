# Operations documentation

Use the [release runbook](../RUNBOOK.md) for authorized release ordering,
rollback and recovery. [Production paths](onyx-server-paths.md) owns the
accepted fleet's exact services, paths, version, artifact hashes, configured
listeners and recovery scope. The [guide index](../guide/README.md) maps setup,
service management, testing, TLS, persistence and Helix tasks.

| Document | Scope |
| --- | --- |
| [Production paths](onyx-server-paths.md) | Canonical dated fleet inventory and refresh commands |
| [Mesh acceptance checklist](mesh-metrics-deploy-checklist.md) | Release ordering, custody, rollback and live recovery checks |
| [Client disconnects](client-disconnects.md) | Current receive diagnostics and Linux socket policy |
| [E2EE group activation](e2ee-group-authority-v2-activation.md) | Live operator barrier, direct-peer readiness, compatibility and retained custody |
| [OCG2 runtime activation](ocg2-runtime-activation.md) | Supported authority modes and staged rollout; no assumption that minting is live |
| [OpenBSD service policy](openbsd-service-policy.md) | Strict policy compiler/helper contract and native acceptance still required |
| [Roadmap acceptance inventory](roadmap-acceptance-ledger-2026-10-26.md) | All 98 criteria and their unchanged accepted/partial/open statuses |

The [latest release audit](../audit/release-and-test-speed-2026-11-03.md)
distinguishes production source, later test-only changes, cold-token recovery,
exact-event checks and limits of live acceptance. A later documentation commit
does not imply a different daemon was built or deployed.

Old release/deploy reports, benchmark pilots and wave diaries were removed from
the working tree. Their original bytes remain in
[Git history at the pre-cleanup revision](https://github.com/devinkbrown/onyx-server/tree/3fa6e95021601c92d2a2b68869d8fa9f4047d391/docs/ops).
Use that history for provenance; use the current guides for operational action.
