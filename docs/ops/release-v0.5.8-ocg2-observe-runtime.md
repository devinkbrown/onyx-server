# OCG2 observe-runtime rollout

Deployment completed at `2026-08-14T08:17:49Z` from source commit
`17f077719a12fd32528ea2472bdfcc08f24a5844` (`0.5.8+17f0777`).

## Artifact proof

- Release artifact: `onyx-server-0.5.8-x86_64-linux-musl`
- SHA-256: `19f08e0aca5ee29187d4fefe4a138dd7998f469116a81d144c71b1196caea4bd`
- `packaging/verify-release.sh` rebuilt the commit with a clean cache and
  produced a byte-identical artifact.
- The staged artifact passed `--check-config` against each node's exact live
  configuration before either runtime was changed.

## Deployed nodes

| Node | Service | Main PID | On-disk SHA-256 | Running `/proc` SHA-256 |
| --- | --- | ---: | --- | --- |
| `eshmaki.me` | active/running | `828697` | `19f08e0aca5ee29187d4fefe4a138dd7998f469116a81d144c71b1196caea4bd` | `19f08e0aca5ee29187d4fefe4a138dd7998f469116a81d144c71b1196caea4bd` |
| `ircx.us` | active/running | `1245448` | `19f08e0aca5ee29187d4fefe4a138dd7998f469116a81d144c71b1196caea4bd` | `19f08e0aca5ee29187d4fefe4a138dd7998f469116a81d144c71b1196caea4bd` |

Both services adopted the replacement through the Helix `SIGUSR2` path. The
peer journal recorded state sealing, listener adoption, mandatory-state restore,
three TLS client reattachments, and preservation of the existing mesh link.

Neither live configuration contains an `[oper.ocg2]` section. Consequently the
new OCG2 observer remains disabled by default on both nodes; this rollout does
not enable projection, minting, or any OCG2 privilege reconciliation path.

## Post-deploy acceptance

- `tools/era2_acceptance_smoke.sh`: pass on both nodes, including unit, version,
  binary capability, and mesh-health checks.
- `tools/mesh_health_smoke.py`: both nodes reported `links_active=1`,
  `peers_up=1`, `partitioned=0`, and `tcp_active=1`.
- `tools/mesh_chat_smoke.py`: guest clients registered and joined `#root`; a
  unique `PRIVMSG` was delivered successfully in both directions across the
  mesh.

## Rollback artifacts

- `eshmaki.me`:
  `/home/kain/onyx-server-run/onyx-server.prev-7933401-20260814T081615Z`
- `ircx.us`:
  `/home/trev/onyx-server-run/onyx-server.prev-7933401-20260814T081615Z`
- Rollback artifact SHA-256 on both nodes:
  `609ff9eb8e143f1fadc759254dda2540d7ab2ace174088785a7c881f42cf6a2c`

To roll back one node, first validate its saved binary against the exact live
configuration, install it over the runtime path, issue the service's `SIGUSR2`
reload, and verify both the running `/proc/<MainPID>/exe` hash and dual-node mesh
health before touching the other node.
