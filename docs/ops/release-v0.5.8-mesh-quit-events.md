# v0.5.8 Mesh QUIT Event Hotfix

Deployment completed 2026-07-31.

## Immutable inputs

- Source commit: `f9db341f7f3ec07969aa49995152080ffb1b53a0`
- Runtime version: `Onyx Server 0.5.8+f9db341`
- ReleaseFast binary SHA-256:
  `fb279756e36626055e64a94aaa10992f931d899a55c1b8e2e3629914679bc2d1`
- Changed runtime source: `src/daemon/server.zig`

The fix preserves an identity-wide IRC `QUIT` and its reason across the
Undertow mesh instead of rendering each convergent channel withdrawal as
`PART`. Recipient-local deduplication emits one `QUIT` to a client sharing
multiple channels while still reaching a client that shares only a later
channel. Genuine `PART` events remain unchanged.

## Verification

- `zig build check`
- `zig build test-server`
- `zig build test-services`
- `zig build test-server -Doptimize=ReleaseSafe`
- `zig build test-services -Doptimize=ReleaseSafe`
- `zig build test`
- `clx verify --cwd /home/kain/onyx-server --timeout 1800`
- Focused `remote QUIT` filter: 70 passed, 0 skipped, 0 failed, 0 leaked

## Rollout

Helix re-exec preserved the established secured mesh link and live client
connections on both nodes:

| Node | Resume time | Restored runtime |
|---|---|---|
| `eshmaki.me` | `2026-07-31 05:17:57 CEST` | 5 clients, 1 mesh link |
| `ircx.us` | `2026-07-30 20:18:17 PDT` | 3 clients, 1 mesh link |

Both exact production configurations passed `--check-config` under
`0.5.8+f9db341`. Post-rollout mesh health on both nodes reported
`links_active=1`, `peers_up=1`, `partitioned=0`, and `tcp_active=1`.

## Live acceptance

Two fresh TLS guest-client probes used isolated temporary channels:

1. Actor on `eshmaki.me`, observer on `ircx.us`: exactly one remote `QUIT`
   carried the supplied reason; no `PART` was observed.
2. Actor on `ircx.us`, observer on `eshmaki.me`: exactly one remote `QUIT`
   carried the supplied reason; no `PART` was observed.

## Rollback

Both nodes retain `onyx-server.prev-f9db341`, version
`Onyx Server 0.5.8+baef0a8`, with SHA-256
`339b289a6c79db628da49a5765f4a3815e902ea9b5c13f658bc601e92950308b`.
Rollback remains subject to the active MESSAGE_V2/Helix compatibility
constraints in `docs/RUNBOOK.md`.
