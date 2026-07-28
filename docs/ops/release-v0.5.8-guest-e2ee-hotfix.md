# Onyx Server 0.5.8 — guest `onyx/e2ee` hotfix

**Status:** dual-node production reload **completed**. Hotfix cut for guest E2EE capability negotiation.

## Change

Unauthenticated guests may negotiate `onyx/e2ee` without a reusable session. Authenticated clients without an attached reusable session continue to be rejected for that capability path.

## Immutable inventory

| Item | Value |
|------|--------|
| Version banner (both nodes) | `Onyx Server 0.5.8+baef0a8` |
| Release artifact SHA-256 | `339b289a6c79db628da49a5765f4a3815e902ea9b5c13f658bc601e92950308b` |
| Nodes | `eshmaki.me`, `ircx.us` |

| | `eshmaki.me` | `ircx.us` |
| --- | --- | --- |
| Banner | `0.5.8+baef0a8` | `0.5.8+baef0a8` |
| Artifact SHA-256 | `339b289a6c79db628da49a5765f4a3815e902ea9b5c13f658bc601e92950308b` | same |
| Reload | one node at a time | one node at a time |
| Reported active | yes | yes |

## Mesh health (both nodes, post-reload)

| Signal | Value |
|--------|-------|
| `links_active` | `1` |
| `peers_up` | `1` |
| `partitioned` | `0` |
| `tcp_active` | `1` |

## Browser guest acceptance

Fresh browser guest session ended **CONNECTED** with **GUEST**. No reconnect loop and no `SESSION_UNAVAILABLE`.
