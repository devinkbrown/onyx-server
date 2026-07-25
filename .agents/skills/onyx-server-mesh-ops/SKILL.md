---
name: onyx-server-mesh-ops
description: >
  Dual-node Onyx Server mesh operations: metrics semantics, health/chat smokes,
  diagnose links_active vs tcp_active, and post-deploy acceptance. Use when
  verifying mesh, deploying S2S changes, or debugging HandshakeTooLarge /
  partition / AKE failures.
---

# Mesh ops (dual-node)

## Healthy mesh (acceptance bar)
Both nodes simultaneously:
- `onyx_s2s_links_active >= 1`
- peers_up / membership shows peer
- `onyx_s2s_partitioned == 0` (or equivalent partition gauge 0)
- `onyx_s2s_tcp_active >= 1` (TCP may equal links when established)
- Journal: `mesh S2S established (secured) peer=<other>`

## Commands
```sh
# Local metrics
curl -sS http://127.0.0.1:9130/metrics | grep -E 'onyx_s2s_(tcp_active|links_active)'

# Both nodes via SSH peer
MESH_SSH_PEER=trev@ircx.us python3 tools/mesh_health_smoke.py http://127.0.0.1:9130/metrics

# Cross-node PRIVMSG (guest auto if SASL unset; force SASL with MESH_SMOKE_REQUIRE_SASL=1)
MESH_SMOKE_B=ircx.us:6697 MESH_SMOKE_INSECURE_TLS=1 python3 tools/mesh_chat_smoke.py
# With credentials:
# export MESH_SMOKE_SASL_USER=… MESH_SMOKE_SASL_PASS=…
```

## Diagnose
| Symptom | Likely cause | Next |
|---------|--------------|------|
| tcp=0 links=0 | peer down, firewall, dial not started | journal auto-connect; unit active |
| tcp>0 links=0 | AKE/Mooring handshake fail, trust root skew, domain label | journal `HandshakeTooLarge` / verify fail; dual-verify crypto domains |
| links flip-flop | version skew, resource limit, reconnect storm | both binary revs; rate of establish lines |
| health green, chat fail | SASL required / guest blocked / channel ACL | chat smoke exit 2 vs 1 |

## Deploy slice for mesh-touching binaries
1. `zig build -Doptimize=ReleaseSafe`
2. `strings zig-out/bin/onyx-server | grep -E 'onyx_s2s_tcp_active|mesh S2S established'`
3. Stage → `--check-config` per node → install → Helix or hard-restart **one node at a time**
4. Wait AKE (metrics may show links=0 for a few seconds)
5. mesh_health_smoke both ways
6. Optional mesh_chat_smoke

## Do not
- Treat `tcp_active` as "mesh is up" without `links_active`
- Rebrand wire crypto domain strings
- Print SASL secrets in logs or agent output
- Deploy without user authorization (`onyx-server-release-deploy` / deploy agent)
