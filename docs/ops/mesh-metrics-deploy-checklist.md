# Mesh metrics deploy checklist (one-liners)

Dual-node: **eshmaki** (OpenRC `/etc/init.d/onyx-server` → `/home/kain/onyx-server-run/onyx-server`) then **ircx** (`trev@ircx.us`, systemd `onyx-server.service` → `/home/trev/onyx-server-run/onyx-server`). Roll **one node at a time**, cold restarts (Helix is blocked by the configured WebTransport listener on both nodes; see `onyx-server-paths.md`).

Canonical path table: [`onyx-server-paths.md`](./onyx-server-paths.md).

```sh
# 0) Build + prove metrics strings (on build host)
zig build -Dtarget=x86_64-linux-musl -Doptimize=ReleaseFast
strings zig-out/bin/onyx-server | grep -E 'onyx_s2s_tcp_active|mesh S2S established|RECOVERYCODES'

# 1) Stage + check-config (per node)
install -m 0755 zig-out/bin/onyx-server /tmp/onyx-server.stage
/tmp/onyx-server.stage --check-config /home/kain/onyx-server-run/onyx-server.local.toml
# peer: /home/trev/onyx-server-run/onyx-server.local.toml

# 2) Replace binary (backup first), cold-restart one node at a time
#    eshmaki: sudo rc-service onyx-server restart
#    ircx:    sudo systemctl restart onyx-server.service

# 3) Mesh health (local + SSH peer when :9130 is loopback-only)
MESH_SSH_PEER=trev@ircx.us python3 tools/mesh_health_smoke.py http://127.0.0.1:9130/metrics
# Expect both sides: links_active>=1 peers_up>=1 partitioned=0

# 4) Acceptance
tools/era2_acceptance_smoke.sh

# 5) Cross-node PRIVMSG smoke
MESH_SMOKE_B=ircx.us:6697 MESH_SMOKE_INSECURE_TLS=1 \
  python3 tools/mesh_chat_smoke.py
```

Details and partition semantics: [`docs/RUNBOOK.md`](../RUNBOOK.md) § Mesh health smoke.
