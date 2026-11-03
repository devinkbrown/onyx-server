# Mesh metrics deploy checklist (one-liners)

Dual-node: **eshmaki** (OpenRC `/etc/init.d/onyx-server` → `/home/kain/onyx-server-run/onyx-server`) then **ircx** (`trev@ircx.us`, systemd `onyx-server.service` → `/home/trev/onyx-server-run/onyx-server`). Roll **one node at a time**, cold restarts (Helix is blocked by the configured WebTransport listener on both nodes; see `onyx-server-paths.md`).

Canonical path table: [`onyx-server-paths.md`](./onyx-server-paths.md).

```sh
# 0) Build + prove metrics strings (on build host)
zig build release -Dtarget=x86_64-linux-musl
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

# 4) Check service, running executable hash/version, all intended listeners,
#    and saved-token recovery after each cold restart. Keep the peer healthy.

# 5) Cross-node PRIVMSG smoke
MESH_SMOKE_A=eshmaki.me:6697 MESH_SMOKE_A_TLS=1 \
  MESH_SMOKE_B=ircx.us:6697 MESH_SMOKE_INSECURE_TLS=0 \
  python3 tools/mesh_chat_smoke.py
```

Complete the [release gates and live acceptance](../RUNBOOK.md) before shipping.
Chat smoke supplements exact-event and reusable-session checks. A unit parser
check does not exercise its sandbox: run the native
[service-kit probe](../guide/service-management.md#isolated-kit-checks) when changing
hardening. Preserve host-specific feed permissions and validate public JSON
after restart.

Details and partition semantics: [`docs/RUNBOOK.md`](../RUNBOOK.md) § Mesh health smoke.
