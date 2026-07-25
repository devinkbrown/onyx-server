# Mesh metrics deploy checklist (one-liners)

Dual-node: **eshmaki** (`orochi.service` → `/home/kain/orochi-run/orochi`) then **ircx** (`trev@ircx.us`, `/home/trev/orochi-run/orochi`). Roll **one node at a time**. Prefer Helix USR2 reload when the image token allows; cold-restart only if the runbook says so.

```sh
# 0) Build + prove metrics strings (on build host)
zig build -Doptimize=ReleaseSafe
strings zig-out/bin/onyx-server | grep -E 'onyx_s2s_tcp_active|mesh S2S established'

# 1) Stage + check-config (per node; paths as above)
install -m 0755 zig-out/bin/onyx-server /tmp/onyx-server.stage
/tmp/onyx-server.stage --check-config /path/to/orochi.*.toml

# 2) Replace binary (backup first), reload/restart unit — see docs/RUNBOOK.md
# 3) Mesh health (local + SSH peer when :9130 is loopback-only)
MESH_SSH_PEER=trev@ircx.us python3 tools/mesh_health_smoke.py http://127.0.0.1:9130/metrics

# Expect both sides: links_active>=1 peers_up>=1 partitioned=0
# Journal: "mesh S2S established"; stuck tcp_active>0 links_active=0 → AKE/trust-root skew

# 4) Cross-node PRIVMSG smoke (guest when network allows unregistered nicks)
MESH_SMOKE_B=ircx.us:6697 MESH_SMOKE_INSECURE_TLS=1 \
  python3 tools/mesh_chat_smoke.py
# auth=guest when MESH_SMOKE_SASL_* unset (auto); unique PRIVMSG both ways on #root

# If guest is rejected (464/465) or you need account-bound checks, set SASL:
#   export MESH_SMOKE_SASL_USER=… MESH_SMOKE_SASL_PASS=…   # or ANNOUNCE_SASL_*
#   # never commit credentials; load from your local secret store / unit env
# Force SASL-only (exit 2 if unset): MESH_SMOKE_REQUIRE_SASL=1
```

Details and partition semantics: [`docs/RUNBOOK.md`](../RUNBOOK.md) § Mesh health smoke.
