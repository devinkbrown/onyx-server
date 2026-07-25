#!/usr/bin/env bash
# Era 2 / post-deploy acceptance smoke for dual-node Onyx Server.
# Checks: unit active, version string, mesh links, RECOVERYCODES in binary.
set -euo pipefail

LOCAL_METRICS="${LOCAL_METRICS:-http://127.0.0.1:9130/metrics}"
PEER_SSH="${PEER_SSH:-trev@ircx.us}"
BIN_LOCAL="${BIN_LOCAL:-/home/kain/onyx-server-run/onyx-server}"
BIN_PEER="${BIN_PEER:-/home/trev/onyx-server-run/onyx-server}"
EXPECT_VER="${EXPECT_VER:-46a48ad}"

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "OK: $*"; }

systemctl is-active --quiet onyx-server.service || fail "local onyx-server.service not active"
ok "local unit active"

ver="$("$BIN_LOCAL" --version 2>&1 | tr -d '\n' || true)"
echo "$ver" | grep -q "$EXPECT_VER" || fail "local version missing $EXPECT_VER (got: $ver)"
ok "local version $EXPECT_VER"

grep -aFq RECOVERYCODES "$BIN_LOCAL" || fail "local binary missing RECOVERYCODES"
ok "local RECOVERYCODES present"

links="$(curl -fsS "$LOCAL_METRICS" | awk '/^onyx_s2s_links_active /{print $2}')"
[[ "${links:-0}" != "0" && -n "${links:-}" ]] || fail "local links_active=$links"
ok "local links_active=$links"

ssh -o BatchMode=yes -o ConnectTimeout=8 "$PEER_SSH" \
  "systemctl is-active --quiet onyx-server.service && $BIN_PEER --version 2>&1 | grep -q $EXPECT_VER && grep -aFq RECOVERYCODES $BIN_PEER" \
  || fail "peer unit/version/RECOVERYCODES check failed"
ok "peer unit + version + RECOVERYCODES"

if [[ -x "$(dirname "$0")/mesh_health_smoke.py" ]]; then
  MESH_SSH_PEER="$PEER_SSH" python3 "$(dirname "$0")/mesh_health_smoke.py" "$LOCAL_METRICS" \
    || fail "mesh_health_smoke"
  ok "mesh_health_smoke both nodes"
fi

echo "PASS: era2 acceptance smoke"
exit 0
