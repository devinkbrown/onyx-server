#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Post-deploy mesh health smoke for dual-node Onyx Server.

Polls Prometheus metrics on one or more nodes and fails if Mooring-established
S2S links or mesh_peers_up look unhealthy.

Usage:
  python3 tools/mesh_health_smoke.py \\
      http://127.0.0.1:9130/metrics \\
      http://ircx.us:9130/metrics

Dual-node via SSH (metrics often bound to localhost only):
  MESH_SSH_PEER=trev@ircx.us python3 tools/mesh_health_smoke.py \\
      http://127.0.0.1:9130/metrics

  # Optional: MESH_SSH_METRICS_URL path on remote (default http://127.0.0.1:9130/metrics)
  # Optional: MESH_SSH_BIN (default ssh), MESH_SSH_OPTS (extra ssh args, space-split)

Exit 0 = healthy; 1 = unhealthy; 2 = usage/network error.
"""
from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
import urllib.error
import urllib.request

GAUGES = (
    "onyx_s2s_links_active",
    "onyx_s2s_tcp_active",
    "onyx_mesh_peers_up",
    "onyx_mesh_peers_total",
    "onyx_mesh_partitioned",
    "onyx_mesh_quorum",
)

DEFAULT_REMOTE_METRICS = "http://127.0.0.1:9130/metrics"


def fetch_http(url: str, timeout: float = 5.0) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "onyx-mesh-health-smoke/1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


def fetch_ssh(peer: str, metrics_url: str, timeout: float = 15.0) -> str:
    """Run curl on remote host; metrics ports are often loopback-only."""
    ssh_bin = os.environ.get("MESH_SSH_BIN", "ssh")
    extra = shlex.split(os.environ.get("MESH_SSH_OPTS", ""))
    # -o BatchMode: fail fast without password prompt; ConnectTimeout for hung peers.
    remote_cmd = f"curl -fsS --max-time 5 {shlex.quote(metrics_url)}"
    cmd = [
        ssh_bin,
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=8",
        *extra,
        peer,
        remote_cmd,
    ]
    try:
        proc = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as e:
        raise OSError(f"ssh binary not found ({ssh_bin}): {e}") from e
    except subprocess.TimeoutExpired as e:
        raise OSError(f"ssh to {peer} timed out after {timeout}s") from e
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
        raise OSError(f"ssh {peer} curl failed: {err}")
    return proc.stdout


def parse_gauges(text: str) -> dict[str, float]:
    out: dict[str, float] = {}
    for name in GAUGES:
        m = re.search(rf"^{re.escape(name)}\s+([0-9.eE+-]+)\s*$", text, re.M)
        if m:
            out[name] = float(m.group(1))
    return out


def check_gauges(label: str, g: dict[str, float]) -> tuple[bool, str]:
    if "onyx_s2s_links_active" not in g:
        # Older binary without Mooring-established gauge semantics still has peers_up.
        if g.get("onyx_mesh_peers_up", 0) >= 1 and g.get("onyx_mesh_partitioned", 1) == 0:
            return True, f"{label}: peers_up={g.get('onyx_mesh_peers_up')} (legacy metrics OK)"
        return False, f"{label}: missing s2s_links_active and peers not up ({g})"

    links = g.get("onyx_s2s_links_active", 0)
    peers = g.get("onyx_mesh_peers_up", 0)
    part = g.get("onyx_mesh_partitioned", 1)
    tcp = g.get("onyx_s2s_tcp_active")  # None on older binaries
    bits = f"links_active={links} peers_up={peers} partitioned={part}"
    if tcp is not None:
        bits += f" tcp_active={tcp}"
    if part != 0:
        return False, f"{label}: partitioned — {bits}"
    if links < 1 and peers < 1:
        return False, f"{label}: no established mesh peer — {bits}"
    if links < 1 and peers >= 1 and tcp is not None:
        # New metrics: peers_up without Mooring links_active is a real skew.
        return False, f"{label}: peers_up without Mooring links_active — {bits}"
    # Older binaries only had links_active tied to TCP accept; peers_up is the
    # health truth there when links_active is present but tcp_active is absent.
    return True, f"{label}: OK — {bits}"


def check_node(url: str) -> tuple[bool, str]:
    try:
        body = fetch_http(url)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return False, f"{url}: fetch failed: {e}"
    return check_gauges(url, parse_gauges(body))


def check_ssh_peer(peer: str) -> tuple[bool, str]:
    metrics_url = os.environ.get("MESH_SSH_METRICS_URL", DEFAULT_REMOTE_METRICS)
    label = f"ssh:{peer}:{metrics_url}"
    try:
        body = fetch_ssh(peer, metrics_url)
    except OSError as e:
        return False, f"{label}: fetch failed: {e}"
    return check_gauges(label, parse_gauges(body))


def main(argv: list[str]) -> int:
    ssh_peer = os.environ.get("MESH_SSH_PEER", "").strip()
    urls = argv[1:]
    if not urls and not ssh_peer:
        print(
            "usage: mesh_health_smoke.py <metrics-url> [metrics-url...]\n"
            "   or: MESH_SSH_PEER=user@host mesh_health_smoke.py [local-metrics-url...]",
            file=sys.stderr,
        )
        return 2
    ok_all = True
    for url in urls:
        ok, msg = check_node(url)
        print(msg)
        ok_all = ok_all and ok
    if ssh_peer:
        ok, msg = check_ssh_peer(ssh_peer)
        print(msg)
        ok_all = ok_all and ok
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
