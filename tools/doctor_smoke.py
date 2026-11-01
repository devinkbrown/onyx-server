#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Native doctor CLI acceptance using private config and one loopback HTTP fixture."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import resource
import secrets
import subprocess
import tempfile
import threading


LIMIT = 1 << 20


class SmokeFailure(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SmokeFailure(message)


def limit_files() -> None:
    resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT, LIMIT))


@contextmanager
def metrics_endpoint(body: bytes):
    class Server(HTTPServer):
        def get_request(self):
            connection, address = super().get_request()
            connection.settimeout(2)
            return connection, address

        def handle_error(self, *_):
            # Broken fixture clients cannot turn request data into a traceback.
            pass

    class Handler(BaseHTTPRequestHandler):
        calls = 0

        def do_GET(self):
            Handler.calls += 1
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    server = Server(("127.0.0.1", 0), Handler)
    server.timeout = 1
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/metrics", Handler
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        require(not thread.is_alive(), "metrics fixture failed to stop")


def invoke(binary: Path, root: Path, config: Path, case: str, *, url=None):
    command = [str(binary), "doctor", str(config)]
    if url is not None:
        command.append(url)
    command.append("--json")
    captures = [root / f"{case}.{suffix}" for suffix in ("out", "err")]
    with captures[0].open("xb") as out, captures[1].open("xb") as err:
        for path in captures:
            path.chmod(0o600)
        result = subprocess.run(command, cwd=root, stdin=subprocess.DEVNULL,
                                stdout=out, stderr=err, timeout=20,
                                env={"PATH": os.defpath, "TMPDIR": str(root), "NO_COLOR": "1"},
                                preexec_fn=limit_files)
    require(all(path.stat().st_size < LIMIT for path in captures), "doctor capture reached bound")
    raw = captures[0].read_bytes()
    try:
        report = json.loads(raw)
    except (ValueError, UnicodeError):
        raise SmokeFailure("doctor JSON is malformed") from None
    require(isinstance(report, dict), "doctor JSON has wrong shape")
    return result.returncode, report, raw + captures[1].read_bytes()


def run(binary: Path) -> dict:
    require(binary.is_file(), "explicit binary is missing")
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="onyx-doctor-smoke-") as temporary:
        root = Path(temporary)
        marker = "private_" + secrets.token_hex(32)
        config = root / "candidate.toml"
        config.write_text('[node]\nid=1\n[listen]\nirc=6680\n[cloak]\nsecret="' + marker + '"\n')
        config.chmod(0o600)
        original = config.read_bytes()
        code, offline, raw = invoke(binary, root, config, "offline")
        require(code == 0, "offline doctor failed")
        require(offline.get("observations", "missing") is None, "offline observations must be null")
        require(offline.get("readiness") == "unknown", "doctor readiness must remain unknown")
        environment = offline.get("service_environment")
        require(isinstance(environment, dict) and environment.get("manager_hint") in ("openrc", "systemd", "unknown") and
                all(environment.get(key) in ("present", "absent", "unknown") for key in
                    ("openrc_marker", "systemd_marker", "container_marker")), "service environment is malformed")
        service_plan=offline.get("service_plan")
        require(isinstance(service_plan,dict) and service_plan.get("selected") in ("openrc","systemd","foreground"), "service plan missing")
        template=service_plan.get("template",{})
        require(template.get("preflight_argv",[None,None])[1]=="--check-config" and
                template.get("start_argv",[None,None])[1]==template.get("config"), "service template argv malformed")
        require(all(service_plan.get(k,"").startswith("unknown") for k in
                    ("host_paths","runtime_identity_access","manager_status","daemon_readiness","network_reachability","resource_ceilings")), "unverified service state claimed")
        require(service_plan.get("container_template",{}).get("identity")=="10001:10001", "container template missing")
        require(isinstance(offline.get("report_build_version"), str) and bool(offline["report_build_version"]),
                "reporting build version is missing")
        require(marker.encode() not in raw and str(config).encode() not in raw, "private config leaked")

        body = ("onyx_s2s_tcp_active 2\nonyx_s2s_links_active 1\nonyx_mesh_partitioned 0\n"
                "onyx_mesh_peers_up 1\nonyx_mesh_peers_total 2\nonyx_mesh_quorum 1\nonyx_mesh_components 1\n"
                'onyx_connection_diagnostics_total{event="recv_eof"} 17\n'
                'onyx_connection_diagnostics_total{event="closed",account="' + marker + '"} 99\n'
                + marker + " 123\n").encode()
        with metrics_endpoint(body) as (url, handler):
            code, online, raw = invoke(binary, root, config, "online", url=url)
            require(handler.calls == 1, "doctor must issue exactly one metrics GET")
            require(code == 0, "online doctor failed")
            require(marker.encode() not in raw and url.encode() not in raw, "metrics labels or URL leaked")
        counts = online.get("observations")
        require(isinstance(counts, dict), "numeric observations are missing")
        require((counts.get("tcp_active"), counts.get("established_links"), counts.get("partitioned")) == (2, 1, 0),
                "numeric observations are incorrect")
        require(counts.get("secured_links") is None and "unknown" in counts.get("freshness", ""),
                "secured status and freshness must remain unknown")
        require((counts.get("peers_up"), counts.get("peers_total"), counts.get("quorum"), counts.get("components")) == (1, 2, 1, 1),
                "peer health observations are incorrect")
        entries = counts.get("connection_events")
        require(isinstance(entries, list) and all(isinstance(entry, dict) and
                isinstance(entry.get("event"), str) and "count" in entry for entry in entries),
                "diagnostic observations have wrong shape")
        events = {entry["event"]: entry["count"] for entry in entries}
        require(events.get("recv_eof") == 17 and events.get("closed") is None,
                "diagnostic allowlist observations are incorrect")
        require(online.get("report_build_version") == offline["report_build_version"], "build identity changed")
        require(online.get("readiness") == "unknown", "metrics cannot establish readiness")

        ambiguous = b"onyx_s2s_tcp_active 1\nonyx_s2s_tcp_active 2\nonyx_s2s_links_active 0\nonyx_mesh_partitioned 1\n"
        with metrics_endpoint(ambiguous) as (url, handler):
            code, report, _ = invoke(binary, root, config, "ambiguous", url=url)
            require(handler.calls == 1 and code == 1, "partition must fail the doctor check")
        require(report.get("observations", {}).get("tcp_active", "missing") is None,
                "duplicate metric must remain unknown")
        require(config.read_bytes() == original, "doctor modified candidate")
        expected = {config.name} | {f"{case}.{suffix}" for case in ("offline", "online", "ambiguous")
                                   for suffix in ("out", "err")}
        require({path.name for path in root.iterdir()} == expected,
                "doctor created unexpected fixture state")
        require(hashlib.sha256(binary.read_bytes()).hexdigest() == digest, "binary changed during smoke")
        return {"artifact_sha256": digest, "report_build_version": offline["report_build_version"],
                "checks": ["offline-unknown", "one-bounded-http-get", "numeric-observations",
                           "private-input-omission", "duplicate-unknown", "partition-failure", "read-only"],
                "limitations": ["fixture-metrics-only", "no-live-mesh-or-media-readiness"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.binary.resolve()), indent=2))
    except (SmokeFailure, OSError, subprocess.SubprocessError):
        # Neither child diagnostics nor exception payloads are safe report data.
        parser.exit(1, "doctor smoke: fixture failed; private captures omitted\n")
