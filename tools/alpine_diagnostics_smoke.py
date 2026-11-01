#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Native loopback proof that typed connection logs redact private QUIT text.

Runs one temporary daemon, with no installed-service or external network use.
Exercises the sink budget and metrics, but not OpenRC delivery or syslog retention.
"""
from __future__ import annotations

import argparse
import json
import http.client
import time
import os
from pathlib import Path
import platform
import re
import resource
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile

from alpine_runtime_smoke import FixtureFailure, registered_ping, require, sha256, stop


LOG_LIMIT = 1 << 20


def limit_fixture_files() -> None:
    # This fixture has no account store or writable log sink other than its
    # captured stdout/stderr. Bound malicious/broken-child writes in the kernel.
    resource.setrlimit(resource.RLIMIT_FSIZE, (LOG_LIMIT, LOG_LIMIT))


def captured_command(command: list[str], root: Path, env: dict[str, str],
                     destination: Path, *, timeout: int) -> tuple[int, bytes]:
    with destination.open("xb") as stream:
        destination.chmod(0o600)
        result = subprocess.run(command, cwd=root, env=env, stdout=stream,
                                stderr=subprocess.STDOUT, timeout=timeout,
                                preexec_fn=limit_fixture_files)
    require(destination.stat().st_size < LOG_LIMIT, "fixture command log reached bound")
    return result.returncode, destination.read_bytes()


def metrics(port: int) -> tuple[int, int]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        conn.request("GET", "/metrics")
        response = conn.getresponse()
        require(response.status == 200, "fixture metrics HTTP failure")
        data = response.read(LOG_LIMIT + 1)
        require(len(data) <= LOG_LIMIT, "fixture metrics exceeded bound")
    finally:
        conn.close()
    def value(pattern: bytes) -> int:
        matches = re.findall(pattern, data, re.MULTILINE)
        require(len(matches) == 1, "fixture diagnostic metric missing or duplicated")
        return int(matches[0])
    return (value(rb'^onyx_connection_diagnostics_total\{event="accepted"\} ([0-9]+)$'),
            value(rb'^onyx_connection_diagnostics_sink_suppressed_total ([0-9]+)$'))


def budget_probe(process: subprocess.Popen, port: int, metrics_port: int, marker: bytes, stream) -> dict:
    # Align to a local monotonic second; require the daemon's own counters to
    # demonstrate suppression. Slow hosts get three bounded attempts, never a pass.
    before = metrics(metrics_port)
    for attempt in range(3):
        target = int(time.monotonic()) + 1
        while time.monotonic() < target:
            time.sleep(max(0, min(0.01, target - time.monotonic())))
        started = time.monotonic()
        for _ in range(200):
            require(process.poll() is None, "fixture daemon exited during budget burst")
            with socket.create_connection(("127.0.0.1", port), timeout=1) as client:
                client.sendall(b"PRIVMSG nobody :" + marker + b"\r\nQUIT :" + marker + b"\r\n")
        elapsed = time.monotonic() - started
        time.sleep(0.4)  # let the reactor process the complete burst
        after = metrics(metrics_port)
        if elapsed < 0.8 and after[1] > before[1] and after[0] - before[0] > 128:
            time.sleep(1.2)
            summary_offset = stream.tell()
            registered_ping(process, port, quit_marker=marker)
            return {"accepted_delta": after[0] - before[0],
                    "suppressed_delta": after[1] - before[1],
                    "attempt": attempt + 1, "burst_ms": int(elapsed * 1000),
                    "summary_offset": summary_offset}
        before = after
    raise FixtureFailure("budget burst did not reach suppression within bounded timing attempts")


def verify_budget(output: bytes, marker: bytes, proof: dict) -> None:
    require(marker not in output, "private payload leaked into fixture log")
    lines = [line for line in output.splitlines() if line.startswith(b"onyx-server: connection ")]
    summaries = [int(m.group(1)) for line in output[proof["summary_offset"]:].splitlines()
                 if line.startswith(b"onyx-server: connection ") and (m := re.search(rb' suppressed=([0-9]+)$', line))]
    require(proof["accepted_delta"] > 128 and proof["suppressed_delta"] > 0,
            "fixture budget counters did not advance")
    require(any(n > 0 for n in summaries), "post-window suppression summary missing")


def run(source: Path) -> dict:
    require(sys.platform == "linux", "native smoke requires Linux")
    require(os.geteuid() != 0, "run this acceptance as a non-root user")
    require(source.is_file(), "explicit artifact is not a regular file")
    with tempfile.TemporaryDirectory(prefix="onyx-alpine-diagnostics-") as temporary:
        root = Path(temporary)
        binary = root / "onyx-server"
        digest = sha256(source)
        shutil.copyfile(source, binary)
        binary.chmod(0o500)
        require(digest == sha256(binary) == sha256(source), "artifact changed while copying")
        env = {"PATH": os.defpath, "TMPDIR": str(root)}
        code, version_output = captured_command([str(binary), "--version"], root, env,
                                               root / "version.log", timeout=10)
        require(code == 0, "artifact version command failed")
        version = re.search(rb"(?:^|\n)[ \t]*Onyx Server ([0-9][0-9A-Za-z.+-]{0,127})[ \t]*(?:\n|$)",
                            version_output)
        require(version is not None, "artifact version format unrecognized")
        reservation = socket.socket()
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
        metric_reservation = socket.socket()
        metric_reservation.bind(("127.0.0.1", 0))
        metrics_port = metric_reservation.getsockname()[1]
        config = root / "server.toml"
        try:
            config.write_text(
                '[node]\nid = 1\n'
                '[network]\nserver_name = "alpine.diagnostics.fixture"\n'
                f'[listen]\nhost = "127.0.0.1"\nirc = {port}\nws = 0\n'
                '[limits]\nnum_shards = 1\n'
                f'[cloak]\nsecret = "{secrets.token_hex(32)}"\n'
                f'[metrics]\nbind = "127.0.0.1"\nlisten = {metrics_port}\n'
            )
            config.chmod(0o400)
            code, _ = captured_command([str(binary), "--check-config", str(config)], root, env,
                                       root / "preflight.log", timeout=20)
            require(code == 0, "fixture configuration preflight failed")
        finally:
            reservation.close()
            metric_reservation.close()
        marker = ("private-quit-" + secrets.token_hex(32)).encode()
        log = root / "daemon.log"
        with log.open("xb") as stream:
            log.chmod(0o600)
            process = subprocess.Popen([str(binary), str(config)], cwd=root, env=env,
                                       stdout=stream, stderr=subprocess.STDOUT,
                                       start_new_session=True, preexec_fn=limit_fixture_files)
            try:
                registered_ping(process, port, quit_marker=marker)
                proof = budget_probe(process, port, metrics_port, marker, stream)
            finally:
                stop(process)
        require(log.stat().st_size < LOG_LIMIT, "fixture log reached observation bound")
        output = log.read_bytes()
        require(marker not in output, "private QUIT text leaked into fixture log")
        lines = [line for line in output.splitlines()
                 if line.startswith(b"onyx-server: connection ")]
        require(bool(lines), "no typed connection diagnostics observed")
        require(all(len(line) < 1024 for line in lines),
                "typed connection diagnostic exceeded formatter bound")
        for event in (b"accepted", b"registered", b"command_quit", b"closed"):
            matched = [line for line in lines if b"event=" + event + b" " in line]
            require(bool(matched), "required connection diagnostic event missing")
            for line in matched:
                for field in (b"shard=", b"slot=", b"generation=", b"fd=",
                              b"transport=tcp ", b"queued=", b"reason=", b"suppressed="):
                    require(field in line, "typed diagnostic metadata missing")
        quit_lines = [line for line in lines if b"event=command_quit " in line]
        require(all(b"reason=none " in line for line in quit_lines),
                "QUIT diagnostic did not omit caller-provided reason")
        verify_budget(output, marker, proof)
        require(sha256(binary) == digest, "fixture binary changed")
        return dict(artifact_sha256=digest,
                    version=version.group(1).decode("ascii"),
                    platform=platform.platform(), uid=os.geteuid(),
                    alpine=Path("/etc/alpine-release").exists(),
                    typed_lines=len(lines), budget_proof=proof,
                    checks=["native-irc-registration-pong-quit", "private-quit-log-redaction",
                            "required-event-metadata", "bounded-diagnostic-lines",
                            "live-rate-suppression-counters-and-summary", "private-message-canary"],
                    limitations=["no-OpenRC-logger-delivery-or-syslog-retention",
                                 "no-all-command-or-secret-redaction-proof"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.binary.resolve()), indent=2))
    except (FixtureFailure, OSError, subprocess.TimeoutExpired) as error:
        print(f"alpine diagnostics smoke: {error}", file=sys.stderr)
        sys.exit(1)
