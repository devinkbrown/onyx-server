#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Exercise a generated private bundle with a real, pinned TLS IRC client.

Explicit artifact, non-root Linux, temporary identities, loopback listeners and
bounded cleanup only. Does not touch an installed service or external network.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import tempfile
import time

from setup_review_client import run_review
from alpine_runtime_smoke import registered_ping, require, sha256, stop


def sibling_roundtrip(process, client, register=False):
    """Keep this socket open across the rejected handshake, then probe again."""
    client.settimeout(0.3)
    if register:
        client.sendall(b"NICK staysibling\r\nUSER staysibling 0 * :persistent fixture\r\n")
    marker = secrets.token_hex(12).encode()
    pending = b""
    welcomed = not register
    if welcomed:
        client.sendall(b"PING :" + marker + b"\r\n")
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        require(process.poll() is None, "fixture daemon exited during sibling participation")
        try:
            chunk = client.recv(65536)
        except socket.timeout:
            continue
        require(bool(chunk), "existing sibling closed unexpectedly")
        pending += chunk
        require(len(pending) <= 1 << 20, "sibling response exceeded bound")
        while b"\r\n" in pending:
            line, pending = pending.split(b"\r\n", 1)
            if line.startswith(b"PING "):
                client.sendall(b"PONG " + line[5:] + b"\r\n")
            if b" 001 staysibling " in line and not welcomed:
                welcomed = True
                client.sendall(b"PING :" + marker + b"\r\n")
            if welcomed and b" PONG " in line and line.endswith(b":" + marker):
                return
    raise RuntimeError("existing sibling participation deadline expired")


def tls_registration(process, port, context, hostname):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=hostname) as client:
            require(client.version() in ("TLSv1.2", "TLSv1.3"), "TLS was not negotiated")
            client.settimeout(0.3)
            client.sendall(b"NICK setupfixture\r\nUSER setupfixture 0 * :TLS fixture\r\n")
            marker = secrets.token_hex(12).encode()
            pending = b""
            welcomed = False
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                require(process.poll() is None, "fixture daemon exited during TLS IRC")
                try:
                    chunk = client.recv(65536)
                except socket.timeout:
                    continue
                require(bool(chunk), "TLS IRC closed before registration/PONG")
                pending += chunk
                require(len(pending) <= 1 << 20, "TLS IRC response exceeded bound")
                while b"\r\n" in pending:
                    line, pending = pending.split(b"\r\n", 1)
                    if line.startswith(b"PING "):
                        client.sendall(b"PONG " + line[5:] + b"\r\n")
                    if b" 001 setupfixture " in line and not welcomed:
                        welcomed = True
                        client.sendall(b"PING :" + marker + b"\r\n")
                    if welcomed and b" PONG " in line and line.endswith(b":" + marker):
                        return client.version()
            raise RuntimeError("TLS IRC registration/PONG deadline expired")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--scratch-dir", type=Path,
                        default=Path(__file__).resolve().parents[1] / ".zig-cache/setup-tls-smoke")
    args = parser.parse_args()
    require(os.uname().sysname == "Linux" and os.geteuid() != 0,
            "run this fixture as a non-root Linux user")
    binary = args.binary.resolve(strict=True)
    artifact_hash = sha256(binary)
    args.scratch_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    checks = []
    with tempfile.TemporaryDirectory(prefix="bundle-", dir=args.scratch_dir) as temporary:
        root = Path(temporary).resolve()
        reservations = [socket.socket(), socket.socket()]
        process = None
        try:
            for reservation in reservations:
                reservation.bind(("127.0.0.1", 0))
            irc, tls = [reservation.getsockname()[1] for reservation in reservations]
            bundle = root / "node"
            hostname = "setup.example.test"
            result, review, _ = run_review([
                str(binary), "setup", "--new", "--hostname", hostname,
                "--listen", "127.0.0.1", "--irc-port", str(irc),
                "--tls-port", str(tls), "--bundle", str(bundle), "--json",
            ], cwd=root)
            require(review is not None and review["certificate_subject"] == hostname,
                    "actual certificate subject was not reviewed")
            require(result.returncode == 0, "private bundle provisioning failed")
            require(json.loads(result.stdout)["changes_applied"], "bundle was not published")
            checks.append("canonical private bundle provisioned")
            before = {path.name: sha256(path) for path in bundle.iterdir() if path.is_file()}
            require(len(before) == 5, "unexpected private bundle file set")
            for path in bundle.iterdir():
                require(path.stat().st_mode & 0o777 == 0o600, "bundle file mode differs from 0600")
            elsewhere = root / "elsewhere"
            elsewhere.mkdir(mode=0o700)
            config = bundle / "onyx-server.toml"
            checked = subprocess.run([str(binary), "--check-config", str(config)],
                                     cwd=elsewhere, capture_output=True, timeout=10)
            require(checked.returncode == 0, "bundle config failed from unrelated cwd")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert((bundle / "tls-cert.der").read_bytes()))
            for reservation in reservations:
                reservation.close()
            log_path = root / "runtime.log"
            descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as log:
                process = subprocess.Popen([str(binary), str(config)], cwd=elsewhere,
                                           stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                registered_ping(process, irc)
                checks.append("real loopback IRC registration and PONG")
                with socket.create_connection(("127.0.0.1", irc), timeout=5) as sibling:
                    sibling_roundtrip(process, sibling, register=True)
                    version = tls_registration(process, tls, context, hostname)
                    checks.append("pinned certificate and hostname: real TLS IRC registration/PONG")
                    try:
                        with socket.create_connection(("127.0.0.1", tls), timeout=5) as raw:
                            context.wrap_socket(raw, server_hostname="wrong.example.test").close()
                    except ssl.SSLCertVerificationError:
                        checks.append("wrong hostname rejected by standard TLS client")
                    else:
                        raise RuntimeError("wrong hostname unexpectedly verified")
                    sibling_roundtrip(process, sibling)
                    checks.append("same registered sibling participates after rejected TLS verification")
                stop(process)
            require(before == {path.name: sha256(path) for path in bundle.iterdir() if path.is_file()},
                    "runtime changed canonical config or private material")
            require(artifact_hash == sha256(binary), "fixture artifact changed during acceptance")
            checks.append("private identity/config/certificate/key/secret remain unchanged")
        finally:
            for reservation in reservations:
                reservation.close()
            if process is not None and process.poll() is None:
                stop(process)
    print(json.dumps({"checks": checks, "tls": version, "artifact_sha256": artifact_hash,
                      "uid": os.geteuid(), "complete": True}))


if __name__ == "__main__":
    main()
