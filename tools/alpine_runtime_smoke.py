#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Real non-root Linux startup, loopback IRC, and identity recovery smoke.

Requires an explicit local artifact. Uses only private temporary fixtures; no
installed services, live configs, external network, or container engine calls.
This is not a read-only-root container or full Alpine network acceptance test.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time


class FixtureFailure(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise FixtureFailure(message)


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def stop(process: subprocess.Popen, *, crash: bool = False) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL if crash else signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def registered_ping(process: subprocess.Popen, port: int,
                    *, quit_marker: bytes | None = None) -> None:
    deadline = time.monotonic() + 20
    client = None
    while time.monotonic() < deadline:
        require(process.poll() is None, "fixture daemon exited before IRC readiness")
        try:
            client = socket.create_connection(("127.0.0.1", port), timeout=0.3)
            break
        except OSError:
            time.sleep(0.05)
    require(client is not None, "fixture loopback listener did not become ready")
    with client:
        client.settimeout(0.3)
        client.sendall(b"NICK alpinefixture\r\nUSER smoke 0 * :Alpine fixture\r\n")
        marker = secrets.token_hex(12).encode()
        pending = b""
        welcomed = False
        while time.monotonic() < deadline:
            require(process.poll() is None, "fixture daemon exited during IRC exchange")
            try:
                chunk = client.recv(65536)
            except socket.timeout:
                continue
            require(bool(chunk), "fixture IRC connection closed before response")
            pending += chunk
            require(len(pending) <= 1 << 20, "fixture IRC response exceeded bound")
            while b"\r\n" in pending:
                line, pending = pending.split(b"\r\n", 1)
                if line.startswith(b"PING "):
                    client.sendall(b"PONG " + line[5:] + b"\r\n")
                if b" 001 alpinefixture " in line and not welcomed:
                    welcomed = True
                    client.sendall(b"PING :" + marker + b"\r\n")
                if welcomed and b" PONG " in line and line.endswith(b":" + marker):
                    require(process.poll() is None, "fixture daemon exited after PONG")
                    if quit_marker is not None:
                        client.sendall(b"QUIT :" + quit_marker + b"\r\n")
                        while time.monotonic() < deadline:
                            try:
                                if not client.recv(65536):
                                    return
                            except socket.timeout:
                                continue
                        raise FixtureFailure("fixture QUIT did not close the connection")
                    return
        raise FixtureFailure("fixture IRC registration/PONG deadline expired")


def private_key(state: Path) -> str:
    key = state / "onyx-server-node.key"
    require(key.is_file() and not key.is_symlink(), "fixture identity key absent")
    info = key.stat()
    require(stat.S_IMODE(info.st_mode) == 0o600, "fixture identity mode is not 0600")
    require(info.st_uid == os.geteuid(), "fixture identity owner differs from daemon user")
    text = key.read_text().strip()
    require(len(text) == 64, "fixture identity encoding length differs")
    try:
        bytes.fromhex(text)
    except ValueError:
        raise FixtureFailure("fixture identity is not hex") from None
    return sha256(key)


def run(source: Path) -> dict:
    require(sys.platform == "linux", "native smoke requires Linux")
    require(os.geteuid() != 0, "run this acceptance as a non-root user")
    require(source.is_file(), "explicit artifact is not a regular file")
    with tempfile.TemporaryDirectory(prefix="onyx-alpine-runtime-") as temporary:
        root = Path(temporary)
        binary = root / "onyx-server"
        before = sha256(source)
        shutil.copyfile(source, binary)
        binary.chmod(0o500)
        require(before == sha256(binary) == sha256(source), "artifact changed while copying")
        # Inherit no service-specific settings, cloud credentials, or daemon
        # secret overrides from the invoking environment.
        env = {"PATH": os.defpath, "HOME": str(root), "TMPDIR": str(root)}
        version = subprocess.run([str(binary), "--version"], cwd=root, env=env,
                                 capture_output=True, text=True, timeout=10)
        require(version.returncode == 0, "artifact version command failed")
        state = root / "state"
        state.mkdir(mode=0o700)
        # Reserve an explicit loopback port through config validation. A small
        # close-to-bind race remains; failure is a failed smoke, never a pass.
        reservation = socket.socket()
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
        config = state / "onyx-server.toml"
        config.write_text(
            '[node]\nid = 1\n'
            '[network]\nserver_name = "alpine.fixture.local"\n'
            f'[listen]\nhost = "127.0.0.1"\nirc = {port}\nws = 0\n'
            '[limits]\nnum_shards = 1\n'
            '[sasl]\nenabled = true\naccount_db = "accounts.db"\n'
            f'[cloak]\nsecret = "{secrets.token_hex(32)}"\n'
        )
        config.chmod(0o400)
        config_digest = sha256(config)
        invalid = state / "invalid.toml"
        invalid.write_text('[node]\nid = 0\n[listen]\nirc = 0\n')
        invalid.chmod(0o400)
        try:
            for path, success in ((invalid, False), (config, True)):
                checked = subprocess.run([str(binary), "--check-config", str(path)],
                                         cwd=state, env=env, capture_output=True, timeout=20)
                require((checked.returncode == 0) == success,
                        "native configuration preflight result differed")
            # Actual startup rejection, not just the check-config command.
            rejected = subprocess.run([str(binary), str(invalid)], cwd=state, env=env,
                                      capture_output=True, timeout=20)
            require(rejected.returncode != 0, "invalid startup unexpectedly succeeded")
            require(not (state / "onyx-server-node.key").exists(),
                    "preflight or invalid startup generated identity state")
        finally:
            reservation.close()
        invalid.unlink()

        identity = None
        backup = root / "backup"
        for phase in ("first-boot", "crash-restart", "backup-restore"):
            if phase == "backup-restore":
                state = root / "restored"
                shutil.copytree(backup, state)
                config = state / "onyx-server.toml"
            log = root / f"{phase}.log"
            # Logs may contain private fixture state; never print them.
            with log.open("xb") as output:
                log.chmod(0o600)
                process = subprocess.Popen([str(binary), str(config)], cwd=state, env=env,
                                           stdout=output, stderr=subprocess.STDOUT,
                                           start_new_session=True)
                try:
                    registered_ping(process, port)
                    current = private_key(state)
                    if identity is None:
                        identity = current
                    require(current == identity, "identity changed across recovery")
                    require(sha256(config) == config_digest, "daemon modified configuration")
                finally:
                    stop(process, crash=phase == "first-boot")
            if phase == "first-boot":
                require(process.returncode == -signal.SIGKILL, "crash signal was not observed")
                require((state / "accounts.db").is_file(), "native account store absent")
                shutil.copytree(state, backup)
        require(sha256(binary) == before, "fixture binary changed")
        return dict(artifact_sha256=before,
                    version=(version.stdout + version.stderr).strip(),
                    platform=platform.platform(), uid=os.geteuid(),
                    alpine=Path("/etc/alpine-release").exists(),
                    checks=["invalid-preflight", "invalid-startup", "valid-preflight",
                            "nonroot-irc-registration-pong", "sigkill-restart-stable-identity",
                            "backup-restore-stable-identity", "private-key-owner-mode",
                            "readonly-config-unchanged", "artifact-unchanged"],
                    limitations=["container-readonly-root-not-tested", "no-supervisor",
                                 "no-TLS-DNS-IPv6-UDP-WebTransport-mesh-acceptance"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.binary.resolve()), indent=2))
    except (FixtureFailure, OSError, subprocess.TimeoutExpired) as error:
        print(f"alpine runtime smoke: {error}", file=sys.stderr)
        sys.exit(1)
