#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bounded two-process native Core orphan-retry/real-exec fixture runner.

The sidecar exchanges ordinary IRC canaries and observes fixed proof markers.
Only the closed builtin Core fixture seeds state, drives the production retry,
executes the ordinary upgrade, and validates actual successor adoption.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import time

LIMIT = 2 * 1024 * 1024
LINE = 8192


class Failure(Exception):
    pass


class Runner:
    def __init__(self, deadline):
        self.deadline = deadline
        self.phase = "startup"
        self.selector = selectors.DefaultSelector()
        self.processes = {}
        self.buffers = {}
        self.records = {}
        self.totals = {}
        self.errors = {}
        self.owner = None
        self.control = None
        self.owner_eof = False
        self.allow_eof = False

    def add(self, name, stream):
        os.set_blocking(stream.fileno(), False)
        self.selector.register(stream, selectors.EVENT_READ, name)
        self.buffers[name], self.records[name], self.totals[name] = bytearray(), [], 0

    def launch(self, role, binary, directory, *arguments):
        process = subprocess.Popen([str(binary), *arguments], cwd=directory,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True,
                                   close_fds=True)
        self.processes[role] = process
        self.add(role, process.stdout)
        self.add(role + "-error", process.stderr)
        return process

    def pump(self, end):
        left = min(end, self.deadline) - time.monotonic()
        if left <= 0:
            raise Failure("operation_deadline")
        for key, _ in self.selector.select(min(left, 0.2)):
            name = key.data
            try:
                chunk = os.read(key.fileobj.fileno(), 4096)
            except BlockingIOError:
                continue
            if not chunk:
                self.selector.unregister(key.fileobj)
                if self.buffers[name]:
                    raise Failure("unterminated_record")
                if name == "owner":
                    self.owner_eof = True
                    # Classify helper stderr from this same readiness batch
                    # before reporting transport teardown as the outer cause.
                continue
            self.totals[name] += len(chunk)
            if self.totals[name] > LIMIT:
                raise Failure("stream_bound")
            self.buffers[name].extend(chunk)
            while b"\n" in self.buffers[name]:
                raw, _, rest = self.buffers[name].partition(b"\n")
                self.buffers[name] = bytearray(rest)
                line = bytes(raw).rstrip(b"\r")
                if len(line) > LINE:
                    raise Failure("line_bound")
                self.records[name].append(line)
                if name.endswith("-error"):
                    match = re.fullmatch(rb"session-retry-failure stage=([a-z_][a-z0-9_]{0,47}) error=([A-Za-z][A-Za-z0-9_]{0,63})", line)
                    if match:
                        self.errors[name] = "stage_" + match[1].decode() + "_error_" + match[2].decode()
                    match = re.fullmatch(rb"session-retry-helper error=([A-Za-z][A-Za-z0-9_]{0,63})", line)
                    if match and name not in self.errors:
                        self.errors[name] = "error_" + match[1].decode()
                if name in ("owner", "control") and line.startswith(b"PING "):
                    self.send(b"PONG " + line[5:], self.owner if name == "owner" else self.control)
            if len(self.buffers[name]) > LINE:
                raise Failure("line_bound")
        if self.errors:
            raise Failure("helper_refusal")
        if self.owner_eof and not self.allow_eof:
            raise Failure("original_socket_eof")
        for role, process in self.processes.items():
            stdout_open = any(key.data == role for key in self.selector.get_map().values())
            if process.poll() is not None and not stdout_open and not (role == "source" and b"PASS" in self.records.get(role, [])):
                # Drain available fixed stderr classes before reporting; never
                # expose raw debug text, addresses, paths or IRC transcripts.
                raise Failure("helper_exit_" + role)

    def wait(self, role, predicate, timeout=25):
        end = min(self.deadline, time.monotonic() + timeout)
        while True:
            for line in self.records.get(role, []):
                if predicate(line):
                    return line
            self.pump(end)

    def send(self, line, stream=None):
        stream = self.owner if stream is None else stream
        if time.monotonic() >= self.deadline or stream is None:
            raise Failure("owner_send_deadline")
        if b"\r" in line or b"\n" in line:
            raise Failure("outbound_framing")
        stream.setblocking(True)
        stream.settimeout(min(3, max(0.001, self.deadline - time.monotonic())))
        try:
            stream.sendall(line + b"\r\n")
        finally:
            stream.setblocking(False)

    def summary(self):
        rows = []
        for role, process in self.processes.items():
            code = process.poll()
            status = "running" if code is None else "exit_" + str(code)
            rows.append(role + "_" + status + "_" + self.errors.get(role + "-error", "class_unavailable"))
        return ";".join(rows)

    def close(self):
        self.selector.close()
        if self.owner is not None:
            self.owner.close()
        if self.control is not None:
            self.control.close()
        # Signal every private group even if its leader has already exited.
        for sig in (signal.SIGTERM, signal.SIGKILL):
            for process in self.processes.values():
                try:
                    os.killpg(process.pid, sig)
                except ProcessLookupError:
                    pass
            for process in self.processes.values():
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    if sig == signal.SIGKILL:
                        raise Failure("cleanup_deadline") from None
        for process in self.processes.values():
            process.stdout.close()
            process.stderr.close()


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(binary, timeout, scratch):
    artifact = sha(binary)
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        peer_port = reservation.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix="onyx-session-retry-", dir=scratch) as temporary:
        directory = Path(temporary)
        os.chmod(directory, 0o700)
        peer_dir, source_dir = directory / "peer", directory / "source"
        peer_dir.mkdir(mode=0o700)
        source_dir.mkdir(mode=0o700)
        runner = Runner(time.monotonic() + timeout)
        try:
            runner.launch("peer", binary, peer_dir, "peer", str(peer_port))
            runner.wait("peer", lambda line: line == b"PEER_READY")
            source = runner.launch("source", binary, source_dir, "source", str(peer_port))
            original_pid = source.pid
            port_line = runner.wait("source", lambda line: re.fullmatch(rb"PORT [0-9]{1,5}", line) is not None)
            runner.phase = "registration"
            runner.owner = socket.create_connection(("127.0.0.1", int(port_line.split()[1])), timeout=5)
            runner.add("owner", runner.owner)
            runner.send(b"NICK RetryOwner")
            runner.send(b"USER retry 0 * :Retry physical canary")
            runner.wait("owner", lambda line: b" 001 " in line)
            runner.phase = "control_lifecycle"
            runner.control = socket.create_connection(("127.0.0.1", int(port_line.split()[1])), timeout=5)
            runner.add("control", runner.control)
            runner.send(b"NICK RetryControlOwner", runner.control)
            runner.send(b"USER retrycontrol 0 * :Retired session control", runner.control)
            runner.wait("control", lambda line: b" 001 " in line)
            runner.wait("source", lambda line: line == b"CONTROL_BOUND")
            runner.send(b"IDENTIFY retry-control :Local-Fixture-Only-Password9!", runner.control)
            runner.wait("control", lambda line: b"You are now identified as retry-control" in line)
            runner.send(b"PING :retry-control-authenticated", runner.control)
            runner.wait("control", lambda line: b" PONG " in line and line.endswith(b":retry-control-authenticated"))
            # This is a real transport EOF. Ordinary Core close creates the
            # detached snapshot; the source emits retirement only after its
            # exact physical generation is absent from the owner slab.
            runner.selector.unregister(runner.control)
            runner.control.shutdown(socket.SHUT_WR)
            runner.control.close()
            runner.control = None
            runner.wait("source", lambda line: line == b"CONTROL_RETIRED")
            original_fd = runner.owner.fileno()
            for generation in range(3):
                runner.phase = "generation_" + str(generation)
                runner.wait("source", lambda line, g=generation: line == b"GEN " + str(g).encode())
                if generation == 0:
                    runner.wait("peer", lambda line: line == b"SEEN17")
                if runner.owner.fileno() != original_fd or source.pid != original_pid or source.poll() is not None:
                    raise Failure("physical_process_identity_changed")
                marker = b"retry-gen-" + str(generation).encode()
                runner.send(b"PING :" + marker)
                runner.wait("owner", lambda line, m=marker: b" PONG " in line and line.endswith(b":" + m))
                if generation < 2:
                    runner.wait("source", lambda line, n=(generation + 1) * 8: line == b"PAGE " + str(n).encode())
            runner.allow_eof = True
            runner.phase = "final_recovery"
            runner.wait("source", lambda line: line == b"PASS")
            runner.wait("peer", lambda line: line == b"PEER_CONVERGED")
            source_digest = runner.wait("source", lambda line: re.fullmatch(rb"SOURCE_DIGEST [0-9a-f]{64}", line) is not None)
            peer_digest = runner.wait("peer", lambda line: re.fullmatch(rb"PEER_DIGEST [0-9a-f]{64}", line) is not None)
            if source_digest.split()[1] != peer_digest.split()[1]:
                raise Failure("signed_revoke_origin_bytes_differ")
            if runner.records["source"].count(b"QUEUE_RETAINED") != 2 or runner.records["source"].count(b"FIRST_RETRY_FAILED") != 2:
                raise Failure("fault_or_pressure_receipt_count")
            if runner.records["source"].count(b"PAGE 8") != 1 or runner.records["source"].count(b"PAGE 16") != 1:
                raise Failure("retry_page_count")
            end = time.monotonic() + 5
            while source.poll() is None:
                runner.pump(end)
            if source.returncode != 0 or sha(binary) != artifact:
                raise Failure("terminal_artifact_or_exit")
            print("PASS session retry exec: 17 orphan groups; cursor8/16 across two real execs; persistent first failure; queue admission pressure; secured peer convergence; original socket canaries")
        except Exception as exc:
            kind = str(exc) if isinstance(exc, Failure) else "operation_" + type(exc).__name__
            raise Failure(runner.phase + ":" + kind + ";" + runner.summary()) from None
        finally:
            runner.close()



def run_publication(binary, timeout, scratch):
    """Independent mode; the default two-exec T06 journey is unchanged."""
    artifact = sha(binary)
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        peer_port = reservation.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix="onyx-publication-retry-", dir=scratch) as temporary:
        directory = Path(temporary)
        os.chmod(directory, 0o700)
        peer_dir, source_dir = directory / "peer", directory / "source"
        peer_dir.mkdir(mode=0o700)
        source_dir.mkdir(mode=0o700)
        runner = Runner(time.monotonic() + timeout)
        try:
            runner.launch("peer", binary, peer_dir, "publication-peer", str(peer_port))
            runner.wait("peer", lambda line: line == b"PEER_READY")
            source = runner.launch("source", binary, source_dir, "publication-source", str(peer_port))
            port = runner.wait("source", lambda line: re.fullmatch(rb"PORT [0-9]{1,5}", line) is not None)
            runner.phase = "publication_registration"
            runner.owner = socket.create_connection(("127.0.0.1", int(port.split()[1])), timeout=5)
            runner.add("owner", runner.owner)
            runner.send(b"NICK RetryOwner")
            runner.send(b"USER retry 0 * :Publication physical canary")
            runner.wait("owner", lambda line: b" 001 " in line)
            runner.wait("peer", lambda line: line == b"PUBLICATION_EMPTY")
            runner.wait("source", lambda line: line == b"PUBLICATION_BOUND")
            runner.send(b"IDENTIFY retry-control :Local-Fixture-Only-Password9!")
            runner.wait("owner", lambda line: b"You are now identified as retry-control" in line)
            runner.phase = "publication_fault_and_replay"
            runner.wait("source", lambda line: line == b"PUBLICATION_REUSED")
            runner.wait("peer", lambda line: line == b"PUBLICATION_CONVERGED")
            source_digest = runner.wait("source", lambda line: re.fullmatch(rb"SOURCE_DIGEST [0-9a-f]{64}", line) is not None)
            peer_digest = runner.wait("peer", lambda line: re.fullmatch(rb"PEER_DIGEST [0-9a-f]{64}", line) is not None)
            if source_digest.split()[1] != peer_digest.split()[1]:
                raise Failure("publication_signed_bytes_differ")
            if runner.records["peer"].count(b"PUBLICATION_EMPTY") != 1 or runner.records["peer"].count(b"PUBLICATION_CONVERGED") != 1 or runner.records["source"].count(b"PUBLICATION_REUSED") != 1:
                raise Failure("publication_receipt_count")
            runner.phase = "publication_original_socket_canary"
            runner.wait("source", lambda line: line == b"GEN 0")
            runner.send(b"PING :retry-gen-0")
            runner.wait("owner", lambda line: b" PONG " in line and line.endswith(b":retry-gen-0"))
            runner.allow_eof = True
            runner.wait("source", lambda line: line == b"PASS")
            end = min(runner.deadline, time.monotonic() + 5)
            while source.poll() is None:
                runner.pump(end)
            if source.returncode != 0 or sha(binary) != artifact:
                raise Failure("terminal_artifact_or_exit")
            print("PASS publication retry: initial secured peer unaware; OFFER fanout and lease allocation refused; same canonical OFFER reused; retained replay converges exact OFFER+lease; original socket canary")
        except Exception as exc:
            kind = str(exc) if isinstance(exc, Failure) else "operation_" + type(exc).__name__
            raise Failure(runner.phase + ":" + kind + ";" + runner.summary()) from None
        finally:
            runner.close()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--scratch-dir", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--publication", action="store_true", help="Run independent OFFER/lease retry convergence proof")
    args = parser.parse_args()
    if sys.platform != "linux" or not 0 < args.timeout <= 180:
        parser.error("Linux and timeout in (0,180] required")
    try:
        selected = run_publication if args.publication else run
        selected(args.binary.resolve(strict=True), args.timeout, args.scratch_dir.resolve(strict=True))
    except Exception as exc:
        reason = str(exc) if isinstance(exc, Failure) else "preflight_" + type(exc).__name__
        print("FAIL session retry exec: " + reason, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
