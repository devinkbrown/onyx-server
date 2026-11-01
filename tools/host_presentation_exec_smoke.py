#!/usr/bin/env python3
"""Exercise actual Core host-presentation exec and fail-closed refusal."""
import argparse
import hashlib
import os
import re
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

MAX_STREAM = 65536
MAX_LINE = 8192


class SmokeFailure(Exception):
    def __init__(self, reason, exit_status=None):
        super().__init__(reason)
        self.exit_status = exit_status


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def command(line, name, last=None):
    fields = line.split(b" ")
    if fields and fields[0].startswith(b"@"):
        fields = fields[1:]
    if fields and fields[0].startswith(b":"):
        fields = fields[1:]
    return bool(fields and fields[0].upper() == name and (last is None or fields[-1] == b":" + last))


class Harness:
    def __init__(self, process, deadline):
        self.process = process
        self.deadline = deadline
        self.selector = selectors.DefaultSelector()
        self.buffers = {}
        self.totals = {}
        self.lines = {}
        self.sockets = []
        self.allow_socket_eof = False
        self.add("stdout", process.stdout)
        self.add("stderr", process.stderr)

    def add(self, name, stream):
        os.set_blocking(stream.fileno(), False)
        self.selector.register(stream, selectors.EVENT_READ, name)
        self.buffers[name] = bytearray()
        self.totals[name] = 0
        self.lines[name] = []

    def send(self, sock, data):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise SmokeFailure("deadline")
        sock.settimeout(min(5, remaining))
        sock.sendall(data)
        sock.setblocking(False)

    def connect(self, port, nick):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise SmokeFailure("deadline")
        sock = socket.create_connection(("127.0.0.1", port), timeout=min(5, remaining))
        self.sockets.append(sock)
        self.send(sock, (f"CAP LS 302\r\nCAP REQ :chghost\r\nCAP END\r\nNICK {nick}\r\n"
                         f"USER issuer 0 * :Host fixture\r\n").encode("ascii"))
        self.add(nick, sock)
        self.wait(nick, lambda line: command(line, b"001"))
        self.wait(nick, lambda line: b" CAP " in line and b" ACK " in line and any(part.lstrip(b":") == b"chghost" for part in line.split()))
        self.send(sock, b"JOIN #host-proof\r\n")
        self.wait(nick, lambda line: command(line, b"366") and b"#host-proof" in line.split())
        return sock

    def pump(self, stage_deadline):
        remaining = min(self.deadline, stage_deadline) - time.monotonic()
        if remaining <= 0:
            raise SmokeFailure("deadline")
        for key, _ in self.selector.select(min(remaining, 0.25)):
            name = key.data
            try:
                data = os.read(key.fileobj.fileno(), 4096)
            except BlockingIOError:
                continue
            if not data:
                self.selector.unregister(key.fileobj)
                if self.buffers[name]:
                    raise SmokeFailure("unterminated output")
                if name not in ("stdout", "stderr") and not self.allow_socket_eof:
                    raise SmokeFailure("original connection closed before terminal barrier")
                continue
            self.totals[name] += len(data)
            if self.totals[name] > MAX_STREAM:
                raise SmokeFailure("output limit")
            self.buffers[name].extend(data)
            while b"\n" in self.buffers[name]:
                line, _, tail = self.buffers[name].partition(b"\n")
                self.buffers[name] = bytearray(tail)
                if len(line) > MAX_LINE:
                    raise SmokeFailure("line limit")
                self.lines[name].append(line.rstrip(b"\r"))
            if len(self.buffers[name]) > MAX_LINE:
                raise SmokeFailure("line limit")

    def wait(self, name, predicate):
        limit = min(self.deadline, time.monotonic() + 60)
        while True:
            for line in self.lines[name]:
                if predicate(line):
                    return line
            if self.process.poll() is not None and not any(k.data == "stdout" for k in self.selector.get_map().values()):
                raise SmokeFailure("helper exited before evidence", exit_status=self.process.returncode)
            self.pump(limit)

    def close(self):
        self.selector.close()
        for sock in self.sockets:
            sock.close()


def check_transcripts(lines_by_name, baseline, mode, old, new):
    """Inspect every post-baseline CHGHOST through terminal EOF."""
    expected = b":GeneratedOwner!issuer@" + old + b" CHGHOST issuer " + new
    for name in ("GeneratedOwner", "HostObserver", "OperControl"):
        lines = lines_by_name[name]
        changes = [(i, line) for i, line in enumerate(lines) if i > baseline[name] and command(line, b"CHGHOST")]
        if mode == "source":
            if len(changes) != 1 or changes[0][1] != expected:
                raise SmokeFailure("unexpected host repair")
            if name != "OperControl":
                notice = b":host-proof.test NOTICE " + name.encode("ascii") + b" :retained-before-host-repair"
                notices = [i for i, line in enumerate(lines) if i > baseline[name] and line == notice]
                if len(notices) != 1 or notices[0] >= changes[0][0]:
                    raise SmokeFailure("host repair ordering")
        elif changes:
            raise SmokeFailure("unexpected host repair")


def _expect_rejected_fixture(lines, baseline, mode):
    try:
        check_transcripts(lines, baseline, mode, b"old", b"new")
    except SmokeFailure:
        return
    raise AssertionError("invalid transcript was accepted")


def test_extra_different_host_repair_is_rejected():
    notice = lambda name: b":host-proof.test NOTICE " + name.encode("ascii") + b" :retained-before-host-repair"
    repair = b":GeneratedOwner!issuer@old CHGHOST issuer new"
    lines = {name: [b"baseline", notice(name), repair] for name in ("GeneratedOwner", "HostObserver")}
    lines["OperControl"] = [b"baseline", repair]
    lines["HostObserver"].append(b":GeneratedOwner!issuer@new CHGHOST issuer other")
    _expect_rejected_fixture(lines, {name: 0 for name in lines}, "source")


def test_refusal_rejects_nonmatching_repair():
    lines = {name: [b"baseline"] for name in ("GeneratedOwner", "HostObserver", "OperControl")}
    lines["OperControl"].append(b":Other!issuer@old CHGHOST issuer other")
    _expect_rejected_fixture(lines, {name: 0 for name in lines}, "source-unknown")


def test_repair_after_pong_is_rejected():
    notice = lambda name: b":host-proof.test NOTICE " + name.encode("ascii") + b" :retained-before-host-repair"
    repair = b":GeneratedOwner!issuer@old CHGHOST issuer new"
    lines = {name: [b"baseline", notice(name), repair, b":s PONG s :terminal"] for name in ("GeneratedOwner", "HostObserver")}
    lines["OperControl"] = [b"baseline", repair, b":s PONG s :terminal", b":Other!issuer@old CHGHOST issuer late"]
    _expect_rejected_fixture(lines, {name: 0 for name in lines}, "source")



def test_three_recipients_accept_one_owner_repair():
    repair = b":GeneratedOwner!issuer@old CHGHOST issuer new"
    lines = {name: [b"baseline", b":host-proof.test NOTICE " + name.encode("ascii") + b" :retained-before-host-repair", repair] for name in ("GeneratedOwner", "HostObserver")}
    lines["OperControl"] = [b"baseline", repair]
    check_transcripts(lines, {name: 0 for name in lines}, "source", b"old", b"new")


def test_control_subject_repair_is_rejected():
    repair = b":GeneratedOwner!issuer@old CHGHOST issuer new"
    lines = {name: [b"baseline", b":host-proof.test NOTICE " + name.encode("ascii") + b" :retained-before-host-repair", repair] for name in ("GeneratedOwner", "HostObserver")}
    lines["OperControl"] = [b"baseline", repair, b":OperControl!issuer@operator.control CHGHOST issuer other"]
    _expect_rejected_fixture(lines, {name: 0 for name in lines}, "source")


def run_case(binary, mode, timeout, scratch_dir):
    deadline = time.monotonic() + timeout
    with tempfile.TemporaryDirectory(prefix="onyx-host-exec-", dir=scratch_dir) as scratch:
        os.chmod(scratch, 0o700)
        process = subprocess.Popen([str(binary), mode], cwd=scratch, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True, close_fds=True)
        harness = Harness(process, deadline)
        try:
            port_line = harness.wait("stdout", lambda line: re.fullmatch(rb"PORT [0-9]{1,5}", line) is not None)
            port = int(port_line.split()[1])
            if not 0 < port < 65536:
                raise SmokeFailure("invalid port")
            clients = {name: harness.connect(port, name) for name in ("GeneratedOwner", "HostObserver", "OperControl")}
            baseline_marker = harness.wait("stdout", lambda line: line == b"BASELINE")
            baseline = {}
            for name, token in (("GeneratedOwner", b"host-baseline-owner"), ("HostObserver", b"host-baseline-observer"), ("OperControl", b"host-baseline-oper")):
                harness.send(clients[name], b"PING :" + token + b"\r\n")
                pong = harness.wait(name, lambda line, expected=token: command(line, b"PONG", expected))
                baseline[name] = harness.lines[name].index(pong)
            host_line = harness.wait("stdout", lambda line: re.fullmatch(rb"HOST [^\s]+ [^\s]+", line) is not None)
            _, old, new = host_line.split(b" ")
            if old == new or len(old) > 255 or len(new) > 255:
                raise SmokeFailure("invalid host transition")
            harness.wait("stdout", lambda line: line == (b"ADOPTED" if mode == "source" else b"REFUSED"))
            harness.send(clients["HostObserver"], b"WHOIS OperControl\r\n")
            harness.wait("HostObserver", lambda line: command(line, b"318") and b"OperControl" in line.split())
            whois = [line.split() for line in harness.lines["HostObserver"] if command(line, b"311") and b"OperControl" in line.split()]
            if len(whois) != 1 or whois[0][3:6] != [b"OperControl", b"issuer", b"operator.control"]:
                raise SmokeFailure("explicit operator host changed")
            for name, token in (("GeneratedOwner", b"host-owner"), ("HostObserver", b"host-observer"), ("OperControl", b"host-oper")):
                harness.send(clients[name], b"PING :" + token + b"\r\n")
                harness.wait(name, lambda line, expected=token: command(line, b"PONG", expected))
            # Terminal PONGs establish that each original socket survived the
            # post-adoption/refusal phase; keep reading through process exit and
            # EOF so a late host change is included in the transcript.
            for name, token in (("GeneratedOwner", b"host-terminal-owner"), ("HostObserver", b"host-terminal-observer"), ("OperControl", b"host-terminal-oper")):
                harness.send(clients[name], b"PING :" + token + b"\r\n")
                harness.wait(name, lambda line, expected=token: command(line, b"PONG", expected))
            harness.allow_socket_eof = True
            harness.send(clients["GeneratedOwner"], b"PING :host-finish\r\n")
            harness.wait("stdout", lambda line: line == b"PASS")
            exit_deadline = min(deadline, time.monotonic() + 60)
            while process.poll() is None or harness.selector.get_map():
                harness.pump(exit_deadline)
            check_transcripts(harness.lines, baseline, mode, old, new)
            if process.returncode != 0:
                raise SmokeFailure("helper failed", exit_status=process.returncode)
            expected_stdout = [port_line, baseline_marker, host_line, b"ADOPTED" if mode == "source" else b"REFUSED", b"PASS"]
            if harness.lines["stdout"] != expected_stdout:
                raise SmokeFailure("unexpected helper markers")
        finally:
            harness.close()
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
            # Recheck the original private process group even when its leader
            # exited: a surviving child must not escape cleanup.
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                pass
            else:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if process.poll() is None:
                process.wait(timeout=2)
            if process.stdout:
                process.stdout.close()
            if process.stderr:
                process.stderr.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--timeout", type=float, default=180.0, help="deadline per mode in seconds")
    parser.add_argument("--scratch-dir", type=Path)
    args = parser.parse_args()
    if not 0 < args.timeout <= 600:
        parser.error("timeout must be greater than 0 and at most 600")
    mode = "setup"
    try:
        binary = args.binary.resolve(strict=True)
        if not binary.is_file():
            raise SmokeFailure("helper is not a regular file")
        initial_hash = digest(binary)
        mode = "source"
        run_case(binary, mode, args.timeout, args.scratch_dir)
        mode = "source-unknown"
        run_case(binary, mode, args.timeout, args.scratch_dir)
        if digest(binary) != initial_hash:
            raise SmokeFailure("helper binary changed")
        print(f"PASS host production exec: 3 original sockets, ordered repair and refusal; binary sha256={initial_hash}")
        return 0
    except SmokeFailure as exc:
        status = "" if exc.exit_status is None else f"; helper exit status={exc.exit_status}"
        print(f"FAIL host production exec: {mode}: {exc}{status}", file=sys.stderr)
        return 1
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"FAIL host production exec: {mode}: {type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
