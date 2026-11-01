#!/usr/bin/env python3
"""Exercise the production issuer's real Helix exec with inherited IRC sockets.

The helper mode uses actual source freeze, FD plan, exec and successor validation.
Optional --adopt-cuts performs each bounded fresh-exec adoption allocation cut.
All credentials and complete transcripts remain private to the fixture.
"""
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

MAX_OUTPUT = 65536
MAX_WIRE = 65536
MAX_LINE = 8192


class SmokeFailure(Exception):
    pass


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class Harness:
    def __init__(self, process, deadline):
        self.process = process
        self.deadline = deadline
        self.selector = selectors.DefaultSelector()
        self.buffers = {}
        self.totals = {}
        self.lines = {}
        self.transcripts = {}
        self.closed_clients = set()
        self.allow_client_eof = False
        self.phase = "source-port"
        self.sockets = []
        self.add("stdout", process.stdout)
        self.add("stderr", process.stderr)

    def add(self, name, stream):
        os.set_blocking(stream.fileno(), False)
        self.selector.register(stream, selectors.EVENT_READ, name)
        self.buffers[name] = bytearray()
        self.totals[name] = 0
        self.lines[name] = []
        self.transcripts[name] = []

    def connect(self, port, nick):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise SmokeFailure("deadline before client connect")
        sock = socket.create_connection(("127.0.0.1", port), timeout=min(remaining, 5))
        self.sockets.append(sock)
        sock.settimeout(min(remaining, 5))
        sock.sendall(f"NICK {nick}\r\nUSER issuer 0 * :Issuer fixture\r\n".encode("ascii"))
        self.add(nick, sock)
        return sock

    def pump(self, stage_deadline):
        remaining = min(self.deadline, stage_deadline) - time.monotonic()
        if remaining <= 0:
            raise SmokeFailure("deadline waiting for expected evidence")
        events = self.selector.select(min(remaining, 0.25))
        unexpected_eof = None
        # Drain fixed helper diagnostics before reporting a socket EOF from
        # the same readiness batch. Never print raw stderr or IRC contents.
        events.sort(key=lambda item: 0 if item[0].data == "stderr" else 1)
        for key, _ in events:
            name = key.data
            try:
                data = os.read(key.fileobj.fileno(), 4096)
            except BlockingIOError:
                continue
            if not data:
                self.selector.unregister(key.fileobj)
                if self.buffers[name]:
                    raise SmokeFailure("unterminated output")
                if name not in ("stdout", "stderr"):
                    self.closed_clients.add(name)
                    if not self.allow_client_eof:
                        unexpected_eof = name
                continue
            self.totals[name] += len(data)
            if self.totals[name] > (MAX_OUTPUT if name in ("stdout", "stderr") else MAX_WIRE):
                raise SmokeFailure("output limit exceeded")
            self.buffers[name].extend(data)
            while b"\n" in self.buffers[name]:
                line, _, rest = self.buffers[name].partition(b"\n")
                self.buffers[name] = bytearray(rest)
                if len(line) > MAX_LINE:
                    raise SmokeFailure("line limit exceeded")
                complete = line.rstrip(b"\r")
                self.lines[name].append(complete)
                self.transcripts[name].append(complete)
            if len(self.buffers[name]) > MAX_LINE:
                raise SmokeFailure("line limit exceeded")
        if unexpected_eof is not None:
            raise SmokeFailure("client disconnected before completion role=" + unexpected_eof)

    def wait_line(self, name, predicate):
        stage_deadline = min(self.deadline, time.monotonic() + 20)
        while True:
            for index, line in enumerate(self.lines[name]):
                if predicate(line):
                    del self.lines[name][: index + 1]
                    return line
            if self.process.poll() is not None and not any(key.data == "stdout" for key in self.selector.get_map().values()):
                raise SmokeFailure("helper exited before expected evidence")
            self.pump(stage_deadline)

    def close(self):
        self.selector.close()
        for sock in self.sockets:
            sock.close()


def irc_command(line, command, final=None):
    fields = line.split(b" ")
    if fields and fields[0].startswith(b":"):
        fields = fields[1:]
    return bool(fields and fields[0] == command and (final is None or fields[-1] == b":" + final))


def class_summary(labels):
    counts = {}
    sequence = []
    for label in labels:
        counts[label] = min(999, counts.get(label, 0) + 1)
        if len(sequence) < 64:
            sequence.append(label)
    classes = ",".join(f"{label}:{counts[label]}" for label in sorted(counts)[:24]) or "none"
    return classes + ";seen001=" + str(int("001" in counts)) + ";sequence=" + (",".join(sequence) or "none")


def record_classes(records):
    """Bounded protocol classes only: never prefixes, targets, tags or text."""
    labels = []
    for record in records:
        fields = record.split(b" ")
        if fields and fields[0].startswith(b"@"):
            fields = fields[1:]
        if fields and fields[0].startswith(b":"):
            fields = fields[1:]
        command = fields[0] if fields else b""
        if re.fullmatch(rb"[0-9]{3}", command):
            label = command.decode("ascii")
        elif command in (b"ERROR", b"NOTICE", b"PING", b"PONG", b"FAIL", b"WARN"):
            label = command.decode("ascii")
        else:
            label = "other"
        labels.append(label)
    return class_summary(labels)


def stdout_classes(records):
    labels = []
    for record in records:
        match = re.fullmatch(rb"(PORT|ADOPTED|REFUSED|ABORTED|PASS)(?: [0-9]+(?: [01])?)?", record)
        labels.append(match.group(1).decode("ascii") if match else "other")
    return class_summary(labels)


def run(binary, timeout, scratch_dir, refusal=False, cut=None):
    deadline = time.monotonic() + timeout
    before_hash = sha256(binary)
    with tempfile.TemporaryDirectory(prefix="onyx-issuer-exec-", dir=scratch_dir) as scratch:
        os.chmod(scratch, 0o700)
        mode = "source-refuse" if refusal else "source"
        arguments = [str(binary), mode]
        if cut is not None:
            arguments = [str(binary), "source-adopt-census"] if cut == "census" else [str(binary), "source-adopt-cut", str(cut)]
        process = subprocess.Popen(arguments, cwd=scratch, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True, close_fds=True)
        harness = Harness(process, deadline)
        harness.allow_client_eof = cut is not None
        try:
            port_line = harness.wait_line("stdout", lambda line: re.fullmatch(rb"PORT [0-9]{1,5}", line) is not None)
            port = int(port_line.split()[1])
            if not 0 < port < 65536:
                raise SmokeFailure("invalid helper port")
            harness.phase = "committed-registration"
            committed = harness.connect(port, "CommittedIssuer")
            harness.wait_line("CommittedIssuer", lambda line: irc_command(line, b"001"))
            harness.phase = "pending-registration-and-exec"
            pending = harness.connect(port, "PendingIssuer")
            stage = harness.wait_line("stdout", lambda line: line in (b"ADOPTED", b"REFUSED") or
                                      re.fullmatch(rb"ADOPTED [0-9]+ [01]|ABORTED [0-9]+", line) is not None)
            aborted = stage.startswith(b"ABORTED ")
            allocations = None
            induced = False
            if aborted:
                if cut in (None, "census") or int(stage.split()[1]) != cut:
                    raise SmokeFailure("unexpected native adopt rollback")
                induced = True
            else:
                if refusal != (stage == b"REFUSED") or harness.closed_clients:
                    raise SmokeFailure("unexpected native transition or closed source socket")
                if stage.startswith(b"ADOPTED "):
                    _, count, fault = stage.split()
                    allocations, induced = int(count), fault == b"1"
                elif cut is not None:
                    raise SmokeFailure("native allocation census absent")
                # The serving Core checks owned ADS at capture and adoption.
                # These exact records must precede the normal PONG on each
                # original physical socket, with no late duplicates at EOF.
                for sock, nick, token in (
                    (committed, "CommittedIssuer", b"issuer-committed"),
                    (pending, "PendingIssuer", b"issuer-pending"),
                ):
                    harness.phase = "retained-prefix-" + nick
                    prefix = b":issuer-production.test NOTICE " + nick.encode("ascii") + b" :retained-before-issuer-carry"
                    harness.wait_line(nick, lambda line, expected=prefix: line == expected)
                    sock.settimeout(min(max(deadline - time.monotonic(), 0.001), 5))
                    harness.phase = "canary-pong-" + nick
                    sock.sendall(b"PING :" + token + b"\r\n")
                    harness.wait_line(nick, lambda line, expected=token: irc_command(line, b"PONG", expected))
                harness.allow_client_eof = True
                harness.phase = "next-registration"
                next_client = harness.connect(port, "NextIssuer")
                harness.wait_line("NextIssuer", lambda line: irc_command(line, b"001"))
                next_client.settimeout(min(max(deadline - time.monotonic(), 0.001), 5))
                next_client.sendall(b"PING :issuer-next-finish\r\n")
                harness.wait_line("NextIssuer", lambda line: irc_command(line, b"PONG", b"issuer-next-finish"))
                harness.phase = "next-finish-pong"
                harness.wait_line("stdout", lambda line: line == b"PASS")
            harness.phase = "terminal-stream-drain"
            exit_deadline = min(deadline, time.monotonic() + 20)
            while process.poll() is None or harness.selector.get_map():
                harness.pump(exit_deadline)
            if process.returncode != 0:
                raise SmokeFailure("helper exited unsuccessfully")
            for nick, token in (("CommittedIssuer", b"issuer-committed"), ("PendingIssuer", b"issuer-pending")):
                prefix = b":issuer-production.test NOTICE " + nick.encode("ascii") + b" :retained-before-issuer-carry"
                lines = harness.transcripts[nick]
                matching = [index for index, line in enumerate(lines) if line == prefix]
                if aborted:
                    if matching or nick not in harness.closed_clients:
                        raise SmokeFailure("failed target activated inherited output or leaked socket")
                else:
                    pongs = [index for index, line in enumerate(lines) if irc_command(line, b"PONG", token)]
                    if len(matching) != 1 or len(pongs) != 1 or matching[0] >= pongs[0]:
                        raise SmokeFailure("retained issuer prefix lost reordered or duplicated")
            if sha256(binary) != before_hash:
                raise SmokeFailure("helper binary changed during run")
            if cut is None:
                print(f"PASS issuer production {'refusal' if refusal else 'exec'}: 2 original sockets, owned nonempty prefix, 1 subsequent reservation; binary sha256={before_hash}")
            return aborted, allocations, induced
        except Exception as exc:
            helper_error = "unavailable"
            helper_phase = "unavailable"
            for record in harness.transcripts.get("stderr", []):
                immediate = re.fullmatch(rb"issuer-production-failure: stage=([a-z_]{1,40}) error=([A-Za-z][A-Za-z0-9_]{0,63})", record)
                if immediate:
                    helper_phase = immediate.group(1).decode("ascii")
                    helper_error = immediate.group(2).decode("ascii")
                match = re.fullmatch(rb"issuer-production-helper: ([A-Za-z][A-Za-z0-9_]{0,63})", record)
                if match:
                    helper_error = match.group(1).decode("ascii")
            status = process.poll()
            status_text = "running" if status is None else str(status)
            reason = str(exc) if isinstance(exc, SmokeFailure) else type(exc).__name__
            # Only fixed stage/role names, numbers, and a Zig error-name token.
            # Raw IRC, stderr, credentials, paths, and OS error text stay private.
            committed_classes = record_classes(harness.transcripts.get("CommittedIssuer", []))
            pending_classes = record_classes(harness.transcripts.get("PendingIssuer", []))
            stage_classes = stdout_classes(harness.transcripts.get("stdout", []))
            raise SmokeFailure(f"phase={harness.phase} helper_exit={status_text} helper_stage={helper_phase} helper_error={helper_error} committed_records={committed_classes} pending_records={pending_classes} stdout_records={stage_classes} reason={reason}") from None
        finally:
            harness.close()
            # The source may have exited while its private process group
            # still contains a capability probe or exec descendant.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=2)
            if process.stdout:
                process.stdout.close()
            if process.stderr:
                process.stderr.close()


def run_adopt_cuts(binary, timeout, scratch_dir):
    deadline = time.monotonic() + timeout
    def attempt(cut):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SmokeFailure("native allocation campaign deadline")
        return run(binary, min(90, remaining), scratch_dir, cut=cut)
    aborted, count, induced = attempt("census")
    if aborted or induced or count is None or not 0 < count < 4096:
        raise SmokeFailure("native adoption allocation census invalid")
    rollbacks = 0
    committed_faults = 0
    for ordinal in range(count):
        aborted, _, induced = attempt(ordinal)
        if not induced:
            raise SmokeFailure("native allocation ordinal changed; no cuts may be skipped")
        rollbacks += int(aborted)
        committed_faults += int(not aborted)
        if (ordinal + 1) % 16 == 0:
            print(f"PROGRESS issuer adoption allocation cuts: {ordinal + 1}/{count}", flush=True)
    aborted, final_count, induced = attempt(count)
    if aborted or induced or final_count != count:
        raise SmokeFailure("native final allocation census changed")
    print(f"PASS issuer fresh-exec adoption allocation cuts: {count} distinct ordinals, {rollbacks} inert target rollbacks, {committed_faults} committed optional-fault canary checks; final normal exec passed")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path, help="compiled production issuer exec helper")
    parser.add_argument("--adopt-cuts", action="store_true", help="finite fresh-exec adoption allocation census and every ordinal; helper required")
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument("--scratch-dir", type=Path)
    args = parser.parse_args()
    if not 0 < args.timeout <= 600:
        parser.error("timeout must be greater than 0 and at most 600 seconds")
    binary = args.binary.resolve(strict=True)
    if not binary.is_file():
        parser.error("binary must be a regular file")
    try:
        if args.adopt_cuts:
            run_adopt_cuts(binary, args.timeout, args.scratch_dir)
        else:
            run(binary, args.timeout, args.scratch_dir)
            run(binary, args.timeout, args.scratch_dir, refusal=True)
    except Exception as exc:
        reason = str(exc) if isinstance(exc, SmokeFailure) else type(exc).__name__
        print(f"FAIL issuer production exec: {reason}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
