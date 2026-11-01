#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Linux production CLI A-B-C issuer/session journey, with real A then B exec.

Requires the ordinary daemon, never the issuer test helper. Public test-vector
mesh identities come from windows_mesh_smoke; TLS/session framing and delivery
oracles come from windows_session_smoke. No credential or transcript is printed.
An unread accepted wire prefix is checked across exec; this tool alone cannot
prove whether that prefix was in kernel versus daemon-owned custody at the cut.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import secrets
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error

import windows_mesh_smoke as mesh
import windows_session_smoke as session

MAX_LOG = 2 * 1024 * 1024
MAX_WIRE = 4 * 1024 * 1024
MAX_LINE = 8192
RESTORED = "UPGRADE resume — restored mandatory World/history/events/replay/webhooks".encode()


class Failure(Exception):
    """Fixed class only: never include command, credential or raw exception."""


class Budget:
    def __init__(self, timeout):
        self.end = time.monotonic() + timeout
        self.phase = "preflight"
        self.processes = []
        self.nodes = {}

    def check(self):
        if time.monotonic() >= self.end:
            raise Failure("journey_deadline")
        if any(p.poll() is not None for p in self.processes):
            raise Failure("daemon_exit")

    def daemon_summary(self):
        summaries = []
        for process in self.processes:
            node, log = self.nodes.get(process.pid, ("unknown", None))
            code = process.poll()
            if code is not None and log is not None:
                # The exited leader's final pipe bytes must reach the fixed
                # classifier before teardown deletes the private log directory.
                log.thread.join(timeout=0.25)
            status = "running" if code is None else ("signal_" + str(-code) if code < 0 else "exit_" + str(code))
            category = log.failure_class() if log is not None else "logger_unavailable"
            summaries.append("node_" + node + "_" + status + "_class_" + category)
        return ";".join(summaries) or "no_daemon_started"

    def remaining(self, cap=30):
        self.check()
        return min(cap, max(0.001, self.end - time.monotonic()))


class PrivateLog:
    """Drain a private process pipe continuously with a hard byte ceiling."""
    def __init__(self, process, path):
        self.process, self.path = process, path
        self.count = 0
        self.restores = 0
        self.refusal = None
        self.startup_error = None
        self.startup_panic = False
        self.line_buffer = b""
        self.overflow = False
        self.failed = False
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        tail = b""
        try:
            with self.path.open("xb") as output:
                os.chmod(self.path, 0o600)
                while True:
                    chunk = os.read(self.process.stdout.fileno(), 4096)
                    if not chunk:
                        break
                    with self.lock:
                        self.count += len(chunk)
                        if self.count > MAX_LOG:
                            self.overflow = True
                        else:
                            output.write(chunk)
                        combined = tail + chunk
                        self.restores += combined.count(RESTORED)
                        tail = combined[-(len(RESTORED) - 1):]
                        self.line_buffer += chunk
                        while b"\n" in self.line_buffer:
                            line, self.line_buffer = self.line_buffer.split(b"\n", 1)
                            # This producer writes @errorName only. Anchoring
                            # excludes unrelated text, paths and IRC payloads.
                            match = re.fullmatch(rb"onyx-server: deferred UPGRADE failed: ([A-Za-z][A-Za-z0-9_]{0,63})", line.rstrip(b"\r"))
                            if match is not None:
                                self.refusal = match[1].decode("ascii")
                            default_error = re.fullmatch(rb"error: ([A-Za-z][A-Za-z0-9_]{0,63})", line.rstrip(b"\r"))
                            cold_error = re.fullmatch(rb"onyx-server: configured guest issuer cold open failed \(([A-Za-z][A-Za-z0-9_]{0,63})\); provision missing state explicitly with --initialize-guest-issuer <config.toml>; existing state is never replaced automatically", line.rstrip(b"\r"))
                            if default_error is not None or cold_error is not None:
                                self.startup_error = (default_error or cold_error)[1].decode("ascii")
                            if re.fullmatch(rb"(?:thread [0-9]+ )?panic: configured guest issuer requires fallible prepareConfiguredColdResources before admission", line.rstrip(b"\r")):
                                self.startup_panic = True
                            if len(line) > MAX_LINE:
                                self.overflow = True
                        if len(self.line_buffer) > MAX_LINE:
                            self.overflow = True
                            self.line_buffer = b""
        except Exception:
            self.failed = True

    def failure_class(self):
        with self.lock:
            if self.startup_panic:
                return "configured_issuer_not_prepared"
            if self.startup_error is not None:
                return "startup_error_" + self.startup_error
            if self.refusal is not None:
                return "deferred_upgrade_" + self.refusal
            if self.overflow or self.failed:
                return "private_log_bound_or_io"
            return "unavailable"

    def restored(self):
        with self.lock:
            if self.overflow or self.failed:
                raise Failure("private_log_bound_or_io")
            if self.refusal is not None:
                raise Failure("deferred_upgrade_refused_" + self.refusal)
            return self.restores


class Client(session.Client):
    def __init__(self, port, label, budget):
        self.budget = budget
        self.wire_bytes = 0
        super().__init__(port, label)

    def send(self, line):
        self.budget.check()
        if b"\r" in line or b"\n" in line or len(line) > MAX_LINE:
            raise Failure("invalid_outbound_framing")
        super().send(line)

    def pump(self):
        self.budget.check()
        before = len(self.seen)
        super().pump()
        for line in self.seen[before:]:
            self.wire_bytes += len(line) + 2
            if len(line) > MAX_LINE:
                raise Failure("irc_line_bound")
        if len(self.buffer) > MAX_LINE or self.wire_bytes > MAX_WIRE:
            raise Failure("irc_wire_bound")

    def wait(self, predicate, start, operation, timeout=20):
        try:
            return super().wait(predicate, start, operation,
                                min(timeout, self.budget.remaining(timeout)))
        except TimeoutError:
            raise Failure("irc_response_deadline") from None
        except (OSError, ConnectionError):
            raise Failure("tls_socket_eof_or_io") from None


class Oracle(session.Oracle):
    def event(self, source, clients, eligible, target, phase):
        super().event(source, clients, eligible, target, phase)
        needle = self.events[-1][0]
        bodies = [next(line for line in c.seen if needle in line).split(b" ", 1)[1]
                  for c in eligible]
        if len(set(bodies)) != 1:
            raise Failure("accepted_origin_bytes_differ")


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def stop_groups(processes):
    # Always signal the original private group, including when its leader exited.
    for sig in (signal.SIGTERM, signal.SIGKILL):
        for process in processes:
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                pass
        for process in processes:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                if sig == signal.SIGKILL:
                    raise Failure("process_group_cleanup_deadline") from None


def run(binary, timeout, scratch):
    budget = Budget(timeout)
    artifact = digest(binary)
    ports = mesh.reserve_ports(12)
    irc, s2s, metrics, tls = ports[:3], ports[3:6], ports[6:9], ports[9:12]
    clients, logs = [], []
    by_node = {}
    budget.phase = "configuration"
    with tempfile.TemporaryDirectory(prefix="onyx-issuer-session-", dir=scratch) as temporary:
        root = Path(temporary)
        os.chmod(root, 0o700)
        pinned = root / "onyx-server"
        shutil.copy2(binary, pinned)
        if digest(pinned) != artifact:
            raise Failure("artifact_pin_mismatch")
        directories = [root / label for label in "ABC"]
        configs = []
        try:
            for index, directory in enumerate(directories):
                directory.mkdir(mode=0o700)
                for private in ("accounts-private", "issuer-private"):
                    (directory / private).mkdir(mode=0o700)
                config = directory / "node.toml"
                text = mesh.node_config(index, irc[index], s2s[index], metrics[index], s2s[1],
                                        tls=tls[index], account_services=True, relay_v2=True)
                text += '\n[guest_presence]\nissuer_path = "issuer-private/issuer.wal"\n'
                config.write_text(text, encoding="utf-8")
                os.chmod(config, 0o600)
                configs.append(config)
                for option in ("--check-config", "--initialize-guest-issuer"):
                    # Fixed tool diagnostics only; provisioner output may contain private paths.
                    provision = subprocess.Popen([str(pinned), option, str(config)], cwd=directory,
                                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                                 stderr=subprocess.STDOUT, start_new_session=True, close_fds=True)
                    provision_log = None
                    try:
                        provision_log = PrivateLog(provision, directory / (option[2:] + "-private.log"))
                        provision_end = time.monotonic() + budget.remaining()
                        while provision.poll() is None:
                            provision_log.restored()
                            if time.monotonic() >= provision_end:
                                raise Failure("provision_deadline")
                            time.sleep(0.025)
                        if provision.returncode:
                            raise Failure("configuration_or_offline_issuer_refused")
                    finally:
                        try:
                            stop_groups([provision])
                        finally:
                            if provision_log is not None:
                                provision_log.thread.join(timeout=3)
                            provision.stdout.close()
                    provision_log.restored()
            budget.phase = "startup"
            for index in (1, 0, 2):
                process = subprocess.Popen([str(pinned), str(configs[index])], cwd=directories[index],
                                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT, start_new_session=True, close_fds=True)
                budget.processes.append(process)
                budget.nodes[process.pid] = ("ABC"[index], None)
                log = PrivateLog(process, directories[index] / "daemon-private.log")
                budget.nodes[process.pid] = ("ABC"[index], log)
                logs.append(log)
                by_node[index] = process, log

            def links():
                end = time.monotonic() + budget.remaining(45)
                while time.monotonic() < end:
                    budget.check()
                    try:
                        rows = [mesh.gauges(port) for port in metrics]
                    except (OSError, urllib.error.URLError, TimeoutError):
                        time.sleep(0.05)
                        continue
                    if all(row.get("onyx_s2s_links_active") == degree and
                           row.get("onyx_s2s_tcp_active") == degree and
                           row.get("onyx_mesh_peers_up") == degree and
                           row.get("onyx_mesh_partitioned") == 0
                           for row, degree in zip(rows, (1, 2, 1))):
                        for log in logs:
                            log.restored()
                        return
                    time.sleep(0.05)
                raise Failure("secured_line_topology_deadline")

            links()
            password = secrets.token_urlsafe(24).encode("ascii")

            def connect(node, label, account=None):
                client = Client(tls[node], label, budget)
                clients.append(client)
                client.register(label, account, password if account else None)
                if account is None:
                    response = client.command(b"CAP REQ :message-tags server-time echo-message",
                                              b" CAP ", "guest identity capabilities")
                    if b" ACK " not in response:
                        raise Failure("guest_event_capabilities_refused")
                return client

            budget.phase = "account_registration"
            for node in range(3):
                registrar = connect(node, "Registrar" + str(node))
                registrar.command(b"REGISTER " + session.ACCOUNT + b" * " + password,
                                  b"REGISTER SUCCESS ", "account registration", timeout=30)
                registrar.close()
                clients.remove(registrar)
            registrar = connect(2, "ObserverRegistrar")
            registrar.command(b"REGISTER " + session.OBSERVER_ACCOUNT + b" * " + password,
                              b"REGISTER SUCCESS ", "observer registration", timeout=30)
            registrar.close()
            clients.remove(registrar)
            budget.phase = "four_attachments"
            origin = connect(0, "IssuerOrigin", session.ACCOUNT)
            origin.join()
            local, portable = origin.tokens()
            if not re.fullmatch(rb"[0-9a-f]{32}", local) or len(portable) <= len(local):
                raise Failure("session_credentials_absent")
            near = connect(0, "IssuerNear", session.ACCOUNT)
            near.resume(local)
            middle = connect(1, "IssuerMiddle", session.ACCOUNT)
            middle.resume(portable)
            far = connect(2, "IssuerFar", session.ACCOUNT)
            far.resume(portable)
            attached = [origin, near, middle, far]
            observer = connect(2, "IssuerObserver", session.OBSERVER_ACCOUNT)
            observer.join()
            observer.tokens()
            observer.wait_nick(origin.nick)
            guests = [connect(i, "IssuerGuest" + str(i)) for i in range(3)]
            for guest in guests:
                guest.join()
            held_fds = {c: c.sock.fileno() for c in clients}
            held_tokens = {c: c.tokens()[0] for c in attached}
            if any(re.fullmatch(rb"[0-9a-f]{32}", token) is None or token != local
                   for token in held_tokens.values()):
                raise Failure("initial_four_attachment_token_mismatch")

            def host(client):
                start = len(client.seen)
                client.send(b"WHOIS " + client.nick)
                client.wait(lambda line: b" 318 " in line, start, "guest WHOIS terminal")
                rows = [line.split() for line in client.seen[start:] if b" 311 " in line]
                if len(rows) != 1 or len(rows[0]) < 6 or rows[0][3] != client.nick:
                    raise Failure("guest_profile_absent")
                return rows[0][5]

            hosts = {g: host(g) for g in guests}
            oracle = Oracle()
            retained = []

            def physical(marker):
                for i, client in enumerate(clients):
                    if client.sock.fileno() != held_fds[client]:
                        raise Failure("original_socket_replaced")
                    client.ping((marker + "-socket-" + str(i)).encode())
                for client, token in held_tokens.items():
                    if client.tokens()[0] != token:
                        raise Failure("retained_local_token_changed")
                if any(host(g) != expected for g, expected in hosts.items()):
                    raise Failure("retained_guest_presentation_changed")

            def participation(marker):
                everyone = attached + [observer] + guests
                for i, source in enumerate(attached):
                    oracle.event(source, everyone, everyone, session.ROOM, marker + "-channel-" + str(i))
                    oracle.event(source, everyone, attached, origin.nick, marker + "-dm-" + str(i))
                oracle.event(observer, everyone, attached + [observer], origin.nick, marker + "-independent-dm")
                for i, guest in enumerate(guests):
                    oracle.event(guest, everyone, everyone, session.ROOM, marker + "-issuer-" + str(i))
                physical(marker)
                oracle.cumulative(everyone)
                for needle, identity, body, starts, receivers in retained:
                    for client in receivers:
                        matches = [line for line in client.seen[starts[client]:] if needle in line]
                        if len(matches) != 1 or event_identity(matches[0]) != identity or matches[0].split(b" ", 1)[1] != body:
                            raise Failure("retained_prefix_lost_duplicated_or_changed")

            budget.phase = "baseline_events"
            participation("before-exec")
            for node, label in ((0, "A"), (1, "B")):
                budget.phase = "retained_prefix_" + label
                # Do not pump any of the four attachments until after exec.
                # Independent guests on C and this upgrade's target node both
                # witness acceptance before the sender's ordered PING barrier.
                needle = b"PRIVMSG " + session.ROOM + b" :held-before-" + label.encode() + b"-" + oracle.nonce
                starts = {c: len(c.seen) for c in attached}
                witness_starts = {g: len(g.seen) for g in (guests[2], guests[node])}
                observer.send(needle)
                witness = guests[2].wait(lambda line: needle in line, witness_starts[guests[2]], "accepted C pre-exec witness")
                target_witness = guests[node].wait(lambda line: needle in line, witness_starts[guests[node]], "accepted target-node pre-exec witness")
                identity = event_identity(witness)
                if event_identity(target_witness) != identity or target_witness.split(b" ", 1)[1] != witness.split(b" ", 1)[1]:
                    raise Failure("target_preexec_acceptance_identity_changed")
                observer.ping(b"held-prefix-sender-barrier-" + label.encode())
                retained.append((needle, identity, witness.split(b" ", 1)[1], starts, tuple(attached)))
                budget.phase = "actual_exec_" + label
                process, log = by_node[node]
                before = log.restored()
                pid = process.pid
                process.send_signal(signal.SIGUSR2)
                end = time.monotonic() + budget.remaining(45)
                while log.restored() == before:
                    budget.check()
                    if time.monotonic() >= end:
                        raise Failure("actual_exec_restore_deadline")
                    time.sleep(0.05)
                if process.pid != pid or process.poll() is not None:
                    raise Failure("exec_process_identity_changed")
                links()
                for client in attached:
                    client.wait(lambda line: needle in line, starts[client], "held pre-exec prefix")
                budget.phase = "post_exec_" + label
                participation("after-" + label)
                fresh = connect(node, "IssuerNext" + label)
                fresh.join()
                held_fds[fresh] = fresh.sock.fileno()
                hosts[fresh] = host(fresh)
                guests.append(fresh)
                oracle.event(fresh, attached + [observer] + guests, attached + [observer] + guests,
                             session.ROOM, "issuer-progress-" + label)
            budget.phase = "fifth_opposite_edge_resume"
            fifth = connect(2, "IssuerFifth", session.ACCOUNT)
            held_fds[fifth] = fifth.sock.fileno()
            fifth.resume(portable)
            if fifth.tokens()[0] != local:
                raise Failure("fifth_resume_token_changed")
            held_tokens[fifth] = fifth.tokens()[0]
            attached.append(fifth)
            participation("fifth-after-both")
            links()
            if digest(pinned) != artifact or digest(binary) != artifact:
                raise Failure("artifact_changed")
            print("PASS issuer session CLI: secured A-B-C; A then B same-PID exec; four original TLS attachments; fifth C resume; exact events and retained tokens/presentation")
        except Failure as exc:
            raise Failure(budget.phase + ":" + str(exc) + ";" + budget.daemon_summary()) from None
        except Exception as exc:
            # Only fixed exception *type*, never its potentially secret text.
            raise Failure(budget.phase + ":operation_" + type(exc).__name__ + ";" + budget.daemon_summary()) from None
        finally:
            for client in reversed(clients):
                try:
                    client.close()
                except OSError:
                    pass
            try:
                stop_groups(budget.processes)
            finally:
                for log in logs:
                    log.thread.join(timeout=3)
                for process in budget.processes:
                    if process.stdout:
                        process.stdout.close()


def event_identity(line):
    if not line.startswith(b"@"):
        raise Failure("accepted_identity_tags_absent")
    tags = dict(item.split(b"=", 1) for item in line[1:].split(b" ", 1)[0].split(b";") if b"=" in item)
    if not tags.get(b"msgid") or not tags.get(b"time"):
        raise Failure("accepted_identity_tags_absent")
    return tags[b"msgid"], tags[b"time"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--timeout", type=float, default=600)
    parser.add_argument("--scratch-dir", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "linux" or not 0 < args.timeout <= 1200:
        parser.error("Linux and timeout in (0,1200] required")
    try:
        run(args.binary.resolve(strict=True), args.timeout, args.scratch_dir.resolve(strict=True))
    except Exception as exc:
        reason = str(exc) if isinstance(exc, Failure) else "preflight_" + type(exc).__name__
        print("FAIL issuer session CLI: " + reason, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
