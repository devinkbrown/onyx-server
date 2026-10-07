#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Fresh-boot runtime smoke test.

Complements tools/upgrade_smoke.py (which exercises the SIGUSR2 hot upgrade).
This one proves a COLD boot from a config file serves IRC end-to-end:

  * the daemon boots from a minimal temp config (TCP listener, ephemeral port),
  * a plain TCP client registers (NICK/USER) and gets RPL_WELCOME (001),
  * PING gets a PONG from the same image,
  * three clients prove direct and channel delivery, bounded IRC lines,
    NAMES, PART, and rejoin,
  * Windows advertises the full IRCv3 CAP and ISUPPORT surface,
  * Windows keeps the first client responsive through 140 concurrent peers,
  * QUIT tears the clients down cleanly,
  * the daemon is stopped cleanly.

A hard wall-clock deadline guarantees it never hangs CI: any check that blocks
past the deadline fails loudly with a non-zero exit and the daemon log dumped.

Usage: python3 tools/runtime_smoke.py [path-to-onyx-server-binary]
Exit code 0 = PASS.
"""
import argparse
from contextlib import ExitStack
import os
import socket
import subprocess
import sys
import tempfile
import time
import traceback

HOST = "127.0.0.1"
NICK = "smoke"
STATUS_PREFIXES = "~&@%+*!."
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_BIN = os.path.join(ROOT, "zig-out", "bin", "onyx-server" + (".exe" if os.name == "nt" else ""))

# Hard ceiling on the whole run so a wedged daemon never hangs CI.
DEADLINE_S = 90.0
_START = time.monotonic()


def remaining():
    """Seconds left before the global deadline."""
    return max(0.0, DEADLINE_S - (time.monotonic() - _START))


def recv_to_eof(sock, timeout=4.0):
    """Drain optional QUIT text and require the daemon to close the socket."""
    timeout = min(timeout, remaining())
    end = time.monotonic() + timeout
    buf = b""
    while time.monotonic() < end:
        wait = end - time.monotonic()
        if wait <= 0:
            break
        sock.settimeout(wait)
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        except OSError as exc:
            received = buf.decode("utf-8", "replace")
            raise ConnectionError(f"QUIT socket read failed after {received!r}: {exc}") from exc
        if not chunk:
            return buf.decode("utf-8", "replace")
        buf += chunk
    raise TimeoutError(f"daemon did not close client after QUIT; received {buf.decode('utf-8', 'replace')!r}")


class IrcClient:
    """Read whole IRC lines while retaining bytes from coalesced TCP packets."""

    def __init__(self, sock):
        self.sock = sock
        self.pending = b""

    def send(self, line):
        self.sock.sendall((line + "\r\n").encode())

    def line(self, timeout):
        end = time.monotonic() + min(timeout, remaining())
        while b"\n" not in self.pending:
            wait = end - time.monotonic()
            if wait <= 0:
                raise TimeoutError("timed out waiting for IRC line")
            self.sock.settimeout(wait)
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout as exc:
                raise TimeoutError("timed out waiting for IRC line") from exc
            if not chunk:
                raise ConnectionError(f"IRC socket closed with pending bytes {self.pending!r}")
            self.pending += chunk
        raw, self.pending = self.pending.split(b"\n", 1)
        return raw.rstrip(b"\r").decode("utf-8", "replace")

    def until(self, marker, timeout=4.0, forbidden=None):
        end = time.monotonic() + min(timeout, remaining())
        seen = []
        while time.monotonic() < end:
            try:
                line = self.line(end - time.monotonic())
            except TimeoutError as exc:
                raise TimeoutError(f"expected {marker!r}; received {seen!r}") from exc
            seen.append(line)
            if forbidden and forbidden in line:
                raise AssertionError(f"unexpected {forbidden!r} in {line!r}")
            if marker in line:
                return line
        raise TimeoutError(f"expected {marker!r}; received {seen!r}")

    def barrier_without(self, forbidden, token):
        """A PONG proves prior fanout completed without delivering forbidden text."""
        self.send(f"PING :{token}")
        pong = self.until(f":{token}", forbidden=forbidden)
        if " PONG " not in pong:
            raise AssertionError(f"barrier did not receive PONG: {pong!r}")
        if forbidden.encode() in self.pending:
            raise AssertionError(f"unexpected {forbidden!r} after barrier in {self.pending!r}")
        return pong


def connect(port, process=None):
    deadline = time.monotonic() + min(30 if process else 4, remaining())
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise RuntimeError(f"daemon exited before IRC listener opened ({process.returncode})")
        try:
            return socket.create_connection((HOST, port), timeout=min(1, remaining()))
        except OSError:
            if process is None:
                raise
            time.sleep(0.05)
    raise TimeoutError("IRC listener did not open before the smoke deadline")


def cleanup(proc):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)


def dump_log(log):
    try:
        with open(log, encoding="utf-8", errors="replace") as f:
            print("--- daemon log ---")
            print(f.read())
    except (OSError, TypeError):
        pass


def fail(msg, proc=None, log=None):
    print(f"FAIL: {msg}")
    cleanup(proc)
    dump_log(log)
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Cold-boot Onyx Server and exercise IRC over loopback")
    parser.add_argument("binary", nargs="?", default=DEFAULT_BIN, help="path to the onyx-server binary")
    args = parser.parse_args()
    binary = args.binary
    if os.name == "nt" and not os.path.exists(binary) and os.path.exists(binary + ".exe"):
        binary += ".exe"
    if not os.path.exists(binary):
        fail(f"binary not found: {binary} (run `zig build` first)")
    binary = os.path.abspath(binary)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as held:
        held.bind((HOST, 0))
        port = held.getsockname()[1]

    # Minimal config: a single plaintext TCP listener on an ephemeral port. Bind
    # to loopback only so the smoke never exposes a port off-box. Mirrors the key
    # structure documented in etc/onyx-server.reference.toml ([node].id + [listen]).
    with tempfile.TemporaryDirectory(prefix="onyx-runtime-") as run_dir:
        conf = os.path.join(run_dir, "runtime.toml")
        log = os.path.join(run_dir, "runtime.log")
        with open(conf, "w", encoding="utf-8") as f:
            f.write(
                "[node]\nid = 1\n"
                f"[listen]\nhost = \"{HOST}\"\nirc = {port}\n"
            )

        proc = None
        stage = "start daemon"
        try:
            with open(log, "w", encoding="utf-8") as log_file:
                proc = subprocess.Popen([binary, conf], cwd=run_dir, stdout=log_file, stderr=subprocess.STDOUT)
            stage = "register first client"
            with connect(port, proc) as c_sock:
                print(f"PASS: daemon booted from config (PID {proc.pid})")
                c = IrcClient(c_sock)
                if os.name == "nt":
                    stage = "full Windows CAP policy"
                    c.send("CAP LS 302")
                    advertised = []
                    while True:
                        line = c.until(" CAP * LS ")
                        advertised.extend(line.split(" :", 1)[-1].split())
                        if " CAP * LS :" in line:
                            break
                    for required in ("server-time", "draft/chathistory", "message-tags"):
                        if required not in advertised:
                            raise AssertionError(f"full Windows server omitted {required}: {advertised!r}")
                    c.send("CAP END")
                    print("PASS: native Windows advertises full IRCv3 CAP extensions")
                    stage = "register first client"
                c.send(f"NICK {NICK}")
                c.send(f"USER {NICK} 0 * :{NICK}")
                c.until(" 001 ")
                if os.name == "nt":
                    isupport = c.until(" 005 ")
                    for required in ("CHANMODES=", "MONITOR=", "CHATHISTORY="):
                        if required not in isupport:
                            raise AssertionError(f"full Windows server omitted {required}: {isupport!r}")
                    print("PASS: native Windows advertises full IRC ISUPPORT")
                print("PASS: first client registered (RPL_WELCOME 001)")

                stage = "PING/PONG on first client"
                c.send("PING :smoke-runtime-ping")
                pong = c.until(":smoke-runtime-ping")
                if " PONG " not in pong:
                    raise AssertionError(f"PING not answered with PONG: {pong!r}")
                print("PASS: PING answered with matching PONG")

                stage = "register second client"
                with connect(port) as peer_sock:
                    peer = IrcClient(peer_sock)
                    peer_nick = NICK + "2"
                    peer.send(f"NICK {peer_nick}")
                    peer.send(f"USER {peer_nick} 0 * :{peer_nick}")
                    peer.until(" 001 ")

                    stage = "register third client"
                    with connect(port) as outsider_sock:
                        outsider = IrcClient(outsider_sock)
                        outsider_nick = NICK + "3"
                        outsider.send(f"NICK {outsider_nick}")
                        outsider.send(f"USER {outsider_nick} 0 * :{outsider_nick}")
                        outsider.until(" 001 ")
                        print("PASS: three live clients registered")

                        channel = "#smoke-runtime"
                        stage = "two clients JOIN channel"
                        c.send(f"JOIN {channel}")
                        c.until(f" JOIN {channel}")
                        c.until(" 366 ")
                        peer.send(f"JOIN {channel}")
                        peer.until(f" JOIN {channel}")
                        peer.until(" 366 ")
                        joined = c.until(f" JOIN {channel}")
                        if not joined.startswith(f":{peer_nick}!"):
                            raise AssertionError(f"first client missed peer JOIN: {joined!r}")
                        print("PASS: JOIN fanout reached both members")

                        stage = "direct nick PRIVMSG"
                        direct = "runtime-direct-delivery"
                        c.send(f"PRIVMSG {peer_nick} :{direct}")
                        delivered = peer.until(direct)
                        if f"PRIVMSG {peer_nick} :{direct}" not in delivered:
                            raise AssertionError(f"nick message malformed: {delivered!r}")
                        outsider.barrier_without(direct, "smoke-third-direct-barrier")
                        c.barrier_without(direct, "smoke-first-direct-barrier")
                        wire_text = "x" * (510 - len(f"PRIVMSG {peer_nick} :".encode()))
                        c.send(f"PRIVMSG {peer_nick} :{wire_text}")
                        delivered = peer.until("x" * 20)
                        if len(delivered.encode()) + 2 != 512 or not delivered.endswith("x" * 20):
                            raise AssertionError(f"direct message did not fill the IRC wire limit: {len(delivered.encode()) + 2}")
                        print("PASS: nick PRIVMSG reached only its target")

                        stage = "channel outsider rejection"
                        denied = "runtime-outsider-denied"
                        outsider.send(f"PRIVMSG {channel} :{denied}")
                        refusal = outsider.until(" 404 ")
                        if channel not in refusal:
                            raise AssertionError(f"outsider refusal lacks channel: {refusal!r}")
                        c.barrier_without(denied, "smoke-first-outsider-barrier")
                        peer.barrier_without(denied, "smoke-second-outsider-barrier")
                        print("PASS: outsider channel send was rejected")

                        stage = "channel PRIVMSG delivery"
                        message = "runtime-channel-delivery"
                        c.send(f"PRIVMSG {channel} :{message}")
                        delivered = peer.until(message)
                        if f"PRIVMSG {channel} :{message}" not in delivered:
                            raise AssertionError(f"channel message malformed: {delivered!r}")
                        wire_text = "y" * (510 - len(f"PRIVMSG {channel} :".encode()))
                        c.send(f"PRIVMSG {channel} :{wire_text}")
                        delivered = peer.until("y" * 20)
                        if len(delivered.encode()) + 2 != 512 or not delivered.endswith("y" * 20):
                            raise AssertionError(f"channel message did not fill the IRC wire limit: {len(delivered.encode()) + 2}")
                        outsider.barrier_without(message, "smoke-third-channel-barrier")
                        print("PASS: channel PRIVMSG reached member, not outsider")

                        stage = "explicit NAMES"
                        peer.send(f"NAMES {channel}")
                        names = peer.until(" 353 ")
                        peer.until(" 366 ")
                        roster = {name.lstrip(STATUS_PREFIXES).lower() for name in names.rsplit(" :", 1)[-1].split()}
                        if roster != {NICK, peer_nick}:
                            raise AssertionError(f"wrong NAMES roster: {names!r}")
                        print("PASS: explicit NAMES reported current channel members")

                        stage = "PART fanout"
                        peer.send(f"PART {channel} :leaving")
                        part_self = peer.until(f" PART {channel}")
                        part_other = c.until(f" PART {channel}")
                        if not part_self.startswith(f":{peer_nick}!") or not part_other.startswith(f":{peer_nick}!"):
                            raise AssertionError(f"wrong PART fanout: {part_self!r}, {part_other!r}")
                        c.send(f"NAMES {channel}")
                        names = c.until(" 353 ")
                        c.until(" 366 ")
                        roster = {name.lstrip(STATUS_PREFIXES).lower() for name in names.rsplit(" :", 1)[-1].split()}
                        if roster != {NICK}:
                            raise AssertionError(f"PART left stale NAMES member: {names!r}")
                        denied = "runtime-after-part-denied"
                        peer.send(f"PRIVMSG {channel} :{denied}")
                        peer.until(" 404 ")
                        c.barrier_without(denied, "smoke-first-part-barrier")
                        print("PASS: PART removed only the departing member")

                        stage = "rejoin and channel delivery"
                        peer.send(f"JOIN {channel}")
                        peer.until(f" JOIN {channel}")
                        peer.until(" 366 ")
                        c.until(f" JOIN {channel}")
                        c.send(f"PRIVMSG {channel} :runtime-after-rejoin")
                        peer.until("PRIVMSG #smoke-runtime :runtime-after-rejoin")
                        print("PASS: departed client rejoined and received channel message")

                        stage = "NICK change fanout"
                        peer.send("NICK :")
                        peer.until(" 431 ")
                        c.barrier_without(" NICK :*", "smoke-empty-nick-barrier")
                        print("PASS: empty NICK was rejected without changing channel identity")

                        changed_nick = peer_nick + "new"
                        peer.send(f"NICK {changed_nick}")
                        nick_self = peer.until(f" NICK :{changed_nick}")
                        nick_other = c.until(f" NICK :{changed_nick}")
                        if not nick_self.startswith(f":{peer_nick}!") or not nick_other.startswith(f":{peer_nick}!"):
                            raise AssertionError(f"wrong NICK fanout: {nick_self!r}, {nick_other!r}")
                        outsider.barrier_without(f" NICK :{changed_nick}", "smoke-third-nick-barrier")
                        print("PASS: NICK change reached changer and shared peer only")

                        stage = "QUIT second client"
                        peer.send("QUIT :bye")
                        quit_other = c.until(" QUIT :bye")
                        if not quit_other.startswith(f":{changed_nick}!"):
                            raise AssertionError(f"wrong QUIT fanout: {quit_other!r}")
                        outsider.barrier_without(" QUIT :bye", "smoke-third-quit-barrier")
                        recv_to_eof(peer_sock, timeout=2.0)
                        print("PASS: QUIT reached shared peer before departing socket EOF")

                        stage = "QUIT third client"
                        outsider.send("QUIT :bye")
                        recv_to_eof(outsider_sock, timeout=2.0)

                stage = "abrupt disconnect fanout"
                with connect(port) as abrupt_sock:
                    abrupt = IrcClient(abrupt_sock)
                    abrupt.send("NICK sudden")
                    abrupt.send("USER sudden 0 * :sudden")
                    abrupt.until(" 001 ")
                    abrupt.send(f"JOIN {channel}")
                    abrupt.until(" 366 ")
                    c.until(f" JOIN {channel}")
                quit_other = c.until(" QUIT :")
                if not quit_other.startswith(":sudden!"):
                    raise AssertionError(f"abrupt disconnect lacked QUIT fanout: {quit_other!r}")
                print("PASS: abrupt disconnect emitted QUIT to shared peer")

                if os.name == "nt":
                    stage = "Windows multiline overlong concat refusal"
                    with connect(port) as multiline_sock:
                        multiline = IrcClient(multiline_sock)
                        multiline.send("CAP REQ :draft/multiline standard-replies")
                        multiline.until(" CAP * ACK :")
                        multiline.send("CAP END")
                        multiline.send("NICK multiline")
                        multiline.send("USER multiline 0 * :multiline")
                        multiline.until(" 001 ")
                        multiline.send(f"JOIN {channel}")
                        multiline.until(" 366 ")
                        c.until(f" JOIN {channel}")
                        multiline.send(f"BATCH +z draft/multiline {channel}")
                        multiline.send(f"@batch=z PRIVMSG {channel} :{'a' * 300}")
                        multiline.send(f"@batch=z;draft/multiline-concat PRIVMSG {channel} :{'b' * 300}")
                        multiline.send("BATCH -z")
                        multiline.until("FAIL BATCH MULTILINE_INVALID")
                        c.barrier_without("a" * 20, "smoke-multiline-first-barrier")
                        c.barrier_without("b" * 20, "smoke-multiline-second-barrier")
                        multiline.send("QUIT :bye")
                        departed = c.until(" QUIT :bye")
                        if not departed.startswith(":multiline!"):
                            raise AssertionError(f"wrong multiline-client QUIT fanout: {departed!r}")
                        recv_to_eof(multiline_sock, timeout=2.0)
                    print("PASS: oversized multiline concat was refused before delivery")

                stage = "large NAMES roster"
                roster_channel = "#smoke-roster"
                c.send(f"JOIN {roster_channel}")
                c.until(" 366 ")
                expected_roster = {NICK}
                with ExitStack() as stack:
                    for i in range(40):
                        stage = f"large NAMES roster member {i}"
                        sock = stack.enter_context(connect(port))
                        member = IrcClient(sock)
                        nick = f"roster{i:02d}" + "x" * 50
                        expected_roster.add(nick)
                        member.send(f"NICK {nick}")
                        member.send(f"USER roster{i:02d} 0 * :roster")
                        member.until(" 001 ")
                        member.send(f"JOIN {roster_channel}")
                        member.until(" 366 ")
                    c.send(f"NAMES {roster_channel}")
                    roster = set()
                    names_lines = 0
                    while True:
                        line = c.line(min(10.0, remaining()))
                        if " 366 " in line and roster_channel in line:
                            break
                        if " 353 " not in line or roster_channel not in line:
                            continue
                        if len(line.encode("utf-8")) + 2 > 512:
                            raise AssertionError(f"oversized NAMES line: {line!r}")
                        names_lines += 1
                        roster.update(name.lstrip(STATUS_PREFIXES) for name in line.rsplit(" :", 1)[-1].split())
                    if names_lines < 2 or roster != expected_roster:
                        raise AssertionError(f"incomplete NAMES roster: {names_lines} lines, {len(roster)} nicks")
                    c.send(f"PART {roster_channel} :done")
                    c.until(f" PART {roster_channel}")
                print("PASS: large NAMES roster arrived in bounded complete lines")

                stage = "first client survives roster disconnect storm"
                c.send("PING :post-roster-disconnect")
                pong = c.until(" PONG ")
                if not pong.endswith(":post-roster-disconnect"):
                    raise AssertionError(f"wrong PONG after roster disconnect storm: {pong!r}")
                print("PASS: first client stayed responsive after 40 peers disconnected")

                if os.name == "nt":
                    stage = "register 140 concurrent Windows clients"
                    with ExitStack() as stack:
                        peers = []
                        for i in range(140):
                            stage = f"register concurrent Windows client {i + 1}/140"
                            sock = stack.enter_context(connect(port))
                            member = IrcClient(sock)
                            peers.append((sock, member))
                            nick = f"concurrent{i:03d}"
                            member.send(f"NICK {nick}")
                            member.send(f"USER {nick} 0 * :{nick}")
                            member.until(" 001 ")
                        stage = "first client responsive with 140 Windows peers"
                        c.send("PING :with-140-peers")
                        pong = c.until(":with-140-peers")
                        if " PONG " not in pong:
                            raise AssertionError(f"wrong PONG with 140 peers: {pong!r}")
                        print("PASS: 140 concurrent Windows peers registered")
                        for i, (sock, member) in enumerate(peers):
                            stage = f"disconnect concurrent Windows client {i + 1}/140"
                            member.send("QUIT :bye")
                            recv_to_eof(sock, timeout=2.0)

                    stage = "first client survives 140 Windows peer disconnects"
                    c.send("PING :post-140-disconnect")
                    pong = c.until(":post-140-disconnect")
                    if " PONG " not in pong:
                        raise AssertionError(f"wrong PONG after 140 peer disconnects: {pong!r}")
                    print("PASS: first client stayed responsive after 140 peers disconnected")

                stage = "QUIT first client"
                c.send("QUIT :bye")
                recv_to_eof(c_sock, timeout=2.0)
                print("PASS: all three clients reached EOF after QUIT")

            if proc.poll() is not None:
                fail("daemon died after serving the clients (should still be running)", proc, log)
        except Exception as exc:
            print(f"FAIL during {stage}: {type(exc).__name__}: {exc}")
            traceback.print_exc(file=sys.stdout)
            exit_before_cleanup = proc.poll() if proc else None
            cleanup(proc)
            print(f"daemon exit code before cleanup: {exit_before_cleanup}; after cleanup: {proc.poll() if proc else None}")
            dump_log(log)
            return 1
        finally:
            cleanup(proc)

    print("\nALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
