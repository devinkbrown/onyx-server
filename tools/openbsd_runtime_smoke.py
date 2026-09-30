#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Keep real plain/TLS1.2/TLS1.3/WSS connections over native Helix.

Run against an isolated OpenBSD VM through externally configured SSH forwards:
base/base+1/base+2 -> IPv4 IRC/TLS/WSS, base+10/+11/+12 -> IPv6.
Never target production: this probe sends USR2 to the configured VM process.
"""
import argparse
import base64
import hashlib
import os
import re
import select
import shlex
import socket
import ssl
import struct
import subprocess
import time


class Client:
    def __init__(self, port, transport):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.sock.settimeout(1)
        self.ws = transport == "wss"
        self.wire = b""
        self.irc = b""
        self.fragment = None
        self.seen = []
        self.deadline = time.monotonic() + 15
        if transport != "plain":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # isolated self-signed fixture
            if transport == "tls12":
                ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            elif transport == "tls13":
                ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            self.sock = ctx.wrap_socket(self.sock, server_hostname="openbsd.native.test")
        if self.ws:
            key = base64.b64encode(os.urandom(16)).decode()
            request = ("GET / HTTP/1.1\r\nHost: openbsd.native.test\r\n"
                       "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                       f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
                       "Sec-WebSocket-Protocol: text.ircv3.net\r\n\r\n")
            self.sock.sendall(request.encode())
            response = b""
            deadline = time.monotonic() + 10
            while b"\r\n\r\n" not in response:
                if time.monotonic() >= deadline:
                    raise TimeoutError("WSS HTTP upgrade timeout")
                response += self.sock.recv(65536)
            header, self.wire = response.split(b"\r\n\r\n", 1)
            accept = base64.b64encode(hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
            if b" 101 " not in header or accept not in header:
                raise RuntimeError("WSS upgrade rejected")
            headers = dict(line.split(b":", 1) for line in header.split(b"\r\n")[1:] if b":" in line)
            negotiated = {key.lower(): value.strip() for key, value in headers.items()}
            if negotiated.get(b"sec-websocket-protocol") != b"text.ircv3.net":
                raise RuntimeError("WSS text subprotocol not negotiated")

    def frame(self, opcode, payload):
        mask = os.urandom(4)
        length = len(payload)
        if length < 126:
            header = bytes((0x80 | opcode, 0x80 | length))
        elif length <= 65535:
            header = bytes((0x80 | opcode, 0xfe)) + struct.pack("!H", length)
        else:
            raise ValueError("fixture frame too large")
        self.sock.sendall(header + mask + bytes(v ^ mask[i % 4] for i, v in enumerate(payload)))

    def send(self, payload):
        if self.ws:
            for line in payload.split(b"\r\n"):
                if line:
                    self.frame(1, line)
        else:
            self.sock.sendall(payload)

    def read_wire(self):
        if time.monotonic() >= self.deadline:
            raise TimeoutError("read deadline expired")
        chunk = self.sock.recv(65536)
        if not chunk:
            raise ConnectionError("original physical connection closed")
        return chunk

    def recv(self):
        if not self.ws:
            result = self.sock.recv(65536)
            if not result:
                raise ConnectionError("original physical connection closed")
            return result
        while True:
            if len(self.wire) >= 2:
                opcode = self.wire[0] & 15
                length = self.wire[1] & 127
                offset = 2
                if length == 126:
                    if len(self.wire) < 4:
                        self.wire += self.read_wire()
                        continue
                    length = struct.unpack("!H", self.wire[2:4])[0]
                    offset = 4
                elif length == 127:
                    if len(self.wire) < 10:
                        self.wire += self.read_wire()
                        continue
                    length = struct.unpack("!Q", self.wire[2:10])[0]
                    offset = 10
                if self.wire[1] & 128:
                    raise RuntimeError("masked server frame")
                if length > 1 << 20:
                    raise ValueError("oversize server frame")
                if len(self.wire) >= offset + length:
                    self.wire_frame_final = bool(self.wire[0] & 128)
                    payload = self.wire[offset:offset + length]
                    self.wire = self.wire[offset + length:]
                    final = bool(self.wire_frame_final)
                    if opcode == 1:
                        if self.fragment is not None:
                            raise RuntimeError("nested WSS text fragment")
                        if not final:
                            self.fragment = payload
                            continue
                        payload.decode("utf-8")
                        return payload + b"\r\n"
                    if opcode == 0:
                        if self.fragment is None:
                            raise RuntimeError("orphan WSS continuation")
                        self.fragment += payload
                        if len(self.fragment) > 1 << 20:
                            raise RuntimeError("oversize fragmented WSS message")
                        if not final:
                            continue
                        payload = self.fragment
                        self.fragment = None
                        payload.decode("utf-8")
                        return payload + b"\r\n"
                    if opcode == 2:
                        raise RuntimeError("binary frame on WSS text subprotocol")
                    if opcode == 9:
                        self.frame(10, payload)
                    elif opcode == 8:
                        raise ConnectionError("WSS connection closed")
                    continue
            chunk = self.read_wire()
            self.wire += chunk

    def collect(self):
        self.irc += self.recv()
        lines = self.irc.split(b"\r\n")
        self.irc = lines.pop()
        self.seen.extend(lines)
        return lines

    def until(self, token):
        self.deadline = time.monotonic() + 15
        while True:
            if time.monotonic() >= self.deadline:
                raise TimeoutError("expected IRC response absent")
            try:
                lines = self.collect()
            except TimeoutError:
                continue
            if any(token in line for line in lines):
                return lines


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity", required=True)
    parser.add_argument("--known-hosts", required=True)
    parser.add_argument("--ssh-port", type=int, required=True)
    parser.add_argument("--remote-dir", required=True)
    parser.add_argument("--base-port", type=int, required=True)
    parser.add_argument("--remote-base-port", type=int, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--clients", type=int, default=40)
    parser.add_argument("--rounds", type=int, default=2)
    parser.add_argument("--transport", choices=("all", "plain", "tls12", "tls13", "wss"), default="all")
    parser.add_argument("--reject-missing-key", action="store_true",
                        help="temporarily hide this VM fixture's node key and verify precommit refusal")
    parser.add_argument("--daemon-log", default="daemon-history-sync.log")
    args = parser.parse_args()
    if args.clients < 8 or args.rounds < 1:
        parser.error("at least eight clients and one upgrade required")
    if re.fullmatch(r"[0-9a-f]{64}", args.expected_sha256) is None:
        parser.error("expected SHA-256 must be 64 lowercase hexadecimal characters")
    if not args.remote_dir.startswith("/tmp/onyx-") or any(
            part in (".", "..") for part in args.remote_dir.split("/")):
        parser.error("remote directory must be an isolated /tmp/onyx- fixture")
    if not 1024 <= args.base_port <= 65523 or not 1024 <= args.remote_base_port <= 65533:
        parser.error("fixture ports must be unprivileged and leave room for all forwards")
    ssh = ["ssh", "-p", str(args.ssh_port), "-i", args.identity,
           "-o", "UserKnownHostsFile=" + args.known_hosts, "root@127.0.0.1"]
    def remote(command):
        return subprocess.check_output(ssh + [command], text=True, timeout=10).strip()
    executable = args.remote_dir.rstrip("/") + "/onyx-server"
    config = args.remote_dir.rstrip("/") + "/config.toml"
    def check_image():
        if remote("sha256 -q " + shlex.quote(executable)) != args.expected_sha256:
            raise RuntimeError("fixture daemon artifact SHA-256 mismatch")
    check_image()
    # Exact command path + final config argument, including private successor argv.
    pattern = "^" + re.escape(executable) + " .*" + re.escape(config) + "$"
    def pids():
        result = subprocess.run(ssh + ["pgrep -f " + shlex.quote(pattern)],
                                text=True, capture_output=True, timeout=10)
        if result.returncode not in (0, 1):
            raise RuntimeError("remote process query failed")
        values = result.stdout.split()
        if any(not value.isdigit() for value in values):
            raise RuntimeError("invalid process query")
        return set(values)
    if len(pids()) != 1:
        raise RuntimeError("fixture requires exactly one owned daemon before connecting")
    print("Pinned native daemon SHA256=" + args.expected_sha256, flush=True)
    forwards = []
    for offset, destination in ((0, "127.0.0.1"), (1, "127.0.0.1"), (2, "127.0.0.1"),
                                (10, "[::1]"), (11, "[::1]"), (12, "[::1]")):
        forwards += ["-L", f"127.0.0.1:{args.base_port + offset}:{destination}:{args.remote_base_port + offset % 10}"]
    tunnel = subprocess.Popen(ssh[:-1] + ["-o", "ExitOnForwardFailure=yes", "-N"] + forwards + ssh[-1:],
                              stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    time.sleep(.5)
    if tunnel.poll() is not None:
        raise RuntimeError("fixture SSH forwarding failed")
    clients = []
    transports = ((0, "plain"), (10, "plain"), (1, "tls13"), (11, "tls13"),
                  (1, "tls12"), (11, "tls12"), (2, "wss"), (12, "wss"))
    if args.transport != "all":
        transports = tuple(pair for pair in transports if pair[1] == args.transport)
    payloads = []
    try:
        for index in range(args.clients):
            offset, transport = transports[index % len(transports)]
            client = Client(args.base_port + offset, transport)
            clients.append(client)
            client.send(f"NICK native{index}\r\nUSER native 0 * :native fixture\r\n".encode())
            client.until(b" 376 ")
            client.send(b"JOIN #nativecontinuity\r\n")
            client.until(b" 366 ")
        print(f"PASS {len(clients)} original IPv4/IPv6 {args.transport} transport attachments", flush=True)
        if args.reject_missing_key:
            initial = pids()
            if len(initial) != 1:
                raise RuntimeError("refusal fixture requires one predecessor")
            old = initial.pop()
            key = args.remote_dir.rstrip("/") + "/onyx-server-node.key"
            backup = key + ".smoke-hidden-" + os.urandom(8).hex()
            log = args.remote_dir.rstrip("/") + "/" + args.daemon_log
            if "/" in args.daemon_log or args.daemon_log in (".", ".."):
                raise RuntimeError("daemon log must be a fixture basename")
            offset = int(remote("wc -c < " + shlex.quote(log)))
            remote("mv " + shlex.quote(key) + " " + shlex.quote(backup))
            try:
                remote("kill -USR2 " + old)
                deadline = time.monotonic() + 40
                while time.monotonic() < deadline:
                    # Inspect only the failure code, never the identity file.
                    command = ("tail -c +" + str(offset + 1) + " " + shlex.quote(log) +
                               " | grep -F 'OCG2 requires existing node key' >/dev/null")
                    result = subprocess.run(ssh + [command], timeout=10)
                    if result.returncode == 0 and pids() == {old}:
                        break
                    if result.returncode not in (0, 1):
                        raise RuntimeError("refusal log query failed")
                    time.sleep(.3)
                else:
                    raise TimeoutError("missing identity candidate was not rejected")
                for index, client in enumerate(clients):
                    tag = f"refusal-survival-{index}".encode()
                    client.send(b"PING :" + tag + b"\r\n")
                    client.until(tag)
                print(f"PASS rejected candidate: same predecessor and {len(clients)} original sockets alive", flush=True)
            finally:
                remote("mv " + shlex.quote(backup) + " " + shlex.quote(key))
        for generation in range(args.rounds):
            check_image()
            initial = pids()
            if len(initial) != 1:
                raise RuntimeError("fixture requires one initial daemon")
            old = initial.pop()
            remote("kill -USR2 " + old)
            deadline = time.monotonic() + 40
            while time.monotonic() < deadline:
                current = pids()
                if len(current) == 1 and old not in current:
                    new = current.pop()
                    command = remote("ps -ww -p " + new + " -o args=")
                    if "--helix-native-successor-v1" not in command:
                        raise RuntimeError("survivor is not an executed native successor")
                    break
                time.sleep(.3)
            else:
                raise TimeoutError("successor did not commit")
            time.sleep(1)
            check_image()
            for index, client in enumerate(clients):
                tag = f"continuity-{generation}-{index}".encode()
                client.send(b"PING :" + tag + b"\r\n")
                client.until(tag)
            payload = f"exact-message-{generation}".encode()
            clients[0].send(b"PRIVMSG #nativecontinuity :" + payload + b"\r\n")
            for client in clients[1:]:
                client.until(payload)
            payloads.append(payload)
            quiet_end = time.monotonic() + 1
            for client in clients:
                client.sock.settimeout(.02)
                client.deadline = quiet_end
            while time.monotonic() < quiet_end:
                ready, _, _ = select.select([client.sock for client in clients], [], [], .02)
                for client in clients:
                    pending = isinstance(client.sock, ssl.SSLSocket) and client.sock.pending()
                    if client.sock in ready or pending or client.wire:
                        try:
                            client.collect()
                        except TimeoutError:
                            pass
            # Final sweep closes the last traversal gap, including decrypted TLS
            # bytes that need not appear as kernel socket readiness.
            for client in clients:
                client.deadline = time.monotonic() + .1
                try:
                    while True:
                        ready, _, _ = select.select([client.sock], [], [], 0)
                        pending = isinstance(client.sock, ssl.SSLSocket) and client.sock.pending()
                        if not ready and not pending and not client.wire:
                            break
                        client.collect()
                except TimeoutError:
                    pass
            for client in clients[1:]:
                for observed in payloads:
                    count = sum(b" PRIVMSG #nativecontinuity :" + observed == line[line.find(b" PRIVMSG "):]
                                for line in client.seen if b" PRIVMSG " in line)
                    if count != 1:
                        raise RuntimeError(f"expected one matching PRIVMSG, received {count}")
            for client in clients:
                client.sock.settimeout(1)
            print(f"PASS upgrade {generation + 1}: PID {old}->{new}; all original sockets retained; "
                  f"{len(clients) - 1} single deliveries observed through the drain window", flush=True)
    finally:
        for client in clients:
            client.sock.close()
        tunnel.terminate()
        try:
            tunnel.wait(timeout=5)
        except subprocess.TimeoutExpired:
            tunnel.kill()
            tunnel.wait(timeout=5)


if __name__ == "__main__":
    main()
