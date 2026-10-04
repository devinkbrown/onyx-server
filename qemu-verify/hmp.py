#!/usr/bin/env python3
"""Minimal HMP client: hmp.py <socket> <command...> -> prints output until prompt."""
import re
import socket
import sys

ANSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][0-9A-Z]|\x00")


def main():
    sock_path = sys.argv[1]
    cmd = " ".join(sys.argv[2:])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(25)
    s.connect(("127.0.0.1", int(sock_path)))
    buf = b""
    while not buf.endswith(b"(qemu) "):
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    s.sendall(cmd.encode() + b"\n")
    buf = b""
    while not buf.endswith(b"(qemu) "):
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
    buf = ANSI.sub(b"", buf)
    # drop echoed command line (first line) and trailing prompt
    lines = buf.split(b"\r\n")
    if lines and lines[0].strip() == cmd.encode():
        lines = lines[1:]
    while lines and lines[-1].strip() in (b"", b"(qemu)"):
        lines.pop()
    sys.stdout.write(b"\r\n".join(lines).decode(errors="replace") + "\n")


if __name__ == "__main__":
    main()
