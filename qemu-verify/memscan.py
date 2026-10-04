#!/usr/bin/env python3
"""Scan a guest RAM dump for cpio/initrd signatures: memscan.py <dump>"""
import sys

CHUNK = 1 << 20


def find_all(path, needle):
    with open(path, "rb") as f:
        carry = b""
        off = 0
        while True:
            data = f.read(CHUNK)
            if not data:
                break
            buf = carry + data
            start = 0
            while True:
                i = buf.find(needle, start)
                if i < 0:
                    break
                print(f"{needle.decode(errors='replace')} at fileoff 0x{off - len(carry) + i:x}")
                start = i + 1
            carry = buf[-(len(needle) - 1):] if len(needle) > 1 else b""
            off += len(data)


def main():
    path = sys.argv[1]
    for needle in (b"070701", b"boot.wim", b"TRAILER!!!", b"MSWIM"):
        find_all(path, needle)


if __name__ == "__main__":
    main()
