#!/usr/bin/env python3
"""Build a newc cpio archive: mkcpio.py <out.cpio> <arcname>=<path> ..."""
import sys


def pad4(n):
    return (4 - (n % 4)) % 4


def main():
    out = sys.argv[1]
    ino = 1
    with open(out, "wb") as f:
        for spec in sys.argv[2:]:
            arcname, path = spec.split("=", 1)
            with open(path, "rb") as pf:
                data = pf.read()
            name = arcname.encode() + b"\x00"
            f.write(b"070701")
            for v in (ino, 0o100644, 0, 0, 1, 0, len(data), 0, 0,
                      0, 0, len(name), 0):
                f.write(f"{v:08x}".encode())
            f.write(name)
            f.write(b"\x00" * pad4(110 + len(name)))
            f.write(data)
            f.write(b"\x00" * pad4(len(data)))
            ino += 1
        name = b"TRAILER!!!\x00"
        f.write(b"070701")
        for v in (ino, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(name), 0):
            f.write(f"{v:08x}".encode())
        f.write(name)
        f.write(b"\x00" * pad4(110 + len(name)))
        # pad archive to 512
        pos = f.tell()
        f.write(b"\x00" * ((512 - (pos % 512)) % 512))
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
