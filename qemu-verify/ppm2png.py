#!/usr/bin/env python3
"""PPM P6 -> PNG converter (stdlib only): ppm2png.py <in.ppm> <out.png>"""
import struct
import sys
import zlib


def main():
    src, dst = sys.argv[1], sys.argv[2]
    with open(src, "rb") as f:
        magic = f.readline().strip()
        assert magic == b"P6", magic
        # skip comments
        line = f.readline()
        while line.startswith(b"#"):
            line = f.readline()
        w, h = map(int, line.split())
        maxval = int(f.readline().strip())
        assert maxval == 255
        px = f.read(w * h * 3)
    assert len(px) == w * h * 3, (len(px), w, h)
    raw = b"".join(b"\x00" + px[y * w * 3 : (y + 1) * w * 3] for y in range(h))
    comp = zlib.compress(raw, 6)

    def chunk(typ, data):
        c = struct.pack(">I", len(data)) + typ + data
        return c + struct.pack(">I", zlib.crc32(typ + data) & 0xFFFFFFFF)

    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", comp)
        + chunk(b"IEND", b"")
    )
    with open(dst, "wb") as f:
        f.write(png)
    print(f"{dst}: {w}x{h}")


if __name__ == "__main__":
    main()
