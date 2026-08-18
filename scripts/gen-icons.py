#!/usr/bin/env python3
"""Generate simple Easy Connection PNG icons (no extra Python deps)."""
from __future__ import annotations

import struct
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "apps" / "desktop" / "src-tauri" / "icons"


def png(width: int, height: int, rgba_rows: list[bytes]) -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(tag + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", crc)

    raw = b"".join(b"\x00" + row for row in rgba_rows)
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def icon(size: int) -> bytes:
    rows = []
    for y in range(size):
        row = bytearray()
        for x in range(size):
            # Rounded-square teal mark with a lighter "E" bar suggestion.
            nx = (x + 0.5) / size
            ny = (y + 0.5) / size
            inset = 0.08
            inside = inset < nx < 1 - inset and inset < ny < 1 - inset
            if not inside:
                row.extend(b"\x00\x00\x00\x00")
                continue
            bar = (
                (0.28 < nx < 0.42 and 0.25 < ny < 0.75)
                or (0.28 < nx < 0.72 and 0.25 < ny < 0.36)
                or (0.28 < nx < 0.64 and 0.45 < ny < 0.55)
                or (0.28 < nx < 0.72 and 0.64 < ny < 0.75)
            )
            if bar:
                row.extend(bytes((240, 252, 255, 255)))
            else:
                row.extend(bytes((14, 116, 144, 255)))
        rows.append(bytes(row))
    return png(size, size, rows)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "32x32.png").write_bytes(icon(32))
    (OUT / "128x128.png").write_bytes(icon(128))
    (OUT / "henry.w@example.net").write_bytes(icon(256))
    (OUT / "icon.png").write_bytes(icon(512))
    print(f"Wrote icons in {OUT}")


if __name__ == "__main__":
    main()
