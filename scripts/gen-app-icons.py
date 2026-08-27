#!/usr/bin/env python3
"""Regenerate src-tauri/icons from apps/desktop/src-tauri/icon.png (1024×1024).

Equivalent to `cargo tauri icon …` when the Tauri CLI is unavailable.
"""
from __future__ import annotations

import struct
import zlib
from pathlib import Path

try:
    from PIL import Image
except ImportError as e:  # pragma: no cover
    raise SystemExit("Pillow required: pip install pillow") from e

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "apps" / "desktop" / "src-tauri" / "icon.png"
OUT = ROOT / "apps" / "desktop" / "src-tauri" / "icons"


def main() -> None:
    if not SRC.is_file():
        raise SystemExit(f"missing source icon: {SRC}")
    img = Image.open(SRC).convert("RGBA")
    w, h = img.size
    if w < 1024 or h < 1024:
        raise SystemExit(f"source icon must be at least 1024×1024 (got {w}×{h})")

    OUT.mkdir(parents=True, exist_ok=True)

    sizes = {
        "32x32.png": 32,
        "64x64.png": 64,
        "128x128.png": 128,
        "128x128@2x.png": 256,
        "icon.png": 512,
    }
    for name, size in sizes.items():
        resized = img.resize((size, size), Image.Resampling.LANCZOS)
        resized.save(OUT / name, format="PNG")

    # Windows .ico with several sizes
    ico_sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    img.save(
        OUT / "icon.ico",
        format="ICO",
        sizes=ico_sizes,
    )

    # Keep a full-resolution copy for reference / AppImage
    img.resize((1024, 1024), Image.Resampling.LANCZOS).save(OUT / "icon-1024.png", format="PNG")

    print(f"Regenerated icons in {OUT} from {SRC} ({w}×{h})")


if __name__ == "__main__":
    main()
