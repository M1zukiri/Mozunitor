#!/usr/bin/env python3
"""从 mozunitor/branding.py 的 16×16 母版生成 favicon 与构建用 ICO。"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mozunitor import branding      # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--svg", default=str(ROOT / "static" / "icon.svg"),
                    help="favicon 输出路径")
    ap.add_argument("--ico", help="PyInstaller --icon 用的多尺寸 ICO 输出路径")
    args = ap.parse_args()

    svg_path = Path(args.svg)
    svg_path.write_text(branding.svg(), encoding="utf-8", newline="\n")
    print(f"svg -> {svg_path}")
    if args.ico:
        print(f"ico -> {branding.write_ico(Path(args.ico))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
