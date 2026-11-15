"""应用图标：四角取景框 + 琥珀状态点。

16×16 像素母版，只按整数倍最近邻放大，保证 16/32/48/256 托盘与资源视图锐利。
`static/icon.svg` 由 `tools/make_icon.py` 从同一母版生成，不要手改。
"""

from __future__ import annotations

from pathlib import Path

# '.' 壳体底色，'P' 面板浅青，'A' 琥珀状态点
PATTERN = (
    "................",
    ".PPPPPP..PPPPPP.",
    ".PPPPPP..PPPPPP.",
    ".PP..........PP.",
    ".PP..........PP.",
    ".PP..........PP.",
    ".PP...AAAA...PP.",
    "......AAAA......",
    "......AAAA......",
    ".PP...AAAA...PP.",
    ".PP..........PP.",
    ".PP..........PP.",
    ".PP..........PP.",
    ".PPPPPP..PPPPPP.",
    ".PPPPPP..PPPPPP.",
    "................",
)
GRID = 16
COLORS = {
    ".": (11, 14, 15),
    "P": (169, 213, 207),
    "A": (217, 164, 65),
}


def render(size: int = 256):
    """返回 size×size 的 RGBA 图标；size 不是 16 的整数倍时最近邻缩放。"""
    from PIL import Image, ImageDraw

    scale = max(1, size // GRID)
    side = GRID * scale
    img = Image.new("RGBA", (side, side), COLORS["."] + (255,))
    draw = ImageDraw.Draw(img)
    for y, row in enumerate(PATTERN):
        for x, ch in enumerate(row):
            if ch in "PA":
                draw.rectangle([x * scale, y * scale, x * scale + scale - 1,
                                y * scale + scale - 1], fill=COLORS[ch] + (255,))
    if side != size:
        img = img.resize((size, size), Image.NEAREST)
    return img


def svg() -> str:
    """矢量版 favicon：每行合并同色像素，产物只有几十个 rect。"""
    hexes = {k: "#%02x%02x%02x" % v for k, v in COLORS.items()}
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{GRID}" height="{GRID}" '
             f'viewBox="0 0 {GRID} {GRID}" shape-rendering="crispEdges">',
             f'<rect width="{GRID}" height="{GRID}" fill="{hexes["."]}"/>']
    for y, row in enumerate(PATTERN):
        x = 0
        while x < len(row):
            ch = row[x]
            if ch == ".":
                x += 1
                continue
            start = x
            while x < len(row) and row[x] == ch:
                x += 1
            parts.append(f'<rect x="{start}" y="{y}" width="{x - start}" height="1" '
                         f'fill="{hexes[ch]}"/>')
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def ico_bytes(sizes: tuple[int, ...] = (16, 32, 48, 64, 128, 256)) -> bytes:
    """多尺寸 ICO：每帧存原生渲染的 PNG，避免 Pillow 缩放把像素图抹糊。"""
    import io
    import struct

    frames = []
    for size in sizes:
        buf = io.BytesIO()
        render(size).save(buf, format="PNG")
        frames.append((size, buf.getvalue()))

    out = io.BytesIO()
    out.write(struct.pack("<HHH", 0, 1, len(frames)))
    offset = 6 + 16 * len(frames)
    for size, png in frames:
        dim = 0 if size >= 256 else size          # ICO 里 0 表示 256
        out.write(struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(png), offset))
        offset += len(png)
    for _, png in frames:
        out.write(png)
    return out.getvalue()


def write_ico(path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(ico_bytes())
    return path
