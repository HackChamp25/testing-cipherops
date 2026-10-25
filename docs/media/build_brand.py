"""Build Cipherops brand PNGs from the vector mark (run: python docs/media/build_brand.py)."""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

OUT = Path(__file__).resolve().parent

INK = (16, 42, 67)  # #102A43
ACCENT = (196, 120, 42)  # #C4782A
SLATE = (72, 101, 129)  # #486581
PAPER = (255, 255, 255, 255)
INK_ON_DARK = (230, 236, 242)  # #E6ECF2


def draw_mark(draw: ImageDraw.ImageDraw, cx: float, cy: float, scale: float, ink, accent) -> None:
    """Hierarchical ladder mark: amber apex, three rungs, rooted base."""
    s = scale
    sw = max(3, int(round(s * 0.085)))
    node_r = max(4, int(round(s * 0.07)))

    top = cy - 1.05 * s
    # spine from under apex to crotch
    crotch = cy + 0.55 * s
    draw.line([(cx, top + 0.22 * s), (cx, crotch)], fill=ink, width=sw)

    # rungs (longest → shortest), end nodes
    for i, (half_mul, yoff) in enumerate(((1.05, -0.35), (0.82, 0.05), (0.58, 0.45))):
        y = cy + yoff * s
        half = half_mul * s * 0.42
        color = accent if i == 0 else ink
        draw.line([(cx - half, y), (cx + half, y)], fill=color, width=sw)
        for x in (cx - half, cx + half):
            draw.ellipse([x - node_r, y - node_r, x + node_r, y + node_r], fill=color)

    # rooted base
    foot_y = cy + 1.05 * s
    foot_x = 0.55 * s
    for sign in (-1, 1):
        draw.line([(cx, crotch), (cx + sign * foot_x, foot_y)], fill=ink, width=sw)
        draw.ellipse(
            [
                cx + sign * foot_x - node_r,
                foot_y - node_r,
                cx + sign * foot_x + node_r,
                foot_y + node_r,
            ],
            fill=ink,
        )

    # apex node
    ar = 0.20 * s
    draw.ellipse([cx - ar, top - ar, cx + ar, top + ar], fill=accent)


def make_mark(path: Path, bg, ink, accent, size: int = 640) -> None:
    img = Image.new("RGBA", (size, size), bg)
    draw = ImageDraw.Draw(img)
    draw_mark(draw, size / 2, size / 2 + size * 0.02, size * 0.32, ink, accent)
    img.save(path, optimize=True)
    print("wrote", path.name)


def make_banner(path: Path, bg, ink, accent, slate, word, size=(1100, 320)) -> None:
    w, h = size
    img = Image.new("RGBA", (w, h), bg)
    d = ImageDraw.Draw(img)
    mx = int(h * 0.40)
    draw_mark(d, mx, h / 2 + 4, h * 0.26, ink, accent)
    try:
        font = ImageFont.truetype("C:/Windows/Fonts/segoeuib.ttf", 78)
        sub = ImageFont.truetype("C:/Windows/Fonts/segoeui.ttf", 24)
    except OSError:
        font = ImageFont.load_default()
        sub = font
    text = "CIPHEROPS"
    # Position from measured ink box so the rule sits under glyphs, not through them.
    probe = d.textbbox((0, 0), text, font=font)
    tw, th = probe[2] - probe[0], probe[3] - probe[1]
    tx = mx + int(h * 0.38)
    ty = (h - th) // 2 - 22
    d.text((tx, ty), text, font=font, fill=word)
    ink = d.textbbox((tx, ty), text, font=font)
    rule_y = ink[3] + 10
    d.line([(ink[0], rule_y), (ink[2], rule_y)], fill=accent, width=3)
    d.text(
        (tx, rule_y + 12),
        "PQC DNSSEC  ·  MTL mode  ·  Reference implementation",
        font=sub,
        fill=slate,
    )
    img.save(path, optimize=True)
    print("wrote", path.name)


def main() -> None:
    make_mark(OUT / "cipherops-mark-light.png", PAPER, INK, ACCENT)
    make_mark(OUT / "cipherops-mark-dark.png", (0, 0, 0, 0), INK_ON_DARK, ACCENT)
    make_banner(OUT / "cipherops-banner-light.png", PAPER, INK, ACCENT, SLATE, INK)
    make_banner(
        OUT / "cipherops-banner-dark.png",
        (11, 22, 34, 255),
        INK_ON_DARK,
        ACCENT,
        (139, 168, 190),
        INK_ON_DARK,
    )

    (OUT / "cipherops-mark.svg").write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" role="img" aria-label="Cipherops mark">
  <title>Cipherops</title>
  <g fill="none" stroke-linecap="round" stroke-linejoin="round">
    <circle cx="64" cy="18" r="11" fill="#C4782A"/>
    <path stroke="#102A43" stroke-width="6" d="M64 32 V78"/>
    <path stroke="#C4782A" stroke-width="6" d="M30 48 H98"/>
    <circle cx="30" cy="48" r="5" fill="#C4782A"/><circle cx="98" cy="48" r="5" fill="#C4782A"/>
    <path stroke="#102A43" stroke-width="6" d="M36 66 H92"/>
    <circle cx="36" cy="66" r="5" fill="#102A43"/><circle cx="92" cy="66" r="5" fill="#102A43"/>
    <path stroke="#102A43" stroke-width="6" d="M44 84 H84"/>
    <circle cx="44" cy="84" r="5" fill="#102A43"/><circle cx="84" cy="84" r="5" fill="#102A43"/>
    <path stroke="#102A43" stroke-width="6" d="M64 78 L40 112 M64 78 L88 112"/>
    <circle cx="40" cy="112" r="5" fill="#102A43"/><circle cx="88" cy="112" r="5" fill="#102A43"/>
  </g>
</svg>
""",
        encoding="utf-8",
    )
    print("wrote cipherops-mark.svg")


if __name__ == "__main__":
    main()
