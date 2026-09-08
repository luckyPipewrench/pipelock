#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Generate and verify Pipelock's canonical brand assets."""

from __future__ import annotations

import argparse
import hashlib
import math
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "assets"
ACCENT, PURPLE, BG, ELEVATED = "#00e5a0", "#7c3aed", "#09090b", "#0e0e11"
TEXT, MUTED, DIM = "#e2e8f0", "#94a3b8", "#64748b"
MONO = "'JetBrains Mono', 'Fira Code', ui-monospace, SFMono-Regular, Menlo, monospace"
SANS = "Inter, system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"
FOOTER = "Apache 2.0 core  ·  maintained by PipeLab"


def mark() -> str:
    return f'''  <g aria-label="Pipelock lock mark">
    <path d="M72 112V68C72 35 93 18 120 18S168 35 168 68V112" fill="none" stroke="{ACCENT}" stroke-width="22" stroke-linecap="round"/>
    <rect x="46" y="104" width="148" height="110" rx="14" fill="{ELEVATED}" stroke="{ACCENT}" stroke-width="3"/>
    <rect x="55" y="113" width="130" height="92" rx="9" fill="none" stroke="{ACCENT}" stroke-opacity="0.18"/>
    <circle cx="120" cy="150" r="13" fill="{ACCENT}"/><circle cx="120" cy="150" r="6" fill="{BG}"/>
    <path d="M116 158h8v24a4 4 0 0 1-8 0z" fill="{ACCENT}"/>
  </g>'''


def logo() -> str:
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="240" height="240" viewBox="0 0 240 240" role="img" aria-label="Pipelock logo">
{mark()}
</svg>
'''


def favicon() -> str:
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64" role="img" aria-label="Pipelock favicon">
  <rect width="64" height="64" rx="12" fill="{ELEVATED}"/><g transform="translate(8 8) scale(.2)">{mark()}</g>
</svg>
'''


def lockup() -> str:
    # The mark's right edge lands at x=90.5 after the scale above, and the
    # wordmark's cap height is 39 units at font-size 52. The gap between them is
    # 0.75 of that cap height, which is the spacing unit the brand guidelines
    # already use for clear space. It used to be 1.31, wide enough that the mark
    # and the wordmark read as two objects instead of one lockup.
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="465" height="112" viewBox="-32 0 465 112" role="img" aria-label="Pipelock logo lockup">
  <g transform="scale(.4666667)">{mark()}</g>
  <text x="119.8" y="70" font-family="{MONO}" font-size="52" font-weight="700" letter-spacing="-.02em"><tspan fill="{TEXT}">Pipe</tspan><tspan fill="{ACCENT}">lock</tspan></text>
  <text x="122.8" y="94" font-family="{SANS}" font-size="14" fill="{MUTED}" letter-spacing=".286em">AGENT FIREWALL</text>
</svg>
'''


def stacked_lockup() -> str:
    # The mark's lower edge is at y=214 and the wordmark's cap height is 39 at
    # font-size 52, so a baseline of 281 leaves 0.75 of a cap height between
    # them, matching the horizontal lockup. The wordmark used to sit at 258,
    # six units below the lock, close enough that the ascenders read as
    # touching it. The canvas grew from 290 to 313 to keep the tagline's
    # existing spacing below the wordmark.
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="420" height="313" viewBox="0 0 420 313" role="img" aria-label="Pipelock stacked logo lockup">
  <g transform="translate(90)">{mark()}</g>
  <text x="210" y="281" text-anchor="middle" font-family="{MONO}" font-size="52" font-weight="700" letter-spacing="-.02em"><tspan fill="{TEXT}">Pipe</tspan><tspan fill="{ACCENT}">lock</tspan></text>
  <text x="210" y="305" text-anchor="middle" font-family="{SANS}" font-size="14" fill="{MUTED}" letter-spacing=".286em">AGENT FIREWALL</text>
</svg>
'''


def particles() -> str:
    rng = random.Random(340)
    pts = []
    while len(pts) < 42:
        point = (rng.randint(70, 1210), rng.randint(55, 565))
        if not (420 <= point[0] <= 1060 and 190 <= point[1] <= 460):
            pts.append(point)
    out = [f'  <g stroke="{ACCENT}" stroke-width="1">']
    for i, (x1, y1) in enumerate(pts):
        for x2, y2 in pts[i + 1 :]:
            distance = math.hypot(x2 - x1, y2 - y1)
            if distance < 150:
                opacity = round(0.16 * (1 - distance / 150), 3)
                out.append(f'    <line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" opacity="{opacity}"/>')
    out.extend(["  </g>", f'  <g fill="{ACCENT}" opacity=".5">'])
    out.extend(f'    <circle cx="{x}" cy="{y}" r="1.6"/>' for x, y in pts)
    out.append("  </g>")
    return "\n".join(out)


def social_preview() -> str:
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="640" viewBox="0 0 1280 640" role="img" aria-label="Pipelock. Agent firewall with signed decision evidence. {FOOTER}.">
  <defs>
    <radialGradient id="teal" cx="28%" cy="22%" r="58%"><stop offset="0" stop-color="{ACCENT}" stop-opacity=".22"/><stop offset="1" stop-color="{ACCENT}" stop-opacity="0"/></radialGradient>
    <radialGradient id="purple" cx="76%" cy="84%" r="58%"><stop offset="0" stop-color="{PURPLE}" stop-opacity=".30"/><stop offset="1" stop-color="{PURPLE}" stop-opacity="0"/></radialGradient>
  </defs>
  <rect width="1280" height="640" fill="{BG}"/><rect width="1280" height="640" fill="url(#teal)"/><rect width="1280" height="640" fill="url(#purple)"/>
{particles()}
  <g transform="translate(75)">
    <g transform="translate(104 172) scale(1.18)">{mark()}</g>
    <text x="452" y="287" font-family="{MONO}" font-size="92" font-weight="700" letter-spacing="-.025em"><tspan fill="{TEXT}">Pipe</tspan><tspan fill="{ACCENT}">lock</tspan></text>
    <text x="456" y="342" font-family="{SANS}" font-size="25" fill="{MUTED}">Agent firewall with signed decision evidence</text>
    <g font-family="{MONO}" font-size="17" font-weight="600" text-anchor="middle">
      <rect x="456" y="398" width="122" height="46" rx="23" fill="{ACCENT}" fill-opacity=".08" stroke="{ACCENT}" stroke-opacity=".42"/><text x="517" y="428" fill="{ACCENT}">inspect</text>
      <rect x="596" y="398" width="136" height="46" rx="23" fill="{ACCENT}" fill-opacity=".08" stroke="{ACCENT}" stroke-opacity=".42"/><text x="664" y="428" fill="{ACCENT}">enforce</text>
      <rect x="750" y="398" width="112" height="46" rx="23" fill="{ACCENT}" fill-opacity=".08" stroke="{ACCENT}" stroke-opacity=".42"/><text x="806" y="428" fill="{ACCENT}">prove</text>
    </g>
  </g>
  <text x="120" y="566" font-family="{MONO}" font-size="16" fill="{DIM}" letter-spacing=".12em">{FOOTER}</text>
</svg>
'''


GENERATED = {"pipelock-logo.svg": logo, "pipelock-lockup.svg": lockup, "pipelock-lockup-stacked.svg": stacked_lockup, "pipelock-favicon.svg": favicon, "social-preview.svg": social_preview}
RASTERS = {"pipelock-logo.png": "pipelock-logo.svg", "social-preview.png": "social-preview.svg"}

# Every size a consumer has actually asked us for, generated from the one SVG.
# Before this ladder existed each size was exported by hand into whatever tool
# needed it, which is how assets/pipelock-logo.png came to be a 240-unit mark
# sitting untouched in the corner of an 800x800 white canvas.
ICON_SIZES = (16, 32, 48, 64, 128, 256, 512, 1024)
ICON_DIR = "icons"
ICO_SIZES = (16, 32, 48, 64, 128, 256)
ICO_NAME = "icons/pipelock.ico"


def icon_rasters() -> dict[str, tuple[str, int]]:
    """Map each ladder PNG to its SVG source and square pixel size."""
    return {
        f"{ICON_DIR}/pipelock-logo-{size}.png": ("pipelock-logo.svg", size)
        for size in ICON_SIZES
    }


def source_file(png: str) -> Path:
    return ASSETS / f"{png}.source"


def raster_fingerprint(png: Path, svg: Path) -> str:
    """Bind a raster provenance record to both its SVG source and PNG bytes."""
    svg_bytes = svg.read_bytes().replace(b"\r\n", b"\n")
    return f"svg {hashlib.sha256(svg_bytes).hexdigest()}\npng {hashlib.sha256(png.read_bytes()).hexdigest()}\n"


def _rasterize(svg: Path, png: Path, size: int) -> None:
    """Render one SVG to a square transparent PNG.

    Rendering is a developer step, not a CI step: CI verifies the stamped
    fingerprints instead, so a machine without a renderer can still check the
    tree. Inkscape is used because it honours the viewBox and scales the mark
    to fill the requested canvas; the hand exports it replaces did not.
    """
    import shutil
    import subprocess

    inkscape = shutil.which("inkscape")
    if inkscape is None:
        raise SystemExit(
            "render_brand: inkscape is required to render rasters; "
            "install it or leave the committed PNGs untouched"
        )
    png.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            inkscape,
            str(svg),
            "--export-type=png",
            f"--export-filename={png}",
            f"--export-width={size}",
            f"--export-height={size}",
            "--export-background-opacity=0",
        ],
        check=True,
        capture_output=True,
    )


def _write_ico(pngs: list[Path], target: Path) -> None:
    """Bundle the small ladder sizes into a single multi-resolution .ico."""
    import shutil
    import subprocess

    magick = shutil.which("magick") or shutil.which("convert")
    if magick is None:
        raise SystemExit("render_brand: ImageMagick is required to build the .ico")
    target.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [magick, *[str(p) for p in pngs], str(target)], check=True, capture_output=True
    )


def render_rasters() -> int:
    """Regenerate every raster from its SVG and re-stamp provenance."""
    for png, svg in RASTERS.items():
        svg_path = ASSETS / svg
        png_path = ASSETS / png
        if png == "social-preview.png":
            # Social previews are wide, not square, so they keep their own export.
            continue
        _rasterize(svg_path, png_path, 800)
        source_file(png).write_text(
            raster_fingerprint(png_path, svg_path), encoding="utf-8"
        )
        print(f"rendered assets/{png}")

    ladder = []
    for png, (svg, size) in icon_rasters().items():
        svg_path = ASSETS / svg
        png_path = ASSETS / png
        _rasterize(svg_path, png_path, size)
        source_file(png).write_text(
            raster_fingerprint(png_path, svg_path), encoding="utf-8"
        )
        ladder.append((size, png_path))
        print(f"rendered assets/{png}")

    ico_inputs = [p for size, p in sorted(ladder) if size in ICO_SIZES]
    ico_path = ASSETS / ICO_NAME
    _write_ico(ico_inputs, ico_path)
    source_file(ICO_NAME).write_text(
        raster_fingerprint(ico_path, ASSETS / "pipelock-logo.svg"), encoding="utf-8"
    )
    print(f"rendered assets/{ICO_NAME}")
    return 0


def check() -> list[str]:
    problems = []
    for filename, render in GENERATED.items():
        path = ASSETS / filename
        if not path.exists() or path.read_text(encoding="utf-8") != render():
            problems.append(f"assets/{filename}: missing or stale; run scripts/render_brand.py")
    for png, svg in RASTERS.items():
        png_path = ASSETS / png
        svg_path = ASSETS / svg
        stamp = source_file(png)
        if not png_path.exists() or not svg_path.exists() or not stamp.exists():
            problems.append(f"assets/{png}: raster or provenance sidecar missing")
            continue
        if stamp.read_text(encoding="utf-8") != raster_fingerprint(png_path, svg_path):
            problems.append(f"assets/{png}: PNG or assets/{svg} changed since export")
    # The ladder is verified the same way as the other rasters: a raster whose
    # bytes or SVG source moved since export is reported, never silently kept.
    for png, (svg, size) in icon_rasters().items():
        png_path = ASSETS / png
        svg_path = ASSETS / svg
        stamp = source_file(png)
        if not png_path.exists() or not stamp.exists():
            problems.append(f"assets/{png}: raster or provenance sidecar missing")
            continue
        if stamp.read_text(encoding="utf-8") != raster_fingerprint(png_path, svg_path):
            problems.append(f"assets/{png}: PNG or assets/{svg} changed since export")
    ico_path = ASSETS / ICO_NAME
    ico_stamp = source_file(ICO_NAME)
    if not ico_path.exists() or not ico_stamp.exists():
        problems.append(f"assets/{ICO_NAME}: icon bundle or provenance sidecar missing")
    elif ico_stamp.read_text(encoding="utf-8") != raster_fingerprint(
        ico_path, ASSETS / "pipelock-logo.svg"
    ):
        problems.append(f"assets/{ICO_NAME}: bundle or its SVG source changed since export")
    for path in (ASSETS / "pipelock-logo.svg", ASSETS / "pipelock-favicon.svg", ASSETS / "social-preview.svg"):
        if path.exists() and "#00ffc8" in path.read_text(encoding="utf-8").lower():
            problems.append(f"{path.relative_to(ROOT)}: contains retired #00ffc8 cyan")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--stamp-png", action="store_true")
    parser.add_argument(
        "--render-rasters",
        action="store_true",
        help="regenerate every PNG and the .ico from the SVGs, then re-stamp",
    )
    args = parser.parse_args()
    if args.render_rasters:
        return render_rasters()
    if args.stamp_png:
        stampable = dict(RASTERS)
        stampable.update({png: svg for png, (svg, _size) in icon_rasters().items()})
        stampable[ICO_NAME] = "pipelock-logo.svg"
        for png, svg in stampable.items():
            png_path = ASSETS / png
            svg_path = ASSETS / svg
            if not png_path.exists() or not svg_path.exists():
                print(f"cannot stamp assets/{png}: raster or assets/{svg} missing")
                return 1
            source_file(png).write_text(raster_fingerprint(png_path, svg_path), encoding="utf-8")
            print(f"stamped assets/{png}.source")
        return 0
    if args.check:
        problems = check()
        if problems:
            print("check-brand: FAIL")
            for problem in problems:
                print(f"  {problem}")
            return 1
        print(
            f"check-brand: OK ({len(GENERATED)} vectors, {len(RASTERS)} rasters, "
            f"{len(icon_rasters())} ladder icons and 1 bundle)"
        )
        return 0
    ASSETS.mkdir(exist_ok=True)
    for filename, render in GENERATED.items():
        (ASSETS / filename).write_text(render(), encoding="utf-8", newline="\n")
        print(f"wrote assets/{filename}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
