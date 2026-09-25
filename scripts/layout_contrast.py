"""Contrast of every text box against the pixels behind it, from scripts/layout_check.mjs.

    uv run python scripts/layout_contrast.py out/layout

For each state the check wrote a screenshot with every glyph transparent (``*.bg.png``) and
the text boxes with their computed colours (``*.json``). The backdrop of a box is what is
really there: the page colour, a card, the photograph, the hex field or a gradient. Each
backdrop pixel is compared with the text colour (alpha blended onto it), and the box fails
when its 10th-percentile contrast is below WCAG AA: 4.5:1, or 3:1 for large text (24 px, or
18.7 px bold). Exits 1 on any failure, so it can gate a release.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from PIL import Image


def _channel(value: float) -> float:
    value /= 255
    return value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4


def luminance(rgb: tuple[float, float, float]) -> float:
    r, g, b = (_channel(v) for v in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def ratio(a: float, b: float) -> float:
    high, low = max(a, b), min(a, b)
    return (high + 0.05) / (low + 0.05)


def parse(color: str) -> tuple[float, float, float, float]:
    nums = [float(n) for n in re.findall(r"[\d.]+", color)]
    return (nums[0], nums[1], nums[2], nums[3] if len(nums) > 3 else 1.0)


def check(folder: Path) -> list[dict[str, object]]:
    failures = []
    for data_file in sorted(folder.glob("*.json")):
        if data_file.name in {"geometry.json", "contrast.json"}:
            continue
        data = json.loads(data_file.read_text(encoding="utf-8"))
        for screen in data.get("screens", []):
            backdrop = folder / f"{data['label']}.{screen['index']}.bg.png"
            if backdrop.is_file():
                failures += _screen(
                    data["label"], Image.open(backdrop).convert("RGB"), screen["texts"]
                )
    return failures


def _screen(
    label: str, image: Image.Image, texts: list[dict[str, object]]
) -> list[dict[str, object]]:
    failures: list[dict[str, object]] = []
    for box in texts:
        r, g, b, a = parse(box["color"])
        if a == 0:
            continue
        x0, y0 = max(0, int(box["x"])), max(0, int(box["y"]))
        x1 = min(image.width, int(box["x"] + box["w"]))
        y1 = min(image.height, int(box["y"] + box["h"]))
        if x1 - x0 < 2 or y1 - y0 < 2:
            continue
        region = image.crop((x0, y0, x1, y1)).resize(
            (max(1, (x1 - x0) // 2), max(1, (y1 - y0) // 2))
        )
        scores = []
        for pixel in region.get_flattened_data():
            blended = tuple(a * c + (1 - a) * p for c, p in zip((r, g, b), pixel, strict=True))
            scores.append(ratio(luminance(blended), luminance(pixel)))
        scores.sort()
        worst = scores[len(scores) // 10]
        large = box["size"] >= 24 or (box["size"] >= 18.66 and box["weight"] >= 700)
        need = 3.0 if large else 4.5
        if worst < need:
            failures.append(
                {
                    "state": label,
                    "text": box["name"],
                    "contrast": round(worst, 2),
                    "needs": need,
                }
            )
    return failures


if __name__ == "__main__":
    folder = Path(sys.argv[1] if len(sys.argv) > 1 else "out/layout")
    found = check(folder)
    (folder / "contrast.json").write_text(json.dumps(found, indent=1), encoding="utf-8")
    states = len(
        [p for p in folder.glob("*.json") if p.name not in {"geometry.json", "contrast.json"}]
    )
    print(f"text boxes checked in {states} states; contrast failures: {len(found)}")
    for item in found[:40]:
        print(f"  {item['state']}: {item['text']} {item['contrast']}:1 (needs {item['needs']})")
    sys.exit(1 if found else 0)
