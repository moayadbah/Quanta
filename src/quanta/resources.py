"""Locate committed assets in either a source checkout or an installed wheel."""

from pathlib import Path


def asset_path(relative: str) -> Path:
    source = Path(__file__).resolve().parents[2] / relative
    if source.exists():
        return source
    return Path(__file__).resolve().parent / "data" / relative
