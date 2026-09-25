"""Every guided migration shows real code. This runs each example, so none can ship broken."""

from __future__ import annotations

import json

import pytest

from quanta.core.readiness import standards
from quanta.resources import asset_path

GUIDES = json.loads(asset_path("config/migrations.json").read_text(encoding="utf-8"))["guides"]


@pytest.mark.parametrize("guide", GUIDES, ids=lambda g: g["id"])
def test_example_runs(guide: dict) -> None:
    # Our own shipped example code, run to prove it works; never third-party input.
    code = compile(guide["example"], f"<guide {guide['id']}>", "exec")
    exec(code, {"__name__": "example"})  # noqa: S102


@pytest.mark.parametrize("guide", GUIDES, ids=lambda g: g["id"])
def test_every_guide_cites_a_published_source(guide: dict) -> None:
    assert guide["sources"]
    assert set(guide["sources"]) <= set(standards()["sources"])
