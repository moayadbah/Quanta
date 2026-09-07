from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from quanta.cli import app
from quanta.core.cbom import read_cbom
from quanta.errors import Reject


def test_cbom_is_merged_and_changes_provenance(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("print('not executed')\n")
    cbom = tmp_path / "cbom.json"
    cbom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {
                        "type": "cryptographic-asset",
                        "name": "SHA1",
                        "cryptoProperties": {"assetType": "algorithm"},
                        "evidence": {"occurrences": [{"location": "app.py", "line": 1}]},
                    }
                ],
            }
        )
    )
    runner = CliRunner()
    out = tmp_path / "out"
    result = runner.invoke(app, ["analyze", str(source), "--out", str(out), "--cbom", str(cbom)])
    assert result.exit_code == 0, result.output
    graph = json.loads((out / "cdg.json").read_text())
    assert sum(n["kind"] == "crypto_call" and n["source"] == "cbom" for n in graph["nodes"]) == 1
    meta = json.loads((out / "meta.json").read_text())
    assert meta["cbom_sha256"] in meta["provenance"]["analyzer_version"]
    assert meta["cbom_unlocated"] == 0
    assert "SHA1" in (out / "report.html").read_text()


@pytest.mark.parametrize(
    "location", ["/etc/passwd.py", "../escape.py", "C:\\file.py", "http://a/b.py"]
)
def test_cbom_does_not_fabricate_source_locations(tmp_path: Path, location: str) -> None:
    path = tmp_path / "input.json"
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {
                        "type": "cryptographic-asset",
                        "name": "SHA1",
                        "evidence": {"occurrences": [{"location": location, "line": 2}]},
                    }
                ],
            }
        )
    )
    result = read_cbom(path)
    assert result.sites == []
    assert result.unlocated == 1


def test_cbom_wrong_version_refused(tmp_path: Path) -> None:
    path = tmp_path / "input.json"
    path.write_text('{"bomFormat":"CycloneDX","specVersion":"1.5"}')
    with pytest.raises(Reject, match="CBOM_INVALID"):
        read_cbom(path)
