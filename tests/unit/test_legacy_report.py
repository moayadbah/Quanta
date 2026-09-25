"""An older engine's run can never read as a clean result (round six).

``tests/fixtures/legacy_run`` is a real run of analyzer 0.3.0 (the engine the live scanner
ran before its snapshot was rebuilt) on a small repository: an ECDSA key, a SHA-1 digest in
shipped code and a SHA-1 known-answer test. It has no findings.json and no readiness.json,
its file paths predate roles, and its plan proposes patching the test. The report once read
those gaps as zeros and told a user that an ECDSA library needed nothing.
"""

from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from quanta.core.fixes import FixPlan, reevaluate
from quanta.core.legacy import normalise
from quanta.core.pdf import render_pdf
from quanta.core.report import render_data
from quanta.core.report_data import build, en
from quanta.web.app import create_app
from quanta.web.jobs import Job, JobRegistry

LEGACY = Path(__file__).resolve().parents[1] / "fixtures" / "legacy_run"
CLEAN = ("doc.findings_none", "doc.deadlines_none")


def _read(name: str) -> Any:
    path = LEGACY / name
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


def _legacy_report(lang: str = "en") -> dict[str, Any]:
    run = normalise(
        score=_read("score.json"),
        readiness=None,
        findings=None,
        plan=FixPlan.model_validate(_read("fixes.json")),
        cdg=_read("cdg.json"),
    )
    return build(
        score=_read("score.json"),
        meta=_read("meta.json"),
        readiness=run.readiness,
        findings=run.findings,
        fixes=run.plan.public(),
        lang=lang,
        assessed=run.assessed,
        roles_measured=run.roles_measured,
        older_engine=run.older_engine,
        rescan_url="/workspace.html#rescan=example/signer",
    )


def _all_text(data: dict[str, Any]) -> str:
    return json.dumps(data, ensure_ascii=False, default=str)


def test_the_fixture_is_really_old_format() -> None:
    assert _read("findings.json") is None and _read("readiness.json") is None
    assert _read("score.json")["provenance"]["analyzer_version"].startswith("0.3.0")
    plan = _read("fixes.json")
    assert {f["path"] for f in plan["files"]} == {"src/signer/digest.py", "tests/test_digest.py"}


def test_an_old_run_never_states_a_clean_result() -> None:
    for lang in ("en", "ar"):
        data = _legacy_report(lang)
        text = _all_text(data)
        assert data["assessed"] is False and data["verdict"] == "not_assessed"
        for key in CLEAN:
            assert en(key) not in text
        assert "(0 shipped)" not in text and "0 shipped" not in text
        assert data["shipped_files"] is None
        # Its calls are still listed, classed with today's rules.
        assert data["findings_total"] >= 2
        assert data["L"]["legacy"] and data["rescan_url"]


def test_a_patch_the_current_rules_refuse_never_appears() -> None:
    data = _legacy_report()
    patched = {p["path"] for p in data["patches"]}
    refused = {r["where"].rsplit(":", 1)[0] for r in data["refusals"]}
    assert patched == {"src/signer/digest.py"}
    assert "tests/test_digest.py" in refused
    assert "_quanta" not in _all_text(data)
    # The diff shows the real line with context, not one word.
    patch = data["patches"][0]
    kinds = [line["kind"] for line in patch["lines"]]
    assert kinds.count("-") == 1 and kinds.count("+") == 1 and kinds.count(" ") >= 2
    assert "hashlib.sha256(data)" in next(
        line["text"] for line in patch["lines"] if line["kind"] == "+"
    )


def test_reevaluate_leaves_a_current_plan_alone() -> None:
    current = FixPlan.model_validate_json(
        (Path(__file__).resolve().parents[2] / "demo" / "sample" / "fixes.json").read_text(
            encoding="utf-8"
        )
    )
    assert reevaluate(current) is current


@pytest.mark.parametrize(
    "missing",
    ["readiness", "counts_without_findings", "coverage_without_source_files"],
)
def test_a_missing_field_never_renders_as_zero(missing: str) -> None:
    sample = Path(__file__).resolve().parents[2] / "demo" / "sample"
    score = json.loads((sample / "score.json").read_text(encoding="utf-8"))
    readiness = json.loads((sample / "readiness.json").read_text(encoding="utf-8"))
    findings = json.loads((sample / "findings.json").read_text(encoding="utf-8"))["findings"]
    if missing == "readiness":
        readiness = None
    if missing == "counts_without_findings":
        findings = []
    if missing == "coverage_without_source_files":
        score["coverage"].pop("source_files")
    data = build(score=score, meta={}, readiness=readiness, findings=findings, fixes={"files": []})
    text = _all_text(data)
    for key in CLEAN:
        assert en(key) not in text
    assert "(0 shipped)" not in text


def test_both_documents_render_an_old_run_in_both_languages() -> None:
    for lang in ("en", "ar"):
        data = _legacy_report(lang)
        html = render_data(data)
        assert data["L"]["legacy"] in html and "Cryptographic Agility Report" not in html
        assert "�" not in html
        pdf = render_pdf(data)
        assert pdf.startswith(b"%PDF") and len(pdf) > 10_000
        assert render_pdf(data, "letter").startswith(b"%PDF")


def test_the_web_serves_an_old_run_through_todays_rules(tmp_path: Path) -> None:
    registry = JobRegistry(tmp_path / "artifacts")
    job = Job(id=str(uuid.uuid4()), repo_url="https://github.com/example/signer")
    job.cached = True
    job.status = "succeeded"
    job.finished_at = time.time()
    job.artifact_dir = LEGACY
    registry.adopt_cached(job)
    with TestClient(create_app(registry.artifact_root, registry.db.path)) as client:
        base = f"/api/v1/analyses/{job.id}"
        report = client.get(f"{base}/report")
        assert report.status_code == 200
        assert "Cryptographic Agility Report" not in report.text
        assert en("doc.legacy", version="0.3.0+rules.2026.08.01") in report.text
        assert en("doc.findings_none") not in report.text
        plan = client.get(f"{base}/fixes").json()
        assert [f["path"] for f in plan["files"]] == ["src/signer/digest.py"]
        assert all(c["context_before"] for f in plan["files"] for c in f["changes"])
        findings = client.get(f"{base}/findings").json()["findings"]
        assert {f["file"] for f in findings} >= {"src/signer/digest.py", "src/signer/keys.py"}
        pdf = client.get(f"{base}/report.pdf?lang=ar")
        assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
