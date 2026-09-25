"""Two uses of the project's own test run (Master Plan 10 and 25).

* :func:`trace_check`: run the tests once with the crypto tracer and report how much of
  the executed cryptography the static inventory found. Answers "how much did Quanta
  miss here?" for this repository, instead of quoting a corpus average.
* :func:`verify_changes`: run the tests twice before and twice after a proposed change,
  measure which changed lines ran, and, for changes that alter outputs on purpose, swap
  the algorithm at each changed site to check the tests can tell the difference. Returns
  one verdict: ``verified``, ``passed_unexercised``, ``regressed`` or ``unverifiable``.

Everything that executes repository code goes through :class:`~quanta.verify.sandbox.Sandbox`.
"""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from quanta.verify.plan import install_plan
from quanta.verify.sandbox import Sandbox, outcomes, write_json
from quanta.verify.trace import check, read_trace

#: A swap to another member of the same family, for site mutation (Master Plan 25.7).
_SWAPS = {"sha256": "sha512", "SHA256": "SHA512", "sha512": "sha256", "SHA512": "SHA256"}


@dataclass
class Verdict:
    verdict: str
    reasons: list[str]
    details: dict[str, Any] = field(default_factory=dict)

    def public(self) -> dict[str, Any]:
        return {"verdict": self.verdict, "reasons": self.reasons, **self.details}


def trace_check(root: Path, cdg: dict[str, Any], out: Path, name: str) -> dict[str, Any]:
    """Install, run the tests once traced, and compare with the static inventory."""
    plan = install_plan(root)
    report: dict[str, Any] = {"install_rule": plan.rule, "extras": plan.extras}
    if not plan.possible or plan.command is None:
        report.update({"status": "unverifiable", "reason": plan.reason or plan.rule})
        write_json(out / "trace.json", report)
        return report
    sandbox = Sandbox(name, root, out)
    ok, tail = sandbox.install(plan.command)
    if not ok:
        report.update({"status": "unverifiable", "reason": "install failed", "log": tail[-800:]})
        write_json(out / "trace.json", report)
        return report
    traced = sandbox.run_tests("T1", trace=True)
    if traced.trace is None or not traced.trace.is_file():
        # A missing trace is not "the tests ran no crypto"; it is no measurement at all.
        report.update(
            {
                "status": "unverifiable",
                "reason": "the test run produced no trace",
                "log": traced.log_tail[-800:],
            }
        )
        write_json(out / "trace.json", report)
        return report
    plain = sandbox.run_tests("B1")
    counts = outcomes(traced.junit)
    result = check(read_trace(traced.trace), cdg)
    report.update(
        {
            "status": "done",
            "tests": {
                "passed": sum(v == "passed" for v in counts.values()),
                "failed": sum(v == "failed" for v in counts.values()),
                "skipped": sum(v == "skipped" for v in counts.values()),
            },
            "seconds": {"traced": traced.seconds, "untraced": plain.seconds},
            **result.public(),
        }
    )
    write_json(out / "trace.json", report)
    return report


def _changed_lines(original: str, updated: str) -> list[int]:
    """New-side line numbers that differ, from a plain line diff."""
    import difflib

    lines: list[int] = []
    matcher = difflib.SequenceMatcher(a=original.splitlines(), b=updated.splitlines())
    for tag, _i1, _i2, j1, j2 in matcher.get_opcodes():
        if tag in {"replace", "insert"}:
            lines.extend(range(j1 + 1, j2 + 1))
    return lines


def verify_changes(
    root: Path,
    files: list[dict[str, str]],
    out: Path,
    name: str,
    *,
    compatibility_changing: bool = True,
) -> Verdict:
    """Verify ``files`` (``{"path", "content"}``) against the project's own tests."""
    plan = install_plan(root)
    if not plan.possible or plan.command is None:
        return Verdict("unverifiable", [f"no install method: {plan.reason or plan.rule}"])
    sandbox = Sandbox(name, root, out)
    ok, tail = sandbox.install(plan.command)
    if not ok:
        return Verdict("unverifiable", ["installation failed"], {"install_log": tail[-800:]})

    with tempfile.TemporaryDirectory(prefix="quanta-overlay-") as tmp:
        overlay = Path(tmp)
        changed: dict[str, list[int]] = {}
        for file in files:
            target = overlay / file["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(file["content"], encoding="utf-8", newline="")
            original = (root / file["path"]).read_text(encoding="utf-8")
            changed[file["path"]] = _changed_lines(original, file["content"])
        runs = {n: sandbox.run_tests(n) for n in ("B1", "B2")}
        runs.update({n: sandbox.run_tests(n, overlay=overlay) for n in ("P1", "P2")})
        runs["C1"] = sandbox.run_tests("C1", overlay=overlay, coverage_files=sorted(changed))
        b1, b2, p1, p2 = (outcomes(runs[n].junit) for n in ("B1", "B2", "P1", "P2"))
        stable = sorted(t for t, v in b1.items() if v == "passed" and b2.get(t) == "passed")
        regressions = sorted(
            t for t in stable if not (p1.get(t) == "passed" and p2.get(t) == "passed")
        )
        unexecuted = _unexecuted(out / "coverage-C1.json", changed)
        mutants: list[dict[str, Any]] = []
        if compatibility_changing and stable and not regressions:
            mutants = _site_mutation(sandbox, files, overlay, changed, stable)

    details: dict[str, Any] = {
        "install_rule": plan.rule,
        "stable_pass": len(stable),
        "regressions": regressions,
        "unexecuted_changed_lines": unexecuted,
        "site_mutants": mutants,
        "runs": [r.public() for r in runs.values()],
    }
    if not stable:
        verdict = Verdict("unverifiable", ["no test passed twice before the change"], details)
    elif regressions:
        verdict = Verdict(
            "regressed", [f"{len(regressions)} test(s) passed before and failed after"], details
        )
    else:
        reasons = []
        if unexecuted is None:
            reasons.append("changed-line coverage was not available")
        elif unexecuted:
            reasons.append(f"{len(unexecuted)} changed line(s) never ran")
        survived = [m for m in mutants if not m["killed"]]
        if compatibility_changing and survived:
            reasons.append(
                f"{len(survived)} algorithm swap(s) at changed sites were not detected by any "
                "test; the tests cannot see this change"
            )
        verdict = (
            Verdict("passed_unexercised", reasons, details)
            if reasons
            else Verdict(
                "verified", ["no regression; all changed lines ran; all checks passed"], details
            )
        )
    write_json(out / "verification.json", verdict.public())
    return verdict


def _unexecuted(coverage: Path, changed: dict[str, list[int]]) -> list[str] | None:
    if not coverage.is_file():
        return None
    data = json.loads(coverage.read_text(encoding="utf-8"))
    missing: list[str] = []
    for path, lines in changed.items():
        info = next(
            (v for k, v in data.get("files", {}).items() if k.replace("\\", "/").endswith(path)),
            None,
        )
        if info is None:
            missing += [f"{path}:{n}" for n in lines]
            continue
        executable = set(info.get("executed_lines", [])) | set(info.get("missing_lines", []))
        missing += [f"{path}:{n}" for n in lines if n in executable and n in info["missing_lines"]]
    return missing


def _site_mutation(
    sandbox: Sandbox,
    files: list[dict[str, str]],
    overlay: Path,
    changed: dict[str, list[int]],
    stable: list[str],
) -> list[dict[str, Any]]:
    """Swap the algorithm on each changed line once; killed when a stable test fails."""
    results: list[dict[str, Any]] = []
    for file in files:
        lines = file["content"].splitlines(keepends=True)
        for number in changed[file["path"]]:
            text = lines[number - 1]
            swap = next((old for old in _SWAPS if old in text), None)
            if swap is None:
                continue
            mutated = [*lines]
            mutated[number - 1] = text.replace(swap, _SWAPS[swap], 1)
            target = overlay / file["path"]
            target.write_text("".join(mutated), encoding="utf-8", newline="")
            run = sandbox.run_tests(f"M{len(results) + 1}", overlay=overlay)
            target.write_text(file["content"], encoding="utf-8", newline="")
            after = outcomes(run.junit)
            killed = any(after.get(t) != "passed" for t in stable)
            results.append(
                {
                    "file": file["path"],
                    "line": number,
                    "swap": f"{swap}->{_SWAPS[swap]}",
                    "killed": killed,
                }
            )
    return results
