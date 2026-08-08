"""CDG construction and Agility Score computation (DoD-C3, DoD-C4)."""

from __future__ import annotations

import math
from pathlib import Path

import networkx as nx
import pytest

from quanta.config import Settings
from quanta.core.detect import DetectionResult, detect_repository
from quanta.core.graph import (
    build_cdg,
    crypto_nodes,
    from_node_link,
    isolation_cut_size,
    to_node_link,
)
from quanta.core.ingest import walk_repository
from quanta.core.models import Coverage, Provenance, dump_canonical_json
from quanta.core.score import compute_score, factor_config, factor_propagation, factor_sites

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "repos"

PROVENANCE = Provenance(
    repo="owner/name",
    commit_sha="a" * 40,
    analyzer_version="0.1.0",
    crypto_ruleset_version="2026.08.01",
)


def analyse(name: str) -> tuple[DetectionResult, nx.DiGraph]:
    repo = FIXTURES / name
    detection = detect_repository(walk_repository(repo).files, repo)
    return detection, build_cdg(detection)


def score_of(name: str) -> object:
    detection, graph = analyse(name)
    coverage = Coverage(
        files_scanned=detection.files_scanned, files_unparseable=len(detection.unparseable)
    )
    return compute_score(detection, graph, PROVENANCE, coverage)


# ---------------------------------------------------------------------------------------
# CDG structure (DoD-C3)
# ---------------------------------------------------------------------------------------


def test_cdg_round_trips_through_node_link() -> None:
    _detection, graph = analyse("facade_crypto")
    restored = from_node_link(to_node_link(graph))

    assert restored.number_of_nodes() == graph.number_of_nodes()
    assert restored.number_of_edges() == graph.number_of_edges()
    assert set(restored.nodes) == set(graph.nodes)
    assert set(restored.edges) == set(graph.edges)


def test_every_call_edge_is_low_confidence() -> None:
    """DoD-C3. One-hop qualified-name resolution approximates value flow; "low" is honest."""
    for name in ("hardcoded_crypto", "configured_crypto", "facade_crypto", "no_crypto"):
        _detection, graph = analyse(name)
        for source, target, data in graph.edges(data=True):
            if data["kind"] == "call":
                assert data["confidence"] == "low", f"{name}: {source}->{target}"


def test_non_call_edges_are_high_confidence() -> None:
    _detection, graph = analyse("facade_crypto")
    for _s, _t, data in graph.edges(data=True):
        if data["kind"] in {"binding", "value_flow", "import"}:
            assert data["confidence"] == "high"


def test_graph_build_is_byte_identical_across_runs() -> None:
    """DoD-C3 requires determinism across three runs."""
    payloads = [dump_canonical_json(to_node_link(analyse("facade_crypto")[1])) for _ in range(3)]
    assert payloads[0] == payloads[1] == payloads[2]


def test_import_edges_connect_repository_modules() -> None:
    _detection, graph = analyse("facade_crypto")
    imports = [(s, t) for s, t, d in graph.edges(data=True) if d["kind"] == "import"]
    assert len(imports) == 1, "src.app imports src.crypto_facade"


def test_third_party_imports_are_not_invented_as_nodes() -> None:
    """Only modules inside the repository become nodes; cryptography itself must not."""
    _detection, graph = analyse("facade_crypto")
    names = {d["qualified_name"] for _n, d in graph.nodes(data=True) if d["kind"] == "module"}
    assert names == {"src.app", "src.crypto_facade"}


def test_call_edges_link_application_code_to_the_facade() -> None:
    _detection, graph = analyse("facade_crypto")
    calls = [(s, t) for s, t, d in graph.edges(data=True) if d["kind"] == "call"]
    assert len(calls) == 6, "six app functions call three facade functions"


def test_ambiguous_callees_are_dropped_not_guessed(tmp_path: Path) -> None:
    """§5.3.2: unresolvable targets are NOT guessed."""
    root = tmp_path / "repo"
    (root / "a").mkdir(parents=True)
    (root / "b").mkdir()
    for pkg in ("a", "b"):
        (root / pkg / "m.py").write_text("def helper():\n    return 1\n")
    (root / "c.py").write_text("import m\n\n\ndef go():\n    return m.helper()\n")

    detection = detect_repository(walk_repository(root).files, root)
    graph = build_cdg(detection)
    calls = [(s, t) for s, t, d in graph.edges(data=True) if d["kind"] == "call"]
    assert calls == [], "m.helper is ambiguous between a.m and b.m, so no edge is emitted"


def test_crypto_sites_attach_to_their_enclosing_function() -> None:
    detection, graph = analyse("hardcoded_crypto")
    site = next(s for s in detection.crypto_calls if s.line == 16)
    predecessors = [graph.nodes[p]["qualified_name"] for p in graph.predecessors(site.site_id)]
    assert "src.auth.legacy_digest" in predecessors


def test_selectors_flow_into_the_call_they_configure() -> None:
    detection, graph = analyse("facade_crypto")
    literal = detection.algo_literals[0]
    assert literal.parent_site_id in set(graph.successors(literal.site_id))


# ---------------------------------------------------------------------------------------
# Isolation
# ---------------------------------------------------------------------------------------


def test_isolation_cut_is_smaller_for_a_facade_than_for_scattered_crypto() -> None:
    facade_cut, _ = isolation_cut_size(analyse("facade_crypto")[1])
    scattered_cut, _ = isolation_cut_size(analyse("hardcoded_crypto")[1])
    assert facade_cut < scattered_cut


def test_repository_without_crypto_reports_disconnected() -> None:
    cut, disconnected = isolation_cut_size(analyse("no_crypto")[1])
    assert (cut, disconnected) == (0, True)


def test_a_self_contained_crypto_module_is_a_minimal_cut(tmp_path: Path) -> None:
    """Crypto confined to one module nothing else imports is the ideal insulation layer.

    Removing that single module decouples cryptography from everything else, so the cut
    is 1 — the strongest non-trivial isolation the metric can report.
    """
    root = tmp_path / "repo"
    root.mkdir()
    (root / "lonely.py").write_text("import hashlib\nhashlib.sha1(b'')\n")
    (root / "other.py").write_text("def unrelated():\n    return 1\n")

    detection = detect_repository(walk_repository(root).files, root)
    cut, disconnected = isolation_cut_size(build_cdg(detection))
    assert disconnected is False
    assert cut == 1


# ---------------------------------------------------------------------------------------
# Factors (§5.3.3)
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(("count", "expected"), [(0, 1.0), (1, 1 / (1 + math.log10(2)))])
def test_factor_sites_matches_the_published_formula(count: int, expected: float) -> None:
    graph: nx.DiGraph = nx.DiGraph()
    for i in range(count):
        graph.add_node(f"c{i}", kind="crypto_call")
    assert factor_sites(graph).normalised == pytest.approx(expected)


def test_factor_sites_decreases_monotonically() -> None:
    values = []
    for count in (1, 5, 20, 100, 500):
        graph: nx.DiGraph = nx.DiGraph()
        for i in range(count):
            graph.add_node(f"c{i}", kind="crypto_call")
        values.append(factor_sites(graph).normalised)
    assert values == sorted(values, reverse=True)


def test_factor_config_rewards_configuration_over_literals() -> None:
    configured = factor_config(analyse("configured_crypto")[0]).normalised
    hardcoded = factor_config(analyse("hardcoded_crypto")[0]).normalised
    assert configured > hardcoded
    assert hardcoded == 0.0


def test_factor_config_is_neutral_when_nothing_selects_an_algorithm() -> None:
    """No selectors must not manufacture a deduction against the repository."""
    value = factor_config(DetectionResult())
    assert value.normalised == 1.0
    assert value.raw == "none"


def test_factor_propagation_is_clamped_into_the_unit_interval() -> None:
    for name in ("hardcoded_crypto", "configured_crypto", "facade_crypto", "no_crypto"):
        value = factor_propagation(analyse(name)[1])
        assert 0.0 <= value.normalised <= 1.0


# ---------------------------------------------------------------------------------------
# Score assembly (DoD-C4)
# ---------------------------------------------------------------------------------------


def test_clean_repository_scores_one_hundred() -> None:
    score = score_of("no_crypto")
    assert score.agility_score == 100.0
    assert score.deductions == ()


def test_score_is_bounded_and_ordered_across_fixtures() -> None:
    scores = {
        name: score_of(name).agility_score
        for name in ("no_crypto", "configured_crypto", "facade_crypto", "hardcoded_crypto")
    }
    assert all(0.0 <= v <= 100.0 for v in scores.values())
    assert scores["no_crypto"] > scores["configured_crypto"]
    assert scores["configured_crypto"] > scores["hardcoded_crypto"]


def test_every_deduction_carries_a_citation() -> None:
    """PROC-08 / DoD-C4: a score without a traceable cause is a defect."""
    for name in ("hardcoded_crypto", "configured_crypto", "facade_crypto"):
        score = score_of(name)
        assert score.deductions
        for deduction in score.deductions:
            assert deduction.citations
            for citation in deduction.citations:
                path, _, line = citation.rpartition(":")
                assert path and line.isdigit()


def test_citations_point_at_real_files() -> None:
    detection, _graph = analyse("hardcoded_crypto")
    known = {f"{s.file}:{s.line}" for s in detection.sites}
    for deduction in score_of("hardcoded_crypto").deductions:
        assert set(deduction.citations) <= known


def test_contributions_sum_to_the_score() -> None:
    score = score_of("hardcoded_crypto")
    total = sum(f.contribution for f in score.factors.values())
    assert score.agility_score == pytest.approx(total, abs=0.01)


def test_weights_come_from_the_pre_registered_set() -> None:
    score = score_of("hardcoded_crypto")
    assert score.factors["call_sites"].weight == 0.30
    assert score.factors["isolation_layer"].weight == 0.30
    assert score.factors["selection_source"].weight == 0.20
    assert score.factors["propagation_depth"].weight == 0.20


def test_weights_must_sum_to_one() -> None:
    """§11.2 forbids silent renormalisation — a bad weight set must fail loudly."""
    settings = Settings()
    settings.weights.f_sites = 0.5
    with pytest.raises(ValueError, match=r"sum to 1\.00"):
        settings.weights.validate_sum()


def test_score_json_is_byte_identical_across_runs() -> None:
    """NFR-03."""
    payloads = [dump_canonical_json(score_of("hardcoded_crypto")) for _ in range(3)]
    assert payloads[0] == payloads[1] == payloads[2]


def test_weak_and_quantum_recommendations_appear() -> None:
    actions = " ".join(r.action for r in score_of("hardcoded_crypto").recommendations)
    assert "MD5" in actions or "weak" in actions.lower()
    assert "ML-KEM" in actions


def test_crypto_node_count_matches_detected_call_sites() -> None:
    detection, graph = analyse("hardcoded_crypto")
    assert len(crypto_nodes(graph)) == len(detection.crypto_calls)
