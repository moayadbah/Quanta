"""The worked example of Master Plan 8.8, as direct function calls, to 6 decimals."""

from __future__ import annotations

from quanta.core.metric_v2 import MetricInputs, f_config, f_isolation, f_propagation, f_sites

SCATTERED = {"backup": 1, "integrity": 1, "passwords": 1, "sessions": 3, "store": 1, "tokens": 1}


def _score(values: tuple[float, float, float, float]) -> float:
    weights = (0.30, 0.30, 0.20, 0.20)
    return 100.0 * sum(w * v for w, v in zip(weights, values, strict=True))


def test_factor_values_of_the_worked_example() -> None:
    assert round(f_sites(8), 6) == 0.511707
    assert round(f_isolation(SCATTERED), 6) == 0.21875
    assert round(f_propagation(14, 6, 2), 6) == 0.428571
    assert round(f_propagation(14, 1, 6), 6) == 0.5
    assert round(f_config(4, 4), 6) == 0.5
    assert f_config(0, 8) == 0.0


def test_totals_of_the_worked_example() -> None:
    scattered = _score((f_sites(8), f_isolation(SCATTERED), 0.0, f_propagation(14, 6, 2)))
    facade = _score((f_sites(8), f_isolation({"cryptobox": 8}), 0.0, f_propagation(14, 1, 6)))
    configured = _score(
        (f_sites(8), f_isolation({"cryptobox": 8}), f_config(4, 4), f_propagation(14, 1, 6))
    )
    assert round(scattered, 4) == 30.4851
    assert round(facade, 4) == 55.3512
    assert round(configured, 4) == 65.3512


def test_isolation_is_one_for_a_single_module_and_one_over_k_for_an_even_spread() -> None:
    assert f_isolation({"crypto": 5}) == 1.0
    assert round(f_isolation({"a": 2, "b": 2, "c": 2}), 6) == round(1 / 3, 6)


def test_factors_stay_in_the_unit_interval() -> None:
    for n in (0, 1, 10, 10_000):
        assert 0.0 < f_sites(n) <= 1.0
    assert f_propagation(0, 0, 0) == 1.0
    inputs = MetricInputs({"a": 1}, 0, 1, frozenset({"a", "b"}), frozenset({"a"}), frozenset())
    assert inputs.n == 1
