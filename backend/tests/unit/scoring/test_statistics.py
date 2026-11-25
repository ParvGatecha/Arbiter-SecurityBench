"""Unit tests validating statistical confidence intervals and significance tests."""

from __future__ import annotations

import math

import pytest

from arbiter_securitybench.statistics import (
    bootstrap_confidence_interval,
    fisher_exact_test,
    holm_bonferroni_adjust,
    mcnemar_exact_test,
    wilson_confidence_interval,
)


def test_wilson_confidence_interval_matches_manual_calculation() -> None:
    # Manual Wilson calculation for k=3, n=10, z=1.959963984540054 (95%):
    k, n = 3, 10
    z = 1.959963984540054
    p = k / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p + z2 / (2.0 * n)) / denom
    margin = (z / denom) * math.sqrt((p * (1.0 - p)) / n + z2 / (4.0 * n * n))

    ci = wilson_confidence_interval(k, n, confidence_level=0.95)
    assert ci is not None
    assert ci.estimate == pytest.approx(0.3)
    assert ci.lower == pytest.approx(center - margin, rel=1e-6)
    assert ci.upper == pytest.approx(center + margin, rel=1e-6)

    # Edge cases: n=0, k=0, k=n
    assert wilson_confidence_interval(0, 0) is None
    ci_zero = wilson_confidence_interval(0, 10)
    assert ci_zero is not None
    assert ci_zero.lower == 0.0
    assert 0.0 < ci_zero.upper < 0.35

    ci_one = wilson_confidence_interval(10, 10)
    assert ci_one is not None
    assert ci_one.upper == 1.0
    assert 0.65 < ci_one.lower < 1.0


def test_bootstrap_confidence_interval_determinism_and_edge_cases() -> None:
    assert bootstrap_confidence_interval([]) is None

    ci_const = bootstrap_confidence_interval([1.0, 1.0, 1.0, 1.0])
    assert ci_const is not None
    assert ci_const.lower == 1.0
    assert ci_const.upper == 1.0

    vals = [1.0, 0.0, 1.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0]
    weights = [10.0, 1.0, 6.0, 1.0, 3.0, 6.0, 1.0, 3.0, 1.0, 10.0]
    ci1 = bootstrap_confidence_interval(vals, weights=weights, seed=123)
    ci2 = bootstrap_confidence_interval(vals, weights=weights, seed=123)
    assert ci1 == ci2
    assert ci1 is not None
    assert ci1.lower <= ci1.estimate <= ci1.upper


def test_mcnemar_fisher_and_holm_bonferroni() -> None:
    # Paired discordant: n01=12, n10=2 -> exact two-sided binomial p = 2 * sum_{i=0..2} C(14, i) * 0.5^14
    expected_p = 2.0 * sum(math.comb(14, i) for i in range(3)) * (0.5**14)
    base = [0] * 12 + [1] * 2 + [0] * 6
    cand = [1] * 12 + [0] * 2 + [0] * 6
    sig = mcnemar_exact_test(base, cand)
    assert sig.paired is True
    assert sig.p_value == pytest.approx(expected_p, rel=1e-6)
    assert sig.statistically_significant is True
    assert sig.effect_size == pytest.approx((12 - 2) / 20)

    # Zero discordant pairs
    sig_same = mcnemar_exact_test([0, 1, 0], [0, 1, 0])
    assert sig_same.p_value == 1.0
    assert sig_same.statistically_significant is False

    # Fisher exact test
    fisher = fisher_exact_test(1, 20, 10, 20)
    assert fisher.paired is False
    assert fisher.statistically_significant is True

    # Holm-Bonferroni manual verification: raw [0.01, 0.04, 0.03] -> sorted [0.01, 0.03, 0.04]
    # multipliers [3, 2, 1] -> [0.03, 0.06, 0.06] -> mapped back [0.03, 0.06, 0.06]
    adj = holm_bonferroni_adjust([0.01, 0.04, 0.03])
    assert adj == pytest.approx([0.03, 0.06, 0.06])
