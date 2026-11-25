"""Hypothesis testing and multiple-comparison adjustments using SciPy and NumPy."""

from __future__ import annotations

import numpy as np
from pydantic import BaseModel, ConfigDict, Field
from scipy import stats


class SignificanceTestOutput(BaseModel):
    """Result of a statistical significance test comparing two benchmark runs."""

    model_config = ConfigDict(frozen=True)

    test_name: str
    comparison_label: str
    statistic: float
    p_value: float = Field(ge=0.0, le=1.0)
    adjusted_p_value: float | None = Field(default=None, ge=0.0, le=1.0)
    alpha: float = Field(gt=0.0, lt=1.0)
    statistically_significant: bool
    effect_size: float | None = None
    sample_size: int = Field(ge=0)
    paired: bool
    notes: str | None = None


def mcnemar_exact_test(
    baseline_outcomes: list[int] | np.ndarray,
    candidate_outcomes: list[int] | np.ndarray,
    *,
    comparison_label: str = "overall_asr",
    alpha: float = 0.05,
) -> SignificanceTestOutput:
    """Exact paired McNemar binomial test for two binary outcome vectors (0 or 1)."""
    base = np.asarray(baseline_outcomes, dtype=np.int64)
    cand = np.asarray(candidate_outcomes, dtype=np.int64)
    if base.shape != cand.shape:
        raise ValueError("Paired McNemar test requires equal-length outcome arrays.")
    if base.size == 0:
        return SignificanceTestOutput(
            test_name="mcnemar_exact",
            comparison_label=comparison_label,
            statistic=0.0,
            p_value=1.0,
            alpha=alpha,
            statistically_significant=False,
            effect_size=0.0,
            sample_size=0,
            paired=True,
            notes="Empty sample; significance test skipped.",
        )

    # Discordant pairs: n01 (baseline=0, candidate=1), n10 (baseline=1, candidate=0)
    n01 = int(np.sum((base == 0) & (cand == 1)))
    n10 = int(np.sum((base == 1) & (cand == 0)))
    n_discordant = n01 + n10
    risk_diff = float(np.mean(cand) - np.mean(base))

    if n_discordant == 0:
        return SignificanceTestOutput(
            test_name="mcnemar_exact",
            comparison_label=comparison_label,
            statistic=0.0,
            p_value=1.0,
            alpha=alpha,
            statistically_significant=False,
            effect_size=risk_diff,
            sample_size=int(base.size),
            paired=True,
            notes="Zero discordant pairs between baseline and candidate.",
        )

    res = stats.binomtest(min(n01, n10), n=n_discordant, p=0.5, alternative="two-sided")
    p_val = float(res.pvalue)
    return SignificanceTestOutput(
        test_name="mcnemar_exact",
        comparison_label=comparison_label,
        statistic=float(abs(n01 - n10)),
        p_value=p_val,
        alpha=alpha,
        statistically_significant=p_val < alpha,
        effect_size=risk_diff,
        sample_size=int(base.size),
        paired=True,
        notes=f"Discordant pairs: degraded(0->1)={n01}, improved(1->0)={n10}.",
    )


def fisher_exact_test(
    baseline_successes: int,
    baseline_total: int,
    candidate_successes: int,
    candidate_total: int,
    *,
    comparison_label: str = "overall_asr",
    alpha: float = 0.05,
) -> SignificanceTestOutput:
    """Two-sided Fisher's exact test for unpaired proportion comparison."""
    if baseline_total <= 0 or candidate_total <= 0:
        return SignificanceTestOutput(
            test_name="fisher_exact",
            comparison_label=comparison_label,
            statistic=1.0,
            p_value=1.0,
            alpha=alpha,
            statistically_significant=False,
            effect_size=None,
            sample_size=max(0, baseline_total) + max(0, candidate_total),
            paired=False,
            notes="Zero sample size in one or both runs; significance test skipped.",
        )

    b_fail = baseline_total - baseline_successes
    c_fail = candidate_total - candidate_successes
    table = np.array([[baseline_successes, b_fail], [candidate_successes, c_fail]], dtype=np.int64)
    odds_ratio, p_val = stats.fisher_exact(table, alternative="two-sided")
    risk_diff = (candidate_successes / candidate_total) - (baseline_successes / baseline_total)

    return SignificanceTestOutput(
        test_name="fisher_exact",
        comparison_label=comparison_label,
        statistic=float(odds_ratio) if np.isfinite(odds_ratio) else float("inf"),
        p_value=float(p_val),
        alpha=alpha,
        statistically_significant=bool(p_val < alpha),
        effect_size=float(risk_diff),
        sample_size=baseline_total + candidate_total,
        paired=False,
        notes="Unpaired comparison (test suites or executed sample IDs differ).",
    )


def holm_bonferroni_adjust(p_values: list[float]) -> list[float]:
    """Adjust p-values using Holm-Bonferroni step-down FWER control."""
    m = len(p_values)
    if m == 0:
        return []
    indexed = sorted(enumerate(p_values), key=lambda pair: pair[1])
    adjusted = [0.0] * m
    running_max = 0.0
    for rank, (orig_idx, p_val) in enumerate(indexed):
        scaled = min(1.0, p_val * (m - rank))
        running_max = max(running_max, scaled)
        adjusted[orig_idx] = running_max
    return adjusted
