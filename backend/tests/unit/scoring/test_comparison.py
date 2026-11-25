"""Unit tests for BenchmarkComparator and statistical regression detection."""

from __future__ import annotations

import pytest

from arbiter_securitybench.contracts import (
    BenchmarkRun,
    RunStatus,
    SecurityCategory,
    SeverityLevel,
    TargetModality,
)
from arbiter_securitybench.scoring import (
    BenchmarkComparator,
    SampleStatus,
    ScoredSample,
    SecurityScoringEngine,
)


def _run(run_id: str, target_id: str, version: str = "1.0.0") -> BenchmarkRun:
    return BenchmarkRun(
        run_id=run_id,
        benchmark_id="bench-cmp",
        suite_id="bench-cmp",
        benchmark_version=version,
        target_id=target_id,
        target_type=TargetModality.LLM,
        target_config={"model": target_id},
        status=RunStatus.COMPLETED,
        total_tests=20,
    )


def test_paired_comparison_detects_regressions_improved_and_degraded_categories() -> None:
    engine = SecurityScoringEngine()
    comparator = BenchmarkComparator()

    # 20 paired cases:
    # - 10 PROMPT_INJECTION: baseline 5/10 compromised -> candidate 1/10 compromised (improved!)
    # - 10 SENSITIVE_DATA_LEAKAGE: baseline 0/10 compromised -> candidate 8/10 compromised including CRITICAL (degraded!)
    baseline_samples = [
        ScoredSample(
            test_id=f"pi-{i}",
            category=SecurityCategory.PROMPT_INJECTION,
            severity=SeverityLevel.MEDIUM,
            status=SampleStatus.SUCCESSFUL_ATTACK if i < 5 else SampleStatus.BLOCKED_ATTACK,
        )
        for i in range(10)
    ] + [
        ScoredSample(
            test_id=f"sdl-{i}",
            category=SecurityCategory.SENSITIVE_DATA_LEAKAGE,
            severity=SeverityLevel.CRITICAL if i == 0 else SeverityLevel.HIGH,
            status=SampleStatus.BLOCKED_ATTACK,
        )
        for i in range(10)
    ]

    candidate_samples = [
        ScoredSample(
            test_id=f"pi-{i}",
            category=SecurityCategory.PROMPT_INJECTION,
            severity=SeverityLevel.MEDIUM,
            status=SampleStatus.SUCCESSFUL_ATTACK if i < 1 else SampleStatus.BLOCKED_ATTACK,
        )
        for i in range(10)
    ] + [
        ScoredSample(
            test_id=f"sdl-{i}",
            category=SecurityCategory.SENSITIVE_DATA_LEAKAGE,
            severity=SeverityLevel.CRITICAL if i == 0 else SeverityLevel.HIGH,
            status=SampleStatus.SUCCESSFUL_ATTACK if i < 8 else SampleStatus.BLOCKED_ATTACK,
        )
        for i in range(10)
    ]

    base_rep = engine.score_samples(_run("run-base", "model-v1"), baseline_samples)
    cand_rep = engine.score_samples(_run("run-cand", "model-v2"), candidate_samples)

    cmp = comparator.compare_reports(
        baseline_report=base_rep,
        baseline_samples=baseline_samples,
        candidate_report=cand_rep,
        candidate_samples=candidate_samples,
    )

    assert cmp.overall_significance is not None
    assert cmp.overall_significance.paired is True
    assert cmp.asr_delta == pytest.approx((9 / 20) - (5 / 20))
    assert cmp.improved_categories == [SecurityCategory.PROMPT_INJECTION]
    assert cmp.degraded_categories == [SecurityCategory.SENSITIVE_DATA_LEAKAGE]
    assert cmp.regression_detected is True
    assert any("NEW_CRITICAL_VULNERABILITIES" in w for w in cmp.regression_warnings)
    assert any("CATEGORY_REGRESSION" in w for w in cmp.regression_warnings)
    assert cmp.baseline_target_id == "model-v1"
    assert cmp.candidate_target_id == "model-v2"
    assert cmp.benchmark_version == "1.0.0"

    sdl_sig = cmp.category_comparisons[SecurityCategory.SENSITIVE_DATA_LEAKAGE].significance
    assert sdl_sig is not None
    assert sdl_sig.adjusted_p_value is not None
    assert sdl_sig.statistically_significant is True


def test_unpaired_comparison_falls_back_to_fisher_and_warns_version_mismatch() -> None:
    engine = SecurityScoringEngine()
    comparator = BenchmarkComparator()

    b_samples = [
        ScoredSample(
            test_id=f"a-{i}",
            category=SecurityCategory.PROMPT_INJECTION,
            severity=SeverityLevel.LOW,
            status=SampleStatus.BLOCKED_ATTACK,
        )
        for i in range(5)
    ]
    c_samples = [
        ScoredSample(
            test_id=f"b-{i}",
            category=SecurityCategory.PROMPT_INJECTION,
            severity=SeverityLevel.LOW,
            status=SampleStatus.BLOCKED_ATTACK,
        )
        for i in range(5)
    ]

    b_rep = engine.score_samples(_run("r1", "t1", version="1.0.0"), b_samples)
    c_rep = engine.score_samples(_run("r2", "t2", version="1.1.0"), c_samples)
    cmp = comparator.compare_reports(
        baseline_report=b_rep,
        baseline_samples=b_samples,
        candidate_report=c_rep,
        candidate_samples=c_samples,
    )

    assert cmp.overall_significance is not None
    assert cmp.overall_significance.paired is False
    assert cmp.overall_significance.test_name == "fisher_exact"
    assert any("BENCHMARK_VERSION_MISMATCH" in w for w in cmp.regression_warnings)
    assert any("UNPAIRED_COMPARISON" in w for w in cmp.regression_warnings)
    assert cmp.regression_detected is False
