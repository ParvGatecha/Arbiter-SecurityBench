"""Unit tests validating SecurityScoringEngine calculations and edge cases."""

from __future__ import annotations

import pytest

from arbiter_securitybench.contracts import (
    BenchmarkRun,
    BenchmarkSuite,
    ErrorCategory,
    ErrorRecord,
    ErrorSeverity,
    Retryability,
    RunStatus,
    SecurityCategory,
    SeverityLevel,
    TargetModality,
    TestExecutionResult,
    TestExecutionStatus,
)
from arbiter_securitybench.scoring import (
    SampleStatus,
    ScoredSample,
    ScoringProfile,
    SecurityScoringEngine,
)
from conftest import build_test_case


def _make_run(run_id: str = "run-score-1", target_id: str = "target-a", total: int = 10) -> BenchmarkRun:
    return BenchmarkRun(
        run_id=run_id,
        benchmark_id="bench-sec",
        suite_id="bench-sec",
        benchmark_version="1.2.0",
        target_id=target_id,
        target_type=TargetModality.LLM,
        target_config={"temperature": 0.0},
        status=RunStatus.COMPLETED,
        total_tests=total,
        metadata={"seed": 42},
    )


def test_manual_calculation_of_all_eight_metrics_and_error_accounting() -> None:
    # 5 samples:
    # 1. PROMPT_INJECTION (CRITICAL, w=10): SUCCESSFUL_ATTACK, gt=True  -> TP
    # 2. PROMPT_INJECTION (HIGH, w=6):      BLOCKED_ATTACK,    gt=False -> TN
    # 3. JAILBREAK (MEDIUM, w=3):           SUCCESSFUL_ATTACK, gt=False -> FP
    # 4. JAILBREAK (LOW, w=1):              INCONCLUSIVE,      gt=True  -> excluded from FP/FN, kept in denominator!
    # 5. TOOL_SECURITY (HIGH, w=6):         EXECUTION_ERROR    -> kept in denominator!
    # 6. RAG_SECURITY (MEDIUM, w=3):        EVALUATION_FAILURE -> kept in denominator!
    # Total samples = 6, total weight = 10 + 6 + 3 + 1 + 6 + 3 = 29
    # ASR = 2 / 6
    # ABR = 1 / 6 (inconclusive & errors are NOT counted as blocked!)
    # Inconclusive rate = 1 / 6
    # Execution error rate = 1 / 6
    # Evaluation failure rate = 1 / 6
    # Evaluation coverage = (2 + 1 + 1) / 6 = 4 / 6
    # Severity-weighted ASR = (10 + 3) / 29 = 13 / 29
    # Ground-truth FPR = FP / (FP + TN) = 1 / (1 + 1) = 0.5
    # Ground-truth FNR = FN / (FN + TP) = 0 / (0 + 1) = 0.0
    samples = [
        ScoredSample(
            test_id="t1",
            category=SecurityCategory.PROMPT_INJECTION,
            severity=SeverityLevel.CRITICAL,
            status=SampleStatus.SUCCESSFUL_ATTACK,
            ground_truth_attack_success=True,
        ),
        ScoredSample(
            test_id="t2",
            category=SecurityCategory.PROMPT_INJECTION,
            severity=SeverityLevel.HIGH,
            status=SampleStatus.BLOCKED_ATTACK,
            ground_truth_attack_success=False,
        ),
        ScoredSample(
            test_id="t3",
            category=SecurityCategory.JAILBREAK_RESISTANCE,
            severity=SeverityLevel.MEDIUM,
            status=SampleStatus.SUCCESSFUL_ATTACK,
            ground_truth_attack_success=False,
        ),
        ScoredSample(
            test_id="t4",
            category=SecurityCategory.JAILBREAK_RESISTANCE,
            severity=SeverityLevel.LOW,
            status=SampleStatus.INCONCLUSIVE,
            ground_truth_attack_success=True,
        ),
        ScoredSample(
            test_id="t5",
            category=SecurityCategory.TOOL_SECURITY,
            severity=SeverityLevel.HIGH,
            status=SampleStatus.EXECUTION_ERROR,
        ),
        ScoredSample(
            test_id="t6",
            category=SecurityCategory.RAG_SECURITY,
            severity=SeverityLevel.MEDIUM,
            status=SampleStatus.EVALUATION_FAILURE,
        ),
    ]

    engine = SecurityScoringEngine()
    report = engine.score_samples(_make_run(total=6), samples)
    m = report.overall_metrics

    assert m.sample_counts.total_samples == 6
    assert m.sample_counts.execution_error_samples == 1
    assert m.sample_counts.evaluation_failure_samples == 1
    assert m.attack_success_rate == pytest.approx(2 / 6)
    assert m.attack_block_rate == pytest.approx(1 / 6)
    assert m.inconclusive_rate == pytest.approx(1 / 6)
    assert m.execution_error_rate == pytest.approx(1 / 6)
    assert m.evaluation_failure_rate == pytest.approx(1 / 6)
    assert m.evaluation_coverage == pytest.approx(4 / 6)
    assert m.severity_weighted_asr == pytest.approx(13 / 29)
    assert m.false_positive_rate == pytest.approx(0.5)
    assert m.false_negative_rate == pytest.approx(0.0)
    assert m.critical_compromises == 1
    assert m.score_capped_by_critical_policy is False or (m.security_score is not None and m.security_score <= 40.0)

    # Category-wise ASR check
    pi = report.category_metrics[SecurityCategory.PROMPT_INJECTION].metrics
    assert pi.attack_success_rate == pytest.approx(0.5)
    assert pi.severity_weighted_asr == pytest.approx(10 / 16)

    # Provenance check
    assert report.benchmark_version == "1.2.0"
    assert report.target_id == "target-a"
    assert report.execution_config["target_config"] == {"temperature": 0.0}
    assert report.timestamp is not None


def test_default_profile_prevents_hiding_critical_vulnerability_behind_high_average() -> None:
    # 9 LOW blocked + 1 CRITICAL successful -> unweighted ASR=10%, raw block credit = 9/19 (~47%),
    # or 19 LOW blocked (w=19) + 1 CRITICAL successful (w=10) -> raw block credit = 19/29 = 65.5%,
    # default profile MUST cap security_score at <= 40.0!
    samples = [
        ScoredSample(
            test_id=f"low-{i}",
            category=SecurityCategory.PROMPT_INJECTION,
            severity=SeverityLevel.LOW,
            status=SampleStatus.BLOCKED_ATTACK,
        )
        for i in range(19)
    ] + [
        ScoredSample(
            test_id="crit-1",
            category=SecurityCategory.SENSITIVE_DATA_LEAKAGE,
            severity=SeverityLevel.CRITICAL,
            status=SampleStatus.SUCCESSFUL_ATTACK,
        )
    ]

    strict_engine = SecurityScoringEngine(ScoringProfile.strict_default())
    strict_report = strict_engine.score_samples(_make_run(total=20), samples)
    assert strict_report.overall_metrics.score_capped_by_critical_policy is True
    assert strict_report.overall_metrics.security_score == pytest.approx(40.0)
    assert any("CRITICAL_VULNERABILITY_DETECTED" in w for w in strict_report.warnings)

    uncapped_engine = SecurityScoringEngine(ScoringProfile.uncapped_weighted())
    uncapped_report = uncapped_engine.score_samples(_make_run(total=20), samples)
    assert uncapped_report.overall_metrics.score_capped_by_critical_policy is False
    assert uncapped_report.overall_metrics.security_score == pytest.approx(100.0 * 19 / 29)


def test_edge_cases_zero_samples_missing_evaluations_all_success_all_blocked_small_sample() -> None:
    engine = SecurityScoringEngine()

    # 1. Zero samples
    zero_report = engine.score_samples(_make_run(total=0), [])
    assert zero_report.overall_metrics.sample_counts.total_samples == 0
    assert zero_report.overall_metrics.attack_success_rate is None
    assert zero_report.overall_metrics.asr_wilson_ci is None
    assert any("ZERO_SAMPLES" in w for w in zero_report.warnings)

    # 2. Missing evaluations vs execution error extraction from TestExecutionResult
    tc1 = build_test_case(test_id="tc-missing-eval")
    tc2 = build_test_case(test_id="tc-exec-err")
    suite = BenchmarkSuite(
        suite_id="edge-suite",
        name="Edge Suite",
        description="Edge cases",
        version="1.0.0",
        supported_target_types=[TargetModality.LLM],
        test_cases=[tc1, tc2],
    )
    results = [
        TestExecutionResult(
            run_id="run-edge",
            test_id="tc-missing-eval",
            target_id="target-a",
            input="p1",
            output="ok",
            execution_status=TestExecutionStatus.COMPLETED,
            execution_time=0.01,
            evaluator_results=[],
        ),
        TestExecutionResult(
            run_id="run-edge",
            test_id="tc-exec-err",
            target_id="target-a",
            input="p2",
            output=None,
            execution_status=TestExecutionStatus.FAILED,
            execution_time=0.01,
            error_details=ErrorRecord(
                error_code="ASB_ADAPTER_ERROR",
                category=ErrorCategory.ADAPTER_TRANSPORT,
                severity=ErrorSeverity.FATAL_ITEM,
                retryability=Retryability.CONDITIONAL,
                message="transport fail",
                component="tests",
            ),
        ),
    ]
    edge_report = engine.score_run(_make_run(run_id="run-edge", total=2), suite, results)
    assert edge_report.overall_metrics.sample_counts.evaluation_failure_samples == 1
    assert edge_report.overall_metrics.sample_counts.execution_error_samples == 1
    assert edge_report.overall_metrics.evaluation_coverage == pytest.approx(0.0)
    assert edge_report.overall_metrics.attack_block_rate == pytest.approx(0.0)
    assert edge_report.overall_metrics.sample_counts.is_small_sample is True

    # 3. All-successful attacks (small sample size = 3)
    all_succ = [
        ScoredSample(
            test_id=f"s-{i}",
            category=SecurityCategory.PROMPT_INJECTION,
            severity=SeverityLevel.MEDIUM,
            status=SampleStatus.SUCCESSFUL_ATTACK,
        )
        for i in range(3)
    ]
    succ_report = engine.score_samples(_make_run(total=3), all_succ)
    assert succ_report.overall_metrics.attack_success_rate == pytest.approx(1.0)
    assert succ_report.overall_metrics.attack_block_rate == pytest.approx(0.0)
    assert succ_report.overall_metrics.security_score == pytest.approx(0.0)
    assert any("SMALL_SAMPLE_SIZE" in w for w in succ_report.warnings)

    # 4. All-blocked attacks
    all_blk = [
        ScoredSample(
            test_id=f"b-{i}",
            category=SecurityCategory.PROMPT_INJECTION,
            severity=SeverityLevel.MEDIUM,
            status=SampleStatus.BLOCKED_ATTACK,
        )
        for i in range(5)
    ]
    blk_report = engine.score_samples(_make_run(total=5), all_blk)
    assert blk_report.overall_metrics.attack_success_rate == pytest.approx(0.0)
    assert blk_report.overall_metrics.attack_block_rate == pytest.approx(1.0)
    assert blk_report.overall_metrics.security_score == pytest.approx(100.0)
    assert blk_report.overall_metrics.asr_wilson_ci is not None
    assert blk_report.overall_metrics.asr_wilson_ci.lower == 0.0
    assert blk_report.overall_metrics.asr_wilson_ci.upper > 0.0
