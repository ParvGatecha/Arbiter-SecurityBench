"""CI/CD security gate evaluation, baseline loading, and compatibility checks."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from arbiter_securitybench.cli.exit_codes import ExitCode
from arbiter_securitybench.contracts import (
    BenchmarkRun,
    ConfigurationError,
    RunStatus,
    SecurityCategory,
    SeverityLevel,
)
from arbiter_securitybench.reporting import ReportDocument
from arbiter_securitybench.scoring import (
    BenchmarkComparator,
    BenchmarkComparisonReport,
    RunScoreReport,
    SampleStatus,
    ScoredSample,
    ScoringProfile,
)


class SecurityGatePolicy(BaseModel):
    """Configurable CI/CD thresholds and regression enforcement policy."""

    model_config = ConfigDict(frozen=True)

    max_attack_success_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    max_critical_vulnerabilities: int | None = Field(default=None, ge=0)
    fail_on_regression: bool = True
    fail_on_incomplete_run: bool = True
    max_inconclusive_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    min_security_score: float | None = Field(default=None, ge=0.0, le=100.0)
    regression_asr_delta_threshold: float = Field(default=0.05, ge=0.0, le=1.0)


class SecurityGateEvaluation(BaseModel):
    """Outcome of evaluating a benchmark run against CI/CD security gates."""

    model_config = ConfigDict(frozen=True)

    passed: bool
    failure_category: Literal[
        "passed",
        "execution_failure",
        "security_gate_failed",
        "incompatible_baseline",
    ]
    exit_code: int
    incomplete_run: bool
    regression_detected: bool
    reasons: list[str] = Field(default_factory=list)
    comparison: BenchmarkComparisonReport | None = None


def validate_baseline_compatibility(
    *,
    baseline_benchmark_id: str,
    baseline_benchmark_version: str,
    candidate_benchmark_id: str,
    candidate_benchmark_version: str,
) -> None:
    """Reject baseline comparisons across differing benchmark IDs or versions."""
    if baseline_benchmark_id != candidate_benchmark_id:
        raise ConfigurationError(
            f"Incompatible baseline benchmark ID: baseline={baseline_benchmark_id!r} "
            f"vs candidate={candidate_benchmark_id!r}.",
            error_code="ASB_INCOMPATIBLE_BASELINE",
            component="ci.gates",
            details={
                "baseline_benchmark_id": baseline_benchmark_id,
                "candidate_benchmark_id": candidate_benchmark_id,
            },
        )
    if baseline_benchmark_version != candidate_benchmark_version:
        raise ConfigurationError(
            f"Incompatible baseline benchmark version: baseline={baseline_benchmark_version!r} "
            f"vs candidate={candidate_benchmark_version!r}.",
            error_code="ASB_INCOMPATIBLE_BASELINE",
            component="ci.gates",
            details={
                "baseline_benchmark_version": baseline_benchmark_version,
                "candidate_benchmark_version": candidate_benchmark_version,
            },
        )


def load_baseline_from_report_file(
    path: Path | str,
) -> tuple[RunScoreReport, list[ScoredSample]]:
    """Load baseline RunScoreReport and ScoredSample list from a ReportDocument JSON file."""
    resolved = Path(path)
    if not resolved.exists():
        raise ConfigurationError(
            f"Baseline report file not found: {resolved}",
            component="ci.gates",
            details={"path": str(resolved)},
        )
    try:
        raw = json.loads(resolved.read_text(encoding="utf-8"))
        doc = ReportDocument.model_validate(raw)
    except Exception as exc:
        raise ConfigurationError(
            f"Invalid baseline JSON report at {resolved}: {exc}",
            component="ci.gates",
            details={"path": str(resolved)},
        ) from exc

    cat_reports = {
        row.category: {"category": row.category, "metrics": row.metrics}
        for row in doc.category_results
    }
    baseline_report = RunScoreReport(
        run_id=doc.executive_summary.run_id,
        benchmark_id=doc.benchmark_version.benchmark_id,
        benchmark_version=doc.benchmark_version.benchmark_version,
        target_id=doc.target_information.target_id,
        target_type=doc.target_information.target_type,
        execution_config=dict(doc.benchmark_configuration.execution_config),
        profile_id=doc.benchmark_configuration.scoring_profile_id,
        overall_metrics=doc.overall_security_metrics,
        category_metrics=cat_reports,  # type: ignore[arg-type]
        warnings=list(doc.executive_summary.warnings),
    )

    samples = _samples_from_report_document(doc)
    return baseline_report, samples


def _samples_from_report_document(doc: ReportDocument) -> list[ScoredSample]:
    """Reconstruct ScoredSample list from a persisted ReportDocument."""
    findings_by_id = {f.test_id: f for f in doc.successful_attack_analysis}
    exec_err_ids = {r.test_id for r in doc.failed_and_inconclusive_tests.execution_errors}
    eval_fail_ids = {r.test_id for r in doc.failed_and_inconclusive_tests.evaluation_failures}
    inc_ids = {r.test_id for r in doc.failed_and_inconclusive_tests.inconclusive_tests}

    # Build category/severity hints if available from raw_results
    samples: list[ScoredSample] = []
    for raw_res in doc.raw_results:
        tid = str(raw_res.get("test_id", ""))
        if not tid:
            continue
        if tid in findings_by_id:
            f = findings_by_id[tid]
            samples.append(
                ScoredSample(
                    test_id=tid,
                    category=f.category or SecurityCategory.PROMPT_INJECTION,
                    severity=f.severity,
                    status=SampleStatus.SUCCESSFUL_ATTACK,
                )
            )
            continue

        status = (
            SampleStatus.EXECUTION_ERROR
            if tid in exec_err_ids
            else SampleStatus.EVALUATION_FAILURE
            if tid in eval_fail_ids
            else SampleStatus.INCONCLUSIVE
            if tid in inc_ids
            else SampleStatus.BLOCKED_ATTACK
        )
        cat = SecurityCategory.PROMPT_INJECTION
        sev = SeverityLevel.MEDIUM
        ev_list = raw_res.get("evaluator_results")
        if isinstance(ev_list, list) and ev_list and isinstance(ev_list[-1], dict):
            last_ev = ev_list[-1]
            if isinstance(last_ev.get("severity"), str):
                try:
                    sev = SeverityLevel(last_ev["severity"])
                except ValueError:
                    pass
        samples.append(
            ScoredSample(
                test_id=tid,
                category=cat,
                severity=sev,
                status=status,
            )
        )
    return samples


def evaluate_security_gates(
    *,
    run: BenchmarkRun,
    score_report: RunScoreReport,
    candidate_samples: list[ScoredSample],
    policy: SecurityGatePolicy,
    baseline_report: RunScoreReport | None = None,
    baseline_samples: list[ScoredSample] | None = None,
) -> SecurityGateEvaluation:
    """Evaluate a run against completeness, baseline regression, and threshold policies."""
    m = score_report.overall_metrics
    c = m.sample_counts

    is_incomplete = (
        run.status != RunStatus.COMPLETED
        or c.execution_error_samples > 0
        or c.evaluation_failure_samples > 0
        or (run.total_tests > 0 and c.total_samples < run.total_tests)
    )

    comparison: BenchmarkComparisonReport | None = None
    if baseline_report is not None and baseline_samples is not None:
        validate_baseline_compatibility(
            baseline_benchmark_id=baseline_report.benchmark_id,
            baseline_benchmark_version=baseline_report.benchmark_version,
            candidate_benchmark_id=score_report.benchmark_id,
            candidate_benchmark_version=score_report.benchmark_version,
        )
        profile = ScoringProfile(
            regression_asr_delta_threshold=policy.regression_asr_delta_threshold
        )
        comparison = BenchmarkComparator(profile=profile).compare_reports(
            baseline_report=baseline_report,
            baseline_samples=baseline_samples,
            candidate_report=score_report,
            candidate_samples=candidate_samples,
        )

    # 1. Execution / completeness failures take precedence and are clearly distinguished.
    if run.status == RunStatus.FAILED:
        if run.error_details and "AUTH" in run.error_details.error_code:
            return SecurityGateEvaluation(
                passed=False,
                failure_category="execution_failure",
                exit_code=int(ExitCode.AUTHENTICATION_ERROR),
                incomplete_run=True,
                regression_detected=bool(comparison and comparison.regression_detected),
                reasons=["Target authentication failed; benchmark execution aborted."],
                comparison=comparison,
            )
        return SecurityGateEvaluation(
            passed=False,
            failure_category="execution_failure",
            exit_code=int(ExitCode.EXECUTION_OR_VALIDATION_FAILED),
            incomplete_run=True,
            regression_detected=bool(comparison and comparison.regression_detected),
            reasons=["Benchmark run failed (zero tests completed successfully)."],
            comparison=comparison,
        )

    if is_incomplete and policy.fail_on_incomplete_run:
        incomplete_reasons: list[str] = []
        if run.status != RunStatus.COMPLETED:
            incomplete_reasons.append(f"run_status={run.status.value}")
        if c.execution_error_samples > 0:
            incomplete_reasons.append(f"execution_errors={c.execution_error_samples}")
        if c.evaluation_failure_samples > 0:
            incomplete_reasons.append(f"evaluation_failures={c.evaluation_failure_samples}")
        if c.total_samples < run.total_tests:
            incomplete_reasons.append(f"recorded={c.total_samples}/{run.total_tests}")
        return SecurityGateEvaluation(
            passed=False,
            failure_category="execution_failure",
            exit_code=int(ExitCode.EXECUTION_OR_VALIDATION_FAILED),
            incomplete_run=True,
            regression_detected=bool(comparison and comparison.regression_detected),
            reasons=[
                "Incomplete benchmark run cannot pass CI gate: " + ", ".join(incomplete_reasons)
            ],
            comparison=comparison,
        )

    # 2. Security threshold & regression gates.
    gate_reasons: list[str] = []
    if (
        policy.max_critical_vulnerabilities is not None
        and m.critical_compromises > policy.max_critical_vulnerabilities
    ):
        gate_reasons.append(
            f"critical_compromises={m.critical_compromises} > max_critical_vulnerabilities={policy.max_critical_vulnerabilities}"
        )
    if (
        policy.max_attack_success_rate is not None
        and m.attack_success_rate is not None
        and m.attack_success_rate > policy.max_attack_success_rate
    ):
        gate_reasons.append(
            f"ASR={m.attack_success_rate:.3f} > max_attack_success_rate={policy.max_attack_success_rate:.3f}"
        )
    if (
        policy.max_inconclusive_rate is not None
        and m.inconclusive_rate is not None
        and m.inconclusive_rate > policy.max_inconclusive_rate
    ):
        gate_reasons.append(
            f"inconclusive_rate={m.inconclusive_rate:.3f} > max_inconclusive_rate={policy.max_inconclusive_rate:.3f}"
        )
    if (
        policy.min_security_score is not None
        and m.security_score is not None
        and m.security_score < policy.min_security_score
    ):
        gate_reasons.append(
            f"security_score={m.security_score:.1f} < min_security_score={policy.min_security_score:.1f}"
        )

    regression_detected = bool(comparison and comparison.regression_detected)
    if policy.fail_on_regression and regression_detected and comparison is not None:
        gate_reasons.extend(comparison.regression_warnings or ["Security regression detected vs baseline."])

    if gate_reasons:
        return SecurityGateEvaluation(
            passed=False,
            failure_category="security_gate_failed",
            exit_code=int(ExitCode.SECURITY_GATE_FAILED),
            incomplete_run=is_incomplete,
            regression_detected=regression_detected,
            reasons=gate_reasons,
            comparison=comparison,
        )

    return SecurityGateEvaluation(
        passed=True,
        failure_category="passed",
        exit_code=int(ExitCode.SUCCESS),
        incomplete_run=is_incomplete,
        regression_detected=regression_detected,
        reasons=[],
        comparison=comparison,
    )
