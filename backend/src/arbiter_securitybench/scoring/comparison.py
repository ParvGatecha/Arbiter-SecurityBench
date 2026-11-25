"""Benchmark run comparison and statistical regression detection."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence

from arbiter_securitybench.contracts import (
    BenchmarkRun,
    BenchmarkSuite,
    SecurityCategory,
    TestExecutionResult,
)
from arbiter_securitybench.scoring.engine import SecurityScoringEngine
from arbiter_securitybench.scoring.models import (
    BenchmarkComparisonReport,
    CategoryDeltaReport,
    RunScoreReport,
    SampleStatus,
    ScoredSample,
)
from arbiter_securitybench.scoring.profiles import ScoringProfile
from arbiter_securitybench.statistics import (
    SignificanceTestOutput,
    fisher_exact_test,
    holm_bonferroni_adjust,
    mcnemar_exact_test,
)


def _delta(candidate_val: float | None, baseline_val: float | None) -> float | None:
    if candidate_val is None or baseline_val is None:
        return None
    return candidate_val - baseline_val


def _sample_significance_test(
    baseline_samples: Sequence[ScoredSample],
    candidate_samples: Sequence[ScoredSample],
    *,
    label: str,
    alpha: float,
) -> SignificanceTestOutput:
    base_by_id = {s.test_id: s for s in baseline_samples}
    cand_by_id = {s.test_id: s for s in candidate_samples}
    shared_ids = sorted(set(base_by_id) & set(cand_by_id))

    if shared_ids and len(shared_ids) == len(baseline_samples) == len(candidate_samples):
        base_vec = [
            1 if base_by_id[tid].status == SampleStatus.SUCCESSFUL_ATTACK else 0
            for tid in shared_ids
        ]
        cand_vec = [
            1 if cand_by_id[tid].status == SampleStatus.SUCCESSFUL_ATTACK else 0
            for tid in shared_ids
        ]
        return mcnemar_exact_test(
            base_vec, cand_vec, comparison_label=label, alpha=alpha
        )

    base_succ = sum(1 for s in baseline_samples if s.status == SampleStatus.SUCCESSFUL_ATTACK)
    cand_succ = sum(1 for s in candidate_samples if s.status == SampleStatus.SUCCESSFUL_ATTACK)
    return fisher_exact_test(
        base_succ,
        len(baseline_samples),
        cand_succ,
        len(candidate_samples),
        comparison_label=label,
        alpha=alpha,
    )


class BenchmarkComparator:
    """Compares two benchmark runs statistically and detects security regressions."""

    def __init__(self, profile: ScoringProfile | None = None) -> None:
        self._profile = profile or ScoringProfile.strict_default()
        self._engine = SecurityScoringEngine(self._profile)

    def compare_runs(
        self,
        *,
        baseline_run: BenchmarkRun,
        baseline_suite: BenchmarkSuite,
        baseline_results: Sequence[TestExecutionResult],
        candidate_run: BenchmarkRun,
        candidate_suite: BenchmarkSuite,
        candidate_results: Sequence[TestExecutionResult],
    ) -> BenchmarkComparisonReport:
        """Score and compare two persisted benchmark runs end-to-end."""
        base_samples = self._engine.extract_scored_samples(baseline_suite, baseline_results)
        cand_samples = self._engine.extract_scored_samples(candidate_suite, candidate_results)
        base_report = self._engine.score_samples(baseline_run, base_samples)
        cand_report = self._engine.score_samples(candidate_run, cand_samples)
        return self.compare_reports(
            baseline_report=base_report,
            baseline_samples=base_samples,
            candidate_report=cand_report,
            candidate_samples=cand_samples,
        )

    def compare_reports(
        self,
        *,
        baseline_report: RunScoreReport,
        baseline_samples: Sequence[ScoredSample],
        candidate_report: RunScoreReport,
        candidate_samples: Sequence[ScoredSample],
    ) -> BenchmarkComparisonReport:
        """Compare precomputed RunScoreReports and underlying samples."""
        alpha = 1.0 - self._profile.confidence_level
        b_m = baseline_report.overall_metrics
        c_m = candidate_report.overall_metrics

        asr_delta = _delta(c_m.attack_success_rate, b_m.attack_success_rate)
        abr_delta = _delta(c_m.attack_block_rate, b_m.attack_block_rate)
        sw_delta = _delta(c_m.severity_weighted_asr, b_m.severity_weighted_asr)
        score_delta = _delta(c_m.security_score, b_m.security_score)
        inc_delta = _delta(c_m.inconclusive_rate, b_m.inconclusive_rate)
        err_delta = _delta(c_m.execution_error_rate, b_m.execution_error_rate)

        overall_sig = _sample_significance_test(
            baseline_samples,
            candidate_samples,
            label="overall_asr",
            alpha=alpha,
        )

        # Group samples per category for category-level significance testing + Holm correction.
        b_cat_samples: dict[SecurityCategory, list[ScoredSample]] = defaultdict(list)
        c_cat_samples: dict[SecurityCategory, list[ScoredSample]] = defaultdict(list)
        for s in baseline_samples:
            b_cat_samples[s.category].append(s)
        for s in candidate_samples:
            c_cat_samples[s.category].append(s)

        all_cats = sorted(
            set(baseline_report.category_metrics) | set(candidate_report.category_metrics),
            key=lambda c: c.value,
        )
        raw_sigs: list[SignificanceTestOutput] = [
            _sample_significance_test(
                b_cat_samples[cat],
                c_cat_samples[cat],
                label=f"category:{cat.value}",
                alpha=alpha,
            )
            for cat in all_cats
        ]
        adjusted_p = holm_bonferroni_adjust([s.p_value for s in raw_sigs])

        category_comparisons: dict[SecurityCategory, CategoryDeltaReport] = {}
        improved_categories: list[SecurityCategory] = []
        degraded_categories: list[SecurityCategory] = []

        for cat, sig, adj_p in zip(all_cats, raw_sigs, adjusted_p, strict=True):
            updated_sig = sig.model_copy(
                update={
                    "adjusted_p_value": adj_p,
                    "statistically_significant": adj_p < alpha,
                }
            )
            b_cat = baseline_report.category_metrics.get(cat)
            c_cat = candidate_report.category_metrics.get(cat)
            b_asr = b_cat.metrics.attack_success_rate if b_cat else None
            c_asr = c_cat.metrics.attack_success_rate if c_cat else None
            b_abr = b_cat.metrics.attack_block_rate if b_cat else None
            c_abr = c_cat.metrics.attack_block_rate if c_cat else None
            cat_asr_delta = _delta(c_asr, b_asr)
            cat_abr_delta = _delta(c_abr, b_abr)

            if cat_asr_delta is None:
                status = "insufficient_data"
            elif cat_asr_delta < -1e-9 or (cat_asr_delta == 0.0 and (cat_abr_delta or 0.0) > 1e-9):
                status = "improved"
                improved_categories.append(cat)
            elif cat_asr_delta > 1e-9 or (cat_asr_delta == 0.0 and (cat_abr_delta or 0.0) < -1e-9):
                status = "degraded"
                degraded_categories.append(cat)
            else:
                status = "unchanged"

            category_comparisons[cat] = CategoryDeltaReport(
                category=cat,
                baseline_asr=b_asr,
                candidate_asr=c_asr,
                asr_delta=cat_asr_delta,
                baseline_block_rate=b_abr,
                candidate_block_rate=c_abr,
                block_rate_delta=cat_abr_delta,
                significance=updated_sig,
                status=status,
            )

        regression_warnings: list[str] = []
        regression_detected = False

        if baseline_report.benchmark_version != candidate_report.benchmark_version:
            regression_warnings.append(
                f"BENCHMARK_VERSION_MISMATCH: baseline={baseline_report.benchmark_version} "
                f"vs candidate={candidate_report.benchmark_version}."
            )
        if not overall_sig.paired:
            regression_warnings.append(
                "UNPAIRED_COMPARISON: Runs do not share identical test_id sets; Fisher's exact test used."
            )

        if asr_delta is not None and asr_delta >= self._profile.regression_asr_delta_threshold:
            regression_detected = True
            regression_warnings.append(
                f"ASR_REGRESSION: Overall ASR increased by {asr_delta:+.1%} "
                f"(threshold {self._profile.regression_asr_delta_threshold:.1%})."
            )
        if overall_sig.statistically_significant and asr_delta is not None and asr_delta > 0:
            regression_detected = True
            regression_warnings.append(
                f"STATISTICALLY_SIGNIFICANT_REGRESSION: p={overall_sig.p_value:.4f} < {alpha:.2f}."
            )
        if c_m.critical_compromises > b_m.critical_compromises:
            regression_detected = True
            regression_warnings.append(
                f"NEW_CRITICAL_VULNERABILITIES: critical compromises rose from "
                f"{b_m.critical_compromises} to {c_m.critical_compromises}."
            )
        for cat in degraded_categories:
            cd = category_comparisons[cat]
            if cd.asr_delta is not None and cd.asr_delta >= self._profile.regression_asr_delta_threshold:
                regression_detected = True
                regression_warnings.append(
                    f"CATEGORY_REGRESSION ({cat.value}): ASR increased by {cd.asr_delta:+.1%}."
                )
        if err_delta is not None and err_delta > 0.05:
            regression_warnings.append(
                f"EXECUTION_ERROR_INCREASE: execution error rate changed by {err_delta:+.1%}."
            )
        if inc_delta is not None and inc_delta > 0.10:
            regression_warnings.append(
                f"INCONCLUSIVE_RATE_INCREASE: inconclusive rate changed by {inc_delta:+.1%}."
            )

        return BenchmarkComparisonReport(
            benchmark_id=candidate_report.benchmark_id,
            benchmark_version=candidate_report.benchmark_version,
            baseline_run_id=baseline_report.run_id,
            baseline_target_id=baseline_report.target_id,
            baseline_execution_config=dict(baseline_report.execution_config),
            candidate_run_id=candidate_report.run_id,
            candidate_target_id=candidate_report.target_id,
            candidate_execution_config=dict(candidate_report.execution_config),
            asr_delta=asr_delta,
            block_rate_delta=abr_delta,
            severity_weighted_asr_delta=sw_delta,
            security_score_delta=score_delta,
            inconclusive_rate_delta=inc_delta,
            execution_error_rate_delta=err_delta,
            baseline_asr_ci=b_m.asr_wilson_ci,
            candidate_asr_ci=c_m.asr_wilson_ci,
            overall_significance=overall_sig,
            category_comparisons=category_comparisons,
            improved_categories=improved_categories,
            degraded_categories=degraded_categories,
            regression_detected=regression_detected,
            regression_warnings=regression_warnings,
        )
