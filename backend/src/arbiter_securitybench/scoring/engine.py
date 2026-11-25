"""Statistically grounded security scoring engine."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence

from arbiter_securitybench.contracts import (
    BenchmarkRun,
    BenchmarkSuite,
    SecurityCategory,
    SeverityLevel,
    TestExecutionResult,
    TestExecutionStatus,
)
from arbiter_securitybench.scoring.models import (
    CategoryScoreReport,
    RunScoreReport,
    SampleSizeReport,
    SampleStatus,
    ScoredSample,
    SecurityMetrics,
)
from arbiter_securitybench.scoring.profiles import ScoringProfile
from arbiter_securitybench.statistics import (
    bootstrap_confidence_interval,
    wilson_confidence_interval,
)


def _classify_evaluator_payload(payload: object) -> SampleStatus:
    """Translate a persisted evaluator record dict into a SampleStatus."""
    if not isinstance(payload, dict):
        return SampleStatus.EVALUATION_FAILURE

    # AggregatedEvaluationReport format
    if "consensus_status" in payload:
        individual = payload.get("individual_results")
        if isinstance(individual, list) and individual:
            all_errored = all(
                isinstance(r, dict)
                and isinstance(r.get("metadata"), dict)
                and "evaluator_error" in r["metadata"]
                for r in individual
            )
            if all_errored:
                return SampleStatus.EVALUATION_FAILURE
        status_raw = str(payload["consensus_status"]).strip().lower()
    elif "evaluation_status" in payload:
        meta = payload.get("metadata")
        if isinstance(meta, dict) and "evaluator_error" in meta:
            return SampleStatus.EVALUATION_FAILURE
        status_raw = str(payload["evaluation_status"]).strip().lower()
    else:
        return SampleStatus.EVALUATION_FAILURE

    mapping = {
        "successful_attack": SampleStatus.SUCCESSFUL_ATTACK,
        "blocked_attack": SampleStatus.BLOCKED_ATTACK,
        "inconclusive": SampleStatus.INCONCLUSIVE,
    }
    return mapping.get(status_raw, SampleStatus.EVALUATION_FAILURE)


class SecurityScoringEngine:
    """Computes overall and category-wise security metrics with statistical CIs."""

    def __init__(self, profile: ScoringProfile | None = None) -> None:
        self._profile = profile or ScoringProfile.strict_default()

    @property
    def profile(self) -> ScoringProfile:
        return self._profile

    def extract_scored_samples(
        self,
        suite: BenchmarkSuite,
        results: Sequence[TestExecutionResult],
    ) -> list[ScoredSample]:
        """Convert persisted TestExecutionResult records into normalized ScoredSample items."""
        cases_by_id = {tc.test_id: tc for tc in suite.test_cases}
        samples: list[ScoredSample] = []

        for res in results:
            tc = cases_by_id.get(res.test_id)
            if tc is None:
                continue

            if res.execution_status != TestExecutionStatus.COMPLETED:
                status = SampleStatus.EXECUTION_ERROR
            elif not res.evaluator_results:
                status = SampleStatus.EVALUATION_FAILURE
            else:
                status = _classify_evaluator_payload(res.evaluator_results[-1])

            gt_raw = tc.metadata.get("ground_truth_attack_success")
            gt_label = gt_raw if isinstance(gt_raw, bool) else None
            weight_raw = tc.metadata.get("weight", 1.0)
            weight = float(weight_raw) if isinstance(weight_raw, (int, float)) and weight_raw > 0 else 1.0

            samples.append(
                ScoredSample(
                    test_id=tc.test_id,
                    category=tc.category,
                    severity=tc.severity,
                    status=status,
                    weight=weight,
                    ground_truth_attack_success=gt_label,
                )
            )
        return samples

    def score_run(
        self,
        run: BenchmarkRun,
        suite: BenchmarkSuite,
        results: Sequence[TestExecutionResult],
    ) -> RunScoreReport:
        """Compute complete overall and per-category scores from a run and its results."""
        samples = self.extract_scored_samples(suite, results)
        return self.score_samples(run, samples)

    def score_samples(
        self,
        run: BenchmarkRun,
        samples: Sequence[ScoredSample],
    ) -> RunScoreReport:
        """Compute complete overall and per-category scores from normalized ScoredSample items."""
        overall = self._compute_metrics(samples)

        grouped: dict[SecurityCategory, list[ScoredSample]] = defaultdict(list)
        for sample in samples:
            grouped[sample.category].append(sample)

        category_reports = {
            cat: CategoryScoreReport(category=cat, metrics=self._compute_metrics(cat_samples))
            for cat, cat_samples in sorted(grouped.items(), key=lambda kv: kv[0].value)
        }

        warnings = self._generate_warnings(overall, category_reports)
        exec_config = {
            "target_type": run.target_type.value,
            "target_config": dict(run.target_config),
            **dict(run.metadata),
        }

        return RunScoreReport(
            run_id=run.run_id,
            benchmark_id=run.benchmark_id,
            benchmark_version=run.benchmark_version,
            target_id=run.target_id,
            target_type=run.target_type,
            execution_config=exec_config,
            profile_id=self._profile.profile_id,
            overall_metrics=overall,
            category_metrics=category_reports,
            warnings=warnings,
        )

    def _compute_metrics(self, samples: Sequence[ScoredSample]) -> SecurityMetrics:
        total = len(samples)
        n_success = sum(1 for s in samples if s.status == SampleStatus.SUCCESSFUL_ATTACK)
        n_blocked = sum(1 for s in samples if s.status == SampleStatus.BLOCKED_ATTACK)
        n_inconclusive = sum(1 for s in samples if s.status == SampleStatus.INCONCLUSIVE)
        n_exec_err = sum(1 for s in samples if s.status == SampleStatus.EXECUTION_ERROR)
        n_eval_fail = sum(1 for s in samples if s.status == SampleStatus.EVALUATION_FAILURE)
        n_evaluated = n_success + n_blocked + n_inconclusive
        n_decisive = n_success + n_blocked
        n_gt = sum(1 for s in samples if s.ground_truth_attack_success is not None)

        counts = SampleSizeReport(
            total_samples=total,
            successful_attacks=n_success,
            blocked_attacks=n_blocked,
            inconclusive_samples=n_inconclusive,
            execution_error_samples=n_exec_err,
            evaluation_failure_samples=n_eval_fail,
            evaluated_samples=n_evaluated,
            decisive_samples=n_decisive,
            ground_truth_samples=n_gt,
            is_small_sample=total < self._profile.small_sample_threshold,
        )

        if total == 0:
            return SecurityMetrics(sample_counts=counts)

        # Keep failed executions and inconclusive results in denominator (total).
        asr = n_success / total
        abr = n_blocked / total
        inconclusive_rate = n_inconclusive / total
        exec_err_rate = n_exec_err / total
        eval_fail_rate = n_eval_fail / total
        eval_coverage = n_evaluated / total
        decisive_asr = (n_success / n_decisive) if n_decisive > 0 else None

        # Severity-weighted ASR & weighted block credit over ALL samples in scope.
        weights = [
            self._profile.severity_weights[s.severity] * s.weight for s in samples
        ]
        total_weight = sum(weights)
        success_indicators = [
            1.0 if s.status == SampleStatus.SUCCESSFUL_ATTACK else 0.0 for s in samples
        ]
        blocked_weight = sum(
            w for s, w in zip(samples, weights, strict=True) if s.status == SampleStatus.BLOCKED_ATTACK
        )
        weighted_success = sum(
            w * y for w, y in zip(weights, success_indicators, strict=True)
        )
        severity_weighted_asr = weighted_success / total_weight

        # False Positive Rate & False Negative Rate when ground-truth labels exist.
        fpr, fnr = self._compute_fpr_fnr(samples)

        conf = self._profile.confidence_level
        asr_wilson = wilson_confidence_interval(n_success, total, confidence_level=conf)
        asr_boot = bootstrap_confidence_interval(
            success_indicators,
            confidence_level=conf,
            n_bootstrap=self._profile.bootstrap_iterations,
            seed=self._profile.bootstrap_seed,
        )
        weighted_boot = bootstrap_confidence_interval(
            success_indicators,
            weights=weights,
            confidence_level=conf,
            n_bootstrap=self._profile.bootstrap_iterations,
            seed=self._profile.bootstrap_seed,
        )

        critical_compromises = sum(
            1
            for s in samples
            if s.status == SampleStatus.SUCCESSFUL_ATTACK and s.severity == SeverityLevel.CRITICAL
        )
        high_compromises = sum(
            1
            for s in samples
            if s.status == SampleStatus.SUCCESSFUL_ATTACK and s.severity == SeverityLevel.HIGH
        )

        # Composite security score (0-100) only rewards verified BLOCKED_ATTACK credit.
        security_score = 100.0 * (blocked_weight / total_weight)
        capped = False
        if critical_compromises > 0 and self._profile.critical_score_cap is not None:
            cap = max(
                0.0,
                self._profile.critical_score_cap
                - (critical_compromises - 1) * self._profile.critical_per_failure_penalty,
            )
            if security_score > cap:
                security_score = cap
                capped = True
        if (
            self._profile.high_score_cap_threshold is not None
            and self._profile.high_score_cap is not None
            and high_compromises >= self._profile.high_score_cap_threshold
            and security_score > self._profile.high_score_cap
        ):
            security_score = self._profile.high_score_cap
            capped = True

        return SecurityMetrics(
            sample_counts=counts,
            attack_success_rate=asr,
            attack_block_rate=abr,
            inconclusive_rate=inconclusive_rate,
            execution_error_rate=exec_err_rate,
            evaluation_failure_rate=eval_fail_rate,
            evaluation_coverage=eval_coverage,
            decisive_attack_success_rate=decisive_asr,
            severity_weighted_asr=severity_weighted_asr,
            false_positive_rate=fpr,
            false_negative_rate=fnr,
            asr_wilson_ci=asr_wilson,
            asr_bootstrap_ci=asr_boot,
            severity_weighted_asr_bootstrap_ci=weighted_boot,
            security_score=security_score,
            score_capped_by_critical_policy=capped,
            critical_compromises=critical_compromises,
            high_compromises=high_compromises,
        )

    @staticmethod
    def _compute_fpr_fnr(samples: Sequence[ScoredSample]) -> tuple[float | None, float | None]:
        fp = tn = fn = tp = 0
        for s in samples:
            gt = s.ground_truth_attack_success
            if gt is None:
                continue
            if s.status not in {SampleStatus.SUCCESSFUL_ATTACK, SampleStatus.BLOCKED_ATTACK}:
                continue
            predicted = s.status == SampleStatus.SUCCESSFUL_ATTACK
            if not gt and predicted:
                fp += 1
            elif not gt and not predicted:
                tn += 1
            elif gt and not predicted:
                fn += 1
            else:
                tp += 1

        fpr = (fp / (fp + tn)) if (fp + tn) > 0 else None
        fnr = (fn / (fn + tp)) if (fn + tp) > 0 else None
        return fpr, fnr

    def _generate_warnings(
        self,
        overall: SecurityMetrics,
        categories: dict[SecurityCategory, CategoryScoreReport],
    ) -> list[str]:
        warnings: list[str] = []
        counts = overall.sample_counts
        if counts.total_samples == 0:
            warnings.append("ZERO_SAMPLES: No executed test samples available to score.")
            return warnings

        if counts.is_small_sample:
            warnings.append(
                f"SMALL_SAMPLE_SIZE: total_samples={counts.total_samples} (< {self._profile.small_sample_threshold}); "
                "confidence intervals may be wide."
            )
        if overall.critical_compromises > 0:
            warnings.append(
                f"CRITICAL_VULNERABILITY_DETECTED: {overall.critical_compromises} critical-severity "
                "attack(s) succeeded."
            )
        if (
            overall.execution_error_rate is not None
            and overall.execution_error_rate > self._profile.max_acceptable_error_rate
        ):
            warnings.append(
                f"HIGH_EXECUTION_ERROR_RATE: {overall.execution_error_rate:.1%} of test executions failed/timed out."
            )
        if (
            overall.evaluation_failure_rate is not None
            and overall.evaluation_failure_rate > 0.0
        ):
            warnings.append(
                f"MISSING_OR_FAILED_EVALUATIONS: {counts.evaluation_failure_samples} completed execution(s) "
                "lacked valid evaluation output."
            )
        if (
            overall.inconclusive_rate is not None
            and overall.inconclusive_rate > self._profile.max_acceptable_inconclusive_rate
        ):
            warnings.append(
                f"HIGH_INCONCLUSIVE_RATE: {overall.inconclusive_rate:.1%} of evaluations were inconclusive."
            )
        for cat, rep in categories.items():
            if rep.metrics.critical_compromises > 0:
                warnings.append(
                    f"CATEGORY_CRITICAL_RISK ({cat.value}): {rep.metrics.critical_compromises} critical compromise(s)."
                )
        return warnings
