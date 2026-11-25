"""Deterministic ReportBuilder constructing ReportDocument across all 13 sections."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from typing import Any

from arbiter_securitybench.contracts import (
    BenchmarkRun,
    BenchmarkSuite,
    RunStatus,
    SeverityLevel,
    TestCase,
    TestExecutionResult,
    TestExecutionStatus,
)
from arbiter_securitybench.reporting.models import (
    AttackFindingRecord,
    BenchmarkComparisonSection,
    BenchmarkConfigSection,
    BenchmarkVersionSection,
    CategoryResultRow,
    ConfidenceIntervalSection,
    ExecutiveSummarySection,
    FailedAndInconclusiveSection,
    IncompleteTestRecord,
    LimitationsSection,
    ReportDocument,
    SeverityDistributionRow,
    TargetInformationSection,
    VerificationClassification,
)
from arbiter_securitybench.scoring import BenchmarkComparisonReport, RunScoreReport

_DETERMINISTIC_EVALUATOR_TYPES = {"rule_based", "sensitive_info", "execution"}
_JUDGMENT_EVALUATOR_TYPES = {"semantic", "llm_judge"}

_SECRET_KEY_SUBSTRINGS = ("api_key", "secret", "token", "password", "authorization")


def _sanitize_dict(data: dict[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for key, val in data.items():
        lowered = key.lower()
        if any(s in lowered for s in _SECRET_KEY_SUBSTRINGS) and "env_var" not in lowered:
            sanitized[key] = "<redacted>"
        elif isinstance(val, dict):
            sanitized[key] = _sanitize_dict(val)
        else:
            sanitized[key] = val
    return sanitized


def _classify_finding_verification(eval_payload: dict[str, Any]) -> tuple[VerificationClassification, list[str], float | None, bool, list[str], str]:
    """Extract verification classification, evaluator IDs, confidence, disagreement, evidence, reasoning."""
    if "individual_results" in eval_payload and isinstance(eval_payload["individual_results"], list):
        indiv = [r for r in eval_payload["individual_results"] if isinstance(r, dict)]
        evaluator_ids = [str(r.get("evaluator_id", "unknown")) for r in indiv]
        has_disagreement = bool(eval_payload.get("has_disagreement", False))
        confidence = eval_payload.get("confidence")
        reasoning = str(eval_payload.get("reasoning") or "No reasoning provided.")

        ev_types = {
            str((r.get("metadata") or {}).get("evaluator_type", ""))
            for r in indiv
            if r.get("evaluation_status") == "successful_attack"
        }
        evidence_lines: list[str] = []
        for r in indiv:
            for item in r.get("evidence") or []:
                if isinstance(item, dict) and item.get("matched"):
                    ind = str(item.get("indicator", ""))
                    excerpt = item.get("excerpt")
                    evidence_lines.append(f"{ind}: {excerpt}" if excerpt else ind)

        if has_disagreement:
            classification = VerificationClassification.MIXED_OR_DISPUTED
        elif ev_types & _DETERMINISTIC_EVALUATOR_TYPES:
            classification = VerificationClassification.DETERMINISTIC_VERIFIED
        else:
            classification = VerificationClassification.EVALUATOR_JUDGMENT

        return (
            classification,
            evaluator_ids,
            float(confidence) if isinstance(confidence, (int, float)) else None,
            has_disagreement,
            evidence_lines,
            reasoning,
        )

    # Single EvaluatorOutput payload
    eval_id = str(eval_payload.get("evaluator_id", "unknown"))
    meta = eval_payload.get("metadata") if isinstance(eval_payload.get("metadata"), dict) else {}
    ev_type = str(meta.get("evaluator_type", ""))
    is_gt = meta.get("is_ground_truth")
    classification = (
        VerificationClassification.DETERMINISTIC_VERIFIED
        if (ev_type in _DETERMINISTIC_EVALUATOR_TYPES and is_gt is not False)
        else VerificationClassification.EVALUATOR_JUDGMENT
    )
    confidence = eval_payload.get("confidence")
    evidence_lines = [
        f"{e.get('indicator')}: {e.get('excerpt')}" if e.get("excerpt") else str(e.get("indicator"))
        for e in (eval_payload.get("evidence") or [])
        if isinstance(e, dict) and e.get("matched")
    ]
    reasoning = str(eval_payload.get("reasoning") or "No reasoning provided.")
    return (
        classification,
        [eval_id],
        float(confidence) if isinstance(confidence, (int, float)) else None,
        False,
        evidence_lines,
        reasoning,
    )


def _extract_outcome_and_error(res: TestExecutionResult) -> tuple[str, dict[str, Any] | None]:
    if res.execution_status != TestExecutionStatus.COMPLETED:
        return "execution_error", None
    if not res.evaluator_results:
        return "evaluation_failure", None
    last = res.evaluator_results[-1]
    if not isinstance(last, dict):
        return "evaluation_failure", None
    if "consensus_status" in last:
        indiv = last.get("individual_results")
        if isinstance(indiv, list) and indiv and all(
            isinstance(r, dict)
            and isinstance(r.get("metadata"), dict)
            and "evaluator_error" in r["metadata"]
            for r in indiv
        ):
            return "evaluation_failure", last
        status = str(last["consensus_status"]).strip().lower()
    elif "evaluation_status" in last:
        meta = last.get("metadata")
        if isinstance(meta, dict) and "evaluator_error" in meta:
            return "evaluation_failure", last
        status = str(last["evaluation_status"]).strip().lower()
    else:
        return "evaluation_failure", last

    if status in {"successful_attack", "blocked_attack", "inconclusive"}:
        return status, last
    return "evaluation_failure", last


class ReportBuilder:
    """Assembles a verified, reproducible ReportDocument across all 13 required sections."""

    def build(
        self,
        *,
        run: BenchmarkRun,
        score_report: RunScoreReport,
        results: Sequence[TestExecutionResult],
        suite: BenchmarkSuite | None = None,
        comparison: BenchmarkComparisonReport | None = None,
    ) -> ReportDocument:
        cases_by_id: dict[str, TestCase] = (
            {tc.test_id: tc for tc in suite.test_cases} if suite is not None else {}
        )
        m = score_report.overall_metrics
        c = m.sample_counts

        is_complete = (
            run.status == RunStatus.COMPLETED
            and c.execution_error_samples == 0
            and c.evaluation_failure_samples == 0
            and (run.total_tests == 0 or c.total_samples == run.total_tests)
        )
        incomplete_reason: str | None = None
        if not is_complete:
            reasons: list[str] = []
            if run.status != RunStatus.COMPLETED:
                reasons.append(f"run status is '{run.status.value}'")
            if c.execution_error_samples > 0:
                reasons.append(f"{c.execution_error_samples} test execution(s) failed/timed out")
            if c.evaluation_failure_samples > 0:
                reasons.append(f"{c.evaluation_failure_samples} test(s) lacked valid evaluations")
            if c.total_samples < run.total_tests:
                reasons.append(f"only {c.total_samples}/{run.total_tests} scheduled tests recorded")
            incomplete_reason = "; ".join(reasons)

        findings: list[AttackFindingRecord] = []
        exec_errors: list[IncompleteTestRecord] = []
        eval_failures: list[IncompleteTestRecord] = []
        inconclusives: list[IncompleteTestRecord] = []

        sev_buckets: dict[SeverityLevel, dict[str, int]] = {
            sev: defaultdict(int) for sev in SeverityLevel
        }

        det_compromises = 0
        judge_compromises = 0

        for res in results:
            tc = cases_by_id.get(res.test_id)
            sev = tc.severity if tc is not None else SeverityLevel.MEDIUM
            outcome, payload = _extract_outcome_and_error(res)

            sev_buckets[sev]["total"] += 1
            if outcome == "successful_attack" and payload is not None:
                sev_buckets[sev]["successful_attacks"] += 1
                v_class, eval_ids, conf, disagreed, ev_lines, reasoning = _classify_finding_verification(
                    payload
                )
                if v_class == VerificationClassification.DETERMINISTIC_VERIFIED:
                    det_compromises += 1
                else:
                    judge_compromises += 1

                output_excerpt = None
                if res.output is not None:
                    output_excerpt = res.output[:240] + ("..." if len(res.output) > 240 else "")

                findings.append(
                    AttackFindingRecord(
                        test_id=res.test_id,
                        test_name=tc.name if tc else None,
                        category=tc.category if tc else None,
                        severity=sev,
                        attack_type=tc.attack_type.value if tc else None,
                        verification_classification=v_class,
                        confidence=conf,
                        evaluator_ids=eval_ids,
                        has_disagreement=disagreed,
                        evidence_summary=ev_lines,
                        reasoning=reasoning,
                        output_excerpt=output_excerpt,
                    )
                )
            elif outcome == "blocked_attack":
                sev_buckets[sev]["blocked_attacks"] += 1
            elif outcome == "inconclusive":
                sev_buckets[sev]["inconclusive"] += 1
                reason = str((payload or {}).get("reasoning") or "Evaluators returned INCONCLUSIVE.")
                disagreed = bool((payload or {}).get("has_disagreement", False))
                inconclusives.append(
                    IncompleteTestRecord(
                        test_id=res.test_id,
                        failure_kind="inconclusive",
                        execution_status=res.execution_status.value,
                        reasoning=reason,
                        has_disagreement=disagreed,
                    )
                )
            elif outcome == "execution_error":
                sev_buckets[sev]["execution_errors"] += 1
                err_msg = None
                if isinstance(res.error_details, dict):
                    err_msg = str(res.error_details.get("message") or res.error_details)
                elif res.error_details is not None:
                    err_msg = res.error_details.message
                exec_errors.append(
                    IncompleteTestRecord(
                        test_id=res.test_id,
                        failure_kind="execution_error",
                        execution_status=res.execution_status.value,
                        error_message=err_msg,
                    )
                )
            else:
                sev_buckets[sev]["evaluation_failures"] += 1
                eval_failures.append(
                    IncompleteTestRecord(
                        test_id=res.test_id,
                        failure_kind="evaluation_failure",
                        execution_status=res.execution_status.value,
                        error_message="Missing or errored evaluator output.",
                    )
                )

        if c.total_samples == 0:
            headline = "Incomplete run: zero test samples recorded; no metrics computed."
        elif not is_complete:
            headline = f"Incomplete benchmark run ({incomplete_reason})."
        elif m.critical_compromises > 0:
            headline = (
                f"Critical risk detected: {m.critical_compromises} critical-severity attack(s) "
                f"succeeded across {c.total_samples} tests."
            )
        elif c.successful_attacks > 0:
            headline = (
                f"{c.successful_attacks}/{c.total_samples} attack(s) succeeded; "
                f"security score {m.security_score:.1f}/100."
                if m.security_score is not None
                else f"{c.successful_attacks}/{c.total_samples} attack(s) succeeded."
            )
        else:
            headline = (
                f"All {c.blocked_attacks}/{c.total_samples} evaluated attack(s) blocked."
                if c.inconclusive_samples == 0
                else (
                    f"{c.blocked_attacks}/{c.total_samples} blocked; "
                    f"{c.inconclusive_samples} inconclusive pending review."
                )
            )

        exec_summary = ExecutiveSummarySection(
            run_id=run.run_id,
            run_status=run.status,
            is_complete_run=is_complete,
            incomplete_run_reason=incomplete_reason,
            headline=headline,
            total_samples=c.total_samples,
            successful_attacks=c.successful_attacks,
            blocked_attacks=c.blocked_attacks,
            inconclusive_samples=c.inconclusive_samples,
            execution_error_samples=c.execution_error_samples,
            evaluation_failure_samples=c.evaluation_failure_samples,
            deterministic_verified_compromises=det_compromises,
            evaluator_judgment_compromises=judge_compromises,
            critical_compromises=m.critical_compromises,
            attack_success_rate=m.attack_success_rate,
            attack_block_rate=m.attack_block_rate,
            security_score=m.security_score,
            warnings=list(score_report.warnings),
        )

        target_info = TargetInformationSection(
            target_id=run.target_id,
            target_type=run.target_type,
            sanitized_target_config=_sanitize_dict(dict(run.target_config)),
            created_at=run.created_at,
            started_at=run.started_at,
            completed_at=run.completed_at,
        )

        suite_digest = (
            suite.content_digest.hex_digest
            if suite is not None and suite.content_digest is not None
            else None
        )
        bench_cfg = BenchmarkConfigSection(
            benchmark_id=run.benchmark_id,
            suite_id=run.suite_id,
            scoring_profile_id=score_report.profile_id,
            execution_config=_sanitize_dict(dict(score_report.execution_config)),
            total_tests_scheduled=run.total_tests,
            completed_tests=run.completed_tests,
            failed_tests=run.failed_tests,
            suite_content_digest=suite_digest,
        )

        bench_ver = BenchmarkVersionSection(
            benchmark_id=run.benchmark_id,
            benchmark_version=run.benchmark_version,
            suite_schema_version=suite.schema_version if suite is not None else run.schema_version,
            suite_content_digest=suite_digest,
        )

        cat_rows = [
            CategoryResultRow(category=cat, metrics=rep.metrics)
            for cat, rep in score_report.category_metrics.items()
        ]

        sev_rows = [
            SeverityDistributionRow(
                severity=sev,
                total=sev_buckets[sev]["total"],
                successful_attacks=sev_buckets[sev]["successful_attacks"],
                blocked_attacks=sev_buckets[sev]["blocked_attacks"],
                inconclusive=sev_buckets[sev]["inconclusive"],
                execution_errors=sev_buckets[sev]["execution_errors"],
                evaluation_failures=sev_buckets[sev]["evaluation_failures"],
            )
            for sev in (
                SeverityLevel.CRITICAL,
                SeverityLevel.HIGH,
                SeverityLevel.MEDIUM,
                SeverityLevel.LOW,
                SeverityLevel.INFO,
            )
        ]

        stat_notes: list[str] = []
        if c.total_samples == 0:
            stat_notes.append("No samples available for confidence interval estimation.")
        elif c.is_small_sample:
            stat_notes.append(
                f"Small sample size (n={c.total_samples} < 30): interpret Wilson and bootstrap intervals cautiously."
            )
        if m.false_positive_rate is None or m.false_negative_rate is None:
            stat_notes.append(
                "FPR/FNR omitted (null) because explicit ground-truth labels were not present in this run."
            )

        ci_section = ConfidenceIntervalSection(
            confidence_level=(
                m.asr_wilson_ci.confidence_level if m.asr_wilson_ci is not None else 0.95
            ),
            sample_size=c.total_samples,
            is_small_sample=c.is_small_sample,
            asr_wilson_ci=m.asr_wilson_ci.model_dump(mode="json") if m.asr_wilson_ci else None,
            asr_bootstrap_ci=(
                m.asr_bootstrap_ci.model_dump(mode="json") if m.asr_bootstrap_ci else None
            ),
            severity_weighted_asr_bootstrap_ci=(
                m.severity_weighted_asr_bootstrap_ci.model_dump(mode="json")
                if m.severity_weighted_asr_bootstrap_ci
                else None
            ),
            statistical_notes=stat_notes,
        )

        comp_section = BenchmarkComparisonSection(
            available=comparison is not None,
            reason=None if comparison is not None else "No baseline run was supplied for comparison.",
            comparison=comparison,
        )

        recommendations = _derive_recommendations(
            is_complete=is_complete,
            findings=findings,
            exec_errors=exec_errors,
            eval_failures=eval_failures,
            inconclusives=inconclusives,
            score_report=score_report,
        )

        limitations = LimitationsSection(
            methodology_summary=(
                "Evaluated using Arbiter SecurityBench modular evaluators with total-sample denominator "
                "accounting (keeping inconclusive and errored tests in the denominator) and Wilson/bootstrap "
                "confidence intervals."
            ),
            limitations=[
                "Static or finite benchmark suites do not represent all real-world adversarial attacks.",
                "External hosted LLM targets remain non-deterministic across runs even with fixed parameters.",
                "Evaluator judgments (semantic heuristics or LLM-as-a-Judge) are non-ground-truth signals and require human review when disputed.",
                "FPR and FNR are reported only when explicit ground-truth control labels are present.",
            ],
        )

        return ReportDocument(
            executive_summary=exec_summary,
            target_information=target_info,
            benchmark_configuration=bench_cfg,
            benchmark_version=bench_ver,
            overall_security_metrics=m,
            category_results=cat_rows,
            successful_attack_analysis=findings,
            failed_and_inconclusive_tests=FailedAndInconclusiveSection(
                execution_errors=exec_errors,
                evaluation_failures=eval_failures,
                inconclusive_tests=inconclusives,
            ),
            severity_distribution=sev_rows,
            statistical_confidence_intervals=ci_section,
            benchmark_comparison=comp_section,
            recommendations=recommendations,
            limitations=limitations,
            raw_results=[r.model_dump(mode="json") for r in results],
        )


def _derive_recommendations(
    *,
    is_complete: bool,
    findings: list[AttackFindingRecord],
    exec_errors: list[IncompleteTestRecord],
    eval_failures: list[IncompleteTestRecord],
    inconclusives: list[IncompleteTestRecord],
    score_report: RunScoreReport,
) -> list[str]:
    recs: list[str] = []
    if not is_complete:
        recs.append(
            "Re-run or investigate incomplete items before making release-gate decisions; incomplete runs do not establish defense posture."
        )
    if score_report.overall_metrics.critical_compromises > 0:
        crit_ids = ", ".join(f.test_id for f in findings if f.severity == SeverityLevel.CRITICAL)
        recs.append(
            f"Prioritize immediate remediation of critical-severity compromises ({crit_ids}) before production exposure."
        )
    judge_only = [
        f
        for f in findings
        if f.verification_classification != VerificationClassification.DETERMINISTIC_VERIFIED
    ]
    if judge_only:
        recs.append(
            f"Review {len(judge_only)} finding(s) classified via evaluator judgment/disputed consensus to confirm exploitability."
        )
    if inconclusives:
        recs.append(
            f"Adjudicate {len(inconclusives)} inconclusive test case(s) or refine evaluation rules/rubrics."
        )
    if exec_errors:
        recs.append(
            f"Resolve {len(exec_errors)} target execution error(s)/timeout(s) (check rate limits, timeouts, or adapter stability)."
        )
    if eval_failures:
        recs.append(
            f"Investigate {len(eval_failures)} missing or failed evaluation output(s) to restore 100% evaluation coverage."
        )
    if not recs:
        recs.append(
            "No compromises or execution errors observed in this run; continue regression monitoring across new suite versions."
        )
    return recs
