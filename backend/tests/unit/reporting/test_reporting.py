"""Snapshot and validation tests for JSON, interactive HTML, and printable PDF reports."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from pypdf import PdfReader

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
from arbiter_securitybench.reporting import (
    REPORT_SCHEMA_VERSION,
    ReportDocument,
    ReportExporter,
    VerificationClassification,
)
from arbiter_securitybench.scoring import BenchmarkComparator, SecurityScoringEngine
from conftest import build_test_case

_EXPECTED_TOP_LEVEL_KEYS = {
    "report_schema_version",
    "generated_at",
    "executive_summary",
    "target_information",
    "benchmark_configuration",
    "benchmark_version",
    "overall_security_metrics",
    "category_results",
    "successful_attack_analysis",
    "failed_and_inconclusive_tests",
    "severity_distribution",
    "statistical_confidence_intervals",
    "benchmark_comparison",
    "recommendations",
    "limitations",
    "raw_results",
}


def _fixture_run_suite_results() -> tuple[BenchmarkRun, BenchmarkSuite, list[TestExecutionResult]]:
    fixed_ts = datetime(2026, 11, 25, 12, 0, 0, tzinfo=UTC)
    cases = [
        build_test_case(
            test_id="tc-det-crit",
            category=SecurityCategory.SENSITIVE_DATA_LEAKAGE,
            severity=SeverityLevel.CRITICAL,
        ),
        build_test_case(
            test_id="tc-judge-med",
            category=SecurityCategory.JAILBREAK_RESISTANCE,
            severity=SeverityLevel.MEDIUM,
        ),
        build_test_case(
            test_id="tc-blocked",
            category=SecurityCategory.PROMPT_INJECTION,
            severity=SeverityLevel.HIGH,
        ),
        build_test_case(
            test_id="tc-inc",
            category=SecurityCategory.SYSTEM_PROMPT_EXTRACTION,
            severity=SeverityLevel.LOW,
        ),
        build_test_case(
            test_id="tc-err",
            category=SecurityCategory.PROMPT_INJECTION,
            severity=SeverityLevel.MEDIUM,
        ),
    ]
    suite = BenchmarkSuite(
        suite_id="rep-suite",
        name="Report Test Suite",
        description="Suite for report validation and snapshot tests.",
        version="1.0.0",
        supported_target_types=[TargetModality.LLM],
        test_cases=cases,
    )
    run = BenchmarkRun(
        run_id="run-rep-001",
        benchmark_id="rep-suite",
        suite_id="rep-suite",
        benchmark_version="1.0.0",
        target_id="target-demo",
        target_type=TargetModality.LLM,
        target_config={"model": "demo-llm", "api_key": "should-be-redacted"},
        status=RunStatus.PARTIALLY_COMPLETED,
        total_tests=5,
        completed_tests=4,
        failed_tests=1,
        created_at=fixed_ts,
        started_at=fixed_ts,
        completed_at=fixed_ts,
        metadata={"seed": 42},
    )
    results = [
        TestExecutionResult(
            run_id="run-rep-001",
            test_id="tc-det-crit",
            target_id="target-demo",
            input="p1",
            output="Leaked <script>alert(1)</script> CANARY_KEY",
            execution_status=TestExecutionStatus.COMPLETED,
            execution_time=0.12,
            evaluator_results=[
                {
                    "evaluator_id": "evaluator.sensitive_info",
                    "evaluation_status": "successful_attack",
                    "attack_success": True,
                    "confidence": 0.95,
                    "severity": "critical",
                    "evidence": [{"indicator": "canary:CANARY_KEY", "matched": True, "excerpt": "CANARY_KEY"}],
                    "reasoning": "Canary leaked verbatim.",
                    "metadata": {"evaluator_type": "sensitive_info"},
                }
            ],
            timestamp=fixed_ts,
        ),
        TestExecutionResult(
            run_id="run-rep-001",
            test_id="tc-judge-med",
            target_id="target-demo",
            input="p2",
            output="Sure, here is a hypothetical bypass.",
            execution_status=TestExecutionStatus.COMPLETED,
            execution_time=0.22,
            evaluator_results=[
                {
                    "evaluator_id": "evaluator.llm_judge",
                    "evaluation_status": "successful_attack",
                    "attack_success": True,
                    "confidence": 0.80,
                    "severity": "medium",
                    "evidence": [],
                    "reasoning": "Judge assessed policy bypass.",
                    "metadata": {"evaluator_type": "llm_judge", "is_ground_truth": False},
                }
            ],
            timestamp=fixed_ts,
        ),
        TestExecutionResult(
            run_id="run-rep-001",
            test_id="tc-blocked",
            target_id="target-demo",
            input="p3",
            output="I cannot comply.",
            execution_status=TestExecutionStatus.COMPLETED,
            execution_time=0.05,
            evaluator_results=[
                {
                    "evaluator_id": "evaluator.rule_based",
                    "evaluation_status": "blocked_attack",
                    "attack_success": False,
                    "confidence": 0.9,
                    "severity": "high",
                    "evidence": [],
                    "reasoning": "Refused cleanly.",
                    "metadata": {"evaluator_type": "rule_based"},
                }
            ],
            timestamp=fixed_ts,
        ),
        TestExecutionResult(
            run_id="run-rep-001",
            test_id="tc-inc",
            target_id="target-demo",
            input="p4",
            output="Maybe.",
            execution_status=TestExecutionStatus.COMPLETED,
            execution_time=0.05,
            evaluator_results=[
                {
                    "evaluator_id": "evaluator.semantic",
                    "evaluation_status": "inconclusive",
                    "attack_success": None,
                    "confidence": 0.4,
                    "severity": "low",
                    "evidence": [],
                    "reasoning": "Ambiguous reply.",
                    "metadata": {"evaluator_type": "semantic"},
                }
            ],
            timestamp=fixed_ts,
        ),
        TestExecutionResult(
            run_id="run-rep-001",
            test_id="tc-err",
            target_id="target-demo",
            input="p5",
            output=None,
            execution_status=TestExecutionStatus.FAILED,
            execution_time=0.5,
            error_details=ErrorRecord(
                error_code="ASB_ADAPTER_ERROR",
                category=ErrorCategory.ADAPTER_TRANSPORT,
                severity=ErrorSeverity.FATAL_ITEM,
                retryability=Retryability.CONDITIONAL,
                message="Upstream 502 error",
                component="tests",
                occurred_at=fixed_ts,
            ),
            timestamp=fixed_ts,
        ),
    ]
    return run, suite, results


def test_json_report_schema_snapshot_and_epistemic_integrity(tmp_path: Path) -> None:
    run, suite, results = _fixture_run_suite_results()
    score_report = SecurityScoringEngine().score_run(run, suite, results)
    exporter = ReportExporter()

    json_path = exporter.export(
        run=run,
        score_report=score_report,
        results=results,
        output_dir=tmp_path,
        report_format="json",
        suite=suite,
    )
    raw = json.loads(json_path.read_text(encoding="utf-8"))
    assert set(raw.keys()) == _EXPECTED_TOP_LEVEL_KEYS
    assert raw["report_schema_version"] == REPORT_SCHEMA_VERSION

    doc = ReportDocument.model_validate(raw)
    es = doc.executive_summary
    assert es.is_complete_run is False
    assert es.incomplete_run_reason is not None
    assert es.deterministic_verified_compromises == 1
    assert es.evaluator_judgment_compromises == 1
    assert doc.target_information.sanitized_target_config["api_key"] == "<redacted>"

    # Never invent missing FPR/FNR metrics when ground-truth labels absent
    assert doc.overall_security_metrics.false_positive_rate is None
    assert doc.overall_security_metrics.false_negative_rate is None

    # Distinguish verified finding from evaluator judgment
    ver_map = {f.test_id: f.verification_classification for f in doc.successful_attack_analysis}
    assert ver_map["tc-det-crit"] == VerificationClassification.DETERMINISTIC_VERIFIED
    assert ver_map["tc-judge-med"] == VerificationClassification.EVALUATOR_JUDGMENT

    # Incomplete and inconclusive lists populated accurately
    assert [e.test_id for e in doc.failed_and_inconclusive_tests.execution_errors] == ["tc-err"]
    assert [i.test_id for i in doc.failed_and_inconclusive_tests.inconclusive_tests] == ["tc-inc"]
    assert doc.benchmark_comparison.available is False


def test_html_and_pdf_reports_with_comparison_and_xss_escaping(tmp_path: Path) -> None:
    run, suite, results = _fixture_run_suite_results()
    engine = SecurityScoringEngine()
    score_report = engine.score_run(run, suite, results)

    # Create a baseline comparison
    base_run = run.model_copy(update={"run_id": "run-base-000", "status": RunStatus.COMPLETED})
    comparison = BenchmarkComparator().compare_runs(
        baseline_run=base_run,
        baseline_suite=suite,
        baseline_results=results,
        candidate_run=run,
        candidate_suite=suite,
        candidate_results=results,
    )

    exporter = ReportExporter()
    html_path = exporter.export(
        run=run,
        score_report=score_report,
        results=results,
        output_dir=tmp_path,
        report_format="html",
        suite=suite,
        comparison=comparison,
    )
    html_text = html_path.read_text(encoding="utf-8")

    # Verify all 13 sections, interactive controls, inline SVG charts, and XSS escaping
    for section_title in (
        "1. Executive Summary",
        "2. Target Information",
        "3. Benchmark Configuration",
        "4. Benchmark Version",
        "5. Overall Security Metrics",
        "6. Category-wise Results",
        "7. Successful Attack Analysis",
        "8. Failed and Inconclusive Tests",
        "9. Severity Distribution",
        "10. Statistical Confidence Intervals",
        "11. Benchmark Comparison",
        "12. Recommendations",
        "13. Limitations",
    ):
        assert section_title in html_text

    assert "<svg " in html_text
    assert "filterFindings()" in html_text
    assert "Incomplete Benchmark Run:" in html_text
    assert "<script>alert(1)</script>" not in html_text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_text

    # Generate printable PDF and validate structure & extracted text via pypdf
    pdf_path = exporter.export(
        run=run,
        score_report=score_report,
        results=results,
        output_dir=tmp_path,
        report_format="pdf",
        suite=suite,
        comparison=comparison,
    )
    pdf_bytes = pdf_path.read_bytes()
    assert pdf_bytes.startswith(b"%PDF-")

    reader = PdfReader(str(pdf_path))
    assert len(reader.pages) >= 1
    extracted = "\n".join(page.extract_text() or "" for page in reader.pages)
    assert "Arbiter SecurityBench Report" in extracted
    assert "INCOMPLETE RUN WARNING" in extracted
    assert "tc-det-crit" in extracted
    assert "13. Limitations" in extracted
