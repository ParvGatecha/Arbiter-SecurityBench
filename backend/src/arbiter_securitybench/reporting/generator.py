"""Unified ReportExporter generating JSON, HTML, PDF, and Markdown reports."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from arbiter_securitybench.contracts import (
    BenchmarkRun,
    BenchmarkSuite,
    TestExecutionResult,
)
from arbiter_securitybench.reporting.builder import ReportBuilder
from arbiter_securitybench.reporting.html_renderer import render_html_report
from arbiter_securitybench.reporting.models import ReportDocument
from arbiter_securitybench.reporting.pdf_renderer import render_pdf_report
from arbiter_securitybench.scoring import BenchmarkComparisonReport, RunScoreReport


def _fmt_pct(value: float | None) -> str:
    return "N/A" if value is None else f"{value * 100:.1f}%"


def _fmt_score(value: float | None) -> str:
    return "N/A" if value is None else f"{value:.1f} / 100"


class ReportExporter:
    """Renders reproducible JSON, HTML, PDF, and Markdown reports."""

    def __init__(self, builder: ReportBuilder | None = None) -> None:
        self._builder = builder or ReportBuilder()

    def build_document(
        self,
        *,
        run: BenchmarkRun,
        score_report: RunScoreReport,
        results: Sequence[TestExecutionResult],
        suite: BenchmarkSuite | None = None,
        comparison: BenchmarkComparisonReport | None = None,
    ) -> ReportDocument:
        """Assemble the structured 13-section ReportDocument."""
        return self._builder.build(
            run=run,
            score_report=score_report,
            results=results,
            suite=suite,
            comparison=comparison,
        )

    def export(
        self,
        *,
        run: BenchmarkRun,
        score_report: RunScoreReport,
        results: Sequence[TestExecutionResult],
        output_dir: Path | str,
        report_format: str = "html",
        suite: BenchmarkSuite | None = None,
        comparison: BenchmarkComparisonReport | None = None,
    ) -> Path:
        """Write a formatted report file for a benchmark run and return its path."""
        fmt = report_format.strip().lower()
        if fmt not in {"html", "json", "pdf", "markdown", "md"}:
            raise ValueError(f"Unsupported report format: {report_format!r}")

        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        ext = "md" if fmt in {"markdown", "md"} else fmt
        out_path = out_dir / f"report_{run.run_id}.{ext}"

        doc = self.build_document(
            run=run,
            score_report=score_report,
            results=results,
            suite=suite,
            comparison=comparison,
        )

        if fmt == "pdf":
            out_path.write_bytes(render_pdf_report(doc))
        elif fmt == "json":
            out_path.write_text(doc.model_dump_json(indent=2) + "\n", encoding="utf-8")
        elif fmt in {"markdown", "md"}:
            out_path.write_text(self.render_markdown(doc), encoding="utf-8")
        else:
            out_path.write_text(render_html_report(doc), encoding="utf-8")
        return out_path

    def render_json(
        self,
        *,
        run: BenchmarkRun,
        score_report: RunScoreReport,
        results: Sequence[TestExecutionResult],
        suite: BenchmarkSuite | None = None,
        comparison: BenchmarkComparisonReport | None = None,
    ) -> str:
        doc = self.build_document(
            run=run,
            score_report=score_report,
            results=results,
            suite=suite,
            comparison=comparison,
        )
        return doc.model_dump_json(indent=2) + "\n"

    def render_html(
        self,
        *,
        run: BenchmarkRun,
        score_report: RunScoreReport,
        results: Sequence[TestExecutionResult],
        suite: BenchmarkSuite | None = None,
        comparison: BenchmarkComparisonReport | None = None,
    ) -> str:
        doc = self.build_document(
            run=run,
            score_report=score_report,
            results=results,
            suite=suite,
            comparison=comparison,
        )
        return render_html_report(doc)

    def render_pdf(
        self,
        *,
        run: BenchmarkRun,
        score_report: RunScoreReport,
        results: Sequence[TestExecutionResult],
        suite: BenchmarkSuite | None = None,
        comparison: BenchmarkComparisonReport | None = None,
    ) -> bytes:
        doc = self.build_document(
            run=run,
            score_report=score_report,
            results=results,
            suite=suite,
            comparison=comparison,
        )
        return render_pdf_report(doc)

    def render_markdown(self, doc: ReportDocument) -> str:
        es = doc.executive_summary
        ti = doc.target_information
        bv = doc.benchmark_version
        om = doc.overall_security_metrics
        c = om.sample_counts
        lines = [
            f"# Arbiter SecurityBench Report — `{es.run_id}`",
            "",
            "## 1. Executive Summary",
            f"- **Headline:** {es.headline}",
            f"- **Run Status:** `{es.run_status.value}` (Complete: `{es.is_complete_run}`)",
            f"- **Deterministic Compromises:** {es.deterministic_verified_compromises}",
            f"- **Evaluator Judgment Compromises:** {es.evaluator_judgment_compromises}",
            "",
            "## 2. Target Information",
            f"- **Target:** `{ti.target_id}` (`{ti.target_type.value}`)",
            "",
            "## 3. Benchmark Configuration & 4. Benchmark Version",
            f"- **Benchmark:** `{bv.benchmark_id}` (`{bv.benchmark_version}`)",
            f"- **Scoring Profile:** `{doc.benchmark_configuration.scoring_profile_id}`",
            "",
            "## 5. Overall Security Metrics",
            "| Metric | Value |",
            "|---|---|",
            f"| Total Samples | {c.total_samples} |",
            f"| Successful Attacks | {c.successful_attacks} |",
            f"| Blocked Attacks | {c.blocked_attacks} |",
            f"| Inconclusive | {c.inconclusive_samples} |",
            f"| Execution Errors | {c.execution_error_samples} |",
            f"| Evaluation Failures | {c.evaluation_failure_samples} |",
            f"| Attack Success Rate (ASR) | {_fmt_pct(om.attack_success_rate)} |",
            f"| Attack Block Rate (ABR) | {_fmt_pct(om.attack_block_rate)} |",
            f"| Severity-Weighted ASR | {_fmt_pct(om.severity_weighted_asr)} |",
            f"| Evaluation Coverage | {_fmt_pct(om.evaluation_coverage)} |",
            f"| Security Score | {_fmt_score(om.security_score)} |",
            "",
            "## 6. Category-wise Results",
            "| Category | Samples | ASR | Block Rate |",
            "|---|---:|---:|---:|",
        ]
        for row in doc.category_results:
            cm = row.metrics
            lines.append(
                f"| `{row.category.value}` | {cm.sample_counts.total_samples} | "
                f"{_fmt_pct(cm.attack_success_rate)} | {_fmt_pct(cm.attack_block_rate)} |"
            )
        lines.extend(["", "## 12. Recommendations"])
        for rec in doc.recommendations:
            lines.append(f"- {rec}")
        lines.extend(["", "## 13. Limitations"])
        for lim in doc.limitations.limitations:
            lines.append(f"- {lim}")
        return "\n".join(lines) + "\n"
