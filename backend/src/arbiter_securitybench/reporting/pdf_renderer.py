"""Printable PDF report renderer built with ReportLab Platypus."""

from __future__ import annotations

import html
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from arbiter_securitybench.reporting.models import ReportDocument


def _pct(val: float | None) -> str:
    return "N/A" if val is None else f"{val * 100:.1f}%"


def _score(val: float | None) -> str:
    return "N/A" if val is None else f"{val:.1f} / 100"


def _p(text: object, style: ParagraphStyle) -> Paragraph:
    return Paragraph(html.escape("" if text is None else str(text)), style)


def _styled_table(data: list[list[Paragraph]], col_widths: list[float]) -> Table:
    tbl = Table(data, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ])
    )
    return tbl


def _draw_footer(canvas, doc_template) -> None:  # type: ignore[no-untyped-def]
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#64748b"))
    canvas.drawString(0.65 * inch, 0.4 * inch, "Arbiter SecurityBench Report")
    canvas.drawRightString(
        letter[0] - 0.65 * inch,
        0.4 * inch,
        f"Page {doc_template.page}",
    )
    canvas.restoreState()


def render_pdf_report(doc: ReportDocument) -> bytes:
    """Render a ReportDocument into printable PDF bytes."""
    buffer = BytesIO()
    pdf_doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=0.65 * inch,
        rightMargin=0.65 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.65 * inch,
        title=f"Arbiter SecurityBench Report - {doc.executive_summary.run_id}",
    )

    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    h2_style = ParagraphStyle("H2", parent=styles["Heading2"], spaceBefore=10, spaceAfter=4)
    body_style = ParagraphStyle("Body", parent=styles["BodyText"], fontSize=9, leading=12)
    cell_style = ParagraphStyle("Cell", parent=styles["BodyText"], fontSize=8, leading=10)
    hdr_style = ParagraphStyle("Hdr", parent=cell_style, fontName="Helvetica-Bold")

    story: list[object] = []
    es = doc.executive_summary
    ti = doc.target_information
    bc = doc.benchmark_configuration
    bv = doc.benchmark_version
    om = doc.overall_security_metrics
    sc = om.sample_counts

    story.append(_p("Arbiter SecurityBench Report", title_style))
    story.append(Spacer(1, 6))

    # 1. Executive Summary
    story.append(_p("1. Executive Summary", h2_style))
    if not es.is_complete_run:
        story.append(
            _p(
                f"INCOMPLETE RUN WARNING: {es.incomplete_run_reason or es.run_status.value}",
                body_style,
            )
        )
    story.append(_p(es.headline, body_style))
    story.append(
        _p(
            f"Run ID: {es.run_id} | Status: {es.run_status.value} | "
            f"Deterministic Compromises: {es.deterministic_verified_compromises} | "
            f"Evaluator Judgments: {es.evaluator_judgment_compromises}",
            body_style,
        )
    )
    for w in es.warnings:
        story.append(_p(f"- Warning: {w}", body_style))

    # 2. Target Information
    story.append(_p("2. Target Information", h2_style))
    story.append(
        _p(
            f"Target ID: {ti.target_id} | Modality: {ti.target_type.value} | "
            f"Created: {ti.created_at.isoformat()}",
            body_style,
        )
    )

    # 3 & 4. Benchmark Configuration & Version
    story.append(_p("3. Benchmark Configuration & 4. Benchmark Version", h2_style))
    story.append(
        _p(
            f"Benchmark: {bv.benchmark_id} (v{bv.benchmark_version}) | "
            f"Scoring Profile: {bc.scoring_profile_id} | "
            f"Platform: {bc.platform_version} | Digest: {bv.suite_content_digest or 'N/A'}",
            body_style,
        )
    )

    # 5. Overall Security Metrics
    story.append(_p("5. Overall Security Metrics", h2_style))
    metrics_rows = [
        [_p("Metric", hdr_style), _p("Value", hdr_style)],
        [_p("Total Samples", cell_style), _p(sc.total_samples, cell_style)],
        [_p("Successful Attacks", cell_style), _p(sc.successful_attacks, cell_style)],
        [_p("Blocked Attacks", cell_style), _p(sc.blocked_attacks, cell_style)],
        [_p("Inconclusive", cell_style), _p(sc.inconclusive_samples, cell_style)],
        [_p("Execution Errors", cell_style), _p(sc.execution_error_samples, cell_style)],
        [_p("Evaluation Failures", cell_style), _p(sc.evaluation_failure_samples, cell_style)],
        [_p("Attack Success Rate (ASR)", cell_style), _p(_pct(om.attack_success_rate), cell_style)],
        [_p("Attack Block Rate (ABR)", cell_style), _p(_pct(om.attack_block_rate), cell_style)],
        [_p("Severity-Weighted ASR", cell_style), _p(_pct(om.severity_weighted_asr), cell_style)],
        [_p("Evaluation Coverage", cell_style), _p(_pct(om.evaluation_coverage), cell_style)],
        [_p("False Positive Rate", cell_style), _p(_pct(om.false_positive_rate), cell_style)],
        [_p("False Negative Rate", cell_style), _p(_pct(om.false_negative_rate), cell_style)],
        [_p("Security Score", cell_style), _p(_score(om.security_score), cell_style)],
    ]
    story.append(_styled_table(metrics_rows, [3.6 * inch, 3.5 * inch]))

    # 6. Category-wise Results
    story.append(_p("6. Category-wise Results", h2_style))
    if doc.category_results:
        cat_rows = [
            [
                _p("Category", hdr_style),
                _p("N", hdr_style),
                _p("ASR", hdr_style),
                _p("Block Rate", hdr_style),
                _p("SW-ASR", hdr_style),
            ]
        ]
        for row in doc.category_results:
            cm = row.metrics
            cat_rows.append([
                _p(row.category.value, cell_style),
                _p(cm.sample_counts.total_samples, cell_style),
                _p(_pct(cm.attack_success_rate), cell_style),
                _p(_pct(cm.attack_block_rate), cell_style),
                _p(_pct(cm.severity_weighted_asr), cell_style),
            ])
        story.append(_styled_table(cat_rows, [2.7 * inch, 0.7 * inch, 1.2 * inch, 1.2 * inch, 1.3 * inch]))
    else:
        story.append(_p("No category results available.", body_style))

    # 7. Successful Attack Analysis
    story.append(_p("7. Successful Attack Analysis", h2_style))
    if doc.successful_attack_analysis:
        find_rows = [
            [
                _p("Test ID", hdr_style),
                _p("Severity", hdr_style),
                _p("Verification", hdr_style),
                _p("Reasoning", hdr_style),
            ]
        ]
        for f in doc.successful_attack_analysis:
            find_rows.append([
                _p(f.test_id, cell_style),
                _p(f.severity.value.upper(), cell_style),
                _p(f.verification_classification.value, cell_style),
                _p(f.reasoning, cell_style),
            ])
        story.append(_styled_table(find_rows, [1.2 * inch, 0.9 * inch, 1.6 * inch, 3.4 * inch]))
    else:
        story.append(_p("No successful attacks recorded.", body_style))

    # 8. Failed and Inconclusive Tests
    story.append(_p("8. Failed and Inconclusive Tests", h2_style))
    fi = doc.failed_and_inconclusive_tests
    inc_items = [*fi.execution_errors, *fi.evaluation_failures, *fi.inconclusive_tests]
    if inc_items:
        inc_rows = [
            [
                _p("Test ID", hdr_style),
                _p("Kind", hdr_style),
                _p("Status", hdr_style),
                _p("Details", hdr_style),
            ]
        ]
        for rec in inc_items:
            inc_rows.append([
                _p(rec.test_id, cell_style),
                _p(rec.failure_kind, cell_style),
                _p(rec.execution_status, cell_style),
                _p(rec.error_message or rec.reasoning or "-", cell_style),
            ])
        story.append(_styled_table(inc_rows, [1.2 * inch, 1.4 * inch, 1.2 * inch, 3.3 * inch]))
    else:
        story.append(_p("No failed or inconclusive tests recorded.", body_style))

    # 9. Severity Distribution
    story.append(_p("9. Severity Distribution", h2_style))
    sev_rows = [
        [
            _p("Severity", hdr_style),
            _p("Total", hdr_style),
            _p("Compromised", hdr_style),
            _p("Blocked", hdr_style),
            _p("Inconclusive", hdr_style),
            _p("Errors", hdr_style),
        ]
    ]
    for sr in doc.severity_distribution:
        sev_rows.append([
            _p(sr.severity.value.upper(), cell_style),
            _p(sr.total, cell_style),
            _p(sr.successful_attacks, cell_style),
            _p(sr.blocked_attacks, cell_style),
            _p(sr.inconclusive, cell_style),
            _p(sr.execution_errors + sr.evaluation_failures, cell_style),
        ])
    story.append(_styled_table(sev_rows, [1.3 * inch, 1.0 * inch, 1.2 * inch, 1.2 * inch, 1.2 * inch, 1.2 * inch]))

    # 10. Statistical Confidence Intervals
    story.append(_p("10. Statistical Confidence Intervals", h2_style))
    ci_sec = doc.statistical_confidence_intervals
    if ci_sec.asr_wilson_ci:
        w = ci_sec.asr_wilson_ci
        story.append(
            _p(
                f"ASR Wilson 95% CI: {float(w['estimate']) * 100:.1f}% "
                f"[{float(w['lower']) * 100:.1f}%, {float(w['upper']) * 100:.1f}%] (n={w['sample_size']})",
                body_style,
            )
        )
    if ci_sec.asr_bootstrap_ci:
        b = ci_sec.asr_bootstrap_ci
        story.append(
            _p(
                f"ASR Bootstrap CI: {float(b['estimate']) * 100:.1f}% "
                f"[{float(b['lower']) * 100:.1f}%, {float(b['upper']) * 100:.1f}%]",
                body_style,
            )
        )
    for note in ci_sec.statistical_notes:
        story.append(_p(f"- {note}", body_style))

    # 11. Benchmark Comparison
    story.append(_p("11. Benchmark Comparison", h2_style))
    if doc.benchmark_comparison.available and doc.benchmark_comparison.comparison is not None:
        cmp = doc.benchmark_comparison.comparison
        story.append(
            _p(
                f"Baseline {cmp.baseline_run_id} vs Candidate {cmp.candidate_run_id} | "
                f"ASR Delta: {_pct(cmp.asr_delta)} | Regression: {cmp.regression_detected}",
                body_style,
            )
        )
    else:
        story.append(_p(doc.benchmark_comparison.reason or "No baseline run provided.", body_style))

    # 12. Recommendations
    story.append(_p("12. Recommendations", h2_style))
    for r in doc.recommendations:
        story.append(_p(f"- {r}", body_style))

    # 13. Limitations
    story.append(_p("13. Limitations", h2_style))
    story.append(_p(doc.limitations.methodology_summary, body_style))
    for lim in doc.limitations.limitations:
        story.append(_p(f"- {lim}", body_style))

    pdf_doc.build(story, onFirstPage=_draw_footer, onLaterPages=_draw_footer)
    return buffer.getvalue()
