"""Interactive standalone HTML report renderer with inline SVG charts and JS filtering."""

from __future__ import annotations

import html
import json

from arbiter_securitybench.reporting.models import ReportDocument


def _pct(val: float | None) -> str:
    return "N/A" if val is None else f"{val * 100:.1f}%"


def _score(val: float | None) -> str:
    return "N/A" if val is None else f"{val:.1f} / 100"


def _esc(val: object) -> str:
    return html.escape("" if val is None else str(val), quote=True)


def _render_category_svg(doc: ReportDocument) -> str:
    rows = doc.category_results
    if not rows:
        return "<p class='muted'>No category results available.</p>"

    bar_h = 26
    gap = 14
    left_pad = 230
    chart_w = 420
    svg_w = left_pad + chart_w + 90
    svg_h = 34 + len(rows) * (bar_h + gap)
    lines = [
        f'<svg viewBox="0 0 {svg_w} {svg_h}" class="chart-svg" role="img" aria-label="Category Attack Success vs Block Rate">',
        f'<text x="{left_pad}" y="16" font-size="11" fill="#374151">0%</text>',
        f'<text x="{left_pad + chart_w // 2 - 12}" y="16" font-size="11" fill="#374151">50%</text>',
        f'<text x="{left_pad + chart_w - 22}" y="16" font-size="11" fill="#374151">100%</text>',
    ]
    for idx, row in enumerate(rows):
        y = 26 + idx * (bar_h + gap)
        asr = row.metrics.attack_success_rate or 0.0
        abr = row.metrics.attack_block_rate or 0.0
        asr_w = round(asr * chart_w, 1)
        abr_w = round(abr * chart_w, 1)
        lines.append(
            f'<text x="6" y="{y + 16}" font-size="12" fill="#111827">{_esc(row.category.value)}</text>'
        )
        lines.append(
            f'<rect x="{left_pad}" y="{y}" width="{chart_w}" height="{bar_h}" fill="#f3f4f6" rx="3" />'
        )
        lines.append(
            f'<rect x="{left_pad}" y="{y}" width="{asr_w}" height="{bar_h // 2}" fill="#dc2626" rx="2" />'
        )
        lines.append(
            f'<rect x="{left_pad}" y="{y + bar_h // 2}" width="{abr_w}" height="{bar_h // 2}" fill="#16a34a" rx="2" />'
        )
        lines.append(
            f'<text x="{left_pad + chart_w + 8}" y="{y + 12}" font-size="10" fill="#dc2626">ASR {_pct(row.metrics.attack_success_rate)}</text>'
        )
        lines.append(
            f'<text x="{left_pad + chart_w + 8}" y="{y + 23}" font-size="10" fill="#16a34a">ABR {_pct(row.metrics.attack_block_rate)}</text>'
        )
    lines.append("</svg>")
    return "\n".join(lines)


def _render_severity_svg(doc: ReportDocument) -> str:
    rows = doc.severity_distribution
    max_total = max((r.total for r in rows), default=0)
    if max_total == 0:
        return "<p class='muted'>No severity distribution samples recorded.</p>"

    left_pad = 100
    chart_w = 420
    svg_w = left_pad + chart_w + 110
    row_h = 26
    svg_h = 20 + len(rows) * 34
    lines = [
        f'<svg viewBox="0 0 {svg_w} {svg_h}" class="chart-svg" role="img" aria-label="Severity Distribution">'
    ]
    for idx, row in enumerate(rows):
        y = 12 + idx * 34
        scale = chart_w / max_total
        w_succ = round(row.successful_attacks * scale, 1)
        w_blk = round(row.blocked_attacks * scale, 1)
        w_inc = round((row.inconclusive + row.execution_errors + row.evaluation_failures) * scale, 1)
        x = float(left_pad)
        lines.append(
            f'<text x="6" y="{y + 16}" font-size="12" fill="#111827">{_esc(row.severity.value.upper())}</text>'
        )
        lines.append(
            f'<rect x="{left_pad}" y="{y}" width="{chart_w}" height="{row_h}" fill="#f3f4f6" rx="3" />'
        )
        if w_succ > 0:
            lines.append(f'<rect x="{x}" y="{y}" width="{w_succ}" height="{row_h}" fill="#dc2626" />')
            x += w_succ
        if w_blk > 0:
            lines.append(f'<rect x="{x}" y="{y}" width="{w_blk}" height="{row_h}" fill="#16a34a" />')
            x += w_blk
        if w_inc > 0:
            lines.append(f'<rect x="{x}" y="{y}" width="{w_inc}" height="{row_h}" fill="#d97706" />')
        lines.append(
            f'<text x="{left_pad + chart_w + 8}" y="{y + 17}" font-size="11" fill="#374151">n={row.total} (vuln={row.successful_attacks})</text>'
        )
    lines.append("</svg>")
    return "\n".join(lines)


def _render_ci_svg(doc: ReportDocument) -> str:
    ci_sec = doc.statistical_confidence_intervals
    intervals: list[tuple[str, dict[str, object]]] = []
    if ci_sec.asr_wilson_ci:
        intervals.append(("ASR (Wilson 95% CI)", ci_sec.asr_wilson_ci))
    if ci_sec.asr_bootstrap_ci:
        intervals.append(("ASR (Bootstrap CI)", ci_sec.asr_bootstrap_ci))
    if ci_sec.severity_weighted_asr_bootstrap_ci:
        intervals.append(("Severity-Weighted ASR CI", ci_sec.severity_weighted_asr_bootstrap_ci))

    if not intervals:
        return "<p class='muted'>No statistical confidence intervals computed (zero samples).</p>"

    left_pad = 190
    chart_w = 400
    svg_w = left_pad + chart_w + 130
    svg_h = 30 + len(intervals) * 38
    lines = [
        f'<svg viewBox="0 0 {svg_w} {svg_h}" class="chart-svg" role="img" aria-label="Confidence Intervals">',
        f'<line x1="{left_pad}" y1="14" x2="{left_pad + chart_w}" y2="14" stroke="#d1d5db" />',
    ]
    for idx, (label, ci) in enumerate(intervals):
        y = 34 + idx * 38
        low = float(ci.get("lower", 0.0))  # type: ignore[arg-type]
        est = float(ci.get("estimate", 0.0))  # type: ignore[arg-type]
        high = float(ci.get("upper", 0.0))  # type: ignore[arg-type]
        x1 = left_pad + low * chart_w
        xm = left_pad + est * chart_w
        x2 = left_pad + high * chart_w
        lines.append(f'<text x="6" y="{y + 4}" font-size="11" fill="#111827">{_esc(label)}</text>')
        lines.append(f'<line x1="{x1:.1f}" y1="{y}" x2="{x2:.1f}" y2="{y}" stroke="#2563eb" stroke-width="3" />')
        lines.append(f'<circle cx="{xm:.1f}" cy="{y}" r="5" fill="#1d4ed8" />')
        lines.append(
            f'<text x="{left_pad + chart_w + 10}" y="{y + 4}" font-size="11" fill="#374151">'
            f'{est * 100:.1f}% [{low * 100:.1f}%, {high * 100:.1f}%]</text>'
        )
    lines.append("</svg>")
    return "\n".join(lines)


def render_html_report(doc: ReportDocument) -> str:
    """Render a ReportDocument into a self-contained interactive HTML report."""
    es = doc.executive_summary
    ti = doc.target_information
    bc = doc.benchmark_configuration
    bv = doc.benchmark_version
    om = doc.overall_security_metrics
    sc = om.sample_counts

    incomplete_banner = ""
    if not es.is_complete_run:
        incomplete_banner = (
            "<div class='banner-warn'>"
            f"<strong>Incomplete Benchmark Run:</strong> {_esc(es.incomplete_run_reason or es.run_status.value)}"
            "</div>"
        )

    warnings_html = "".join(f"<li>{_esc(w)}</li>" for w in es.warnings)

    cat_rows_html = []
    for row in doc.category_results:
        cm = row.metrics
        cat_rows_html.append(
            "<tr>"
            f"<td><code>{_esc(row.category.value)}</code></td>"
            f"<td>{cm.sample_counts.total_samples}</td>"
            f"<td>{cm.sample_counts.successful_attacks}</td>"
            f"<td>{cm.sample_counts.blocked_attacks}</td>"
            f"<td>{cm.sample_counts.inconclusive_samples}</td>"
            f"<td>{_pct(cm.attack_success_rate)}</td>"
            f"<td>{_pct(cm.attack_block_rate)}</td>"
            f"<td>{_pct(cm.severity_weighted_asr)}</td>"
            f"<td>{cm.critical_compromises}</td>"
            "</tr>"
        )

    finding_rows_html = []
    for f in doc.successful_attack_analysis:
        ev_items = "".join(f"<li>{_esc(e)}</li>" for e in f.evidence_summary[:5])
        badge_cls = (
            "badge-verified"
            if f.verification_classification.value == "deterministic_verified"
            else "badge-judgment"
        )
        finding_rows_html.append(
            f"<tr class='finding-row' data-severity='{_esc(f.severity.value)}' "
            f"data-verification='{_esc(f.verification_classification.value)}' "
            f"data-search='{_esc((f.test_id + ' ' + (f.test_name or '') + ' ' + (f.category.value if f.category else '')).lower())}'>"
            f"<td><code>{_esc(f.test_id)}</code><br/><small>{_esc(f.test_name or '')}</small></td>"
            f"<td>{_esc(f.category.value if f.category else 'unknown')}</td>"
            f"<td><span class='sev sev-{_esc(f.severity.value)}'>{_esc(f.severity.value.upper())}</span></td>"
            f"<td><span class='badge {badge_cls}'>{_esc(f.verification_classification.value)}</span></td>"
            f"<td>{'N/A' if f.confidence is None else f'{f.confidence:.2f}'}</td>"
            f"<td><details><summary>{_esc(f.reasoning[:90])}</summary>"
            f"<p>{_esc(f.reasoning)}</p>"
            f"{'<ul>' + ev_items + '</ul>' if ev_items else ''}"
            f"{'<pre>' + _esc(f.output_excerpt) + '</pre>' if f.output_excerpt else ''}"
            "</details></td>"
            "</tr>"
        )

    incomplete_rows = []
    fi = doc.failed_and_inconclusive_tests
    for rec in [*fi.execution_errors, *fi.evaluation_failures, *fi.inconclusive_tests]:
        incomplete_rows.append(
            "<tr>"
            f"<td><code>{_esc(rec.test_id)}</code></td>"
            f"<td>{_esc(rec.failure_kind)}</td>"
            f"<td>{_esc(rec.execution_status)}</td>"
            f"<td>{_esc(rec.error_message or rec.reasoning or '-')}</td>"
            "</tr>"
        )

    sev_rows_html = "".join(
        "<tr>"
        f"<td>{_esc(r.severity.value.upper())}</td>"
        f"<td>{r.total}</td>"
        f"<td>{r.successful_attacks}</td>"
        f"<td>{r.blocked_attacks}</td>"
        f"<td>{r.inconclusive}</td>"
        f"<td>{r.execution_errors}</td>"
        f"<td>{r.evaluation_failures}</td>"
        "</tr>"
        for r in doc.severity_distribution
    )

    if doc.benchmark_comparison.available and doc.benchmark_comparison.comparison is not None:
        cmp = doc.benchmark_comparison.comparison
        comp_html = (
            f"<p><strong>Baseline:</strong> <code>{_esc(cmp.baseline_run_id)}</code> ({_esc(cmp.baseline_target_id)}) "
            f"vs <strong>Candidate:</strong> <code>{_esc(cmp.candidate_run_id)}</code> ({_esc(cmp.candidate_target_id)})</p>"
            f"<p><strong>ASR Delta:</strong> {_pct(cmp.asr_delta)} | "
            f"<strong>Block Rate Delta:</strong> {_pct(cmp.block_rate_delta)} | "
            f"<strong>Regression Detected:</strong> {'YES' if cmp.regression_detected else 'NO'}</p>"
            f"<p><strong>Improved Categories:</strong> {_esc(', '.join(c.value for c in cmp.improved_categories) or 'None')}</p>"
            f"<p><strong>Degraded Categories:</strong> {_esc(', '.join(c.value for c in cmp.degraded_categories) or 'None')}</p>"
        )
    else:
        comp_html = f"<p class='muted'>{_esc(doc.benchmark_comparison.reason or 'Not available.')}</p>"

    recs_html = "".join(f"<li>{_esc(r)}</li>" for r in doc.recommendations)
    lims_html = "".join(f"<li>{_esc(lim)}</li>" for lim in doc.limitations.limitations)
    stat_notes_html = "".join(
        f"<li>{_esc(n)}</li>" for n in doc.statistical_confidence_intervals.statistical_notes
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Arbiter SecurityBench Report — {_esc(es.run_id)}</title>
  <style>
    :root {{ --bg: #f8fafc; --card: #ffffff; --border: #e2e8f0; --text: #0f172a; --muted: #475569; }}
    body {{ font-family: system-ui, -apple-system, Segoe UI, sans-serif; margin: 0; padding: 2rem; background: var(--bg); color: var(--text); line-height: 1.5; }}
    .container {{ max-width: 1120px; margin: 0 auto; }}
    .section {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem 1.5rem; margin-bottom: 1.25rem; }}
    h1 {{ margin-top: 0; font-size: 1.75rem; }}
    h2 {{ margin-top: 0; font-size: 1.2rem; border-bottom: 1px solid var(--border); padding-bottom: 0.4rem; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 0.75rem; margin: 1rem 0; }}
    .kpi {{ background: #f1f5f9; border-radius: 6px; padding: 0.75rem 1rem; }}
    .kpi .label {{ font-size: 0.78rem; color: var(--muted); text-transform: uppercase; }}
    .kpi .val {{ font-size: 1.35rem; font-weight: 700; margin-top: 0.2rem; }}
    table {{ border-collapse: collapse; width: 100%; margin: 0.75rem 0; font-size: 0.9rem; }}
    th, td {{ border: 1px solid var(--border); padding: 0.5rem 0.65rem; text-align: left; vertical-align: top; }}
    th {{ background: #f1f5f9; }}
    .banner-warn {{ background: #fef3c7; border: 1px solid #f59e0b; padding: 0.85rem 1rem; border-radius: 6px; margin-bottom: 1rem; }}
    .badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 999px; font-size: 0.75rem; font-weight: 600; }}
    .badge-verified {{ background: #dcfce7; color: #166534; }}
    .badge-judgment {{ background: #e0f2fe; color: #075985; }}
    .sev {{ font-weight: 700; font-size: 0.78rem; }}
    .sev-critical {{ color: #991b1b; }} .sev-high {{ color: #c2410c; }} .sev-medium {{ color: #a16207; }}
    .controls {{ display: flex; gap: 0.75rem; flex-wrap: wrap; margin-bottom: 0.75rem; }}
    input, select {{ padding: 0.4rem 0.6rem; border: 1px solid var(--border); border-radius: 4px; }}
    .chart-svg {{ width: 100%; max-width: 760px; height: auto; display: block; margin: 0.5rem 0; }}
    .muted {{ color: var(--muted); }}
    pre {{ background: #f8fafc; padding: 0.5rem; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; }}
    @media print {{ body {{ background: #fff; padding: 0.5rem; }} .controls {{ display: none; }} .section {{ break-inside: avoid; }} }}
  </style>
</head>
<body>
<div class="container">
  <h1>Arbiter SecurityBench Report</h1>
  {incomplete_banner}

  <section class="section">
    <h2>1. Executive Summary</h2>
    <p><strong>{_esc(es.headline)}</strong></p>
    <div class="grid">
      <div class="kpi"><div class="label">Security Score</div><div class="val">{_score(es.security_score)}</div></div>
      <div class="kpi"><div class="label">Attack Success Rate</div><div class="val">{_pct(es.attack_success_rate)}</div></div>
      <div class="kpi"><div class="label">Attack Block Rate</div><div class="val">{_pct(es.attack_block_rate)}</div></div>
      <div class="kpi"><div class="label">Total Samples</div><div class="val">{es.total_samples}</div></div>
      <div class="kpi"><div class="label">Deterministic Compromises</div><div class="val">{es.deterministic_verified_compromises}</div></div>
      <div class="kpi"><div class="label">Evaluator Judgments</div><div class="val">{es.evaluator_judgment_compromises}</div></div>
    </div>
    {"<ul>" + warnings_html + "</ul>" if warnings_html else ""}
  </section>

  <section class="section">
    <h2>2. Target Information</h2>
    <p><strong>Target ID:</strong> <code>{_esc(ti.target_id)}</code> | <strong>Modality:</strong> <code>{_esc(ti.target_type.value)}</code></p>
    <p><strong>Created:</strong> {_esc(ti.created_at.isoformat())} | <strong>Started:</strong> {_esc(ti.started_at.isoformat() if ti.started_at else 'N/A')} | <strong>Completed:</strong> {_esc(ti.completed_at.isoformat() if ti.completed_at else 'N/A')}</p>
    <pre>{_esc(json.dumps(ti.sanitized_target_config, indent=2))}</pre>
  </section>

  <section class="section">
    <h2>3. Benchmark Configuration &amp; 4. Benchmark Version</h2>
    <p><strong>Benchmark ID:</strong> <code>{_esc(bv.benchmark_id)}</code> | <strong>Version:</strong> <code>{_esc(bv.benchmark_version)}</code> | <strong>Suite Schema:</strong> <code>{_esc(bv.suite_schema_version)}</code></p>
    <p><strong>Scoring Profile:</strong> <code>{_esc(bc.scoring_profile_id)}</code> | <strong>Platform Version:</strong> <code>{_esc(bc.platform_version)}</code> | <strong>Suite Digest:</strong> <code>{_esc(bv.suite_content_digest or 'N/A')}</code></p>
    <pre>{_esc(json.dumps(bc.execution_config, indent=2))}</pre>
  </section>

  <section class="section">
    <h2>5. Overall Security Metrics</h2>
    <table>
      <tr><th>Metric</th><th>Value</th></tr>
      <tr><td>Total Samples (Denominator)</td><td>{sc.total_samples}</td></tr>
      <tr><td>Successful Attacks</td><td>{sc.successful_attacks}</td></tr>
      <tr><td>Blocked Attacks</td><td>{sc.blocked_attacks}</td></tr>
      <tr><td>Inconclusive Samples</td><td>{sc.inconclusive_samples}</td></tr>
      <tr><td>Execution Errors</td><td>{sc.execution_error_samples}</td></tr>
      <tr><td>Evaluation Failures</td><td>{sc.evaluation_failure_samples}</td></tr>
      <tr><td>Evaluation Coverage</td><td>{_pct(om.evaluation_coverage)}</td></tr>
      <tr><td>Severity-Weighted ASR</td><td>{_pct(om.severity_weighted_asr)}</td></tr>
      <tr><td>False Positive Rate (Ground-Truth)</td><td>{_pct(om.false_positive_rate)}</td></tr>
      <tr><td>False Negative Rate (Ground-Truth)</td><td>{_pct(om.false_negative_rate)}</td></tr>
    </table>
  </section>

  <section class="section">
    <h2>6. Category-wise Results</h2>
    {_render_category_svg(doc)}
    <table>
      <tr><th>Category</th><th>Samples</th><th>Compromised</th><th>Blocked</th><th>Inconclusive</th><th>ASR</th><th>Block Rate</th><th>Severity-Weighted ASR</th><th>Critical</th></tr>
      {"".join(cat_rows_html) if cat_rows_html else "<tr><td colspan='9'>No category data.</td></tr>"}
    </table>
  </section>

  <section class="section">
    <h2>7. Successful Attack Analysis</h2>
    <div class="controls">
      <input id="findingSearch" type="search" placeholder="Filter by test ID or category..." oninput="filterFindings()" />
      <select id="severityFilter" onchange="filterFindings()">
        <option value="">All Severities</option>
        <option value="critical">CRITICAL</option>
        <option value="high">HIGH</option>
        <option value="medium">MEDIUM</option>
        <option value="low">LOW</option>
      </select>
      <select id="verificationFilter" onchange="filterFindings()">
        <option value="">All Verification Types</option>
        <option value="deterministic_verified">Deterministic Verified</option>
        <option value="evaluator_judgment">Evaluator Judgment</option>
        <option value="mixed_or_disputed">Mixed / Disputed</option>
      </select>
    </div>
    <table>
      <thead><tr><th>Test</th><th>Category</th><th>Severity</th><th>Verification</th><th>Confidence</th><th>Details</th></tr></thead>
      <tbody id="findingsBody">
        {"".join(finding_rows_html) if finding_rows_html else "<tr><td colspan='6'>No successful attacks recorded.</td></tr>"}
      </tbody>
    </table>
  </section>

  <section class="section">
    <h2>8. Failed and Inconclusive Tests</h2>
    <table>
      <tr><th>Test ID</th><th>Classification</th><th>Execution Status</th><th>Details</th></tr>
      {"".join(incomplete_rows) if incomplete_rows else "<tr><td colspan='4'>No failed or inconclusive tests.</td></tr>"}
    </table>
  </section>

  <section class="section">
    <h2>9. Severity Distribution</h2>
    {_render_severity_svg(doc)}
    <table>
      <tr><th>Severity</th><th>Total</th><th>Successful Attacks</th><th>Blocked</th><th>Inconclusive</th><th>Exec Errors</th><th>Eval Failures</th></tr>
      {sev_rows_html}
    </table>
  </section>

  <section class="section">
    <h2>10. Statistical Confidence Intervals</h2>
    {_render_ci_svg(doc)}
    {"<ul>" + stat_notes_html + "</ul>" if stat_notes_html else ""}
  </section>

  <section class="section">
    <h2>11. Benchmark Comparison</h2>
    {comp_html}
  </section>

  <section class="section">
    <h2>12. Recommendations</h2>
    <ul>{recs_html}</ul>
  </section>

  <section class="section">
    <h2>13. Limitations &amp; Methodology</h2>
    <p>{_esc(doc.limitations.methodology_summary)}</p>
    <ul>{lims_html}</ul>
  </section>
</div>
<script>
function filterFindings() {{
  const q = (document.getElementById('findingSearch').value || '').toLowerCase();
  const sev = document.getElementById('severityFilter').value;
  const ver = document.getElementById('verificationFilter').value;
  document.querySelectorAll('#findingsBody .finding-row').forEach(row => {{
    const matchText = !q || row.dataset.search.includes(q);
    const matchSev = !sev || row.dataset.severity === sev;
    const matchVer = !ver || row.dataset.verification === ver;
    row.style.display = (matchText && matchSev && matchVer) ? '' : 'none';
  }});
}}
</script>
</body>
</html>
"""
