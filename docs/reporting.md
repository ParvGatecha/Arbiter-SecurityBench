# Reporting Engine Specification — Arbiter SecurityBench

The **Arbiter SecurityBench Reporting Engine** (`arbiter_securitybench.reporting`) transforms persisted `BenchmarkRun`, `RunScoreReport`, `TestExecutionResult`, and optional `BenchmarkComparisonReport` objects into reproducible, audit-ready reports.

---

## 1. Supported Formats

| Format | Flag / Config Value | Renderer | Primary Use Case |
|---|---|---|---|
| **JSON** | `json` | `ReportDocument.model_dump_json()` | Machine-readable CI/CD ingestion, archival, downstream SIEM/GRC pipelines |
| **HTML** | `html` | `render_html_report()` | Self-contained interactive report with inline SVG charts, severity/verification filters, and expandable evidence |
| **PDF** | `pdf` | `render_pdf_report()` (ReportLab) | Clean, printable executive and compliance audit artifact |
| **Markdown** | `markdown` / `md` | `ReportExporter.render_markdown()` | Lightweight repository/PR summaries |

---

## 2. Standardized 13-Section Structure

Every JSON, HTML, and PDF report preserves the same canonical 13 sections:

1. **Executive Summary** — Run completeness flag (`is_complete_run`), headline, sample breakdown, deterministic vs. evaluator-judgment compromise counts, critical compromises, and warnings.
2. **Target Information** — `target_id`, `target_type`, sanitized target configuration (inline secret-like fields redacted), and execution timestamps.
3. **Benchmark Configuration** — Suite ID, scoring profile ID, execution configuration, scheduled/completed/failed test counts, and platform/schema versions.
4. **Benchmark Version** — Exact semantic `benchmark_version`, suite `schema_version`, and SHA-256 `suite_content_digest`.
5. **Overall Security Metrics** — Total denominator accounting, ASR, Attack Block Rate, Inconclusive Rate, Execution Error Rate, Evaluation Failure Rate, Evaluation Coverage, Severity-Weighted ASR, and ground-truth FPR/FNR (`null` when ground-truth labels are absent).
6. **Category-wise Results** — Per-`SecurityCategory` sample counts, ASR, Block Rate, Severity-Weighted ASR, and critical compromise counts.
7. **Successful Attack Analysis** — Per-finding `test_id`, category, severity, `verification_classification` (`deterministic_verified`, `evaluator_judgment`, or `mixed_or_disputed`), confidence, evidence, reasoning, and excerpt.
8. **Failed and Inconclusive Tests** — Separate tables for `execution_errors`, `evaluation_failures`, and `inconclusive_tests`.
9. **Severity Distribution** — Outcome breakdown across `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, and `INFO`.
10. **Statistical Confidence Intervals** — Wilson 95% CI, bootstrap CIs, sample-size adequacy flag, and statistical assumptions/notes.
11. **Benchmark Comparison** — Baseline vs. candidate deltas, improved/degraded categories, and regression flags when a baseline run is provided (`available: false` otherwise).
12. **Recommendations** — Evidence-grounded next steps derived strictly from observed compromises, incomplete runs, or errors.
13. **Limitations** — Methodological summary and explicit scope/validity boundaries.

---

## 3. Epistemic & Reproducibility Guarantees

- **Zero Fabricated Metrics:** Missing FPR/FNR or zero-sample rates remain `null` / `N/A`.
- **Incomplete Run Flagging:** `PARTIALLY_COMPLETED`, `FAILED`, `CANCELLED`, or missing-evaluation runs display an explicit incomplete-run warning banner in HTML/PDF and `is_complete_run: false` in JSON.
- **Verification Separation:** Deterministic findings (`RuleBasedEvaluator` exact/canary matches, `SensitiveInfoEvaluator` leaks, `ExecutionEvaluator` tool compromises) are explicitly separated from non-ground-truth `EVALUATOR_JUDGMENT` and `MIXED_OR_DISPUTED` findings.

---

## 4. Usage Examples

### Python API
```python
from arbiter_securitybench.reporting import ReportExporter

exporter = ReportExporter()
pdf_path = exporter.export(
    run=run,
    score_report=score_report,
    results=results,
    output_dir="reports",
    report_format="pdf",
    suite=suite,
    comparison=comparison,  # optional BenchmarkComparisonReport
)
```

### CLI
```bash
arbiter report generate --run-id run-abc123 --format html --output-dir reports
arbiter report generate --run-id run-abc123 --baseline-run-id run-base --format pdf
arbiter report generate --run-id run-abc123 --format json
```
