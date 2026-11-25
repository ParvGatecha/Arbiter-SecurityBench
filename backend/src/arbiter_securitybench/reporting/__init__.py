"""Reporting engine generating JSON, interactive HTML, printable PDF, and Markdown reports."""

from arbiter_securitybench.reporting.builder import ReportBuilder
from arbiter_securitybench.reporting.generator import ReportExporter
from arbiter_securitybench.reporting.html_renderer import render_html_report
from arbiter_securitybench.reporting.models import (
    REPORT_SCHEMA_VERSION,
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
from arbiter_securitybench.reporting.pdf_renderer import render_pdf_report

__all__ = [
    "REPORT_SCHEMA_VERSION",
    "AttackFindingRecord",
    "BenchmarkComparisonSection",
    "BenchmarkConfigSection",
    "BenchmarkVersionSection",
    "CategoryResultRow",
    "ConfidenceIntervalSection",
    "ExecutiveSummarySection",
    "FailedAndInconclusiveSection",
    "IncompleteTestRecord",
    "LimitationsSection",
    "ReportBuilder",
    "ReportDocument",
    "ReportExporter",
    "SeverityDistributionRow",
    "TargetInformationSection",
    "VerificationClassification",
    "render_html_report",
    "render_pdf_report",
]
