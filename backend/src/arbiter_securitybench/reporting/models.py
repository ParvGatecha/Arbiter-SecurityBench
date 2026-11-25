"""Stable machine-readable report schemas covering all 13 benchmark report sections."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from arbiter_securitybench.contracts import (
    PLATFORM_VERSION,
    SCHEMA_VERSION,
    RunStatus,
    SecurityCategory,
    SeverityLevel,
    TargetModality,
)
from arbiter_securitybench.scoring import BenchmarkComparisonReport, SecurityMetrics

REPORT_SCHEMA_VERSION = "1.0.0"


class VerificationClassification(StrEnum):
    """Distinguishes deterministic verified findings from probabilistic evaluator judgments."""

    DETERMINISTIC_VERIFIED = "deterministic_verified"
    EVALUATOR_JUDGMENT = "evaluator_judgment"
    MIXED_OR_DISPUTED = "mixed_or_disputed"


class ExecutiveSummarySection(BaseModel):
    """High-level security posture and run completeness summary."""

    model_config = ConfigDict(frozen=True)

    run_id: str
    run_status: RunStatus
    is_complete_run: bool
    incomplete_run_reason: str | None = None
    headline: str
    total_samples: int = Field(ge=0)
    successful_attacks: int = Field(ge=0)
    blocked_attacks: int = Field(ge=0)
    inconclusive_samples: int = Field(ge=0)
    execution_error_samples: int = Field(ge=0)
    evaluation_failure_samples: int = Field(ge=0)
    deterministic_verified_compromises: int = Field(ge=0)
    evaluator_judgment_compromises: int = Field(ge=0)
    critical_compromises: int = Field(ge=0)
    attack_success_rate: float | None = None
    attack_block_rate: float | None = None
    security_score: float | None = None
    warnings: list[str] = Field(default_factory=list)


class TargetInformationSection(BaseModel):
    """Sanitized target system identity and timing metadata."""

    model_config = ConfigDict(frozen=True)

    target_id: str
    target_type: TargetModality
    sanitized_target_config: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None


class BenchmarkConfigSection(BaseModel):
    """Reproducibility and execution configuration metadata."""

    model_config = ConfigDict(frozen=True)

    benchmark_id: str
    suite_id: str
    scoring_profile_id: str
    execution_config: dict[str, Any] = Field(default_factory=dict)
    total_tests_scheduled: int = Field(ge=0)
    completed_tests: int = Field(ge=0)
    failed_tests: int = Field(ge=0)
    platform_version: str = Field(default=PLATFORM_VERSION)
    contract_schema_version: str = Field(default=SCHEMA_VERSION)
    suite_content_digest: str | None = None


class BenchmarkVersionSection(BaseModel):
    """Exact version provenance of the executed benchmark suite."""

    model_config = ConfigDict(frozen=True)

    benchmark_id: str
    benchmark_version: str
    suite_schema_version: str = Field(default=SCHEMA_VERSION)
    suite_content_digest: str | None = None


class CategoryResultRow(BaseModel):
    """Per-category metrics summary."""

    model_config = ConfigDict(frozen=True)

    category: SecurityCategory
    metrics: SecurityMetrics


class AttackFindingRecord(BaseModel):
    """Detailed record for a test case classified as SUCCESSFUL_ATTACK."""

    model_config = ConfigDict(frozen=True)

    test_id: str
    test_name: str | None = None
    category: SecurityCategory | None = None
    severity: SeverityLevel
    attack_type: str | None = None
    verification_classification: VerificationClassification
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    evaluator_ids: list[str] = Field(default_factory=list)
    has_disagreement: bool = False
    evidence_summary: list[str] = Field(default_factory=list)
    reasoning: str
    output_excerpt: str | None = None


class IncompleteTestRecord(BaseModel):
    """Record for a test case that failed execution, lacked evaluation, or was inconclusive."""

    model_config = ConfigDict(frozen=True)

    test_id: str
    failure_kind: str  # "execution_error" | "evaluation_failure" | "inconclusive"
    execution_status: str
    error_message: str | None = None
    reasoning: str | None = None
    has_disagreement: bool = False


class FailedAndInconclusiveSection(BaseModel):
    """Grouped accounting of execution errors, evaluation failures, and inconclusive tests."""

    model_config = ConfigDict(frozen=True)

    execution_errors: list[IncompleteTestRecord] = Field(default_factory=list)
    evaluation_failures: list[IncompleteTestRecord] = Field(default_factory=list)
    inconclusive_tests: list[IncompleteTestRecord] = Field(default_factory=list)


class SeverityDistributionRow(BaseModel):
    """Outcome counts for a single SeverityLevel."""

    model_config = ConfigDict(frozen=True)

    severity: SeverityLevel
    total: int = Field(ge=0)
    successful_attacks: int = Field(ge=0)
    blocked_attacks: int = Field(ge=0)
    inconclusive: int = Field(ge=0)
    execution_errors: int = Field(ge=0)
    evaluation_failures: int = Field(ge=0)


class ConfidenceIntervalSection(BaseModel):
    """Statistical uncertainty bounds and sample-size reporting."""

    model_config = ConfigDict(frozen=True)

    confidence_level: float = Field(gt=0.0, lt=1.0)
    sample_size: int = Field(ge=0)
    is_small_sample: bool
    asr_wilson_ci: dict[str, Any] | None = None
    asr_bootstrap_ci: dict[str, Any] | None = None
    severity_weighted_asr_bootstrap_ci: dict[str, Any] | None = None
    statistical_notes: list[str] = Field(default_factory=list)


class BenchmarkComparisonSection(BaseModel):
    """Optional run-to-run comparison section (never fabricated when unavailable)."""

    model_config = ConfigDict(frozen=True)

    available: bool
    reason: str | None = None
    comparison: BenchmarkComparisonReport | None = None


class LimitationsSection(BaseModel):
    """Explicit methodological and scope limitations included in every report."""

    model_config = ConfigDict(frozen=True)

    methodology_summary: str
    limitations: list[str] = Field(default_factory=list)


class ReportDocument(BaseModel):
    """Stable machine-readable JSON schema containing all 13 required report sections."""

    model_config = ConfigDict(frozen=True)

    report_schema_version: str = Field(default=REPORT_SCHEMA_VERSION)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    executive_summary: ExecutiveSummarySection
    target_information: TargetInformationSection
    benchmark_configuration: BenchmarkConfigSection
    benchmark_version: BenchmarkVersionSection
    overall_security_metrics: SecurityMetrics
    category_results: list[CategoryResultRow] = Field(default_factory=list)
    successful_attack_analysis: list[AttackFindingRecord] = Field(default_factory=list)
    failed_and_inconclusive_tests: FailedAndInconclusiveSection
    severity_distribution: list[SeverityDistributionRow] = Field(default_factory=list)
    statistical_confidence_intervals: ConfidenceIntervalSection
    benchmark_comparison: BenchmarkComparisonSection
    recommendations: list[str] = Field(default_factory=list)
    limitations: LimitationsSection
    raw_results: list[dict[str, Any]] = Field(default_factory=list)
