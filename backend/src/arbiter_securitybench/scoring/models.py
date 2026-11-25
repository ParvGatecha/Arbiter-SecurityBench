"""Structured scoring, category breakdown, and run comparison schemas."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from arbiter_securitybench.contracts import SecurityCategory, SeverityLevel, TargetModality
from arbiter_securitybench.statistics import ProportionCI, SignificanceTestOutput


class SampleStatus(StrEnum):
    """Mutually exclusive accounting classification of a single benchmark sample."""

    SUCCESSFUL_ATTACK = "successful_attack"
    BLOCKED_ATTACK = "blocked_attack"
    INCONCLUSIVE = "inconclusive"
    EXECUTION_ERROR = "execution_error"
    EVALUATION_FAILURE = "evaluation_failure"


class ScoredSample(BaseModel):
    """Normalized scoring input for one executed test case item."""

    model_config = ConfigDict(frozen=True)

    test_id: str = Field(min_length=1)
    category: SecurityCategory
    severity: SeverityLevel
    status: SampleStatus
    weight: float = Field(default=1.0, gt=0.0)
    ground_truth_attack_success: bool | None = None


class SampleSizeReport(BaseModel):
    """Transparent sample accounting distinguishing execution errors from evaluation failures."""

    model_config = ConfigDict(frozen=True)

    total_samples: int = Field(ge=0)
    successful_attacks: int = Field(ge=0)
    blocked_attacks: int = Field(ge=0)
    inconclusive_samples: int = Field(ge=0)
    execution_error_samples: int = Field(ge=0)
    evaluation_failure_samples: int = Field(ge=0)
    evaluated_samples: int = Field(ge=0)
    decisive_samples: int = Field(ge=0)
    ground_truth_samples: int = Field(ge=0)
    is_small_sample: bool


class SecurityMetrics(BaseModel):
    """Complete metric suite for either an overall run or a single SecurityCategory."""

    model_config = ConfigDict(frozen=True)

    sample_counts: SampleSizeReport
    attack_success_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    attack_block_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    inconclusive_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    execution_error_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    evaluation_failure_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    evaluation_coverage: float | None = Field(default=None, ge=0.0, le=1.0)
    decisive_attack_success_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    severity_weighted_asr: float | None = Field(default=None, ge=0.0, le=1.0)
    false_positive_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    false_negative_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    asr_wilson_ci: ProportionCI | None = None
    asr_bootstrap_ci: ProportionCI | None = None
    severity_weighted_asr_bootstrap_ci: ProportionCI | None = None
    security_score: float | None = Field(default=None, ge=0.0, le=100.0)
    score_capped_by_critical_policy: bool = False
    critical_compromises: int = Field(default=0, ge=0)
    high_compromises: int = Field(default=0, ge=0)


class CategoryScoreReport(BaseModel):
    """Metrics breakdown for one SecurityCategory."""

    model_config = ConfigDict(frozen=True)

    category: SecurityCategory
    metrics: SecurityMetrics


class RunScoreReport(BaseModel):
    """Complete statistically grounded score report for a single benchmark run."""

    model_config = ConfigDict(frozen=True)

    run_id: str
    benchmark_id: str
    benchmark_version: str
    target_id: str
    target_type: TargetModality
    execution_config: dict[str, Any] = Field(default_factory=dict)
    profile_id: str
    overall_metrics: SecurityMetrics
    category_metrics: dict[SecurityCategory, CategoryScoreReport] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class CategoryDeltaReport(BaseModel):
    """Per-category comparison between a baseline run and candidate run."""

    model_config = ConfigDict(frozen=True)

    category: SecurityCategory
    baseline_asr: float | None
    candidate_asr: float | None
    asr_delta: float | None
    baseline_block_rate: float | None
    candidate_block_rate: float | None
    block_rate_delta: float | None
    significance: SignificanceTestOutput | None = None
    status: str  # "improved" | "degraded" | "unchanged" | "insufficient_data"


class BenchmarkComparisonReport(BaseModel):
    """Statistical comparison and regression detection report between two benchmark runs."""

    model_config = ConfigDict(frozen=True)

    benchmark_id: str
    benchmark_version: str
    baseline_run_id: str
    baseline_target_id: str
    baseline_execution_config: dict[str, Any] = Field(default_factory=dict)
    candidate_run_id: str
    candidate_target_id: str
    candidate_execution_config: dict[str, Any] = Field(default_factory=dict)
    asr_delta: float | None
    block_rate_delta: float | None
    severity_weighted_asr_delta: float | None
    security_score_delta: float | None
    inconclusive_rate_delta: float | None
    execution_error_rate_delta: float | None
    baseline_asr_ci: ProportionCI | None = None
    candidate_asr_ci: ProportionCI | None = None
    overall_significance: SignificanceTestOutput | None = None
    category_comparisons: dict[SecurityCategory, CategoryDeltaReport] = Field(default_factory=dict)
    improved_categories: list[SecurityCategory] = Field(default_factory=list)
    degraded_categories: list[SecurityCategory] = Field(default_factory=list)
    regression_detected: bool
    regression_warnings: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
