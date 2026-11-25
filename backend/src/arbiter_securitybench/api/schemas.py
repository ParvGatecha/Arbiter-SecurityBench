"""FastAPI request and response schemas for Benchmark Core, Scoring, Reporting, and Targets."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from arbiter_securitybench.contracts import (
    BenchmarkLifecycleState,
    BenchmarkRun,
    DifficultyLevel,
    RunStatus,
    SecurityCategory,
    SemanticVersion,
    SeverityLevel,
    TargetModality,
    TestCase,
    TestExecutionResult,
    TestExecutionStatus,
)


class ErrorResponse(BaseModel):
    """Consistent structured API error payload."""

    model_config = ConfigDict(frozen=True)

    error_code: str
    category: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


class CreateBenchmarkRunRequest(BaseModel):
    """Request payload for triggering a sequential benchmark execution run."""

    model_config = ConfigDict(extra="forbid")

    benchmark_id: str = Field(min_length=1, max_length=128)
    version: str | None = Field(default=None, min_length=1)
    target_id: str = Field(min_length=1, max_length=128)
    target_config: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("version")
    @classmethod
    def _validate_optional_semver(cls, value: str | None) -> str | None:
        if value is not None:
            SemanticVersion.parse(value)
        return value


class BenchmarkSummaryResponse(BaseModel):
    """Summary representation of a registered benchmark suite version."""

    benchmark_id: str
    suite_id: str
    name: str
    description: str
    version: str
    categories: list[SecurityCategory]
    supported_target_types: list[TargetModality]
    test_count: int
    lifecycle_state: BenchmarkLifecycleState


class BenchmarkListResponse(BaseModel):
    """Filtered list of registered benchmarks."""

    items: list[BenchmarkSummaryResponse]
    total: int


class BenchmarkDetailResponse(BaseModel):
    """Detailed representation of a specific benchmark suite and its versions."""

    benchmark_id: str
    suite_id: str
    name: str
    description: str
    version: str
    available_versions: list[str]
    categories: list[SecurityCategory]
    supported_target_types: list[TargetModality]
    lifecycle_state: BenchmarkLifecycleState
    test_count: int
    test_cases: list[TestCase]
    metadata: dict[str, Any]


class PaginatedTestCasesResponse(BaseModel):
    """Paginated and filtered test cases belonging to a benchmark suite."""

    benchmark_id: str
    suite_id: str
    version: str
    items: list[TestCase]
    total: int
    limit: int
    offset: int
    categories: list[SecurityCategory] = Field(default_factory=list)
    difficulties: list[DifficultyLevel] = Field(default_factory=list)
    severities: list[SeverityLevel] = Field(default_factory=list)


class RunListResponse(BaseModel):
    """Paginated list of benchmark execution runs."""

    items: list[BenchmarkRun]
    total: int
    total_count: int
    limit: int
    offset: int


class RunResultsResponse(BaseModel):
    """Execution results belonging to a single benchmark run."""

    run_id: str
    benchmark_id: str
    benchmark_version: str
    target_id: str
    status: RunStatus
    total_results: int
    filtered_total: int
    limit: int
    offset: int
    results: list[TestExecutionResult]


class TargetSummaryResponse(BaseModel):
    """Sanitized representation of a registered target adapter instance."""

    target_id: str
    target_type: TargetModality
    adapter_type: str
    provider: str
    model_name: str
    endpoint: str | None = None
    capabilities: list[str] = Field(default_factory=list)
    is_connected: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class TargetListResponse(BaseModel):
    """List of registered target adapters and supported adapter factory types."""

    items: list[TargetSummaryResponse]
    available_adapter_types: list[str]
    total: int


class CreateTargetRequest(BaseModel):
    """Request payload for registering a configured HTTP/model target adapter."""

    model_config = ConfigDict(extra="forbid")

    adapter_type: Literal["openai", "anthropic", "gemini", "ollama", "http"]
    target_id: str = Field(min_length=1, max_length=128)
    target_type: TargetModality = TargetModality.LLM
    model: str | None = Field(default=None, min_length=1)
    base_url: str | None = Field(default=None, min_length=1)
    endpoint_url: str | None = Field(default=None, min_length=1)
    api_key_env_var: str | None = None
    allow_unauthenticated: bool | None = None
    timeout_seconds: float = Field(default=30.0, gt=0.0, le=300.0)
    response_text_path: str = Field(default="response", min_length=1)
    prompt_field: str = Field(default="prompt", min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


class TargetHealthResponse(BaseModel):
    """Live connectivity and health check result for a registered target adapter."""

    target_id: str
    healthy: bool
    latency_ms: float | None = None
    detail: str


class CompareRunsRequest(BaseModel):
    """Request payload for statistical comparison between two compatible benchmark runs."""

    model_config = ConfigDict(extra="forbid")

    baseline_run_id: str = Field(min_length=1, max_length=128)
    candidate_run_id: str = Field(min_length=1, max_length=128)
    profile: Literal["default", "weighted"] = "default"


class LeaderboardEntryResponse(BaseModel):
    """Verified or community-submitted leaderboard row computed strictly from eligible persisted runs."""

    rank: int = Field(ge=1)
    run_id: str
    target_id: str
    target_type: TargetModality
    provider: str | None = None
    model_name: str | None = None
    benchmark_id: str
    benchmark_version: str
    submission_type: Literal["official_verified", "community_submitted"]
    security_score: float = Field(ge=0.0, le=100.0)
    attack_success_rate: float = Field(ge=0.0, le=1.0)
    attack_block_rate: float = Field(ge=0.0, le=1.0)
    severity_weighted_asr: float = Field(ge=0.0, le=1.0)
    inconclusive_rate: float = Field(ge=0.0, le=1.0)
    evaluation_coverage: float = Field(ge=0.0, le=1.0)
    total_samples: int = Field(ge=1)
    critical_compromises: int = Field(ge=0)
    high_compromises: int = Field(ge=0)
    score_capped_by_critical_policy: bool = False
    completed_at: datetime | None = None
    category_asr: dict[str, float | None] = Field(default_factory=dict)


class LeaderboardResponse(BaseModel):
    """Real leaderboard computed strictly from eligible completed benchmark runs."""

    items: list[LeaderboardEntryResponse]
    total: int
    eligible_runs_count: int
    excluded_runs_count: int
    eligibility_criteria: str


class PlatformSettingsResponse(BaseModel):
    """Non-secret runtime settings and capability inventory for the active backend instance."""

    platform_version: str
    storage_backend: str
    builtin_datasets_loaded: bool
    default_timeout_seconds: float | None
    available_adapter_types: list[str]
    registered_target_count: int
    registered_benchmark_count: int
    scoring_profiles: list[str]
    report_formats: list[str]
    supported_run_statuses: list[RunStatus]
    supported_result_statuses: list[TestExecutionStatus]
