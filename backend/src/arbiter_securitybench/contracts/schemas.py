"""Canonical Pydantic v2 schemas for Arbiter SecurityBench.

All schemas are strictly typed, version-aware, and designed to prevent
unverified claims from masquerading as verified security findings.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from arbiter_securitybench.contracts.errors import ErrorRecord
from arbiter_securitybench.contracts.lifecycles import (
    BenchmarkLifecycleState,
    EvaluationLifecycleState,
    ExecutionLifecycleState,
    TestCaseLifecycleState,
)
from arbiter_securitybench.contracts.versioning import (
    SCHEMA_VERSION,
    ComponentVersions,
    compute_canonical_digest,
)


class SecurityCategory(StrEnum):
    """Initial seven core AI security benchmark categories."""

    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK_RESISTANCE = "jailbreak_resistance"
    SENSITIVE_DATA_LEAKAGE = "sensitive_data_leakage"
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    TOOL_SECURITY = "tool_security"
    RAG_SECURITY = "rag_security"
    AGENT_SECURITY = "agent_security"


class TargetModality(StrEnum):
    """System architecture class under test."""

    LLM = "llm"
    RAG = "rag"
    AGENT = "agent"


class SeverityLevel(StrEnum):
    """Security impact severity assigned to a test case or finding."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackOutcome(StrEnum):
    """Outcome of a single test case execution trace."""

    DEFENDED = "defended"
    COMPROMISED = "compromised"
    PARTIAL = "partial"
    INCONCLUSIVE = "inconclusive"
    EXECUTION_ERROR = "execution_error"


class VerificationStatus(StrEnum):
    """Epistemic verification status of an evaluation result.

    Constraint: UNVERIFIED or INDETERMINATE results must never be reported
    as verified security findings.
    """

    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    INDETERMINATE = "indeterminate"
    ERRORED = "errored"


class EvaluatorType(StrEnum):
    """Mechanism used to evaluate an execution trace."""

    DETERMINISTIC_RULE = "deterministic_rule"
    CANARY_MATCH = "canary_match"
    TOOL_POLICY_ASSERTION = "tool_policy_assertion"
    CLASSIFIER = "classifier"
    LLM_JUDGE = "llm_judge"
    HUMAN_ADJUDICATION = "human_adjudication"
    HYBRID_CONSENSUS = "hybrid_consensus"


class ReportFormat(StrEnum):
    """Supported export formats for reproducible benchmark reports."""

    JSON = "json"
    MARKDOWN = "markdown"
    SARIF = "sarif"
    BUNDLE_TAR_GZ = "bundle_tar_gz"


class ContentDigest(BaseModel):
    """Cryptographic integrity digest of a canonical payload."""

    model_config = ConfigDict(frozen=True)

    algorithm: str = Field(default="sha256", pattern="^sha256$")
    hex_digest: str = Field(pattern="^[0-9a-f]{64}$")

    @classmethod
    def from_payload(cls, payload: Any) -> ContentDigest:
        return cls(algorithm="sha256", hex_digest=compute_canonical_digest(payload))


class TestCaseReference(BaseModel):
    """Immutable reference to a specific pinned version of a test case."""

    model_config = ConfigDict(frozen=True)

    test_case_id: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=1)
    content_digest: ContentDigest
    weight: float = Field(default=1.0, gt=0.0)


class TestCaseSpec(BaseModel):
    """Canonical specification for an individual security test case."""

    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default=SCHEMA_VERSION)
    test_case_id: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=1)
    title: str = Field(min_length=1, max_length=256)
    category: SecurityCategory
    subcategory: str = Field(min_length=1, max_length=128)
    target_modality: TargetModality
    severity: SeverityLevel
    attack_vector: str = Field(min_length=1)
    system_context_template: str | None = None
    turns: list[dict[str, Any]] = Field(min_length=1)
    rag_fixtures: list[dict[str, Any]] = Field(default_factory=list)
    tool_fixtures: list[dict[str, Any]] = Field(default_factory=list)
    expected_safe_behavior: str = Field(min_length=1)
    failure_indicators: list[str] = Field(min_length=1)
    evaluation_rubric: dict[str, Any] = Field(default_factory=dict)
    requires_deterministic_verification: bool = Field(default=False)
    lifecycle_state: TestCaseLifecycleState = Field(default=TestCaseLifecycleState.PROPOSED)
    provenance: dict[str, str] = Field(default_factory=dict)
    content_digest: ContentDigest | None = None

    def canonical_payload(self) -> dict[str, Any]:
        """Return fields that define the immutable semantic content of the test case."""
        return self.model_dump(
            exclude={"lifecycle_state", "content_digest"},
            mode="json",
        )


class BenchmarkSpec(BaseModel):
    """Canonical specification of a versioned security benchmark suite."""

    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default=SCHEMA_VERSION)
    benchmark_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=256)
    version: str = Field(min_length=1)
    description: str = Field(min_length=1)
    categories: list[SecurityCategory] = Field(min_length=1)
    target_modalities: list[TargetModality] = Field(min_length=1)
    test_cases: list[TestCaseReference] = Field(default_factory=list)
    evaluation_policy_version: str = Field(min_length=1)
    lifecycle_state: BenchmarkLifecycleState = Field(default=BenchmarkLifecycleState.DRAFT)
    provenance: dict[str, str] = Field(default_factory=dict)
    content_digest: ContentDigest | None = None

    @model_validator(mode="after")
    def _published_requires_cases_and_digest(self) -> BenchmarkSpec:
        if self.lifecycle_state == BenchmarkLifecycleState.PUBLISHED:
            if not self.test_cases:
                raise ValueError("Published benchmark must include at least one test case.")
            if self.content_digest is None:
                raise ValueError("Published benchmark must include a content_digest.")
        return self


class TargetConfig(BaseModel):
    """Pinned configuration of the target AI system under evaluation."""

    model_config = ConfigDict(frozen=True)

    target_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=256)
    modality: TargetModality
    adapter_type: str = Field(min_length=1, max_length=128)
    adapter_version: str = Field(min_length=1)
    model_identifier: str = Field(min_length=1, max_length=256)
    inference_parameters: dict[str, Any] = Field(default_factory=dict)
    tool_permissions: list[str] = Field(default_factory=list)
    rag_corpus_snapshot_ref: str | None = None
    configuration_digest: ContentDigest | None = None


class ExecutionPolicy(BaseModel):
    """Controls determinism, retries, timeouts, and sandbox isolation for a run."""

    model_config = ConfigDict(frozen=True)

    repetitions_per_case: int = Field(default=1, ge=1, le=50)
    per_turn_timeout_seconds: float = Field(default=60.0, gt=0.0)
    per_case_timeout_seconds: float = Field(default=300.0, gt=0.0)
    max_retries_on_transient_error: int = Field(default=2, ge=0, le=10)
    concurrency_limit: int = Field(default=4, ge=1, le=128)
    fail_fast_on_integrity_error: bool = Field(default=True)
    sandbox_enforced: bool = Field(default=True)


class ExecutionEnvironmentSnapshot(BaseModel):
    """Captured runtime environment metadata required for reproducibility audits."""

    model_config = ConfigDict(frozen=True)

    python_version: str
    os_platform: str
    dependency_lock_digest: str | None = None
    git_commit: str | None = None
    worker_hostname_hash: str | None = None
    captured_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ExecutionManifest(BaseModel):
    """Immutable manifest pinning every input required to reproduce a benchmark run."""

    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default=SCHEMA_VERSION)
    run_id: str = Field(min_length=1, max_length=128)
    benchmark_id: str = Field(min_length=1, max_length=128)
    benchmark_version: str = Field(min_length=1)
    benchmark_digest: ContentDigest
    target_config: TargetConfig
    versions: ComponentVersions
    random_seed: int = Field(ge=0)
    execution_policy: ExecutionPolicy = Field(default_factory=ExecutionPolicy)
    environment: ExecutionEnvironmentSnapshot
    lifecycle_state: ExecutionLifecycleState = Field(default=ExecutionLifecycleState.PENDING)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    started_at: datetime | None = None
    completed_at: datetime | None = None
    run_errors: list[ErrorRecord] = Field(default_factory=list)


class ToolCallRecord(BaseModel):
    """Trace record of an attempted or executed tool invocation during an attack."""

    model_config = ConfigDict(frozen=True)

    call_id: str
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    permitted_by_policy: bool
    executed_in_sandbox: bool
    output_summary: str | None = None
    error: str | None = None


class TurnTrace(BaseModel):
    """Single interaction turn within a test case execution trace."""

    model_config = ConfigDict(frozen=True)

    turn_index: int = Field(ge=0)
    input_payload: dict[str, Any]
    retrieved_context_refs: list[str] = Field(default_factory=list)
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    raw_output: str | None = None
    latency_ms: float = Field(ge=0.0)
    token_usage: dict[str, int] = Field(default_factory=dict)


class ExecutionTrace(BaseModel):
    """Complete execution trace for one attempt of one test case."""

    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default=SCHEMA_VERSION)
    trace_id: str = Field(min_length=1, max_length=128)
    run_id: str = Field(min_length=1, max_length=128)
    test_case_id: str = Field(min_length=1, max_length=128)
    test_case_version: str = Field(min_length=1)
    attempt_index: int = Field(ge=0)
    derived_seed: int = Field(ge=0)
    turns: list[TurnTrace] = Field(default_factory=list)
    error: ErrorRecord | None = None
    trace_digest: ContentDigest | None = None
    recorded_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class EvaluatorEvidence(BaseModel):
    """Auditable evidence produced by an evaluator supporting an outcome."""

    model_config = ConfigDict(frozen=True)

    rule_or_criterion_id: str
    matched: bool
    rationale: str
    observed_span: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvaluationResult(BaseModel):
    """Outcome and verification record for a single execution trace."""

    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default=SCHEMA_VERSION)
    evaluation_id: str = Field(min_length=1, max_length=128)
    run_id: str = Field(min_length=1, max_length=128)
    trace_id: str = Field(min_length=1, max_length=128)
    test_case_id: str = Field(min_length=1, max_length=128)
    category: SecurityCategory
    severity: SeverityLevel
    evaluator_id: str = Field(min_length=1)
    evaluator_version: str = Field(min_length=1)
    evaluator_type: EvaluatorType
    outcome: AttackOutcome
    verification_status: VerificationStatus
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    evidence: list[EvaluatorEvidence] = Field(default_factory=list)
    lifecycle_state: EvaluationLifecycleState = Field(default=EvaluationLifecycleState.PRELIMINARY)
    error: ErrorRecord | None = None
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def _enforce_epistemic_integrity(self) -> EvaluationResult:
        if (
            self.lifecycle_state == EvaluationLifecycleState.VERIFIED
            and self.verification_status != VerificationStatus.VERIFIED
        ):
            raise ValueError(
                "Evaluation in VERIFIED lifecycle state must have verification_status == VERIFIED."
            )
        if self.outcome == AttackOutcome.EXECUTION_ERROR and self.verification_status == VerificationStatus.VERIFIED:
            raise ValueError(
                "An EXECUTION_ERROR outcome cannot be marked as VerificationStatus.VERIFIED."
            )
        return self


class ConfidenceInterval(BaseModel):
    """Statistical confidence interval for an estimated metric."""

    model_config = ConfigDict(frozen=True)

    method: str = Field(min_length=1)
    confidence_level: float = Field(gt=0.0, lt=1.0)
    lower: float = Field(ge=0.0, le=1.0)
    upper: float = Field(ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _bounds_ordered(self) -> ConfidenceInterval:
        if self.lower > self.upper:
            raise ValueError("Confidence interval lower bound cannot exceed upper bound.")
        return self


class CategoryScore(BaseModel):
    """Aggregated security score breakdown for a single SecurityCategory."""

    model_config = ConfigDict(frozen=True)

    category: SecurityCategory
    total_traces: int = Field(ge=0)
    verified_traces: int = Field(ge=0)
    unverified_traces: int = Field(ge=0)
    indeterminate_traces: int = Field(ge=0)
    errored_traces: int = Field(ge=0)
    attack_success_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    defense_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    defense_rate_ci: ConfidenceInterval | None = None
    severity_weighted_risk: float | None = Field(default=None, ge=0.0, le=1.0)


class ScoreSummary(BaseModel):
    """Top-level score summary for a benchmark run."""

    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default=SCHEMA_VERSION)
    run_id: str = Field(min_length=1)
    scoring_version: str = Field(min_length=1)
    total_traces: int = Field(ge=0)
    verified_traces: int = Field(ge=0)
    unverified_traces: int = Field(ge=0)
    indeterminate_traces: int = Field(ge=0)
    errored_traces: int = Field(ge=0)
    overall_defense_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    overall_defense_rate_ci: ConfidenceInterval | None = None
    overall_severity_weighted_risk: float | None = Field(default=None, ge=0.0, le=1.0)
    category_scores: list[CategoryScore] = Field(default_factory=list)
    includes_unverified_results: bool = Field(default=False)
    computed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class HypothesisTestResult(BaseModel):
    """Result of a statistical comparison test between two runs or configurations."""

    model_config = ConfigDict(frozen=True)

    test_name: str
    comparison_label: str
    statistic: float
    p_value: float = Field(ge=0.0, le=1.0)
    adjusted_p_value: float | None = Field(default=None, ge=0.0, le=1.0)
    effect_size: float | None = None
    sample_size: int = Field(ge=0)
    notes: str | None = None


class InterRaterReliabilityResult(BaseModel):
    """Agreement metrics between independent evaluators or human adjudicators."""

    model_config = ConfigDict(frozen=True)

    metric_name: str
    score: float = Field(ge=-1.0, le=1.0)
    sample_size: int = Field(ge=0)
    raters: list[str] = Field(min_length=2)


class StatisticalAnalysisResult(BaseModel):
    """Statistical analysis output accompanying a ScoreSummary."""

    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default=SCHEMA_VERSION)
    analysis_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    statistical_version: str = Field(min_length=1)
    confidence_level: float = Field(default=0.95, gt=0.0, lt=1.0)
    hypothesis_tests: list[HypothesisTestResult] = Field(default_factory=list)
    inter_rater_reliability: list[InterRaterReliabilityResult] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    computed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ReportArtifact(BaseModel):
    """Descriptor for an exported benchmark report artifact."""

    model_config = ConfigDict(frozen=True)

    report_id: str
    run_id: str
    report_format: ReportFormat
    content_digest: ContentDigest
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    verified_findings_only: bool = Field(default=True)


class ResultBundle(BaseModel):
    """Canonical, self-contained result storage format for export and auditing."""

    model_config = ConfigDict(frozen=True)

    bundle_schema_version: str = Field(default=SCHEMA_VERSION)
    manifest: ExecutionManifest
    traces: list[ExecutionTrace] = Field(default_factory=list)
    evaluations: list[EvaluationResult] = Field(default_factory=list)
    score_summary: ScoreSummary | None = None
    statistical_analysis: StatisticalAnalysisResult | None = None
    bundle_digest: ContentDigest | None = None
