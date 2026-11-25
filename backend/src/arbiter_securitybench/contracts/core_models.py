"""Foundational Benchmark Core Pydantic models and target adapter contract.

These models define benchmark definitions, suites, test cases, benchmark runs,
and individual test execution results with strict validation and immutability.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from arbiter_securitybench.contracts.errors import ErrorRecord
from arbiter_securitybench.contracts.lifecycles import (
    BenchmarkLifecycleState,
    RunStatus,
    TestCaseLifecycleState,
)
from arbiter_securitybench.contracts.schemas import (
    ContentDigest,
    SecurityCategory,
    SeverityLevel,
    TargetModality,
)
from arbiter_securitybench.contracts.versioning import SCHEMA_VERSION, SemanticVersion


class AttackType(StrEnum):
    """Classification of the adversarial technique used by a test case."""

    DIRECT_INJECTION = "direct_injection"
    INDIRECT_INJECTION = "indirect_injection"
    JAILBREAK = "jailbreak"
    SENSITIVE_DATA_EXFILTRATION = "sensitive_data_exfiltration"
    SYSTEM_PROMPT_LEAKAGE = "system_prompt_leakage"
    TOOL_ABUSE = "tool_abuse"
    RAG_POISONING = "rag_poisoning"
    GOAL_HIJACKING = "goal_hijacking"
    MULTI_TURN_ESCALATION = "multi_turn_escalation"
    POLICY_EVASION = "policy_evasion"


class DifficultyLevel(StrEnum):
    """Relative adversarial sophistication of a test case."""

    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    EXPERT = "expert"


class TestExecutionStatus(StrEnum):
    """Execution status of an individual test case attempt."""

    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


class EvaluationCriteria(BaseModel):
    """Structured evaluation expectations attached to a test case."""

    model_config = ConfigDict(frozen=True)

    description: str = Field(min_length=1)
    success_indicators: list[str] = Field(default_factory=list)
    failure_indicators: list[str] = Field(default_factory=list)
    requires_deterministic_check: bool = Field(default=False)


class TestCase(BaseModel):
    """Strongly typed definition of an individual security benchmark test case."""

    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default=SCHEMA_VERSION)
    test_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=256)
    description: str = Field(min_length=1)
    category: SecurityCategory
    attack_type: AttackType
    difficulty: DifficultyLevel
    severity: SeverityLevel
    input_prompt: str = Field(min_length=1)
    expected_behavior: str = Field(min_length=1)
    evaluation_criteria: EvaluationCriteria
    tags: list[str] = Field(default_factory=list)
    benchmark_version: str = Field(min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)
    lifecycle_state: TestCaseLifecycleState = Field(default=TestCaseLifecycleState.ACTIVE)
    content_digest: ContentDigest | None = None

    @field_validator("benchmark_version")
    @classmethod
    def _validate_semver(cls, value: str) -> str:
        SemanticVersion.parse(value)
        return value

    @field_validator("tags")
    @classmethod
    def _normalize_tags(cls, value: list[str]) -> list[str]:
        seen: set[str] = set()
        normalized: list[str] = []
        for raw_tag in value:
            tag = raw_tag.strip()
            if not tag:
                raise ValueError("Test case tags must not contain empty strings.")
            if tag not in seen:
                seen.add(tag)
                normalized.append(tag)
        return normalized

    @model_validator(mode="after")
    def _ensure_content_digest(self) -> TestCase:
        if self.content_digest is None:
            digest = ContentDigest.from_payload(
                self.model_dump(exclude={"lifecycle_state", "content_digest"}, mode="json")
            )
            object.__setattr__(self, "content_digest", digest)
        return self


class BenchmarkSuite(BaseModel):
    """Versioned collection of security test cases forming an executable suite."""

    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default=SCHEMA_VERSION)
    suite_id: str = Field(min_length=1, max_length=128)
    benchmark_id: str = Field(default="")
    name: str = Field(min_length=1, max_length=256)
    description: str = Field(min_length=1)
    version: str = Field(min_length=1)
    supported_target_types: list[TargetModality] = Field(min_length=1)
    categories: list[SecurityCategory] = Field(default_factory=list)
    test_cases: list[TestCase] = Field(min_length=1)
    lifecycle_state: BenchmarkLifecycleState = Field(default=BenchmarkLifecycleState.DRAFT)
    metadata: dict[str, Any] = Field(default_factory=dict)
    content_digest: ContentDigest | None = None

    @field_validator("version")
    @classmethod
    def _validate_version(cls, value: str) -> str:
        SemanticVersion.parse(value)
        return value

    @field_validator("supported_target_types")
    @classmethod
    def _deduplicate_target_types(cls, value: list[TargetModality]) -> list[TargetModality]:
        return list(dict.fromkeys(value))

    @model_validator(mode="after")
    def _validate_suite_coherence(self) -> BenchmarkSuite:
        if not self.benchmark_id:
            object.__setattr__(self, "benchmark_id", self.suite_id)

        seen_test_ids: set[str] = set()
        case_categories: list[SecurityCategory] = []
        for tc in self.test_cases:
            if tc.test_id in seen_test_ids:
                raise ValueError(f"Duplicate test_id {tc.test_id!r} inside benchmark suite.")
            seen_test_ids.add(tc.test_id)
            if tc.category not in case_categories:
                case_categories.append(tc.category)

        if not self.categories:
            object.__setattr__(self, "categories", case_categories)
        else:
            dedup_cats = list(dict.fromkeys(self.categories))
            object.__setattr__(self, "categories", dedup_cats)
            missing = set(case_categories) - set(dedup_cats)
            if missing:
                missing_str = ", ".join(sorted(c.value for c in missing))
                raise ValueError(
                    f"Suite categories do not cover all test case categories: {missing_str}"
                )

        if self.content_digest is None:
            digest = ContentDigest.from_payload(
                self.model_dump(exclude={"lifecycle_state", "content_digest"}, mode="json")
            )
            object.__setattr__(self, "content_digest", digest)

        return self

    @property
    def test_count(self) -> int:
        return len(self.test_cases)

    def get_test_case(self, test_id: str) -> TestCase | None:
        for tc in self.test_cases:
            if tc.test_id == test_id:
                return tc
        return None


class BenchmarkDefinition(BaseModel):
    """Top-level identity and version index for a registered benchmark."""

    model_config = ConfigDict(frozen=True)

    benchmark_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=256)
    description: str = Field(min_length=1)
    categories: list[SecurityCategory] = Field(min_length=1)
    supported_target_types: list[TargetModality] = Field(min_length=1)
    versions: list[str] = Field(default_factory=list)
    latest_version: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("versions")
    @classmethod
    def _validate_versions(cls, value: list[str]) -> list[str]:
        for ver in value:
            SemanticVersion.parse(ver)
        return value


class TargetExecutionRequest(BaseModel):
    """Payload delivered to a target adapter for a single test execution."""

    model_config = ConfigDict(frozen=True)

    run_id: str = Field(min_length=1)
    test_id: str = Field(min_length=1)
    input_prompt: str = Field(min_length=1)
    target_config: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class TargetExecutionResponse(BaseModel):
    """Structured response returned by a target adapter for a single test execution."""

    model_config = ConfigDict(frozen=True)

    output: str | None = None
    raw_response: dict[str, Any] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class BenchmarkTargetAdapter(ABC):
    """Target adapter contract used by the Phase 1 benchmark execution engine."""

    @property
    @abstractmethod
    def target_id(self) -> str:
        """Stable identifier for the configured target."""

    @property
    @abstractmethod
    def target_type(self) -> TargetModality:
        """Target modality (LLM, RAG, or AGENT)."""

    @abstractmethod
    async def execute(self, request: TargetExecutionRequest) -> TargetExecutionResponse:
        """Execute a single test input against the target system."""


class TestExecutionResult(BaseModel):
    """Standardized result produced for a single executed test case."""

    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default=SCHEMA_VERSION)
    run_id: str = Field(min_length=1, max_length=128)
    test_id: str = Field(min_length=1, max_length=128)
    target_id: str = Field(min_length=1, max_length=128)
    input: str = Field(min_length=1)
    output: str | None = None
    execution_status: TestExecutionStatus
    execution_time: float = Field(ge=0.0)
    raw_response: dict[str, Any] | None = None
    evaluator_results: list[dict[str, Any]] = Field(default_factory=list)
    error_details: ErrorRecord | dict[str, Any] | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def _validate_result_integrity(self) -> TestExecutionResult:
        if self.execution_status == TestExecutionStatus.FAILED and self.error_details is None:
            raise ValueError("Failed test execution result must include error_details.")
        if self.execution_status == TestExecutionStatus.COMPLETED and self.output is None and self.raw_response is None:
            raise ValueError(
                "Completed test execution result cannot omit both output and raw_response."
            )
        return self


class BenchmarkRun(BaseModel):
    """Execution record for a benchmark suite run against a target."""

    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default=SCHEMA_VERSION)
    run_id: str = Field(min_length=1, max_length=128)
    benchmark_id: str = Field(min_length=1, max_length=128)
    suite_id: str = Field(min_length=1, max_length=128)
    benchmark_version: str = Field(min_length=1)
    target_id: str = Field(min_length=1, max_length=128)
    target_type: TargetModality
    target_config: dict[str, Any] = Field(default_factory=dict)
    status: RunStatus = Field(default=RunStatus.PENDING)
    total_tests: int = Field(ge=0)
    completed_tests: int = Field(default=0, ge=0)
    failed_tests: int = Field(default=0, ge=0)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    error_details: ErrorRecord | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("benchmark_version")
    @classmethod
    def _validate_semver(cls, value: str) -> str:
        SemanticVersion.parse(value)
        return value
