"""State machines and transition validators for all core domain lifecycles."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from arbiter_securitybench.contracts.errors import InvalidLifecycleTransitionError


class BenchmarkLifecycleState(StrEnum):
    """Lifecycle states of a benchmark suite definition.

    Published benchmarks are immutable; changes require creating a new version.
    """

    DRAFT = "draft"
    IN_REVIEW = "in_review"
    VALIDATED = "validated"
    PUBLISHED = "published"
    DEPRECATED = "deprecated"
    ARCHIVED = "archived"


class TestCaseLifecycleState(StrEnum):
    """Lifecycle states of an individual security test case."""

    PROPOSED = "proposed"
    IN_CURATION = "in_curation"
    CALIBRATED = "calibrated"
    ACTIVE = "active"
    QUARANTINED = "quarantined"
    DEPRECATED = "deprecated"
    REJECTED = "rejected"
    RETIRED = "retired"


class ExecutionLifecycleState(StrEnum):
    """Lifecycle states of a benchmark execution run."""

    PENDING = "pending"
    QUEUED = "queued"
    INITIALIZING = "initializing"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL_FAILURE = "partial_failure"
    FAILED = "failed"
    CANCELLED = "cancelled"


class RunStatus(StrEnum):
    """Core execution statuses for sequential and async benchmark runs."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PARTIALLY_COMPLETED = "partially_completed"


class EvaluationLifecycleState(StrEnum):
    """Lifecycle states of an evaluation result for a single execution trace.

    Only VERIFIED results may be reported as verified security findings.
    """

    UNSCORED = "unscored"
    EVALUATING = "evaluating"
    PRELIMINARY = "preliminary"
    VERIFIED = "verified"
    DISPUTED = "disputed"
    INVALIDATED = "invalidated"


BENCHMARK_TRANSITIONS: dict[BenchmarkLifecycleState, frozenset[BenchmarkLifecycleState]] = {
    BenchmarkLifecycleState.DRAFT: frozenset({
        BenchmarkLifecycleState.IN_REVIEW,
        BenchmarkLifecycleState.ARCHIVED,
    }),
    BenchmarkLifecycleState.IN_REVIEW: frozenset({
        BenchmarkLifecycleState.DRAFT,
        BenchmarkLifecycleState.VALIDATED,
    }),
    BenchmarkLifecycleState.VALIDATED: frozenset({
        BenchmarkLifecycleState.IN_REVIEW,
        BenchmarkLifecycleState.PUBLISHED,
    }),
    BenchmarkLifecycleState.PUBLISHED: frozenset({
        BenchmarkLifecycleState.DEPRECATED,
    }),
    BenchmarkLifecycleState.DEPRECATED: frozenset({
        BenchmarkLifecycleState.ARCHIVED,
    }),
    BenchmarkLifecycleState.ARCHIVED: frozenset(),
}

TEST_CASE_TRANSITIONS: dict[TestCaseLifecycleState, frozenset[TestCaseLifecycleState]] = {
    TestCaseLifecycleState.PROPOSED: frozenset({
        TestCaseLifecycleState.IN_CURATION,
        TestCaseLifecycleState.REJECTED,
    }),
    TestCaseLifecycleState.IN_CURATION: frozenset({
        TestCaseLifecycleState.CALIBRATED,
        TestCaseLifecycleState.REJECTED,
    }),
    TestCaseLifecycleState.CALIBRATED: frozenset({
        TestCaseLifecycleState.ACTIVE,
        TestCaseLifecycleState.IN_CURATION,
    }),
    TestCaseLifecycleState.ACTIVE: frozenset({
        TestCaseLifecycleState.QUARANTINED,
        TestCaseLifecycleState.DEPRECATED,
    }),
    TestCaseLifecycleState.QUARANTINED: frozenset({
        TestCaseLifecycleState.ACTIVE,
        TestCaseLifecycleState.DEPRECATED,
        TestCaseLifecycleState.RETIRED,
    }),
    TestCaseLifecycleState.DEPRECATED: frozenset({
        TestCaseLifecycleState.RETIRED,
    }),
    TestCaseLifecycleState.REJECTED: frozenset(),
    TestCaseLifecycleState.RETIRED: frozenset(),
}

EXECUTION_TRANSITIONS: dict[ExecutionLifecycleState, frozenset[ExecutionLifecycleState]] = {
    ExecutionLifecycleState.PENDING: frozenset({
        ExecutionLifecycleState.QUEUED,
        ExecutionLifecycleState.CANCELLED,
    }),
    ExecutionLifecycleState.QUEUED: frozenset({
        ExecutionLifecycleState.INITIALIZING,
        ExecutionLifecycleState.CANCELLED,
        ExecutionLifecycleState.FAILED,
    }),
    ExecutionLifecycleState.INITIALIZING: frozenset({
        ExecutionLifecycleState.RUNNING,
        ExecutionLifecycleState.FAILED,
        ExecutionLifecycleState.CANCELLED,
    }),
    ExecutionLifecycleState.RUNNING: frozenset({
        ExecutionLifecycleState.COMPLETED,
        ExecutionLifecycleState.PARTIAL_FAILURE,
        ExecutionLifecycleState.FAILED,
        ExecutionLifecycleState.CANCELLED,
    }),
    ExecutionLifecycleState.COMPLETED: frozenset(),
    ExecutionLifecycleState.PARTIAL_FAILURE: frozenset(),
    ExecutionLifecycleState.FAILED: frozenset(),
    ExecutionLifecycleState.CANCELLED: frozenset(),
}

RUN_STATUS_TRANSITIONS: dict[RunStatus, frozenset[RunStatus]] = {
    RunStatus.PENDING: frozenset({
        RunStatus.RUNNING,
        RunStatus.CANCELLED,
        RunStatus.FAILED,
    }),
    RunStatus.RUNNING: frozenset({
        RunStatus.COMPLETED,
        RunStatus.PARTIALLY_COMPLETED,
        RunStatus.FAILED,
        RunStatus.CANCELLED,
    }),
    RunStatus.COMPLETED: frozenset(),
    RunStatus.PARTIALLY_COMPLETED: frozenset(),
    RunStatus.FAILED: frozenset(),
    RunStatus.CANCELLED: frozenset(),
}

EVALUATION_TRANSITIONS: dict[EvaluationLifecycleState, frozenset[EvaluationLifecycleState]] = {
    EvaluationLifecycleState.UNSCORED: frozenset({
        EvaluationLifecycleState.EVALUATING,
        EvaluationLifecycleState.INVALIDATED,
    }),
    EvaluationLifecycleState.EVALUATING: frozenset({
        EvaluationLifecycleState.PRELIMINARY,
        EvaluationLifecycleState.VERIFIED,
        EvaluationLifecycleState.INVALIDATED,
    }),
    EvaluationLifecycleState.PRELIMINARY: frozenset({
        EvaluationLifecycleState.VERIFIED,
        EvaluationLifecycleState.DISPUTED,
        EvaluationLifecycleState.INVALIDATED,
    }),
    EvaluationLifecycleState.VERIFIED: frozenset({
        EvaluationLifecycleState.DISPUTED,
        EvaluationLifecycleState.INVALIDATED,
    }),
    EvaluationLifecycleState.DISPUTED: frozenset({
        EvaluationLifecycleState.VERIFIED,
        EvaluationLifecycleState.INVALIDATED,
    }),
    EvaluationLifecycleState.INVALIDATED: frozenset(),
}


def _validate_transition(
    entity: str,
    current: StrEnum,
    target: StrEnum,
    allowed_map: dict[Any, frozenset[Any]],
) -> None:
    allowed = allowed_map.get(current, frozenset())
    if target not in allowed:
        raise InvalidLifecycleTransitionError(
            f"Cannot transition {entity} from {current.value!r} to {target.value!r}",
            component="lifecycles",
            details={
                "entity": entity,
                "current_state": current.value,
                "target_state": target.value,
                "allowed_targets": sorted(s.value for s in allowed),
            },
        )


def validate_benchmark_transition(
    current: BenchmarkLifecycleState,
    target: BenchmarkLifecycleState,
) -> None:
    """Validate a benchmark lifecycle state transition."""
    _validate_transition("benchmark", current, target, BENCHMARK_TRANSITIONS)


def validate_test_case_transition(
    current: TestCaseLifecycleState,
    target: TestCaseLifecycleState,
) -> None:
    """Validate a test case lifecycle state transition."""
    _validate_transition("test_case", current, target, TEST_CASE_TRANSITIONS)


def validate_execution_transition(
    current: ExecutionLifecycleState,
    target: ExecutionLifecycleState,
) -> None:
    """Validate an execution run lifecycle state transition."""
    _validate_transition("execution_run", current, target, EXECUTION_TRANSITIONS)


def validate_run_status_transition(
    current: RunStatus,
    target: RunStatus,
) -> None:
    """Validate a benchmark run status transition."""
    _validate_transition("benchmark_run", current, target, RUN_STATUS_TRANSITIONS)


def validate_evaluation_transition(
    current: EvaluationLifecycleState,
    target: EvaluationLifecycleState,
) -> None:
    """Validate an evaluation lifecycle state transition."""
    _validate_transition("evaluation", current, target, EVALUATION_TRANSITIONS)
