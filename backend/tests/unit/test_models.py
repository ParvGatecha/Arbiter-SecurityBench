"""Unit tests for TestCase, BenchmarkSuite, TestExecutionResult, and RunStatus validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError as PydanticValidationError

from arbiter_securitybench.contracts import (
    BenchmarkSuite,
    ErrorCategory,
    ErrorRecord,
    ErrorSeverity,
    InvalidLifecycleTransitionError,
    Retryability,
    RunStatus,
    SecurityCategory,
    TargetModality,
    TestExecutionResult,
    TestExecutionStatus,
    validate_run_status_transition,
)
from conftest import build_suite, build_test_case


def test_test_case_validation_and_tag_normalization() -> None:
    tc = build_test_case(tags=[" baseline ", "prompt-injection", "baseline"])
    assert tc.tags == ["baseline", "prompt-injection"]
    assert tc.content_digest is not None
    assert len(tc.content_digest.hex_digest) == 64

    with pytest.raises(PydanticValidationError):
        build_test_case(tags=["valid", "   "])

    with pytest.raises(PydanticValidationError):
        build_test_case(benchmark_version="not-semver")


def test_benchmark_suite_validation_rejects_duplicate_tests_and_uncovered_categories() -> None:
    tc1 = build_test_case(test_id="tc-dup", category=SecurityCategory.PROMPT_INJECTION)
    tc2 = build_test_case(test_id="tc-dup", category=SecurityCategory.PROMPT_INJECTION)

    with pytest.raises(PydanticValidationError):
        BenchmarkSuite(
            suite_id="suite-dup",
            name="Dup Suite",
            description="Duplicate test ID check",
            version="1.0.0",
            supported_target_types=[TargetModality.LLM],
            test_cases=[tc1, tc2],
        )

    tc_other = build_test_case(test_id="tc-tool", category=SecurityCategory.TOOL_SECURITY)
    with pytest.raises(PydanticValidationError):
        BenchmarkSuite(
            suite_id="suite-mismatch",
            name="Mismatch Suite",
            description="Category mismatch check",
            version="1.0.0",
            supported_target_types=[TargetModality.AGENT],
            categories=[SecurityCategory.PROMPT_INJECTION],
            test_cases=[tc_other],
        )

    valid_suite = build_suite()
    assert valid_suite.test_count == 2
    assert valid_suite.get_test_case("tc-001") is not None
    assert valid_suite.get_test_case("missing") is None


def test_result_schema_enforces_no_fabricated_completion_or_missing_error() -> None:
    with pytest.raises(PydanticValidationError):
        TestExecutionResult(
            run_id="run-1",
            test_id="tc-1",
            target_id="target-1",
            input="prompt",
            output=None,
            raw_response=None,
            execution_status=TestExecutionStatus.COMPLETED,
            execution_time=0.1,
        )

    with pytest.raises(PydanticValidationError):
        TestExecutionResult(
            run_id="run-1",
            test_id="tc-1",
            target_id="target-1",
            input="prompt",
            output=None,
            execution_status=TestExecutionStatus.FAILED,
            execution_time=0.1,
            error_details=None,
        )

    valid_fail = TestExecutionResult(
        run_id="run-1",
        test_id="tc-1",
        target_id="target-1",
        input="prompt",
        output=None,
        execution_status=TestExecutionStatus.FAILED,
        execution_time=0.1,
        error_details=ErrorRecord(
            error_code="ASB_ADAPTER_ERROR",
            category=ErrorCategory.ADAPTER_TRANSPORT,
            severity=ErrorSeverity.FATAL_ITEM,
            retryability=Retryability.CONDITIONAL,
            message="Simulated transport failure",
            component="tests",
        ),
    )
    assert valid_fail.execution_status == TestExecutionStatus.FAILED


def test_run_status_transitions() -> None:
    validate_run_status_transition(RunStatus.PENDING, RunStatus.RUNNING)
    validate_run_status_transition(RunStatus.RUNNING, RunStatus.PARTIALLY_COMPLETED)

    with pytest.raises(InvalidLifecycleTransitionError):
        validate_run_status_transition(RunStatus.COMPLETED, RunStatus.RUNNING)
    with pytest.raises(InvalidLifecycleTransitionError):
        validate_run_status_transition(RunStatus.PENDING, RunStatus.COMPLETED)
