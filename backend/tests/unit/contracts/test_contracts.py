"""Contract tests verifying core schemas, lifecycles, errors, and versioning."""

from __future__ import annotations

import pytest
from pydantic import ValidationError as PydanticValidationError

from arbiter_securitybench.contracts import (
    AttackOutcome,
    BenchmarkLifecycleState,
    BenchmarkSpec,
    ComponentVersions,
    ConfidenceInterval,
    ContentDigest,
    ErrorCategory,
    ErrorSeverity,
    EvaluationLifecycleState,
    EvaluationResult,
    EvaluatorType,
    ExecutionLifecycleState,
    InvalidLifecycleTransitionError,
    Retryability,
    SecurityCategory,
    SemanticVersion,
    SeverityLevel,
    TargetModality,
    TestCaseLifecycleState,
    TestCaseReference,
    TestCaseSpec,
    VerificationStatus,
    compute_canonical_digest,
    validate_benchmark_transition,
    validate_evaluation_transition,
    validate_execution_transition,
    validate_test_case_transition,
)


def test_security_categories_cover_initial_seven() -> None:
    expected = {
        "prompt_injection",
        "jailbreak_resistance",
        "sensitive_data_leakage",
        "system_prompt_extraction",
        "tool_security",
        "rag_security",
        "agent_security",
    }
    assert {c.value for c in SecurityCategory} == expected


def test_semver_parsing_and_compatibility() -> None:
    v1_0 = SemanticVersion.parse("1.0.0")
    v1_2 = SemanticVersion.parse("1.2.0")
    v2_0 = SemanticVersion.parse("2.0.0")
    assert v1_2.is_compatible_with(v1_0)
    assert not v1_0.is_compatible_with(v1_2)
    assert not v2_0.is_compatible_with(v1_2)

    with pytest.raises(ValueError):
        SemanticVersion.parse("not-a-version")


def test_canonical_digest_determinism() -> None:
    d1 = compute_canonical_digest({"b": 2, "a": 1})
    d2 = compute_canonical_digest({"a": 1, "b": 2})
    assert d1 == d2
    assert len(d1) == 64


def test_published_benchmark_requires_cases_and_digest() -> None:
    with pytest.raises(PydanticValidationError):
        BenchmarkSpec(
            benchmark_id="bench-core",
            name="Core Suite",
            version="1.0.0",
            description="Minimal test",
            categories=[SecurityCategory.PROMPT_INJECTION],
            target_modalities=[TargetModality.LLM],
            evaluation_policy_version="1.0.0",
            lifecycle_state=BenchmarkLifecycleState.PUBLISHED,
        )

    digest = ContentDigest.from_payload({"case": "tc-1"})
    spec = BenchmarkSpec(
        benchmark_id="bench-core",
        name="Core Suite",
        version="1.0.0",
        description="Minimal test",
        categories=[SecurityCategory.PROMPT_INJECTION],
        target_modalities=[TargetModality.LLM],
        test_cases=[
            TestCaseReference(
                test_case_id="tc-1",
                version="1.0.0",
                content_digest=digest,
            )
        ],
        evaluation_policy_version="1.0.0",
        lifecycle_state=BenchmarkLifecycleState.PUBLISHED,
        content_digest=ContentDigest.from_payload({"benchmark": "bench-core"}),
    )
    assert spec.lifecycle_state == BenchmarkLifecycleState.PUBLISHED


def test_epistemic_integrity_on_evaluation_result() -> None:
    with pytest.raises(PydanticValidationError):
        EvaluationResult(
            evaluation_id="eval-1",
            run_id="run-1",
            trace_id="trace-1",
            test_case_id="tc-1",
            category=SecurityCategory.TOOL_SECURITY,
            severity=SeverityLevel.HIGH,
            evaluator_id="det-rule-1",
            evaluator_version="1.0.0",
            evaluator_type=EvaluatorType.DETERMINISTIC_RULE,
            outcome=AttackOutcome.DEFENDED,
            verification_status=VerificationStatus.UNVERIFIED,
            lifecycle_state=EvaluationLifecycleState.VERIFIED,
        )

    with pytest.raises(PydanticValidationError):
        EvaluationResult(
            evaluation_id="eval-2",
            run_id="run-1",
            trace_id="trace-2",
            test_case_id="tc-1",
            category=SecurityCategory.RAG_SECURITY,
            severity=SeverityLevel.MEDIUM,
            evaluator_id="det-rule-1",
            evaluator_version="1.0.0",
            evaluator_type=EvaluatorType.DETERMINISTIC_RULE,
            outcome=AttackOutcome.EXECUTION_ERROR,
            verification_status=VerificationStatus.VERIFIED,
            lifecycle_state=EvaluationLifecycleState.VERIFIED,
        )


def test_lifecycle_transitions_enforce_state_machines() -> None:
    validate_benchmark_transition(
        BenchmarkLifecycleState.DRAFT, BenchmarkLifecycleState.IN_REVIEW
    )
    with pytest.raises(InvalidLifecycleTransitionError) as exc_info:
        validate_benchmark_transition(
            BenchmarkLifecycleState.DRAFT, BenchmarkLifecycleState.PUBLISHED
        )
    rec = exc_info.value.to_record()
    assert rec.category == ErrorCategory.LIFECYCLE
    assert rec.severity == ErrorSeverity.FATAL_ITEM
    assert rec.retryability == Retryability.NON_RETRYABLE

    validate_test_case_transition(
        TestCaseLifecycleState.PROPOSED, TestCaseLifecycleState.IN_CURATION
    )
    with pytest.raises(InvalidLifecycleTransitionError):
        validate_test_case_transition(
            TestCaseLifecycleState.RETIRED, TestCaseLifecycleState.ACTIVE
        )

    validate_execution_transition(
        ExecutionLifecycleState.PENDING, ExecutionLifecycleState.QUEUED
    )
    with pytest.raises(InvalidLifecycleTransitionError):
        validate_execution_transition(
            ExecutionLifecycleState.COMPLETED, ExecutionLifecycleState.RUNNING
        )

    validate_evaluation_transition(
        EvaluationLifecycleState.UNSCORED, EvaluationLifecycleState.EVALUATING
    )
    with pytest.raises(InvalidLifecycleTransitionError):
        validate_evaluation_transition(
            EvaluationLifecycleState.INVALIDATED, EvaluationLifecycleState.VERIFIED
        )


def test_component_versions_and_confidence_interval_validation() -> None:
    versions = ComponentVersions(
        benchmark_version="1.0.0",
        adapter_version="1.0.0",
        evaluator_version="1.0.0",
    )
    assert versions.schema_version == "1.0.0"

    with pytest.raises(PydanticValidationError):
        ConfidenceInterval(
            method="wilson",
            confidence_level=0.95,
            lower=0.8,
            upper=0.4,
        )


def test_test_case_canonical_payload_excludes_volatile_fields() -> None:
    tc = TestCaseSpec(
        test_case_id="tc-sample-1",
        version="1.0.0",
        title="Contract schema check",
        category=SecurityCategory.AGENT_SECURITY,
        subcategory="goal_hijacking",
        target_modality=TargetModality.AGENT,
        severity=SeverityLevel.HIGH,
        attack_vector="indirect_observation",
        turns=[{"role": "user", "content": "<placeholder>"}],
        expected_safe_behavior="Agent preserves authorized task scope.",
        failure_indicators=["unauthorized_tool_invocation"],
        lifecycle_state=TestCaseLifecycleState.PROPOSED,
    )
    payload = tc.canonical_payload()
    assert "lifecycle_state" not in payload
    assert "content_digest" not in payload
