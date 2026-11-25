"""Shared test fixtures and deterministic stub target adapters (no LLM calls)."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from arbiter_securitybench.contracts import (
    AttackType,
    BenchmarkSuite,
    BenchmarkTargetAdapter,
    DifficultyLevel,
    EvaluationCriteria,
    SecurityCategory,
    SeverityLevel,
    TargetExecutionRequest,
    TargetExecutionResponse,
    TargetModality,
    TestCase,
)


class StubTargetAdapter(BenchmarkTargetAdapter):
    """Deterministic test double simulating target responses, errors, or delays."""

    def __init__(
        self,
        target_id: str = "stub-target-1",
        target_type: TargetModality = TargetModality.LLM,
        *,
        fail_on_test_ids: set[str] | None = None,
        delay_on_test_ids: dict[str, float] | None = None,
        on_execute_hook: Any | None = None,
    ) -> None:
        self._target_id = target_id
        self._target_type = target_type
        self._fail_on = fail_on_test_ids or set()
        self._delays = delay_on_test_ids or {}
        self._hook = on_execute_hook
        self.executed_test_ids: list[str] = []

    @property
    def target_id(self) -> str:
        return self._target_id

    @property
    def target_type(self) -> TargetModality:
        return self._target_type

    async def execute(self, request: TargetExecutionRequest) -> TargetExecutionResponse:
        self.executed_test_ids.append(request.test_id)
        if self._hook is not None:
            self._hook(request)
        if request.test_id in self._delays:
            await asyncio.sleep(self._delays[request.test_id])
        if request.test_id in self._fail_on:
            raise RuntimeError(f"Simulated adapter failure for {request.test_id}")
        return TargetExecutionResponse(
            output=f"stub-response:{request.test_id}",
            raw_response={"test_id": request.test_id, "echo": request.input_prompt},
        )


def build_test_case(
    *,
    test_id: str = "tc-001",
    name: str = "Sample Prompt Injection Check",
    category: SecurityCategory = SecurityCategory.PROMPT_INJECTION,
    attack_type: AttackType = AttackType.DIRECT_INJECTION,
    difficulty: DifficultyLevel = DifficultyLevel.MEDIUM,
    severity: SeverityLevel = SeverityLevel.HIGH,
    benchmark_version: str = "1.0.0",
    tags: list[str] | None = None,
) -> TestCase:
    return TestCase(
        test_id=test_id,
        name=name,
        description=f"Test case specification for {test_id}.",
        category=category,
        attack_type=attack_type,
        difficulty=difficulty,
        severity=severity,
        input_prompt=f"<test-input:{test_id}>",
        expected_behavior="Target maintains policy boundaries.",
        evaluation_criteria=EvaluationCriteria(
            description="Verify no forbidden instruction execution occurs.",
            success_indicators=["maintains_policy"],
            failure_indicators=["follows_override"],
        ),
        tags=tags if tags is not None else ["baseline", "prompt-injection"],
        benchmark_version=benchmark_version,
        metadata={"author": "unit-test"},
    )


def build_suite(
    *,
    suite_id: str = "suite-core",
    version: str = "1.0.0",
    test_cases: list[TestCase] | None = None,
    supported_target_types: list[TargetModality] | None = None,
    categories: list[SecurityCategory] | None = None,
) -> BenchmarkSuite:
    cases = test_cases if test_cases is not None else [
        build_test_case(test_id="tc-001", benchmark_version=version),
        build_test_case(
            test_id="tc-002",
            category=SecurityCategory.SENSITIVE_DATA_LEAKAGE,
            attack_type=AttackType.SENSITIVE_DATA_EXFILTRATION,
            benchmark_version=version,
        ),
    ]
    return BenchmarkSuite(
        suite_id=suite_id,
        name=f"Suite {suite_id}",
        description="Deterministic suite fixture for unit testing.",
        version=version,
        supported_target_types=supported_target_types or [TargetModality.LLM, TargetModality.AGENT],
        categories=categories or [],
        test_cases=cases,
    )


@pytest.fixture
def sample_suite() -> BenchmarkSuite:
    return build_suite()
