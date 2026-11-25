"""Evaluation interface hook separating attack execution from scoring/evaluation."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from arbiter_securitybench.attacks.models import AttackExecutionOutput
from arbiter_securitybench.contracts import TestCase


@runtime_checkable
class ResultEvaluator(Protocol):
    """Interface passed raw attack execution outputs for downstream evaluation."""

    async def evaluate(
        self,
        test_case: TestCase,
        execution_output: AttackExecutionOutput,
    ) -> list[dict[str, Any]]:
        """Evaluate an attack execution output and return structured evaluator records."""


class NoOpResultEvaluator:
    """Default pass-through evaluator when scoring/evaluation is deferred."""

    async def evaluate(
        self,
        test_case: TestCase,
        execution_output: AttackExecutionOutput,
    ) -> list[dict[str, Any]]:
        return []
