"""Standardized evaluation models, outcomes, and disagreement tracking schemas."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from arbiter_securitybench.attacks.models import AttackExecutionOutput
from arbiter_securitybench.contracts import SeverityLevel, TestCase, TestExecutionResult


class EvaluationOutcome(StrEnum):
    """Three standardized evaluation outcomes."""

    SUCCESSFUL_ATTACK = "successful_attack"
    BLOCKED_ATTACK = "blocked_attack"
    INCONCLUSIVE = "inconclusive"


class EvaluationEvidenceItem(BaseModel):
    """Single auditable piece of evidence supporting an evaluation verdict."""

    model_config = ConfigDict(frozen=True)

    indicator: str = Field(min_length=1)
    matched: bool
    source: str = Field(default="response_text")
    excerpt: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class ToolCallAttempt(BaseModel):
    """Structured record of an attempted or executed tool action during an evaluation."""

    model_config = ConfigDict(frozen=True)

    tool_name: str = Field(min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)
    permitted_by_policy: bool = True
    attempted: bool = True
    executed: bool = False
    succeeded: bool = False
    blocked_reason: str | None = None
    output: str | None = None


class EvaluationInput(BaseModel):
    """Target- and attack-independent input passed to evaluators."""

    model_config = ConfigDict(frozen=True)

    test_case: TestCase
    response_text: str
    conversation_history: list[dict[str, Any]] = Field(default_factory=list)
    system_context: str | None = None
    tool_events: list[ToolCallAttempt] = Field(default_factory=list)
    raw_response: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_attack_output(
        cls,
        test_case: TestCase,
        execution_output: AttackExecutionOutput,
    ) -> EvaluationInput:
        """Build an EvaluationInput from an AttackExecutionOutput."""
        tool_events = _extract_tool_events(
            turns=[t.model_dump(mode="json") for t in execution_output.turns],
            raw_response={},
        )
        system_ctx = test_case.metadata.get("system_context")
        return cls(
            test_case=test_case,
            response_text=execution_output.final_response_text,
            conversation_history=[
                m.model_dump(mode="json") for m in execution_output.conversation_history
            ],
            system_context=str(system_ctx) if isinstance(system_ctx, str) else None,
            tool_events=tool_events,
            raw_response={
                "attack_id": execution_output.attack_id,
                "category": execution_output.category.value,
                "variant_id": execution_output.variant_id,
                "turns": [t.model_dump(mode="json") for t in execution_output.turns],
            },
            metadata=dict(execution_output.metadata),
        )

    @classmethod
    def from_execution_result(
        cls,
        test_case: TestCase,
        result: TestExecutionResult,
    ) -> EvaluationInput:
        """Build an EvaluationInput from a persisted TestExecutionResult."""
        raw = result.raw_response or {}
        turns = raw.get("turns") if isinstance(raw.get("turns"), list) else []
        history = (
            raw.get("conversation_history")
            if isinstance(raw.get("conversation_history"), list)
            else []
        )
        tool_events = _extract_tool_events(turns=turns, raw_response=raw)
        system_ctx = test_case.metadata.get("system_context")
        return cls(
            test_case=test_case,
            response_text=result.output or "",
            conversation_history=history,
            system_context=str(system_ctx) if isinstance(system_ctx, str) else None,
            tool_events=tool_events,
            raw_response=raw,
            metadata={"run_id": result.run_id, "target_id": result.target_id},
        )


def _extract_tool_events(
    *,
    turns: list[Any],
    raw_response: dict[str, Any],
) -> list[ToolCallAttempt]:
    events: list[ToolCallAttempt] = []
    candidates: list[Any] = []
    if isinstance(raw_response.get("tool_calls"), list):
        candidates.extend(raw_response["tool_calls"])
    for turn in turns:
        if isinstance(turn, dict):
            turn_raw = turn.get("raw_response")
            if isinstance(turn_raw, dict) and isinstance(turn_raw.get("tool_calls"), list):
                candidates.extend(turn_raw["tool_calls"])
            if isinstance(turn.get("tool_calls"), list):
                candidates.extend(turn["tool_calls"])
    for item in candidates:
        if isinstance(item, ToolCallAttempt):
            events.append(item)
        elif isinstance(item, dict) and isinstance(item.get("tool_name"), str):
            events.append(ToolCallAttempt.model_validate(item))
    return events


class EvaluatorOutput(BaseModel):
    """Standardized output contract returned by every evaluator."""

    model_config = ConfigDict(frozen=True)

    evaluator_id: str = Field(min_length=1, max_length=128)
    evaluation_status: EvaluationOutcome
    attack_success: bool | None
    confidence: float = Field(ge=0.0, le=1.0)
    severity: SeverityLevel
    evidence: list[EvaluationEvidenceItem] = Field(default_factory=list)
    reasoning: str = Field(min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _align_status_and_attack_success(self) -> EvaluatorOutput:
        if self.evaluation_status == EvaluationOutcome.SUCCESSFUL_ATTACK and self.attack_success is not True:
            raise ValueError("SUCCESSFUL_ATTACK requires attack_success == True.")
        if self.evaluation_status == EvaluationOutcome.BLOCKED_ATTACK and self.attack_success is not False:
            raise ValueError("BLOCKED_ATTACK requires attack_success == False.")
        if self.evaluation_status == EvaluationOutcome.INCONCLUSIVE and self.attack_success is not None:
            raise ValueError("INCONCLUSIVE requires attack_success == None.")
        return self


class EvaluatorDisagreement(BaseModel):
    """Record describing a conflict between two evaluators on the same test case."""

    model_config = ConfigDict(frozen=True)

    evaluator_a: str
    outcome_a: EvaluationOutcome
    evaluator_b: str
    outcome_b: EvaluationOutcome
    conflict_type: str
    confidence_delta: float = Field(ge=0.0, le=1.0)


class AggregatedEvaluationReport(BaseModel):
    """Combined multi-evaluator output including disagreement tracking."""

    model_config = ConfigDict(frozen=True)

    test_id: str
    consensus_status: EvaluationOutcome
    attack_success: bool | None
    confidence: float = Field(ge=0.0, le=1.0)
    severity: SeverityLevel
    individual_results: list[EvaluatorOutput] = Field(min_length=1)
    has_disagreement: bool
    agreement_ratio: float = Field(ge=0.0, le=1.0)
    disagreements: list[EvaluatorDisagreement] = Field(default_factory=list)
    requires_human_review: bool
    reasoning: str
