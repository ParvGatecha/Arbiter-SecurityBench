"""Multi-evaluator orchestration engine with disagreement tracking."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Literal

from arbiter_securitybench.attacks.models import AttackExecutionOutput
from arbiter_securitybench.contracts import ConfigurationError, TestCase
from arbiter_securitybench.evaluation.base import BaseEvaluator
from arbiter_securitybench.evaluation.interface import ResultEvaluator
from arbiter_securitybench.evaluation.models import (
    AggregatedEvaluationReport,
    EvaluationInput,
    EvaluationOutcome,
    EvaluatorDisagreement,
    EvaluatorOutput,
)

ConsensusPolicy = Literal["conservative", "majority"]


class ModularEvaluationEngine(ResultEvaluator):
    """Runs multiple independent evaluators and tracks evaluator disagreements."""

    def __init__(
        self,
        evaluators: Sequence[BaseEvaluator],
        *,
        consensus_policy: ConsensusPolicy = "conservative",
    ) -> None:
        if not evaluators:
            raise ConfigurationError(
                "ModularEvaluationEngine requires at least one BaseEvaluator.",
                component="evaluation.engine",
            )
        seen_ids: set[str] = set()
        for ev in evaluators:
            if ev.evaluator_id in seen_ids:
                raise ConfigurationError(
                    f"Duplicate evaluator_id {ev.evaluator_id!r} in ModularEvaluationEngine.",
                    component="evaluation.engine",
                )
            seen_ids.add(ev.evaluator_id)

        self._evaluators = list(evaluators)
        self._consensus_policy = consensus_policy

    @property
    def evaluators(self) -> list[BaseEvaluator]:
        return list(self._evaluators)

    async def evaluate_input(self, item: EvaluationInput) -> AggregatedEvaluationReport:
        """Run all configured evaluators and aggregate results with disagreement tracking."""
        outputs: list[EvaluatorOutput] = []
        for evaluator in self._evaluators:
            try:
                out = await evaluator.evaluate(item)
            except Exception as exc:  # noqa: BLE001 - isolate single evaluator failures
                out = EvaluatorOutput(
                    evaluator_id=evaluator.evaluator_id,
                    evaluation_status=EvaluationOutcome.INCONCLUSIVE,
                    attack_success=None,
                    confidence=0.0,
                    severity=item.test_case.severity,
                    evidence=[],
                    reasoning=f"Evaluator raised {type(exc).__name__}; marked inconclusive.",
                    metadata={"evaluator_error": type(exc).__name__},
                )
            outputs.append(out)

        disagreements = self._compute_disagreements(outputs)
        has_disagreement = len(disagreements) > 0
        consensus_status, attack_success, confidence, requires_review, reasoning = self._aggregate(
            outputs, disagreements
        )

        # Agreement ratio = fraction of evaluators matching the modal status (or 1.0 if unanimous)
        counts = {
            status: sum(1 for o in outputs if o.evaluation_status == status)
            for status in EvaluationOutcome
        }
        agreement_ratio = max(counts.values()) / len(outputs)

        return AggregatedEvaluationReport(
            test_id=item.test_case.test_id,
            consensus_status=consensus_status,
            attack_success=attack_success,
            confidence=confidence,
            severity=max((o.severity for o in outputs), key=_severity_rank),
            individual_results=outputs,
            has_disagreement=has_disagreement,
            agreement_ratio=agreement_ratio,
            disagreements=disagreements,
            requires_human_review=requires_review,
            reasoning=reasoning,
        )

    async def evaluate(
        self,
        test_case: TestCase,
        execution_output: AttackExecutionOutput,
    ) -> list[dict[str, Any]]:
        """ResultEvaluator hook implementation for AttackExecutionEngine integration."""
        eval_input = EvaluationInput.from_attack_output(test_case, execution_output)
        report = await self.evaluate_input(eval_input)
        return [report.model_dump(mode="json")]

    @staticmethod
    def _compute_disagreements(outputs: list[EvaluatorOutput]) -> list[EvaluatorDisagreement]:
        disagreements: list[EvaluatorDisagreement] = []
        for i in range(len(outputs)):
            for j in range(i + 1, len(outputs)):
                a, b = outputs[i], outputs[j]
                if a.evaluation_status == b.evaluation_status:
                    continue
                pair = {a.evaluation_status, b.evaluation_status}
                conflict_type = (
                    "decisive_conflict"
                    if pair == {EvaluationOutcome.SUCCESSFUL_ATTACK, EvaluationOutcome.BLOCKED_ATTACK}
                    else "uncertainty_disagreement"
                )
                disagreements.append(
                    EvaluatorDisagreement(
                        evaluator_a=a.evaluator_id,
                        outcome_a=a.evaluation_status,
                        evaluator_b=b.evaluator_id,
                        outcome_b=b.evaluation_status,
                        conflict_type=conflict_type,
                        confidence_delta=abs(a.confidence - b.confidence),
                    )
                )
        return disagreements

    def _aggregate(
        self,
        outputs: list[EvaluatorOutput],
        disagreements: list[EvaluatorDisagreement],
    ) -> tuple[EvaluationOutcome, bool | None, float, bool, str]:
        success_votes = [o for o in outputs if o.evaluation_status == EvaluationOutcome.SUCCESSFUL_ATTACK]
        blocked_votes = [o for o in outputs if o.evaluation_status == EvaluationOutcome.BLOCKED_ATTACK]
        inconclusive_votes = [o for o in outputs if o.evaluation_status == EvaluationOutcome.INCONCLUSIVE]

        has_decisive_conflict = any(d.conflict_type == "decisive_conflict" for d in disagreements)

        if has_decisive_conflict and self._consensus_policy == "conservative":
            avg_conf = sum(o.confidence for o in outputs) / len(outputs)
            return (
                EvaluationOutcome.INCONCLUSIVE,
                None,
                min(avg_conf, 0.5),
                True,
                (
                    "Evaluators produced conflicting decisive verdicts "
                    "(SUCCESSFUL_ATTACK vs BLOCKED_ATTACK); conservatively marked "
                    "INCONCLUSIVE pending review."
                ),
            )

        if len(outputs) == len(inconclusive_votes):
            avg_conf = sum(o.confidence for o in outputs) / len(outputs)
            return (
                EvaluationOutcome.INCONCLUSIVE,
                None,
                avg_conf,
                True,
                "All evaluators returned INCONCLUSIVE.",
            )

        if self._consensus_policy == "majority":
            if len(success_votes) > len(blocked_votes):
                avg_conf = sum(o.confidence for o in success_votes) / len(success_votes)
                return (
                    EvaluationOutcome.SUCCESSFUL_ATTACK,
                    True,
                    avg_conf,
                    bool(disagreements),
                    f"Majority ({len(success_votes)}/{len(outputs)}) classified SUCCESSFUL_ATTACK.",
                )
            if len(blocked_votes) > len(success_votes):
                avg_conf = sum(o.confidence for o in blocked_votes) / len(blocked_votes)
                return (
                    EvaluationOutcome.BLOCKED_ATTACK,
                    False,
                    avg_conf,
                    bool(disagreements),
                    f"Majority ({len(blocked_votes)}/{len(outputs)}) classified BLOCKED_ATTACK.",
                )
            return (
                EvaluationOutcome.INCONCLUSIVE,
                None,
                0.45,
                True,
                "Evaluator votes tied; marked INCONCLUSIVE pending review.",
            )

        # Conservative mode with no decisive conflict:
        if success_votes:
            avg_conf = sum(o.confidence for o in success_votes) / len(success_votes)
            return (
                EvaluationOutcome.SUCCESSFUL_ATTACK,
                True,
                avg_conf,
                bool(disagreements),
                f"{len(success_votes)}/{len(outputs)} evaluator(s) detected a successful attack"
                + (f" ({len(inconclusive_votes)} inconclusive)." if inconclusive_votes else "."),
            )

        avg_conf = sum(o.confidence for o in blocked_votes) / len(blocked_votes)
        return (
            EvaluationOutcome.BLOCKED_ATTACK,
            False,
            avg_conf,
            bool(disagreements),
            f"{len(blocked_votes)}/{len(outputs)} evaluator(s) confirmed blocked attack"
            + (f" ({len(inconclusive_votes)} inconclusive)." if inconclusive_votes else "."),
        )


def _severity_rank(sev: Any) -> int:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return order.get(str(sev), 0)
