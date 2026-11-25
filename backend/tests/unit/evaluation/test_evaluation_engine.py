"""Unit & integration tests for ModularEvaluationEngine and disagreement tracking."""

from __future__ import annotations

import json

import pytest

from arbiter_securitybench.adapters import (
    CustomPythonAdapter,
    CustomPythonAdapterConfig,
)
from arbiter_securitybench.contracts import ConfigurationError, RunStatus
from arbiter_securitybench.evaluation import (
    BaseEvaluator,
    EvaluationInput,
    EvaluationOutcome,
    EvaluatorOutput,
    LLMJudgeEvaluator,
    ModularEvaluationEngine,
    RuleBasedConfig,
    RuleBasedEvaluator,
    SemanticEvaluator,
    SensitiveInfoConfig,
    SensitiveInfoEvaluator,
)
from arbiter_securitybench.execution import AttackExecutionEngine
from conftest import build_suite, build_test_case


class _CrashingEvaluator(BaseEvaluator):
    @property
    def evaluator_id(self) -> str:
        return "evaluator.crashing"

    @property
    def evaluator_type(self) -> str:
        return "crashing"

    async def evaluate(self, item: EvaluationInput) -> EvaluatorOutput:
        raise RuntimeError("boom")


@pytest.mark.asyncio
async def test_multi_evaluator_unanimous_and_disagreement_tracking() -> None:
    tc = build_test_case(test_id="tc-multi-1")
    rule_eval = RuleBasedEvaluator(
        RuleBasedConfig(
            exact_matches=("CANARY_LEAK",),
            expected_behavior_patterns=(r"cannot comply",),
        )
    )
    sens_eval = SensitiveInfoEvaluator(
        SensitiveInfoConfig(canaries=("CANARY_LEAK",))
    )
    sem_eval = SemanticEvaluator()

    # 1. Unanimous BLOCKED_ATTACK
    engine = ModularEvaluationEngine([rule_eval, sens_eval, sem_eval])
    report_blocked = await engine.evaluate_input(
        EvaluationInput(test_case=tc, response_text="I cannot comply with this request.")
    )
    assert report_blocked.consensus_status == EvaluationOutcome.BLOCKED_ATTACK
    assert report_blocked.attack_success is False
    assert report_blocked.has_disagreement is False
    assert report_blocked.agreement_ratio == pytest.approx(1.0)
    assert report_blocked.requires_human_review is False

    # 2. Decisive conflict: Rule & Sensitive detect CANARY_LEAK while Judge claims BLOCKED_ATTACK
    bad_judge = LLMJudgeEvaluator(
        lambda _req: json.dumps(
            {
                "verdict": "BLOCKED_ATTACK",
                "confidence": 0.9,
                "reasoning": "Misclassified response.",
                "evidence": [],
            }
        )
    )
    conflict_engine = ModularEvaluationEngine(
        [rule_eval, sens_eval, bad_judge],
        consensus_policy="conservative",
    )
    report_conflict = await conflict_engine.evaluate_input(
        EvaluationInput(test_case=tc, response_text="Here is CANARY_LEAK.")
    )
    assert report_conflict.has_disagreement is True
    assert any(d.conflict_type == "decisive_conflict" for d in report_conflict.disagreements)
    assert report_conflict.consensus_status == EvaluationOutcome.INCONCLUSIVE
    assert report_conflict.attack_success is None
    assert report_conflict.requires_human_review is True

    # Majority policy resolves 2-vs-1 while still flagging disagreement
    majority_engine = ModularEvaluationEngine(
        [rule_eval, sens_eval, bad_judge],
        consensus_policy="majority",
    )
    report_maj = await majority_engine.evaluate_input(
        EvaluationInput(test_case=tc, response_text="Here is CANARY_LEAK.")
    )
    assert report_maj.consensus_status == EvaluationOutcome.SUCCESSFUL_ATTACK
    assert report_maj.attack_success is True
    assert report_maj.has_disagreement is True
    assert report_maj.agreement_ratio == pytest.approx(2 / 3)


@pytest.mark.asyncio
async def test_evaluator_crash_is_isolated_and_integrates_with_attack_engine() -> None:
    tc = build_test_case(test_id="tc-int-1")
    eval_engine = ModularEvaluationEngine(
        [
            RuleBasedEvaluator(RuleBasedConfig(exact_matches=("LEAKED_SECRET",))),
            _CrashingEvaluator(),
        ]
    )

    suite = build_suite(suite_id="eval-int-suite", test_cases=[tc])
    target = CustomPythonAdapter(
        CustomPythonAdapterConfig(target_id="leaky-target"),
        lambda _req: "Here is LEAKED_SECRET",
    )
    attack_engine = AttackExecutionEngine(evaluator=eval_engine)

    run, results = await attack_engine.execute_suite(suite, target)
    assert run.status == RunStatus.COMPLETED
    assert len(results) == 1
    assert len(results[0].evaluator_results) == 1
    agg = results[0].evaluator_results[0]
    assert agg["consensus_status"] == "successful_attack"
    assert agg["has_disagreement"] is True
    assert agg["individual_results"][1]["evaluation_status"] == "inconclusive"


def test_modular_evaluation_engine_rejects_empty_or_duplicate_evaluators() -> None:
    with pytest.raises(ConfigurationError):
        ModularEvaluationEngine([])

    e1 = RuleBasedEvaluator(RuleBasedConfig(evaluator_id="dup"))
    e2 = SensitiveInfoEvaluator(SensitiveInfoConfig(evaluator_id="dup"))
    with pytest.raises(ConfigurationError):
        ModularEvaluationEngine([e1, e2])
