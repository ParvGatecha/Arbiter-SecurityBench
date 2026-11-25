"""Abstract Attack base contract and safe target invocation helpers."""

from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any

from arbiter_securitybench.adapters.base import TargetAdapter
from arbiter_securitybench.adapters.models import (
    AdapterRequest,
    AdapterResponse,
    ConversationMessage,
)
from arbiter_securitybench.attacks.models import (
    AttackCategory,
    AttackExecutionOutput,
    AttackTurnRecord,
    AttackVariant,
)
from arbiter_securitybench.contracts import (
    BenchmarkTargetAdapter,
    DifficultyLevel,
    SeverityLevel,
    TargetExecutionRequest,
    TestCase,
)


class AttackCancelledError(Exception):
    """Internal signal raised when an attack execution is cancelled mid-conversation."""


class Attack(ABC):
    """Abstract base class for all modular security attacks."""

    @property
    @abstractmethod
    def attack_id(self) -> str:
        """Unique identifier for this attack implementation."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name of the attack."""

    @property
    @abstractmethod
    def category(self) -> AttackCategory:
        """Attack category from AttackCategory."""

    @property
    @abstractmethod
    def description(self) -> str:
        """Clear description of the attack technique and risk."""

    @property
    @abstractmethod
    def severity(self) -> SeverityLevel:
        """Default security severity associated with this attack."""

    @property
    @abstractmethod
    def difficulty(self) -> DifficultyLevel:
        """Default adversarial sophistication of this attack."""

    @abstractmethod
    def generate_variants(
        self,
        test_case: TestCase,
        *,
        seed: int = 0,
        max_variants: int = 3,
    ) -> list[AttackVariant]:
        """Generate deterministic, safe adversarial prompt variants for a test case."""

    @abstractmethod
    async def execute(
        self,
        target: TargetAdapter | BenchmarkTargetAdapter,
        test_case: TestCase,
        *,
        run_id: str,
        variant: AttackVariant | None = None,
        target_config: dict[str, Any] | None = None,
        per_turn_timeout_seconds: float | None = None,
        is_cancelled: Callable[[], bool] | None = None,
    ) -> AttackExecutionOutput:
        """Execute single-turn or multi-turn attack against an explicitly configured target."""


class BaseConversationAttack(Attack, ABC):
    """Shared single-turn and multi-turn execution logic for standardized attacks."""

    def _build_default_variant(self, test_case: TestCase) -> AttackVariant:
        turns_meta = test_case.metadata.get("turns")
        if isinstance(turns_meta, list) and all(isinstance(t, str) and t.strip() for t in turns_meta) and turns_meta:
            turns = list(turns_meta)
        else:
            turns = [test_case.input_prompt]

        system_ctx = test_case.metadata.get("system_context")
        system_context = str(system_ctx) if isinstance(system_ctx, str) and system_ctx else None

        history_raw = test_case.metadata.get("conversation_history")
        history: list[ConversationMessage] = []
        if isinstance(history_raw, list):
            for item in history_raw:
                if isinstance(item, dict) and isinstance(item.get("role"), str) and isinstance(item.get("content"), str):
                    history.append(
                        ConversationMessage(role=item["role"], content=item["content"])
                    )

        return AttackVariant(
            variant_id=f"{test_case.test_id}:primary",
            attack_id=self.attack_id,
            turns=turns,
            system_context=system_context,
            initial_history=history,
            metadata={"source": "test_case_primary"},
        )

    async def execute(
        self,
        target: TargetAdapter | BenchmarkTargetAdapter,
        test_case: TestCase,
        *,
        run_id: str,
        variant: AttackVariant | None = None,
        target_config: dict[str, Any] | None = None,
        per_turn_timeout_seconds: float | None = None,
        is_cancelled: Callable[[], bool] | None = None,
    ) -> AttackExecutionOutput:
        active_variant = variant or self._build_default_variant(test_case)
        resolved_cfg = dict(target_config or {})
        history = list(active_variant.initial_history)
        turn_records: list[AttackTurnRecord] = []
        total_latency = 0.0

        for idx, prompt in enumerate(active_variant.turns):
            if is_cancelled is not None and is_cancelled():
                raise AttackCancelledError(f"Attack {self.attack_id!r} cancelled before turn {idx}.")

            turn_start = time.perf_counter()
            if isinstance(target, TargetAdapter):
                req = AdapterRequest(
                    prompt=prompt,
                    conversation_history=list(history),
                    system_context=active_variant.system_context,
                    metadata={
                        "run_id": run_id,
                        "test_id": test_case.test_id,
                        "attack_id": self.attack_id,
                        "variant_id": active_variant.variant_id,
                        "turn_index": idx,
                    },
                    timeout=per_turn_timeout_seconds,
                )
                coro = target.send_prompt(req)
                if per_turn_timeout_seconds is not None:
                    resp: AdapterResponse = await asyncio.wait_for(
                        coro, timeout=per_turn_timeout_seconds
                    )
                else:
                    resp = await coro
                elapsed = time.perf_counter() - turn_start
                response_text = resp.response_text
                turn_records.append(
                    AttackTurnRecord(
                        turn_index=idx,
                        prompt=prompt,
                        response_text=response_text,
                        latency_seconds=resp.latency if resp.latency > 0 else elapsed,
                        token_usage=resp.token_usage,
                        model_information=resp.model_information,
                        raw_response=resp.raw_response,
                        execution_metadata=resp.execution_metadata,
                    )
                )
                total_latency += resp.latency if resp.latency > 0 else elapsed
            else:
                # Support lightweight BenchmarkTargetAdapter implementations cleanly.
                bridge_cfg = {
                    **resolved_cfg,
                    "conversation_history": [m.model_dump() for m in history],
                    "turn_index": idx,
                }
                if active_variant.system_context is not None:
                    bridge_cfg["system_context"] = active_variant.system_context
                if per_turn_timeout_seconds is not None:
                    bridge_cfg["timeout"] = per_turn_timeout_seconds

                bridge_req = TargetExecutionRequest(
                    run_id=run_id,
                    test_id=test_case.test_id,
                    input_prompt=prompt,
                    target_config=bridge_cfg,
                    metadata={
                        "attack_id": self.attack_id,
                        "variant_id": active_variant.variant_id,
                        "turn_index": idx,
                    },
                )
                coro2 = target.execute(bridge_req)
                if per_turn_timeout_seconds is not None:
                    bridge_resp = await asyncio.wait_for(coro2, timeout=per_turn_timeout_seconds)
                else:
                    bridge_resp = await coro2
                elapsed = time.perf_counter() - turn_start
                response_text = bridge_resp.output or ""
                turn_records.append(
                    AttackTurnRecord(
                        turn_index=idx,
                        prompt=prompt,
                        response_text=response_text,
                        latency_seconds=elapsed,
                        raw_response=bridge_resp.raw_response or {},
                        execution_metadata=bridge_resp.metadata,
                    )
                )
                total_latency += elapsed

            history.append(ConversationMessage(role="user", content=prompt))
            history.append(ConversationMessage(role="assistant", content=response_text))

        return AttackExecutionOutput(
            attack_id=self.attack_id,
            category=self.category,
            variant_id=active_variant.variant_id,
            turns=turn_records,
            final_response_text=turn_records[-1].response_text,
            total_latency_seconds=total_latency,
            conversation_history=history,
            metadata={
                "turn_count": len(turn_records),
                "is_multi_turn": len(turn_records) > 1,
                **active_variant.metadata,
            },
        )
