"""Unit & integration tests for AttackExecutionEngine."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from arbiter_securitybench.adapters import (
    AdapterAuthenticationError,
    AdapterConnectionError,
    AdapterRequest,
    AdapterResponse,
    CustomPythonAdapter,
    CustomPythonAdapterConfig,
    ModelInformation,
    RateLimitConfig,
    RetryPolicyConfig,
    TargetAdapterRegistry,
)
from arbiter_securitybench.attacks import (
    AttackExecutionConfig,
    AttackExecutionOutput,
    AttackRegistry,
    create_deterministic_attack_suite,
)
from arbiter_securitybench.contracts import (
    ConfigurationError,
    RunStatus,
    TargetModality,
    TestCase,
    TestExecutionStatus,
)
from arbiter_securitybench.execution import (
    AttackExecutionEngine,
    CancellationToken,
    ExecutionCheckpointStore,
    build_checkpoint_scope,
)
from arbiter_securitybench.registry import BenchmarkCoreRegistry
from arbiter_securitybench.storage import InMemoryRunRepository
from conftest import build_suite, build_test_case


class _RecordingEvaluator:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, int]] = []

    async def evaluate(
        self,
        test_case: TestCase,
        execution_output: AttackExecutionOutput,
    ) -> list[dict[str, Any]]:
        self.calls.append(
            (test_case.test_id, execution_output.attack_id, len(execution_output.turns))
        )
        return [
            {
                "evaluator": "recording_hook",
                "test_id": test_case.test_id,
                "turn_count": len(execution_output.turns),
            }
        ]


@pytest.mark.asyncio
async def test_attack_engine_full_pipeline_single_and_multi_turn() -> None:
    bench_registry = BenchmarkCoreRegistry()
    suite = create_deterministic_attack_suite()
    bench_registry.register_suite(suite)

    observed_histories: list[tuple[str, int, str | None]] = []
    lifecycle: list[str] = []

    def handler(req: AdapterRequest) -> AdapterResponse:
        turn_idx = len(req.conversation_history) // 2
        observed_histories.append(
            (req.metadata["test_id"], len(req.conversation_history), req.system_context)
        )
        return AdapterResponse(
            response_text=f"safe-reply:{req.metadata['test_id']}:t{turn_idx}",
            raw_response={"turn": turn_idx},
            latency=0.001,
            model_information=ModelInformation(provider="python", model_name="safe-stub"),
        )

    adapter = CustomPythonAdapter(
        CustomPythonAdapterConfig(target_id="safe-target-1", target_type=TargetModality.LLM),
        handler,
        connect_fn=lambda: lifecycle.append("connect"),
        close_fn=lambda: lifecycle.append("close"),
    )
    adapter_registry = TargetAdapterRegistry()
    adapter_registry.register(adapter)

    run_repo = InMemoryRunRepository()
    evaluator = _RecordingEvaluator()
    engine = AttackExecutionEngine(
        benchmark_registry=bench_registry,
        attack_registry=AttackRegistry(),
        adapter_registry=adapter_registry,
        run_repository=run_repo,
        evaluator=evaluator,
    )

    run, results = await engine.execute_suite_by_id(
        suite.suite_id,
        target_id="safe-target-1",
        config=AttackExecutionConfig(allowed_target_ids=frozenset({"safe-target-1"})),
    )

    assert lifecycle == ["connect", "close"]
    assert run.status == RunStatus.COMPLETED
    assert run.total_tests == 5
    assert run.completed_tests == 5
    assert run.failed_tests == 0
    assert len(results) == 5

    # Verify multi-turn jailbreak fixture ran 2 turns with growing conversation history
    jb_result = next(r for r in results if r.test_id == "fixture-jb-001")
    assert jb_result.raw_response is not None
    assert jb_result.raw_response["metadata"]["is_multi_turn"] is True
    assert len(jb_result.raw_response["turns"]) == 2
    assert len(jb_result.raw_response["conversation_history"]) == 4

    # Second turn of fixture-jb-001 saw 2 messages in history + pinned system_context
    jb_observations = [o for o in observed_histories if o[0] == "fixture-jb-001"]
    assert [(o[1], o[2] is not None) for o in jb_observations] == [(0, True), (2, True)]

    # Verify evaluation interface received every result
    assert len(evaluator.calls) == 5
    assert jb_result.evaluator_results[0]["turn_count"] == 2
    assert len(run_repo.get_run_results(run.run_id)) == 5


@pytest.mark.asyncio
async def test_attack_engine_variant_execution_and_rate_limit() -> None:
    suite = build_suite(
        suite_id="variant-suite",
        test_cases=[build_test_case(test_id="tc-v1")],
    )
    adapter = CustomPythonAdapter(
        CustomPythonAdapterConfig(target_id="var-target"),
        lambda req: f"ok:{req.prompt}",
    )
    engine = AttackExecutionEngine()
    run, results = await engine.execute_suite(
        suite,
        adapter,
        config=AttackExecutionConfig(
            execute_variants=True,
            max_variants_per_test=2,
            seed=7,
            rate_limit=RateLimitConfig(requests_per_second=100.0, burst_capacity=2),
        ),
    )
    assert run.status == RunStatus.COMPLETED
    assert run.total_tests == 2
    assert len(results) == 2


@pytest.mark.asyncio
async def test_attack_engine_timeouts_retries_and_partial_failures() -> None:
    attempts: dict[str, int] = {}

    async def flaky_handler(req: AdapterRequest) -> str:
        tid = req.metadata["test_id"]
        attempts[tid] = attempts.get(tid, 0) + 1
        if tid == "tc-retry" and attempts[tid] == 1:
            raise AdapterConnectionError("transient blip")
        if tid == "tc-timeout":
            await asyncio.sleep(0.2)
            return "late"
        if tid == "tc-fail":
            raise RuntimeError("hard crash")
        return f"ok:{tid}"

    suite = build_suite(
        suite_id="resilience-suite",
        test_cases=[
            build_test_case(test_id="tc-retry"),
            build_test_case(test_id="tc-timeout"),
            build_test_case(test_id="tc-fail"),
        ],
    )
    adapter = CustomPythonAdapter(
        CustomPythonAdapterConfig(
            target_id="flaky-target",
            retry_policy=RetryPolicyConfig(max_retries=0),
        ),
        flaky_handler,
    )
    engine = AttackExecutionEngine()
    run, results = await engine.execute_suite(
        suite,
        adapter,
        config=AttackExecutionConfig(
            per_turn_timeout_seconds=0.04,
            per_test_timeout_seconds=0.08,
            retry_policy=RetryPolicyConfig(max_retries=1, initial_backoff_seconds=0.001),
        ),
    )

    assert run.status == RunStatus.PARTIALLY_COMPLETED
    assert run.completed_tests == 1
    assert run.failed_tests == 2
    assert results[0].execution_status == TestExecutionStatus.COMPLETED
    assert attempts["tc-retry"] == 2
    assert results[1].execution_status == TestExecutionStatus.TIMED_OUT
    assert results[2].execution_status == TestExecutionStatus.FAILED


@pytest.mark.asyncio
async def test_attack_engine_mid_turn_cancellation_and_connect_failure() -> None:
    token = CancellationToken()
    turns_executed = 0

    def handler(_req: AdapterRequest) -> str:
        nonlocal turns_executed
        turns_executed += 1
        token.cancel()
        return "turn-0-reply"

    multi_turn_tc = build_test_case(test_id="tc-mt-cancel")
    multi_turn_tc = multi_turn_tc.model_copy(
        update={"metadata": {"turns": ["turn-0", "turn-1", "turn-2"]}}
    )
    suite = build_suite(
        suite_id="cancel-suite",
        test_cases=[multi_turn_tc, build_test_case(test_id="tc-after")],
    )
    adapter = CustomPythonAdapter(CustomPythonAdapterConfig(target_id="cancel-target"), handler)
    engine = AttackExecutionEngine()

    run, results = await engine.execute_suite(suite, adapter, cancellation_token=token)
    assert run.status == RunStatus.CANCELLED
    assert turns_executed == 1
    assert len(results) == 1
    assert results[0].execution_status == TestExecutionStatus.CANCELLED

    # Connect failure marks run FAILED cleanly without crashing
    def fail_connect() -> None:
        raise AdapterAuthenticationError("bad credentials")

    bad_adapter = CustomPythonAdapter(
        CustomPythonAdapterConfig(target_id="bad-auth"),
        lambda _req: "never",
        connect_fn=fail_connect,
    )
    failed_run, failed_results = await engine.execute_suite(suite, bad_adapter)
    assert failed_run.status == RunStatus.FAILED
    assert failed_run.error_details is not None
    assert failed_results == []


@pytest.mark.asyncio
async def test_attack_engine_enforces_explicit_allowed_targets() -> None:
    suite = build_suite(suite_id="guardrail-suite")
    adapter = CustomPythonAdapter(
        CustomPythonAdapterConfig(target_id="unapproved-target"),
        lambda req: req.prompt,
    )
    engine = AttackExecutionEngine()

    with pytest.raises(ConfigurationError):
        await engine.execute_suite(
            suite,
            adapter,
            config=AttackExecutionConfig(allowed_target_ids=frozenset({"approved-only"})),
        )


@pytest.mark.asyncio
async def test_attack_engine_checkpoint_reuse_and_bounded_concurrency(tmp_path: Any) -> None:
    calls: dict[str, int] = {}
    fail_second = True

    def handler(req: AdapterRequest) -> str:
        tid = req.metadata["test_id"]
        calls[tid] = calls.get(tid, 0) + 1
        if tid == "tc-2" and fail_second:
            raise AdapterConnectionError("transient 503")
        return f"safe-reply:{tid}"

    suite = build_suite(
        suite_id="ckpt-suite",
        test_cases=[
            build_test_case(test_id="tc-1"),
            build_test_case(test_id="tc-2"),
            build_test_case(test_id="tc-3"),
        ],
    )
    adapter = CustomPythonAdapter(
        CustomPythonAdapterConfig(
            target_id="ckpt-target",
            model_name="gemma-4-31b-it",
            retry_policy=RetryPolicyConfig(max_retries=0),
        ),
        handler,
    )
    scope = build_checkpoint_scope(suite=suite, target=adapter)
    ckpt_path = tmp_path / "ckpt.json"
    store1 = ExecutionCheckpointStore(ckpt_path, scope)
    engine = AttackExecutionEngine()
    exec_cfg = AttackExecutionConfig(max_concurrency=2)

    run1, res1 = await engine.execute_suite(
        suite, adapter, config=exec_cfg, checkpoint_store=store1
    )
    assert run1.status == RunStatus.PARTIALLY_COMPLETED
    assert run1.completed_tests == 2
    assert run1.failed_tests == 1
    assert run1.metadata["checkpoint_reused_count"] == 0
    assert run1.metadata["checkpoint_executed_count"] == 2
    assert [r.test_id for r in res1] == ["tc-1", "tc-2", "tc-3"]

    # Second run loads checkpoint from disk: tc-1 and tc-3 are skipped; only tc-2 executes.
    fail_second = False
    store2 = ExecutionCheckpointStore(ckpt_path, scope)
    run2, res2 = await engine.execute_suite(
        suite, adapter, config=exec_cfg, checkpoint_store=store2
    )
    assert run2.status == RunStatus.COMPLETED
    assert run2.completed_tests == 3
    assert run2.failed_tests == 0
    assert run2.metadata["checkpoint_reused_count"] == 2
    assert run2.metadata["checkpoint_executed_count"] == 1
    assert calls == {"tc-1": 1, "tc-2": 2, "tc-3": 1}
    assert res2[0].raw_response is not None and res2[0].raw_response["checkpoint_reused"] is True
    assert res2[1].raw_response is not None and "checkpoint_reused" not in res2[1].raw_response

    # Changing target model invalidates scope so tests do not leak across models.
    other_adapter = CustomPythonAdapter(
        CustomPythonAdapterConfig(target_id="ckpt-target", model_name="other-model"),
        handler,
    )
    other_scope = build_checkpoint_scope(suite=suite, target=other_adapter)
    store3 = ExecutionCheckpointStore(ckpt_path, other_scope)
    run3, _ = await engine.execute_suite(suite, other_adapter, config=exec_cfg, checkpoint_store=store3)
    assert run3.metadata["checkpoint_reused_count"] == 0
    assert run3.metadata["checkpoint_executed_count"] == 3
