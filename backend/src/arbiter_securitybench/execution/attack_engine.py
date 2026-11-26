"""Modular AttackExecutionEngine orchestrating adversarial benchmark runs."""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from arbiter_securitybench.adapters import (
    AsyncTokenBucketRateLimiter,
    TargetAdapter,
    TargetAdapterRegistry,
)
from arbiter_securitybench.adapters.resilience import execute_with_retry
from arbiter_securitybench.attacks import (
    Attack,
    AttackCancelledError,
    AttackExecutionConfig,
    AttackExecutionOutput,
    AttackRegistry,
    AttackVariant,
)
from arbiter_securitybench.contracts import (
    AdapterError,
    BenchmarkRun,
    BenchmarkSuite,
    BenchmarkTargetAdapter,
    ConfigurationError,
    ErrorRecord,
    ExecutionTimeoutError,
    RunStatus,
    SecurityBenchError,
    TestCase,
    TestExecutionResult,
    TestExecutionStatus,
    validate_run_status_transition,
)
from arbiter_securitybench.evaluation import NoOpResultEvaluator, ResultEvaluator
from arbiter_securitybench.execution.checkpoint import ExecutionCheckpointStore
from arbiter_securitybench.execution.engine import CancellationToken
from arbiter_securitybench.registry import BenchmarkCoreRegistry
from arbiter_securitybench.storage import InMemoryRunRepository, RunRepository


class AttackExecutionEngine:
    """Executes standardized single-turn and multi-turn attacks against explicit targets."""

    def __init__(
        self,
        *,
        benchmark_registry: BenchmarkCoreRegistry | None = None,
        attack_registry: AttackRegistry | None = None,
        adapter_registry: TargetAdapterRegistry | None = None,
        run_repository: RunRepository | None = None,
        evaluator: ResultEvaluator | None = None,
    ) -> None:
        self._benchmark_registry = benchmark_registry
        self._attack_registry = attack_registry or AttackRegistry()
        self._adapter_registry = adapter_registry
        self._run_repo = run_repository or InMemoryRunRepository()
        self._evaluator: ResultEvaluator = evaluator or NoOpResultEvaluator()
        self._cancelled_runs: set[str] = set()

    def cancel_run(self, run_id: str) -> None:
        """Request cooperative cancellation for an active or pending run."""
        self._cancelled_runs.add(run_id)

    def _is_cancelled(self, run_id: str, token: CancellationToken | None) -> bool:
        return (run_id in self._cancelled_runs) or (token is not None and token.is_cancelled)

    async def execute_suite_by_id(
        self,
        benchmark_id: str,
        *,
        target_id: str,
        version: str | None = None,
        config: AttackExecutionConfig | None = None,
        target_config: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        run_id: str | None = None,
        cancellation_token: CancellationToken | None = None,
    ) -> tuple[BenchmarkRun, list[TestExecutionResult]]:
        """Load a registered BenchmarkSuite and TargetAdapter by ID and execute attacks."""
        if self._benchmark_registry is None:
            raise ConfigurationError(
                "benchmark_registry must be configured to execute suites by ID.",
                component="execution.attack_engine",
            )
        if self._adapter_registry is None:
            raise ConfigurationError(
                "adapter_registry must be configured to resolve targets by ID.",
                component="execution.attack_engine",
            )

        suite = self._benchmark_registry.get_benchmark(benchmark_id, version=version)
        target = self._adapter_registry.get(target_id)
        return await self.execute_suite(
            suite,
            target,
            config=config,
            target_config=target_config,
            metadata=metadata,
            run_id=run_id,
            cancellation_token=cancellation_token,
        )

    async def execute_suite(
        self,
        suite: BenchmarkSuite,
        target: TargetAdapter | BenchmarkTargetAdapter,
        *,
        config: AttackExecutionConfig | None = None,
        target_config: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        run_id: str | None = None,
        cancellation_token: CancellationToken | None = None,
        checkpoint_store: ExecutionCheckpointStore | None = None,
    ) -> tuple[BenchmarkRun, list[TestExecutionResult]]:
        """Execute all adversarial test cases in a suite against an explicitly configured target."""
        exec_cfg = config or AttackExecutionConfig()

        if not target.target_id.strip():
            raise ConfigurationError(
                "Target adapter must define a non-empty explicit target_id.",
                component="execution.attack_engine",
            )
        if (
            exec_cfg.allowed_target_ids is not None
            and target.target_id not in exec_cfg.allowed_target_ids
        ):
            raise ConfigurationError(
                f"Target {target.target_id!r} is not in allowed_target_ids.",
                component="execution.attack_engine",
                details={"target_id": target.target_id},
            )
        if target.target_type not in suite.supported_target_types:
            raise ConfigurationError(
                f"Target {target.target_id!r} modality {target.target_type.value!r} "
                f"is not supported by suite {suite.suite_id!r}.",
                component="execution.attack_engine",
                details={
                    "target_id": target.target_id,
                    "target_type": target.target_type.value,
                    "supported_target_types": [t.value for t in suite.supported_target_types],
                },
            )

        # Build execution plan (primary test cases or seeded variants) before creating run.
        work_items: list[tuple[TestCase, Attack, AttackVariant | None]] = []
        for tc in suite.test_cases:
            attack = self._attack_registry.resolve_for_test_case(tc)
            if exec_cfg.execute_variants:
                variants = attack.generate_variants(
                    tc, seed=exec_cfg.seed, max_variants=exec_cfg.max_variants_per_test
                )
                if variants:
                    for variant in variants:
                        work_items.append((tc, attack, variant))
                else:
                    work_items.append((tc, attack, None))
            else:
                work_items.append((tc, attack, None))

        resolved_run_id = run_id or f"run-{uuid4().hex}"
        resolved_target_config = dict(target_config or {})
        resolved_metadata = {
            **dict(metadata or {}),
            "engine": "attack_execution_engine",
            "seed": exec_cfg.seed,
            "execute_variants": exec_cfg.execute_variants,
        }

        run = BenchmarkRun(
            run_id=resolved_run_id,
            benchmark_id=suite.benchmark_id,
            suite_id=suite.suite_id,
            benchmark_version=suite.version,
            target_id=target.target_id,
            target_type=target.target_type,
            target_config=resolved_target_config,
            status=RunStatus.PENDING,
            total_tests=len(work_items),
            metadata=resolved_metadata,
        )
        run = self._run_repo.create_run(run)

        if self._is_cancelled(resolved_run_id, cancellation_token):
            validate_run_status_transition(run.status, RunStatus.CANCELLED)
            cancelled = run.model_copy(
                update={"status": RunStatus.CANCELLED, "completed_at": datetime.now(UTC)}
            )
            return self._run_repo.update_run(cancelled), []

        validate_run_status_transition(run.status, RunStatus.RUNNING)
        run = self._run_repo.update_run(
            run.model_copy(update={"status": RunStatus.RUNNING, "started_at": datetime.now(UTC)})
        )

        # Check cross-run checkpoint store before opening any target connection.
        ordered_results: list[TestExecutionResult | None] = [None] * len(work_items)
        pending_indices: list[int] = []
        completed_tests = 0
        failed_tests = 0
        checkpoint_reused_count = 0

        for idx, (test_case, _attack, variant) in enumerate(work_items):
            variant_id = variant.variant_id if variant is not None else None
            cached = (
                checkpoint_store.lookup(
                    test_case,
                    variant_id=variant_id,
                    run_id=resolved_run_id,
                    target_id=target.target_id,
                )
                if checkpoint_store is not None
                else None
            )
            if cached is not None:
                self._run_repo.save_test_result(cached)
                ordered_results[idx] = cached
                completed_tests += 1
                checkpoint_reused_count += 1
            else:
                pending_indices.append(idx)

        if checkpoint_reused_count > 0:
            run = self._run_repo.update_run(
                run.model_copy(
                    update={
                        "completed_tests": completed_tests,
                        "failed_tests": failed_tests,
                    }
                )
            )

        opened_connection = False
        if pending_indices and isinstance(target, TargetAdapter) and not target.is_connected:
            try:
                await target.connect()
                opened_connection = True
            except SecurityBenchError as exc:
                validate_run_status_transition(run.status, RunStatus.FAILED)
                failed = run.model_copy(
                    update={
                        "status": RunStatus.FAILED,
                        "completed_at": datetime.now(UTC),
                        "error_details": exc.to_record(),
                    }
                )
                return self._run_repo.update_run(failed), [
                    r for r in ordered_results if r is not None
                ]

        rate_limiter = (
            AsyncTokenBucketRateLimiter(exec_cfg.rate_limit)
            if exec_cfg.rate_limit is not None
            else None
        )

        cancelled_mid_run = False
        checkpoint_executed_count = 0
        state_lock = asyncio.Lock()

        async def _run_indexed(idx: int) -> None:
            nonlocal run, completed_tests, failed_tests, cancelled_mid_run, checkpoint_executed_count
            test_case, attack, variant = work_items[idx]
            variant_id = variant.variant_id if variant is not None else None

            if self._is_cancelled(resolved_run_id, cancellation_token):
                cancelled_mid_run = True
                return

            result = await self._execute_item(
                run_id=resolved_run_id,
                test_case=test_case,
                attack=attack,
                variant=variant,
                target=target,
                exec_cfg=exec_cfg,
                target_config=resolved_target_config,
                rate_limiter=rate_limiter,
                cancellation_token=cancellation_token,
            )

            async with state_lock:
                self._run_repo.save_test_result(result)
                ordered_results[idx] = result
                if result.execution_status == TestExecutionStatus.COMPLETED:
                    completed_tests += 1
                    checkpoint_executed_count += 1
                    if checkpoint_store is not None:
                        checkpoint_store.record(test_case, result, variant_id=variant_id)
                elif result.execution_status == TestExecutionStatus.CANCELLED:
                    cancelled_mid_run = True
                else:
                    failed_tests += 1

                run = self._run_repo.update_run(
                    run.model_copy(
                        update={
                            "completed_tests": completed_tests,
                            "failed_tests": failed_tests,
                        }
                    )
                )

        try:
            if exec_cfg.max_concurrency <= 1:
                for idx in pending_indices:
                    if self._is_cancelled(resolved_run_id, cancellation_token) or cancelled_mid_run:
                        cancelled_mid_run = True
                        break
                    await _run_indexed(idx)
            else:
                semaphore = asyncio.Semaphore(exec_cfg.max_concurrency)

                async def _bounded_run(idx: int) -> None:
                    async with semaphore:
                        if (
                            self._is_cancelled(resolved_run_id, cancellation_token)
                            or cancelled_mid_run
                        ):
                            return
                        await _run_indexed(idx)

                await asyncio.gather(*(_bounded_run(idx) for idx in pending_indices))
        finally:
            if (
                isinstance(target, TargetAdapter)
                and (opened_connection or exec_cfg.disconnect_on_finish)
                and target.is_connected
            ):
                await target.close()

        results = [r for r in ordered_results if r is not None]

        if cancelled_mid_run or self._is_cancelled(resolved_run_id, cancellation_token):
            final_status = RunStatus.CANCELLED
        elif failed_tests == 0 and completed_tests == len(work_items):
            final_status = RunStatus.COMPLETED
        elif completed_tests > 0 and failed_tests > 0:
            final_status = RunStatus.PARTIALLY_COMPLETED
        else:
            final_status = RunStatus.FAILED

        validate_run_status_transition(run.status, final_status)
        final_metadata = {
            **dict(run.metadata),
            "checkpoint_reused_count": checkpoint_reused_count,
            "checkpoint_executed_count": checkpoint_executed_count,
        }
        final_run = run.model_copy(
            update={
                "status": final_status,
                "completed_tests": completed_tests,
                "failed_tests": failed_tests,
                "completed_at": datetime.now(UTC),
                "metadata": final_metadata,
            }
        )
        return self._run_repo.update_run(final_run), results

    async def _execute_item(
        self,
        *,
        run_id: str,
        test_case: TestCase,
        attack: Attack,
        variant: AttackVariant | None,
        target: TargetAdapter | BenchmarkTargetAdapter,
        exec_cfg: AttackExecutionConfig,
        target_config: dict[str, Any],
        rate_limiter: AsyncTokenBucketRateLimiter | None,
        cancellation_token: CancellationToken | None,
    ) -> TestExecutionResult:
        start_perf = time.perf_counter()

        async def _run_attack_once() -> AttackExecutionOutput:
            if rate_limiter is not None:
                await rate_limiter.acquire()
            coro = attack.execute(
                target,
                test_case,
                run_id=run_id,
                variant=variant,
                target_config=target_config,
                per_turn_timeout_seconds=exec_cfg.per_turn_timeout_seconds,
                is_cancelled=lambda: self._is_cancelled(run_id, cancellation_token),
            )
            return await asyncio.wait_for(coro, timeout=exec_cfg.per_test_timeout_seconds)

        try:
            output = await execute_with_retry(
                _run_attack_once,
                policy=exec_cfg.retry_policy,
                target_id=target.target_id,
                adapter_type=attack.attack_id,
            )
            elapsed = time.perf_counter() - start_perf
            evaluator_records = await self._evaluator.evaluate(test_case, output)
            return TestExecutionResult(
                run_id=run_id,
                test_id=test_case.test_id,
                target_id=target.target_id,
                input=output.turns[0].prompt,
                output=output.final_response_text,
                execution_status=TestExecutionStatus.COMPLETED,
                execution_time=elapsed,
                raw_response={
                    "attack_id": output.attack_id,
                    "category": output.category.value,
                    "variant_id": output.variant_id,
                    "turns": [t.model_dump(mode="json") for t in output.turns],
                    "conversation_history": [
                        m.model_dump(mode="json") for m in output.conversation_history
                    ],
                    "total_latency_seconds": output.total_latency_seconds,
                    "metadata": output.metadata,
                },
                evaluator_results=evaluator_records,
                error_details=None,
            )
        except AttackCancelledError as exc:
            elapsed = time.perf_counter() - start_perf
            return TestExecutionResult(
                run_id=run_id,
                test_id=test_case.test_id,
                target_id=target.target_id,
                input=test_case.input_prompt,
                output=None,
                execution_status=TestExecutionStatus.CANCELLED,
                execution_time=elapsed,
                raw_response=None,
                evaluator_results=[],
                error_details={
                    "error_code": "ASB_EXECUTION_CANCELLED",
                    "message": str(exc),
                },
            )
        except TimeoutError:
            elapsed = time.perf_counter() - start_perf
            err: ErrorRecord = ExecutionTimeoutError(
                f"Attack {attack.attack_id!r} on test {test_case.test_id!r} timed out "
                f"after {exec_cfg.per_test_timeout_seconds}s.",
                component="execution.attack_engine",
                details={
                    "test_id": test_case.test_id,
                    "attack_id": attack.attack_id,
                    "timeout_seconds": exec_cfg.per_test_timeout_seconds,
                },
            ).to_record()
            return TestExecutionResult(
                run_id=run_id,
                test_id=test_case.test_id,
                target_id=target.target_id,
                input=test_case.input_prompt,
                output=None,
                execution_status=TestExecutionStatus.TIMED_OUT,
                execution_time=elapsed,
                raw_response=None,
                evaluator_results=[],
                error_details=err,
            )
        except SecurityBenchError as exc:
            elapsed = time.perf_counter() - start_perf
            return TestExecutionResult(
                run_id=run_id,
                test_id=test_case.test_id,
                target_id=target.target_id,
                input=test_case.input_prompt,
                output=None,
                execution_status=TestExecutionStatus.FAILED,
                execution_time=elapsed,
                raw_response=None,
                evaluator_results=[],
                error_details=exc.to_record(),
            )
        except Exception as exc:  # noqa: BLE001 - isolate item failure without crashing benchmark run
            elapsed = time.perf_counter() - start_perf
            wrapped = AdapterError(
                f"Unhandled error executing attack {attack.attack_id!r} on {test_case.test_id!r}: {exc}",
                component="execution.attack_engine",
                details={
                    "test_id": test_case.test_id,
                    "attack_id": attack.attack_id,
                    "exception_type": type(exc).__name__,
                },
            ).to_record()
            return TestExecutionResult(
                run_id=run_id,
                test_id=test_case.test_id,
                target_id=target.target_id,
                input=test_case.input_prompt,
                output=None,
                execution_status=TestExecutionStatus.FAILED,
                execution_time=elapsed,
                raw_response=None,
                evaluator_results=[],
                error_details=wrapped,
            )
