"""Sequential benchmark execution engine with isolation, cancellation, and persistence."""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from threading import Event
from typing import Any, Protocol
from uuid import uuid4

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
    TargetExecutionRequest,
    TestCase,
    TestExecutionResult,
    TestExecutionStatus,
    validate_run_status_transition,
)
from arbiter_securitybench.storage import InMemoryRunRepository, RunRepository


class CancellationToken:
    """Thread-safe cooperative cancellation signal for benchmark runs."""

    def __init__(self) -> None:
        self._event = Event()

    def cancel(self) -> None:
        """Signal that the associated run should cancel before the next test case."""
        self._event.set()

    @property
    def is_cancelled(self) -> bool:
        return self._event.is_set()


class _ResultEvaluationEngine(Protocol):
    async def evaluate_input(self, item: Any) -> Any:
        ...


class BenchmarkExecutionEngine:
    """Executes benchmark suites sequentially and persists runs and individual results."""

    def __init__(
        self,
        run_repository: RunRepository | None = None,
        *,
        per_test_timeout_seconds: float | None = 60.0,
        evaluation_engine: _ResultEvaluationEngine | None = None,
    ) -> None:
        if per_test_timeout_seconds is not None and per_test_timeout_seconds <= 0:
            raise ConfigurationError(
                "per_test_timeout_seconds must be positive when provided.",
                component="execution.engine",
            )
        self._run_repo = run_repository or InMemoryRunRepository()
        self._per_test_timeout_seconds = per_test_timeout_seconds
        self._evaluation_engine = evaluation_engine
        self._cancelled_runs: set[str] = set()

    def cancel_run(self, run_id: str) -> None:
        """Request cooperative cancellation for a run by run_id."""
        self._cancelled_runs.add(run_id)

    def _is_cancelled(self, run_id: str, token: CancellationToken | None) -> bool:
        return (run_id in self._cancelled_runs) or (token is not None and token.is_cancelled)

    async def execute_suite(
        self,
        suite: BenchmarkSuite,
        adapter: BenchmarkTargetAdapter,
        *,
        target_config: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        run_id: str | None = None,
        cancellation_token: CancellationToken | None = None,
    ) -> tuple[BenchmarkRun, list[TestExecutionResult]]:
        """Execute all test cases in a suite sequentially against the target adapter."""
        if adapter.target_type not in suite.supported_target_types:
            raise ConfigurationError(
                f"Target adapter {adapter.target_id!r} modality {adapter.target_type.value!r} "
                f"is not supported by suite {suite.suite_id!r}.",
                component="execution.engine",
                details={
                    "target_id": adapter.target_id,
                    "target_type": adapter.target_type.value,
                    "supported_target_types": [t.value for t in suite.supported_target_types],
                },
            )

        resolved_run_id = run_id or f"run-{uuid4().hex}"
        resolved_target_config = dict(target_config or {})
        resolved_metadata = dict(metadata or {})

        run = BenchmarkRun(
            run_id=resolved_run_id,
            benchmark_id=suite.benchmark_id,
            suite_id=suite.suite_id,
            benchmark_version=suite.version,
            target_id=adapter.target_id,
            target_type=adapter.target_type,
            target_config=resolved_target_config,
            status=RunStatus.PENDING,
            total_tests=suite.test_count,
            metadata=resolved_metadata,
        )
        run = self._run_repo.create_run(run)

        if self._is_cancelled(resolved_run_id, cancellation_token):
            validate_run_status_transition(run.status, RunStatus.CANCELLED)
            cancelled_run = run.model_copy(
                update={
                    "status": RunStatus.CANCELLED,
                    "completed_at": datetime.now(UTC),
                }
            )
            return self._run_repo.update_run(cancelled_run), []

        validate_run_status_transition(run.status, RunStatus.RUNNING)
        started_at = datetime.now(UTC)
        run = self._run_repo.update_run(
            run.model_copy(update={"status": RunStatus.RUNNING, "started_at": started_at})
        )

        results: list[TestExecutionResult] = []
        completed_tests = 0
        failed_tests = 0

        for test_case in suite.test_cases:
            if self._is_cancelled(resolved_run_id, cancellation_token):
                validate_run_status_transition(run.status, RunStatus.CANCELLED)
                cancelled_run = run.model_copy(
                    update={
                        "status": RunStatus.CANCELLED,
                        "completed_tests": completed_tests,
                        "failed_tests": failed_tests,
                        "completed_at": datetime.now(UTC),
                    }
                )
                return self._run_repo.update_run(cancelled_run), results

            result = await self._execute_single_test(
                run_id=resolved_run_id,
                test_case=test_case,
                adapter=adapter,
                target_config=resolved_target_config,
            )
            self._run_repo.save_test_result(result)
            results.append(result)

            if result.execution_status == TestExecutionStatus.COMPLETED:
                completed_tests += 1
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

        if self._is_cancelled(resolved_run_id, cancellation_token):
            final_status = RunStatus.CANCELLED
        elif failed_tests == 0 and completed_tests == suite.test_count:
            final_status = RunStatus.COMPLETED
        elif completed_tests > 0 and failed_tests > 0:
            final_status = RunStatus.PARTIALLY_COMPLETED
        else:
            final_status = RunStatus.FAILED

        validate_run_status_transition(run.status, final_status)
        final_run = run.model_copy(
            update={
                "status": final_status,
                "completed_tests": completed_tests,
                "failed_tests": failed_tests,
                "completed_at": datetime.now(UTC),
            }
        )
        return self._run_repo.update_run(final_run), results

    async def _execute_single_test(
        self,
        *,
        run_id: str,
        test_case: TestCase,
        adapter: BenchmarkTargetAdapter,
        target_config: dict[str, Any],
    ) -> TestExecutionResult:
        request = TargetExecutionRequest(
            run_id=run_id,
            test_id=test_case.test_id,
            input_prompt=test_case.input_prompt,
            target_config=target_config,
            metadata={
                "category": test_case.category.value,
                "attack_type": test_case.attack_type.value,
                "severity": test_case.severity.value,
                "benchmark_version": test_case.benchmark_version,
            },
        )
        start_perf = time.perf_counter()
        try:
            coro = adapter.execute(request)
            if self._per_test_timeout_seconds is not None:
                response = await asyncio.wait_for(coro, timeout=self._per_test_timeout_seconds)
            else:
                response = await coro

            elapsed = time.perf_counter() - start_perf
            result = TestExecutionResult(
                run_id=run_id,
                test_id=test_case.test_id,
                target_id=adapter.target_id,
                input=test_case.input_prompt,
                output=response.output,
                execution_status=TestExecutionStatus.COMPLETED,
                execution_time=elapsed,
                raw_response=response.raw_response,
                evaluator_results=[],
                error_details=None,
            )
            if self._evaluation_engine is not None:
                from arbiter_securitybench.evaluation.models import EvaluationInput

                eval_input = EvaluationInput.from_execution_result(test_case, result)
                eval_report = await self._evaluation_engine.evaluate_input(eval_input)
                result = result.model_copy(
                    update={"evaluator_results": [eval_report.model_dump(mode="json")]}
                )
            return result
        except TimeoutError:
            elapsed = time.perf_counter() - start_perf
            err_record: ErrorRecord = ExecutionTimeoutError(
                f"Test case {test_case.test_id!r} exceeded timeout of {self._per_test_timeout_seconds}s.",
                component="execution.engine",
                details={"test_id": test_case.test_id, "timeout_seconds": self._per_test_timeout_seconds},
            ).to_record()
            return TestExecutionResult(
                run_id=run_id,
                test_id=test_case.test_id,
                target_id=adapter.target_id,
                input=test_case.input_prompt,
                output=None,
                execution_status=TestExecutionStatus.TIMED_OUT,
                execution_time=elapsed,
                raw_response=None,
                evaluator_results=[],
                error_details=err_record,
            )
        except SecurityBenchError as exc:
            elapsed = time.perf_counter() - start_perf
            return TestExecutionResult(
                run_id=run_id,
                test_id=test_case.test_id,
                target_id=adapter.target_id,
                input=test_case.input_prompt,
                output=None,
                execution_status=TestExecutionStatus.FAILED,
                execution_time=elapsed,
                raw_response=None,
                evaluator_results=[],
                error_details=exc.to_record(),
            )
        except Exception as exc:  # noqa: BLE001 - isolate per-test adapter failures so the suite continues
            elapsed = time.perf_counter() - start_perf
            wrapped = AdapterError(
                f"Target adapter raised unhandled error during test {test_case.test_id!r}: {exc}",
                component="execution.engine",
                details={"test_id": test_case.test_id, "exception_type": type(exc).__name__},
            ).to_record()
            return TestExecutionResult(
                run_id=run_id,
                test_id=test_case.test_id,
                target_id=adapter.target_id,
                input=test_case.input_prompt,
                output=None,
                execution_status=TestExecutionStatus.FAILED,
                execution_time=elapsed,
                raw_response=None,
                evaluator_results=[],
                error_details=wrapped,
            )
