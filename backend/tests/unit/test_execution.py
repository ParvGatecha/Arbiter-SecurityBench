"""Unit tests for BenchmarkExecutionEngine lifecycle, failures, partial runs, and cancellation."""

from __future__ import annotations

import pytest

from arbiter_securitybench.contracts import (
    ConfigurationError,
    RunStatus,
    TargetExecutionRequest,
    TargetModality,
    TestExecutionStatus,
)
from arbiter_securitybench.execution import BenchmarkExecutionEngine, CancellationToken
from arbiter_securitybench.storage import InMemoryRunRepository
from conftest import StubTargetAdapter, build_suite, build_test_case


@pytest.mark.asyncio
async def test_sequential_execution_completes_and_persists_results() -> None:
    run_repo = InMemoryRunRepository()
    engine = BenchmarkExecutionEngine(run_repository=run_repo)
    suite = build_suite(
        suite_id="suite-exec",
        test_cases=[
            build_test_case(test_id="tc-1"),
            build_test_case(test_id="tc-2"),
            build_test_case(test_id="tc-3"),
        ],
    )
    adapter = StubTargetAdapter(target_id="mock-llm")

    run, results = await engine.execute_suite(suite, adapter)

    assert adapter.executed_test_ids == ["tc-1", "tc-2", "tc-3"]
    assert run.status == RunStatus.COMPLETED
    assert run.total_tests == 3
    assert run.completed_tests == 3
    assert run.failed_tests == 0
    assert run.started_at is not None
    assert run.completed_at is not None
    assert run.completed_at >= run.started_at
    assert len(results) == 3
    assert all(r.execution_status == TestExecutionStatus.COMPLETED for r in results)
    assert all(r.evaluator_results == [] for r in results)

    persisted_run = run_repo.get_run(run.run_id)
    assert persisted_run is not None
    assert persisted_run.status == RunStatus.COMPLETED
    assert len(run_repo.get_run_results(run.run_id)) == 3


@pytest.mark.asyncio
async def test_individual_test_failure_produces_partially_completed_run() -> None:
    run_repo = InMemoryRunRepository()
    engine = BenchmarkExecutionEngine(run_repository=run_repo)
    suite = build_suite(
        suite_id="suite-partial",
        test_cases=[
            build_test_case(test_id="tc-ok-1"),
            build_test_case(test_id="tc-fail"),
            build_test_case(test_id="tc-ok-2"),
        ],
    )
    adapter = StubTargetAdapter(fail_on_test_ids={"tc-fail"})

    run, results = await engine.execute_suite(suite, adapter)

    assert run.status == RunStatus.PARTIALLY_COMPLETED
    assert run.completed_tests == 2
    assert run.failed_tests == 1
    assert [r.test_id for r in results] == ["tc-ok-1", "tc-fail", "tc-ok-2"]
    assert results[1].execution_status == TestExecutionStatus.FAILED
    assert results[1].output is None
    assert results[1].error_details is not None


@pytest.mark.asyncio
async def test_all_tests_failing_marks_run_failed() -> None:
    engine = BenchmarkExecutionEngine()
    suite = build_suite(
        suite_id="suite-all-fail",
        test_cases=[build_test_case(test_id="tc-f1"), build_test_case(test_id="tc-f2")],
    )
    adapter = StubTargetAdapter(fail_on_test_ids={"tc-f1", "tc-f2"})

    run, results = await engine.execute_suite(suite, adapter)

    assert run.status == RunStatus.FAILED
    assert run.completed_tests == 0
    assert run.failed_tests == 2
    assert all(r.execution_status == TestExecutionStatus.FAILED for r in results)


@pytest.mark.asyncio
async def test_timeout_records_timed_out_status() -> None:
    engine = BenchmarkExecutionEngine(per_test_timeout_seconds=0.05)
    suite = build_suite(
        suite_id="suite-timeout",
        test_cases=[build_test_case(test_id="tc-slow"), build_test_case(test_id="tc-fast")],
    )
    adapter = StubTargetAdapter(delay_on_test_ids={"tc-slow": 0.2})

    run, results = await engine.execute_suite(suite, adapter)

    assert run.status == RunStatus.PARTIALLY_COMPLETED
    assert results[0].execution_status == TestExecutionStatus.TIMED_OUT
    assert results[0].output is None
    assert results[1].execution_status == TestExecutionStatus.COMPLETED


@pytest.mark.asyncio
async def test_cooperative_cancellation_stops_before_next_test() -> None:
    run_repo = InMemoryRunRepository()
    engine = BenchmarkExecutionEngine(run_repository=run_repo)
    token = CancellationToken()

    def cancel_after_first(req: TargetExecutionRequest) -> None:
        if req.test_id == "tc-1":
            token.cancel()

    suite = build_suite(
        suite_id="suite-cancel",
        test_cases=[
            build_test_case(test_id="tc-1"),
            build_test_case(test_id="tc-2"),
            build_test_case(test_id="tc-3"),
        ],
    )
    adapter = StubTargetAdapter(on_execute_hook=cancel_after_first)

    run, results = await engine.execute_suite(suite, adapter, cancellation_token=token)

    assert run.status == RunStatus.CANCELLED
    assert run.completed_tests == 1
    assert len(results) == 1
    assert adapter.executed_test_ids == ["tc-1"]
    assert len(run_repo.get_run_results(run.run_id)) == 1


@pytest.mark.asyncio
async def test_incompatible_target_modality_raises_configuration_error() -> None:
    engine = BenchmarkExecutionEngine()
    suite = build_suite(
        suite_id="suite-rag-only",
        supported_target_types=[TargetModality.RAG],
    )
    adapter = StubTargetAdapter(target_type=TargetModality.LLM)

    with pytest.raises(ConfigurationError):
        await engine.execute_suite(suite, adapter)
