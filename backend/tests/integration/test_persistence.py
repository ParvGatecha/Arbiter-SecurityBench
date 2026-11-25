"""Integration tests for SQLAlchemy persistence (SQLite backend) and InMemory repositories."""

from __future__ import annotations

from pathlib import Path

import pytest

from arbiter_securitybench.contracts import (
    DuplicateRegistrationError,
    RunStatus,
    SecurityCategory,
)
from arbiter_securitybench.execution import BenchmarkExecutionEngine
from arbiter_securitybench.registry import BenchmarkCoreRegistry
from arbiter_securitybench.storage import (
    SQLAlchemyBenchmarkRepository,
    SQLAlchemyRunRepository,
    create_db_engine,
    create_session_factory,
    init_db,
)
from conftest import StubTargetAdapter, build_suite, build_test_case


@pytest.mark.asyncio
async def test_sqlalchemy_sqlite_persistence_round_trip(tmp_path: Path) -> None:
    db_path = tmp_path / "securitybench_test.db"
    engine = create_db_engine(f"sqlite:///{db_path}")
    init_db(engine)
    session_factory = create_session_factory(engine)

    bench_repo = SQLAlchemyBenchmarkRepository(session_factory)
    run_repo = SQLAlchemyRunRepository(session_factory)
    registry = BenchmarkCoreRegistry(repository=bench_repo)
    exec_engine = BenchmarkExecutionEngine(run_repository=run_repo)

    suite = build_suite(
        suite_id="sql-suite",
        version="1.0.0",
        test_cases=[
            build_test_case(test_id="tc-sql-1"),
            build_test_case(test_id="tc-sql-2", category=SecurityCategory.TOOL_SECURITY),
        ],
    )
    registry.register_suite(suite)

    # Re-instantiate registry over the same DB to confirm real persistence.
    reloaded_registry = BenchmarkCoreRegistry(repository=SQLAlchemyBenchmarkRepository(session_factory))
    loaded_suite = reloaded_registry.get_benchmark("sql-suite", version="1.0.0")
    assert loaded_suite.test_count == 2
    assert reloaded_registry.get_test_case("tc-sql-1", "1.0.0").name == "Sample Prompt Injection Check"

    with pytest.raises(DuplicateRegistrationError):
        reloaded_registry.register_suite(suite)

    adapter = StubTargetAdapter(target_id="sql-target", fail_on_test_ids={"tc-sql-2"})
    run, _ = await exec_engine.execute_suite(loaded_suite, adapter)

    reloaded_run_repo = SQLAlchemyRunRepository(session_factory)
    persisted_run = reloaded_run_repo.get_run(run.run_id)
    assert persisted_run is not None
    assert persisted_run.status == RunStatus.PARTIALLY_COMPLETED
    assert persisted_run.completed_tests == 1
    assert persisted_run.failed_tests == 1

    persisted_results = reloaded_run_repo.get_run_results(run.run_id)
    assert [r.test_id for r in persisted_results] == ["tc-sql-1", "tc-sql-2"]
    assert persisted_results[0].output == "stub-response:tc-sql-1"
    assert persisted_results[1].error_details is not None
