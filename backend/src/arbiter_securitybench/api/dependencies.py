"""Dependency container and wiring helpers for the FastAPI application."""

from __future__ import annotations

import os
from dataclasses import dataclass

from fastapi import Request

from arbiter_securitybench.adapters import TargetAdapterRegistry
from arbiter_securitybench.contracts import NotFoundError
from arbiter_securitybench.datasets import register_arbiter_benchmark_v1
from arbiter_securitybench.evaluation import (
    ModularEvaluationEngine,
    RuleBasedEvaluator,
    SemanticEvaluator,
    SensitiveInfoEvaluator,
)
from arbiter_securitybench.execution import BenchmarkExecutionEngine
from arbiter_securitybench.registry import BenchmarkCoreRegistry
from arbiter_securitybench.storage import (
    BenchmarkRepository,
    InMemoryBenchmarkRepository,
    InMemoryRunRepository,
    RunRepository,
    SQLAlchemyBenchmarkRepository,
    SQLAlchemyRunRepository,
    create_db_engine,
    create_session_factory,
    init_db,
)


def _describe_storage_backend(database_url: str | None) -> str:
    if not database_url:
        return "in_memory"
    scheme = database_url.split(":", 1)[0].split("+", 1)[0].strip().lower()
    return scheme or "database"


@dataclass(slots=True)
class AppContainer:
    """Explicit dependency container attached to FastAPI app.state."""

    registry: BenchmarkCoreRegistry
    run_repository: RunRepository
    execution_engine: BenchmarkExecutionEngine
    adapter_registry: TargetAdapterRegistry
    storage_backend: str = "in_memory"
    default_timeout_seconds: float | None = 60.0
    builtin_datasets_loaded: bool = False


def build_default_container(
    *,
    database_url: str | None = None,
    per_test_timeout_seconds: float | None = 60.0,
    load_builtin_datasets: bool | None = None,
) -> AppContainer:
    """Build the default API runtime container (SQLAlchemy when ASB_DATABASE_URL is set)."""
    resolved_url = database_url if database_url is not None else os.getenv("ASB_DATABASE_URL")
    if resolved_url:
        engine = create_db_engine(resolved_url)
        init_db(engine)
        session_factory = create_session_factory(engine)
        benchmark_repo: BenchmarkRepository = SQLAlchemyBenchmarkRepository(session_factory)
        run_repo: RunRepository = SQLAlchemyRunRepository(session_factory)
    else:
        benchmark_repo = InMemoryBenchmarkRepository()
        run_repo = InMemoryRunRepository()

    registry = BenchmarkCoreRegistry(repository=benchmark_repo)
    should_load_builtin = (
        load_builtin_datasets
        if load_builtin_datasets is not None
        else os.getenv("ASB_LOAD_BUILTIN_DATASETS", "").strip().lower() in {"1", "true", "yes"}
    )
    if should_load_builtin:
        try:
            registry.get_benchmark("arbiter-security-benchmark")
        except NotFoundError:
            register_arbiter_benchmark_v1(registry)

    evaluation_engine = ModularEvaluationEngine(
        evaluators=[
            RuleBasedEvaluator(),
            SensitiveInfoEvaluator(),
            SemanticEvaluator(),
        ],
        consensus_policy="conservative",
    )
    execution_engine = BenchmarkExecutionEngine(
        run_repository=run_repo,
        per_test_timeout_seconds=per_test_timeout_seconds,
        evaluation_engine=evaluation_engine,
    )
    adapter_registry = TargetAdapterRegistry()
    return AppContainer(
        registry=registry,
        run_repository=run_repo,
        execution_engine=execution_engine,
        adapter_registry=adapter_registry,
        storage_backend=_describe_storage_backend(resolved_url),
        default_timeout_seconds=per_test_timeout_seconds,
        builtin_datasets_loaded=should_load_builtin,
    )


def get_container(request: Request) -> AppContainer:
    """FastAPI dependency returning the container attached to application state."""
    return request.app.state.container
