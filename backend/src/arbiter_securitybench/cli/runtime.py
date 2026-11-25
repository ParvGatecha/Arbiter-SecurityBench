"""Standalone runtime wiring for executing benchmarks without starting FastAPI."""

from __future__ import annotations

from pathlib import Path

from arbiter_securitybench.adapters import (
    AnthropicAdapter,
    AnthropicAdapterConfig,
    GeminiAdapter,
    GeminiAdapterConfig,
    GenericHTTPAdapter,
    GenericHTTPAdapterConfig,
    OllamaAdapter,
    OllamaAdapterConfig,
    OpenAIAdapterConfig,
    OpenAICompatibleAdapter,
    RateLimitConfig,
    RetryPolicyConfig,
    TargetAdapterRegistry,
)
from arbiter_securitybench.cli.config import (
    ExecutionSectionConfig,
    SecurityBenchConfig,
    TargetEntryConfig,
)
from arbiter_securitybench.contracts import (
    BenchmarkTargetAdapter,
    ConfigurationError,
    DuplicateRegistrationError,
)
from arbiter_securitybench.datasets import load_benchmark_suite, register_arbiter_benchmark_v1
from arbiter_securitybench.registry import BenchmarkCoreRegistry
from arbiter_securitybench.storage import (
    RunRepository,
    SQLAlchemyBenchmarkRepository,
    SQLAlchemyRunRepository,
    create_db_engine,
    create_session_factory,
    init_db,
)

SUITE_ALIASES: dict[str, str] = {
    "security-v1": "arbiter-security-benchmark",
    "v1": "arbiter-security-benchmark",
}


def resolve_suite_id(suite_name: str) -> str:
    """Resolve friendly CLI suite aliases to canonical suite_id values."""
    cleaned = suite_name.strip()
    return SUITE_ALIASES.get(cleaned.lower(), cleaned)


def _ensure_sqlite_parent_dir(database_url: str) -> None:
    if database_url.startswith("sqlite:///") and not database_url.startswith("sqlite:///:memory:"):
        raw_path = database_url.removeprefix("sqlite:///")
        Path(raw_path).parent.mkdir(parents=True, exist_ok=True)


def build_cli_stores(
    config: SecurityBenchConfig,
    *,
    extra_suite_file: Path | str | None = None,
) -> tuple[BenchmarkCoreRegistry, RunRepository]:
    """Initialize SQLAlchemy persistence and populate built-in/custom benchmarks."""
    _ensure_sqlite_parent_dir(config.storage.database_url)
    engine = create_db_engine(config.storage.database_url)
    init_db(engine)
    session_factory = create_session_factory(engine)

    bench_repo = SQLAlchemyBenchmarkRepository(session_factory)
    run_repo = SQLAlchemyRunRepository(session_factory)
    registry = BenchmarkCoreRegistry(repository=bench_repo)

    try:
        register_arbiter_benchmark_v1(registry)
    except DuplicateRegistrationError:
        pass

    suite_file = extra_suite_file or config.benchmark.suite_file
    if suite_file:
        custom_suite = load_benchmark_suite(suite_file, validate=True)
        try:
            registry.register_suite(custom_suite)
        except DuplicateRegistrationError:
            pass

    return registry, run_repo


def build_adapter_from_entry(
    target_id: str,
    entry: TargetEntryConfig,
    execution_cfg: ExecutionSectionConfig,
    *,
    adapter_registry: TargetAdapterRegistry | None = None,
) -> BenchmarkTargetAdapter:
    """Instantiate a concrete TargetAdapter from a TargetEntryConfig."""
    if adapter_registry is not None and target_id in adapter_registry.list_target_ids():
        return adapter_registry.get(target_id)

    retry_policy = RetryPolicyConfig(max_retries=execution_cfg.max_retries)
    rate_limit = (
        RateLimitConfig(requests_per_second=execution_cfg.rate_limit_rps, burst_capacity=1)
        if execution_cfg.rate_limit_rps is not None
        else None
    )

    t_type = entry.type.lower()
    if t_type == "openai":
        if not entry.model:
            raise ConfigurationError(
                f"Target {target_id!r} (type=openai) requires 'model'.",
                component="cli.runtime",
            )
        return OpenAICompatibleAdapter(
            OpenAIAdapterConfig(
                target_id=target_id,
                target_type=entry.modality,
                model=entry.model,
                base_url=entry.base_url or "https://api.openai.com/v1",
                api_key_env_var=entry.api_key_env_var or "OPENAI_API_KEY",
                allow_unauthenticated=bool(entry.allow_unauthenticated),
                timeout_seconds=execution_cfg.timeout,
                retry_policy=retry_policy,
                rate_limit=rate_limit,
            )
        )

    if t_type == "anthropic":
        if not entry.model:
            raise ConfigurationError(
                f"Target {target_id!r} (type=anthropic) requires 'model'.",
                component="cli.runtime",
            )
        return AnthropicAdapter(
            AnthropicAdapterConfig(
                target_id=target_id,
                target_type=entry.modality,
                model=entry.model,
                base_url=entry.base_url or "https://api.anthropic.com",
                api_key_env_var=entry.api_key_env_var or "ANTHROPIC_API_KEY",
                allow_unauthenticated=bool(entry.allow_unauthenticated),
                timeout_seconds=execution_cfg.timeout,
                retry_policy=retry_policy,
                rate_limit=rate_limit,
            )
        )

    if t_type == "gemini":
        if not entry.model:
            raise ConfigurationError(
                f"Target {target_id!r} (type=gemini) requires 'model'.",
                component="cli.runtime",
            )
        return GeminiAdapter(
            GeminiAdapterConfig(
                target_id=target_id,
                target_type=entry.modality,
                model=entry.model,
                base_url=entry.base_url or "https://generativelanguage.googleapis.com",
                api_key_env_var=entry.api_key_env_var or "GEMINI_API_KEY",
                allow_unauthenticated=bool(entry.allow_unauthenticated),
                timeout_seconds=execution_cfg.timeout,
                retry_policy=retry_policy,
                rate_limit=rate_limit,
            )
        )

    if t_type == "ollama":
        if not entry.model:
            raise ConfigurationError(
                f"Target {target_id!r} (type=ollama) requires 'model'.",
                component="cli.runtime",
            )
        return OllamaAdapter(
            OllamaAdapterConfig(
                target_id=target_id,
                target_type=entry.modality,
                model=entry.model,
                base_url=entry.base_url or "http://localhost:11434",
                timeout_seconds=execution_cfg.timeout,
                retry_policy=retry_policy,
                rate_limit=rate_limit,
            )
        )

    if t_type == "http":
        endpoint = entry.endpoint_url or entry.base_url
        if not endpoint:
            raise ConfigurationError(
                f"Target {target_id!r} (type=http) requires 'endpoint_url'.",
                component="cli.runtime",
            )
        return GenericHTTPAdapter(
            GenericHTTPAdapterConfig(
                target_id=target_id,
                target_type=entry.modality,
                endpoint_url=endpoint,
                health_check_url=entry.health_check_url,
                api_key_env_var=entry.api_key_env_var,
                allow_unauthenticated=(
                    True if entry.allow_unauthenticated is None else entry.allow_unauthenticated
                ),
                prompt_field=entry.prompt_field or "prompt",
                response_text_path=entry.response_text_path or "response",
                model_name=entry.model or "custom-http-app",
                timeout_seconds=execution_cfg.timeout,
                retry_policy=retry_policy,
                rate_limit=rate_limit,
            )
        )

    raise ConfigurationError(
        f"Unsupported target type {entry.type!r} for target {target_id!r}.",
        component="cli.runtime",
        details={"target_id": target_id, "type": entry.type},
    )
