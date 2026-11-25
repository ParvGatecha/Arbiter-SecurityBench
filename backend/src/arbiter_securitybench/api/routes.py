"""FastAPI v1 REST endpoints for benchmarks, targets, runs, scoring, comparison, reports, and leaderboard."""

from __future__ import annotations

import time
from typing import Annotated, Any, Literal
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Query, Response, status
from pydantic import ValidationError as PydanticValidationError

from arbiter_securitybench.adapters.models import (
    AnthropicAdapterConfig,
    GeminiAdapterConfig,
    GenericHTTPAdapterConfig,
    OllamaAdapterConfig,
    OpenAIAdapterConfig,
)
from arbiter_securitybench.api.dependencies import AppContainer, get_container
from arbiter_securitybench.api.schemas import (
    BenchmarkDetailResponse,
    BenchmarkListResponse,
    BenchmarkSummaryResponse,
    CompareRunsRequest,
    CreateBenchmarkRunRequest,
    CreateTargetRequest,
    ErrorResponse,
    LeaderboardEntryResponse,
    LeaderboardResponse,
    PaginatedTestCasesResponse,
    PlatformSettingsResponse,
    RunListResponse,
    RunResultsResponse,
    TargetHealthResponse,
    TargetListResponse,
    TargetSummaryResponse,
)
from arbiter_securitybench.contracts import (
    PLATFORM_VERSION,
    BenchmarkRun,
    BenchmarkSuite,
    BenchmarkTargetAdapter,
    ConfigurationError,
    DifficultyLevel,
    NotFoundError,
    RunStatus,
    SecurityCategory,
    SemanticVersion,
    SeverityLevel,
    TargetModality,
    TestExecutionResult,
    TestExecutionStatus,
    ValidationError,
)
from arbiter_securitybench.reporting import ReportExporter
from arbiter_securitybench.scoring import (
    BenchmarkComparator,
    BenchmarkComparisonReport,
    RunScoreReport,
    ScoringProfile,
    SecurityScoringEngine,
)

router = APIRouter(prefix="/api/v1", tags=["benchmarks", "runs", "targets", "scoring", "reports"])

ContainerDep = Annotated[AppContainer, Depends(get_container)]


def _sanitize_endpoint(endpoint: str | None) -> str | None:
    if not endpoint:
        return None
    parsed = urlparse(endpoint)
    if parsed.scheme and parsed.netloc:
        # Strip embedded userinfo/credentials if present.
        host = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port else ""
        return f"{parsed.scheme}://{host}{port}{parsed.path}".rstrip("/")
    return endpoint


def _describe_adapter(adapter: BenchmarkTargetAdapter) -> TargetSummaryResponse:
    get_info = getattr(adapter, "get_target_info", None)
    is_connected = bool(getattr(adapter, "is_connected", False))
    if callable(get_info):
        info = get_info()
        return TargetSummaryResponse(
            target_id=adapter.target_id,
            target_type=adapter.target_type,
            adapter_type=str(getattr(info, "adapter_type", "custom")),
            provider=str(getattr(info, "provider", "custom")),
            model_name=str(getattr(info, "model_name", adapter.target_id)),
            endpoint=_sanitize_endpoint(getattr(info, "endpoint", None)),
            capabilities=list(getattr(info, "capabilities", [])),
            is_connected=is_connected,
            metadata=dict(getattr(info, "metadata", {})),
        )
    return TargetSummaryResponse(
        target_id=adapter.target_id,
        target_type=adapter.target_type,
        adapter_type="custom",
        provider="custom",
        model_name=adapter.target_id,
        endpoint=None,
        capabilities=["execute"],
        is_connected=True,
        metadata={},
    )


def _resolve_profile(profile_name: str) -> ScoringProfile:
    if profile_name == "weighted":
        return ScoringProfile.uncapped_weighted()
    if profile_name == "default":
        return ScoringProfile.strict_default()
    raise ValidationError(
        f"Unsupported scoring profile {profile_name!r}. Expected 'default' or 'weighted'.",
        component="api.routes",
        details={"profile": profile_name},
    )


def _get_run_or_404(container: AppContainer, run_id: str) -> BenchmarkRun:
    run = container.run_repository.get_run(run_id)
    if run is None:
        raise NotFoundError(
            f"Benchmark run {run_id!r} was not found.",
            component="api.routes",
            details={"run_id": run_id},
        )
    return run


def _get_run_bundle(
    container: AppContainer,
    run_id: str,
) -> tuple[BenchmarkRun, BenchmarkSuite, list[TestExecutionResult]]:
    run = _get_run_or_404(container, run_id)
    suite = container.registry.get_benchmark(run.suite_id, version=run.benchmark_version)
    results = container.run_repository.get_run_results(run_id)
    return run, suite, results


def _extract_result_verdict(result: TestExecutionResult) -> str:
    if result.execution_status != TestExecutionStatus.COMPLETED:
        return "execution_error"
    if not result.evaluator_results:
        return "evaluation_failure"
    last_payload = result.evaluator_results[-1]
    if "consensus_status" in last_payload:
        return str(last_payload["consensus_status"]).strip().lower()
    if "evaluation_status" in last_payload:
        return str(last_payload["evaluation_status"]).strip().lower()
    return "evaluation_failure"


@router.get(
    "/platform/settings",
    response_model=PlatformSettingsResponse,
)
def get_platform_settings(container: ContainerDep) -> PlatformSettingsResponse:
    """Return non-secret runtime settings and capability metadata for the platform UI."""
    benchmarks = container.registry.list_benchmarks()
    return PlatformSettingsResponse(
        platform_version=PLATFORM_VERSION,
        storage_backend=container.storage_backend,
        builtin_datasets_loaded=container.builtin_datasets_loaded,
        default_timeout_seconds=container.default_timeout_seconds,
        available_adapter_types=container.adapter_registry.list_adapter_types(),
        registered_target_count=len(container.adapter_registry.list_target_ids()),
        registered_benchmark_count=len(benchmarks),
        scoring_profiles=["default", "weighted"],
        report_formats=["json", "html", "pdf", "markdown"],
        supported_run_statuses=list(RunStatus),
        supported_result_statuses=list(TestExecutionStatus),
    )


@router.get(
    "/targets",
    response_model=TargetListResponse,
)
def list_targets(container: ContainerDep) -> TargetListResponse:
    """List registered AI target adapters and available adapter factory types."""
    target_ids = container.adapter_registry.list_target_ids()
    items = [_describe_adapter(container.adapter_registry.get(tid)) for tid in target_ids]
    return TargetListResponse(
        items=items,
        available_adapter_types=container.adapter_registry.list_adapter_types(),
        total=len(items),
    )


@router.post(
    "/targets",
    response_model=TargetSummaryResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        409: {"model": ErrorResponse, "description": "Duplicate target"},
        422: {"model": ErrorResponse, "description": "Invalid config"},
    },
)
def register_target(
    payload: CreateTargetRequest,
    container: ContainerDep,
) -> TargetSummaryResponse:
    """Instantiate and register a target adapter using environment-referenced credentials only."""
    try:
        adapter_type = payload.adapter_type
        if adapter_type == "openai":
            if not payload.model:
                raise ValidationError(
                    "OpenAI-compatible target requires a non-empty 'model'.",
                    component="api.routes",
                )
            config: Any = OpenAIAdapterConfig(
                target_id=payload.target_id,
                target_type=payload.target_type,
                model=payload.model,
                base_url=payload.base_url or "https://api.openai.com/v1",
                api_key_env_var=payload.api_key_env_var if payload.api_key_env_var is not None else "OPENAI_API_KEY",
                allow_unauthenticated=bool(payload.allow_unauthenticated),
                timeout_seconds=payload.timeout_seconds,
                metadata=payload.metadata,
            )
        elif adapter_type == "anthropic":
            if not payload.model:
                raise ValidationError(
                    "Anthropic target requires a non-empty 'model'.",
                    component="api.routes",
                )
            config = AnthropicAdapterConfig(
                target_id=payload.target_id,
                target_type=payload.target_type,
                model=payload.model,
                base_url=payload.base_url or "https://api.anthropic.com",
                api_key_env_var=payload.api_key_env_var if payload.api_key_env_var is not None else "ANTHROPIC_API_KEY",
                allow_unauthenticated=bool(payload.allow_unauthenticated),
                timeout_seconds=payload.timeout_seconds,
                metadata=payload.metadata,
            )
        elif adapter_type == "gemini":
            if not payload.model:
                raise ValidationError(
                    "Gemini target requires a non-empty 'model'.",
                    component="api.routes",
                )
            config = GeminiAdapterConfig(
                target_id=payload.target_id,
                target_type=payload.target_type,
                model=payload.model,
                base_url=payload.base_url or "https://generativelanguage.googleapis.com",
                api_key_env_var=payload.api_key_env_var if payload.api_key_env_var is not None else "GEMINI_API_KEY",
                allow_unauthenticated=bool(payload.allow_unauthenticated),
                timeout_seconds=payload.timeout_seconds,
                metadata=payload.metadata,
            )
        elif adapter_type == "ollama":
            if not payload.model:
                raise ValidationError(
                    "Ollama target requires a non-empty 'model'.",
                    component="api.routes",
                )
            config = OllamaAdapterConfig(
                target_id=payload.target_id,
                target_type=payload.target_type,
                model=payload.model,
                base_url=payload.base_url or "http://localhost:11434",
                timeout_seconds=payload.timeout_seconds,
                metadata=payload.metadata,
            )
        else:
            endpoint_url = payload.endpoint_url or payload.base_url
            if not endpoint_url:
                raise ValidationError(
                    "Generic HTTP target requires 'endpoint_url'.",
                    component="api.routes",
                )
            config = GenericHTTPAdapterConfig(
                target_id=payload.target_id,
                target_type=payload.target_type,
                endpoint_url=endpoint_url,
                api_key_env_var=payload.api_key_env_var,
                allow_unauthenticated=(
                    True if payload.allow_unauthenticated is None else payload.allow_unauthenticated
                ),
                timeout_seconds=payload.timeout_seconds,
                prompt_field=payload.prompt_field,
                response_text_path=payload.response_text_path,
                model_name=payload.model or "custom-http-app",
                metadata=payload.metadata,
            )
    except PydanticValidationError as exc:
        raise ValidationError(
            f"Invalid target adapter configuration: {exc.errors()[0]['msg']}",
            component="api.routes",
            details={"errors": exc.errors()},
        ) from exc

    adapter = container.adapter_registry.create_adapter(
        payload.adapter_type,
        config,
        register_instance=True,
    )
    return _describe_adapter(adapter)


@router.post(
    "/targets/{target_id}/health",
    response_model=TargetHealthResponse,
)
async def check_target_health(
    target_id: str,
    container: ContainerDep,
) -> TargetHealthResponse:
    """Run an active connectivity/health check against a registered target adapter."""
    adapter = container.adapter_registry.get(target_id)
    health_fn = getattr(adapter, "health_check", None)
    start = time.perf_counter()
    if callable(health_fn):
        try:
            healthy = bool(await health_fn())
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            detail = "Target health check succeeded." if healthy else "Target reported unhealthy status."
            return TargetHealthResponse(
                target_id=target_id,
                healthy=healthy,
                latency_ms=round(elapsed_ms, 2),
                detail=detail,
            )
        except Exception as exc:  # noqa: BLE001 - report real connectivity failure cleanly
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            return TargetHealthResponse(
                target_id=target_id,
                healthy=False,
                latency_ms=round(elapsed_ms, 2),
                detail=str(exc),
            )
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return TargetHealthResponse(
        target_id=target_id,
        healthy=True,
        latency_ms=round(elapsed_ms, 2),
        detail="Custom Python target adapter is loaded in registry.",
    )


@router.get(
    "/benchmarks",
    response_model=BenchmarkListResponse,
)
def list_benchmarks(
    container: ContainerDep,
    category: Annotated[SecurityCategory | None, Query()] = None,
    target_type: Annotated[TargetModality | None, Query()] = None,
) -> BenchmarkListResponse:
    """List registered benchmark suites with optional category/modality filters."""
    suites = container.registry.list_benchmarks(category=category, target_type=target_type)
    items = [
        BenchmarkSummaryResponse(
            benchmark_id=s.benchmark_id,
            suite_id=s.suite_id,
            name=s.name,
            description=s.description,
            version=s.version,
            categories=list(s.categories),
            supported_target_types=list(s.supported_target_types),
            test_count=s.test_count,
            lifecycle_state=s.lifecycle_state,
        )
        for s in suites
    ]
    return BenchmarkListResponse(items=items, total=len(items))


@router.get(
    "/benchmarks/{benchmark_id}",
    response_model=BenchmarkDetailResponse,
)
def get_benchmark(
    benchmark_id: str,
    container: ContainerDep,
    version: Annotated[str | None, Query()] = None,
) -> BenchmarkDetailResponse:
    """Retrieve a specific benchmark suite (latest version by default)."""
    if version is not None:
        try:
            SemanticVersion.parse(version)
        except ValueError as exc:
            raise ValidationError(
                f"Invalid semantic version query parameter: {version!r}",
                component="api.routes",
                details={"version": version},
            ) from exc

    suite = container.registry.get_benchmark(benchmark_id, version=version)
    versions = container.registry.list_versions(suite.suite_id)
    return BenchmarkDetailResponse(
        benchmark_id=suite.benchmark_id,
        suite_id=suite.suite_id,
        name=suite.name,
        description=suite.description,
        version=suite.version,
        available_versions=versions,
        categories=list(suite.categories),
        supported_target_types=list(suite.supported_target_types),
        lifecycle_state=suite.lifecycle_state,
        test_count=suite.test_count,
        test_cases=list(suite.test_cases),
        metadata=dict(suite.metadata),
    )


@router.get(
    "/benchmarks/{benchmark_id}/test-cases",
    response_model=PaginatedTestCasesResponse,
)
def list_benchmark_test_cases(
    benchmark_id: str,
    container: ContainerDep,
    version: Annotated[str | None, Query()] = None,
    category: Annotated[SecurityCategory | None, Query()] = None,
    difficulty: Annotated[DifficultyLevel | None, Query()] = None,
    severity: Annotated[SeverityLevel | None, Query()] = None,
    search: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 25,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> PaginatedTestCasesResponse:
    """List paginated and filtered test cases for Dataset & Benchmark Explorer."""
    if version is not None:
        try:
            SemanticVersion.parse(version)
        except ValueError as exc:
            raise ValidationError(
                f"Invalid semantic version query parameter: {version!r}",
                component="api.routes",
                details={"version": version},
            ) from exc

    suite = container.registry.get_benchmark(benchmark_id, version=version)
    q = search.strip().lower() if search else None

    filtered = []
    for tc in suite.test_cases:
        if category is not None and tc.category != category:
            continue
        if difficulty is not None and tc.difficulty != difficulty:
            continue
        if severity is not None and tc.severity != severity:
            continue
        if q:
            haystack = " ".join(
                [tc.test_id, tc.name, tc.description, tc.input_prompt, " ".join(tc.tags)]
            ).lower()
            if q not in haystack:
                continue
        filtered.append(tc)

    page = filtered[offset : offset + limit]
    return PaginatedTestCasesResponse(
        benchmark_id=suite.benchmark_id,
        suite_id=suite.suite_id,
        version=suite.version,
        items=page,
        total=len(filtered),
        limit=limit,
        offset=offset,
        categories=sorted({tc.category for tc in suite.test_cases}, key=lambda c: c.value),
        difficulties=sorted({tc.difficulty for tc in suite.test_cases}, key=lambda d: d.value),
        severities=sorted({tc.severity for tc in suite.test_cases}, key=lambda s: s.value),
    )


@router.post(
    "/benchmarks/runs",
    response_model=BenchmarkRun,
    status_code=status.HTTP_201_CREATED,
)
async def create_benchmark_run(
    payload: CreateBenchmarkRunRequest,
    container: ContainerDep,
) -> BenchmarkRun:
    """Execute a registered benchmark suite sequentially against a registered target adapter."""
    suite = container.registry.get_benchmark(payload.benchmark_id, version=payload.version)
    adapter = container.adapter_registry.get(payload.target_id)
    run, _ = await container.execution_engine.execute_suite(
        suite,
        adapter,
        target_config=payload.target_config,
        metadata=payload.metadata,
    )
    return run


@router.get(
    "/runs",
    response_model=RunListResponse,
)
def list_runs(
    container: ContainerDep,
    benchmark_id: Annotated[str | None, Query()] = None,
    run_status: Annotated[RunStatus | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> RunListResponse:
    """List persisted benchmark execution runs with pagination metadata."""
    all_matching = container.run_repository.list_runs(
        benchmark_id=benchmark_id,
        status=run_status,
        limit=10_000,
        offset=0,
    )
    runs = all_matching[offset : offset + limit]
    return RunListResponse(
        items=runs,
        total=len(runs),
        total_count=len(all_matching),
        limit=limit,
        offset=offset,
    )


@router.get(
    "/runs/{run_id}",
    response_model=BenchmarkRun,
)
def get_run(
    run_id: str,
    container: ContainerDep,
) -> BenchmarkRun:
    """Retrieve metadata and execution status for a benchmark run."""
    return _get_run_or_404(container, run_id)


@router.get(
    "/runs/{run_id}/results",
    response_model=RunResultsResponse,
)
def get_run_results(
    run_id: str,
    container: ContainerDep,
    execution_status: Annotated[TestExecutionStatus | None, Query()] = None,
    verdict: Annotated[str | None, Query()] = None,
    search: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 500,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> RunResultsResponse:
    """Retrieve persisted test execution results for a benchmark run with optional filtering."""
    run = _get_run_or_404(container, run_id)
    results = container.run_repository.get_run_results(run_id)
    q = search.strip().lower() if search else None
    normalized_verdict = verdict.strip().lower() if verdict else None

    filtered: list[TestExecutionResult] = []
    for item in results:
        if execution_status is not None and item.execution_status != execution_status:
            continue
        if normalized_verdict is not None and _extract_result_verdict(item) != normalized_verdict:
            continue
        if q:
            haystack = " ".join([item.test_id, item.input, item.output or ""]).lower()
            if q not in haystack:
                continue
        filtered.append(item)

    page = filtered[offset : offset + limit]
    return RunResultsResponse(
        run_id=run.run_id,
        benchmark_id=run.benchmark_id,
        benchmark_version=run.benchmark_version,
        target_id=run.target_id,
        status=run.status,
        total_results=len(results),
        filtered_total=len(filtered),
        limit=limit,
        offset=offset,
        results=page,
    )


@router.get(
    "/runs/{run_id}/scores",
    response_model=RunScoreReport,
)
def get_run_scores(
    run_id: str,
    container: ContainerDep,
    profile: Annotated[Literal["default", "weighted"], Query()] = "default",
) -> RunScoreReport:
    """Compute statistically grounded security scores for a persisted run."""
    run, suite, results = _get_run_bundle(container, run_id)
    engine = SecurityScoringEngine(_resolve_profile(profile))
    return engine.score_run(run, suite, results)


@router.post(
    "/runs/compare",
    response_model=BenchmarkComparisonReport,
)
def compare_runs(
    payload: CompareRunsRequest,
    container: ContainerDep,
) -> BenchmarkComparisonReport:
    """Statistically compare a candidate run against a compatible baseline run."""
    base_run, base_suite, base_results = _get_run_bundle(container, payload.baseline_run_id)
    cand_run, cand_suite, cand_results = _get_run_bundle(container, payload.candidate_run_id)

    if base_run.benchmark_id != cand_run.benchmark_id or base_run.benchmark_version != cand_run.benchmark_version:
        raise ConfigurationError(
            "Cannot compare runs executed against different benchmark IDs or versions.",
            component="api.routes",
            details={
                "baseline_benchmark": f"{base_run.benchmark_id}@{base_run.benchmark_version}",
                "candidate_benchmark": f"{cand_run.benchmark_id}@{cand_run.benchmark_version}",
            },
        )

    comparator = BenchmarkComparator(_resolve_profile(payload.profile))
    return comparator.compare_runs(
        baseline_run=base_run,
        baseline_suite=base_suite,
        baseline_results=base_results,
        candidate_run=cand_run,
        candidate_suite=cand_suite,
        candidate_results=cand_results,
    )


@router.get("/runs/{run_id}/report")
def get_run_report(
    run_id: str,
    container: ContainerDep,
    report_format: Annotated[Literal["json", "html", "pdf", "markdown"], Query(alias="format")] = "json",
    baseline_run_id: Annotated[str | None, Query()] = None,
    profile: Annotated[Literal["default", "weighted"], Query()] = "default",
    download: Annotated[bool, Query()] = False,
) -> Response:
    """Generate and return or download a structured security report in JSON, HTML, PDF, or Markdown."""
    run, suite, results = _get_run_bundle(container, run_id)
    scoring_profile = _resolve_profile(profile)
    engine = SecurityScoringEngine(scoring_profile)
    score_report = engine.score_run(run, suite, results)

    comparison: BenchmarkComparisonReport | None = None
    if baseline_run_id:
        base_run, base_suite, base_results = _get_run_bundle(container, baseline_run_id)
        if (
            base_run.benchmark_id == run.benchmark_id
            and base_run.benchmark_version == run.benchmark_version
        ):
            comparator = BenchmarkComparator(scoring_profile)
            comparison = comparator.compare_runs(
                baseline_run=base_run,
                baseline_suite=base_suite,
                baseline_results=base_results,
                candidate_run=run,
                candidate_suite=suite,
                candidate_results=results,
            )

    exporter = ReportExporter()
    ext = "md" if report_format == "markdown" else report_format
    headers = (
        {"Content-Disposition": f'attachment; filename="report_{run.run_id}.{ext}"'}
        if download
        else {}
    )

    if report_format == "json":
        content = exporter.render_json(
            run=run,
            score_report=score_report,
            results=results,
            suite=suite,
            comparison=comparison,
        )
        return Response(content=content, media_type="application/json", headers=headers)
    if report_format == "html":
        content = exporter.render_html(
            run=run,
            score_report=score_report,
            results=results,
            suite=suite,
            comparison=comparison,
        )
        return Response(content=content, media_type="text/html; charset=utf-8", headers=headers)
    if report_format == "pdf":
        pdf_bytes = exporter.render_pdf(
            run=run,
            score_report=score_report,
            results=results,
            suite=suite,
            comparison=comparison,
        )
        return Response(content=pdf_bytes, media_type="application/pdf", headers=headers)

    doc = exporter.build_document(
        run=run,
        score_report=score_report,
        results=results,
        suite=suite,
        comparison=comparison,
    )
    md_text = exporter.render_markdown(doc)
    return Response(content=md_text, media_type="text/markdown; charset=utf-8", headers=headers)


@router.get(
    "/leaderboard",
    response_model=LeaderboardResponse,
)
def get_leaderboard(
    container: ContainerDep,
    benchmark_id: Annotated[str | None, Query()] = None,
    version: Annotated[str | None, Query()] = None,
    submission_type: Annotated[Literal["all", "official_verified", "community_submitted"], Query()] = "all",
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> LeaderboardResponse:
    """Compute real model rankings exclusively from eligible persisted benchmark runs."""
    all_runs = container.run_repository.list_runs(
        benchmark_id=benchmark_id,
        status=None,
        limit=10_000,
        offset=0,
    )
    scoring_engine = SecurityScoringEngine(ScoringProfile.strict_default())
    eligible_entries: list[LeaderboardEntryResponse] = []
    excluded_count = 0

    for run in all_runs:
        if version is not None and run.benchmark_version != version:
            continue
        if run.status != RunStatus.COMPLETED:
            excluded_count += 1
            continue
        try:
            suite = container.registry.get_benchmark(run.suite_id, version=run.benchmark_version)
        except NotFoundError:
            excluded_count += 1
            continue

        results = container.run_repository.get_run_results(run.run_id)
        if not results:
            excluded_count += 1
            continue

        score_report = scoring_engine.score_run(run, suite, results)
        overall = score_report.overall_metrics
        coverage = overall.evaluation_coverage or 0.0
        if (
            overall.sample_counts.total_samples <= 0
            or coverage < 1.0
            or overall.security_score is None
            or overall.attack_success_rate is None
            or overall.attack_block_rate is None
            or overall.severity_weighted_asr is None
            or overall.inconclusive_rate is None
        ):
            excluded_count += 1
            continue

        raw_sub_type = str(run.metadata.get("submission_type", "")).strip().lower()
        is_verified = raw_sub_type == "official_verified" or run.metadata.get("verified") is True
        resolved_sub_type: Literal["official_verified", "community_submitted"] = (
            "official_verified" if is_verified else "community_submitted"
        )
        if submission_type != "all" and resolved_sub_type != submission_type:
            continue

        target_meta = None
        if run.target_id in container.adapter_registry.list_target_ids():
            target_meta = _describe_adapter(container.adapter_registry.get(run.target_id))

        eligible_entries.append(
            LeaderboardEntryResponse(
                rank=1,
                run_id=run.run_id,
                target_id=run.target_id,
                target_type=run.target_type,
                provider=(
                    str(run.metadata.get("provider"))
                    if run.metadata.get("provider")
                    else (target_meta.provider if target_meta else None)
                ),
                model_name=(
                    str(run.metadata.get("model_name"))
                    if run.metadata.get("model_name")
                    else (target_meta.model_name if target_meta else run.target_id)
                ),
                benchmark_id=run.benchmark_id,
                benchmark_version=run.benchmark_version,
                submission_type=resolved_sub_type,
                security_score=overall.security_score,
                attack_success_rate=overall.attack_success_rate,
                attack_block_rate=overall.attack_block_rate,
                severity_weighted_asr=overall.severity_weighted_asr,
                inconclusive_rate=overall.inconclusive_rate,
                evaluation_coverage=coverage,
                total_samples=overall.sample_counts.total_samples,
                critical_compromises=overall.critical_compromises,
                high_compromises=overall.high_compromises,
                score_capped_by_critical_policy=overall.score_capped_by_critical_policy,
                completed_at=run.completed_at,
                category_asr={
                    cat.value: cat_report.metrics.attack_success_rate
                    for cat, cat_report in score_report.category_metrics.items()
                },
            )
        )

    eligible_entries.sort(
        key=lambda e: (
            -e.security_score,
            e.attack_success_rate,
            -(e.completed_at.timestamp() if e.completed_at else 0.0),
        )
    )
    ranked = [
        entry.model_copy(update={"rank": idx})
        for idx, entry in enumerate(eligible_entries, start=1)
    ]
    page = ranked[offset : offset + limit]
    return LeaderboardResponse(
        items=page,
        total=len(ranked),
        eligible_runs_count=len(ranked),
        excluded_runs_count=excluded_count,
        eligibility_criteria=(
            "Requires RunStatus=completed, registered suite provenance, total_samples > 0, "
            "and 100% evaluation coverage (zero execution errors or evaluation failures)."
        ),
    )
