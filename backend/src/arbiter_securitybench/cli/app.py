"""Typer command-line interface for Arbiter SecurityBench."""

from __future__ import annotations

import asyncio
import json
import os
import platform
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated

import typer
from rich.table import Table

from arbiter_securitybench.attacks import AttackExecutionConfig
from arbiter_securitybench.ci import (
    SecurityGatePolicy,
    evaluate_security_gates,
    load_baseline_from_report_file,
    validate_baseline_compatibility,
)
from arbiter_securitybench.cli.config import (
    DEFAULT_CONFIG_FILENAME,
    TargetEntryConfig,
    default_yaml_template,
    load_config,
    resolve_config_path,
    save_config_dict,
)
from arbiter_securitybench.cli.exit_codes import ExitCode, exit_code_for_exception
from arbiter_securitybench.cli.output import (
    emit_error,
    emit_json,
    print_run_summary,
    progress_spinner,
    stderr_console,
    stdout_console,
    write_github_step_summary,
)
from arbiter_securitybench.cli.runtime import (
    build_adapter_from_entry,
    build_cli_stores,
    resolve_suite_id,
)
from arbiter_securitybench.contracts import (
    METHODOLOGY_VERSIONS,
    PLATFORM_VERSION,
    SCHEMA_VERSION,
    ConfigurationError,
    SecurityBenchError,
    SecurityCategory,
    TargetModality,
)
from arbiter_securitybench.datasets import default_v1_dataset_path, validate_dataset_payload
from arbiter_securitybench.evaluation import (
    ModularEvaluationEngine,
    RuleBasedEvaluator,
    SemanticEvaluator,
    SensitiveInfoEvaluator,
)
from arbiter_securitybench.execution import AttackExecutionEngine
from arbiter_securitybench.reporting import ReportExporter
from arbiter_securitybench.scoring import BenchmarkComparator, SecurityScoringEngine


@dataclass(slots=True)
class CLIState:
    """Shared root CLI options propagated via Typer context."""

    config_path: Path | None
    json_output: bool
    non_interactive: bool


def _env_flag(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes"}


def _get_state(ctx: typer.Context) -> CLIState:
    obj = ctx.obj
    if isinstance(obj, CLIState):
        return obj
    return CLIState(
        config_path=None,
        json_output=_env_flag("ASB_JSON"),
        non_interactive=_env_flag("ASB_NON_INTERACTIVE"),
    )


def _fail_with_error(
    exc: BaseException,
    *,
    json_mode: bool,
    exit_code: ExitCode | None = None,
) -> typer.Exit:
    code = exit_code or exit_code_for_exception(exc)
    if isinstance(exc, SecurityBenchError):
        emit_error(
            exc.message,
            error_code=exc.error_code,
            json_mode=json_mode,
            details=exc.details,
        )
    else:
        emit_error(str(exc), json_mode=json_mode)
    return typer.Exit(code=int(code))


app = typer.Typer(
    name="arbiter",
    help="Arbiter SecurityBench CLI — standalone AI security benchmarking toolkit.",
    no_args_is_help=True,
    add_completion=False,
)
benchmark_app = typer.Typer(help="List, inspect, and execute security benchmarks.", no_args_is_help=True)
target_app = typer.Typer(help="Manage configured AI target systems.", no_args_is_help=True)
report_app = typer.Typer(help="Generate security benchmark reports.", no_args_is_help=True)
dataset_app = typer.Typer(help="Validate benchmark dataset files.", no_args_is_help=True)

app.add_typer(benchmark_app, name="benchmark")
app.add_typer(target_app, name="target")
app.add_typer(report_app, name="report")
app.add_typer(dataset_app, name="dataset")


@app.callback()
def root_callback(
    ctx: typer.Context,
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to securitybench.yaml configuration file."),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit machine-readable JSON output."),
    ] = False,
    non_interactive: Annotated[
        bool,
        typer.Option("--non-interactive", "-y", help="Disable interactive prompts and spinners."),
    ] = False,
) -> None:
    ctx.obj = CLIState(
        config_path=config,
        json_output=json_output or _env_flag("ASB_JSON"),
        non_interactive=non_interactive or _env_flag("ASB_NON_INTERACTIVE"),
    )


@app.command("init")
def init_command(
    ctx: typer.Context,
    path: Annotated[
        Path | None,
        typer.Option("--path", "-p", help="Target path for generated securitybench.yaml."),
    ] = None,
    target_type: Annotated[
        str,
        typer.Option("--target-type", help="Default target adapter type (openai, anthropic, gemini, ollama, http)."),
    ] = "openai",
    model: Annotated[
        str,
        typer.Option("--model", help="Default target model identifier."),
    ] = "example-model",
    suite: Annotated[
        str,
        typer.Option("--suite", help="Default benchmark suite ID or alias."),
    ] = "security-v1",
    report_format: Annotated[
        str,
        typer.Option("--report-format", help="Default report format (html, json, markdown)."),
    ] = "html",
    output_dir: Annotated[
        str,
        typer.Option("--output-dir", help="Default directory for generated reports."),
    ] = "reports",
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Overwrite existing configuration file."),
    ] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON output.")] = False,
    non_interactive: Annotated[
        bool,
        typer.Option("--non-interactive", "-y", help="Run non-interactively using flag defaults."),
    ] = False,
) -> None:
    """Initialize a secret-free securitybench.yaml configuration file."""
    state = _get_state(ctx)
    use_json = state.json_output or json_output
    target_path = path or resolve_config_path(state.config_path)

    if target_path.exists() and not force:
        raise _fail_with_error(
            ConfigurationError(
                f"Configuration file already exists at {target_path}. Pass --force to overwrite.",
                component="cli.init",
            ),
            json_mode=use_json,
            exit_code=ExitCode.CONFIGURATION_ERROR,
        )

    template = default_yaml_template(
        target_type=target_type.strip().lower(),
        model=model,
        suite=suite,
        report_format=report_format.strip().lower(),
        output_dir=output_dir,
    )
    save_config_dict(target_path, template)

    if use_json:
        emit_json({"created": str(target_path), "config": template})
    else:
        stdout_console.print(
            f"[green]Initialized[/green] configuration at [bold]{target_path}[/bold] "
            "(API keys are referenced via environment variables, never stored in YAML)."
        )


@app.command("version")
def version_command(
    ctx: typer.Context,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON output.")] = False,
) -> None:
    """Display platform, schema, and methodology versions."""
    state = _get_state(ctx)
    use_json = state.json_output or json_output
    info = {
        "platform_version": PLATFORM_VERSION,
        "schema_version": SCHEMA_VERSION,
        "methodology_versions": METHODOLOGY_VERSIONS,
        "python_version": platform.python_version(),
    }
    if use_json:
        emit_json(info)
    else:
        stdout_console.print(
            f"Arbiter SecurityBench [bold]{PLATFORM_VERSION}[/bold] "
            f"(schema {SCHEMA_VERSION}, Python {info['python_version']})"
        )


@benchmark_app.command("list")
def benchmark_list(
    ctx: typer.Context,
    category: Annotated[
        SecurityCategory | None,
        typer.Option("--category", help="Filter by SecurityCategory."),
    ] = None,
    target_type: Annotated[
        TargetModality | None,
        typer.Option("--target-type", help="Filter by TargetModality (llm, rag, agent)."),
    ] = None,
    suite_file: Annotated[
        Path | None,
        typer.Option("--suite-file", help="Optional custom dataset JSON file to include."),
    ] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON output.")] = False,
) -> None:
    """List available benchmark suites."""
    state = _get_state(ctx)
    use_json = state.json_output or json_output
    try:
        cfg = load_config(state.config_path)
        registry, _ = build_cli_stores(cfg, extra_suite_file=suite_file)
        suites = registry.list_benchmarks(category=category, target_type=target_type)
    except SecurityBenchError as exc:
        raise _fail_with_error(exc, json_mode=use_json) from exc

    if use_json:
        emit_json({
            "total": len(suites),
            "benchmarks": [
                {
                    "benchmark_id": s.benchmark_id,
                    "suite_id": s.suite_id,
                    "name": s.name,
                    "version": s.version,
                    "test_count": s.test_count,
                    "categories": [c.value for c in s.categories],
                    "supported_target_types": [t.value for t in s.supported_target_types],
                }
                for s in suites
            ],
        })
        return

    table = Table(title="Available Benchmarks")
    table.add_column("Suite ID", style="cyan")
    table.add_column("Name")
    table.add_column("Version")
    table.add_column("Tests", justify="right")
    table.add_column("Target Types")
    for s in suites:
        table.add_row(
            s.suite_id,
            s.name,
            s.version,
            str(s.test_count),
            ", ".join(t.value for t in s.supported_target_types),
        )
    stdout_console.print(table)


@benchmark_app.command("inspect")
def benchmark_inspect(
    ctx: typer.Context,
    benchmark_id: Annotated[
        str,
        typer.Argument(help="Benchmark suite ID or alias (e.g. security-v1)."),
    ],
    version: Annotated[
        str | None,
        typer.Option("--version", "-v", help="Exact benchmark version."),
    ] = None,
    limit: Annotated[
        int,
        typer.Option("--limit", min=1, max=100, help="Number of sample test cases to display."),
    ] = 10,
    suite_file: Annotated[
        Path | None,
        typer.Option("--suite-file", help="Optional custom dataset JSON file to load."),
    ] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON output.")] = False,
) -> None:
    """Inspect a benchmark suite, category breakdown, and test cases."""
    state = _get_state(ctx)
    use_json = state.json_output or json_output
    try:
        cfg = load_config(state.config_path)
        registry, _ = build_cli_stores(cfg, extra_suite_file=suite_file)
        resolved_id = resolve_suite_id(benchmark_id)
        suite = registry.get_benchmark(resolved_id, version=version)
        versions = registry.list_versions(suite.suite_id)
    except SecurityBenchError as exc:
        raise _fail_with_error(exc, json_mode=use_json) from exc

    diff_counts = Counter(tc.difficulty.value for tc in suite.test_cases)
    sev_counts = Counter(tc.severity.value for tc in suite.test_cases)

    if use_json:
        emit_json({
            "benchmark_id": suite.benchmark_id,
            "suite_id": suite.suite_id,
            "name": suite.name,
            "description": suite.description,
            "version": suite.version,
            "available_versions": versions,
            "test_count": suite.test_count,
            "difficulty_counts": dict(sorted(diff_counts.items())),
            "severity_counts": dict(sorted(sev_counts.items())),
            "sample_test_cases": [
                {
                    "test_id": tc.test_id,
                    "name": tc.name,
                    "category": tc.category.value,
                    "difficulty": tc.difficulty.value,
                    "severity": tc.severity.value,
                }
                for tc in suite.test_cases[:limit]
            ],
        })
        return

    stdout_console.print(f"[bold cyan]{suite.name}[/bold cyan] (`{suite.suite_id}` v{suite.version})")
    stdout_console.print(suite.description)
    stdout_console.print(
        f"Tests: [bold]{suite.test_count}[/bold] | "
        f"Versions: {', '.join(versions)} | "
        f"Difficulties: {dict(sorted(diff_counts.items()))}"
    )

    table = Table(title=f"Sample Test Cases (showing {min(limit, suite.test_count)} of {suite.test_count})")
    table.add_column("Test ID", style="cyan")
    table.add_column("Name")
    table.add_column("Category")
    table.add_column("Difficulty")
    table.add_column("Severity")
    for tc in suite.test_cases[:limit]:
        table.add_row(tc.test_id, tc.name, tc.category.value, tc.difficulty.value, tc.severity.value)
    stdout_console.print(table)


@benchmark_app.command("run")
def benchmark_run(
    ctx: typer.Context,
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to securitybench.yaml configuration file."),
    ] = None,
    suite: Annotated[
        str | None,
        typer.Option("--suite", "-s", help="Benchmark suite ID or alias (overrides securitybench.yaml)."),
    ] = None,
    version: Annotated[
        str | None,
        typer.Option("--version", "-v", help="Benchmark version to execute."),
    ] = None,
    target: Annotated[
        str | None,
        typer.Option("--target", "-t", help="Target ID defined in securitybench.yaml."),
    ] = None,
    suite_file: Annotated[
        Path | None,
        typer.Option("--suite-file", help="Path to a custom benchmark dataset JSON file."),
    ] = None,
    timeout: Annotated[
        float | None,
        typer.Option("--timeout", min=0.001, help="Per-turn/request timeout in seconds."),
    ] = None,
    max_retries: Annotated[
        int | None,
        typer.Option("--max-retries", min=0, max=10, help="Maximum retries on transient failures."),
    ] = None,
    limit: Annotated[
        int | None,
        typer.Option("--limit", min=1, help="Execute only the first N test cases from the suite."),
    ] = None,
    fail_on_critical: Annotated[
        bool,
        typer.Option("--fail-on-critical", help="Exit with code 4 if any critical attack succeeds."),
    ] = False,
    max_asr: Annotated[
        float | None,
        typer.Option("--max-asr", min=0.0, max=1.0, help="Exit with code 4 if overall ASR exceeds threshold."),
    ] = None,
    max_critical: Annotated[
        int | None,
        typer.Option("--max-critical", min=0, help="Maximum allowed critical-severity compromises."),
    ] = None,
    baseline_run_id: Annotated[
        str | None,
        typer.Option("--baseline-run-id", help="Persisted baseline run ID for regression comparison."),
    ] = None,
    baseline_file: Annotated[
        Path | None,
        typer.Option("--baseline-file", help="Path to a baseline JSON report artifact for comparison."),
    ] = None,
    fail_on_regression: Annotated[
        bool | None,
        typer.Option(
            "--fail-on-regression/--no-fail-on-regression",
            help="Fail CI gate when regression is detected vs baseline.",
        ),
    ] = None,
    allow_incomplete: Annotated[
        bool,
        typer.Option("--allow-incomplete", help="Allow incomplete runs without failing the CI gate."),
    ] = False,
    export_report: Annotated[
        bool,
        typer.Option("--export-report", help="Automatically export report(s) after execution."),
    ] = False,
    report_format: Annotated[
        str | None,
        typer.Option(
            "--report-format",
            help="Comma-separated report formats to export (e.g. 'json,html,pdf').",
        ),
    ] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON output.")] = False,
    non_interactive: Annotated[
        bool,
        typer.Option("--non-interactive", "-y", help="Suppress interactive UI spinners."),
    ] = False,
) -> None:
    """Execute a benchmark suite standalone against a configured target."""
    state = _get_state(ctx)
    use_json = state.json_output or json_output
    is_non_interactive = state.non_interactive or non_interactive

    try:
        cfg = load_config(config or state.config_path)
        if timeout is not None:
            cfg = cfg.model_copy(
                update={"execution": cfg.execution.model_copy(update={"timeout": timeout})}
            )
        if max_retries is not None:
            cfg = cfg.model_copy(
                update={"execution": cfg.execution.model_copy(update={"max_retries": max_retries})}
            )

        targets = cfg.resolved_targets()
        target_id = target or cfg.default_target_id()
        if not target_id or target_id not in targets:
            raise ConfigurationError(
                f"Target {target_id!r} is not configured. Run `arbiter init` or `arbiter target add`.",
                component="cli.benchmark.run",
                details={"configured_targets": sorted(targets)},
            )

        registry, run_repo = build_cli_stores(cfg, extra_suite_file=suite_file)
        resolved_suite_id = resolve_suite_id(suite or cfg.benchmark.suite)
        loaded_suite = registry.get_benchmark(
            resolved_suite_id,
            version=version or cfg.benchmark.version,
        )
        if limit is not None and limit < loaded_suite.test_count:
            loaded_suite = loaded_suite.model_copy(
                update={"test_cases": loaded_suite.test_cases[:limit]}
            )

        if baseline_run_id is not None and baseline_file is not None:
            raise ConfigurationError(
                "Specify either --baseline-run-id or --baseline-file, not both.",
                component="cli.benchmark.run",
            )

        scoring_engine = SecurityScoringEngine()
        baseline_report = None
        baseline_samples = None
        if baseline_run_id is not None:
            base_run = run_repo.get_run(baseline_run_id)
            if base_run is None:
                raise ConfigurationError(
                    f"Baseline run {baseline_run_id!r} was not found.",
                    component="cli.benchmark.run",
                )
            base_suite = registry.get_benchmark(base_run.suite_id, version=base_run.benchmark_version)
            base_results = run_repo.get_run_results(base_run.run_id)
            baseline_samples = scoring_engine.extract_scored_samples(base_suite, base_results)
            baseline_report = scoring_engine.score_samples(base_run, baseline_samples)
        elif baseline_file is not None:
            baseline_report, baseline_samples = load_baseline_from_report_file(baseline_file)

        if baseline_report is not None:
            validate_baseline_compatibility(
                baseline_benchmark_id=baseline_report.benchmark_id,
                baseline_benchmark_version=baseline_report.benchmark_version,
                candidate_benchmark_id=loaded_suite.benchmark_id,
                candidate_benchmark_version=loaded_suite.version,
            )

        adapter = build_adapter_from_entry(target_id, targets[target_id], cfg.execution)
        evaluator = ModularEvaluationEngine([
            RuleBasedEvaluator(),
            SensitiveInfoEvaluator(),
            SemanticEvaluator(),
        ])
        engine = AttackExecutionEngine(
            benchmark_registry=registry,
            run_repository=run_repo,
            evaluator=evaluator,
        )
        exec_cfg = AttackExecutionConfig(
            per_turn_timeout_seconds=cfg.execution.timeout,
            per_test_timeout_seconds=max(cfg.execution.timeout * 3.0, 60.0),
            seed=cfg.execution.seed,
            execute_variants=cfg.execution.execute_variants,
            max_variants_per_test=cfg.execution.max_variants_per_test,
            allowed_target_ids=frozenset({target_id}),
        )

        show_spinner = (not use_json) and (not is_non_interactive)
        with progress_spinner(
            f"Executing {loaded_suite.test_count} test case(s) against {target_id}...",
            enabled=show_spinner,
        ):
            run, results = asyncio.run(
                engine.execute_suite(loaded_suite, adapter, config=exec_cfg)
            )

        candidate_samples = scoring_engine.extract_scored_samples(loaded_suite, results)
        score_report = scoring_engine.score_samples(run, candidate_samples)

        effective_max_crit = max_critical
        if effective_max_crit is None:
            effective_max_crit = 0 if fail_on_critical else cfg.security_gates.max_critical_vulnerabilities
        effective_max_asr = (
            max_asr if max_asr is not None else cfg.security_gates.max_attack_success_rate
        )
        effective_fail_reg = (
            fail_on_regression
            if fail_on_regression is not None
            else cfg.security_gates.fail_on_regression
        )
        effective_fail_inc = (
            False if allow_incomplete else cfg.security_gates.fail_on_incomplete_run
        )

        policy = SecurityGatePolicy(
            max_attack_success_rate=effective_max_asr,
            max_critical_vulnerabilities=effective_max_crit,
            fail_on_regression=effective_fail_reg,
            fail_on_incomplete_run=effective_fail_inc,
            max_inconclusive_rate=cfg.security_gates.max_inconclusive_rate,
            min_security_score=cfg.security_gates.min_security_score,
            regression_asr_delta_threshold=cfg.security_gates.regression_asr_delta_threshold,
        )
        gate_eval = evaluate_security_gates(
            run=run,
            score_report=score_report,
            candidate_samples=candidate_samples,
            policy=policy,
            baseline_report=baseline_report,
            baseline_samples=baseline_samples,
        )

        formats_to_export: list[str] = []
        if report_format is not None:
            formats_to_export = [f.strip().lower() for f in report_format.split(",") if f.strip()]
        elif export_report:
            formats_to_export = cfg.report.resolved_formats()

        report_paths: list[Path] = []
        exporter = ReportExporter()
        for fmt in formats_to_export:
            exported = exporter.export(
                run=run,
                score_report=score_report,
                results=results,
                output_dir=cfg.report.output_dir,
                report_format=fmt,
                suite=loaded_suite,
                comparison=gate_eval.comparison,
            )
            report_paths.append(exported)
    except SecurityBenchError as exc:
        raise _fail_with_error(exc, json_mode=use_json) from exc

    write_github_step_summary(
        run=run,
        score_report=score_report,
        passed=gate_eval.passed,
        failure_category=gate_eval.failure_category,
        reasons=gate_eval.reasons,
        comparison=gate_eval.comparison,
    )

    first_report_path = str(report_paths[0]) if report_paths else None
    if use_json:
        emit_json({
            "run": run.model_dump(mode="json"),
            "score_report": score_report.model_dump(mode="json"),
            "report_path": first_report_path,
            "report_paths": [str(p) for p in report_paths],
            "security_gate_failed": gate_eval.failure_category == "security_gate_failed",
            "security_gate_reasons": gate_eval.reasons,
            "gate_evaluation": gate_eval.model_dump(mode="json"),
        })
    else:
        print_run_summary(run, score_report)
        for rp in report_paths:
            stdout_console.print(f"[green]Report exported:[/green] {rp}")
        if not gate_eval.passed:
            stderr_console.print(
                f"[bold red]CI Check Failed ({gate_eval.failure_category}):[/bold red] "
                + "; ".join(gate_eval.reasons)
            )

    if not gate_eval.passed:
        raise typer.Exit(code=gate_eval.exit_code)


@target_app.command("list")
def target_list(
    ctx: typer.Context,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON output.")] = False,
) -> None:
    """List AI targets configured in securitybench.yaml."""
    state = _get_state(ctx)
    use_json = state.json_output or json_output
    try:
        cfg = load_config(state.config_path)
    except SecurityBenchError as exc:
        raise _fail_with_error(exc, json_mode=use_json) from exc

    targets = cfg.resolved_targets()
    if use_json:
        emit_json({
            "total": len(targets),
            "targets": [entry.model_dump(mode="json") for entry in targets.values()],
        })
        return

    if not targets:
        stdout_console.print(
            f"No targets configured. Run `arbiter init` or `arbiter target add` to configure {DEFAULT_CONFIG_FILENAME}."
        )
        return

    table = Table(title="Configured Targets")
    table.add_column("Target ID", style="cyan")
    table.add_column("Type")
    table.add_column("Model / Endpoint")
    table.add_column("Credential Env Var")
    for tid, entry in targets.items():
        table.add_row(
            tid,
            entry.type,
            entry.model or entry.endpoint_url or entry.base_url or "-",
            entry.api_key_env_var or ("none (unauthenticated)" if entry.allow_unauthenticated else "-"),
        )
    stdout_console.print(table)


@target_app.command("add")
def target_add(
    ctx: typer.Context,
    target_id: Annotated[str | None, typer.Option("--id", help="Unique target ID.")] = None,
    target_type: Annotated[
        str | None,
        typer.Option("--type", help="Adapter type (openai, anthropic, gemini, ollama, http)."),
    ] = None,
    model: Annotated[str | None, typer.Option("--model", help="Model name.")] = None,
    base_url: Annotated[str | None, typer.Option("--base-url", help="Base API URL.")] = None,
    endpoint_url: Annotated[
        str | None, typer.Option("--endpoint-url", help="Full HTTP endpoint URL (for type=http).")
    ] = None,
    api_key_env_var: Annotated[
        str | None,
        typer.Option("--env-var", help="Environment variable holding API key (never raw secrets)."),
    ] = None,
    force: Annotated[bool, typer.Option("--force", "-f", help="Overwrite existing target ID.")] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON output.")] = False,
    non_interactive: Annotated[
        bool,
        typer.Option("--non-interactive", "-y", help="Fail instead of prompting for missing options."),
    ] = False,
) -> None:
    """Register a target configuration in securitybench.yaml (without storing API keys)."""
    state = _get_state(ctx)
    use_json = state.json_output or json_output
    is_non_interactive = state.non_interactive or non_interactive
    cfg_path = resolve_config_path(state.config_path)

    if not target_type:
        if is_non_interactive:
            raise _fail_with_error(
                ConfigurationError("--type is required in non-interactive mode.", component="cli.target.add"),
                json_mode=use_json,
            )
        target_type = typer.prompt("Target type (openai/anthropic/gemini/ollama/http)", default="openai")

    normalized_type = target_type.strip().lower()
    if not target_id:
        if is_non_interactive:
            raise _fail_with_error(
                ConfigurationError("--id is required in non-interactive mode.", component="cli.target.add"),
                json_mode=use_json,
            )
        target_id = typer.prompt("Target ID", default=f"{normalized_type}-target")

    if normalized_type != "http" and not model and not is_non_interactive:
        model = typer.prompt("Model name", default="example-model")

    try:
        cfg = load_config(cfg_path, require_exists=False)
        existing_targets = dict(cfg.targets)
        if target_id in existing_targets and not force:
            raise ConfigurationError(
                f"Target {target_id!r} already exists in {cfg_path}. Pass --force to overwrite.",
                component="cli.target.add",
            )

        entry = TargetEntryConfig(
            id=target_id,
            type=normalized_type,
            model=model,
            base_url=base_url,
            endpoint_url=endpoint_url,
            api_key_env_var=api_key_env_var,
        )
        # Validate entry by instantiating config checks (without connecting).
        build_adapter_from_entry(target_id, entry, cfg.execution)

        existing_targets[target_id] = entry
        updated = cfg.model_copy(update={"targets": existing_targets})
        save_config_dict(cfg_path, updated.model_dump(mode="json", exclude_none=True))
    except SecurityBenchError as exc:
        raise _fail_with_error(exc, json_mode=use_json) from exc

    if use_json:
        emit_json({"config_path": str(cfg_path), "target": entry.model_dump(mode="json", exclude_none=True)})
    else:
        stdout_console.print(f"[green]Added target[/green] `{target_id}` ({normalized_type}) to {cfg_path}")


@report_app.command("generate")
def report_generate(
    ctx: typer.Context,
    run_id: Annotated[
        str | None,
        typer.Option("--run-id", "-r", help="Run ID to export (defaults to most recent run)."),
    ] = None,
    baseline_run_id: Annotated[
        str | None,
        typer.Option("--baseline-run-id", "-b", help="Optional baseline run ID for comparison."),
    ] = None,
    report_format: Annotated[
        str | None,
        typer.Option("--format", "-f", help="Report format: html, json, pdf, or markdown."),
    ] = None,
    output_dir: Annotated[
        Path | None,
        typer.Option("--output-dir", "-o", help="Output directory for generated report."),
    ] = None,
    suite_file: Annotated[
        Path | None,
        typer.Option("--suite-file", help="Optional custom dataset JSON file used in the run."),
    ] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON output.")] = False,
) -> None:
    """Generate an HTML, PDF, JSON, or Markdown security report from a persisted run."""
    state = _get_state(ctx)
    use_json = state.json_output or json_output

    try:
        cfg = load_config(state.config_path)
        registry, run_repo = build_cli_stores(cfg, extra_suite_file=suite_file)

        if run_id is not None:
            run = run_repo.get_run(run_id)
            if run is None:
                raise ConfigurationError(
                    f"Run {run_id!r} was not found in storage.",
                    component="cli.report.generate",
                    details={"run_id": run_id},
                )
        else:
            recent = run_repo.list_runs(limit=1)
            if not recent:
                raise ConfigurationError(
                    "No benchmark runs found in storage. Run `arbiter benchmark run` first.",
                    component="cli.report.generate",
                )
            run = recent[0]

        suite = registry.get_benchmark(run.suite_id, version=run.benchmark_version)
        results = run_repo.get_run_results(run.run_id)
        score_report = SecurityScoringEngine().score_run(run, suite, results)

        comparison = None
        if baseline_run_id is not None:
            base_run = run_repo.get_run(baseline_run_id)
            if base_run is None:
                raise ConfigurationError(
                    f"Baseline run {baseline_run_id!r} was not found in storage.",
                    component="cli.report.generate",
                    details={"baseline_run_id": baseline_run_id},
                )
            base_suite = registry.get_benchmark(base_run.suite_id, version=base_run.benchmark_version)
            base_results = run_repo.get_run_results(base_run.run_id)
            comparison = BenchmarkComparator().compare_runs(
                baseline_run=base_run,
                baseline_suite=base_suite,
                baseline_results=base_results,
                candidate_run=run,
                candidate_suite=suite,
                candidate_results=results,
            )

        fmt = report_format or cfg.report.format
        out_dir = output_dir or Path(cfg.report.output_dir)
        out_path = ReportExporter().export(
            run=run,
            score_report=score_report,
            results=results,
            output_dir=out_dir,
            report_format=fmt,
            suite=suite,
            comparison=comparison,
        )
    except SecurityBenchError as exc:
        code = ExitCode.NOT_FOUND if "not found" in exc.message.lower() else None
        raise _fail_with_error(exc, json_mode=use_json, exit_code=code) from exc
    except ValueError as exc:
        raise _fail_with_error(
            ConfigurationError(str(exc), component="cli.report.generate"),
            json_mode=use_json,
        ) from exc

    if use_json:
        emit_json({
            "run_id": run.run_id,
            "format": fmt,
            "report_path": str(out_path),
            "score_report": score_report.model_dump(mode="json"),
        })
    else:
        stdout_console.print(f"[green]Generated {fmt.upper()} report:[/green] [bold]{out_path}[/bold]")


@dataset_app.command("validate")
def dataset_validate(
    ctx: typer.Context,
    path: Annotated[
        Path | None,
        typer.Argument(help="Path to dataset JSON file (defaults to Arbiter Security Benchmark v1.0)."),
    ] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON output.")] = False,
) -> None:
    """Validate a benchmark dataset JSON file for schema, uniqueness, and safety."""
    state = _get_state(ctx)
    use_json = state.json_output or json_output
    target_path = path or default_v1_dataset_path()

    if not target_path.exists():
        emit_error(
            f"Dataset file not found: {target_path}",
            error_code="ASB_NOT_FOUND",
            json_mode=use_json,
        )
        raise typer.Exit(code=int(ExitCode.NOT_FOUND))

    try:
        payload = json.loads(target_path.read_text(encoding="utf-8"))
    except ValueError as exc:
        emit_error(
            f"Dataset file is not valid JSON: {exc}",
            error_code="ASB_VALIDATION_ERROR",
            json_mode=use_json,
        )
        raise typer.Exit(code=int(ExitCode.CONFIGURATION_ERROR)) from exc

    report = validate_dataset_payload(payload, strict=False)
    if use_json:
        emit_json(report.model_dump(mode="json"))
    else:
        status_label = "[green]VALID[/green]" if report.valid else "[red]INVALID[/red]"
        stdout_console.print(
            f"Dataset `{target_path}`: {status_label} "
            f"(cases={report.total_cases}, errors={len(report.errors)}, warnings={len(report.warnings)})"
        )
        if report.category_counts:
            stdout_console.print(f"Categories: {report.category_counts}")
        for err in report.errors:
            stderr_console.print(f"  [red]- {err}[/red]")
        for warn in report.warnings:
            stderr_console.print(f"  [yellow]- {warn}[/yellow]")

    if not report.valid:
        raise typer.Exit(code=int(ExitCode.EXECUTION_OR_VALIDATION_FAILED))


def main() -> None:
    """Console script entrypoint."""
    app()
