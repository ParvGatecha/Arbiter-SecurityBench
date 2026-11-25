"""Terminal formatting, JSON emission, and Rich progress helpers for the CLI."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from arbiter_securitybench.contracts import BenchmarkRun
from arbiter_securitybench.scoring import BenchmarkComparisonReport, RunScoreReport

stdout_console = Console()
stderr_console = Console(stderr=True)


def emit_json(payload: Any) -> None:
    """Write deterministic JSON output directly to stdout."""
    sys.stdout.write(json.dumps(payload, indent=2, default=str, ensure_ascii=False) + "\n")


def emit_error(
    message: str,
    *,
    error_code: str = "ASB_CLI_ERROR",
    json_mode: bool = False,
    details: dict[str, Any] | None = None,
) -> None:
    """Render structured JSON or human-readable error message."""
    if json_mode:
        emit_json({
            "error": {
                "error_code": error_code,
                "message": message,
                "details": details or {},
            }
        })
    else:
        stderr_console.print(f"[bold red]Error ({error_code}):[/bold red] {message}")


@contextmanager
def progress_spinner(
    description: str,
    *,
    enabled: bool = True,
) -> Iterator[None]:
    """Show a Rich spinner during long-running operations when interactive output is enabled."""
    if not enabled:
        yield
        return
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=stderr_console,
        transient=True,
    ) as progress:
        progress.add_task(description=description, total=None)
        yield


def print_run_summary(run: BenchmarkRun, score_report: RunScoreReport) -> None:
    """Render an execution and statistical score summary panel and category table."""
    m = score_report.overall_metrics
    c = m.sample_counts

    asr_str = f"{m.attack_success_rate * 100:.1f}%" if m.attack_success_rate is not None else "N/A"
    abr_str = f"{m.attack_block_rate * 100:.1f}%" if m.attack_block_rate is not None else "N/A"
    score_str = f"{m.security_score:.1f} / 100" if m.security_score is not None else "N/A"
    cov_str = f"{m.evaluation_coverage * 100:.1f}%" if m.evaluation_coverage is not None else "N/A"

    summary_lines = [
        f"[bold]Run ID:[/bold] {run.run_id}",
        f"[bold]Benchmark:[/bold] {run.benchmark_id} ({run.benchmark_version})",
        f"[bold]Target:[/bold] {run.target_id} ({run.target_type.value})",
        f"[bold]Run Status:[/bold] {run.status.value}",
        (
            f"[bold]Samples:[/bold] total={c.total_samples}, "
            f"blocked={c.blocked_attacks}, compromised={c.successful_attacks}, "
            f"inconclusive={c.inconclusive_samples}, exec_errors={c.execution_error_samples}"
        ),
        f"[bold]Attack Success Rate:[/bold] {asr_str}   [bold]Block Rate:[/bold] {abr_str}",
        f"[bold]Evaluation Coverage:[/bold] {cov_str}   [bold]Security Score:[/bold] {score_str}",
    ]
    stdout_console.print(Panel("\n".join(summary_lines), title="Execution Summary", expand=False))

    if score_report.category_metrics:
        table = Table(title="Category Breakdown")
        table.add_column("Category", style="cyan")
        table.add_column("Samples", justify="right")
        table.add_column("ASR", justify="right")
        table.add_column("Block Rate", justify="right")
        table.add_column("Severity-Weighted ASR", justify="right")
        for cat, rep in score_report.category_metrics.items():
            cm = rep.metrics
            table.add_row(
                cat.value,
                str(cm.sample_counts.total_samples),
                f"{cm.attack_success_rate * 100:.1f}%" if cm.attack_success_rate is not None else "N/A",
                f"{cm.attack_block_rate * 100:.1f}%" if cm.attack_block_rate is not None else "N/A",
                f"{cm.severity_weighted_asr * 100:.1f}%" if cm.severity_weighted_asr is not None else "N/A",
            )
        stdout_console.print(table)

    for warning in score_report.warnings:
        stderr_console.print(f"[yellow]Warning:[/yellow] {warning}")


def write_github_step_summary(
    *,
    run: BenchmarkRun,
    score_report: RunScoreReport,
    passed: bool,
    failure_category: str,
    reasons: list[str],
    comparison: BenchmarkComparisonReport | None = None,
) -> None:
    """Append a concise Markdown CI summary to $GITHUB_STEP_SUMMARY when running in GitHub Actions."""
    summary_file = os.getenv("GITHUB_STEP_SUMMARY")
    if not summary_file:
        return

    m = score_report.overall_metrics
    c = m.sample_counts
    asr = f"{m.attack_success_rate * 100:.1f}%" if m.attack_success_rate is not None else "N/A"
    abr = f"{m.attack_block_rate * 100:.1f}%" if m.attack_block_rate is not None else "N/A"
    score = f"{m.security_score:.1f}/100" if m.security_score is not None else "N/A"
    badge = "PASSED" if passed else f"FAILED ({failure_category})"

    lines = [
        f"## Arbiter SecurityBench CI Result: {badge}",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Run ID | `{run.run_id}` |",
        f"| Benchmark | `{run.benchmark_id}` (`{run.benchmark_version}`) |",
        f"| Target | `{run.target_id}` |",
        f"| Run Status | `{run.status.value}` |",
        f"| Samples | total={c.total_samples}, compromised={c.successful_attacks}, blocked={c.blocked_attacks}, inconclusive={c.inconclusive_samples}, exec_errors={c.execution_error_samples} |",
        f"| Attack Success Rate (ASR) | {asr} |",
        f"| Attack Block Rate (ABR) | {abr} |",
        f"| Critical Compromises | {m.critical_compromises} |",
        f"| Security Score | {score} |",
    ]
    if comparison is not None:
        asr_delta = f"{comparison.asr_delta * 100:+.1f}%" if comparison.asr_delta is not None else "N/A"
        lines.append(
            f"| Baseline Comparison | `{comparison.baseline_run_id}` (ASR delta: {asr_delta}, regression={comparison.regression_detected}) |"
        )
    if reasons:
        lines.extend(["", "### Failure Reasons"])
        for reason in reasons:
            lines.append(f"- {reason}")

    Path(summary_file).parent.mkdir(parents=True, exist_ok=True)
    with Path(summary_file).open("a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
