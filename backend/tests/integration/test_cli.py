"""Integration tests for the standalone Arbiter SecurityBench Typer CLI."""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from arbiter_securitybench.cli import ExitCode, app

runner = CliRunner()


class _LocalMockAIHandler(BaseHTTPRequestHandler):
    """Minimal local HTTP AI handler for isolated end-to-end CLI tests."""

    compromise_mode = False

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "ok"}')

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(length)
        if self.compromise_mode:
            body = {"response": "INJECTION_CONFIRMED_001 CANARY_MD_COMMENT"}
        else:
            body = {"response": "I cannot comply with override requests."}
        encoded = json.dumps(body).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


@pytest.fixture
def local_ai_server() -> Iterator[str]:
    _LocalMockAIHandler.compromise_mode = False
    server = ThreadingHTTPServer(("127.0.0.1", 0), _LocalMockAIHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        yield f"http://127.0.0.1:{port}/ask"
    finally:
        server.shutdown()
        server.server_close()


def test_cli_init_version_and_target_management(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ASB_DATABASE_URL", f"sqlite:///{tmp_path / 'cli.db'}")

    res_ver = runner.invoke(app, ["version", "--json"])
    assert res_ver.exit_code == ExitCode.SUCCESS
    ver_data = json.loads(res_ver.stdout)
    assert "platform_version" in ver_data
    assert ver_data["schema_version"] == "1.0.0"

    res_init = runner.invoke(app, ["init", "--non-interactive"])
    assert res_init.exit_code == ExitCode.SUCCESS
    cfg_file = tmp_path / "securitybench.yaml"
    assert cfg_file.exists()
    raw_cfg = yaml.safe_load(cfg_file.read_text(encoding="utf-8"))
    assert raw_cfg["target"]["type"] == "openai"
    assert raw_cfg["target"]["api_key_env_var"] == "OPENAI_API_KEY"
    assert "api_key" not in raw_cfg["target"]

    # Re-init without --force fails with CONFIGURATION_ERROR
    res_init_dup = runner.invoke(app, ["init", "--non-interactive"])
    assert res_init_dup.exit_code == ExitCode.CONFIGURATION_ERROR

    # Add a local Ollama target non-interactively and list targets
    res_add = runner.invoke(
        app,
        [
            "target",
            "add",
            "--id",
            "local-ollama",
            "--type",
            "ollama",
            "--model",
            "llama3.2",
            "--non-interactive",
        ],
    )
    assert res_add.exit_code == ExitCode.SUCCESS

    res_list = runner.invoke(app, ["target", "list", "--json"])
    assert res_list.exit_code == ExitCode.SUCCESS
    targets_payload = json.loads(res_list.stdout)
    target_ids = {t["id"] for t in targets_payload["targets"]}
    assert "local-ollama" in target_ids

    # Reject inline secret api_key in securitybench.yaml
    bad_cfg = tmp_path / "bad.yaml"
    bad_cfg.write_text(
        yaml.safe_dump({"target": {"type": "openai", "model": "m", "api_key": "raw-secret"}}),
        encoding="utf-8",
    )
    res_bad = runner.invoke(app, ["--config", str(bad_cfg), "target", "list", "--json"])
    assert res_bad.exit_code == ExitCode.CONFIGURATION_ERROR


def test_cli_benchmark_list_inspect_and_dataset_validate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ASB_DATABASE_URL", f"sqlite:///{tmp_path / 'bench.db'}")

    res_list = runner.invoke(app, ["benchmark", "list", "--json"])
    assert res_list.exit_code == ExitCode.SUCCESS
    list_data = json.loads(res_list.stdout)
    assert list_data["total"] >= 1
    assert any(b["suite_id"] == "arbiter-security-benchmark" for b in list_data["benchmarks"])

    res_inspect = runner.invoke(
        app, ["benchmark", "inspect", "security-v1", "--limit", "3", "--json"]
    )
    assert res_inspect.exit_code == ExitCode.SUCCESS
    inspect_data = json.loads(res_inspect.stdout)
    assert inspect_data["test_count"] == 100
    assert len(inspect_data["sample_test_cases"]) == 3

    res_missing = runner.invoke(app, ["benchmark", "inspect", "unknown-suite", "--json"])
    assert res_missing.exit_code == ExitCode.NOT_FOUND

    res_val = runner.invoke(app, ["dataset", "validate", "--json"])
    assert res_val.exit_code == ExitCode.SUCCESS
    val_data = json.loads(res_val.stdout)
    assert val_data["valid"] is True
    assert val_data["total_cases"] == 100

    bad_ds = tmp_path / "invalid_dataset.json"
    bad_ds.write_text('{"schema_version": "0.0.0", "test_cases": []}', encoding="utf-8")
    res_bad_val = runner.invoke(app, ["dataset", "validate", str(bad_ds), "--json"])
    assert res_bad_val.exit_code == ExitCode.EXECUTION_OR_VALIDATION_FAILED


def test_cli_standalone_benchmark_run_report_generation_and_ci_gates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    local_ai_server: str,
) -> None:
    monkeypatch.chdir(tmp_path)
    db_url = f"sqlite:///{tmp_path / 'runs.db'}"
    monkeypatch.setenv("ASB_DATABASE_URL", db_url)

    cfg_path = tmp_path / "securitybench.yaml"
    cfg_path.write_text(
        yaml.safe_dump({
            "target": {
                "id": "local-fastapi-app",
                "type": "http",
                "endpoint_url": local_ai_server,
                "model": "local-app-v1",
                "allow_unauthenticated": True,
            },
            "benchmark": {"suite": "security-v1"},
            "execution": {"timeout": 10, "max_retries": 0},
            "report": {"format": "html", "output_dir": str(tmp_path / "reports")},
        }),
        encoding="utf-8",
    )

    # 1. Passing run with JSON output & auto-exported HTML report
    res_run = runner.invoke(
        app,
        [
            "--config",
            str(cfg_path),
            "--non-interactive",
            "benchmark",
            "run",
            "--limit",
            "5",
            "--export-report",
            "--json",
        ],
    )
    assert res_run.exit_code == ExitCode.SUCCESS, res_run.stdout + res_run.stderr
    run_payload = json.loads(res_run.stdout)
    run_id = run_payload["run"]["run_id"]
    assert run_payload["run"]["status"] == "completed"
    assert run_payload["score_report"]["overall_metrics"]["sample_counts"]["total_samples"] == 5
    assert Path(run_payload["report_path"]).exists()

    # 2. Standalone report generation in Markdown and JSON from persisted SQLite DB
    res_md = runner.invoke(
        app,
        [
            "--config",
            str(cfg_path),
            "report",
            "generate",
            "--run-id",
            run_id,
            "--format",
            "markdown",
            "--json",
        ],
    )
    assert res_md.exit_code == ExitCode.SUCCESS
    md_path = Path(json.loads(res_md.stdout)["report_path"])
    assert md_path.exists()
    assert run_id in md_path.read_text(encoding="utf-8")

    # 3. Compromised responses trigger CI security gate exit code (SECURITY_GATE_FAILED = 4)
    _LocalMockAIHandler.compromise_mode = True
    res_gate = runner.invoke(
        app,
        [
            "--config",
            str(cfg_path),
            "--non-interactive",
            "benchmark",
            "run",
            "--limit",
            "2",
            "--max-asr",
            "0.0",
            "--json",
        ],
    )
    assert res_gate.exit_code == ExitCode.SECURITY_GATE_FAILED
    gate_payload = json.loads(res_gate.stdout)
    assert gate_payload["security_gate_failed"] is True
    gate_run_id = gate_payload["run"]["run_id"]

    # Export PDF report with baseline comparison via CLI
    res_pdf = runner.invoke(
        app,
        [
            "--config",
            str(cfg_path),
            "report",
            "generate",
            "--run-id",
            gate_run_id,
            "--baseline-run-id",
            run_id,
            "--format",
            "pdf",
            "--json",
        ],
    )
    assert res_pdf.exit_code == ExitCode.SUCCESS
    pdf_path = Path(json.loads(res_pdf.stdout)["report_path"])
    assert pdf_path.exists()
    assert pdf_path.read_bytes().startswith(b"%PDF-")

    # 4. Missing API credential returns AUTHENTICATION_ERROR (exit code 3)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    auth_cfg = tmp_path / "auth_fail.yaml"
    auth_cfg.write_text(
        yaml.safe_dump({
            "target": {"id": "oai", "type": "openai", "model": "gpt-4o-mini"},
            "benchmark": {"suite": "security-v1"},
        }),
        encoding="utf-8",
    )
    res_auth = runner.invoke(
        app,
        [
            "--config",
            str(auth_cfg),
            "--non-interactive",
            "benchmark",
            "run",
            "--limit",
            "1",
            "--json",
        ],
    )
    assert res_auth.exit_code == ExitCode.AUTHENTICATION_ERROR
