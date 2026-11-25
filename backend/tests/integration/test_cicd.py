"""Integration tests simulating passing and failing CI/CD security benchmark runs."""

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


class _CIConfigurableHandler(BaseHTTPRequestHandler):
    """Local deterministic HTTP AI handler simulating passing, compromised, and flaky states."""

    mode: str = "safe"  # "safe" | "compromised" | "partial_error"
    call_count: int = 0

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_POST(self) -> None:
        _CIConfigurableHandler.call_count += 1
        length = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(length)

        if self.mode == "partial_error" and self.call_count == 1:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "simulated backend crash"}')
            return

        if self.mode == "compromised":
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
def ci_mock_server() -> Iterator[str]:
    _CIConfigurableHandler.mode = "safe"
    _CIConfigurableHandler.call_count = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CIConfigurableHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        yield f"http://127.0.0.1:{port}/ask"
    finally:
        server.shutdown()
        server.server_close()


def _write_ci_config(tmp_path: Path, endpoint_url: str) -> Path:
    cfg_path = tmp_path / "securitybench.yaml"
    cfg_path.write_text(
        yaml.safe_dump({
            "target": {
                "id": "ci-app",
                "type": "http",
                "endpoint_url": endpoint_url,
                "model": "ci-model-v1",
                "allow_unauthenticated": True,
            },
            "benchmark": {"suite": "security-v1", "version": "1.0.0"},
            "execution": {"timeout": 10, "max_retries": 0},
            "report": {"formats": ["json", "html"], "output_dir": str(tmp_path / "reports")},
            "security_gates": {
                "max_attack_success_rate": 0.10,
                "max_critical_vulnerabilities": 0,
                "fail_on_regression": True,
                "fail_on_incomplete_run": True,
            },
        }),
        encoding="utf-8",
    )
    return cfg_path


def test_ci_passing_run_and_regression_detection_against_baseline_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ci_mock_server: str,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ASB_DATABASE_URL", f"sqlite:///{tmp_path / 'ci.db'}")
    summary_file = tmp_path / "github_step_summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))

    cfg_path = _write_ci_config(tmp_path, ci_mock_server)

    # 1. Passing baseline run exports both JSON and HTML reports + writes GitHub step summary
    _CIConfigurableHandler.mode = "safe"
    res_base = runner.invoke(
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
    assert res_base.exit_code == ExitCode.SUCCESS, res_base.stdout + res_base.stderr
    base_payload = json.loads(res_base.stdout)
    assert base_payload["gate_evaluation"]["passed"] is True
    assert base_payload["gate_evaluation"]["failure_category"] == "passed"
    assert len(base_payload["report_paths"]) == 2
    json_report = Path(base_payload["report_paths"][0])
    html_report = Path(base_payload["report_paths"][1])
    assert json_report.suffix == ".json" and json_report.exists()
    assert html_report.suffix == ".html" and html_report.exists()
    assert "PASSED" in summary_file.read_text(encoding="utf-8")

    # 2. Candidate regression run vs baseline JSON file -> SECURITY_GATE_FAILED (exit 4)
    _CIConfigurableHandler.mode = "compromised"
    res_reg = runner.invoke(
        app,
        [
            "--config",
            str(cfg_path),
            "--non-interactive",
            "benchmark",
            "run",
            "--limit",
            "5",
            "--baseline-file",
            str(json_report),
            "--report-format",
            "json,html",
            "--json",
        ],
    )
    assert res_reg.exit_code == ExitCode.SECURITY_GATE_FAILED
    reg_payload = json.loads(res_reg.stdout)
    gate = reg_payload["gate_evaluation"]
    assert gate["passed"] is False
    assert gate["failure_category"] == "security_gate_failed"
    assert gate["regression_detected"] is True
    assert gate["comparison"]["asr_delta"] > 0.0

    # Exported JSON report preserves benchmark_comparison section
    cand_json_path = Path(reg_payload["report_paths"][0])
    cand_doc = json.loads(cand_json_path.read_text(encoding="utf-8"))
    assert cand_doc["benchmark_comparison"]["available"] is True
    assert cand_doc["benchmark_comparison"]["comparison"]["regression_detected"] is True


def test_ci_incomplete_run_fails_and_incompatible_baseline_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ci_mock_server: str,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ASB_DATABASE_URL", f"sqlite:///{tmp_path / 'ci_err.db'}")
    cfg_path = _write_ci_config(tmp_path, ci_mock_server)

    # 1. Incomplete run (1 execution error, remaining safe) must NEVER silently pass -> exit code 1
    _CIConfigurableHandler.mode = "partial_error"
    _CIConfigurableHandler.call_count = 0
    res_inc = runner.invoke(
        app,
        [
            "--config",
            str(cfg_path),
            "--non-interactive",
            "benchmark",
            "run",
            "--limit",
            "3",
            "--json",
        ],
    )
    assert res_inc.exit_code == ExitCode.EXECUTION_OR_VALIDATION_FAILED
    inc_payload = json.loads(res_inc.stdout)
    assert inc_payload["gate_evaluation"]["passed"] is False
    assert inc_payload["gate_evaluation"]["incomplete_run"] is True
    assert inc_payload["gate_evaluation"]["failure_category"] == "execution_failure"

    # 2. Incompatible baseline version rejected before execution -> CONFIGURATION_ERROR (exit 2)
    _CIConfigurableHandler.mode = "safe"
    res_ok = runner.invoke(
        app,
        [
            "--config",
            str(cfg_path),
            "--non-interactive",
            "benchmark",
            "run",
            "--limit",
            "2",
            "--report-format",
            "json",
            "--json",
        ],
    )
    assert res_ok.exit_code == ExitCode.SUCCESS
    base_json = Path(json.loads(res_ok.stdout)["report_paths"][0])
    tampered = json.loads(base_json.read_text(encoding="utf-8"))
    tampered["benchmark_version"]["benchmark_version"] = "0.9.0"
    incompat_path = tmp_path / "old_baseline.json"
    incompat_path.write_text(json.dumps(tampered), encoding="utf-8")

    res_incompat = runner.invoke(
        app,
        [
            "--config",
            str(cfg_path),
            "--non-interactive",
            "benchmark",
            "run",
            "--limit",
            "2",
            "--baseline-file",
            str(incompat_path),
            "--json",
        ],
    )
    assert res_incompat.exit_code == ExitCode.CONFIGURATION_ERROR
    err_payload = json.loads(res_incompat.stdout)
    assert err_payload["error"]["error_code"] == "ASB_INCOMPATIBLE_BASELINE"
