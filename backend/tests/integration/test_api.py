"""Integration tests for FastAPI v1 benchmark and run endpoints."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from arbiter_securitybench.api import build_default_container, create_app
from arbiter_securitybench.contracts import SecurityCategory, TargetModality
from conftest import StubTargetAdapter, build_suite, build_test_case


def _create_test_client(tmp_path: Path) -> TestClient:
    db_url = f"sqlite:///{tmp_path / 'api_test.db'}"
    container = build_default_container(database_url=db_url)
    suite_v1 = build_suite(
        suite_id="api-bench",
        version="1.0.0",
        test_cases=[
            build_test_case(test_id="tc-api-1", category=SecurityCategory.PROMPT_INJECTION),
            build_test_case(test_id="tc-api-2", category=SecurityCategory.JAILBREAK_RESISTANCE),
        ],
    )
    suite_v2 = build_suite(
        suite_id="api-bench",
        version="2.0.0",
        test_cases=[
            build_test_case(
                test_id="tc-api-3",
                category=SecurityCategory.RAG_SECURITY,
                benchmark_version="2.0.0",
            )
        ],
        supported_target_types=[TargetModality.RAG],
    )
    container.registry.register_suite(suite_v1)
    container.registry.register_suite(suite_v2)
    container.adapter_registry.register(
        StubTargetAdapter(target_id="llm-stub", target_type=TargetModality.LLM)
    )
    container.adapter_registry.register(
        StubTargetAdapter(
            target_id="llm-partial-stub",
            target_type=TargetModality.LLM,
            fail_on_test_ids={"tc-api-2"},
        )
    )
    app = create_app(container=container)
    return TestClient(app)


def test_list_and_get_benchmarks(tmp_path: Path) -> None:
    client = _create_test_client(tmp_path)

    resp = client.get("/api/v1/benchmarks")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 2

    filtered = client.get("/api/v1/benchmarks", params={"category": "rag_security"})
    assert filtered.status_code == 200
    assert filtered.json()["total"] == 1
    assert filtered.json()["items"][0]["version"] == "2.0.0"

    detail_latest = client.get("/api/v1/benchmarks/api-bench")
    assert detail_latest.status_code == 200
    assert detail_latest.json()["version"] == "2.0.0"
    assert detail_latest.json()["available_versions"] == ["1.0.0", "2.0.0"]

    detail_v1 = client.get("/api/v1/benchmarks/api-bench", params={"version": "1.0.0"})
    assert detail_v1.status_code == 200
    assert detail_v1.json()["test_count"] == 2

    missing = client.get("/api/v1/benchmarks/unknown")
    assert missing.status_code == 404
    assert missing.json()["error_code"] == "ASB_NOT_FOUND"

    bad_semver = client.get("/api/v1/benchmarks/api-bench", params={"version": "invalid"})
    assert bad_semver.status_code == 422


def test_create_and_query_runs_and_results(tmp_path: Path) -> None:
    client = _create_test_client(tmp_path)

    create_resp = client.post(
        "/api/v1/benchmarks/runs",
        json={
            "benchmark_id": "api-bench",
            "version": "1.0.0",
            "target_id": "llm-partial-stub",
            "target_config": {"temperature": 0},
        },
    )
    assert create_resp.status_code == 201
    run = create_resp.json()
    run_id = run["run_id"]
    assert run["status"] == "partially_completed"
    assert run["completed_tests"] == 1
    assert run["failed_tests"] == 1

    runs_resp = client.get("/api/v1/runs", params={"benchmark_id": "api-bench"})
    assert runs_resp.status_code == 200
    assert runs_resp.json()["total"] == 1

    run_detail = client.get(f"/api/v1/runs/{run_id}")
    assert run_detail.status_code == 200
    assert run_detail.json()["run_id"] == run_id

    results_resp = client.get(f"/api/v1/runs/{run_id}/results")
    assert results_resp.status_code == 200
    results_body = results_resp.json()
    assert results_body["total_results"] == 2
    assert results_body["results"][0]["execution_status"] == "completed"
    assert results_body["results"][1]["execution_status"] == "failed"


def test_api_run_validation_and_error_responses(tmp_path: Path) -> None:
    client = _create_test_client(tmp_path)

    # Unknown benchmark -> 404
    r1 = client.post(
        "/api/v1/benchmarks/runs",
        json={"benchmark_id": "missing", "target_id": "llm-stub"},
    )
    assert r1.status_code == 404

    # Unknown target adapter -> 404
    r2 = client.post(
        "/api/v1/benchmarks/runs",
        json={"benchmark_id": "api-bench", "version": "1.0.0", "target_id": "no-such-target"},
    )
    assert r2.status_code == 404

    # Incompatible modality (RAG-only suite v2.0.0 vs LLM adapter) -> 422
    r3 = client.post(
        "/api/v1/benchmarks/runs",
        json={"benchmark_id": "api-bench", "version": "2.0.0", "target_id": "llm-stub"},
    )
    assert r3.status_code == 422
    assert r3.json()["error_code"] == "ASB_CONFIGURATION_ERROR"

    # Extra unknown field in request -> 422
    r4 = client.post(
        "/api/v1/benchmarks/runs",
        json={"benchmark_id": "api-bench", "target_id": "llm-stub", "extra": 123},
    )
    assert r4.status_code == 422

    # Unknown run -> 404
    assert client.get("/api/v1/runs/missing-run").status_code == 404
    assert client.get("/api/v1/runs/missing-run/results").status_code == 404


def test_extended_frontend_api_endpoints(tmp_path: Path) -> None:
    client = _create_test_client(tmp_path)

    # Targets & platform settings
    settings = client.get("/api/v1/platform/settings")
    assert settings.status_code == 200
    assert settings.json()["registered_target_count"] == 2
    assert "openai" in settings.json()["available_adapter_types"]

    targets = client.get("/api/v1/targets")
    assert targets.status_code == 200
    assert targets.json()["total"] == 2

    reg_target = client.post(
        "/api/v1/targets",
        json={
            "adapter_type": "ollama",
            "target_id": "local-ollama-llama",
            "model": "llama3.2",
            "base_url": "http://localhost:11434",
        },
    )
    assert reg_target.status_code == 201
    assert reg_target.json()["provider"] == "ollama"

    # Paginated test cases
    tc_page = client.get(
        "/api/v1/benchmarks/api-bench/test-cases",
        params={"version": "1.0.0", "limit": 1, "offset": 0},
    )
    assert tc_page.status_code == 200
    assert tc_page.json()["total"] == 2
    assert len(tc_page.json()["items"]) == 1

    # Execute two completed runs so scores, comparison, reports, and leaderboard are real
    run_a = client.post(
        "/api/v1/benchmarks/runs",
        json={
            "benchmark_id": "api-bench",
            "version": "1.0.0",
            "target_id": "llm-stub",
            "metadata": {"submission_type": "official_verified"},
        },
    )
    assert run_a.status_code == 201
    run_a_id = run_a.json()["run_id"]
    assert run_a.json()["status"] == "completed"

    run_b = client.post(
        "/api/v1/benchmarks/runs",
        json={
            "benchmark_id": "api-bench",
            "version": "1.0.0",
            "target_id": "llm-partial-stub",
        },
    )
    assert run_b.status_code == 201
    run_b_id = run_b.json()["run_id"]
    assert run_b.json()["status"] == "partially_completed"

    scores = client.get(f"/api/v1/runs/{run_a_id}/scores")
    assert scores.status_code == 200
    assert scores.json()["overall_metrics"]["sample_counts"]["total_samples"] == 2
    assert scores.json()["overall_metrics"]["evaluation_coverage"] == 1.0

    # Comparison
    comp = client.post(
        "/api/v1/runs/compare",
        json={"baseline_run_id": run_a_id, "candidate_run_id": run_b_id},
    )
    assert comp.status_code == 200
    assert comp.json()["baseline_run_id"] == run_a_id
    assert comp.json()["candidate_run_id"] == run_b_id

    # Reports (JSON, HTML, PDF)
    rep_json = client.get(f"/api/v1/runs/{run_a_id}/report", params={"format": "json"})
    assert rep_json.status_code == 200
    assert rep_json.json()["executive_summary"]["run_id"] == run_a_id

    rep_html = client.get(
        f"/api/v1/runs/{run_a_id}/report",
        params={"format": "html", "download": True},
    )
    assert rep_html.status_code == 200
    assert "attachment" in rep_html.headers.get("content-disposition", "")

    rep_pdf = client.get(
        f"/api/v1/runs/{run_a_id}/report",
        params={"format": "pdf", "download": True},
    )
    assert rep_pdf.status_code == 200
    assert rep_pdf.content.startswith(b"%PDF")

    # Leaderboard: only run_a is COMPLETED + 100% covered; run_b is partially_completed -> excluded
    lb = client.get("/api/v1/leaderboard")
    assert lb.status_code == 200
    lb_body = lb.json()
    assert lb_body["total"] == 1
    assert lb_body["excluded_runs_count"] == 1
    assert lb_body["items"][0]["run_id"] == run_a_id
    assert lb_body["items"][0]["submission_type"] == "official_verified"

