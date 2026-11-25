"""Mocked unit tests for GenericHTTPAdapter, CustomPythonAdapter, config validation, and rate limits."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
import pytest
from pydantic import ValidationError as PydanticValidationError

from arbiter_securitybench.adapters import (
    AdapterAuthenticationError,
    AdapterRequest,
    AdapterResponse,
    AdapterResponseError,
    AsyncTokenBucketRateLimiter,
    CustomPythonAdapter,
    CustomPythonAdapterConfig,
    GenericHTTPAdapter,
    GenericHTTPAdapterConfig,
    ModelInformation,
    RateLimitConfig,
    RetryPolicyConfig,
)
from arbiter_securitybench.contracts import ConfigurationError, ExecutionTimeoutError, RunStatus
from arbiter_securitybench.execution import BenchmarkExecutionEngine
from conftest import build_suite


@pytest.mark.asyncio
async def test_generic_http_adapter_dot_path_mapping_and_env_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CUSTOM_APP_TOKEN", "app-token-123")
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/healthz":
            return httpx.Response(200, json={"ok": True})
        captured["headers"] = dict(request.headers)
        captured["body"] = json.loads(request.content.decode("utf-8"))
        return httpx.Response(
            200,
            json={
                "data": {"answer": "Custom RAG response", "model": "rag-v2"},
                "metrics": {"in": 15, "out": 8, "total": 23},
            },
        )

    config = GenericHTTPAdapterConfig(
        target_id="custom-rag",
        endpoint_url="https://app.internal.local/v1/ask",
        health_check_url="https://app.internal.local/healthz",
        allow_unauthenticated=False,
        api_key_env_var="CUSTOM_APP_TOKEN",
        auth_header_name="X-Service-Token",
        auth_scheme=None,
        prompt_field="question",
        response_text_path="data.answer",
        model_name_path="data.model",
        input_tokens_path="metrics.in",
        output_tokens_path="metrics.out",
        total_tokens_path="metrics.total",
    )

    async with GenericHTTPAdapter(config, transport=httpx.MockTransport(handler)) as adapter:
        assert await adapter.health_check() is True
        resp = await adapter.send_prompt(AdapterRequest(prompt="What is policy X?"))

    assert captured["headers"]["x-service-token"] == "app-token-123"
    assert captured["body"]["question"] == "What is policy X?"
    assert resp.response_text == "Custom RAG response"
    assert resp.model_information.model_name == "rag-v2"
    assert resp.token_usage is not None
    assert resp.token_usage.total_tokens == 23


@pytest.mark.asyncio
async def test_generic_http_adapter_custom_mappers_and_invalid_path() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        assert body == {"query_text": "ping", "tenant": "t-1"}
        return httpx.Response(200, json={"nested": [{"reply": "pong"}]})

    config = GenericHTTPAdapterConfig(
        target_id="custom-mapper-http",
        endpoint_url="http://localhost:8000/chat",
    )
    adapter = GenericHTTPAdapter(
        config,
        request_mapper=lambda req: {"query_text": req.prompt, "tenant": req.metadata["tenant"]},
        response_mapper=lambda payload, _resp: payload["nested"][0]["reply"],
        transport=httpx.MockTransport(handler),
    )
    async with adapter:
        resp = await adapter.send_prompt(AdapterRequest(prompt="ping", metadata={"tenant": "t-1"}))
    assert resp.response_text == "pong"

    # Invalid dot path raises AdapterResponseError
    def missing_path_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"other": "value"})

    bad_adapter = GenericHTTPAdapter(
        GenericHTTPAdapterConfig(
            target_id="bad-path",
            endpoint_url="http://localhost:8000/chat",
            response_text_path="data.missing",
        ),
        transport=httpx.MockTransport(missing_path_handler),
    )
    async with bad_adapter:
        with pytest.raises(AdapterResponseError):
            await bad_adapter.send_prompt(AdapterRequest(prompt="hello"))


@pytest.mark.asyncio
async def test_generic_http_auth_failure_when_unauthenticated_disallowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MISSING_HTTP_KEY", raising=False)
    cfg = GenericHTTPAdapterConfig(
        target_id="strict-http",
        endpoint_url="https://api.example.com/invoke",
        allow_unauthenticated=False,
        api_key_env_var="MISSING_HTTP_KEY",
    )
    adapter = GenericHTTPAdapter(cfg)
    with pytest.raises(AdapterAuthenticationError):
        await adapter.connect()


@pytest.mark.asyncio
async def test_custom_python_adapter_sync_async_timeout_and_engine_bridge() -> None:
    lifecycle_events: list[str] = []

    def sync_app(req: AdapterRequest) -> str:
        return f"sync:{req.prompt}"

    async def async_app(req: AdapterRequest) -> AdapterResponse:
        return AdapterResponse(
            response_text=f"async:{req.prompt}",
            raw_response={"ok": True},
            latency=0.001,
            model_information=ModelInformation(provider="python", model_name="my-agent"),
        )

    sync_adapter = CustomPythonAdapter(
        CustomPythonAdapterConfig(target_id="py-sync"),
        sync_app,
        connect_fn=lambda: lifecycle_events.append("connect"),
        close_fn=lambda: lifecycle_events.append("close"),
        health_check_fn=lambda: True,
    )
    async with sync_adapter:
        assert await sync_adapter.health_check() is True
        r1 = await sync_adapter.send_prompt(AdapterRequest(prompt="hi"))
    assert r1.response_text == "sync:hi"
    assert lifecycle_events == ["connect", "close"]

    # Bridge directly into BenchmarkExecutionEngine
    async_adapter = CustomPythonAdapter(
        CustomPythonAdapterConfig(target_id="py-async"),
        async_app,
    )
    engine = BenchmarkExecutionEngine()
    suite = build_suite(suite_id="bridge-suite")
    run, results = await engine.execute_suite(suite, async_adapter)
    assert run.status == RunStatus.COMPLETED
    assert len(results) == 2
    assert results[0].output == "async:<test-input:tc-001>"

    # Timeout in Python adapter
    async def slow_app(_req: AdapterRequest) -> str:
        await asyncio.sleep(0.2)
        return "too late"

    slow_adapter = CustomPythonAdapter(
        CustomPythonAdapterConfig(
            target_id="py-slow",
            timeout_seconds=0.02,
            retry_policy=RetryPolicyConfig(max_retries=0),
        ),
        slow_app,
    )
    async with slow_adapter:
        with pytest.raises(ExecutionTimeoutError):
            await slow_adapter.send_prompt(AdapterRequest(prompt="slow"))

    # Invalid handler return type -> AdapterResponseError
    bad_adapter = CustomPythonAdapter(
        CustomPythonAdapterConfig(target_id="py-bad-ret"),
        lambda _req: 12345,  # type: ignore[arg-type, return-value]
    )
    async with bad_adapter:
        with pytest.raises(AdapterResponseError):
            await bad_adapter.send_prompt(AdapterRequest(prompt="bad"))


@pytest.mark.asyncio
async def test_rate_limiter_enforces_token_bucket_spacing() -> None:
    now = 0.0
    sleeps: list[float] = []

    def fake_clock() -> float:
        return now

    async def fake_sleep(seconds: float) -> None:
        nonlocal now
        sleeps.append(seconds)
        now += seconds

    limiter = AsyncTokenBucketRateLimiter(
        RateLimitConfig(requests_per_second=10.0, burst_capacity=1),
        clock=fake_clock,
        sleeper=fake_sleep,
    )
    await limiter.acquire()
    await limiter.acquire()
    await limiter.acquire()
    assert len(sleeps) == 2
    assert all(pytest.approx(0.1) == s for s in sleeps)


def test_malformed_configurations_fail_validation() -> None:
    with pytest.raises(PydanticValidationError):
        GenericHTTPAdapterConfig(
            target_id="bad-url",
            endpoint_url="not-a-valid-url",
        )

    with pytest.raises(PydanticValidationError):
        GenericHTTPAdapterConfig(
            target_id="bad-method",
            endpoint_url="http://localhost:8000/chat",
            method="DELETE",
        )

    with pytest.raises(PydanticValidationError):
        AdapterRequest(prompt="")

    with pytest.raises(ConfigurationError):
        CustomPythonAdapter(
            CustomPythonAdapterConfig(target_id="not-callable"),
            "not_callable",  # type: ignore[arg-type]
        )
