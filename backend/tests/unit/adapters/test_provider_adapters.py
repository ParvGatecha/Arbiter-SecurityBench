"""Mocked unit tests for OpenAI, Anthropic, Gemini, and Ollama adapters."""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx
import pytest

from arbiter_securitybench.adapters import (
    AdapterAuthenticationError,
    AdapterConnectionError,
    AdapterRateLimitError,
    AdapterRequest,
    AdapterResponseError,
    AnthropicAdapter,
    AnthropicAdapterConfig,
    ConversationMessage,
    GeminiAdapter,
    GeminiAdapterConfig,
    OllamaAdapter,
    OllamaAdapterConfig,
    OpenAIAdapterConfig,
    OpenAICompatibleAdapter,
    RetryPolicyConfig,
)
from arbiter_securitybench.contracts import ConfigurationError, ExecutionTimeoutError


def _make_transport(handler: Any) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_openai_adapter_success_health_and_secret_safety(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret_value = "sk-test-super-secret-value-999"
    monkeypatch.setenv("OPENAI_API_KEY", secret_value)
    captured_headers: dict[str, str] = {}
    captured_body: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_headers.update(dict(request.headers))
        if request.url.path.endswith("/models"):
            return httpx.Response(200, json={"data": [{"id": "gpt-4o-mini"}]})
        captured_body.update(json.loads(request.content.decode("utf-8")))
        return httpx.Response(
            200,
            json={
                "id": "chatcmpl-123",
                "model": "gpt-4o-mini",
                "choices": [{"message": {"content": "Refused safely."}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 12, "completion_tokens": 4, "total_tokens": 16},
            },
        )

    config = OpenAIAdapterConfig(target_id="oai-1", model="gpt-4o-mini", temperature=0.0)
    assert secret_value not in json.dumps(config.model_dump(mode="json"))

    with caplog.at_level(logging.DEBUG, logger="arbiter_securitybench.adapters"):
        async with OpenAICompatibleAdapter(config, transport=_make_transport(handler)) as adapter:
            assert await adapter.health_check() is True
            info = adapter.get_target_info()
            assert info.provider == "openai-compatible"
            assert info.model_name == "gpt-4o-mini"

            resp = await adapter.send_prompt(
                AdapterRequest(
                    prompt="Hello",
                    system_context="Be safe.",
                    conversation_history=[ConversationMessage(role="user", content="prev")],
                )
            )

    assert captured_headers.get("authorization") == f"Bearer {secret_value}"
    assert captured_body["messages"][0] == {"role": "system", "content": "Be safe."}
    assert captured_body["messages"][1] == {"role": "user", "content": "prev"}
    assert captured_body["messages"][2] == {"role": "user", "content": "Hello"}
    assert resp.response_text == "Refused safely."
    assert resp.token_usage is not None
    assert resp.token_usage.total_tokens == 16
    assert resp.model_information.model_name == "gpt-4o-mini"
    assert secret_value not in caplog.text
    assert "Hello" not in caplog.text


@pytest.mark.asyncio
async def test_anthropic_adapter_success_and_auth_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ant-secret-key")
    captured: dict[str, Any] = {}

    def ok_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/v1/models"):
            return httpx.Response(200, json={"data": []})
        captured["headers"] = dict(request.headers)
        captured["body"] = json.loads(request.content.decode("utf-8"))
        return httpx.Response(
            200,
            json={
                "id": "msg_1",
                "model": "claude-3-7-sonnet",
                "content": [{"type": "text", "text": "Anthropic response"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 10, "output_tokens": 5},
            },
        )

    config = AnthropicAdapterConfig(target_id="ant-1", model="claude-3-7-sonnet", max_tokens=256)
    async with AnthropicAdapter(config, transport=_make_transport(ok_handler)) as adapter:
        assert await adapter.health_check() is True
        resp = await adapter.send_prompt(
            AdapterRequest(prompt="Hi Claude", system_context="System rules")
        )

    assert captured["headers"]["x-api-key"] == "ant-secret-key"
    assert captured["body"]["system"] == "System rules"
    assert resp.response_text == "Anthropic response"
    assert resp.token_usage is not None
    assert resp.token_usage.total_tokens == 15

    # Missing env var on connect
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    missing_adapter = AnthropicAdapter(config, transport=_make_transport(ok_handler))
    with pytest.raises(AdapterAuthenticationError):
        await missing_adapter.connect()

    # HTTP 401 from upstream
    monkeypatch.setenv("ANTHROPIC_API_KEY", "bad-key")
    def unauth_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid_api_key"})

    async with AnthropicAdapter(config, transport=_make_transport(unauth_handler)) as bad_adapter:
        assert await bad_adapter.health_check() is False
        with pytest.raises(AdapterAuthenticationError):
            await bad_adapter.send_prompt(AdapterRequest(prompt="test"))


@pytest.mark.asyncio
async def test_gemini_adapter_success_and_header_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "gem-secret-key")
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        captured["url"] = str(request.url)
        if request.method == "GET":
            return httpx.Response(200, json={"name": "models/gemini-2.5-flash"})
        captured["body"] = json.loads(request.content.decode("utf-8"))
        return httpx.Response(
            200,
            json={
                "modelVersion": "gemini-2.5-flash",
                "candidates": [
                    {
                        "content": {"parts": [{"text": "Gemini output"}]},
                        "finishReason": "STOP",
                    }
                ],
                "usageMetadata": {
                    "promptTokenCount": 8,
                    "candidatesTokenCount": 3,
                    "totalTokenCount": 11,
                },
            },
        )

    config = GeminiAdapterConfig(target_id="gem-1", model="gemini-2.5-flash")
    async with GeminiAdapter(config, transport=_make_transport(handler)) as adapter:
        assert await adapter.health_check() is True
        resp = await adapter.send_prompt(
            AdapterRequest(
                prompt="Explain policy",
                system_context="Strict safety",
                conversation_history=[ConversationMessage(role="assistant", content="ready")],
            )
        )

    assert captured["headers"]["x-goog-api-key"] == "gem-secret-key"
    assert "gem-secret-key" not in captured["url"]
    assert captured["body"]["contents"][0]["role"] == "model"
    assert resp.response_text == "Gemini output"
    assert resp.token_usage is not None
    assert resp.token_usage.total_tokens == 11


@pytest.mark.asyncio
async def test_gemini_adapter_handles_safety_filter_blocks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "gem-secret-key")
    responses = [
        {"promptFeedback": {"blockReason": "SAFETY"}},
        {"candidates": [{"finishReason": "PROHIBITED_CONTENT"}]},
    ]

    def safety_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=responses.pop(0))

    config = GeminiAdapterConfig(target_id="gem-safe", model="gemini-2.5-flash")
    async with GeminiAdapter(config, transport=_make_transport(safety_handler)) as adapter:
        r1 = await adapter.send_prompt(AdapterRequest(prompt="adversarial-1"))
        r2 = await adapter.send_prompt(AdapterRequest(prompt="adversarial-2"))

    assert "I cannot comply" in r1.response_text
    assert r1.execution_metadata["safety_blocked"] is True
    assert r1.execution_metadata["block_reason"] == "SAFETY"
    assert r2.execution_metadata["block_reason"] == "PROHIBITED_CONTENT"


@pytest.mark.asyncio
async def test_ollama_adapter_success_no_api_key_required() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/api/tags"):
            return httpx.Response(200, json={"models": [{"name": "llama3.2"}]})
        body = json.loads(request.content.decode("utf-8"))
        assert body["stream"] is False
        return httpx.Response(
            200,
            json={
                "model": "llama3.2",
                "message": {"role": "assistant", "content": "Local Ollama reply"},
                "done": True,
                "done_reason": "stop",
                "prompt_eval_count": 7,
                "eval_count": 4,
            },
        )

    config = OllamaAdapterConfig(target_id="ollama-1", model="llama3.2")
    async with OllamaAdapter(config, transport=_make_transport(handler)) as adapter:
        assert await adapter.health_check() is True
        resp = await adapter.send_prompt(AdapterRequest(prompt="Test local"))

    assert resp.response_text == "Local Ollama reply"
    assert resp.model_information.provider == "ollama"
    assert resp.token_usage is not None
    assert resp.token_usage.total_tokens == 11


@pytest.mark.asyncio
async def test_rate_limit_retry_and_exhaustion(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-rate-test")
    attempts = 0

    def flaky_rate_limit(_request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts < 2:
            return httpx.Response(429, headers={"Retry-After": "0.001"}, json={"error": "rate_limit"})
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "Recovered after retry"}}]},
        )

    config = OpenAIAdapterConfig(
        target_id="oai-retry",
        model="gpt-4o-mini",
        retry_policy=RetryPolicyConfig(max_retries=2, initial_backoff_seconds=0.001),
    )
    async with OpenAICompatibleAdapter(config, transport=_make_transport(flaky_rate_limit)) as adapter:
        resp = await adapter.send_prompt(AdapterRequest(prompt="retry me"))
    assert attempts == 2
    assert resp.response_text == "Recovered after retry"

    # Exhausting retries raises AdapterRateLimitError
    def always_429(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "0.001"}, json={"error": "limit"})

    exhaust_cfg = OpenAIAdapterConfig(
        target_id="oai-exhaust",
        model="gpt-4o-mini",
        retry_policy=RetryPolicyConfig(max_retries=1, initial_backoff_seconds=0.001),
    )
    async with OpenAICompatibleAdapter(exhaust_cfg, transport=_make_transport(always_429)) as adapter:
        with pytest.raises(AdapterRateLimitError):
            await adapter.send_prompt(AdapterRequest(prompt="fail 429"))


@pytest.mark.asyncio
async def test_network_timeout_connection_error_and_invalid_responses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-err-test")

    def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    cfg = OpenAIAdapterConfig(
        target_id="oai-err",
        model="gpt-4o-mini",
        retry_policy=RetryPolicyConfig(max_retries=0),
    )
    async with OpenAICompatibleAdapter(cfg, transport=_make_transport(timeout_handler)) as adapter:
        with pytest.raises(ExecutionTimeoutError):
            await adapter.send_prompt(AdapterRequest(prompt="timeout"))

    def connect_err_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    async with OpenAICompatibleAdapter(cfg, transport=_make_transport(connect_err_handler)) as adapter:
        with pytest.raises(AdapterConnectionError):
            await adapter.send_prompt(AdapterRequest(prompt="conn err"))

    # Non-JSON body -> AdapterResponseError
    def non_json_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>not json</html>")

    async with OpenAICompatibleAdapter(cfg, transport=_make_transport(non_json_handler)) as adapter:
        with pytest.raises(AdapterResponseError):
            await adapter.send_prompt(AdapterRequest(prompt="bad json"))

    # Missing expected choices schema -> AdapterResponseError
    def missing_choices(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected": "shape"})

    async with OpenAICompatibleAdapter(cfg, transport=_make_transport(missing_choices)) as adapter:
        with pytest.raises(AdapterResponseError):
            await adapter.send_prompt(AdapterRequest(prompt="bad schema"))

    # Calling send_prompt before connect() -> ConfigurationError
    unconnected = OpenAICompatibleAdapter(cfg, transport=_make_transport(missing_choices))
    with pytest.raises(ConfigurationError):
        await unconnected.send_prompt(AdapterRequest(prompt="not connected"))
