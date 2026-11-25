"""OpenAI and OpenAI-compatible target adapter."""

from __future__ import annotations

import os
from typing import Any

import httpx

from arbiter_securitybench.adapters.base import BaseHTTPTargetAdapter
from arbiter_securitybench.adapters.errors import AdapterResponseError
from arbiter_securitybench.adapters.models import (
    AdapterRequest,
    AdapterResponse,
    ModelInformation,
    OpenAIAdapterConfig,
    TargetInfo,
    TokenUsage,
)


class OpenAICompatibleAdapter(BaseHTTPTargetAdapter):
    """Adapter for OpenAI Chat Completions and compatible local/hosted APIs."""

    def __init__(
        self,
        config: OpenAIAdapterConfig,
        *,
        http_client: httpx.AsyncClient | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        super().__init__(config, http_client=http_client, transport=transport)
        self._config = config

    @property
    def adapter_type(self) -> str:
        return "openai"

    def get_target_info(self) -> TargetInfo:
        return TargetInfo(
            target_id=self.target_id,
            adapter_type=self.adapter_type,
            provider="openai-compatible",
            model_name=self._config.model,
            target_type=self.target_type,
            endpoint=self._config.base_url,
            capabilities=["chat_completions", "system_context", "conversation_history"],
            metadata=dict(self._config.metadata),
        )

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            **self._config.default_headers,
        }
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        if self._config.organization_env_var:
            org = os.getenv(self._config.organization_env_var)
            if org:
                headers["OpenAI-Organization"] = org.strip()
        return headers

    def _build_http_request(
        self, request: AdapterRequest
    ) -> tuple[str, str, dict[str, str], dict[str, Any]]:
        messages: list[dict[str, str]] = []
        if request.system_context:
            messages.append({"role": "system", "content": request.system_context})
        for msg in request.conversation_history:
            messages.append({"role": msg.role, "content": msg.content})
        messages.append({"role": "user", "content": request.prompt})

        body: dict[str, Any] = {
            "model": self._config.model,
            "messages": messages,
            **self._config.extra_body,
        }
        if self._config.temperature is not None:
            body["temperature"] = self._config.temperature
        if self._config.max_tokens is not None:
            body["max_tokens"] = self._config.max_tokens

        return "POST", f"{self._config.base_url}/chat/completions", self._headers(), body

    def _build_health_request(self) -> tuple[str, str, dict[str, str]]:
        return "GET", f"{self._config.base_url}/models", self._headers()

    def _parse_http_response(
        self,
        payload: dict[str, Any],
        latency: float,
        response: httpx.Response,
    ) -> AdapterResponse:
        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices:
            raise AdapterResponseError(
                "OpenAI-compatible response missing non-empty 'choices' list.",
                component="adapters.openai",
                details={"target_id": self.target_id},
            )
        first = choices[0]
        message = first.get("message") if isinstance(first, dict) else None
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str):
            raise AdapterResponseError(
                "OpenAI-compatible response missing string 'choices[0].message.content'.",
                component="adapters.openai",
                details={"target_id": self.target_id},
            )

        usage_raw = payload.get("usage")
        usage = None
        if isinstance(usage_raw, dict):
            usage = TokenUsage(
                input_tokens=usage_raw.get("prompt_tokens"),
                output_tokens=usage_raw.get("completion_tokens"),
                total_tokens=usage_raw.get("total_tokens"),
            )

        return AdapterResponse(
            response_text=content,
            raw_response=payload,
            latency=latency,
            token_usage=usage,
            model_information=ModelInformation(
                provider="openai-compatible",
                model_name=str(payload.get("model") or self._config.model),
                modality=self.target_type,
            ),
            execution_metadata={
                "status_code": response.status_code,
                "finish_reason": first.get("finish_reason") if isinstance(first, dict) else None,
                "response_id": payload.get("id"),
            },
        )
