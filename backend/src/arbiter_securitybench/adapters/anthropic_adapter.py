"""Anthropic Messages API target adapter."""

from __future__ import annotations

from typing import Any

import httpx

from arbiter_securitybench.adapters.base import BaseHTTPTargetAdapter
from arbiter_securitybench.adapters.errors import AdapterResponseError
from arbiter_securitybench.adapters.models import (
    AdapterRequest,
    AdapterResponse,
    AnthropicAdapterConfig,
    ModelInformation,
    TargetInfo,
    TokenUsage,
)


class AnthropicAdapter(BaseHTTPTargetAdapter):
    """Adapter for Anthropic Messages APIs (/v1/messages)."""

    def __init__(
        self,
        config: AnthropicAdapterConfig,
        *,
        http_client: httpx.AsyncClient | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        super().__init__(config, http_client=http_client, transport=transport)
        self._config = config

    @property
    def adapter_type(self) -> str:
        return "anthropic"

    def get_target_info(self) -> TargetInfo:
        return TargetInfo(
            target_id=self.target_id,
            adapter_type=self.adapter_type,
            provider="anthropic",
            model_name=self._config.model,
            target_type=self.target_type,
            endpoint=self._config.base_url,
            capabilities=["messages", "system_context", "conversation_history"],
            metadata=dict(self._config.metadata),
        )

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "anthropic-version": self._config.anthropic_version,
            **self._config.default_headers,
        }
        if self._api_key:
            headers["x-api-key"] = self._api_key
        return headers

    def _build_http_request(
        self, request: AdapterRequest
    ) -> tuple[str, str, dict[str, str], dict[str, Any]]:
        messages = [
            {"role": msg.role, "content": msg.content}
            for msg in request.conversation_history
            if msg.role != "system"
        ]
        messages.append({"role": "user", "content": request.prompt})

        body: dict[str, Any] = {
            "model": self._config.model,
            "max_tokens": self._config.max_tokens,
            "messages": messages,
            **self._config.extra_body,
        }
        if request.system_context:
            body["system"] = request.system_context
        if self._config.temperature is not None:
            body["temperature"] = self._config.temperature

        return "POST", f"{self._config.base_url}/v1/messages", self._headers(), body

    def _build_health_request(self) -> tuple[str, str, dict[str, str]]:
        return "GET", f"{self._config.base_url}/v1/models", self._headers()

    def _parse_http_response(
        self,
        payload: dict[str, Any],
        latency: float,
        response: httpx.Response,
    ) -> AdapterResponse:
        blocks = payload.get("content")
        if not isinstance(blocks, list) or not blocks:
            raise AdapterResponseError(
                "Anthropic response missing non-empty 'content' blocks.",
                component="adapters.anthropic",
                details={"target_id": self.target_id},
            )
        text_parts = [
            block["text"]
            for block in blocks
            if isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str)
        ]
        if not text_parts:
            raise AdapterResponseError(
                "Anthropic response contained no text content blocks.",
                component="adapters.anthropic",
                details={"target_id": self.target_id},
            )

        usage_raw = payload.get("usage")
        usage = None
        if isinstance(usage_raw, dict):
            in_tok = usage_raw.get("input_tokens")
            out_tok = usage_raw.get("output_tokens")
            total = (
                in_tok + out_tok
                if isinstance(in_tok, int) and isinstance(out_tok, int)
                else None
            )
            usage = TokenUsage(input_tokens=in_tok, output_tokens=out_tok, total_tokens=total)

        return AdapterResponse(
            response_text="\n".join(text_parts),
            raw_response=payload,
            latency=latency,
            token_usage=usage,
            model_information=ModelInformation(
                provider="anthropic",
                model_name=str(payload.get("model") or self._config.model),
                modality=self.target_type,
            ),
            execution_metadata={
                "status_code": response.status_code,
                "stop_reason": payload.get("stop_reason"),
                "response_id": payload.get("id"),
            },
        )
