"""Ollama local model REST API target adapter."""

from __future__ import annotations

from typing import Any

import httpx

from arbiter_securitybench.adapters.base import BaseHTTPTargetAdapter
from arbiter_securitybench.adapters.errors import AdapterResponseError
from arbiter_securitybench.adapters.models import (
    AdapterRequest,
    AdapterResponse,
    ModelInformation,
    OllamaAdapterConfig,
    TargetInfo,
    TokenUsage,
)


class OllamaAdapter(BaseHTTPTargetAdapter):
    """Adapter for local Ollama /api/chat endpoints."""

    def __init__(
        self,
        config: OllamaAdapterConfig,
        *,
        http_client: httpx.AsyncClient | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        super().__init__(config, http_client=http_client, transport=transport)
        self._config = config

    @property
    def adapter_type(self) -> str:
        return "ollama"

    def get_target_info(self) -> TargetInfo:
        return TargetInfo(
            target_id=self.target_id,
            adapter_type=self.adapter_type,
            provider="ollama",
            model_name=self._config.model,
            target_type=self.target_type,
            endpoint=self._config.base_url,
            capabilities=["local_chat", "system_context", "conversation_history"],
            metadata=dict(self._config.metadata),
        )

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            **self._config.default_headers,
        }
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
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
            "stream": False,
        }
        if self._config.options:
            body["options"] = dict(self._config.options)
        if self._config.keep_alive is not None:
            body["keep_alive"] = self._config.keep_alive

        return "POST", f"{self._config.base_url}/api/chat", self._headers(), body

    def _build_health_request(self) -> tuple[str, str, dict[str, str]]:
        return "GET", f"{self._config.base_url}/api/tags", self._headers()

    def _parse_http_response(
        self,
        payload: dict[str, Any],
        latency: float,
        response: httpx.Response,
    ) -> AdapterResponse:
        message = payload.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str):
            raise AdapterResponseError(
                "Ollama response missing string 'message.content'.",
                component="adapters.ollama",
                details={"target_id": self.target_id},
            )

        in_tok = payload.get("prompt_eval_count")
        out_tok = payload.get("eval_count")
        usage = None
        if isinstance(in_tok, int) or isinstance(out_tok, int):
            total = (in_tok or 0) + (out_tok or 0) if (in_tok is not None and out_tok is not None) else None
            usage = TokenUsage(input_tokens=in_tok, output_tokens=out_tok, total_tokens=total)

        return AdapterResponse(
            response_text=content,
            raw_response=payload,
            latency=latency,
            token_usage=usage,
            model_information=ModelInformation(
                provider="ollama",
                model_name=str(payload.get("model") or self._config.model),
                modality=self.target_type,
            ),
            execution_metadata={
                "status_code": response.status_code,
                "done": payload.get("done"),
                "done_reason": payload.get("done_reason"),
            },
        )
