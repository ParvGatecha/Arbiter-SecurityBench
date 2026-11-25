"""Google Gemini REST API target adapter."""

from __future__ import annotations

from typing import Any

import httpx

from arbiter_securitybench.adapters.base import BaseHTTPTargetAdapter
from arbiter_securitybench.adapters.errors import AdapterResponseError
from arbiter_securitybench.adapters.models import (
    AdapterRequest,
    AdapterResponse,
    GeminiAdapterConfig,
    ModelInformation,
    TargetInfo,
    TokenUsage,
)

_SAFETY_FINISH_REASONS = frozenset({
    "SAFETY",
    "PROHIBITED_CONTENT",
    "BLOCKLIST",
    "SPII",
    "RECITATION",
})


class GeminiAdapter(BaseHTTPTargetAdapter):
    """Adapter for Google Gemini generateContent REST APIs."""

    def __init__(
        self,
        config: GeminiAdapterConfig,
        *,
        http_client: httpx.AsyncClient | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        super().__init__(config, http_client=http_client, transport=transport)
        self._config = config

    @property
    def adapter_type(self) -> str:
        return "gemini"

    def get_target_info(self) -> TargetInfo:
        return TargetInfo(
            target_id=self.target_id,
            adapter_type=self.adapter_type,
            provider="google-gemini",
            model_name=self._config.model,
            target_type=self.target_type,
            endpoint=self._config.base_url,
            capabilities=["generate_content", "system_context", "conversation_history"],
            metadata=dict(self._config.metadata),
        )

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            **self._config.default_headers,
        }
        if self._api_key:
            # Pass key via header rather than URL query string to avoid secret leakage in logs.
            headers["x-goog-api-key"] = self._api_key
        return headers

    def _build_http_request(
        self, request: AdapterRequest
    ) -> tuple[str, str, dict[str, str], dict[str, Any]]:
        contents: list[dict[str, Any]] = []
        for msg in request.conversation_history:
            if msg.role == "system":
                continue
            role = "model" if msg.role == "assistant" else "user"
            contents.append({"role": role, "parts": [{"text": msg.content}]})
        contents.append({"role": "user", "parts": [{"text": request.prompt}]})

        body: dict[str, Any] = {
            "contents": contents,
            **self._config.extra_body,
        }
        if request.system_context:
            body["systemInstruction"] = {"parts": [{"text": request.system_context}]}

        gen_config: dict[str, Any] = {}
        if self._config.temperature is not None:
            gen_config["temperature"] = self._config.temperature
        if self._config.max_output_tokens is not None:
            gen_config["maxOutputTokens"] = self._config.max_output_tokens
        if gen_config:
            body["generationConfig"] = gen_config

        url = f"{self._config.base_url}/{self._config.api_version}/models/{self._config.model}:generateContent"
        return "POST", url, self._headers(), body

    def _build_health_request(self) -> tuple[str, str, dict[str, str]]:
        url = f"{self._config.base_url}/{self._config.api_version}/models/{self._config.model}"
        return "GET", url, self._headers()

    def _safety_refusal_response(
        self,
        payload: dict[str, Any],
        latency: float,
        response: httpx.Response,
        *,
        block_reason: str,
        finish_reason: str | None = None,
        safety_ratings: Any = None,
    ) -> AdapterResponse:
        usage_raw = payload.get("usageMetadata")
        usage = None
        if isinstance(usage_raw, dict):
            usage = TokenUsage(
                input_tokens=usage_raw.get("promptTokenCount"),
                output_tokens=usage_raw.get("candidatesTokenCount"),
                total_tokens=usage_raw.get("totalTokenCount"),
            )
        return AdapterResponse(
            response_text=(
                f"I cannot comply with this request. Content blocked by safety filter "
                f"(reason: {block_reason})."
            ),
            raw_response=payload,
            latency=latency,
            token_usage=usage,
            model_information=ModelInformation(
                provider="google-gemini",
                model_name=str(payload.get("modelVersion") or self._config.model),
                modality=self.target_type,
            ),
            execution_metadata={
                "status_code": response.status_code,
                "safety_blocked": True,
                "block_reason": block_reason,
                "finish_reason": finish_reason,
                "safety_ratings": safety_ratings,
            },
        )

    def _parse_http_response(
        self,
        payload: dict[str, Any],
        latency: float,
        response: httpx.Response,
    ) -> AdapterResponse:
        prompt_feedback = payload.get("promptFeedback")
        feedback_reason = (
            prompt_feedback.get("blockReason")
            if isinstance(prompt_feedback, dict)
            else None
        )

        candidates = payload.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            if isinstance(feedback_reason, str) and feedback_reason.strip():
                return self._safety_refusal_response(
                    payload,
                    latency,
                    response,
                    block_reason=feedback_reason.strip(),
                    safety_ratings=prompt_feedback.get("safetyRatings")
                    if isinstance(prompt_feedback, dict)
                    else None,
                )
            raise AdapterResponseError(
                "Gemini response missing non-empty 'candidates' list.",
                component="adapters.gemini",
                details={"target_id": self.target_id},
            )
        first = candidates[0]
        finish_reason = first.get("finishReason") if isinstance(first, dict) else None
        safety_ratings = first.get("safetyRatings") if isinstance(first, dict) else None
        content = first.get("content") if isinstance(first, dict) else None
        parts = content.get("parts") if isinstance(content, dict) else None
        if not isinstance(parts, list):
            if (
                isinstance(finish_reason, str)
                and finish_reason.strip().upper() in _SAFETY_FINISH_REASONS
            ):
                return self._safety_refusal_response(
                    payload,
                    latency,
                    response,
                    block_reason=finish_reason.strip().upper(),
                    finish_reason=finish_reason,
                    safety_ratings=safety_ratings,
                )
            raise AdapterResponseError(
                "Gemini response missing 'candidates[0].content.parts'.",
                component="adapters.gemini",
                details={"target_id": self.target_id},
            )

        texts = [p["text"] for p in parts if isinstance(p, dict) and isinstance(p.get("text"), str)]
        if not texts:
            if (
                isinstance(finish_reason, str)
                and finish_reason.strip().upper() in _SAFETY_FINISH_REASONS
            ):
                return self._safety_refusal_response(
                    payload,
                    latency,
                    response,
                    block_reason=finish_reason.strip().upper(),
                    finish_reason=finish_reason,
                    safety_ratings=safety_ratings,
                )
            raise AdapterResponseError(
                "Gemini response candidate contained no text parts.",
                component="adapters.gemini",
                details={"target_id": self.target_id},
            )

        usage_raw = payload.get("usageMetadata")
        usage = None
        if isinstance(usage_raw, dict):
            usage = TokenUsage(
                input_tokens=usage_raw.get("promptTokenCount"),
                output_tokens=usage_raw.get("candidatesTokenCount"),
                total_tokens=usage_raw.get("totalTokenCount"),
            )

        return AdapterResponse(
            response_text="\n".join(texts),
            raw_response=payload,
            latency=latency,
            token_usage=usage,
            model_information=ModelInformation(
                provider="google-gemini",
                model_name=str(payload.get("modelVersion") or self._config.model),
                modality=self.target_type,
            ),
            execution_metadata={
                "status_code": response.status_code,
                "finish_reason": first.get("finishReason") if isinstance(first, dict) else None,
                "safety_ratings": first.get("safetyRatings") if isinstance(first, dict) else None,
            },
        )
