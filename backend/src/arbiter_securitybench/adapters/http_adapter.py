"""Generic HTTP adapter for arbitrary REST AI services and custom FastAPI/Flask apps."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx

from arbiter_securitybench.adapters.base import BaseHTTPTargetAdapter
from arbiter_securitybench.adapters.errors import AdapterResponseError
from arbiter_securitybench.adapters.models import (
    AdapterRequest,
    AdapterResponse,
    GenericHTTPAdapterConfig,
    ModelInformation,
    TargetInfo,
    TokenUsage,
)

RequestMapper = Callable[[AdapterRequest], dict[str, Any]]
ResponseMapper = Callable[[dict[str, Any], httpx.Response], AdapterResponse | str]


def _extract_dot_path(payload: Any, path: str) -> Any:
    """Resolve a dot-separated path (supporting dict keys and integer list indices)."""
    current = payload
    for segment in path.split("."):
        if isinstance(current, dict):
            if segment not in current:
                return None
            current = current[segment]
        elif isinstance(current, list):
            try:
                idx = int(segment)
            except ValueError:
                return None
            if idx < 0 or idx >= len(current):
                return None
            current = current[idx]
        else:
            return None
    return current


class GenericHTTPAdapter(BaseHTTPTargetAdapter):
    """Flexible HTTP target adapter with declarative path mappings and custom mapper hooks."""

    def __init__(
        self,
        config: GenericHTTPAdapterConfig,
        *,
        request_mapper: RequestMapper | None = None,
        response_mapper: ResponseMapper | None = None,
        http_client: httpx.AsyncClient | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        super().__init__(config, http_client=http_client, transport=transport)
        self._config = config
        self._request_mapper = request_mapper
        self._response_mapper = response_mapper

    @property
    def adapter_type(self) -> str:
        return "http"

    def get_target_info(self) -> TargetInfo:
        return TargetInfo(
            target_id=self.target_id,
            adapter_type=self.adapter_type,
            provider=self._config.provider,
            model_name=self._config.model_name,
            target_type=self.target_type,
            endpoint=self._config.endpoint_url,
            capabilities=["custom_http", "custom_mapping"],
            metadata=dict(self._config.metadata),
        )

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            **self._config.default_headers,
        }
        if self._api_key:
            value = (
                f"{self._config.auth_scheme} {self._api_key}"
                if self._config.auth_scheme
                else self._api_key
            )
            headers[self._config.auth_header_name] = value
        return headers

    def _build_http_request(
        self, request: AdapterRequest
    ) -> tuple[str, str, dict[str, str], dict[str, Any]]:
        if self._request_mapper is not None:
            body = self._request_mapper(request)
        else:
            body = dict(self._config.static_payload)
            body[self._config.prompt_field] = request.prompt
            if self._config.history_field and request.conversation_history:
                body[self._config.history_field] = [
                    {"role": m.role, "content": m.content} for m in request.conversation_history
                ]
            if self._config.system_context_field and request.system_context is not None:
                body[self._config.system_context_field] = request.system_context
            if self._config.metadata_field and request.metadata:
                body[self._config.metadata_field] = dict(request.metadata)

        return self._config.method, self._config.endpoint_url, self._headers(), body

    def _build_health_request(self) -> tuple[str, str, dict[str, str]]:
        health_url = self._config.health_check_url or self._config.endpoint_url
        return "GET", health_url, self._headers()

    def _parse_http_response(
        self,
        payload: dict[str, Any],
        latency: float,
        response: httpx.Response,
    ) -> AdapterResponse:
        if self._response_mapper is not None:
            mapped = self._response_mapper(payload, response)
            if isinstance(mapped, AdapterResponse):
                return mapped
            if isinstance(mapped, str):
                return AdapterResponse(
                    response_text=mapped,
                    raw_response=payload,
                    latency=latency,
                    model_information=ModelInformation(
                        provider=self._config.provider,
                        model_name=self._config.model_name,
                        modality=self.target_type,
                    ),
                    execution_metadata={"status_code": response.status_code},
                )
            raise AdapterResponseError(
                "Custom response_mapper returned unsupported type.",
                component="adapters.http",
                details={"target_id": self.target_id, "returned_type": type(mapped).__name__},
            )

        extracted = _extract_dot_path(payload, self._config.response_text_path)
        if not isinstance(extracted, str):
            raise AdapterResponseError(
                f"Generic HTTP response missing string at path {self._config.response_text_path!r}.",
                component="adapters.http",
                details={
                    "target_id": self.target_id,
                    "response_text_path": self._config.response_text_path,
                },
            )

        model_name = self._config.model_name
        if self._config.model_name_path:
            extracted_model = _extract_dot_path(payload, self._config.model_name_path)
            if isinstance(extracted_model, str) and extracted_model.strip():
                model_name = extracted_model

        in_tok = (
            _extract_dot_path(payload, self._config.input_tokens_path)
            if self._config.input_tokens_path
            else None
        )
        out_tok = (
            _extract_dot_path(payload, self._config.output_tokens_path)
            if self._config.output_tokens_path
            else None
        )
        tot_tok = (
            _extract_dot_path(payload, self._config.total_tokens_path)
            if self._config.total_tokens_path
            else None
        )
        usage = None
        if any(isinstance(v, int) for v in (in_tok, out_tok, tot_tok)):
            usage = TokenUsage(
                input_tokens=in_tok if isinstance(in_tok, int) else None,
                output_tokens=out_tok if isinstance(out_tok, int) else None,
                total_tokens=tot_tok if isinstance(tot_tok, int) else None,
            )

        return AdapterResponse(
            response_text=extracted,
            raw_response=payload,
            latency=latency,
            token_usage=usage,
            model_information=ModelInformation(
                provider=self._config.provider,
                model_name=model_name,
                modality=self.target_type,
            ),
            execution_metadata={"status_code": response.status_code},
        )
