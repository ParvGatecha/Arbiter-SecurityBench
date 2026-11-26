"""Base TargetAdapter interface and shared HTTP transport foundation."""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from types import TracebackType
from typing import Any, Self

import httpx

from arbiter_securitybench.adapters.errors import (
    AdapterAuthenticationError,
    AdapterConnectionError,
    AdapterRateLimitError,
    AdapterResponseError,
)
from arbiter_securitybench.adapters.models import (
    AdapterRequest,
    AdapterResponse,
    BaseAdapterConfig,
    CredentialedHTTPAdapterConfig,
    TargetInfo,
)
from arbiter_securitybench.adapters.resilience import (
    AsyncTokenBucketRateLimiter,
    execute_with_retry,
)
from arbiter_securitybench.contracts import (
    BenchmarkTargetAdapter,
    ConfigurationError,
    ExecutionTimeoutError,
    TargetExecutionRequest,
    TargetExecutionResponse,
    TargetModality,
)

logger = logging.getLogger("arbiter_securitybench.adapters")


class TargetAdapter(BenchmarkTargetAdapter, ABC):
    """Universal abstract interface for all AI target adapters."""

    def __init__(self, config: BaseAdapterConfig) -> None:
        self._base_config = config
        self._connected = False
        self._rate_limiter = (
            AsyncTokenBucketRateLimiter(config.rate_limit)
            if config.rate_limit is not None
            else None
        )

    @property
    def target_id(self) -> str:
        return self._base_config.target_id

    @property
    def target_type(self) -> TargetModality:
        return self._base_config.target_type

    @property
    @abstractmethod
    def adapter_type(self) -> str:
        """Canonical adapter type identifier (e.g., 'openai', 'ollama', 'http')."""

    @property
    def is_connected(self) -> bool:
        return self._connected

    @abstractmethod
    async def connect(self) -> None:
        """Validate configuration and initialize underlying connections/resources."""

    @abstractmethod
    async def send_prompt(self, request: AdapterRequest) -> AdapterResponse:
        """Send a standardized prompt request to the target and return standardized response."""

    @abstractmethod
    def get_target_info(self) -> TargetInfo:
        """Return descriptive target metadata and capabilities."""

    @abstractmethod
    async def health_check(self) -> bool:
        """Return True if the target is reachable and configured properly, else False."""

    @abstractmethod
    async def close(self) -> None:
        """Release connections and clean up adapter resources."""

    async def __aenter__(self) -> Self:
        await self.connect()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.close()

    async def execute(self, request: TargetExecutionRequest) -> TargetExecutionResponse:
        """Bridge BenchmarkExecutionEngine requests to the universal TargetAdapter contract."""
        if not self._connected:
            await self.connect()

        timeout_raw = request.target_config.get("timeout")
        timeout = float(timeout_raw) if isinstance(timeout_raw, (int, float)) else None
        system_context_raw = request.target_config.get("system_context")
        system_context = str(system_context_raw) if system_context_raw is not None else None

        adapter_req = AdapterRequest(
            prompt=request.input_prompt,
            system_context=system_context,
            metadata={"run_id": request.run_id, "test_id": request.test_id, **request.metadata},
            timeout=timeout,
        )
        adapter_resp = await self.send_prompt(adapter_req)
        return TargetExecutionResponse(
            output=adapter_resp.response_text,
            raw_response=adapter_resp.raw_response,
            metadata={
                "latency": adapter_resp.latency,
                "token_usage": (
                    adapter_resp.token_usage.model_dump() if adapter_resp.token_usage else None
                ),
                "model_information": adapter_resp.model_information.model_dump(),
                **adapter_resp.execution_metadata,
            },
        )

    async def _acquire_rate_limit(self) -> None:
        if self._rate_limiter is not None:
            await self._rate_limiter.acquire()


class BaseHTTPTargetAdapter(TargetAdapter, ABC):
    """Shared HTTP transport, credential resolution, retry, and error-mapping base."""

    def __init__(
        self,
        config: CredentialedHTTPAdapterConfig,
        *,
        http_client: httpx.AsyncClient | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        super().__init__(config)
        self._http_config = config
        self._external_client = http_client is not None
        self._client = http_client
        self._transport = transport
        self._api_key: str | None = None

    async def connect(self) -> None:
        resolved_key = self._http_config.resolve_api_key()
        if resolved_key is None and not self._http_config.allow_unauthenticated:
            env_hint = self._http_config.api_key_env_var or "configured credential"
            raise AdapterAuthenticationError(
                f"Missing API credential for target {self.target_id!r}; "
                f"set environment variable {env_hint!r}.",
                component=f"adapters.{self.adapter_type}",
                details={"target_id": self.target_id, "env_var": self._http_config.api_key_env_var},
            )
        self._api_key = resolved_key

        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self._http_config.timeout_seconds,
                transport=self._transport,
            )
        self._connected = True
        logger.debug(
            "Connected HTTP target adapter",
            extra={"target_id": self.target_id, "adapter_type": self.adapter_type},
        )

    async def close(self) -> None:
        if self._client is not None and not self._external_client:
            await self._client.aclose()
            self._client = None
        self._connected = False

    def _require_client(self) -> httpx.AsyncClient:
        if not self._connected or self._client is None:
            raise ConfigurationError(
                f"Adapter {self.target_id!r} is not connected; call connect() first.",
                component=f"adapters.{self.adapter_type}",
                details={"target_id": self.target_id},
            )
        return self._client

    @abstractmethod
    def _build_http_request(self, request: AdapterRequest) -> tuple[str, str, dict[str, str], dict[str, Any]]:
        """Return (method, url, headers, json_payload) for the target API call."""

    @abstractmethod
    def _parse_http_response(
        self,
        payload: dict[str, Any],
        latency: float,
        response: httpx.Response,
    ) -> AdapterResponse:
        """Map raw target JSON payload into a standardized AdapterResponse."""

    @abstractmethod
    def _build_health_request(self) -> tuple[str, str, dict[str, str]]:
        """Return (method, url, headers) for health_check()."""

    async def send_prompt(self, request: AdapterRequest) -> AdapterResponse:
        client = self._require_client()
        method, url, headers, body = self._build_http_request(request)
        timeout = request.timeout if request.timeout is not None else self._http_config.timeout_seconds

        async def _attempt() -> AdapterResponse:
            await self._acquire_rate_limit()
            start = time.perf_counter()
            try:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    json=body if method != "GET" else None,
                    timeout=timeout,
                )
            except httpx.TimeoutException as exc:
                raise ExecutionTimeoutError(
                    f"Request to target {self.target_id!r} timed out after {timeout}s.",
                    component=f"adapters.{self.adapter_type}",
                    details={"target_id": self.target_id, "timeout_seconds": timeout},
                ) from exc
            except httpx.RequestError as exc:
                raise AdapterConnectionError(
                    f"Network transport error contacting target {self.target_id!r}: {type(exc).__name__}",
                    component=f"adapters.{self.adapter_type}",
                    details={"target_id": self.target_id, "exception_type": type(exc).__name__},
                ) from exc

            latency = time.perf_counter() - start
            self._raise_for_status(response)

            try:
                payload = response.json()
            except ValueError as exc:
                raise AdapterResponseError(
                    f"Target {self.target_id!r} returned non-JSON response payload.",
                    component=f"adapters.{self.adapter_type}",
                    details={"target_id": self.target_id, "status_code": response.status_code},
                ) from exc

            if not isinstance(payload, dict):
                raise AdapterResponseError(
                    f"Target {self.target_id!r} returned JSON payload of unexpected type {type(payload).__name__}.",
                    component=f"adapters.{self.adapter_type}",
                    details={"target_id": self.target_id, "status_code": response.status_code},
                )

            logger.debug(
                "Received target response",
                extra={
                    "target_id": self.target_id,
                    "adapter_type": self.adapter_type,
                    "status_code": response.status_code,
                    "latency_seconds": round(latency, 4),
                },
            )
            return self._parse_http_response(payload, latency, response)

        return await execute_with_retry(
            _attempt,
            policy=self._http_config.retry_policy,
            target_id=self.target_id,
            adapter_type=self.adapter_type,
        )

    async def health_check(self) -> bool:
        try:
            if not self._connected:
                await self.connect()
            client = self._require_client()
            method, url, headers = self._build_health_request()
            response = await client.request(
                method=method,
                url=url,
                headers=headers,
                timeout=self._http_config.timeout_seconds,
            )
            return 200 <= response.status_code < 300
        except Exception:  # noqa: BLE001 - health_check returns bool on connectivity/auth failures
            return False

    @staticmethod
    def _extract_upstream_error(response: httpx.Response) -> str | None:
        try:
            payload = response.json()
        except ValueError:
            text = response.text.strip()
            return text[:300] if text else None
        if isinstance(payload, dict):
            err = payload.get("error")
            if isinstance(err, dict):
                msg = err.get("message") or err.get("status")
                if isinstance(msg, str) and msg.strip():
                    return msg.strip()[:300]
            if isinstance(err, str) and err.strip():
                return err.strip()[:300]
            msg = payload.get("message")
            if isinstance(msg, str) and msg.strip():
                return msg.strip()[:300]
        return None

    def _raise_for_status(self, response: httpx.Response) -> None:
        code = response.status_code
        if 200 <= code < 300:
            return
        upstream_msg = self._extract_upstream_error(response)
        suffix = f" Details: {upstream_msg}" if upstream_msg else ""
        base_details: dict[str, Any] = {"target_id": self.target_id, "status_code": code}
        if upstream_msg:
            base_details["upstream_message"] = upstream_msg

        if code in {401, 403}:
            raise AdapterAuthenticationError(
                f"Authentication failed for target {self.target_id!r} (HTTP {code}).{suffix}",
                component=f"adapters.{self.adapter_type}",
                details=base_details,
            )
        if code == 429:
            retry_after_raw = response.headers.get("Retry-After")
            retry_after: float | None = None
            if retry_after_raw is not None:
                try:
                    retry_after = float(retry_after_raw)
                except ValueError:
                    retry_after = None
            raise AdapterRateLimitError(
                f"Rate limit exceeded by target {self.target_id!r} (HTTP 429).{suffix}",
                retry_after_seconds=retry_after,
                component=f"adapters.{self.adapter_type}",
                details=base_details,
            )
        if code in self._http_config.retry_policy.retryable_status_codes or code >= 500:
            raise AdapterConnectionError(
                f"Transient server error from target {self.target_id!r} (HTTP {code}).{suffix}",
                component=f"adapters.{self.adapter_type}",
                details=base_details,
            )
        raise AdapterResponseError(
            f"Unexpected HTTP {code} error from target {self.target_id!r}.{suffix}",
            component=f"adapters.{self.adapter_type}",
            details=base_details,
        )
