"""In-process Python callable/application target adapter."""

from __future__ import annotations

import asyncio
import inspect
import time
from collections.abc import Awaitable, Callable
from typing import Any

from arbiter_securitybench.adapters.base import TargetAdapter
from arbiter_securitybench.adapters.errors import AdapterResponseError
from arbiter_securitybench.adapters.models import (
    AdapterRequest,
    AdapterResponse,
    CustomPythonAdapterConfig,
    ModelInformation,
    TargetInfo,
)
from arbiter_securitybench.adapters.resilience import execute_with_retry
from arbiter_securitybench.contracts import ConfigurationError, ExecutionTimeoutError

PythonTargetCallable = Callable[
    [AdapterRequest],
    str | AdapterResponse | dict[str, Any] | Awaitable[str | AdapterResponse | dict[str, Any]],
]


class CustomPythonAdapter(TargetAdapter):
    """Wraps any synchronous or asynchronous Python AI callable/application."""

    def __init__(
        self,
        config: CustomPythonAdapterConfig,
        handler: PythonTargetCallable,
        *,
        health_check_fn: Callable[[], bool | Awaitable[bool]] | None = None,
        connect_fn: Callable[[], None | Awaitable[None]] | None = None,
        close_fn: Callable[[], None | Awaitable[None]] | None = None,
    ) -> None:
        if not callable(handler):
            raise ConfigurationError(
                "CustomPythonAdapter handler must be callable.",
                component="adapters.python",
                details={"target_id": config.target_id},
            )
        super().__init__(config)
        self._config = config
        self._handler = handler
        self._health_check_fn = health_check_fn
        self._connect_fn = connect_fn
        self._close_fn = close_fn

    @property
    def adapter_type(self) -> str:
        return "python"

    def get_target_info(self) -> TargetInfo:
        return TargetInfo(
            target_id=self.target_id,
            adapter_type=self.adapter_type,
            provider=self._config.provider,
            model_name=self._config.model_name,
            target_type=self.target_type,
            endpoint=None,
            capabilities=["in_process_python"],
            metadata=dict(self._config.metadata),
        )

    async def connect(self) -> None:
        if self._connect_fn is not None:
            result = self._connect_fn()
            if inspect.isawaitable(result):
                await result
        self._connected = True

    async def close(self) -> None:
        if self._close_fn is not None:
            result = self._close_fn()
            if inspect.isawaitable(result):
                await result
        self._connected = False

    async def health_check(self) -> bool:
        try:
            if not self._connected:
                await self.connect()
            if self._health_check_fn is None:
                return True
            result = self._health_check_fn()
            if inspect.isawaitable(result):
                return bool(await result)
            return bool(result)
        except Exception:  # noqa: BLE001 - health_check reports readiness as boolean
            return False

    async def send_prompt(self, request: AdapterRequest) -> AdapterResponse:
        if not self._connected:
            raise ConfigurationError(
                f"Adapter {self.target_id!r} is not connected; call connect() first.",
                component="adapters.python",
                details={"target_id": self.target_id},
            )

        timeout = request.timeout if request.timeout is not None else self._config.timeout_seconds

        async def _invoke() -> AdapterResponse:
            await self._acquire_rate_limit()
            start = time.perf_counter()
            try:
                if inspect.iscoroutinefunction(self._handler):
                    raw_out = await asyncio.wait_for(self._handler(request), timeout=timeout)
                else:
                    raw_out = await asyncio.wait_for(
                        asyncio.to_thread(self._handler, request),
                        timeout=timeout,
                    )
            except TimeoutError as exc:
                raise ExecutionTimeoutError(
                    f"Python target {self.target_id!r} exceeded timeout of {timeout}s.",
                    component="adapters.python",
                    details={"target_id": self.target_id, "timeout_seconds": timeout},
                ) from exc

            latency = time.perf_counter() - start
            return self._normalize_output(raw_out, latency)

        return await execute_with_retry(
            _invoke,
            policy=self._config.retry_policy,
            target_id=self.target_id,
            adapter_type=self.adapter_type,
        )

    def _normalize_output(self, raw_out: Any, latency: float) -> AdapterResponse:
        if isinstance(raw_out, AdapterResponse):
            return raw_out
        if isinstance(raw_out, str):
            return AdapterResponse(
                response_text=raw_out,
                raw_response={"response_text": raw_out},
                latency=latency,
                model_information=ModelInformation(
                    provider=self._config.provider,
                    model_name=self._config.model_name,
                    modality=self.target_type,
                ),
            )
        if isinstance(raw_out, dict) and isinstance(raw_out.get("response_text"), str):
            return AdapterResponse(
                response_text=raw_out["response_text"],
                raw_response=raw_out,
                latency=latency,
                model_information=ModelInformation(
                    provider=self._config.provider,
                    model_name=self._config.model_name,
                    modality=self.target_type,
                ),
                execution_metadata={
                    k: v for k, v in raw_out.items() if k != "response_text"
                },
            )
        raise AdapterResponseError(
            f"Python target {self.target_id!r} returned unsupported output type {type(raw_out).__name__}.",
            component="adapters.python",
            details={"target_id": self.target_id, "output_type": type(raw_out).__name__},
        )
