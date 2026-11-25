"""Async rate limiting, bounded retry policies, and secret-safe adapter logging."""

from __future__ import annotations

import asyncio
import logging
import random
import time
from collections.abc import Awaitable, Callable
from typing import TypeVar

from arbiter_securitybench.adapters.errors import (
    AdapterConnectionError,
    AdapterRateLimitError,
)
from arbiter_securitybench.adapters.models import RateLimitConfig, RetryPolicyConfig
from arbiter_securitybench.contracts import ExecutionTimeoutError

T = TypeVar("T")

logger = logging.getLogger("arbiter_securitybench.adapters")


class AsyncTokenBucketRateLimiter:
    """Thread/task-safe async token-bucket rate limiter."""

    def __init__(
        self,
        config: RateLimitConfig,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._rate = config.requests_per_second
        self._capacity = float(config.burst_capacity)
        self._tokens = float(config.burst_capacity)
        self._clock = clock
        self._sleeper = sleeper
        self._last_refill = clock()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until one request token is available."""
        while True:
            wait_seconds = 0.0
            async with self._lock:
                now = self._clock()
                elapsed = max(0.0, now - self._last_refill)
                self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
                self._last_refill = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                wait_seconds = (1.0 - self._tokens) / self._rate
            await self._sleeper(wait_seconds)


def _compute_backoff(
    attempt: int,
    policy: RetryPolicyConfig,
    retry_after: float | None,
) -> float:
    if retry_after is not None and policy.respect_retry_after:
        return min(max(0.0, retry_after), policy.max_backoff_seconds)
    base = policy.initial_backoff_seconds * (policy.backoff_multiplier**attempt)
    capped = min(base, policy.max_backoff_seconds)
    jitter = random.uniform(0.0, capped * 0.25)
    return min(capped + jitter, policy.max_backoff_seconds)


async def execute_with_retry(
    operation: Callable[[], Awaitable[T]],
    *,
    policy: RetryPolicyConfig,
    target_id: str,
    adapter_type: str,
    sleeper: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> T:
    """Execute an async adapter operation with bounded retries on transient failures."""
    attempt = 0
    while True:
        try:
            return await operation()
        except (AdapterRateLimitError, AdapterConnectionError, ExecutionTimeoutError) as exc:
            if attempt >= policy.max_retries:
                logger.warning(
                    "Adapter request exhausted retries",
                    extra={
                        "target_id": target_id,
                        "adapter_type": adapter_type,
                        "attempts": attempt + 1,
                        "error_code": exc.error_code,
                    },
                )
                raise

            retry_after = (
                exc.retry_after_seconds if isinstance(exc, AdapterRateLimitError) else None
            )
            delay = _compute_backoff(attempt, policy, retry_after)
            logger.info(
                "Retrying transient adapter failure",
                extra={
                    "target_id": target_id,
                    "adapter_type": adapter_type,
                    "attempt": attempt + 1,
                    "delay_seconds": round(delay, 3),
                    "error_code": exc.error_code,
                },
            )
            attempt += 1
            await sleeper(delay)
