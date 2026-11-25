"""Typed exceptions for the Arbiter SecurityBench target adapter framework."""

from __future__ import annotations

from arbiter_securitybench.contracts.errors import (
    AdapterError,
    ErrorCategory,
    Retryability,
)


class AdapterAuthenticationError(AdapterError):
    """Raised when target credentials are missing, rejected (401/403), or invalid."""

    category = ErrorCategory.ADAPTER_AUTH
    retryability = Retryability.NON_RETRYABLE
    error_code = "ASB_ADAPTER_AUTH_ERROR"


class AdapterRateLimitError(AdapterError):
    """Raised when a target API enforces rate limits (e.g., HTTP 429)."""

    category = ErrorCategory.ADAPTER_RATE_LIMIT
    retryability = Retryability.RETRYABLE
    error_code = "ASB_ADAPTER_RATE_LIMIT"

    def __init__(
        self,
        message: str,
        *,
        retry_after_seconds: float | None = None,
        component: str = "adapters",
        details: dict[str, object] | None = None,
    ) -> None:
        merged_details = dict(details or {})
        if retry_after_seconds is not None:
            merged_details["retry_after_seconds"] = retry_after_seconds
        super().__init__(
            message,
            component=component,
            details=merged_details,
        )
        self.retry_after_seconds = retry_after_seconds


class AdapterConnectionError(AdapterError):
    """Raised on network connection failures or transient 5xx server responses."""

    category = ErrorCategory.ADAPTER_TRANSPORT
    retryability = Retryability.RETRYABLE
    error_code = "ASB_ADAPTER_CONNECTION_ERROR"


class AdapterResponseError(AdapterError):
    """Raised when a target returns malformed JSON or violates expected schema."""

    category = ErrorCategory.ADAPTER_TRANSPORT
    retryability = Retryability.NON_RETRYABLE
    error_code = "ASB_ADAPTER_INVALID_RESPONSE"
