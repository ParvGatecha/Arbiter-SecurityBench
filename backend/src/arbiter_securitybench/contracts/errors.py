"""Structured error taxonomy and exception hierarchy for Arbiter SecurityBench.

Errors are first-class domain data: adapter failures, timeouts, and evaluator
failures must never be silently collapsed into 'defended' outcomes.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ErrorCategory(StrEnum):
    """High-level classification of failures across the benchmark pipeline."""

    VALIDATION = "validation"
    CONFIGURATION = "configuration"
    LIFECYCLE = "lifecycle"
    ADAPTER_TRANSPORT = "adapter_transport"
    ADAPTER_RATE_LIMIT = "adapter_rate_limit"
    ADAPTER_AUTH = "adapter_auth"
    EXECUTION_TIMEOUT = "execution_timeout"
    SANDBOX_VIOLATION = "sandbox_violation"
    EVALUATOR_FAILURE = "evaluator_failure"
    STATISTICAL_UNDERPOWERED = "statistical_underpowered"
    INTEGRITY_MISMATCH = "integrity_mismatch"
    REPRODUCIBILITY_VIOLATION = "reproducibility_violation"
    STORAGE = "storage"


class ErrorSeverity(StrEnum):
    """Operational severity of a recorded error."""

    WARNING = "warning"
    RECOVERABLE = "recoverable"
    FATAL_ITEM = "fatal_item"
    FATAL_RUN = "fatal_run"


class Retryability(StrEnum):
    """Whether an operation may safely be retried under a bounded backoff policy."""

    RETRYABLE = "retryable"
    NON_RETRYABLE = "non_retryable"
    CONDITIONAL = "conditional"


class ErrorRecord(BaseModel):
    """Serializable error record attached to traces, evaluations, or run manifests."""

    model_config = ConfigDict(frozen=True)

    error_code: str = Field(min_length=1, max_length=128)
    category: ErrorCategory
    severity: ErrorSeverity
    retryability: Retryability
    message: str = Field(min_length=1)
    component: str = Field(min_length=1)
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    details: dict[str, Any] = Field(default_factory=dict)


class SecurityBenchError(Exception):
    """Base exception for all Arbiter SecurityBench domain and runtime errors."""

    category: ErrorCategory = ErrorCategory.VALIDATION
    severity: ErrorSeverity = ErrorSeverity.FATAL_ITEM
    retryability: Retryability = Retryability.NON_RETRYABLE
    error_code: str = "ASB_INTERNAL_ERROR"

    def __init__(
        self,
        message: str,
        *,
        error_code: str | None = None,
        component: str = "core",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        if error_code is not None:
            self.error_code = error_code
        self.component = component
        self.details = details or {}

    def to_record(self) -> ErrorRecord:
        """Convert this exception into a structured, immutable ErrorRecord."""
        return ErrorRecord(
            error_code=self.error_code,
            category=self.category,
            severity=self.severity,
            retryability=self.retryability,
            message=self.message,
            component=self.component,
            details=self.details,
        )


class ValidationError(SecurityBenchError):
    category = ErrorCategory.VALIDATION
    error_code = "ASB_VALIDATION_ERROR"


class ConfigurationError(SecurityBenchError):
    category = ErrorCategory.CONFIGURATION
    severity = ErrorSeverity.FATAL_RUN
    error_code = "ASB_CONFIGURATION_ERROR"


class InvalidLifecycleTransitionError(SecurityBenchError):
    category = ErrorCategory.LIFECYCLE
    error_code = "ASB_INVALID_LIFECYCLE_TRANSITION"


class AdapterError(SecurityBenchError):
    category = ErrorCategory.ADAPTER_TRANSPORT
    retryability = Retryability.CONDITIONAL
    error_code = "ASB_ADAPTER_ERROR"


class ExecutionTimeoutError(SecurityBenchError):
    category = ErrorCategory.EXECUTION_TIMEOUT
    retryability = Retryability.RETRYABLE
    error_code = "ASB_EXECUTION_TIMEOUT"


class EvaluationError(SecurityBenchError):
    category = ErrorCategory.EVALUATOR_FAILURE
    retryability = Retryability.CONDITIONAL
    error_code = "ASB_EVALUATION_ERROR"


class IntegrityError(SecurityBenchError):
    category = ErrorCategory.INTEGRITY_MISMATCH
    severity = ErrorSeverity.FATAL_RUN
    error_code = "ASB_INTEGRITY_MISMATCH"


class ReproducibilityError(SecurityBenchError):
    category = ErrorCategory.REPRODUCIBILITY_VIOLATION
    severity = ErrorSeverity.FATAL_RUN
    error_code = "ASB_REPRODUCIBILITY_VIOLATION"


class DuplicateRegistrationError(ValidationError):
    error_code = "ASB_DUPLICATE_REGISTRATION"


class NotFoundError(SecurityBenchError):
    category = ErrorCategory.VALIDATION
    error_code = "ASB_NOT_FOUND"


class StorageError(SecurityBenchError):
    category = ErrorCategory.STORAGE
    severity = ErrorSeverity.FATAL_RUN
    error_code = "ASB_STORAGE_ERROR"
