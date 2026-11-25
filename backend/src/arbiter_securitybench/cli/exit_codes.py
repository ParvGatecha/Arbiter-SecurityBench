"""Standardized CI/CD exit codes for the Arbiter SecurityBench CLI."""

from __future__ import annotations

from enum import IntEnum

from arbiter_securitybench.adapters import AdapterAuthenticationError
from arbiter_securitybench.contracts import (
    ConfigurationError,
    DuplicateRegistrationError,
    NotFoundError,
    SecurityBenchError,
    ValidationError,
)


class ExitCode(IntEnum):
    """Deterministic process exit codes suitable for CI/CD pipelines."""

    SUCCESS = 0
    EXECUTION_OR_VALIDATION_FAILED = 1
    CONFIGURATION_ERROR = 2
    AUTHENTICATION_ERROR = 3
    SECURITY_GATE_FAILED = 4
    NOT_FOUND = 5


def exit_code_for_exception(exc: BaseException) -> ExitCode:
    """Map domain exceptions to stable CI/CD exit codes."""
    if isinstance(exc, AdapterAuthenticationError):
        return ExitCode.AUTHENTICATION_ERROR
    if isinstance(exc, NotFoundError):
        return ExitCode.NOT_FOUND
    if isinstance(exc, (ConfigurationError, ValidationError, DuplicateRegistrationError)):
        return ExitCode.CONFIGURATION_ERROR
    if isinstance(exc, SecurityBenchError):
        return ExitCode.EXECUTION_OR_VALIDATION_FAILED
    return ExitCode.EXECUTION_OR_VALIDATION_FAILED
