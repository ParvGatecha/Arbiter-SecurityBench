"""Standardized request, response, info, and configuration models for target adapters."""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from arbiter_securitybench.contracts import TargetModality


def _validate_http_url(url: str) -> str:
    stripped = url.strip().rstrip("/")
    parsed = urlparse(stripped)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"Invalid HTTP(S) URL: {url!r}")
    return stripped


class ConversationMessage(BaseModel):
    """Single message turn in conversation history."""

    model_config = ConfigDict(frozen=True)

    role: str = Field(min_length=1, max_length=64)
    content: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class AdapterRequest(BaseModel):
    """Standardized prompt request sent to any TargetAdapter."""

    model_config = ConfigDict(frozen=True)

    prompt: str = Field(min_length=1)
    conversation_history: list[ConversationMessage] = Field(default_factory=list)
    system_context: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    timeout: float | None = Field(default=None, gt=0.0)


class TokenUsage(BaseModel):
    """Token consumption reported by a model or target."""

    model_config = ConfigDict(frozen=True)

    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)


class ModelInformation(BaseModel):
    """Metadata describing the underlying model or AI application that handled the request."""

    model_config = ConfigDict(frozen=True)

    provider: str = Field(min_length=1)
    model_name: str = Field(min_length=1)
    model_version: str | None = None
    modality: TargetModality = TargetModality.LLM


class AdapterResponse(BaseModel):
    """Standardized response returned by any TargetAdapter."""

    model_config = ConfigDict(frozen=True)

    response_text: str
    raw_response: dict[str, Any] = Field(default_factory=dict)
    latency: float = Field(ge=0.0)
    token_usage: TokenUsage | None = None
    model_information: ModelInformation
    execution_metadata: dict[str, Any] = Field(default_factory=dict)


class TargetInfo(BaseModel):
    """Descriptive capability and identity snapshot of a target adapter."""

    model_config = ConfigDict(frozen=True)

    target_id: str = Field(min_length=1)
    adapter_type: str = Field(min_length=1)
    provider: str = Field(min_length=1)
    model_name: str = Field(min_length=1)
    target_type: TargetModality = TargetModality.LLM
    endpoint: str | None = None
    capabilities: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RetryPolicyConfig(BaseModel):
    """Bounded retry and exponential backoff policy for transient adapter errors."""

    model_config = ConfigDict(frozen=True)

    max_retries: int = Field(default=2, ge=0, le=10)
    initial_backoff_seconds: float = Field(default=0.25, gt=0.0)
    max_backoff_seconds: float = Field(default=5.0, gt=0.0)
    backoff_multiplier: float = Field(default=2.0, ge=1.0)
    retryable_status_codes: frozenset[int] = frozenset({429, 500, 502, 503, 504})
    respect_retry_after: bool = True


class RateLimitConfig(BaseModel):
    """Token-bucket rate limit configuration for outbound target requests."""

    model_config = ConfigDict(frozen=True)

    requests_per_second: float = Field(gt=0.0)
    burst_capacity: int = Field(default=1, ge=1)


class BaseAdapterConfig(BaseModel):
    """Common configuration shared across all target adapters."""

    model_config = ConfigDict(frozen=True)

    target_id: str = Field(min_length=1, max_length=128)
    target_type: TargetModality = TargetModality.LLM
    timeout_seconds: float = Field(default=30.0, gt=0.0)
    retry_policy: RetryPolicyConfig = Field(default_factory=RetryPolicyConfig)
    rate_limit: RateLimitConfig | None = None
    default_headers: dict[str, str] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CredentialedHTTPAdapterConfig(BaseAdapterConfig):
    """Base config for HTTP adapters that source credentials from environment variables."""

    api_key_env_var: str | None = None
    api_key: SecretStr | None = Field(default=None, exclude=True)
    allow_unauthenticated: bool = False

    def resolve_api_key(self) -> str | None:
        """Resolve credential from explicit SecretStr override or environment variable."""
        if self.api_key is not None:
            secret = self.api_key.get_secret_value().strip()
            return secret or None
        if self.api_key_env_var:
            val = os.getenv(self.api_key_env_var)
            if val is not None:
                stripped = val.strip()
                return stripped or None
        return None


class OpenAIAdapterConfig(CredentialedHTTPAdapterConfig):
    """Configuration for OpenAI and OpenAI-compatible APIs (vLLM, LiteLLM, LM Studio, etc.)."""

    base_url: str = "https://api.openai.com/v1"
    model: str = Field(min_length=1)
    api_key_env_var: str | None = "OPENAI_API_KEY"
    temperature: float | None = Field(default=None, ge=0.0, le=2.0)
    max_tokens: int | None = Field(default=None, gt=0)
    organization_env_var: str | None = None
    extra_body: dict[str, Any] = Field(default_factory=dict)

    @field_validator("base_url")
    @classmethod
    def _validate_base_url(cls, value: str) -> str:
        return _validate_http_url(value)


class AnthropicAdapterConfig(CredentialedHTTPAdapterConfig):
    """Configuration for Anthropic Messages APIs."""

    base_url: str = "https://api.anthropic.com"
    model: str = Field(min_length=1)
    api_key_env_var: str | None = "ANTHROPIC_API_KEY"
    anthropic_version: str = Field(default="2023-06-01", min_length=1)
    max_tokens: int = Field(default=1024, gt=0)
    temperature: float | None = Field(default=None, ge=0.0, le=1.0)
    extra_body: dict[str, Any] = Field(default_factory=dict)

    @field_validator("base_url")
    @classmethod
    def _validate_base_url(cls, value: str) -> str:
        return _validate_http_url(value)


class GeminiAdapterConfig(CredentialedHTTPAdapterConfig):
    """Configuration for Google Gemini generateContent APIs."""

    base_url: str = "https://generativelanguage.googleapis.com"
    model: str = Field(min_length=1)
    api_key_env_var: str | None = "GEMINI_API_KEY"
    api_version: str = Field(default="v1beta", min_length=1)
    temperature: float | None = Field(default=None, ge=0.0, le=2.0)
    max_output_tokens: int | None = Field(default=None, gt=0)
    extra_body: dict[str, Any] = Field(default_factory=dict)

    @field_validator("base_url")
    @classmethod
    def _validate_base_url(cls, value: str) -> str:
        return _validate_http_url(value)


class OllamaAdapterConfig(CredentialedHTTPAdapterConfig):
    """Configuration for local Ollama REST APIs."""

    base_url: str = "http://localhost:11434"
    model: str = Field(min_length=1)
    api_key_env_var: str | None = None
    allow_unauthenticated: bool = True
    keep_alive: str | None = None
    options: dict[str, Any] = Field(default_factory=dict)

    @field_validator("base_url")
    @classmethod
    def _validate_base_url(cls, value: str) -> str:
        return _validate_http_url(value)


class GenericHTTPAdapterConfig(CredentialedHTTPAdapterConfig):
    """Configuration for arbitrary HTTP/REST AI applications with customizable mappings."""

    endpoint_url: str
    method: str = Field(default="POST")
    health_check_url: str | None = None
    allow_unauthenticated: bool = True
    auth_header_name: str = Field(default="Authorization", min_length=1)
    auth_scheme: str | None = "Bearer"
    prompt_field: str = Field(default="prompt", min_length=1)
    history_field: str | None = "conversation_history"
    system_context_field: str | None = "system_context"
    metadata_field: str | None = "metadata"
    static_payload: dict[str, Any] = Field(default_factory=dict)
    response_text_path: str = Field(default="response", min_length=1)
    model_name_path: str | None = None
    input_tokens_path: str | None = None
    output_tokens_path: str | None = None
    total_tokens_path: str | None = None
    model_name: str = Field(default="custom-http-app", min_length=1)
    provider: str = Field(default="http", min_length=1)

    @field_validator("endpoint_url")
    @classmethod
    def _validate_endpoint_url(cls, value: str) -> str:
        return _validate_http_url(value)

    @field_validator("health_check_url")
    @classmethod
    def _validate_health_url(cls, value: str | None) -> str | None:
        return _validate_http_url(value) if value is not None else None

    @field_validator("method")
    @classmethod
    def _validate_method(cls, value: str) -> str:
        upper = value.strip().upper()
        if upper not in {"GET", "POST", "PUT", "PATCH"}:
            raise ValueError(f"Unsupported HTTP method: {value!r}")
        return upper


class CustomPythonAdapterConfig(BaseAdapterConfig):
    """Configuration for wrapping an in-process Python AI callable or object."""

    model_name: str = Field(default="custom-python-target", min_length=1)
    provider: str = Field(default="python", min_length=1)
