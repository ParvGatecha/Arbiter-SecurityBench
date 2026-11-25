"""Universal target adapter framework for LLMs, RAG systems, and custom AI apps."""

from arbiter_securitybench.adapters.anthropic_adapter import AnthropicAdapter
from arbiter_securitybench.adapters.base import BaseHTTPTargetAdapter, TargetAdapter
from arbiter_securitybench.adapters.errors import (
    AdapterAuthenticationError,
    AdapterConnectionError,
    AdapterRateLimitError,
    AdapterResponseError,
)
from arbiter_securitybench.adapters.gemini_adapter import GeminiAdapter
from arbiter_securitybench.adapters.http_adapter import (
    GenericHTTPAdapter,
    RequestMapper,
    ResponseMapper,
)
from arbiter_securitybench.adapters.models import (
    AdapterRequest,
    AdapterResponse,
    AnthropicAdapterConfig,
    BaseAdapterConfig,
    ConversationMessage,
    CredentialedHTTPAdapterConfig,
    CustomPythonAdapterConfig,
    GeminiAdapterConfig,
    GenericHTTPAdapterConfig,
    ModelInformation,
    OllamaAdapterConfig,
    OpenAIAdapterConfig,
    RateLimitConfig,
    RetryPolicyConfig,
    TargetInfo,
    TokenUsage,
)
from arbiter_securitybench.adapters.ollama_adapter import OllamaAdapter
from arbiter_securitybench.adapters.openai_adapter import OpenAICompatibleAdapter
from arbiter_securitybench.adapters.python_adapter import (
    CustomPythonAdapter,
    PythonTargetCallable,
)
from arbiter_securitybench.adapters.registry import (
    AdapterFactory,
    TargetAdapterRegistry,
    register_adapter,
)
from arbiter_securitybench.adapters.resilience import AsyncTokenBucketRateLimiter
from arbiter_securitybench.contracts import (
    BenchmarkTargetAdapter,
    TargetExecutionRequest,
    TargetExecutionResponse,
)

__all__ = [
    "AdapterAuthenticationError",
    "AdapterConnectionError",
    "AdapterFactory",
    "AdapterRateLimitError",
    "AdapterRequest",
    "AdapterResponse",
    "AdapterResponseError",
    "AnthropicAdapter",
    "AnthropicAdapterConfig",
    "AsyncTokenBucketRateLimiter",
    "BaseAdapterConfig",
    "BaseHTTPTargetAdapter",
    "BenchmarkTargetAdapter",
    "ConversationMessage",
    "CredentialedHTTPAdapterConfig",
    "CustomPythonAdapter",
    "CustomPythonAdapterConfig",
    "GeminiAdapter",
    "GeminiAdapterConfig",
    "GenericHTTPAdapter",
    "GenericHTTPAdapterConfig",
    "ModelInformation",
    "OllamaAdapter",
    "OllamaAdapterConfig",
    "OpenAIAdapterConfig",
    "OpenAICompatibleAdapter",
    "PythonTargetCallable",
    "RateLimitConfig",
    "RequestMapper",
    "ResponseMapper",
    "RetryPolicyConfig",
    "TargetAdapter",
    "TargetAdapterRegistry",
    "TargetExecutionRequest",
    "TargetExecutionResponse",
    "TargetInfo",
    "TokenUsage",
    "register_adapter",
]
