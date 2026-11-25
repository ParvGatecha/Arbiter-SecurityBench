"""Target adapter instance and extensible adapter-type plugin registry."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from arbiter_securitybench.adapters.anthropic_adapter import AnthropicAdapter
from arbiter_securitybench.adapters.gemini_adapter import GeminiAdapter
from arbiter_securitybench.adapters.http_adapter import GenericHTTPAdapter
from arbiter_securitybench.adapters.ollama_adapter import OllamaAdapter
from arbiter_securitybench.adapters.openai_adapter import OpenAICompatibleAdapter
from arbiter_securitybench.adapters.python_adapter import CustomPythonAdapter
from arbiter_securitybench.contracts import (
    BenchmarkTargetAdapter,
    DuplicateRegistrationError,
    NotFoundError,
)

AdapterFactory = Callable[..., BenchmarkTargetAdapter]

_DEFAULT_ADAPTER_FACTORIES: dict[str, AdapterFactory] = {
    "openai": OpenAICompatibleAdapter,
    "anthropic": AnthropicAdapter,
    "gemini": GeminiAdapter,
    "ollama": OllamaAdapter,
    "http": GenericHTTPAdapter,
    "python": CustomPythonAdapter,
}


def register_adapter(
    adapter_type: str,
    *,
    registry: TargetAdapterRegistry | None = None,
) -> Callable[[AdapterFactory], AdapterFactory]:
    """Class/factory decorator allowing developers to register custom adapters cleanly."""
    normalized = adapter_type.strip().lower()
    if not normalized:
        raise ValueError("adapter_type must be a non-empty string.")

    def _decorator(factory: AdapterFactory) -> AdapterFactory:
        if registry is not None:
            registry.register_adapter_type(normalized, factory)
        else:
            if normalized in _DEFAULT_ADAPTER_FACTORIES:
                raise DuplicateRegistrationError(
                    f"Adapter type {normalized!r} is already registered globally.",
                    component="adapters.registry",
                    details={"adapter_type": normalized},
                )
            _DEFAULT_ADAPTER_FACTORIES[normalized] = factory
        return factory

    return _decorator


class TargetAdapterRegistry:
    """Resolves target_id instances and extensible adapter_type factories."""

    def __init__(self, *, include_builtins: bool = True) -> None:
        self._adapters: dict[str, BenchmarkTargetAdapter] = {}
        self._factories: dict[str, AdapterFactory] = (
            dict(_DEFAULT_ADAPTER_FACTORIES) if include_builtins else {}
        )

    def register(self, adapter: BenchmarkTargetAdapter) -> None:
        """Register an instantiated target adapter by its unique target_id."""
        if adapter.target_id in self._adapters:
            raise DuplicateRegistrationError(
                f"Target adapter {adapter.target_id!r} is already registered.",
                component="adapters.registry",
                details={"target_id": adapter.target_id},
            )
        self._adapters[adapter.target_id] = adapter

    def get(self, target_id: str) -> BenchmarkTargetAdapter:
        """Retrieve a registered adapter instance by target_id."""
        adapter = self._adapters.get(target_id)
        if adapter is None:
            raise NotFoundError(
                f"Target adapter {target_id!r} is not registered.",
                component="adapters.registry",
                details={"target_id": target_id},
            )
        return adapter

    def list_target_ids(self) -> list[str]:
        """Return sorted list of registered target_id values."""
        return sorted(self._adapters)

    def register_adapter_type(
        self,
        adapter_type: str,
        factory: AdapterFactory,
        *,
        overwrite: bool = False,
    ) -> None:
        """Register a custom adapter class/factory under an adapter_type key."""
        normalized = adapter_type.strip().lower()
        if not normalized:
            raise ValueError("adapter_type must be a non-empty string.")
        if normalized in self._factories and not overwrite:
            raise DuplicateRegistrationError(
                f"Adapter type {normalized!r} is already registered.",
                component="adapters.registry",
                details={"adapter_type": normalized},
            )
        self._factories[normalized] = factory

    def list_adapter_types(self) -> list[str]:
        """Return sorted list of available adapter_type keys."""
        return sorted(self._factories)

    def create_adapter(
        self,
        adapter_type: str,
        *args: Any,
        register_instance: bool = False,
        **kwargs: Any,
    ) -> BenchmarkTargetAdapter:
        """Instantiate an adapter by adapter_type, optionally registering the instance."""
        normalized = adapter_type.strip().lower()
        factory = self._factories.get(normalized)
        if factory is None:
            raise NotFoundError(
                f"Adapter type {normalized!r} is not registered.",
                component="adapters.registry",
                details={"adapter_type": normalized},
            )
        instance = factory(*args, **kwargs)
        if register_instance:
            self.register(instance)
        return instance
