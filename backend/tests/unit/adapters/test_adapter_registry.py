"""Unit tests for TargetAdapterRegistry instance and plugin-type registration."""

from __future__ import annotations

import pytest

from arbiter_securitybench.adapters import (
    AdapterRequest,
    AdapterResponse,
    BaseAdapterConfig,
    CustomPythonAdapter,
    CustomPythonAdapterConfig,
    ModelInformation,
    OpenAIAdapterConfig,
    TargetAdapter,
    TargetAdapterRegistry,
    TargetInfo,
    register_adapter,
)
from arbiter_securitybench.contracts import DuplicateRegistrationError, NotFoundError


class _CustomPluginConfig(BaseAdapterConfig):
    greeting: str = "hello"


class _CustomPluginAdapter(TargetAdapter):
    def __init__(self, config: _CustomPluginConfig) -> None:
        super().__init__(config)
        self._cfg = config

    @property
    def adapter_type(self) -> str:
        return "custom_plugin"

    async def connect(self) -> None:
        self._connected = True

    async def close(self) -> None:
        self._connected = False

    async def health_check(self) -> bool:
        return True

    def get_target_info(self) -> TargetInfo:
        return TargetInfo(
            target_id=self.target_id,
            adapter_type=self.adapter_type,
            provider="custom",
            model_name="plugin-v1",
        )

    async def send_prompt(self, request: AdapterRequest) -> AdapterResponse:
        return AdapterResponse(
            response_text=f"{self._cfg.greeting}:{request.prompt}",
            latency=0.0,
            model_information=ModelInformation(provider="custom", model_name="plugin-v1"),
        )


def test_builtin_adapter_types_and_instance_registration() -> None:
    registry = TargetAdapterRegistry()
    assert set(registry.list_adapter_types()) >= {
        "anthropic",
        "gemini",
        "http",
        "ollama",
        "openai",
        "python",
    }

    adapter = registry.create_adapter(
        "openai",
        OpenAIAdapterConfig(target_id="oai-reg", model="gpt-4o-mini"),
        register_instance=True,
    )
    assert registry.get("oai-reg") is adapter
    assert registry.list_target_ids() == ["oai-reg"]

    with pytest.raises(DuplicateRegistrationError):
        registry.register(adapter)

    with pytest.raises(NotFoundError):
        registry.get("missing-target")

    with pytest.raises(NotFoundError):
        registry.create_adapter("unknown-adapter-type")


@pytest.mark.asyncio
async def test_developer_can_register_custom_adapter_via_decorator_without_modifying_framework() -> None:
    isolated_registry = TargetAdapterRegistry(include_builtins=False)

    @register_adapter("my_echo_plugin", registry=isolated_registry)
    class DecoratedPluginAdapter(_CustomPluginAdapter):
        pass

    assert isolated_registry.list_adapter_types() == ["my_echo_plugin"]
    instance = isolated_registry.create_adapter(
        "my_echo_plugin",
        _CustomPluginConfig(target_id="plugin-1", greeting="hi"),
        register_instance=True,
    )
    assert isinstance(instance, TargetAdapter)
    async with instance:
        resp = await instance.send_prompt(AdapterRequest(prompt="world"))
    assert resp.response_text == "hi:world"

    py_instance = CustomPythonAdapter(
        CustomPythonAdapterConfig(target_id="py-direct"),
        lambda r: r.prompt,
    )
    isolated_registry.register(py_instance)
    assert isolated_registry.list_target_ids() == ["plugin-1", "py-direct"]

    with pytest.raises(DuplicateRegistrationError):
        isolated_registry.register_adapter_type("my_echo_plugin", DecoratedPluginAdapter)
