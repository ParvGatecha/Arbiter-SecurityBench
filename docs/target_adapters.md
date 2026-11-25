# Universal Target Adapter Framework

The **Arbiter SecurityBench Target Adapter Framework** (`arbiter_securitybench.adapters`) provides a unified, extensible interface for connecting LLMs, RAG pipelines, local models, custom HTTP AI services, and in-process Python AI applications to the benchmarking platform.

---

## 1. Architecture & Core Contract

Every target adapter implements `TargetAdapter` (`arbiter_securitybench.adapters.TargetAdapter`):

- `async connect() -> None` — Validates credentials (from environment variables) and initializes client connections.
- `async send_prompt(request: AdapterRequest) -> AdapterResponse` — Sends a standardized prompt payload and returns normalized text, raw payload, latency, token usage, and model metadata.
- `get_target_info() -> TargetInfo` — Returns non-secret target metadata and capabilities.
- `async health_check() -> bool` — Probes connectivity and credentials without raising unhandled exceptions.
- `async close() -> None` — Releases underlying HTTP clients or resources.

`TargetAdapter` also supports `async with adapter:` and bridges directly to `BenchmarkTargetAdapter.execute(...)`, so any adapter can be registered in `TargetAdapterRegistry` and executed by `BenchmarkExecutionEngine`.

### Standardized Request & Response Models

- **`AdapterRequest`**: `prompt`, `conversation_history`, `system_context`, `metadata`, `timeout`
- **`AdapterResponse`**: `response_text`, `raw_response`, `latency`, `token_usage`, `model_information`, `execution_metadata`

### Built-In Resilience & Security Controls

- **Environment-Variable Credentials:** API keys are resolved via `api_key_env_var` (e.g., `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`) and excluded from serialized config dumps (`SecretStr(..., exclude=True)`).
- **Secret-Safe Logging:** Adapter logs emit operational metadata (`target_id`, `adapter_type`, `status_code`, `latency_seconds`) and never log API keys or prompts.
- **Timeouts, Retries & Rate Limiting:** All adapters support configurable `timeout_seconds`, `RetryPolicyConfig` (bounded exponential backoff honoring `Retry-After` on HTTP `429` and transient `5xx`/network errors, never retrying `401`/`403`), and `RateLimitConfig` (async token-bucket rate limiting).

---

## 2. Supported Built-In Adapter Types

| `adapter_type` | Class | Config Class | Default Credential Env Var |
|---|---|---|---|
| `openai` | `OpenAICompatibleAdapter` | `OpenAIAdapterConfig` | `OPENAI_API_KEY` |
| `anthropic` | `AnthropicAdapter` | `AnthropicAdapterConfig` | `ANTHROPIC_API_KEY` |
| `gemini` | `GeminiAdapter` | `GeminiAdapterConfig` | `GEMINI_API_KEY` |
| `ollama` | `OllamaAdapter` | `OllamaAdapterConfig` | *(none; `allow_unauthenticated=True`)* |
| `http` | `GenericHTTPAdapter` | `GenericHTTPAdapterConfig` | *(optional `api_key_env_var`)* |
| `python` | `CustomPythonAdapter` | `CustomPythonAdapterConfig` | *(in-process)* |

---

## 3. Working Examples

### Example A: Connecting an OpenAI-Compatible Model

Set your API key in the environment (never hardcode it in source files):

```bash
export OPENAI_API_KEY="your-api-key"
```

```python
import asyncio
from arbiter_securitybench.adapters import (
    AdapterRequest,
    OpenAIAdapterConfig,
    OpenAICompatibleAdapter,
    RateLimitConfig,
    RetryPolicyConfig,
)

async def main() -> None:
    config = OpenAIAdapterConfig(
        target_id="openai-gpt4o-mini",
        base_url="https://api.openai.com/v1",  # or a local vLLM / LiteLLM URL
        model="gpt-4o-mini",
        api_key_env_var="OPENAI_API_KEY",
        temperature=0.0,
        timeout_seconds=30.0,
        retry_policy=RetryPolicyConfig(max_retries=2, initial_backoff_seconds=0.5),
        rate_limit=RateLimitConfig(requests_per_second=5.0, burst_capacity=2),
    )

    async with OpenAICompatibleAdapter(config) as adapter:
        if not await adapter.health_check():
            raise RuntimeError("Target failed health check")

        response = await adapter.send_prompt(
            AdapterRequest(
                prompt="Summarize our security policy.",
                system_context="You are a security assistant.",
            )
        )
        print(response.response_text)
        print("Latency (s):", response.latency)
        print("Token usage:", response.token_usage)

asyncio.run(main())
```

---

### Example B: Connecting an Ollama Local Model

Ensure Ollama is running locally (`ollama serve` and `ollama pull llama3.2`):

```python
import asyncio
from arbiter_securitybench.adapters import (
    AdapterRequest,
    OllamaAdapter,
    OllamaAdapterConfig,
)

async def main() -> None:
    config = OllamaAdapterConfig(
        target_id="local-llama3",
        base_url="http://localhost:11434",
        model="llama3.2",
        timeout_seconds=60.0,
        options={"temperature": 0.0},
    )

    async with OllamaAdapter(config) as adapter:
        healthy = await adapter.health_check()
        print("Ollama healthy:", healthy)

        response = await adapter.send_prompt(
            AdapterRequest(
                prompt="Explain why prompt injection happens.",
                system_context="Respond concisely.",
            )
        )
        print(response.response_text)
        print("Model:", response.model_information.model_name)

asyncio.run(main())
```

---

### Example C: Connecting a Custom FastAPI Application

Suppose you have a custom FastAPI AI service running on `http://localhost:8080`:

```python
# custom_app.py (target AI application under test)
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class ChatInput(BaseModel):
    query: str
    context: str | None = None

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}

@app.post("/v1/ask")
def ask(payload: ChatInput) -> dict[str, object]:
    return {
        "result": {"text": f"Processed query safely: {payload.query}", "model": "custom-rag-v1"},
        "usage": {"input": 10, "output": 12},
    }
```

Connect Arbiter SecurityBench to this FastAPI service using `GenericHTTPAdapter` with declarative dot-path mappings (or Python `request_mapper` / `response_mapper` callables for arbitrary schemas):

```python
import asyncio
from arbiter_securitybench.adapters import (
    AdapterRequest,
    GenericHTTPAdapter,
    GenericHTTPAdapterConfig,
)
from arbiter_securitybench.contracts import TargetModality

async def main() -> None:
    config = GenericHTTPAdapterConfig(
        target_id="custom-fastapi-rag",
        target_type=TargetModality.RAG,
        endpoint_url="http://localhost:8080/v1/ask",
        health_check_url="http://localhost:8080/health",
        prompt_field="query",
        system_context_field="context",
        response_text_path="result.text",
        model_name_path="result.model",
        input_tokens_path="usage.input",
        output_tokens_path="usage.output",
    )

    async with GenericHTTPAdapter(config) as adapter:
        assert await adapter.health_check()
        response = await adapter.send_prompt(
            AdapterRequest(
                prompt="List approved compliance controls.",
                system_context="Restrict answers to public policy documents.",
            )
        )
        print(response.response_text)

asyncio.run(main())
```

---

## 4. Defining Custom Adapters Without Modifying the Framework

Developers can wrap in-process Python AI pipelines directly with `CustomPythonAdapter`, or define a full custom `TargetAdapter` subclass and register it with `@register_adapter` or `TargetAdapterRegistry.register_adapter_type`:

```python
from arbiter_securitybench.adapters import (
    AdapterRequest,
    AdapterResponse,
    BaseAdapterConfig,
    ModelInformation,
    TargetAdapter,
    TargetAdapterRegistry,
    TargetInfo,
    register_adapter,
)

registry = TargetAdapterRegistry()

@register_adapter("my_agent_gateway", registry=registry)
class MyAgentGatewayAdapter(TargetAdapter):
    @property
    def adapter_type(self) -> str:
        return "my_agent_gateway"

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
            provider="internal",
            model_name="agent-gateway-v1",
        )

    async def send_prompt(self, request: AdapterRequest) -> AdapterResponse:
        return AdapterResponse(
            response_text=f"Handled: {request.prompt}",
            latency=0.001,
            model_information=ModelInformation(
                provider="internal",
                model_name="agent-gateway-v1",
            ),
        )
```
