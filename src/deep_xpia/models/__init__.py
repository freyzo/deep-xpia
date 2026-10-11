"""Model clients: one interface for the live runner across providers.

  ModelClient.complete(...) -> ModelResponse(text, tool_calls, request_id)

Implementations: AnthropicClient (Messages API), OpenAICompatibleClient
(chat completions, also local servers such as vLLM via base_url) and
ScriptedClient (canned replies, for tests). SDKs are imported lazily, so a
missing provider package only matters when that provider is used.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]  # JSON schema of the arguments


@dataclass
class ToolCall:
    name: str
    args: dict[str, Any]
    id: str = ""


@dataclass
class ModelResponse:
    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    request_id: str | None = None
    raw_content: Any = None  # provider message content, for continuing a tool loop


class ModelClient(Protocol):
    provider: str

    def complete(self, *, model: str, system: str, messages: list[dict[str, Any]], max_tokens: int,
                 temperature: float | None = None, tools: Sequence[ToolSpec] | None = None) -> ModelResponse: ...

    def tool_results(self, response: ModelResponse, results: dict[str, str]) -> list[dict[str, Any]]:
        """Messages that hand tool results back after `response` (assistant turn + results)."""
        ...


class AnthropicClient:
    provider = "anthropic"

    def __init__(self) -> None:
        try:
            import anthropic
        except ImportError:
            raise RuntimeError("anthropic package required for live mode: pip install anthropic")
        self._client = anthropic.Anthropic()

    def complete(self, *, model: str, system: str, messages: list[dict[str, Any]], max_tokens: int,
                 temperature: float | None = None, tools: Sequence[ToolSpec] | None = None) -> ModelResponse:
        params: dict[str, Any] = {"model": model, "max_tokens": max_tokens, "system": system, "messages": messages}
        if temperature is not None:  # omit -> API default, as in the v2 runs
            params["temperature"] = temperature
        if tools:
            params["tools"] = [{"name": t.name, "description": t.description, "input_schema": t.parameters} for t in tools]
        msg = self._client.messages.create(**params)
        texts, calls = [], []
        for block in msg.content or []:
            if getattr(block, "type", None) == "tool_use":
                calls.append(ToolCall(block.name, dict(block.input or {}), str(block.id)))
            else:
                text = getattr(block, "text", "")
                if isinstance(text, str):
                    texts.append(text)
        rid = getattr(msg, "id", None)
        return ModelResponse("".join(texts), calls, rid if isinstance(rid, str) else None, msg.content)

    def tool_results(self, response: ModelResponse, results: dict[str, str]) -> list[dict[str, Any]]:
        return [
            {"role": "assistant", "content": response.raw_content},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": cid, "content": out} for cid, out in results.items()
            ]},
        ]


class OpenAICompatibleClient:
    provider = "openai"

    def __init__(self, base_url: str | None = None) -> None:
        try:
            import openai  # type: ignore[import-not-found]  # optional provider
        except ImportError:
            raise RuntimeError("openai package required for this provider: pip install openai")
        self._client = openai.OpenAI(base_url=base_url) if base_url else openai.OpenAI()

    def complete(self, *, model: str, system: str, messages: list[dict[str, Any]], max_tokens: int,
                 temperature: float | None = None, tools: Sequence[ToolSpec] | None = None) -> ModelResponse:
        params: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": [{"role": "system", "content": system}, *messages],
        }
        if temperature is not None:
            params["temperature"] = temperature
        if tools:
            params["tools"] = [{"type": "function", "function": {
                "name": t.name, "description": t.description, "parameters": t.parameters}} for t in tools]
        resp = self._client.chat.completions.create(**params)
        message = resp.choices[0].message
        calls = [ToolCall(tc.function.name, json.loads(tc.function.arguments or "{}"), str(tc.id))
                 for tc in (message.tool_calls or [])]
        rid = getattr(resp, "id", None)
        return ModelResponse(message.content or "", calls, rid if isinstance(rid, str) else None, message)

    def tool_results(self, response: ModelResponse, results: dict[str, str]) -> list[dict[str, Any]]:
        assistant = {
            "role": "assistant",
            "content": response.text,
            "tool_calls": [{"id": c.id, "type": "function",
                            "function": {"name": c.name, "arguments": json.dumps(c.args)}} for c in response.tool_calls],
        }
        return [assistant, *({"role": "tool", "tool_call_id": cid, "content": out} for cid, out in results.items())]


class ScriptedClient:
    """Deterministic client for tests: replies come from a function of the call."""

    provider = "scripted"

    def __init__(self, reply: Callable[[dict[str, Any]], ModelResponse]) -> None:
        self.reply = reply
        self.calls: list[dict[str, Any]] = []

    def complete(self, *, model: str, system: str, messages: list[dict[str, Any]], max_tokens: int,
                 temperature: float | None = None, tools: Sequence[ToolSpec] | None = None) -> ModelResponse:
        call = {"model": model, "system": system, "messages": messages, "max_tokens": max_tokens,
                "temperature": temperature, "tools": list(tools or [])}
        self.calls.append(call)
        return self.reply(call)

    def tool_results(self, response: ModelResponse, results: dict[str, str]) -> list[dict[str, Any]]:
        return [{"role": "assistant", "content": response.text, "tool_calls": [c.id for c in response.tool_calls]},
                {"role": "user", "content": [{"tool_result": cid, "content": out} for cid, out in results.items()]}]


PROVIDERS = ("anthropic", "openai")


def make_client(provider: str = "anthropic", base_url: str | None = None) -> ModelClient:
    if provider == "anthropic":
        return AnthropicClient()
    if provider == "openai":
        return OpenAICompatibleClient(base_url=base_url)
    raise ValueError(f"unknown provider {provider!r}; expected one of: {', '.join(PROVIDERS)}")
