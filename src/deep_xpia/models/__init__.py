"""Model clients: one interface for the live runner across providers.

  ModelClient.complete(...) -> ModelResponse(text, tool_calls, request_id)

Implementations: AnthropicClient (Messages API), OpenAICompatibleClient
(chat completions, also local servers such as vLLM via base_url) and
ScriptedClient (canned replies, for tests). SDKs are imported lazily, so a
missing provider package only matters when that provider is used.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
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
        content = response.raw_content
        if content is None:  # e.g. replayed from cache: rebuild the assistant turn as plain blocks
            content = ([{"type": "text", "text": response.text}] if response.text else []) + [
                {"type": "tool_use", "id": c.id, "name": c.name, "input": c.args} for c in response.tool_calls]
        return [
            {"role": "assistant", "content": content},
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


def _jsonable(value: Any) -> Any:
    """Stable JSON form of request content, including provider SDK objects."""
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if hasattr(value, "model_dump"):
        return _jsonable(value.model_dump())
    if hasattr(value, "__dict__"):
        return _jsonable({k: v for k, v in vars(value).items() if not k.startswith("_")})
    return str(value)


class CachingClient:
    """Wraps a client; identical requests are answered from a JSON file per request.

    Key = sha256 of (provider, model, system, messages, max_tokens, temperature,
    tools). Lets a run be replayed, and its outputs re-scored, without new calls.
    """

    def __init__(self, inner: ModelClient, cache_dir: str | Path) -> None:
        self.inner = inner
        self.provider = inner.provider
        self.dir = Path(cache_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.hits = self.misses = 0

    def key(self, **request: Any) -> str:
        blob = json.dumps(_jsonable({"provider": self.provider, **request}), sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(blob.encode()).hexdigest()

    def complete(self, *, model: str, system: str, messages: list[dict[str, Any]], max_tokens: int,
                 temperature: float | None = None, tools: Sequence[ToolSpec] | None = None) -> ModelResponse:
        key = self.key(model=model, system=system, messages=messages, max_tokens=max_tokens,
                       temperature=temperature, tools=[asdict(t) for t in tools or []])
        path = self.dir / f"{key}.json"
        if path.exists():
            self.hits += 1
            data = json.loads(path.read_text())
            return ModelResponse(data["text"], [ToolCall(**c) for c in data["tool_calls"]], data["request_id"])
        self.misses += 1
        resp = self.inner.complete(model=model, system=system, messages=messages, max_tokens=max_tokens,
                                   temperature=temperature, tools=tools)
        path.write_text(json.dumps({"text": resp.text, "tool_calls": [asdict(c) for c in resp.tool_calls],
                                    "request_id": resp.request_id}, ensure_ascii=False, sort_keys=True))
        return resp

    def tool_results(self, response: ModelResponse, results: dict[str, str]) -> list[dict[str, Any]]:
        return self.inner.tool_results(response, results)


PROVIDERS = ("anthropic", "openai")


def make_client(provider: str = "anthropic", base_url: str | None = None) -> ModelClient:
    if provider == "anthropic":
        return AnthropicClient()
    if provider == "openai":
        return OpenAICompatibleClient(base_url=base_url)
    raise ValueError(f"unknown provider {provider!r}; expected one of: {', '.join(PROVIDERS)}")
