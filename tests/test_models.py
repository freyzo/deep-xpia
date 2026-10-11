"""Model clients (deep_xpia.models): request mapping and response parsing with mocked SDKs."""

from __future__ import annotations

import json
import sys
from types import SimpleNamespace as NS
from typing import Any
from unittest import mock

import pytest

from deep_xpia.models import AnthropicClient, OpenAICompatibleClient, ToolSpec, make_client

TOOL = ToolSpec("send_email", "Send an email", {"type": "object", "properties": {"target": {"type": "string"}}})


def _anthropic(reply: Any) -> tuple[AnthropicClient, list[dict[str, Any]]]:
    calls: list[dict[str, Any]] = []
    sdk = mock.Mock()
    sdk.messages.create.side_effect = lambda **kw: calls.append(kw) or reply
    with mock.patch.dict(sys.modules, {"anthropic": mock.Mock(Anthropic=lambda: sdk)}):
        return AnthropicClient(), calls


def test_anthropic_request_and_tool_use_parsing() -> None:
    reply = NS(id="msg_1", content=[NS(type="text", text="Sending now."),
                                    NS(type="tool_use", name="send_email", input={"target": "a@b"}, id="tu_1")])
    client, calls = _anthropic(reply)
    resp = client.complete(model="m", system="sys", messages=[{"role": "user", "content": "hi"}],
                           max_tokens=10, tools=[TOOL])
    assert calls[0]["system"] == "sys" and "temperature" not in calls[0]
    assert calls[0]["tools"][0]["input_schema"] == TOOL.parameters
    assert resp.text == "Sending now." and resp.request_id == "msg_1"
    assert [(c.name, c.args, c.id) for c in resp.tool_calls] == [("send_email", {"target": "a@b"}, "tu_1")]
    follow = client.tool_results(resp, {"tu_1": "ok"})
    assert follow[1]["content"][0] == {"type": "tool_result", "tool_use_id": "tu_1", "content": "ok"}


def test_anthropic_temperature_passed_when_set() -> None:
    client, calls = _anthropic(NS(id=None, content=[NS(type="text", text="x")]))
    client.complete(model="m", system="s", messages=[], max_tokens=5, temperature=0.0)
    assert calls[0]["temperature"] == 0.0


def test_openai_compatible_mapping() -> None:
    calls: list[dict[str, Any]] = []
    tc = NS(id="call_1", function=NS(name="send_email", arguments=json.dumps({"target": "x"})))
    reply = NS(id="cmpl_1", choices=[NS(message=NS(content="ok", tool_calls=[tc]))])
    sdk = mock.Mock()
    sdk.chat.completions.create.side_effect = lambda **kw: calls.append(kw) or reply
    with mock.patch.dict(sys.modules, {"openai": mock.Mock(OpenAI=lambda **kw: sdk)}):
        client = OpenAICompatibleClient(base_url="http://localhost:8001/v1")
    resp = client.complete(model="m", system="sys", messages=[{"role": "user", "content": "hi"}], max_tokens=5, tools=[TOOL])
    assert calls[0]["messages"][0] == {"role": "system", "content": "sys"}
    assert calls[0]["tools"][0]["function"]["parameters"] == TOOL.parameters
    assert resp.text == "ok" and resp.tool_calls[0].args == {"target": "x"} and resp.request_id == "cmpl_1"
    follow = client.tool_results(resp, {"call_1": "done"})
    assert follow[-1] == {"role": "tool", "tool_call_id": "call_1", "content": "done"}


def test_unknown_provider_rejected() -> None:
    with pytest.raises(ValueError):
        make_client("gemini")


def test_runner_accepts_an_injected_client() -> None:
    from deep_xpia.bench.runner import BenchRunner
    from deep_xpia.models import ModelResponse, ScriptedClient

    client = ScriptedClient(lambda call: ModelResponse("Here is the summary."))
    runner = BenchRunner("deepxpiabench-v2.jsonl", n_runs=1, client=client)
    case = runner._load_dataset()[0]
    result = runner._run_live(case, 0)
    assert client.calls and result.agent_outputs[0]["output"] == "Here is the summary."
    assert result.run_metadata["provider"] == "anthropic"
