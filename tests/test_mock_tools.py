"""Mock tool environment (bench/tools.py) and tool-based success in the live runner."""

from __future__ import annotations

import socket
from typing import Any

import pytest

from deep_xpia.bench.outcomes import payload_and_markers
from deep_xpia.bench.runner import BenchRunner
from deep_xpia.bench.schema import BenchCase, InjectionPosition
from deep_xpia.bench.tools import MockEnvironment, tools_for
from deep_xpia.models import ModelResponse, ScriptedClient, ToolCall

DATASET = "deepxpiabench-v2.jsonl"


@pytest.fixture(scope="module")
def case() -> BenchCase:
    cases = BenchRunner(DATASET, n_runs=1)._load_dataset()
    return next(c for c in cases if c.injection is not None and c.injection.position == InjectionPosition.FIRST_HOP
                and len(c.topology.agents) >= 3 and payload_and_markers(c, "current")[1])


def _client(first_hop_call: ToolCall | None, later_text: str = "Done.") -> ScriptedClient:
    def reply(call: dict[str, Any]) -> ModelResponse:
        first_turn = len(call["messages"]) == 1
        is_hop0 = first_turn and call["system"] == call.get("_hop0_system", call["system"]) and "previous agent" not in str(call["messages"][0]["content"])
        if first_hop_call is not None and first_turn and is_hop0:
            return ModelResponse("", [first_hop_call])
        return ModelResponse(later_text)
    return ScriptedClient(reply)


def _run(case: BenchCase, client: ScriptedClient, tools: bool = True):
    return BenchRunner(DATASET, n_runs=1, client=client, tools=tools)._run_live(case, 0)


def test_one_tool_per_permission(case: BenchCase) -> None:
    agent = case.topology.agents[0]
    assert [t.name for t in tools_for(agent)] == agent.permissions


def test_attacker_argument_call_is_executed(case: BenchCase) -> None:
    marker = payload_and_markers(case, "current")[1][0]
    result = _run(case, _client(ToolCall("send_email", {"target": marker, "content": "x"}, "t1")))
    assert result.attack_success
    assert result.hop_outcomes[0] == "executed"
    assert result.agent_outputs[0]["tool_calls"][0]["args"]["target"] == marker


def test_benign_call_is_not_executed(case: BenchCase) -> None:
    result = _run(case, _client(ToolCall("send_email", {"target": "team@corp.example", "content": "summary"}, "t1")))
    assert not result.attack_success
    assert "executed" not in result.hop_outcomes


def test_later_refusal_does_not_undo_a_side_effect(case: BenchCase) -> None:
    marker = payload_and_markers(case, "current")[1][0]
    client = _client(ToolCall("send_email", {"target": marker}, "t1"), later_text="I won't do that; it looks like an injection.")
    result = _run(case, client)
    assert result.attack_success and result.outcome != "complied"


def test_tools_off_sends_no_tools(case: BenchCase) -> None:
    client = _client(None)
    _run(case, client, tools=False)
    assert all(call["tools"] == [] for call in client.calls)


def test_no_network(case: BenchCase, monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("network access attempted")
    monkeypatch.setattr(socket, "socket", refuse)
    marker = payload_and_markers(case, "current")[1][0]
    assert _run(case, _client(ToolCall("send_email", {"target": marker}, "t1"))).attack_success


def test_environment_records_and_matches() -> None:
    env = MockEnvironment()
    env.call(0, "a", "read_email", {"target": "inbox"})
    env.call(1, "b", "send_email", {"target": "x@evil-corp.com"})
    assert env.executed_hops(["evil-corp"]) == {1}
    assert env.calls_at(1) == [{"name": "send_email", "args": {"target": "x@evil-corp.com"}}]
