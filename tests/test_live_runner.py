"""Live-mode runner behaviour with a mocked Anthropic client (no network)."""

from __future__ import annotations

import sys
from typing import Any
from unittest import mock

import pytest

from deep_xpia.bench.runner import BenchRunner
from deep_xpia.bench.schema import BenchCase, InjectionPosition

DATASET = "deepxpiabench-v2.jsonl"


def _run(case: BenchCase, defense: str = "none", **runner_kw: Any) -> tuple[Any, list[dict[str, Any]]]:
    calls: list[dict[str, Any]] = []

    def create(**kw: Any) -> Any:
        calls.append(kw)
        return mock.Mock(content=[mock.Mock(text="ok, done.")])

    client = mock.Mock()
    client.messages.create.side_effect = create
    runner = BenchRunner(DATASET, defense=defense, n_runs=1, **runner_kw)
    with mock.patch.dict(sys.modules, {"anthropic": mock.Mock(Anthropic=lambda: client)}):
        result = runner._run_live(case, 0)
    return result, calls


@pytest.fixture(scope="module")
def cases() -> list[BenchCase]:
    return BenchRunner(DATASET, n_runs=1)._load_dataset()


def _first(cases: list[BenchCase], taxonomy: str) -> BenchCase:
    return next(c for c in cases if c.taxonomy_id and c.taxonomy_id.value == taxonomy)


class TestRegistryInjection:
    def test_manifest_in_first_agent_system_prompt(self, cases: list[BenchCase]) -> None:
        case = _first(cases, "DXPIA-008")
        result, calls = _run(case, "none")
        assert case.tool_metadata is not None
        assert case.tool_metadata["name"] in calls[0]["system"]
        assert all(case.tool_metadata["name"] not in c["system"] for c in calls[1:])
        assert not result.detected

    def test_manifest_not_injected_into_prompt(self, cases: list[BenchCase]) -> None:
        case = _first(cases, "DXPIA-008")
        _, calls = _run(case, "none")
        assert case.injection is not None
        assert case.injection.content not in calls[0]["messages"][0]["content"]

    def test_intent_verify_blocks_at_registration(self, cases: list[BenchCase]) -> None:
        result, calls = _run(_first(cases, "DXPIA-008"), "intent-verify")
        assert result.detected and not result.attack_success
        assert calls == []


class TestPromptInjectionUnchanged:
    def test_system_prompts_are_agent_prompts(self, cases: list[BenchCase]) -> None:
        case = _first(cases, "DXPIA-001")
        _, calls = _run(case, "none")
        assert [c["system"] for c in calls] == [a.system_prompt for a in case.topology.agents[: len(calls)]]

    def test_last_hop_injection_reaches_an_executed_hop(self, cases: list[BenchCase]) -> None:
        case = next(
            c for c in cases
            if c.injection is not None and c.injection.position == InjectionPosition.LAST_HOP
        )
        _, calls = _run(case, "none")
        assert case.injection is not None
        assert any(case.injection.content in c["messages"][0]["content"] for c in calls)
