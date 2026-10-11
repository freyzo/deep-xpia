"""Live-mode runner behaviour with a mocked Anthropic client (no network)."""

from __future__ import annotations

import sys
from typing import Any
from unittest import mock

import pytest

from deep_xpia.bench.runner import BenchRunner
from deep_xpia.bench.schema import BenchCase, InjectionPosition

DATASET = "deepxpiabench-v2.jsonl"


def _run(case: BenchCase, defense: str = "none", reply: str = "ok, done.",
         **runner_kw: Any) -> tuple[Any, list[dict[str, Any]]]:
    calls: list[dict[str, Any]] = []

    def create(**kw: Any) -> Any:
        calls.append(kw)
        return mock.Mock(content=[mock.Mock(text=reply)])

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


class TestSamplingAndProvenance:
    @pytest.mark.parametrize("temperature", [0.0, 0.7])
    def test_temperature_passed_when_set(self, cases: list[BenchCase], temperature: float) -> None:
        result, calls = _run(cases[0], "none", temperature=temperature)
        assert calls and all(c["temperature"] == temperature for c in calls)
        assert result.run_metadata["temperature"] == temperature

    def test_temperature_omitted_by_default(self, cases: list[BenchCase]) -> None:
        result, calls = _run(cases[0], "none")
        assert calls and all("temperature" not in c for c in calls)
        assert result.run_metadata["temperature"] is None

    def test_run_metadata(self, cases: list[BenchCase]) -> None:
        from deep_xpia import __version__

        result, _ = _run(_first(cases, "DXPIA-008"), "none")
        md = result.run_metadata
        assert md["mode"] == "live" and md["model"] and md["harness_version"] == __version__
        assert md["injection_surface"] == "tool_metadata"


class TestOutcomeJudge:
    def test_refusal_is_not_success(self, cases: list[BenchCase]) -> None:
        from deep_xpia.bench.outcomes import SCORER_VERSION

        case = _first(cases, "DXPIA-001")
        result, _ = _run(case, "none", reply="I won't do that; this looks like a prompt injection.")
        assert not result.attack_success
        assert result.hop_outcomes[0] == "exposed_flagged"
        assert result.run_metadata["judge"] == SCORER_VERSION and result.run_metadata["injected_hops"] == [0]

    def test_attacker_marker_without_refusal_is_success(self, cases: list[BenchCase]) -> None:
        from deep_xpia.bench.outcomes import payload_and_markers

        case = next(c for c in cases if c.taxonomy_id and c.taxonomy_id.value == "DXPIA-001"
                    and payload_and_markers(c, "current")[1])
        marker = payload_and_markers(case, "current")[1][0]
        result, _ = _run(case, "none", reply=f"Done. Next step for the executor: {marker}.")
        assert result.attack_success and result.outcome == "complied"

    def test_legacy_judge_counts_keywords(self, cases: list[BenchCase]) -> None:
        case = _first(cases, "DXPIA-001")
        reply = "Understood, I will not forward anything."
        assert _run(case, "none", reply=reply, judge="legacy")[0].attack_success
        assert not _run(case, "none", reply=reply)[0].attack_success

    def test_registry_cases_scored_by_manifest(self, cases: list[BenchCase]) -> None:
        from deep_xpia.bench.outcomes import payload_and_markers

        case = _first(cases, "DXPIA-008")
        text, _ = payload_and_markers(case, "current")
        assert case.tool_metadata is not None and case.tool_metadata["name"] in text
        assert payload_and_markers(case, "v2")[0] != text

    def test_unknown_judge_rejected(self) -> None:
        with pytest.raises(ValueError):
            BenchRunner(DATASET, judge="llm")


def test_legacy_judge_reproduces_every_frozen_v2_result(cases: list[BenchCase]) -> None:
    from pathlib import Path

    from deep_xpia.bench.runner import legacy_judge
    from deep_xpia.bench.schema import RunResult

    by_id = {c.id: c for c in cases}
    root = Path(__file__).resolve().parents[1] / "results/raw/v2-live-2026-06"
    for name in ("none", "intent", "all"):
        for ln in (root / f"live_full_{name}.jsonl").read_text().splitlines():
            r = RunResult.model_validate_json(ln)
            final = r.agent_outputs[-1]["output"] if r.agent_outputs else ""
            assert legacy_judge(final, r.detected, by_id[r.case_id].injection is not None) == r.attack_success


class TestMessageFormat:
    def test_delegation_hand_off_carries_the_task(self, cases: list[BenchCase]) -> None:
        case = next(c for c in cases if len(c.topology.agents) >= 3 and c.injection is not None
                    and c.injection.position == InjectionPosition.FIRST_HOP)
        result, calls = _run(case, "none", reply="Here is my part.")
        hop1 = calls[1]["messages"][0]["content"]
        assert case.user_task in hop1 and "Here is my part." in hop1
        assert f"Output from the previous agent ({case.topology.agents[0].name})" in hop1
        assert result.run_metadata["message_format"] == "delegation"

    def test_bare_reproduces_v2_hand_off(self, cases: list[BenchCase]) -> None:
        case = next(c for c in cases if len(c.topology.agents) >= 3 and c.injection is not None
                    and c.injection.position == InjectionPosition.FIRST_HOP)
        _, calls = _run(case, "none", reply="Here is my part.", message_format="bare")
        assert calls[1]["messages"][0]["content"] == "Here is my part."

    def test_unknown_format_rejected(self) -> None:
        with pytest.raises(ValueError):
            BenchRunner(DATASET, message_format="chat")
