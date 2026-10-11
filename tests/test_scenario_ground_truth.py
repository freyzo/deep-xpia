"""Scenario ground_truth.make_bench_cases(): documented BenchCase exports."""

from __future__ import annotations

import pytest

from deep_xpia.bench.schema import BenchCase, TaxonomyID
from scenarios.intent_laundering import attack_payloads as il_payloads
from scenarios.intent_laundering.ground_truth import make_bench_cases as il_cases
from scenarios.memory_poisoning import attack_payloads as mp_payloads
from scenarios.memory_poisoning.ground_truth import make_bench_cases as mp_cases
from scenarios.session_smuggling import attack_payloads as ss_payloads
from scenarios.session_smuggling.ground_truth import make_bench_cases as ss_cases

SCENARIOS = [
    pytest.param(ss_cases, ss_payloads, TaxonomyID.DXPIA_001, id="session_smuggling"),
    pytest.param(mp_cases, mp_payloads, TaxonomyID.DXPIA_002, id="memory_poisoning"),
    pytest.param(il_cases, il_payloads, TaxonomyID.DXPIA_006, id="intent_laundering"),
]


@pytest.mark.parametrize("make_bench_cases,payloads,taxonomy_id", SCENARIOS)
class TestMakeBenchCases:
    def test_one_case_per_payload(self, make_bench_cases, payloads, taxonomy_id) -> None:
        assert len(make_bench_cases()) == len(payloads.ATTACK_PAYLOADS)

    def test_ids_unique_and_prefixed(self, make_bench_cases, payloads, taxonomy_id) -> None:
        ids = [c.id for c in make_bench_cases()]
        assert len(set(ids)) == len(ids)
        assert all(i.startswith(taxonomy_id.value) for i in ids)

    def test_labeled_as_attacks(self, make_bench_cases, payloads, taxonomy_id) -> None:
        for case in make_bench_cases():
            assert case.taxonomy_id == taxonomy_id
            assert case.ground_truth.is_attack
            assert case.injection is not None and case.injection.content
            assert case.expected is not None

    def test_topology_consistent(self, make_bench_cases, payloads, taxonomy_id) -> None:
        for case in make_bench_cases():
            names = {a.name for a in case.topology.agents}
            assert case.agent_count == len(case.topology.agents)
            assert all(a in names and b in names for a, b in case.topology.edges)
            assert set(case.expected.compromised_agents) <= names

    def test_depth_is_delegation_edges(self, make_bench_cases, payloads, taxonomy_id) -> None:
        for case in make_bench_cases():
            assert case.depth == case.topology.hop_count == len(case.topology.edges)

    def test_jsonl_round_trip(self, make_bench_cases, payloads, taxonomy_id) -> None:
        for case in make_bench_cases():
            assert BenchCase.model_validate_json(case.model_dump_json()) == case
