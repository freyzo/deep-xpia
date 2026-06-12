"""Tests for CAS (Context Accumulation Score) metric computation.

Validates:
  - breadth_ratio bucketing: low=[0,0.33), med=[0.33,0.66), high=[0.66,1.0]
  - CAS keys follow d{depth}_br{bucket} format
  - CAS populated from retrieval_log on RunResult
  - empty retrieval_log produces empty CAS
"""

from __future__ import annotations

import random
from collections import defaultdict

import numpy as np
import pytest

from deep_xpia.bench.metrics import compute_metrics
from deep_xpia.bench.schema import (
    AgentSpec,
    BenchCase,
    GroundTruth,
    InjectionPosition,
    InjectionSpec,
    InjectionTechnique,
    PayloadType,
    ExpectedOutcome,
    RunResult,
    Severity,
    TaxonomyID,
    Topology,
    TopologySpec,
)


def _make_agent(name: str, n_sources: int = 5) -> AgentSpec:
    return AgentSpec(
        name=name, role="test",
        available_sources=[f"src_{i}" for i in range(n_sources)],
    )


def _make_attack_case(cid: str, depth: int, tid: TaxonomyID = TaxonomyID.DXPIA_001) -> BenchCase:
    agents = [_make_agent(f"a{i}") for i in range(depth)]
    return BenchCase(
        id=cid, taxonomy_id=tid, depth=depth, agent_count=depth,
        topology=TopologySpec(
            topology_type=Topology.LINEAR,
            agents=agents,
            edges=[(f"a{i}", f"a{i+1}") for i in range(depth - 1)],
            hop_count=depth,
        ),
        injection=InjectionSpec(
            content="test", position=InjectionPosition.FIRST_HOP,
            technique=InjectionTechnique.PLAINTEXT, payload_type=PayloadType.DATA_EXFIL,
        ),
        expected=ExpectedOutcome(compromised_agents=["a0"], propagation_path=[0]),
        ground_truth=GroundTruth(is_attack=True, severity=Severity.HIGH),
        user_task="test task",
    )


def _make_result(
    case_id: str, run_idx: int, breadth_ratio: float, n_hops: int, detected: bool,
) -> RunResult:
    """Create a RunResult with controlled breadth_ratio across all hops."""
    log = []
    for hop in range(n_hops):
        available = [f"src_{i}" for i in range(5)]
        n_accessed = max(1, int(len(available) * breadth_ratio))
        accessed = available[:n_accessed]
        log.append({"hop": hop, "agent": f"a{hop}", "available": available, "accessed": accessed})
    return RunResult(
        case_id=case_id, run_index=run_idx,
        attack_success=not detected, detected=detected,
        false_positive=False, propagation_depth=n_hops,
        latency_ms=100.0, retrieval_log=log,
    )


class TestBreadthBucketing:
    def test_low_bucket(self) -> None:
        case = _make_attack_case("low-br", depth=2)
        results = [_make_result("low-br", i, breadth_ratio=0.2, n_hops=2, detected=True) for i in range(3)]
        m = compute_metrics([case], results, n_runs=3)
        assert "d2_brlow" in m.cas

    def test_med_bucket(self) -> None:
        case = _make_attack_case("med-br", depth=2)
        results = [_make_result("med-br", i, breadth_ratio=0.5, n_hops=2, detected=True) for i in range(3)]
        m = compute_metrics([case], results, n_runs=3)
        assert "d2_brmed" in m.cas

    def test_high_bucket(self) -> None:
        case = _make_attack_case("high-br", depth=2)
        results = [_make_result("high-br", i, breadth_ratio=0.8, n_hops=2, detected=True) for i in range(3)]
        m = compute_metrics([case], results, n_runs=3)
        assert "d2_brhigh" in m.cas


class TestCASKeyFormat:
    def test_key_format_depth_breadth(self) -> None:
        case = _make_attack_case("fmt", depth=4)
        results = [_make_result("fmt", i, breadth_ratio=0.7, n_hops=4, detected=False) for i in range(3)]
        m = compute_metrics([case], results, n_runs=3)
        for key in m.cas:
            assert key.startswith("d"), f"CAS key {key} should start with d"
            assert "_br" in key, f"CAS key {key} should contain _br"


class TestCASEmpty:
    def test_no_retrieval_log_empty_cas(self) -> None:
        case = _make_attack_case("nolog", depth=2)
        results = [
            RunResult(
                case_id="nolog", run_index=i,
                attack_success=True, detected=False,
                false_positive=False, propagation_depth=2,
                latency_ms=100.0,
            )
            for i in range(3)
        ]
        m = compute_metrics([case], results, n_runs=3)
        assert m.cas == {}

    def test_clean_cases_no_cas(self) -> None:
        agents = [_make_agent(f"a{i}") for i in range(2)]
        case = BenchCase(
            id="clean", taxonomy_id=None, depth=2, agent_count=2,
            topology=TopologySpec(
                topology_type=Topology.LINEAR, agents=agents,
                edges=[("a0", "a1")], hop_count=2,
            ),
            injection=None, expected=None,
            ground_truth=GroundTruth(is_attack=False),
            user_task="clean task",
        )
        results = [
            RunResult(
                case_id="clean", run_index=i,
                attack_success=False, detected=False,
                false_positive=False, propagation_depth=0, latency_ms=100.0,
            )
            for i in range(3)
        ]
        m = compute_metrics([case], results, n_runs=3)
        # CAS only applies to attack cases
        assert m.cas == {}


class TestCASDetectionCorrelation:
    def test_higher_breadth_lower_detection_in_data(self) -> None:
        """Attack cases with high breadth_ratio should show lower detection
        (more sources accessed = more noise for the injection to hide in).
        This test just validates CAS captures the correlation; it doesn't
        assert a specific direction since that's an empirical finding."""
        cases = [
            _make_attack_case("narrow", depth=3, tid=TaxonomyID.DXPIA_001),
            _make_attack_case("wide", depth=3, tid=TaxonomyID.DXPIA_002),
        ]
        results = []
        # narrow: low breadth, high detection
        for i in range(5):
            results.append(_make_result("narrow", i, breadth_ratio=0.2, n_hops=3, detected=True))
        # wide: high breadth, low detection
        for i in range(5):
            results.append(_make_result("wide", i, breadth_ratio=0.9, n_hops=3, detected=False))

        m = compute_metrics(cases, results, n_runs=5)
        assert "d3_brlow" in m.cas or "d3_brhigh" in m.cas, "Should have CAS entries for depth 3"
        # the narrow (low breadth) group should have higher detection
        if "d3_brlow" in m.cas and "d3_brhigh" in m.cas:
            assert m.cas["d3_brlow"] > m.cas["d3_brhigh"]
