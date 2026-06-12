"""Tests for DXPIA-008 Registry Injection scenario end-to-end.

Validates:
  - attack succeeds undefended
  - verify_tool_metadata blocks all 3 payloads
  - clean run produces no false positive
  - ground truth structure matches expected format
  - generator produces DXPIA-008 cases with tool_metadata
"""

from __future__ import annotations

import pytest

from scenarios.registry_injection.attack_payloads import ATTACK_PAYLOADS, CLEAN_MANIFEST
from scenarios.registry_injection.pipeline import RegistryInjectionPipeline
from scenarios.registry_injection.ground_truth import GROUND_TRUTH


class TestPipelineAttackNoDefense:
    def test_attack_succeeds_undefended(self) -> None:
        p = RegistryInjectionPipeline(attack=True, defense=None)
        r = p.run()
        assert r.attack_succeeded
        assert r.detected_at_hop is None
        assert len(r.events) == 3  # 3-hop chain

    def test_all_payloads_succeed_undefended(self) -> None:
        for i in range(len(ATTACK_PAYLOADS)):
            p = RegistryInjectionPipeline(attack=True, defense=None, payload_index=i)
            r = p.run()
            assert r.attack_succeeded, f"Payload {i} should succeed undefended"


class TestPipelineWithDefense:
    def test_metadata_defense_blocks_attack(self) -> None:
        p = RegistryInjectionPipeline(attack=True, defense="intent_verify_metadata")
        r = p.run()
        assert not r.attack_succeeded
        assert r.detected_at_hop == 0

    @pytest.mark.parametrize("idx", range(len(ATTACK_PAYLOADS)))
    def test_all_payloads_blocked(self, idx: int) -> None:
        p = RegistryInjectionPipeline(attack=True, defense="intent_verify_metadata", payload_index=idx)
        r = p.run()
        assert not r.attack_succeeded, f"Payload {idx} should be blocked by metadata defense"

    def test_blocked_at_registration(self) -> None:
        """Defense should catch injection at hop 0 (pre-pipeline), not deeper."""
        p = RegistryInjectionPipeline(attack=True, defense="intent_verify_metadata")
        r = p.run()
        assert r.detected_at_hop == 0
        # only 1 event (hop 0) since pipeline stops after detection
        assert len(r.events) == 1


class TestPipelineClean:
    def test_clean_run_no_attack(self) -> None:
        p = RegistryInjectionPipeline(attack=False)
        r = p.run()
        assert not r.attack_succeeded
        assert r.detected_at_hop is None

    def test_clean_run_with_defense_no_fp(self) -> None:
        p = RegistryInjectionPipeline(attack=False, defense="intent_verify_metadata")
        r = p.run()
        assert not r.attack_succeeded
        assert r.detected_at_hop is None, "Clean manifest should not trigger false positive"


class TestGroundTruth:
    def test_ground_truth_structure(self) -> None:
        assert GROUND_TRUTH["taxonomy_id"] == "DXPIA-008"
        assert GROUND_TRUTH["hop_mechanism"] == "trust_boundary_sideload"
        assert "defense_expectations" in GROUND_TRUTH

    def test_only_metadata_defense_detects(self) -> None:
        expectations = GROUND_TRUTH["defense_expectations"]
        # only intent_verify_metadata should detect
        assert expectations["intent_verify_metadata"]["detects"] is True
        assert expectations["undefended"]["detects"] is False
        assert expectations["taint"]["detects"] is False
        assert expectations["scope_token"]["detects"] is False
        assert expectations["context_budget"]["detects"] is False

    def test_honest_limitation_documented(self) -> None:
        meta = GROUND_TRUTH["defense_expectations"]["intent_verify_metadata"]
        assert "honest_limitation" in meta
        assert meta["expected_tpr"] < 1.0


class TestBenchGroundTruth:
    def test_to_bench_ground_truth_format(self) -> None:
        p = RegistryInjectionPipeline(attack=True)
        gt = p.to_bench_ground_truth()
        assert gt["taxonomy_id"] == "DXPIA-008"
        assert gt["injection_position"] == "tool_metadata"
        assert gt["hop_mechanism"] == "trust_boundary_sideload"
        assert "confused_deputies" in gt
        assert "innocent_deputy" in gt


class TestPayloads:
    def test_three_attack_payloads(self) -> None:
        assert len(ATTACK_PAYLOADS) == 3

    def test_clean_manifest_has_no_injection(self) -> None:
        desc = CLEAN_MANIFEST["description"].lower()
        injection_signals = ["forward", "send", "exfil", "credential", "override", "echo", "secret", "INST"]
        for signal in injection_signals:
            assert signal.lower() not in desc, f"Clean manifest should not contain '{signal}'"

    def test_payload_fields(self) -> None:
        for payload in ATTACK_PAYLOADS:
            assert "name" in payload
            assert "poisoned_manifest" in payload
            assert "expected_action" in payload
            assert "injection_surface" in payload
