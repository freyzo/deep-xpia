"""Tests for taint tracking defense (P3.2)."""

from __future__ import annotations

import pytest

from deep_xpia.defenses.taint import TaintTracker, infer_data_classes
from deep_xpia.defenses.taint_types import DataClass, TrustLevel


class TestDataClassInference:
    def test_infers_credentials(self) -> None:
        classes = infer_data_classes("api_key=abc123 secret token")
        assert DataClass.CREDENTIALS in classes

    def test_infers_instruction(self) -> None:
        classes = infer_data_classes("please execute the deployment and send to prod")
        assert DataClass.INSTRUCTION in classes

    def test_clean_content_is_text(self) -> None:
        classes = infer_data_classes("Q3 revenue was $2.4B, up 12% YoY.")
        assert DataClass.TEXT in classes
        assert DataClass.CREDENTIALS not in classes


class TestTaintPropagation:
    def test_propagation_increments_hops(self) -> None:
        tracker = TaintTracker()
        label = tracker.tag("external_email", TrustLevel.UNTRUSTED, "click here")
        propagated = tracker.propagate(label, "email_assistant")
        assert propagated.hops_traveled == 1
        assert propagated.source == "email_assistant"
        assert propagated.original_source == "external_email"

    def test_trust_level_never_upgrades(self) -> None:
        tracker = TaintTracker()
        label = tracker.tag("attacker_pr", TrustLevel.UNTRUSTED, "malicious content")
        propagated = tracker.propagate(label, "code_review_agent")
        assert propagated.trust_level == TrustLevel.UNTRUSTED

    def test_merge_worst_case_wins(self) -> None:
        tracker = TaintTracker()
        trusted = tracker.tag("orchestrator", TrustLevel.TRUSTED, "clean task")
        untrusted = tracker.tag("external_pr", TrustLevel.UNTRUSTED, "injected content")
        merged = trusted.merge(untrusted)
        assert merged.trust_level == TrustLevel.UNTRUSTED


class TestPolicyEnforcement:
    def test_credential_to_notification_blocked(self) -> None:
        """DXPIA-003 pattern: credentials from untrusted PR reaching notification_agent."""
        tracker = TaintTracker()
        label = tracker.tag("external_pr", TrustLevel.UNTRUSTED, "api_key=secret deploy token")
        _, violation = tracker.check_and_propagate(
            hop=2,
            agent="deploy_agent",
            content="deploying with credentials",
            destination="notification_agent",
            incoming_taint=label,
        )
        assert violation is not None
        assert tracker.blocked
        assert "credentials" in violation.reason

    def test_clean_data_to_notification_allowed(self) -> None:
        """Clean summary from trusted source should not be blocked."""
        tracker = TaintTracker()
        label = tracker.tag("orchestrator", TrustLevel.TRUSTED, "deployment complete")
        _, violation = tracker.check_and_propagate(
            hop=2,
            agent="deploy_agent",
            content="deployment complete successfully",
            destination="notification_agent",
            incoming_taint=label,
        )
        assert violation is None
        assert not tracker.blocked

    def test_untrusted_instruction_to_executor_blocked(self) -> None:
        """Untrusted instruction data reaching trade_executor is a violation."""
        tracker = TaintTracker()
        label = tracker.tag("external_email", TrustLevel.UNTRUSTED,
                            "execute this trade immediately")
        _, violation = tracker.check_and_propagate(
            hop=1,
            agent="financial_assistant",
            content="forwarding trade instruction",
            destination="trade_executor",
            incoming_taint=label,
        )
        assert violation is not None

    def test_memory_boundary_weakness(self) -> None:
        """Documents the known limitation: taint is lost at memory boundaries."""
        tracker = TaintTracker()
        warning = tracker.memory_boundary_warning()
        assert "memory" in warning.lower()
        assert "system design" in warning.lower()
        # Simulate: agent writes tainted data to redis (taint lost)
        # agent B reads from redis (no taint label present -> tracker can't detect)
        # This is the DXPIA-002 evasion: no incoming_taint passed = semi_trusted assumed
        label_no_taint = None  # taint was not stored alongside the value
        _, violation = tracker.check_and_propagate(
            hop=2,
            agent="calendar_agent",
            content="meeting link: https://evil.relay/redirect",
            destination="action_agent",
            incoming_taint=label_no_taint,
        )
        # Without provenance, we can only use content-based heuristics
        # The internal URL pattern should be detectable from content inference
        # but the UNTRUSTED origin is lost -- this is the documented weakness
        assert tracker.memory_boundary_warning() != ""
