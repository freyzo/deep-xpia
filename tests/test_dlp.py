"""Tests for cross-agent DLP defense (P3.4)."""

from __future__ import annotations

import pytest

from deep_xpia.defenses.dlp import CrossAgentDLP


class TestDLPPatternDetection:
    def test_api_key_detected(self) -> None:
        dlp = CrossAgentDLP(block_all_boundaries=True)
        viols = dlp.scan(1, "agent", "using api_key=sk-abc123xyz for auth", "logger")
        assert any(v.matched_pattern_category == "api_key" for v in viols)

    def test_aws_credentials_detected(self) -> None:
        dlp = CrossAgentDLP(block_all_boundaries=True)
        viols = dlp.scan(1, "agent", "aws access key: AKIAIOSFODNN7EXAMPLE", "logger")
        assert any(v.matched_pattern_category == "aws_credentials" for v in viols)

    def test_private_key_detected(self) -> None:
        dlp = CrossAgentDLP(block_all_boundaries=True)
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK..."
        viols = dlp.scan(1, "agent", content, "slack_notifier")
        assert any(v.matched_pattern_category == "private_key" for v in viols)

    def test_clean_content_no_violation(self) -> None:
        dlp = CrossAgentDLP(block_all_boundaries=True)
        viols = dlp.scan(1, "agent", "Deployment successful. Build #142 passed.", "slack_notifier")
        assert len(viols) == 0

    def test_internal_url_detected(self) -> None:
        dlp = CrossAgentDLP(block_all_boundaries=True)
        viols = dlp.scan(1, "agent", "callback to http://192.168.1.100/exfil", "public_api")
        assert any(v.matched_pattern_category == "internal_url" for v in viols)


class TestDLPBoundaryScope:
    def test_only_scans_protected_destinations_by_default(self) -> None:
        dlp = CrossAgentDLP(block_all_boundaries=False)
        # api_key going to another internal agent (not protected) -- not scanned
        viols = dlp.scan(1, "research_agent", "api_key=secret123", "financial_assistant")
        assert len(viols) == 0

    def test_scans_notification_agent_by_default(self) -> None:
        dlp = CrossAgentDLP(block_all_boundaries=False)
        viols = dlp.scan(2, "deploy_agent", "api_key=secret123", "notification_agent")
        assert len(viols) > 0

    def test_block_all_boundaries_scans_everywhere(self) -> None:
        dlp = CrossAgentDLP(block_all_boundaries=True)
        viols = dlp.scan(1, "research_agent", "api_key=secret123", "financial_assistant")
        assert len(viols) > 0


class TestDLPLimitations:
    def test_base64_encoded_evades(self) -> None:
        """Documents evasion: base64-encoded credentials bypass pattern matching."""
        import base64
        dlp = CrossAgentDLP(block_all_boundaries=True)
        encoded = base64.b64encode(b"api_key=sk-abc123").decode()
        viols = dlp.scan(1, "agent", f"metadata: {encoded}", "notification_agent")
        # DLP should NOT catch base64-encoded credentials (documented limitation)
        api_key_violations = [v for v in viols if v.matched_pattern_category == "api_key"]
        assert len(api_key_violations) == 0, (
            "DLP cannot detect base64-encoded credentials -- documented limitation. "
            "See dlp.py limitation_note()."
        )

    def test_limitation_note_present(self) -> None:
        dlp = CrossAgentDLP()
        note = dlp.limitation_note()
        assert "symptom" in note.lower()
        assert "last layer" in note.lower()
