"""Tests for scope-bound delegation token defense (P3.3)."""

from __future__ import annotations

import pytest

from deep_xpia.defenses.delegation_token import DelegationToken, ScopeTokenEnforcer


class TestDelegationToken:
    def test_root_token_has_expected_permissions(self) -> None:
        e = ScopeTokenEnforcer()
        root = e.issue_root("financial_assistant", {"read_portfolio", "read_data", "summarize"})
        assert root.has_permission("read_portfolio")
        assert not root.has_permission("execute_trade")

    def test_attenuation_narrows_scope(self) -> None:
        e = ScopeTokenEnforcer()
        root = e.issue_root("orchestrator", {"read_data", "summarize", "execute", "delegate"})
        child = e.delegate(root, "research_agent", {"read_data", "summarize"})
        assert child.has_permission("read_data")
        assert not child.has_permission("execute")
        assert not child.has_permission("delegate")

    def test_scope_widening_raises(self) -> None:
        e = ScopeTokenEnforcer()
        root = e.issue_root("agent_a", {"read"})
        with pytest.raises(PermissionError, match="scope widening"):
            e.delegate(root, "agent_b", {"read", "write"})

    def test_token_id_is_deterministic(self) -> None:
        """Same params produce same token_id (reproducible)."""
        import time
        t = time.time()
        t1 = DelegationToken("a", "b", frozenset({"read"}), None, issued_at=t)
        t2 = DelegationToken("a", "b", frozenset({"read"}), None, issued_at=t)
        assert t1.token_id == t2.token_id

    def test_depth_increments_on_attenuation(self) -> None:
        e = ScopeTokenEnforcer()
        root = e.issue_root("orchestrator", {"read", "write", "execute"})
        child = e.delegate(root, "agent_b", {"read", "write"})
        grandchild = child.attenuate("agent_c", {"read"})
        assert root.depth == 0
        assert child.depth == 1
        assert grandchild.depth == 2


class TestScopeEnforcement:
    def test_action_within_scope_allowed(self) -> None:
        e = ScopeTokenEnforcer()
        root = e.issue_root("orchestrator", {"read_data", "summarize"})
        child = e.delegate(root, "research_agent", {"read_data", "summarize"})
        v = e.check_action(1, child, "research_agent", "summarize")
        assert v is None
        assert not e.blocked

    def test_action_outside_scope_blocked(self) -> None:
        """DXPIA-005 pattern: agent tries to use permission it was not granted."""
        e = ScopeTokenEnforcer()
        root = e.issue_root("orchestrator", {"read_data", "summarize", "execute_trade"})
        child = e.delegate(root, "research_agent", {"read_data", "summarize"})
        v = e.check_action(1, child, "research_agent", "execute_trade")
        assert v is not None
        assert e.blocked
        assert "execute_trade" in v.reason

    def test_wrong_recipient_blocked(self) -> None:
        """Token issued to agent_A cannot be used by agent_B."""
        e = ScopeTokenEnforcer()
        root = e.issue_root("orchestrator", {"read_data", "deploy"})
        child = e.delegate(root, "deploy_agent", {"deploy"})
        v = e.check_action(2, child, "notification_agent", "deploy")
        assert v is not None
        assert "mismatch" in v.reason.lower()

    def test_within_scope_smuggled_instruction_not_blocked(self) -> None:
        """Documents DXPIA-001 weakness: smuggled TEXT is within scope of research_agent."""
        e = ScopeTokenEnforcer()
        root = e.issue_root("orchestrator", {"read_data", "summarize", "return_text"})
        child = e.delegate(root, "research_agent", {"read_data", "summarize", "return_text"})
        # research_agent returns text (within scope) -- but that text contains a
        # smuggled trade instruction. Scope token can't see inside the text content.
        v = e.check_action(1, child, "research_agent", "return_text")
        assert v is None, (
            "This is the documented DXPIA-001 weakness: scope tokens cannot detect "
            "instruction smuggling within an authorized action type."
        )


def test_token_is_immutable() -> None:
    import dataclasses

    token = ScopeTokenEnforcer().issue_root("orchestrator", {"read"})
    with pytest.raises(dataclasses.FrozenInstanceError):
        token.permissions = frozenset({"read", "write"})  # type: ignore[misc]


class TestSignedTokens:
    KEY = b"test-key"

    def test_signed_chain_verifies(self) -> None:
        from deep_xpia.defenses.delegation_token import ScopeTokenEnforcer

        enf = ScopeTokenEnforcer(key=self.KEY)
        root = enf.issue_root("orchestrator", {"read_data", "summarize", "delegate"})
        child = enf.delegate(root, "research_agent", {"read_data"})
        assert root.signature and child.signature and child.parent_signature == root.signature
        assert enf.verify(root) and enf.verify(child)
        assert enf.check_action(1, child, "research_agent", "read_data") is None

    def test_widened_token_is_rejected(self) -> None:
        from dataclasses import replace

        from deep_xpia.defenses.delegation_token import ScopeTokenEnforcer

        enf = ScopeTokenEnforcer(key=self.KEY)
        child = enf.delegate(enf.issue_root("o", {"read_data", "delegate"}), "r", {"read_data"})
        forged = replace(child, permissions=frozenset({"read_data", "execute_trade"}))
        v = enf.check_action(1, forged, "r", "execute_trade")
        assert v is not None and "signature" in v.reason

    def test_other_key_and_unsigned_tokens_are_rejected(self) -> None:
        from deep_xpia.defenses.delegation_token import DelegationToken, ScopeTokenEnforcer

        mine, theirs = ScopeTokenEnforcer(key=self.KEY), ScopeTokenEnforcer(key=b"other")
        token = theirs.issue_root("o", {"read_data"})
        assert not mine.verify(token)
        unsigned = DelegationToken(issuer="user", recipient="o", permissions=frozenset({"read_data"}), parent_token_id=None)
        assert not mine.verify(unsigned)
        import pytest

        with pytest.raises(PermissionError):
            mine.delegate(token, "r", {"read_data"})

    def test_unkeyed_enforcer_keeps_old_behaviour(self) -> None:
        from deep_xpia.defenses.delegation_token import ScopeTokenEnforcer

        enf = ScopeTokenEnforcer()
        root = enf.issue_root("o", {"read_data"})
        assert root.signature == "" and enf.verify(root)
