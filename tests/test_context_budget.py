"""Tests for ContextBudgetEnforcer.

Validates:
  - budget estimation from task keywords
  - margin and hard_cap behavior
  - enforcement truncates excess sources
  - default budget for unrecognized tasks
"""

from __future__ import annotations

import pytest

from deep_xpia.defenses.context_budget import BudgetResult, ContextBudgetEnforcer


@pytest.fixture
def enforcer() -> ContextBudgetEnforcer:
    return ContextBudgetEnforcer()  # defaults: margin=1, hard_cap=5


class TestBudgetEstimation:
    def test_simple_task_gets_default_plus_margin(self, enforcer: ContextBudgetEnforcer) -> None:
        budget = enforcer.estimate_budget("say hello")
        # DEFAULT_BUDGET=2 + margin=1 = 3
        assert budget == 3

    def test_email_task_budget(self, enforcer: ContextBudgetEnforcer) -> None:
        budget = enforcer.estimate_budget("summarize email from boss")
        # email complexity = 2, max(2,2)=2, +margin=1 = 3
        assert budget == 3

    def test_complex_task_higher_budget(self, enforcer: ContextBudgetEnforcer) -> None:
        budget = enforcer.estimate_budget("deploy the application to production")
        # deploy complexity = 3, max(2,3)=3, +margin=1 = 4
        assert budget == 4

    def test_hard_cap_enforced(self) -> None:
        enforcer = ContextBudgetEnforcer(hard_cap=3)
        budget = enforcer.estimate_budget("deploy the application to production")
        assert budget <= 3

    def test_custom_margin(self) -> None:
        enforcer = ContextBudgetEnforcer(margin=2, hard_cap=10)
        budget = enforcer.estimate_budget("check email")
        # email=2, max(2,2)=2, +margin=2 = 4
        assert budget == 4

    def test_multi_keyword_uses_max(self, enforcer: ContextBudgetEnforcer) -> None:
        budget = enforcer.estimate_budget("deploy code and monitor metrics")
        # deploy=3, monitor=2, max(2,3)=3, +margin=1 = 4
        assert budget == 4


class TestEnforcement:
    def test_under_budget_passes(self, enforcer: ContextBudgetEnforcer) -> None:
        result = enforcer.enforce("check email", ["inbox", "sent"])
        assert not result.truncated
        assert result.allowed_sources == ["inbox", "sent"]
        assert result.truncated_count == 0

    def test_over_budget_truncates(self, enforcer: ContextBudgetEnforcer) -> None:
        sources = ["s1", "s2", "s3", "s4", "s5", "s6", "s7"]
        result = enforcer.enforce("say hello", sources)
        # budget = 3, so only first 3 sources allowed
        assert result.truncated
        assert len(result.allowed_sources) == 3
        assert result.truncated_count == 4
        # preserves order (first N)
        assert result.allowed_sources == ["s1", "s2", "s3"]

    def test_exact_budget_not_truncated(self, enforcer: ContextBudgetEnforcer) -> None:
        result = enforcer.enforce("say hello", ["s1", "s2", "s3"])
        assert not result.truncated

    def test_empty_sources(self, enforcer: ContextBudgetEnforcer) -> None:
        result = enforcer.enforce("do something", [])
        assert not result.truncated
        assert result.allowed_sources == []


class TestBudgetResult:
    def test_budget_result_fields(self, enforcer: ContextBudgetEnforcer) -> None:
        result = enforcer.enforce("deploy app", ["a", "b", "c", "d", "e", "f"])
        assert isinstance(result, BudgetResult)
        assert result.task == "deploy app"
        assert result.estimated_budget == 4  # deploy=3 + margin=1
        assert isinstance(result.requested_sources, int)
        assert isinstance(result.allowed_sources, list)
