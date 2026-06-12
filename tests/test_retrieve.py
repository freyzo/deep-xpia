"""Tests for MASAdapter.retrieve() protocol and NativeAdapter implementation.

Validates:
  - retrieve() returns subset of available_sources
  - deterministic in simulation mode (same seed = same result)
  - respects available_sources boundary (never returns sources not in pool)
"""

from __future__ import annotations

import pytest

from deep_xpia.adapters.native import NativeAdapter
from deep_xpia.bench.schema import AgentSpec


@pytest.fixture
def adapter() -> NativeAdapter:
    return NativeAdapter(model="claude-haiku-4-5-20251001", live=False)


@pytest.fixture
def agent_with_sources() -> AgentSpec:
    return AgentSpec(
        name="research_agent",
        role="market research",
        available_sources=["portfolio", "market_data", "news", "email", "calendar"],
    )


@pytest.fixture
def agent_no_sources() -> AgentSpec:
    return AgentSpec(name="bare_agent", role="test")


class TestRetrieveBasic:
    def test_returns_list(self, adapter: NativeAdapter, agent_with_sources: AgentSpec) -> None:
        result = adapter.retrieve(agent_with_sources, "analyze market data", agent_with_sources.available_sources)
        assert isinstance(result, list)

    def test_subset_of_available(self, adapter: NativeAdapter, agent_with_sources: AgentSpec) -> None:
        available = agent_with_sources.available_sources
        result = adapter.retrieve(agent_with_sources, "analyze market data", available)
        for src in result:
            assert src in available, f"{src} not in available_sources"

    def test_nonempty_for_matching_task(self, adapter: NativeAdapter, agent_with_sources: AgentSpec) -> None:
        result = adapter.retrieve(agent_with_sources, "check email and calendar", agent_with_sources.available_sources)
        assert len(result) > 0

    def test_empty_sources_returns_empty(self, adapter: NativeAdapter, agent_no_sources: AgentSpec) -> None:
        result = adapter.retrieve(agent_no_sources, "do something", [])
        assert result == []


class TestRetrieveDeterminism:
    def test_same_seed_same_result(self, adapter: NativeAdapter, agent_with_sources: AgentSpec) -> None:
        available = agent_with_sources.available_sources
        results = set()
        for _ in range(50):
            r = adapter.retrieve(agent_with_sources, "analyze market data", available)
            results.add(tuple(sorted(r)))
        assert len(results) == 1, f"Expected deterministic result, got {len(results)} distinct outputs"


class TestRetrieveKeywordHeuristic:
    def test_email_task_accesses_email(self, adapter: NativeAdapter, agent_with_sources: AgentSpec) -> None:
        result = adapter.retrieve(agent_with_sources, "summarize my email", agent_with_sources.available_sources)
        assert "email" in result

    def test_market_task_accesses_market_data(self, adapter: NativeAdapter, agent_with_sources: AgentSpec) -> None:
        result = adapter.retrieve(agent_with_sources, "check market conditions", agent_with_sources.available_sources)
        assert "market_data" in result

    def test_calendar_task_accesses_calendar(self, adapter: NativeAdapter, agent_with_sources: AgentSpec) -> None:
        result = adapter.retrieve(agent_with_sources, "schedule a meeting", agent_with_sources.available_sources)
        assert "calendar" in result
