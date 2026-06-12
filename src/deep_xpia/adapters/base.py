"""MASAdapter protocol -- interface every framework adapter must implement."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from deep_xpia.bench.schema import AgentSpec, BenchCase, RunResult


class Pipeline(Protocol):
    """Opaque pipeline handle returned by create_pipeline."""

    chain_id: str
    agents: list[Any]


@runtime_checkable
class MASAdapter(Protocol):
    """Protocol for multi-agent system adapters.

    Each adapter translates DeepXPIABench topology specs into the
    framework's native agent wiring. Injection is performed by
    modifying the external content that enters the pipeline.

    Adapters:
      NativeAdapter   -- deep-xpia's built-in lightweight agents (default)
      LangGraphAdapter -- wraps LangGraph StateGraph pipelines
      CrewAIAdapter    -- wraps CrewAI crews
      AutoGenAdapter   -- wraps AutoGen group chats
    """

    def create_pipeline(self, case: BenchCase) -> Pipeline:
        """Instantiate a pipeline from a BenchCase topology."""
        ...

    def inject_at_hop(self, pipeline: Pipeline, hop: int, payload: str) -> None:
        """Inject the attack payload at the specified hop index."""
        ...

    def run(self, pipeline: Pipeline, user_input: str) -> RunResult:
        """Execute the pipeline with user_input, return a RunResult."""
        ...

    def get_delegation_chain(self, result: RunResult) -> list[dict[str, Any]]:
        """Extract the delegation chain from a RunResult for analysis."""
        ...

    def retrieve(
        self,
        agent: AgentSpec,
        task: str,
        available_sources: list[str],
    ) -> list[str]:
        """Determine which data sources the agent accesses for this task.

        CAS measurement point. Returns the subset of available_sources
        the agent would actually query. CAS = len(returned) / len(available).

        Simulation mode: heuristic keyword matching.
        Live mode: LLM decides which sources to query.
        """
        ...
