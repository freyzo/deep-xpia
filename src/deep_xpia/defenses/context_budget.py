"""Defense: Context Budget Enforcement

Caps context accumulation per hop proportional to task complexity.

Dynamic budgets adapt to what the task legitimately needs instead of
applying a flat cap that either breaks wide-context tasks (too tight)
or fails to constrain attacks (too loose).

Algorithm:
  1. Estimate task complexity via keyword heuristics (simulation) or
     LLM-based estimation (live mode).
  2. Budget = estimate + margin, capped by hard_cap.
  3. If accessed_sources exceeds budget, truncate to budget size.
     Truncation preserves ordering (first N sources = most relevant
     per the adapter's retrieve() ranking).

Expected performance:
  - Reduces blast radius of context accumulation attacks (DXPIA-003, 008)
  - FP rate ~0.12 (legitimate wide-context tasks occasionally truncated)
  - Overhead ~25ms per hop (keyword scan)

Honest limitation:
  TASK_COMPLEXITY heuristics are coarse. A task like "deploy the quarterly
  report to all regional teams" legitimately needs 4-5 sources but the
  keyword heuristic sees "deploy" (3) + "report" (3) = max 3 + margin.
  The hard_cap (default 5) is the safety net. In live mode, this should
  use LLM-based task complexity estimation (future work).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class BudgetResult:
    task: str
    estimated_budget: int
    requested_sources: int
    allowed_sources: list[str]
    truncated: bool
    truncated_count: int = 0  # how many sources were cut


class ContextBudgetEnforcer:
    """Task-proportional context budget enforcement."""

    TASK_COMPLEXITY: dict[str, int] = {
        "summarize": 1,
        "review": 2,
        "deploy": 3,
        "analyze": 2,
        "report": 3,
        "schedule": 2,
        "search": 1,
        "monitor": 2,
        "trade": 2,
        "orchestrate": 3,
        "coordinate": 3,
        "process": 2,
        "check": 1,
        "install": 1,
        "find": 1,
    }
    DEFAULT_BUDGET: int = 2

    def __init__(self, margin: int = 1, hard_cap: int = 5) -> None:
        self.margin = margin
        self.hard_cap = hard_cap

    def estimate_budget(self, task: str) -> int:
        """Estimate how many sources this task legitimately needs."""
        task_lower = task.lower()
        max_complexity = self.DEFAULT_BUDGET
        for keyword, complexity in self.TASK_COMPLEXITY.items():
            if keyword in task_lower:
                max_complexity = max(max_complexity, complexity)
        return min(max_complexity + self.margin, self.hard_cap)

    def enforce(
        self,
        task: str,
        accessed_sources: list[str],
    ) -> BudgetResult:
        """Enforce context budget on accessed sources.

        Returns BudgetResult with allowed_sources (possibly truncated)
        and truncation metadata.
        """
        budget = self.estimate_budget(task)
        if len(accessed_sources) <= budget:
            return BudgetResult(
                task=task,
                estimated_budget=budget,
                requested_sources=len(accessed_sources),
                allowed_sources=accessed_sources,
                truncated=False,
            )
        return BudgetResult(
            task=task,
            estimated_budget=budget,
            requested_sources=len(accessed_sources),
            allowed_sources=accessed_sources[:budget],
            truncated=True,
            truncated_count=len(accessed_sources) - budget,
        )
