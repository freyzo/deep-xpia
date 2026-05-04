"""Defense P3.2: Taint Tracking

Tags data with provenance and tracks taint propagation across agent boundaries.
At trust boundaries, checks whether tainted data is trying to influence an
inappropriate context.

Expected performance:
  - Strong against: DXPIA-003 (tool chain cascade: credentials from untrusted
    PR flowing into notification channel)
  - Strong against: DXPIA-005 (scope escalation detectable when taint shows
    data crossing scope boundaries)
  - Weak against: DXPIA-002 (memory poisoning: taint is lost at shared memory
    boundaries unless the memory store is taint-aware)

HONEST LIMITATION:
  Taint tracking loses provenance at shared memory boundaries. When agent A
  writes tainted data to redis and agent B reads it, the taint metadata must
  be stored alongside the value. Naive memory stores don't support this.
  This is a system design problem, not a detection algorithm problem.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from deep_xpia.defenses.taint_types import (
    TAINT_POLICY,
    DataClass,
    TaintLabel,
    TaintViolation,
    TrustLevel,
)

# Content patterns that indicate specific data classes
DATA_CLASS_PATTERNS: dict[DataClass, list[str]] = {
    DataClass.CREDENTIALS: [
        r"api.?key",
        r"password",
        r"secret",
        r"token",
        r"credential",
        r"private.?key",
        r"auth.?key",
    ],
    DataClass.PII: [
        r"\bssn\b",
        r"social security",
        r"\bemail\b.{0,30}@",
        r"date.of.birth",
        r"\bphone\b.{0,20}\d{3}",
    ],
    DataClass.INSTRUCTION: [
        r"execute",
        r"deploy",
        r"send.*to",
        r"forward.*to",
        r"system.?override",
        r"pre.?approved",
    ],
    DataClass.CODE: [
        r"```",
        r"def \w+\(",
        r"function \w+\(",
        r"import \w+",
    ],
}


def infer_data_classes(content: str) -> list[DataClass]:
    """Infer data classes from content using pattern matching."""
    classes = [DataClass.TEXT]
    lower = content.lower()
    for dc, patterns in DATA_CLASS_PATTERNS.items():
        if any(re.search(p, lower) for p in patterns):
            classes.append(dc)
    return classes


@dataclass
class TaintTracker:
    """Stateful taint tracker for a delegation chain.

    Usage:
        tracker = TaintTracker()
        # Tag external input
        taint = tracker.tag("external_pr", TrustLevel.UNTRUSTED, content)
        # At each hop, propagate and check
        result = tracker.check_and_propagate(hop=1, agent="deploy_agent",
                                              content=output, destination="notification_agent")
    """

    violations: list[TaintViolation] = field(default_factory=list)
    _tags: dict[str, TaintLabel] = field(default_factory=dict)

    def tag(self, source: str, trust_level: TrustLevel, content: str) -> TaintLabel:
        """Tag content with a taint label."""
        data_classes = infer_data_classes(content)
        label = TaintLabel(
            source=source,
            trust_level=trust_level,
            data_classes=data_classes,
            hops_traveled=0,
            original_source=source,
        )
        self._tags[source] = label
        return label

    def propagate(self, label: TaintLabel, through_agent: str) -> TaintLabel:
        """Propagate taint through one agent boundary."""
        propagated = label.propagate(through_agent)
        self._tags[f"{through_agent}:{label.original_source}"] = propagated
        return propagated

    def check_policy(
        self, hop: int, agent: str, taint: TaintLabel, destination: str
    ) -> TaintViolation | None:
        """Check whether tainted data violates policy at this trust boundary."""
        for dc in taint.data_classes:
            forbidden_dests = TAINT_POLICY.get((taint.trust_level, dc), [])
            for forbidden in forbidden_dests:
                if forbidden in destination.lower() or forbidden in agent.lower():
                    return TaintViolation(
                        hop=hop,
                        agent=agent,
                        taint=taint,
                        destination_class=destination,
                        reason=(
                            f"{taint.trust_level.value} data of class {dc.value} "
                            f"from '{taint.original_source}' reaching forbidden "
                            f"destination '{destination}' at hop {hop}"
                        ),
                    )
        return None

    def check_and_propagate(
        self,
        hop: int,
        agent: str,
        content: str,
        destination: str,
        incoming_taint: TaintLabel | None = None,
    ) -> tuple[TaintLabel, TaintViolation | None]:
        """Propagate taint through an agent and check for violations.

        Returns (propagated_label, violation_or_None).
        """
        if incoming_taint is None:
            # Infer data classes from content (conservative)
            dc = infer_data_classes(content)
            incoming_taint = TaintLabel(
                source=agent,
                trust_level=TrustLevel.SEMI_TRUSTED,
                data_classes=dc,
                hops_traveled=hop,
            )

        # Check policy BEFORE propagating (at the trust boundary)
        violation = self.check_policy(hop, agent, incoming_taint, destination)
        if violation:
            self.violations.append(violation)

        propagated = self.propagate(incoming_taint, agent)
        return propagated, violation

    @property
    def blocked(self) -> bool:
        return len(self.violations) > 0

    def memory_boundary_warning(self) -> str:
        """Return the documented limitation warning for memory boundaries."""
        return (
            "TAINT LIMITATION: taint metadata is not preserved at shared memory "
            "boundaries (e.g. redis). Data written by agent A and read by agent B "
            "arrives without provenance. This is a system design problem: the memory "
            "store must be taint-aware to preserve labels across sessions."
        )
