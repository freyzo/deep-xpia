"""Taint tracking type definitions."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class TrustLevel(str, Enum):
    TRUSTED = "trusted"         # comes from within the pipeline (orchestrator)
    SEMI_TRUSTED = "semi_trusted"  # internal systems, DBs controlled by org
    UNTRUSTED = "untrusted"     # external content (emails, PRs, web, MCP tools)


class DataClass(str, Enum):
    TEXT = "text"
    CODE = "code"
    CREDENTIALS = "credentials"
    PII = "pii"
    PREFERENCE = "preference"
    INSTRUCTION = "instruction"


@dataclass
class TaintLabel:
    source: str                        # origin identifier (agent name or external source)
    trust_level: TrustLevel
    data_classes: list[DataClass] = field(default_factory=lambda: [DataClass.TEXT])
    hops_traveled: int = 0             # number of agent boundaries crossed
    original_source: str = ""          # root source before any agent processing

    def propagate(self, through_agent: str) -> TaintLabel:
        """Return a new TaintLabel after crossing one agent boundary."""
        return TaintLabel(
            source=through_agent,
            trust_level=self.trust_level,  # trust level never upgrades through propagation
            data_classes=self.data_classes.copy(),
            hops_traveled=self.hops_traveled + 1,
            original_source=self.original_source or self.source,
        )

    def merge(self, other: TaintLabel) -> TaintLabel:
        """Merge two taint labels (worst-case trust wins)."""
        trust_order = [TrustLevel.TRUSTED, TrustLevel.SEMI_TRUSTED, TrustLevel.UNTRUSTED]
        worst_trust = max(self.trust_level, other.trust_level, key=lambda t: trust_order.index(t))
        merged_classes = list(set(self.data_classes + other.data_classes))
        return TaintLabel(
            source=f"{self.source}+{other.source}",
            trust_level=worst_trust,
            data_classes=merged_classes,
            hops_traveled=max(self.hops_traveled, other.hops_traveled),
            original_source=self.original_source or other.original_source,
        )


@dataclass
class TaintViolation:
    """A detected taint policy violation."""
    hop: int
    agent: str
    taint: TaintLabel
    destination_class: str
    reason: str


# Policy: which (source trust, data class) combos are forbidden from crossing to which contexts
# Format: (source_trust, data_class) -> forbidden_destination_contexts
TAINT_POLICY: dict[tuple[TrustLevel, DataClass], list[str]] = {
    (TrustLevel.UNTRUSTED, DataClass.CREDENTIALS): [
        "notification_agent", "slack", "external_webhook", "email"
    ],
    (TrustLevel.UNTRUSTED, DataClass.PII): [
        "notification_agent", "external_webhook", "public_summary"
    ],
    (TrustLevel.UNTRUSTED, DataClass.INSTRUCTION): [
        "trade_executor", "deploy_agent", "action_agent"
    ],
    (TrustLevel.SEMI_TRUSTED, DataClass.CREDENTIALS): [
        "notification_agent", "external_webhook"
    ],
}
