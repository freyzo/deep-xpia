"""Event schema for the scenario event stream (WebSocket)."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel


class EventType(str, Enum):
    DELEGATION_RESULT = "delegation_result"
    CHAIN_COMPLETE = "chain_complete"
    ERROR = "error"


class ChainEvent(BaseModel):
    event_type: EventType
    chain_id: str
    hop_number: int
    hop_depth: int           # total depth of chain
    from_agent: str
    to_agent: str
    intent: str
    content: str
    drift_score: float       # 0=clean, 1=fully compromised
    taint_set: list[str]     # active taint labels
    timestamp_ms: float
    ground_truth_label: str  # for bench mode overlay
    metadata: dict[str, Any] = {}

