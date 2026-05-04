"""WebSocket event types for the delegation chain visualizer."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel


class EventType(str, Enum):
    DELEGATION_START = "delegation_start"
    DELEGATION_RESULT = "delegation_result"
    TRUST_BREACH = "trust_breach"
    MEMORY_WRITE = "memory_write"
    TOOL_CALL = "tool_call"
    EXFIL_ATTEMPT = "exfil_attempt"
    CHAIN_COMPLETE = "chain_complete"
    BENCH_PROGRESS = "bench_progress"


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


class BenchProgressEvent(BaseModel):
    event_type: EventType = EventType.BENCH_PROGRESS
    cases_run: int
    cases_total: int
    asr_current: float
    tpr_current: float
    fpr_current: float
    dda_current: dict[int, float]
    per_taxonomy_current: dict[str, dict[str, float]]
