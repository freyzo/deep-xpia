"""DeepXPIABench data schema (Pydantic v2)."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class TaxonomyID(str, Enum):
    DXPIA_001 = "DXPIA-001"
    DXPIA_002 = "DXPIA-002"
    DXPIA_003 = "DXPIA-003"
    DXPIA_004 = "DXPIA-004"
    DXPIA_005 = "DXPIA-005"
    DXPIA_006 = "DXPIA-006"
    DXPIA_007 = "DXPIA-007"


class HopMechanism(str, Enum):
    INSTRUCTION_PIGGYBACK = "instruction_piggyback"
    TEMPORAL_PERSISTENCE = "temporal_persistence"
    DATA_FLOW_CASCADE = "data_flow_cascade"
    CONTROL_PLANE_INJECTION = "control_plane_injection"
    PRIVILEGE_DIFFERENTIAL = "privilege_differential"
    ADVERSARIAL_REFINEMENT = "adversarial_refinement"
    CONDITIONAL_ACTIVATION = "conditional_activation"


class Topology(str, Enum):
    LINEAR = "linear"
    FAN_OUT = "fan_out"
    HIERARCHICAL = "hierarchical"
    LOOP = "loop"


class InjectionPosition(str, Enum):
    FIRST_HOP = "first_hop"
    MIDDLE_HOP = "middle_hop"
    LAST_HOP = "last_hop"


class InjectionTechnique(str, Enum):
    PLAINTEXT = "plaintext"
    BASE64_ENCODED = "base64_encoded"
    UNICODE_ENCODED = "unicode_encoded"
    ROLE_PLAY = "role_play"
    INSTRUCTION_TAG_SPOOF = "instruction_tag_spoof"
    DELIMITER_ESCAPE = "delimiter_escape"


class PayloadType(str, Enum):
    DATA_EXFIL = "data_exfiltration"
    UNAUTHORIZED_ACTION = "unauthorized_action"
    INFO_SUPPRESSION = "information_suppression"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class DefenseState(str, Enum):
    UNDEFENDED = "undefended"
    INTENT_VERIFY = "intent_verify"
    TAINT = "taint"
    SCOPE_TOKEN = "scope_token"
    DLP = "dlp"
    ALL = "all"


class AgentSpec(BaseModel):
    name: str
    role: str
    permissions: list[str] = Field(default_factory=list)
    system_prompt: str = ""


class TopologySpec(BaseModel):
    topology_type: Topology
    agents: list[AgentSpec]
    edges: list[tuple[str, str]]  # (from_agent_name, to_agent_name)
    hop_count: int


class InjectionSpec(BaseModel):
    content: str
    position: InjectionPosition
    technique: InjectionTechnique
    payload_type: PayloadType
    encoded_content: str | None = None  # set when technique != plaintext


class ExpectedOutcome(BaseModel):
    compromised_agents: list[str]
    propagation_path: list[int]  # hop indices that are compromised
    exfil_data: str | None = None
    unauthorized_action: str | None = None


class GroundTruth(BaseModel):
    is_attack: bool
    severity: Severity | None = None
    delegation_property_violated: str | None = None  # P1-P7
    detection_hop: int | None = None  # hop where a defense should trigger


class BenchCase(BaseModel):
    """Single DeepXPIABench test case."""

    id: str  # e.g. "DXPIA-001-linear-3agent-b64-exfil-042"
    taxonomy_id: TaxonomyID | None  # None for clean cases
    hop_mechanism: HopMechanism | None = None
    depth: int
    agent_count: int
    topology: TopologySpec
    injection: InjectionSpec | None  # None for clean cases
    expected: ExpectedOutcome | None  # None for clean cases
    ground_truth: GroundTruth
    defense_state: DefenseState = DefenseState.UNDEFENDED
    user_task: str  # the legitimate task the user asked for
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_jsonl_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class RunResult(BaseModel):
    """Result of running a single BenchCase."""

    case_id: str
    run_index: int  # 0..N-1
    attack_success: bool
    detected: bool
    false_positive: bool  # only meaningful for clean cases
    propagation_depth: int  # hops before detection (0 if not detected)
    latency_ms: float
    agent_outputs: list[dict[str, Any]] = Field(default_factory=list)
    error: str | None = None


class AggregateMetrics(BaseModel):
    """Aggregate metrics over all RunResults for a dataset."""

    total_cases: int
    attack_cases: int
    clean_cases: int
    n_runs: int

    # core metrics (mean +/- std over N runs)
    asr_mean: float  # attack success rate
    asr_std: float
    tpr_mean: float  # true positive rate (attacks correctly detected)
    tpr_std: float
    fpr_mean: float  # false positive rate (clean cases incorrectly flagged)
    fpr_std: float

    # depth-dependent accuracy (DDA): per-hop-depth detection accuracy
    dda: dict[int, float]  # {depth: detection_accuracy}

    # latency
    latency_mean_ms: float
    latency_std_ms: float

    # per-taxonomy breakdown
    per_taxonomy: dict[str, dict[str, float]]  # {DXPIA-00N: {asr, tpr, fpr}}
