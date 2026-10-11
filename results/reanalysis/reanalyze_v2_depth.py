"""Recompute v2 live DDA under four depth definitions.

label        case.depth as published (v2 generator labels)
topology     topology.hop_count, the delegation edges built
executed     len(topology.agents) - 1, the sequential LLM calls the v2 harness made
             (it ignored topology edges): the right variable for these runs
payload_hops executed calls from the injection hop on (first_hop / tool_metadata 0,
             middle_hop max_hop // 2); last_hop cases excluded, v2 never delivered them

Inputs are the frozen artifacts listed in results/FROZEN_SHA256SUMS; no API calls.
Run from the repo root:
    python results/reanalysis/reanalyze_v2_depth.py > results/reanalysis/dda_v2_corrected_depth.md
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from deep_xpia.bench.metrics import compute_metrics
from deep_xpia.bench.schema import BenchCase, RunResult

DATASET = Path("deepxpiabench-v2.jsonl")
RUNS = {
    "none": Path("results/raw/v2-live-2026-06/live_full_none.jsonl"),
    "intent-verify": Path("results/raw/v2-live-2026-06/live_full_intent.jsonl"),
    "all": Path("results/raw/v2-live-2026-06/live_full_all.jsonl"),
}


def _lines(p: Path) -> list[str]:
    return [ln for ln in p.read_text().splitlines() if ln.strip()]


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()[:16]


def _payload_hops(case: BenchCase) -> int | None:
    """Executed calls from the injection hop on, under v2 harness semantics (None: never delivered)."""
    if case.injection is None:
        return None
    max_hop = len(case.topology.agents) - 1
    pos = case.injection.position.value
    if pos == "last_hop":
        return None
    inject_hop = max_hop // 2 if pos == "middle_hop" else 0
    return max_hop - inject_hop


def main() -> None:
    cases = [BenchCase.model_validate_json(ln) for ln in _lines(DATASET)]
    attacks = [c for c in cases if c.ground_truth.is_attack]
    mism = [c for c in attacks if c.depth != c.topology.hop_count]
    by_topo: dict[str, int] = {}
    for c in mism:
        by_topo[c.topology.topology_type.value] = by_topo.get(c.topology.topology_type.value, 0) + 1

    out = [
        "# v2 live DDA under four depth definitions",
        "",
        "- label: `case.depth` as published (results/depth_analysis.md, README).",
        "- topology: `topology.hop_count`, the delegation edges built. "
        f"{len(mism)} of {len(attacks)} labels disagree with it "
        f"({', '.join(f'{k}: {v}' for k, v in sorted(by_topo.items()))}).",
        "- executed: `len(topology.agents) - 1`, the LLM calls the v2 harness made in sequence. "
        "The harness ignored topology edges, so this is the right variable for these runs; "
        "an earlier version of this file called the topology column 'corrected depth', which was the wrong variable.",
        "- payload_hops: executed calls from the injection hop on; the 44 last_hop cases are excluded "
        "because v2 never delivered their payload (results/reanalysis/v2_outcome_validity.md).",
        "",
        "Inputs (sha256 prefix): " + ", ".join(f"`{p.name}` {_sha(p)}" for p in [DATASET, *RUNS.values()]),
        "Command: `python results/reanalysis/reanalyze_v2_depth.py`",
        "Cells: TPR [Wilson 95% CI] (runs); n=1 run per case.",
        "",
    ]
    delivered = [
        c.model_copy(update={"depth": _payload_hops(c)}) for c in cases
        if not c.ground_truth.is_attack or _payload_hops(c) is not None
    ]
    for label, path in RUNS.items():
        rs = [RunResult.model_validate_json(ln) for ln in _lines(path)]
        tables = {
            "label": compute_metrics(cases, rs, 1, depth_source="label"),
            "topology": compute_metrics(cases, rs, 1, depth_source="topology"),
            "executed": compute_metrics(cases, rs, 1, depth_source="executed"),
            "payload_hops": compute_metrics(delivered, rs, 1, depth_source="label"),
        }
        out += [
            f"## defense = {label}",
            "",
            "| Depth | " + " | ".join(tables) + " |",
            "|---|" + "---|" * len(tables),
        ]
        for d in sorted(set().union(*(m.dda for m in tables.values()))):
            cells = []
            for m in tables.values():
                if d not in m.dda:
                    cells.append("-")
                else:
                    lo, hi = m.dda_ci[d]
                    cells.append(f"{m.dda[d]:.2f} [{lo:.2f}, {hi:.2f}] ({m.dda_n[d]})")
            out.append(f"| {d} | " + " | ".join(cells) + " |")
        out.append("")
    print("\n".join(out))


if __name__ == "__main__":
    main()
