"""Recompute v2 live DDA with corrected depth (topology.hop_count) vs published labels.

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


def main() -> None:
    cases = [BenchCase.model_validate_json(ln) for ln in _lines(DATASET)]
    attacks = [c for c in cases if c.ground_truth.is_attack]
    mism = [c for c in attacks if c.depth != c.topology.hop_count]
    by_topo: dict[str, int] = {}
    for c in mism:
        by_topo[c.topology.topology_type.value] = by_topo.get(c.topology.topology_type.value, 0) + 1

    out = [
        "# v2 live DDA: published depth labels vs corrected depth",
        "",
        "Depth := number of agent-to-agent delegation edges (`topology.hop_count`).",
        f"The v2 generator wrote `case.depth` labels that disagree with `hop_count` for "
        f"{len(mism)} of {len(attacks)} attack cases ({', '.join(f'{k}: {v}' for k, v in sorted(by_topo.items()))}).",
        "Published tables (results/depth_analysis.md, README) used the labels.",
        "",
        "Inputs (sha256 prefix): " + ", ".join(f"`{p.name}` {_sha(p)}" for p in [DATASET, *RUNS.values()]),
        "Command: `python results/reanalysis/reanalyze_v2_depth.py`",
        "CIs: Wilson 95%, n=1 run per case.",
        "",
    ]
    for label, path in RUNS.items():
        rs = [RunResult.model_validate_json(ln) for ln in _lines(path)]
        m_lab = compute_metrics(cases, rs, 1, depth_source="label")
        m_top = compute_metrics(cases, rs, 1, depth_source="topology")
        out += [
            f"## defense = {label}",
            "",
            "| Depth | TPR (published label) [CI] | n | TPR (topology) [CI] | n |",
            "|---|---|---|---|---|",
        ]
        for d in sorted(set(m_lab.dda) | set(m_top.dda)):
            def cell(m, d=d):
                if d not in m.dda:
                    return "-", 0
                lo, hi = m.dda_ci[d]
                return f"{m.dda[d]:.2f} [{lo:.2f}, {hi:.2f}]", m.dda_n[d]
            a, na = cell(m_lab)
            b, nb = cell(m_top)
            out.append(f"| {d} | {a} | {na} | {b} | {nb} |")
        out.append("")
    print("\n".join(out))


if __name__ == "__main__":
    main()
