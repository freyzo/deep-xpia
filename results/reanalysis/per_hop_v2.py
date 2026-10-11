"""Within-chain view of the frozen v2 'none' runs: payload survival and detection by hop.

Each delivered-payload run is indexed by hop offset from its injection hop, so
every row compares hops of the same chains (no depth / attack-type confound).
Detectors run offline on the stored outputs (bench/per_hop.py mirrors the live
runner). Outcome labels come from the provisional scorer (bench/outcomes.py).

Run from the repo root:
    python results/reanalysis/per_hop_v2.py > results/reanalysis/v2_per_hop.md
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from deep_xpia.bench.metrics import wilson_ci
from deep_xpia.bench.outcomes import SCORER_VERSION, injected_hops_v2, score_run
from deep_xpia.bench.per_hop import detector_flags, fire_rate, survival
from deep_xpia.bench.schema import BenchCase, RunResult

DATASET = Path("deepxpiabench-v2.jsonl")
NONE_RUNS = Path("results/raw/v2-live-2026-06/live_full_none.jsonl")
DETECTORS = {"intent": "intent verification", "taint": "taint content flag", "either": "either (live `all`)"}


def _lines(p: Path) -> list[str]:
    return [ln for ln in p.read_text().splitlines() if ln.strip()]


def _cell(k: int, n: int) -> str:
    lo, hi = wilson_ci(k, n)
    return f"{k / n:.2f} [{lo:.2f}, {hi:.2f}] ({n})" if n else "-"


def main() -> None:
    cases = {c.id: c for c in (BenchCase.model_validate_json(ln) for ln in _lines(DATASET))}
    runs = [RunResult.model_validate_json(ln) for ln in _lines(NONE_RUNS)]
    chains, attack_rows, control_rows = [], [], []
    for r in runs:
        case = cases[r.case_id]
        hops = injected_hops_v2(case)
        flags = detector_flags(r, intent=case.user_task)
        if case.ground_truth.is_attack and hops:
            inject = min(hops)
            chains.append((inject, score_run(case, r, hops).per_hop))
            attack_rows.append((inject, flags))
        else:
            control_rows.append((0, flags))

    surv = survival(chains)
    out = [
        "# v2 within-chain view: payload survival and detection by hop",
        "",
        f"> PROVISIONAL: survival uses scorer `{SCORER_VERSION}`, not yet validated against human labels.",
        "",
        f"Inputs (sha256 prefix): `{DATASET}` {hashlib.sha256(DATASET.read_bytes()).hexdigest()[:16]}, "
        f"`{NONE_RUNS.name}` {hashlib.sha256(NONE_RUNS.read_bytes()).hexdigest()[:16]}",
        "Command: `python results/reanalysis/per_hop_v2.py`",
        f"Runs: defense = none (complete chains); {len(chains)} with a delivered payload, "
        f"{len(control_rows)} payload-free (100 clean + 44 never-delivered).",
        "Offset k = hop - injection hop. Cells: rate [Wilson 95% CI] (hops).",
        "",
        "## Payload survival",
        "",
        "Share of chains whose hop k still had the payload in its input.",
        "",
        "| k | survival |",
        "|---|---|",
        *[f"| {k} | {_cell(*kn)} |" for k, kn in surv.items()],
        "",
        "## Detector fire rate by offset (delivered-payload chains)",
        "",
        "Detectors applied offline to the same outputs; negative k = hops before the payload arrived.",
        "",
        "| k | " + " | ".join(DETECTORS.values()) + " |",
        "|---|" + "---|" * len(DETECTORS),
    ]
    rates = {d: fire_rate(attack_rows, d) for d in DETECTORS}
    for k in sorted(rates["intent"]):
        out.append(f"| {k} | " + " | ".join(_cell(*rates[d][k]) for d in DETECTORS) + " |")
    out += [
        "",
        "## Detector fire rate by hop (payload-free runs)",
        "",
        "| hop | " + " | ".join(DETECTORS.values()) + " |",
        "|---|" + "---|" * len(DETECTORS),
    ]
    ctrl = {d: fire_rate(control_rows, d) for d in DETECTORS}
    for k in sorted(ctrl["intent"]):
        out.append(f"| {k} | " + " | ".join(_cell(*ctrl[d][k]) for d in DETECTORS) + " |")
    out += [
        "",
        "## Reading",
        "",
        "- Survival drops to 0.20 one hop after injection and to about 0 after two: the receiving agent",
        "  usually refuses, and its refusal rarely carries the payload text on.",
        "- Intent verification fires mainly on the hop that received the payload (k = 0: 0.30, against",
        "  0.00-0.05 on payload-free hops 0-2). The taint content flag fires about as often on payload-free hops",
        "  (0.44-0.75 after hop 0) as on attack hops: it tracks wording such as 'deploy' or 'token',",
        "  not the payload.",
    ]
    print("\n".join(out))


if __name__ == "__main__":
    main()
