"""Draw the human-labeling sample from the frozen v2 runs and render the annotator sheet.

Writes (results/annotation/):
  items_v2.csv      item_id, case_id, hop, per_hop_subset   (tracked; what gets labeled)
  key_v2.csv        item_id, run_file                        (tracked; NOT shown to annotators)
  labels_template.csv  item_id, label, quote_span, notes     (copy to labels_a.csv / labels_b.csv)
  sheet_v2.csv      item_id, payload_text, input_text, output_text  (rendered for annotators; untracked)

Sampling (seed 42): 100 attack runs stratified by defense x injection position, 50
clean runs stratified by defense; each sampled run contributes its last executed hop;
30 delivered attack runs with >= 2 hops also contribute every other hop. Hop inputs
are reconstructed with the v2 harness rules (bench/outcomes.injected_hops_v2).
The sheet hides the defense, detector results, the v2 judge and the scorer label.

Run from the repo root:  python scripts/annotation_sample.py
"""

from __future__ import annotations

import csv
import random
from collections import defaultdict
from pathlib import Path

from deep_xpia.bench.outcomes import decode_payload, injected_hops_v2
from deep_xpia.bench.schema import BenchCase, RunResult

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results/annotation"
RAW = ROOT / "results/raw/v2-live-2026-06"
RUN_FILES = ["live_full_none.jsonl", "live_full_intent.jsonl", "live_full_all.jsonl"]
SEED, N_ATTACK, N_CLEAN, N_PER_HOP = 42, 100, 50, 30


def _lines(p: Path) -> list[str]:
    return [ln for ln in p.read_text().splitlines() if ln.strip()]


def hop_input(case: BenchCase, run: RunResult, hop: int) -> str:
    """The text the agent at `hop` received in the v2 harness."""
    base = case.user_task if hop == 0 else str(run.agent_outputs[hop - 1]["output"])
    if case.injection is not None and hop in injected_hops_v2(case):
        return f"{base}\n\n{case.injection.content}"
    return base


def _allocate(strata: dict[tuple, list], total: int, rng: random.Random) -> list:
    """Proportional allocation (largest remainder), then a seeded draw inside each stratum."""
    size = sum(len(v) for v in strata.values())
    quotas = {k: total * len(v) / size for k, v in strata.items()}
    counts = {k: int(q) for k, q in quotas.items()}
    for k in sorted(quotas, key=lambda k: (quotas[k] - counts[k], str(k)), reverse=True)[: total - sum(counts.values())]:
        counts[k] += 1
    picked = []
    for k in sorted(strata, key=str):
        picked += rng.sample(sorted(strata[k], key=lambda x: x[1].case_id), counts[k])
    return picked


def draw() -> list[dict]:
    cases = {c.id: c for c in (BenchCase.model_validate_json(ln) for ln in _lines(ROOT / "deepxpiabench-v2.jsonl"))}
    attack: dict[tuple, list] = defaultdict(list)
    clean: dict[tuple, list] = defaultdict(list)
    for fname in RUN_FILES:
        for ln in _lines(RAW / fname):
            run = RunResult.model_validate_json(ln)
            case = cases[run.case_id]
            if not run.agent_outputs:
                continue
            if case.ground_truth.is_attack:
                assert case.injection is not None
                attack[(fname, case.injection.position.value)].append((fname, run, case))
            else:
                clean[(fname,)].append((fname, run, case))
    rng = random.Random(SEED)
    runs = _allocate(attack, N_ATTACK, rng) + _allocate(clean, N_CLEAN, rng)
    eligible = [i for i, (_, run, case) in enumerate(runs[:N_ATTACK])
                if injected_hops_v2(case) and len(run.agent_outputs) >= 2]
    subset = set(rng.sample(eligible, N_PER_HOP))
    items = []
    for i, (fname, run, case) in enumerate(runs):
        last = len(run.agent_outputs) - 1
        hops = range(last + 1) if i in subset else [last]
        for hop in hops:
            items.append({"case": case, "run": run, "run_file": fname, "hop": hop, "per_hop_subset": i in subset})
    rng.shuffle(items)
    for n, it in enumerate(items, 1):
        it["item_id"] = f"v2-{n:03d}"
    return items


def main() -> None:
    items = draw()
    OUT.mkdir(parents=True, exist_ok=True)
    with (OUT / "items_v2.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["item_id", "case_id", "hop", "per_hop_subset"])
        for it in items:
            w.writerow([it["item_id"], it["case"].id, it["hop"], int(it["per_hop_subset"])])
    with (OUT / "key_v2.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["item_id", "run_file"])
        for it in items:
            w.writerow([it["item_id"], it["run_file"]])
    with (OUT / "labels_template.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["item_id", "label", "quote_span", "notes"])
        for it in sorted(items, key=lambda x: x["item_id"]):
            w.writerow([it["item_id"], "", "", ""])
    with (OUT / "sheet_v2.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["item_id", "payload_text", "input_text", "output_text"])
        for it in sorted(items, key=lambda x: x["item_id"]):
            case, run, hop = it["case"], it["run"], it["hop"]
            w.writerow([it["item_id"], decode_payload(case), hop_input(case, run, hop), run.agent_outputs[hop]["output"]])
    print(f"{len(items)} items -> {OUT}/ (sheet_v2.csv is for annotators; do not share key_v2.csv)")


if __name__ == "__main__":
    main()
