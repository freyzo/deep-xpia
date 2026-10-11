#!/usr/bin/env bash
# Regenerate the simulated (illustrative prior) tables. Deterministic: same
# harness commit + dataset => byte-identical outputs. No API calls.
set -euo pipefail
cd "$(dirname "$0")/../.."
DEFENSES=(none intent-verify taint scope dlp context-budget all)
for d in "${DEFENSES[@]}"; do
  deepxpia bench run --dataset deepxpiabench-v2.jsonl --defense "$d" --n-runs 5 \
    --output "results/simulated/raw/$d.jsonl" >/dev/null
done
args=()
for d in "${DEFENSES[@]}"; do args+=("$d=results/simulated/raw/$d.jsonl"); done
deepxpia bench report "${args[@]}" --dataset deepxpiabench-v2.jsonl --out-dir results/simulated \
  --note "SIMULATED: heuristic priors from bench/runner.py, not measurements. Dataset deepxpiabench-v2.jsonl, n=5 runs/case, harness $(git rev-parse --short HEAD). Regenerate: results/simulated/regenerate.sh"
cp results/simulated/coverage_matrix.md results/coverage_matrix.md
