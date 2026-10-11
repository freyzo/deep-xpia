# Depth-Dependent Accuracy (DDA) Analysis

> SIMULATED: heuristic priors from bench/runner.py, not measurements. Dataset deepxpiabench-v2.jsonl, n=5 runs/case, harness 6c867f2. Regenerate: results/simulated/regenerate.sh

DDA measures how detection accuracy changes as injection depth increases.
The hypothesis (from arXiv:2503.12188): detection degrades with depth,
especially for DXPIA-006 (intent laundering).

| Depth | none | intent-verify | taint | scope | dlp | context-budget | all |
|-------|-------|-------|-------|-------|-------|-------|-------|
| 1 | 0.000 | 0.540 | 0.040 | 0.140 | 0.160 | 0.040 | 0.640 |
| 2 | 0.035 | 0.471 | 0.399 | 0.431 | 0.293 | 0.234 | 0.756 |
| 3 | 0.000 | 0.545 | 0.394 | 0.267 | 0.333 | 0.261 | 0.685 |
| 4 | 0.000 | 0.295 | 0.333 | 0.124 | 0.210 | 0.333 | 0.638 |

## Interpretation

If detection accuracy decreases monotonically with depth: supports the
depth-decay hypothesis.

If no significant trend: also a finding -- challenges arXiv:2503.12188.
Report honestly either way. Note: the live (DEEPXPIA_LIVE=1) run did not
show depth decay; depth is confounded with attack type. See README.