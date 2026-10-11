# Depth-Dependent Accuracy (DDA) Analysis

DDA measures how detection accuracy changes as injection depth increases.
Our hypothesis: detection degrades with depth, especially for DXPIA-006
(intent laundering). It is motivated by the laundering mechanism in
arXiv:2503.12188 (Sec. 4), which does not itself test depth.

## Live result (measured): hypothesis NOT confirmed

Claude Haiku, 300 cases, n=1 per case, June 2026. Detection (TPR) by published depth label.
The v2 harness ran each case as a chain of agents - 1 calls, ignoring topology, so labels 1-4
equal the calls made and label-5 cases made 4. Tables by label, topology, executed calls and
hops after injection, with 95% CIs: [reanalysis/dda_v2_corrected_depth.md](reanalysis/dda_v2_corrected_depth.md):

| Depth | none | intent-verify | all |
|-------|------|---------------|-----|
| 1 | 0.00 | 0.20 | 0.00 |
| 2 | 0.00 | 0.19 | 0.72 |
| 3 | 0.00 | 0.25 | 0.85 |
| 4 | 0.00 | 0.38 | 0.88 |
| 5 | 0.00 | 0.18 | 1.00 |

Detection does not decrease monotonically with depth. With intent verification
it is flat and noisy; with intent verification + taint (live `all`) it rises with depth.
Depth is confounded with attack type (all depth-1 cases are DXPIA-008, which the v2
harness delivered as a hop-0 prompt injection), so these buckets cannot isolate a
depth effect. The hypothesis was ours; the v2 data neither supports it nor rules
it out.

## Simulated prior (illustrative, not a measurement)

The table below came from the heuristic simulator and modeled the hypothesized
decline. It did not replicate live and is kept only for reference.

| Depth | none | intent-verify | taint | scope | dlp | all |
|-------|-------|-------|-------|-------|-------|-------|
| 2 | 0.033 | 0.473 | 0.424 | 0.648 | 0.282 | 0.879 |
| 3 | 0.000 | 0.518 | 0.492 | 0.262 | 0.344 | 0.718 |
| 4 | 0.000 | 0.315 | 0.438 | 0.192 | 0.231 | 0.615 |
| 5 | 0.000 | 0.305 | 0.389 | 0.179 | 0.337 | 0.526 |
