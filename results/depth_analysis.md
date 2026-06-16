# Depth-Dependent Accuracy (DDA) Analysis

DDA measures how detection accuracy changes as injection depth increases.
The hypothesis (from arXiv:2503.12188): detection degrades with depth,
especially for DXPIA-006 (intent laundering).

## Live result (measured): hypothesis NOT confirmed

Claude Haiku, 300 cases, n=1 per case, June 2026. Detection (TPR) by depth:

| Depth | none | intent-verify | all |
|-------|------|---------------|-----|
| 1 | 0.00 | 0.20 | 0.00 |
| 2 | 0.00 | 0.19 | 0.72 |
| 3 | 0.00 | 0.25 | 0.85 |
| 4 | 0.00 | 0.38 | 0.88 |
| 5 | 0.00 | 0.18 | 1.00 |

Detection does not decrease monotonically with depth. With intent verification
it is flat and noisy; with all defenses it rises with depth. Depth is confounded
with attack type (depth-1 cases are all DXPIA-008 registry injection, which evades
prompt-stream defenses). So depth is not the causal variable. Per the protocol
below, this is reported as a finding that challenges arXiv:2503.12188: hop count
does not predict detection; trust-boundary position and attack type do.

## Simulated prior (illustrative, not a measurement)

The table below came from the heuristic simulator and modeled the hypothesized
decline. It did not replicate live and is kept only for reference.

| Depth | none | intent-verify | taint | scope | dlp | all |
|-------|-------|-------|-------|-------|-------|-------|
| 2 | 0.033 | 0.473 | 0.424 | 0.648 | 0.282 | 0.879 |
| 3 | 0.000 | 0.518 | 0.492 | 0.262 | 0.344 | 0.718 |
| 4 | 0.000 | 0.315 | 0.438 | 0.192 | 0.231 | 0.615 |
| 5 | 0.000 | 0.305 | 0.389 | 0.179 | 0.337 | 0.526 |
