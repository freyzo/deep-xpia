# Depth-Dependent Accuracy (DDA) Analysis

DDA measures how detection accuracy changes as injection depth increases.
The hypothesis (from arXiv:2503.12188): detection degrades with depth,
especially for DXPIA-006 (intent laundering).

| Depth | none | intent-verify | taint | scope | dlp | all |
|-------|-------|-------|-------|-------|-------|-------|
| 2 | 0.033 | 0.473 | 0.424 | 0.648 | 0.282 | 0.879 |
| 3 | 0.000 | 0.518 | 0.492 | 0.262 | 0.344 | 0.718 |
| 4 | 0.000 | 0.315 | 0.438 | 0.192 | 0.231 | 0.615 |
| 5 | 0.000 | 0.305 | 0.389 | 0.179 | 0.337 | 0.526 |

## Interpretation

If detection accuracy decreases monotonically with depth: confirms the
deep-xpia hypothesis. This is the headline finding.

If no significant trend: also a finding -- challenges arXiv:2503.12188.
Report honestly either way.