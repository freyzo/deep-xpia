# v2 live DDA: published depth labels vs corrected depth

Depth := number of agent-to-agent delegation edges (`topology.hop_count`).
The v2 generator wrote `case.depth` labels that disagree with `hop_count` for 53 of 200 attack cases (fan_out: 4, hierarchical: 35, linear: 7, loop: 7).
Published tables (results/depth_analysis.md, README) used the labels.

Inputs (sha256 prefix): `deepxpiabench-v2.jsonl` 5dd1af774da56259, `live_full_none.jsonl` 80ca7925ac6865fc, `live_full_intent.jsonl` ca7efaf096a3f5f9, `live_full_all.jsonl` ecc6dd19615ecd7e
Command: `python results/reanalysis/reanalyze_v2_depth.py`
CIs: Wilson 95%, n=1 run per case.

## defense = none

| Depth | TPR (published label) [CI] | n | TPR (topology) [CI] | n |
|---|---|---|---|---|
| 1 | 0.00 [0.00, 0.28] | 10 | 0.00 [0.00, 0.28] | 10 |
| 2 | 0.00 [0.00, 0.04] | 90 | 0.00 [0.00, 0.03] | 136 |
| 3 | 0.00 [0.00, 0.06] | 59 | 0.00 [0.00, 0.10] | 33 |
| 4 | 0.00 [0.00, 0.14] | 24 | 0.00 [0.00, 0.15] | 21 |
| 5 | 0.00 [0.00, 0.18] | 17 | - | 0 |

## defense = intent-verify

| Depth | TPR (published label) [CI] | n | TPR (topology) [CI] | n |
|---|---|---|---|---|
| 1 | 0.20 [0.06, 0.51] | 10 | 0.20 [0.06, 0.51] | 10 |
| 2 | 0.19 [0.12, 0.28] | 90 | 0.21 [0.15, 0.29] | 136 |
| 3 | 0.25 [0.16, 0.38] | 59 | 0.24 [0.13, 0.41] | 33 |
| 4 | 0.38 [0.21, 0.57] | 24 | 0.33 [0.17, 0.55] | 21 |
| 5 | 0.18 [0.06, 0.41] | 17 | - | 0 |

## defense = all

| Depth | TPR (published label) [CI] | n | TPR (topology) [CI] | n |
|---|---|---|---|---|
| 1 | 0.00 [0.00, 0.28] | 10 | 0.00 [0.00, 0.28] | 10 |
| 2 | 0.72 [0.62, 0.80] | 90 | 0.76 [0.69, 0.83] | 136 |
| 3 | 0.85 [0.73, 0.92] | 59 | 0.88 [0.73, 0.95] | 33 |
| 4 | 0.88 [0.69, 0.96] | 24 | 0.95 [0.77, 0.99] | 21 |
| 5 | 1.00 [0.82, 1.00] | 17 | - | 0 |

