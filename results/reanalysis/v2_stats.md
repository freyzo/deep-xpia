# v2 statistics: paired tests, clustered CIs, depth slope

> Success rates use the PROVISIONAL outcome scorer (not yet validated against human labels).

Inputs (sha256 prefix): `deepxpiabench-v2.jsonl` 5dd1af774da56259, `live_full_none.jsonl` 80ca7925ac6865fc, `live_full_intent.jsonl` ca7efaf096a3f5f9, `live_full_all.jsonl` ecc6dd19615ecd7e
Command: `python results/reanalysis/stats_v2.py`
Delivered attack cases: 156; clean cases: 100; n=1 run per case.

## Paired comparisons (exact McNemar, Holm-adjusted across this table)

| Comparison | only first | only second | p | Holm p |
|---|---|---|---|---|
| detection: intent vs all (delivered attacks) | 3 | 88 | 1.02e-22 | 6.09e-22 |
| false positive: intent vs all (clean) | 1 | 31 | 1.54e-08 | 6.15e-08 |
| offline on identical outputs: intent vs either (delivered attacks) | 0 | 68 | 6.78e-21 | 3.39e-20 |
| re-scored success: none vs intent | 0 | 0 | 1 | 1 |
| re-scored success: none vs all | 0 | 1 | 1 | 1 |
| re-scored success: intent vs all | 0 | 1 | 1 | 1 |

## Detection intent vs all by taxonomy (exploratory; Holm across the 8 tests)

| Taxonomy | only intent | only all | p | Holm p |
|---|---|---|---|---|
| DXPIA-001 | 0 | 17 | 1.53e-05 | 0.000122 |
| DXPIA-002 | 0 | 10 | 0.00195 | 0.00781 |
| DXPIA-003 | 0 | 11 | 0.000977 | 0.00586 |
| DXPIA-004 | 0 | 11 | 0.000977 | 0.00586 |
| DXPIA-005 | 0 | 10 | 0.00195 | 0.00781 |
| DXPIA-006 | 0 | 15 | 6.1e-05 | 0.000427 |
| DXPIA-007 | 1 | 5 | 0.219 | 0.219 |
| DXPIA-008 | 2 | 9 | 0.0654 | 0.131 |

## Detection rate: Wilson vs template-clustered bootstrap (16 templates)

| Defense | rate | Wilson 95% | clustered bootstrap 95% |
|---|---|---|---|
| intent | 39/156 = 0.25 | [0.19, 0.32] | [0.13, 0.42] |
| all | 124/156 = 0.79 | [0.72, 0.85] | [0.69, 0.91] |

## Depth effect on detection (equivalence test)

Linear-probability slope of `detected` on depth, taxonomy fixed effects, template-cluster bootstrap
(2,000 draws). Slope = change in detection probability per extra hop. TOST at 5%: equivalence within
+-delta holds iff the 90% CI lies inside it; the last column is the smallest margin these data establish.

| Defense | depth | slope | 90% CI | 95% CI | n (clusters) | smallest margin shown |
|---|---|---|---|---|---|---|
| intent | executed calls | -0.026 | [-0.14, 0.06] | [-0.16, 0.08] | 156 (16) | +-0.14 |
| intent | hops after injection | +0.071 | [-0.01, 0.18] | [-0.02, 0.20] | 156 (16) | +-0.18 |
| all | executed calls | +0.143 | [0.07, 0.20] | [0.05, 0.21] | 156 (16) | +-0.20 |
| all | hops after injection | +0.113 | [0.05, 0.18] | [0.03, 0.20] | 156 (16) | +-0.18 |

## Reading

- Intent verification: the slope's 90% CI includes declines of up to 14 points per hop, and no margin
  was fixed in advance, so v2 does not establish that detection is stable with depth.
- Intent + taint: run-level detection rises with depth even within taxonomy, but a run gets one more
  chance to be flagged at every hop and the taint flag fires on about half of payload-free hops
  (v2_per_hop.md). A rising curve is expected without any depth effect on the detectors; per-hop
  rates (v2_per_hop.md) are the measure to use.
- The two configurations differ strongly in how often they fire, on attacks and on clean cases alike;
  with re-scored success near zero for every defense, v2 cannot show that either reduces attack success.
