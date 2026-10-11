# v2 live DDA under four depth definitions

- label: `case.depth` as published (results/depth_analysis.md, README).
- topology: `topology.hop_count`, the delegation edges built. 53 of 200 labels disagree with it (fan_out: 4, hierarchical: 35, linear: 7, loop: 7).
- executed: `len(topology.agents) - 1`, the LLM calls the v2 harness made in sequence. The harness ignored topology edges, so this is the right variable for these runs; an earlier version of this file called the topology column 'corrected depth', which was the wrong variable.
- payload_hops: executed calls from the injection hop on; the 44 last_hop cases are excluded because v2 never delivered their payload (results/reanalysis/v2_outcome_validity.md).

Inputs (sha256 prefix): `deepxpiabench-v2.jsonl` 5dd1af774da56259, `live_full_none.jsonl` 80ca7925ac6865fc, `live_full_intent.jsonl` ca7efaf096a3f5f9, `live_full_all.jsonl` ecc6dd19615ecd7e
Command: `python results/reanalysis/reanalyze_v2_depth.py`
Cells: TPR [Wilson 95% CI] (runs); n=1 run per case.

## defense = none

| Depth | label | topology | executed | payload_hops |
|---|---|---|---|---|
| 1 | 0.00 [0.00, 0.28] (10) | 0.00 [0.00, 0.28] (10) | 0.00 [0.00, 0.28] (10) | 0.00 [0.00, 0.11] (32) |
| 2 | 0.00 [0.00, 0.04] (90) | 0.00 [0.00, 0.03] (136) | 0.00 [0.00, 0.04] (90) | 0.00 [0.00, 0.04] (89) |
| 3 | 0.00 [0.00, 0.06] (59) | 0.00 [0.00, 0.10] (33) | 0.00 [0.00, 0.06] (59) | 0.00 [0.00, 0.11] (30) |
| 4 | 0.00 [0.00, 0.14] (24) | 0.00 [0.00, 0.15] (21) | 0.00 [0.00, 0.09] (41) | 0.00 [0.00, 0.43] (5) |
| 5 | 0.00 [0.00, 0.18] (17) | - | - | - |

## defense = intent-verify

| Depth | label | topology | executed | payload_hops |
|---|---|---|---|---|
| 1 | 0.20 [0.06, 0.51] (10) | 0.20 [0.06, 0.51] (10) | 0.20 [0.06, 0.51] (10) | 0.19 [0.09, 0.35] (32) |
| 2 | 0.19 [0.12, 0.28] (90) | 0.21 [0.15, 0.29] (136) | 0.19 [0.12, 0.28] (90) | 0.26 [0.18, 0.36] (89) |
| 3 | 0.25 [0.16, 0.38] (59) | 0.24 [0.13, 0.41] (33) | 0.25 [0.16, 0.38] (59) | 0.27 [0.14, 0.44] (30) |
| 4 | 0.38 [0.21, 0.57] (24) | 0.33 [0.17, 0.55] (21) | 0.29 [0.18, 0.44] (41) | 0.40 [0.12, 0.77] (5) |
| 5 | 0.18 [0.06, 0.41] (17) | - | - | - |

## defense = all

| Depth | label | topology | executed | payload_hops |
|---|---|---|---|---|
| 1 | 0.00 [0.00, 0.28] (10) | 0.00 [0.00, 0.28] (10) | 0.00 [0.00, 0.28] (10) | 0.56 [0.39, 0.72] (32) |
| 2 | 0.72 [0.62, 0.80] (90) | 0.76 [0.69, 0.83] (136) | 0.72 [0.62, 0.80] (90) | 0.88 [0.79, 0.93] (89) |
| 3 | 0.85 [0.73, 0.92] (59) | 0.88 [0.73, 0.95] (33) | 0.85 [0.73, 0.92] (59) | 0.80 [0.63, 0.90] (30) |
| 4 | 0.88 [0.69, 0.96] (24) | 0.95 [0.77, 0.99] (21) | 0.93 [0.81, 0.97] (41) | 0.80 [0.38, 0.96] (5) |
| 5 | 1.00 [0.82, 1.00] (17) | - | - | - |

