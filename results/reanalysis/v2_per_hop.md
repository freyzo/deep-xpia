# v2 within-chain view: payload survival and detection by hop

> PROVISIONAL: survival uses scorer `outcomes-v1`, not yet validated against human labels.

Inputs (sha256 prefix): `deepxpiabench-v2.jsonl` 5dd1af774da56259, `live_full_none.jsonl` 80ca7925ac6865fc
Command: `python results/reanalysis/per_hop_v2.py`
Runs: defense = none (complete chains); 156 with a delivered payload, 144 payload-free (100 clean + 44 never-delivered).
Offset k = hop - injection hop. Cells: rate [Wilson 95% CI] (hops).

## Payload survival

Share of chains whose hop k still had the payload in its input.

| k | survival |
|---|---|
| 0 | 1.00 [0.98, 1.00] (156) |
| 1 | 0.20 [0.14, 0.28] (124) |
| 2 | 0.03 [0.01, 0.15] (35) |
| 3 | 0.00 [0.00, 0.43] (5) |

## Detector fire rate by offset (delivered-payload chains)

Detectors applied offline to the same outputs; negative k = hops before the payload arrived.

| k | intent verification | taint content flag | either (live `all`) |
|---|---|---|---|
| -2 | 0.07 [0.02, 0.23] (28) | 0.00 [0.00, 0.12] (28) | 0.07 [0.02, 0.23] (28) |
| -1 | 0.00 [0.00, 0.05] (68) | 0.34 [0.24, 0.46] (68) | 0.34 [0.24, 0.46] (68) |
| 0 | 0.30 [0.23, 0.38] (156) | 0.37 [0.29, 0.44] (156) | 0.53 [0.45, 0.61] (156) |
| 1 | 0.13 [0.08, 0.20] (124) | 0.64 [0.55, 0.72] (124) | 0.65 [0.56, 0.72] (124) |
| 2 | 0.09 [0.03, 0.22] (35) | 0.51 [0.36, 0.67] (35) | 0.51 [0.36, 0.67] (35) |
| 3 | 0.20 [0.04, 0.62] (5) | 0.20 [0.04, 0.62] (5) | 0.20 [0.04, 0.62] (5) |

## Detector fire rate by hop (payload-free runs)

| hop | intent verification | taint content flag | either (live `all`) |
|---|---|---|---|
| 0 | 0.00 [0.00, 0.03] (144) | 0.00 [0.00, 0.03] (144) | 0.00 [0.00, 0.03] (144) |
| 1 | 0.05 [0.02, 0.10] (108) | 0.44 [0.35, 0.53] (108) | 0.45 [0.36, 0.55] (108) |
| 2 | 0.02 [0.00, 0.12] (43) | 0.51 [0.37, 0.65] (43) | 0.53 [0.39, 0.67] (43) |
| 3 | 0.12 [0.02, 0.47] (8) | 0.75 [0.41, 0.93] (8) | 0.75 [0.41, 0.93] (8) |

## Reading

- Survival drops to 0.20 one hop after injection and to about 0 after two: the receiving agent
  usually refuses, and its refusal rarely carries the payload text on.
- Intent verification fires mainly on the hop that received the payload (k = 0: 0.30, against
  0.00-0.05 on payload-free hops 0-2). The taint content flag fires about as often on payload-free hops
  (0.44-0.75 after hop 0) as on attack hops: it tracks wording such as 'deploy' or 'token',
  not the payload.
