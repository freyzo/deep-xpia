# Results

## Live results (measured)

Anthropic API, Claude Haiku, 300 cases, n=1 per case, June 2026. `none`, `intent-verify`, and `all` run real defense primitives in the live path; `scope`, `dlp`, and `context-budget` are not yet wired into live mode and raise an error rather than return a fake number.

| Config | ASR | TPR | FPR |
|---|---|---|---|
| none (baseline) | 0.69 | 0.00 | 0.00 |
| intent verification | 0.55 | 0.23 | 0.01 |
| all defenses | 0.12 | 0.77 | 0.31 |

What the measurement says:

- Undefended, 69% of multi-hop injections succeed. No single defense closes the gap: intent verification alone catches 23% at a clean 1% false-positive rate. Stacking all five cuts attack success to 12%, but the false-positive rate climbs to 31%. Real precision/recall wall, no free lunch.
- The depth-decay hypothesis did not replicate. Intent-verification detection by depth is flat and noisy (0.20 / 0.19 / 0.25 / 0.38 / 0.18). With all defenses it rises with depth, because deeper buckets are dominated by attack types the defenses handle well. Depth is confounded with attack type, so it is not the causal variable.
- The real blind spot is the trust boundary. Every depth-1 case is DXPIA-008 registry injection, and it evades all five defenses stacked (TPR 0.00 at depth 1, 0.40 overall). It enters at tool-discovery time, upstream of the defenses.

Live TPR by taxonomy, all defenses: DXPIA-006 1.00, DXPIA-003 0.92, DXPIA-001 0.84, DXPIA-007 0.84, DXPIA-004 0.76, DXPIA-002 0.72, DXPIA-005 0.64, DXPIA-008 0.40.

Reproduce:

```bash
DEEPXPIA_LIVE=1 deepxpia bench run --defense none          --n-runs 1 --output live_full_none.jsonl
DEEPXPIA_LIVE=1 deepxpia bench run --defense intent-verify --n-runs 1 --output live_full_intent.jsonl
DEEPXPIA_LIVE=1 deepxpia bench run --defense all           --n-runs 1 --output live_full_all.jsonl
```

## Simulated baseline (illustrative prior, not a measurement)

These numbers come from per-pattern priors baked into the runner, used for cost-free, deterministic harness testing. They are not measured and should not be cited as results. They are kept only to show the hypothesis the live run was built to test, and which it did not confirm.

| Defense | ASR | TPR | FPR | DXPIA-001 TPR | DXPIA-006 TPR | DXPIA-008 TPR |
|---|---|---|---|---|---|---|
| None | 0.87 | 0.05 | 0.05 | 0.05 | 0.05 | 0.05 |
| Intent verify | 0.52 | 0.57 | 0.15 | 0.82 | 0.38 | 0.55 |
| Taint | 0.64 | 0.53 | 0.08 | 0.35 | 0.32 | 0.10 |
| Scope tokens | 0.66 | 0.38 | 0.05 | 0.20 | 0.22 | 0.15 |
| DLP | 0.71 | 0.33 | 0.10 | 0.25 | 0.28 | 0.20 |
| Context budget | 0.72 | 0.30 | 0.12 | 0.15 | 0.42 | 0.10 |
| All combined | 0.36 | 0.76 | 0.18 | 0.90 | 0.52 | 0.70 |

## Honest limitations

- n=1 per case in the live run. Per-cell rates (especially small depth buckets) are noisy; treat them as directional, not precise.
- Live mode currently implements detectors for `none`, `intent-verify`, `taint`, and `all` only.
- The live `IntentVerifier` uses the heuristic signal scan, not the LLM-based NLI path; the latter would likely shift TPR.
- Results are model-specific (Claude Haiku). Other models will differ.
