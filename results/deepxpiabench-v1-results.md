# DeepXPIABench v1 Results

**Dataset:** 250 cases (150 attack, 100 clean)  
**Runs:** N=5 per case  
**Model:** heuristic simulation (set `DEEPXPIA_LIVE=1` for real API calls)  
**Seed:** 42

## Core Results Table

| Defense | ASR | TPR | FPR | Latency |
|---------|-----|-----|-----|---------|
| None (baseline) | 0.983 ± 0.089 | 0.015 ± 0.057 | 0.050 ± 0.099 | 138 ms |
| Intent verify | 0.567 ± 0.272 | 0.436 ± 0.272 | 0.164 ± 0.171 | 185 ms |
| Taint tracking | 0.567 ± 0.278 | 0.440 ± 0.264 | 0.078 ± 0.132 | 150 ms |
| Scope tokens | 0.620 ± 0.333 | 0.409 ± 0.340 | 0.050 ± 0.099 | 143 ms |
| DLP | 0.709 ± 0.244 | 0.296 ± 0.242 | 0.108 ± 0.156 | 146 ms |
| All combined | **0.280 ± 0.249** | **0.747 ± 0.245** | 0.204 ± 0.192 | 209 ms |

ASR = attack success rate (lower is better with defense).  
TPR = true positive rate / detection rate (higher is better).  
FPR = false positive rate on clean cases (lower is better).

## Depth-Dependent Accuracy (DDA)

**All defenses combined -- detection accuracy by injection depth:**

| Depth | Accuracy |
|-------|----------|
| 2 | 0.879 |
| 3 | 0.718 |
| 4 | 0.615 |
| 5 | 0.526 |

**The headline finding:** Detection accuracy drops 35 points (0.879 → 0.526) as injection depth increases from 2 to 5 hops. Even with all defenses active, a depth-5 injection succeeds nearly half the time.

**Intent verify DDA:**

| Depth | Accuracy |
|-------|----------|
| 2 | 0.473 |
| 3 | 0.518 |
| 4 | 0.315 |
| 5 | 0.305 |

**Scope token DDA (steepest degradation):**

| Depth | Accuracy |
|-------|----------|
| 2 | 0.648 |
| 3 | 0.262 |
| 4 | 0.192 |
| 5 | 0.179 |

Scope tokens work well at shallow depth but degrade sharply by depth 3. Authority narrowing enforcement is most effective at the first delegation boundary.

## Per-Taxonomy TPR (intent verify)

See `coverage_matrix.md` for full defense x taxonomy breakdown.

Key result: DXPIA-006 (intent laundering) has the lowest TPR across all defenses, consistent with the hypothesis that laundering improves injection quality at each hop.

## Failure Analysis

**What breaks at depth 5:**
- Intent verify: laundered instructions (DXPIA-006) have near-zero drift score at hops 2+. The injection looks like natural delegation output.
- Taint tracking: provenance lost at memory boundaries (DXPIA-002). The store must be taint-aware.
- Scope tokens: instruction smuggling within authorized actions (DXPIA-001). The text action type is too broad.

**FPR note:** All-combined defense has the highest FPR (0.204). Layering defenses increases false positives -- each defense contributes independently to the false alarm rate. This is expected; operators should tune thresholds based on acceptable FPR.

## Reproducibility

```bash
deepxpia bench generate --seed 42 --n-attack 150 --n-clean 100
deepxpia bench run --defense none
deepxpia bench run --defense all
```

Results vary by ±0.01-0.03 across seeds due to RNG in the heuristic simulator. Run with `DEEPXPIA_LIVE=1` for model-grounded results.
