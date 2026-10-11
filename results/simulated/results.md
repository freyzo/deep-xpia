> SIMULATED: heuristic priors from bench/runner.py, not measurements. Dataset deepxpiabench-v2.jsonl, n=5 runs/case, harness 6c867f2. Regenerate: results/simulated/regenerate.sh

## Results: defense=none

Cases: 300 total (200 attack, 100 clean), N=5 runs/case

| Metric | Value [95% Wilson CI] |
|--------|-------|
| ASR (attack success rate) | 0.872 [0.850, 0.891] |
| TPR (detection rate) | 0.024 [0.016, 0.035] |
| FPR (false positive rate) | 0.060 [0.042, 0.084] |
| Latency | 139.2 ± 38.1 ms |

### Per-Taxonomy Breakdown

| Attack ID | ASR [95% CI] | TPR [95% CI] | FPR |
|-----------|-----|-----|-----|
| DXPIA-001 | 0.936 [0.879, 0.967] | 0.040 [0.017, 0.090] | n/a |
| DXPIA-002 | 0.888 [0.821, 0.932] | 0.008 [0.001, 0.044] | n/a |
| DXPIA-003 | 0.832 [0.757, 0.887] | 0.000 [0.000, 0.030] | n/a |
| DXPIA-004 | 0.776 [0.695, 0.840] | 0.048 [0.022, 0.101] | n/a |
| DXPIA-005 | 0.888 [0.821, 0.932] | 0.064 [0.033, 0.121] | n/a |
| DXPIA-006 | 0.912 [0.849, 0.950] | 0.000 [0.000, 0.030] | n/a |
| DXPIA-007 | 0.784 [0.704, 0.847] | 0.024 [0.008, 0.068] | n/a |
| DXPIA-008 | 0.960 [0.910, 0.983] | 0.008 [0.001, 0.044] | n/a |

### Depth-Dependent Accuracy (DDA)

| Injection Depth | Detection Accuracy [95% CI] | Runs |
|----------------|-------------------|------|
| 1 | 0.000 [0.000, 0.071] | 50 |
| 2 | 0.035 [0.024, 0.052] | 680 |
| 3 | 0.000 [0.000, 0.023] | 165 |
| 4 | 0.000 [0.000, 0.035] | 105 |

### Context Accumulation Score (CAS)

Detection accuracy by (depth, breadth_ratio bucket).
breadth_ratio = mean(accessed/available) across hops per case.
Buckets: low=[0,0.33), med=[0.33,0.66), high=[0.66,1.0]

| Depth x Breadth | Detection Accuracy |
|----------------|-------------------|
| d1_brmed | 0.000 |
| d2_brhigh | 0.000 |
| d2_brmed | 0.036 |
| d3_brhigh | 0.000 |
| d3_brmed | 0.000 |
| d4_brmed | 0.000 |

## Results: defense=intent-verify

Cases: 300 total (200 attack, 100 clean), N=5 runs/case

| Metric | Value [95% Wilson CI] |
|--------|-------|
| ASR (attack success rate) | 0.550 [0.519, 0.581] |
| TPR (detection rate) | 0.468 [0.437, 0.499] |
| FPR (false positive rate) | 0.158 [0.129, 0.193] |
| Latency | 193.1 ± 62.9 ms |

### Per-Taxonomy Breakdown

| Attack ID | ASR [95% CI] | TPR [95% CI] | FPR |
|-----------|-----|-----|-----|
| DXPIA-001 | 0.264 [0.195, 0.347] | 0.856 [0.784, 0.907] | n/a |
| DXPIA-002 | 0.696 [0.611, 0.770] | 0.392 [0.311, 0.480] | n/a |
| DXPIA-003 | 0.480 [0.394, 0.567] | 0.472 [0.387, 0.559] | n/a |
| DXPIA-004 | 0.600 [0.512, 0.682] | 0.504 [0.418, 0.590] | n/a |
| DXPIA-005 | 0.688 [0.602, 0.763] | 0.400 [0.318, 0.488] | n/a |
| DXPIA-006 | 0.720 [0.636, 0.791] | 0.200 [0.139, 0.279] | n/a |
| DXPIA-007 | 0.600 [0.512, 0.682] | 0.384 [0.303, 0.472] | n/a |
| DXPIA-008 | 0.352 [0.274, 0.439] | 0.536 [0.449, 0.621] | n/a |

### Depth-Dependent Accuracy (DDA)

| Injection Depth | Detection Accuracy [95% CI] | Runs |
|----------------|-------------------|------|
| 1 | 0.540 [0.404, 0.670] | 50 |
| 2 | 0.471 [0.433, 0.508] | 680 |
| 3 | 0.545 [0.469, 0.620] | 165 |
| 4 | 0.295 [0.216, 0.388] | 105 |

### Context Accumulation Score (CAS)

Detection accuracy by (depth, breadth_ratio bucket).
breadth_ratio = mean(accessed/available) across hops per case.
Buckets: low=[0,0.33), med=[0.33,0.66), high=[0.66,1.0]

| Depth x Breadth | Detection Accuracy |
|----------------|-------------------|
| d1_brmed | 0.540 |
| d2_brhigh | 0.400 |
| d2_brmed | 0.471 |
| d3_brhigh | 0.600 |
| d3_brmed | 0.544 |
| d4_brmed | 0.295 |

## Results: defense=taint

Cases: 300 total (200 attack, 100 clean), N=5 runs/case

| Metric | Value [95% Wilson CI] |
|--------|-------|
| ASR (attack success rate) | 0.636 [0.606, 0.665] |
| TPR (detection rate) | 0.373 [0.344, 0.403] |
| FPR (false positive rate) | 0.088 [0.066, 0.116] |
| Latency | 152.9 ± 42.5 ms |

### Per-Taxonomy Breakdown

| Attack ID | ASR [95% CI] | TPR [95% CI] | FPR |
|-----------|-----|-----|-----|
| DXPIA-001 | 0.728 [0.644, 0.798] | 0.376 [0.296, 0.463] | n/a |
| DXPIA-002 | 0.464 [0.379, 0.551] | 0.608 [0.520, 0.689] | n/a |
| DXPIA-003 | 0.392 [0.311, 0.480] | 0.624 [0.537, 0.704] | n/a |
| DXPIA-004 | 0.728 [0.644, 0.798] | 0.304 [0.230, 0.389] | n/a |
| DXPIA-005 | 0.608 [0.520, 0.689] | 0.496 [0.410, 0.582] | n/a |
| DXPIA-006 | 0.752 [0.670, 0.819] | 0.112 [0.068, 0.179] | n/a |
| DXPIA-007 | 0.544 [0.457, 0.629] | 0.432 [0.348, 0.520] | n/a |
| DXPIA-008 | 0.872 [0.802, 0.920] | 0.032 [0.013, 0.079] | n/a |

### Depth-Dependent Accuracy (DDA)

| Injection Depth | Detection Accuracy [95% CI] | Runs |
|----------------|-------------------|------|
| 1 | 0.040 [0.011, 0.135] | 50 |
| 2 | 0.399 [0.362, 0.436] | 680 |
| 3 | 0.394 [0.323, 0.470] | 165 |
| 4 | 0.333 [0.250, 0.428] | 105 |

### Context Accumulation Score (CAS)

Detection accuracy by (depth, breadth_ratio bucket).
breadth_ratio = mean(accessed/available) across hops per case.
Buckets: low=[0,0.33), med=[0.33,0.66), high=[0.66,1.0]

| Depth x Breadth | Detection Accuracy |
|----------------|-------------------|
| d1_brmed | 0.040 |
| d2_brhigh | 0.600 |
| d2_brmed | 0.397 |
| d3_brhigh | 0.400 |
| d3_brmed | 0.394 |
| d4_brmed | 0.333 |

## Results: defense=scope

Cases: 300 total (200 attack, 100 clean), N=5 runs/case

| Metric | Value [95% Wilson CI] |
|--------|-------|
| ASR (attack success rate) | 0.668 [0.638, 0.696] |
| TPR (detection rate) | 0.357 [0.328, 0.387] |
| FPR (false positive rate) | 0.060 [0.042, 0.084] |
| Latency | 147.3 ± 40.4 ms |

### Per-Taxonomy Breakdown

| Attack ID | ASR [95% CI] | TPR [95% CI] | FPR |
|-----------|-----|-----|-----|
| DXPIA-001 | 0.856 [0.784, 0.907] | 0.208 [0.146, 0.287] | n/a |
| DXPIA-002 | 0.792 [0.713, 0.854] | 0.248 [0.181, 0.330] | n/a |
| DXPIA-003 | 0.672 [0.586, 0.748] | 0.296 [0.223, 0.381] | n/a |
| DXPIA-004 | 0.376 [0.296, 0.463] | 0.816 [0.739, 0.874] | n/a |
| DXPIA-005 | 0.304 [0.230, 0.389] | 0.848 [0.775, 0.900] | n/a |
| DXPIA-006 | 0.848 [0.775, 0.900] | 0.064 [0.033, 0.121] | n/a |
| DXPIA-007 | 0.656 [0.569, 0.734] | 0.248 [0.181, 0.330] | n/a |
| DXPIA-008 | 0.840 [0.766, 0.894] | 0.128 [0.080, 0.198] | n/a |

### Depth-Dependent Accuracy (DDA)

| Injection Depth | Detection Accuracy [95% CI] | Runs |
|----------------|-------------------|------|
| 1 | 0.140 [0.070, 0.262] | 50 |
| 2 | 0.431 [0.394, 0.468] | 680 |
| 3 | 0.267 [0.205, 0.339] | 165 |
| 4 | 0.124 [0.074, 0.200] | 105 |

### Context Accumulation Score (CAS)

Detection accuracy by (depth, breadth_ratio bucket).
breadth_ratio = mean(accessed/available) across hops per case.
Buckets: low=[0,0.33), med=[0.33,0.66), high=[0.66,1.0]

| Depth x Breadth | Detection Accuracy |
|----------------|-------------------|
| d1_brmed | 0.140 |
| d2_brhigh | 1.000 |
| d2_brmed | 0.427 |
| d3_brhigh | 0.000 |
| d3_brmed | 0.275 |
| d4_brmed | 0.124 |

## Results: defense=dlp

Cases: 300 total (200 attack, 100 clean), N=5 runs/case

| Metric | Value [95% Wilson CI] |
|--------|-------|
| ASR (attack success rate) | 0.718 [0.689, 0.745] |
| TPR (detection rate) | 0.284 [0.257, 0.313] |
| FPR (false positive rate) | 0.110 [0.085, 0.140] |
| Latency | 149.5 ± 41.2 ms |

### Per-Taxonomy Breakdown

| Attack ID | ASR [95% CI] | TPR [95% CI] | FPR |
|-----------|-----|-----|-----|
| DXPIA-001 | 0.784 [0.704, 0.847] | 0.264 [0.195, 0.347] | n/a |
| DXPIA-002 | 0.744 [0.661, 0.812] | 0.256 [0.188, 0.339] | n/a |
| DXPIA-003 | 0.440 [0.356, 0.528] | 0.576 [0.488, 0.659] | n/a |
| DXPIA-004 | 0.752 [0.670, 0.819] | 0.264 [0.195, 0.347] | n/a |
| DXPIA-005 | 0.800 [0.721, 0.861] | 0.280 [0.209, 0.364] | n/a |
| DXPIA-006 | 0.808 [0.730, 0.867] | 0.112 [0.068, 0.179] | n/a |
| DXPIA-007 | 0.632 [0.545, 0.711] | 0.344 [0.266, 0.431] | n/a |
| DXPIA-008 | 0.784 [0.704, 0.847] | 0.176 [0.119, 0.252] | n/a |

### Depth-Dependent Accuracy (DDA)

| Injection Depth | Detection Accuracy [95% CI] | Runs |
|----------------|-------------------|------|
| 1 | 0.160 [0.083, 0.285] | 50 |
| 2 | 0.293 [0.260, 0.328] | 680 |
| 3 | 0.333 [0.266, 0.408] | 165 |
| 4 | 0.210 [0.143, 0.297] | 105 |

### Context Accumulation Score (CAS)

Detection accuracy by (depth, breadth_ratio bucket).
breadth_ratio = mean(accessed/available) across hops per case.
Buckets: low=[0,0.33), med=[0.33,0.66), high=[0.66,1.0]

| Depth x Breadth | Detection Accuracy |
|----------------|-------------------|
| d1_brmed | 0.160 |
| d2_brhigh | 0.200 |
| d2_brmed | 0.293 |
| d3_brhigh | 0.000 |
| d3_brmed | 0.344 |
| d4_brmed | 0.210 |

## Results: defense=context-budget

Cases: 300 total (200 attack, 100 clean), N=5 runs/case

| Metric | Value [95% Wilson CI] |
|--------|-------|
| ASR (attack success rate) | 0.716 [0.687, 0.743] |
| TPR (detection rate) | 0.239 [0.214, 0.266] |
| FPR (false positive rate) | 0.128 [0.102, 0.160] |
| Latency | 156.6 ± 44.0 ms |

### Per-Taxonomy Breakdown

| Attack ID | ASR [95% CI] | TPR [95% CI] | FPR |
|-----------|-----|-----|-----|
| DXPIA-001 | 0.856 [0.784, 0.907] | 0.144 [0.093, 0.216] | n/a |
| DXPIA-002 | 0.720 [0.636, 0.791] | 0.344 [0.266, 0.431] | n/a |
| DXPIA-003 | 0.416 [0.333, 0.504] | 0.504 [0.418, 0.590] | n/a |
| DXPIA-004 | 0.752 [0.670, 0.819] | 0.224 [0.160, 0.305] | n/a |
| DXPIA-005 | 0.800 [0.721, 0.861] | 0.216 [0.153, 0.296] | n/a |
| DXPIA-006 | 0.656 [0.569, 0.734] | 0.248 [0.181, 0.330] | n/a |
| DXPIA-007 | 0.656 [0.569, 0.734] | 0.200 [0.139, 0.279] | n/a |
| DXPIA-008 | 0.872 [0.802, 0.920] | 0.032 [0.013, 0.079] | n/a |

### Depth-Dependent Accuracy (DDA)

| Injection Depth | Detection Accuracy [95% CI] | Runs |
|----------------|-------------------|------|
| 1 | 0.040 [0.011, 0.135] | 50 |
| 2 | 0.234 [0.204, 0.267] | 680 |
| 3 | 0.261 [0.200, 0.332] | 165 |
| 4 | 0.333 [0.250, 0.428] | 105 |

### Context Accumulation Score (CAS)

Detection accuracy by (depth, breadth_ratio bucket).
breadth_ratio = mean(accessed/available) across hops per case.
Buckets: low=[0,0.33), med=[0.33,0.66), high=[0.66,1.0]

| Depth x Breadth | Detection Accuracy |
|----------------|-------------------|
| d1_brmed | 0.040 |
| d2_brhigh | 0.200 |
| d2_brmed | 0.234 |
| d3_brhigh | 0.000 |
| d3_brmed | 0.269 |
| d4_brmed | 0.333 |

## Results: defense=all

Cases: 300 total (200 attack, 100 clean), N=5 runs/case

| Metric | Value [95% Wilson CI] |
|--------|-------|
| ASR (attack success rate) | 0.265 [0.239, 0.293] |
| TPR (detection rate) | 0.726 [0.698, 0.753] |
| FPR (false positive rate) | 0.180 [0.149, 0.216] |
| Latency | 237.1 ± 90.5 ms |

### Per-Taxonomy Breakdown

| Attack ID | ASR [95% CI] | TPR [95% CI] | FPR |
|-----------|-----|-----|-----|
| DXPIA-001 | 0.136 [0.087, 0.207] | 0.888 [0.821, 0.932] | n/a |
| DXPIA-002 | 0.288 [0.216, 0.373] | 0.656 [0.569, 0.734] | n/a |
| DXPIA-003 | 0.160 [0.106, 0.234] | 0.712 [0.627, 0.784] | n/a |
| DXPIA-004 | 0.256 [0.188, 0.339] | 0.864 [0.793, 0.913] | n/a |
| DXPIA-005 | 0.216 [0.153, 0.296] | 0.904 [0.840, 0.944] | n/a |
| DXPIA-006 | 0.504 [0.418, 0.590] | 0.416 [0.333, 0.504] | n/a |
| DXPIA-007 | 0.360 [0.281, 0.447] | 0.688 [0.602, 0.763] | n/a |
| DXPIA-008 | 0.200 [0.139, 0.279] | 0.680 [0.594, 0.755] | n/a |

### Depth-Dependent Accuracy (DDA)

| Injection Depth | Detection Accuracy [95% CI] | Runs |
|----------------|-------------------|------|
| 1 | 0.640 [0.501, 0.759] | 50 |
| 2 | 0.756 [0.722, 0.787] | 680 |
| 3 | 0.685 [0.610, 0.751] | 165 |
| 4 | 0.638 [0.543, 0.724] | 105 |

### Context Accumulation Score (CAS)

Detection accuracy by (depth, breadth_ratio bucket).
breadth_ratio = mean(accessed/available) across hops per case.
Buckets: low=[0,0.33), med=[0.33,0.66), high=[0.66,1.0]

| Depth x Breadth | Detection Accuracy |
|----------------|-------------------|
| d1_brmed | 0.640 |
| d2_brhigh | 1.000 |
| d2_brmed | 0.754 |
| d3_brhigh | 0.600 |
| d3_brmed | 0.688 |
| d4_brmed | 0.638 |