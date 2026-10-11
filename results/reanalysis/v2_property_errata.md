# v2 dataset errata: SentinelAgent property ids

Dataset: `deepxpiabench-v2.jsonl` (sha256 prefix 5dd1af774da56259); property numbering: arXiv:2604.02767 Sec. III-B/C.
Command: `python results/reanalysis/v2_property_errata.py`

The v2 generator wrote P4 for cascade containment, P3 for forensic reconstructibility
and P5 for a 'tool integrity' property the paper does not define. Metrics never read
this field; read `ground_truth.delegation_property_violated` through this table.

| Taxonomy | v2 value | paper numbering | cases |
|---|---|---|---|
| DXPIA-004 | P4 | P5 (bounded_cascade_containment) | 25 |
| DXPIA-007 | P3 | P4 (forensic_reconstructibility) | 25 |
| DXPIA-008 | P5 | none (no counterpart in P1-P7) | 25 |

Total affected cases: 75

## DXPIA-004

- `DXPIA-004-fan_out-3a-bas-info-000`
- `DXPIA-004-fan_out-3a-del-data-000`
- `DXPIA-004-fan_out-3a-del-unau-000`
- `DXPIA-004-fan_out-3a-del-unau-001`
- `DXPIA-004-fan_out-3a-del-unau-002`
- `DXPIA-004-fan_out-3a-ins-data-000`
- `DXPIA-004-fan_out-3a-pla-unau-000`
- `DXPIA-004-fan_out-3a-rol-data-000`
- `DXPIA-004-fan_out-3a-rol-unau-000`
- `DXPIA-004-fan_out-3a-rol-unau-001`
- `DXPIA-004-fan_out-3a-uni-data-000`
- `DXPIA-004-fan_out-3a-uni-info-000`
- `DXPIA-004-fan_out-3a-uni-info-001`
- `DXPIA-004-linear-3a-bas-info-000`
- `DXPIA-004-linear-3a-bas-info-001`
- `DXPIA-004-linear-3a-bas-unau-000`
- `DXPIA-004-linear-3a-del-data-000`
- `DXPIA-004-linear-3a-del-info-000`
- `DXPIA-004-linear-3a-del-unau-000`
- `DXPIA-004-linear-3a-pla-info-000`
- `DXPIA-004-linear-3a-pla-unau-000`
- `DXPIA-004-linear-3a-rol-info-000`
- `DXPIA-004-linear-3a-rol-unau-000`
- `DXPIA-004-linear-3a-uni-data-000`
- `DXPIA-004-linear-3a-uni-unau-000`

## DXPIA-007

- `DXPIA-007-linear-3a-del-info-000`
- `DXPIA-007-linear-3a-del-info-001`
- `DXPIA-007-linear-3a-ins-data-000`
- `DXPIA-007-linear-3a-ins-info-000`
- `DXPIA-007-linear-3a-ins-info-001`
- `DXPIA-007-linear-3a-uni-info-000`
- `DXPIA-007-linear-4a-bas-data-000`
- `DXPIA-007-linear-4a-bas-info-000`
- `DXPIA-007-linear-4a-del-data-000`
- `DXPIA-007-linear-4a-ins-info-000`
- `DXPIA-007-linear-4a-pla-info-000`
- `DXPIA-007-linear-4a-uni-info-000`
- `DXPIA-007-linear-5a-pla-data-000`
- `DXPIA-007-linear-5a-uni-data-000`
- `DXPIA-007-loop-3a-bas-data-000`
- `DXPIA-007-loop-3a-bas-info-000`
- `DXPIA-007-loop-3a-ins-data-000`
- `DXPIA-007-loop-3a-rol-data-000`
- `DXPIA-007-loop-4a-ins-data-000`
- `DXPIA-007-loop-4a-ins-data-001`
- `DXPIA-007-loop-4a-ins-info-000`
- `DXPIA-007-loop-4a-pla-data-000`
- `DXPIA-007-loop-4a-rol-data-000`
- `DXPIA-007-loop-5a-ins-data-000`
- `DXPIA-007-loop-5a-pla-data-000`

## DXPIA-008

- `DXPIA-008-fan_out-2a-del-data-000`
- `DXPIA-008-fan_out-2a-ins-info-000`
- `DXPIA-008-fan_out-2a-pla-data-000`
- `DXPIA-008-fan_out-3a-rol-info-000`
- `DXPIA-008-fan_out-3a-uni-info-000`
- `DXPIA-008-fan_out-4a-bas-unau-000`
- `DXPIA-008-fan_out-4a-ins-info-000`
- `DXPIA-008-fan_out-4a-pla-info-000`
- `DXPIA-008-fan_out-4a-uni-info-000`
- `DXPIA-008-hierarchical-2a-del-data-000`
- `DXPIA-008-hierarchical-2a-del-unau-000`
- `DXPIA-008-hierarchical-2a-ins-info-000`
- `DXPIA-008-hierarchical-2a-rol-info-000`
- `DXPIA-008-hierarchical-2a-uni-unau-000`
- `DXPIA-008-hierarchical-3a-bas-info-000`
- `DXPIA-008-hierarchical-3a-rol-unau-000`
- `DXPIA-008-hierarchical-4a-bas-info-000`
- `DXPIA-008-hierarchical-4a-pla-data-000`
- `DXPIA-008-hierarchical-4a-rol-unau-000`
- `DXPIA-008-linear-2a-del-info-000`
- `DXPIA-008-linear-2a-rol-unau-000`
- `DXPIA-008-linear-3a-bas-info-000`
- `DXPIA-008-linear-4a-del-data-000`
- `DXPIA-008-linear-4a-del-info-000`
- `DXPIA-008-linear-4a-pla-info-000`
