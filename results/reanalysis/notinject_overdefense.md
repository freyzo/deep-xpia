# Detector over-defense on NotInject

Input: `corpora/notinject/notinject.jsonl` (sha256 prefix c9f77fddd3803e9b; corpora/MANIFEST.yaml). Every prompt is benign: a flag is a false positive.
Command: `python results/reanalysis/notinject_overdefense.py`
Cells: false-positive rate [Wilson 95% CI] (n). Splits one/two/three = 1/2/3 trigger words per prompt.

| Group | intent verification | taint flag | tool-metadata scan |
|---|---|---|---|
| all | 0.00 [0.00, 0.01] (339) | 0.03 [0.01, 0.05] (339) | 0.01 [0.01, 0.03] (339) |
| split NotInject_one | 0.00 [0.00, 0.03] (113) | 0.02 [0.00, 0.06] (113) | 0.00 [0.00, 0.03] (113) |
| split NotInject_three | 0.00 [0.00, 0.03] (113) | 0.04 [0.01, 0.09] (113) | 0.03 [0.01, 0.08] (113) |
| split NotInject_two | 0.00 [0.00, 0.03] (113) | 0.03 [0.01, 0.08] (113) | 0.02 [0.00, 0.06] (113) |
| category Common Queries | 0.00 [0.00, 0.03] (126) | 0.03 [0.01, 0.08] (126) | 0.01 [0.00, 0.04] (126) |
| category Multilingual | 0.00 [0.00, 0.04] (84) | 0.00 [0.00, 0.04] (84) | 0.00 [0.00, 0.04] (84) |
| category Technique Queries | 0.00 [0.00, 0.04] (87) | 0.05 [0.02, 0.11] (87) | 0.05 [0.02, 0.11] (87) |
| category Virtual Creation | 0.00 [0.00, 0.08] (42) | 0.02 [0.00, 0.12] (42) | 0.00 [0.00, 0.08] (42) |

The keyword detectors rarely fire here: NotInject's trigger words (e.g. 'ignore') are not their
keywords. Their false positives come from task wording in agent outputs instead (taint flag fires
on 0.44-0.75 of payload-free hops after hop 0, v2_per_hop.md), so a domain-specific benign set is
the more telling over-defense test for them. InjecGuard (arXiv:2410.22770) reports open-source
guard models close to chance on NotInject, which is what this set is built to expose.
