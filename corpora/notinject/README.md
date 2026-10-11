# NotInject (vendored)

339 benign prompts that contain words common in prompt injections (e.g. "ignore",
"override"), three difficulty levels by number of trigger words. Used as hard
negatives: a detector that flags them over-defends (workflow step P4.6).

- Source: Hugging Face dataset `leolee99/NotInject`, revision
  `847ae76cf8fea5ed325429e569ae8cfef022d2e0`, retrieved 2026-10-11.
- Paper: Li and Liu, "InjecGuard: Benchmarking and Mitigating Over-defense in Prompt
  Injection Guardrail Models", arXiv:2410.22770.
- License: MIT (dataset card). Copyright the original authors; redistributed here
  unmodified apart from flattening the three splits into one JSON-lines file
  (`split`, `row_idx`, `prompt`, `word_list`, `category`).
- Rebuild and verify: `python scripts/fetch_notinject.py` (checks the sha256 in
  `corpora/MANIFEST.yaml`).
