"""Over-defense of the in-house detectors on NotInject (339 benign trigger-word prompts).

Every prompt is benign, so any flag is a false positive. Detectors as the live
runner applies them: intent verification (keyword heuristic, threshold 0.5),
the taint content flag (credential / instruction words), and registration-time
tool-metadata scanning (verify_tool_metadata, threshold 0.15) applied to the
same text. No API calls.

Run from the repo root:
    python results/reanalysis/notinject_overdefense.py > results/reanalysis/notinject_overdefense.md
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path

from deep_xpia.bench.metrics import wilson_ci
from deep_xpia.defenses.intent_verify import IntentVerifier
from deep_xpia.defenses.taint import infer_data_classes
from deep_xpia.defenses.taint_types import DataClass

DATA = Path("corpora/notinject/notinject.jsonl")


def flags(prompt: str) -> dict[str, bool]:
    iv = IntentVerifier(threshold=0.5)
    dcs = infer_data_classes(prompt)
    return {
        "intent verification": iv.verify(hop=1, agent="", intent="", response=prompt).blocked,
        "taint flag": DataClass.CREDENTIALS in dcs or DataClass.INSTRUCTION in dcs,
        "tool-metadata scan": iv.verify_tool_metadata(tool_name="", description=prompt).blocked,
    }


def main() -> None:
    rows = [json.loads(ln) for ln in DATA.read_text().splitlines() if ln.strip()]
    by: dict[str, dict[str, list[int]]] = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    for r in rows:
        f = flags(r["prompt"])
        for group in ("all", f"split {r['split']}", f"category {r['category']}"):
            for det, hit in f.items():
                by[group][det][0] += hit
                by[group][det][1] += 1
    dets = list(flags("").keys())
    out = [
        "# Detector over-defense on NotInject",
        "",
        f"Input: `{DATA}` (sha256 prefix {hashlib.sha256(DATA.read_bytes()).hexdigest()[:16]}; "
        "corpora/MANIFEST.yaml). Every prompt is benign: a flag is a false positive.",
        "Command: `python results/reanalysis/notinject_overdefense.py`",
        "Cells: false-positive rate [Wilson 95% CI] (n). Splits one/two/three = 1/2/3 trigger words per prompt.",
        "",
        "| Group | " + " | ".join(dets) + " |",
        "|---|" + "---|" * len(dets),
    ]
    order = ["all"] + sorted(k for k in by if k.startswith("split")) + sorted(k for k in by if k.startswith("category"))
    for g in order:
        cells = []
        for d in dets:
            k, n = by[g][d]
            lo, hi = wilson_ci(k, n)
            cells.append(f"{k / n:.2f} [{lo:.2f}, {hi:.2f}] ({n})")
        out.append(f"| {g} | " + " | ".join(cells) + " |")
    out += [
        "",
        "The keyword detectors rarely fire here: NotInject's trigger words (e.g. 'ignore') are not their",
        "keywords. Their false positives come from task wording in agent outputs instead (taint flag fires",
        "on 0.44-0.75 of payload-free hops after hop 0, v2_per_hop.md), so a domain-specific benign set is",
        "the more telling over-defense test for them. InjecGuard (arXiv:2410.22770) reports open-source",
        "guard models close to chance on NotInject, which is what this set is built to expose.",
    ]
    print("\n".join(out))


if __name__ == "__main__":
    main()
