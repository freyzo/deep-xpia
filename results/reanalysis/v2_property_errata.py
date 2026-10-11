"""Errata for ground_truth.delegation_property_violated in the frozen v2 dataset.

The v2 generator numbered SentinelAgent properties differently from the paper
(arXiv:2604.02767, Sec. III-B/C). The dataset file is immutable, so this lists
the cases whose id changes under the paper's numbering. No API calls.

Run from the repo root:
    python results/reanalysis/v2_property_errata.py > results/reanalysis/v2_property_errata.md
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

DATASET = Path("deepxpiabench-v2.jsonl")
TAXONOMY = Path("taxonomy/taxonomy.yaml")

# what v2 wrote -> what the paper's numbering gives (None: no counterpart in P1-P7)
REMAP = {
    "DXPIA-004": ("P4", "P5"),
    "DXPIA-007": ("P3", "P4"),
    "DXPIA-008": ("P5", None),
}


def main() -> None:
    raw = DATASET.read_bytes()
    cases = [json.loads(line) for line in raw.decode().splitlines() if line.strip()]
    names = yaml.safe_load(TAXONOMY.read_text())["sentinelagent_reference"]["properties"]
    out = [
        "# v2 dataset errata: SentinelAgent property ids",
        "",
        f"Dataset: `{DATASET}` (sha256 prefix {hashlib.sha256(raw).hexdigest()[:16]}); "
        "property numbering: arXiv:2604.02767 Sec. III-B/C.",
        "Command: `python results/reanalysis/v2_property_errata.py`",
        "",
        "The v2 generator wrote P4 for cascade containment, P3 for forensic reconstructibility",
        "and P5 for a 'tool integrity' property the paper does not define. Metrics never read",
        "this field; read `ground_truth.delegation_property_violated` through this table.",
        "",
        "| Taxonomy | v2 value | paper numbering | cases |",
        "|---|---|---|---|",
    ]
    affected: dict[str, list[str]] = {tid: [] for tid in REMAP}
    for c in cases:
        tid = c.get("taxonomy_id")
        if tid in REMAP:
            old, _ = REMAP[tid]
            if c["ground_truth"]["delegation_property_violated"] != old:
                raise SystemExit(f"{c['id']}: expected {old}, found {c['ground_truth']['delegation_property_violated']}")
            affected[tid].append(c["id"])
    for tid, (old, new) in REMAP.items():
        label = f"{new} ({names[new]})" if new else "none (no counterpart in P1-P7)"
        out.append(f"| {tid} | {old} | {label} | {len(affected[tid])} |")
    out += ["", f"Total affected cases: {sum(len(v) for v in affected.values())}", ""]
    for tid, ids in affected.items():
        out += [f"## {tid}", "", *[f"- `{i}`" for i in sorted(ids)], ""]
    print("\n".join(out).rstrip())


if __name__ == "__main__":
    main()
