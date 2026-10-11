"""Rebuild corpora/notinject/notinject.jsonl from Hugging Face and verify its sha256.

Uses the public datasets-server rows API (no account needed). The three splits
are flattened into one JSON-lines file sorted by (split, row_idx).
Run from the repo root:  python scripts/fetch_notinject.py
"""

from __future__ import annotations

import hashlib
import json
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
API = "https://datasets-server.huggingface.co/rows?dataset=leolee99%2FNotInject&config=default&split={split}&offset={offset}&length=100"
SPLITS = ("NotInject_one", "NotInject_two", "NotInject_three")


def main() -> None:
    entry = next(c for c in yaml.safe_load((ROOT / "corpora/MANIFEST.yaml").read_text())["corpora"] if c["name"] == "notinject")
    rows = []
    for split in SPLITS:
        for offset in (0, 100):
            with urllib.request.urlopen(API.format(split=split, offset=offset), timeout=30) as resp:
                for r in json.load(resp)["rows"]:
                    row = r["row"]
                    rows.append({"split": split, "row_idx": r["row_idx"], "prompt": row["prompt"],
                                 "word_list": row["word_list"], "category": row["category"]})
    rows.sort(key=lambda r: (r["split"], r["row_idx"]))
    data = "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in rows).encode()
    digest = hashlib.sha256(data).hexdigest()
    if len(rows) != entry["rows"] or digest != entry["sha256"]:
        raise SystemExit(f"mismatch: {len(rows)} rows, sha256 {digest} (manifest: {entry['rows']}, {entry['sha256']})")
    (ROOT / entry["file"]).write_bytes(data)
    print(f"ok: {len(rows)} rows, sha256 {digest}")


if __name__ == "__main__":
    main()
