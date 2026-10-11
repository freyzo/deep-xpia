"""paper/related_work.yaml: every entry complete, unique and linked to a primary page."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
MATRIX = yaml.safe_load((ROOT / "paper/related_work.yaml").read_text())


def test_entries_complete_and_unique() -> None:
    fields = MATRIX["fields"]
    ids = [e["id"] for e in MATRIX["entries"]]
    assert len(ids) == len(set(ids))
    for e in MATRIX["entries"]:
        assert list(e) == fields, e["id"]
        assert all(isinstance(e[f], str) and e[f].strip() for f in fields), e["id"]
        assert e["url"].startswith("https://"), e["id"]


def test_arxiv_ids_match_urls() -> None:
    import re

    for e in MATRIX["entries"]:
        m = re.search(r"arXiv:(\d{4}\.\d{5})", e["ref"])
        if m:
            assert e["url"] == f"https://arxiv.org/abs/{m.group(1)}", e["id"]
