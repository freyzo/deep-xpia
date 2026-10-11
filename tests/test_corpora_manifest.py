"""corpora/MANIFEST.yaml: every third-party corpus has a license, a pinned source and a matching sha256."""

from __future__ import annotations

import hashlib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = yaml.safe_load((ROOT / "corpora/MANIFEST.yaml").read_text())


def test_entries_have_provenance() -> None:
    for c in MANIFEST["corpora"]:
        for key in ("name", "use", "source", "revision", "retrieved", "license", "redistribution", "sha256"):
            assert c.get(key), (c.get("name"), key)
        assert c["redistribution"] in ("vendored", "fetch-script")


def test_vendored_files_match_their_checksums() -> None:
    for c in MANIFEST["corpora"]:
        if c["redistribution"] == "vendored":
            data = (ROOT / c["file"]).read_bytes()
            assert hashlib.sha256(data).hexdigest() == c["sha256"], c["name"]
            assert sum(1 for ln in data.splitlines() if ln.strip()) == c["rows"], c["name"]
