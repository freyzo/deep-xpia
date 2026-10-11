"""results/CLAIMS.yaml values must recompute from the frozen raw runs.

Raw live runs are tracked in results/raw/v2-live-2026-06/ (MANIFEST.yaml);
the recompute tests skip only if they are absent (e.g. a partial checkout).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
import yaml

from deep_xpia.bench.metrics import compute_metrics
from deep_xpia.bench.schema import BenchCase, RunResult

ROOT = Path(__file__).resolve().parents[1]
LEDGER = yaml.safe_load((ROOT / "results/CLAIMS.yaml").read_text())
STATUSES = {"verified", "changed", "withdrawn", "simulated", "corrected", "unverifiable"}


def _lines(p: Path) -> list[str]:
    return [ln for ln in p.read_text().splitlines() if ln.strip()]


def test_ledger_schema() -> None:
    for entry in LEDGER["internal"] + LEDGER["external"]:
        assert entry["status"] in STATUSES, entry["id"]
    for entry in LEDGER["external"]:
        assert entry["url"].startswith("https://") and entry["accessed"], entry["id"]


def test_manifest_matches_frozen_checksums() -> None:
    sums = dict(
        reversed(line.split(None, 1))
        for line in (ROOT / "results/FROZEN_SHA256SUMS").read_text().splitlines()
        if line.strip()
    )
    manifest = yaml.safe_load((ROOT / "results/raw/v2-live-2026-06/MANIFEST.yaml").read_text())
    for f in manifest["files"]:
        assert sums[f["file"]] == f["sha256"]
    assert sums["deepxpiabench-v2.jsonl"] == manifest["dataset"]["sha256"]
    assert hashlib.sha256((ROOT / "deepxpiabench-v2.jsonl").read_bytes()).hexdigest() == manifest["dataset"]["sha256"]


@pytest.mark.parametrize("entry", [e for e in LEDGER["internal"] if "value" in e and isinstance(e.get("artifact"), str)
                                   and e["artifact"].startswith("results/raw/")], ids=lambda e: e["id"])
def test_live_values_recompute(entry: dict) -> None:
    raw = ROOT / entry["artifact"]
    if not raw.exists():
        pytest.skip(f"{raw.name} not present (raw runs are not in git)")
    cases = [BenchCase.model_validate_json(ln) for ln in _lines(ROOT / "deepxpiabench-v2.jsonl")]
    m = compute_metrics(cases, [RunResult.model_validate_json(ln) for ln in _lines(raw)], 1)
    got = {"asr": m.asr_mean, "tpr": m.tpr_mean, "fpr": m.fpr_mean,
           "asr_ci": m.asr_ci, "tpr_ci": m.tpr_ci, "fpr_ci": m.fpr_ci}
    for key, want in entry["value"].items():
        if key in got:
            have = got[key]
            if isinstance(want, list):
                assert [round(x, 2) for x in have] == want, (entry["id"], key)
            else:
                assert round(have, 2) == want, (entry["id"], key)


def test_internal_artifacts_exist() -> None:
    """Every artifact an internal claim points to is a file in the repo."""
    for entry in LEDGER["internal"]:
        artifacts = entry.get("artifact", [])
        for a in [artifacts] if isinstance(artifacts, str) else artifacts:
            if " " not in a and "/" in a or a.endswith((".jsonl", ".md", ".py", ".yaml")):
                assert (ROOT / a).exists(), (entry["id"], a)


def test_internal_ids_unique_and_sequential() -> None:
    ids = [int(e["id"][1:]) for e in LEDGER["internal"]]
    assert ids == list(range(1, len(ids) + 1))
