"""Committed re-analysis reports must equal what their scripts print from the frozen inputs."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

REPORTS = [
    ("results/reanalysis/v2_property_errata.py", "results/reanalysis/v2_property_errata.md"),
    ("results/reanalysis/audit_v2_outcomes.py", "results/reanalysis/v2_outcome_validity.md"),
    ("results/reanalysis/reanalyze_v2_depth.py", "results/reanalysis/dda_v2_corrected_depth.md"),
    ("results/reanalysis/rescore_v2.py", "results/reanalysis/v2_rescored.md"),
    ("results/reanalysis/per_hop_v2.py", "results/reanalysis/v2_per_hop.md"),
    ("results/reanalysis/stats_v2.py", "results/reanalysis/v2_stats.md"),
    ("results/reanalysis/notinject_overdefense.py", "results/reanalysis/notinject_overdefense.md"),
]


@pytest.mark.parametrize("script,report", REPORTS, ids=[r for _, r in REPORTS])
def test_report_regenerates(script: str, report: str) -> None:
    out = subprocess.run([sys.executable, script], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    assert out.rstrip("\n") == (ROOT / report).read_text().rstrip("\n")


def test_executed_depth_buckets_v2() -> None:
    """v2 ran agents[:-1] in sequence: executed depth = agents - 1; labels 1-3 match it."""
    from deep_xpia.bench.metrics import compute_metrics
    from deep_xpia.bench.schema import BenchCase, RunResult

    lines = lambda p: [ln for ln in (ROOT / p).read_text().splitlines() if ln.strip()]  # noqa: E731
    cases = [BenchCase.model_validate_json(ln) for ln in lines("deepxpiabench-v2.jsonl")]
    runs = [RunResult.model_validate_json(ln) for ln in lines("results/raw/v2-live-2026-06/live_full_intent.jsonl")]
    executed = compute_metrics(cases, runs, 1, depth_source="executed")
    label = compute_metrics(cases, runs, 1, depth_source="label")
    assert executed.dda_n == {1: 10, 2: 90, 3: 59, 4: 41}
    assert all(executed.dda[d] == label.dda[d] for d in (1, 2, 3))
    assert label.dda_n[4] + label.dda_n[5] == executed.dda_n[4]


def test_unknown_depth_source_rejected() -> None:
    from deep_xpia.bench.metrics import compute_metrics

    with pytest.raises(ValueError):
        compute_metrics([], [], 1, depth_source="hops")


def test_gee_sensitivity_report_regenerates() -> None:
    pytest.importorskip("statsmodels")
    out = subprocess.run([sys.executable, "results/reanalysis/depth_gee_v2.py"], cwd=ROOT,
                         capture_output=True, text=True, check=True).stdout
    assert out.rstrip("\n") == (ROOT / "results/reanalysis/v2_depth_gee.md").read_text().rstrip("\n")
