"""Committed re-analysis reports must equal what their scripts print from the frozen inputs."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

REPORTS = [
    ("results/reanalysis/v2_property_errata.py", "results/reanalysis/v2_property_errata.md"),
]


@pytest.mark.parametrize("script,report", REPORTS, ids=[r for _, r in REPORTS])
def test_report_regenerates(script: str, report: str) -> None:
    out = subprocess.run([sys.executable, script], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    assert out.rstrip("\n") == (ROOT / report).read_text().rstrip("\n")
