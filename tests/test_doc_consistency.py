"""Docs, taxonomy and scenario code must agree (claims that may be cited)."""

from __future__ import annotations

from pathlib import Path

import yaml

from scenarios.registry_injection.pipeline import RegistryInjectionPipeline
from scenarios.session_smuggling.pipeline import SessionSmugglingPipeline

ROOT = Path(__file__).resolve().parents[1]
TAXONOMY = {a["id"]: a for a in yaml.safe_load((ROOT / "taxonomy/taxonomy.yaml").read_text())["attacks"]}


def test_deputy_counts_match_scenarios() -> None:
    for tid, pipeline in (("DXPIA-001", SessionSmugglingPipeline()), ("DXPIA-008", RegistryInjectionPipeline())):
        gt = pipeline.to_bench_ground_truth()
        assert TAXONOMY[tid]["confused_deputies"] == len(gt["confused_deputies"])
        assert TAXONOMY[tid]["innocent_deputies"] == 1


def test_reference_scenarios_exist_and_match_taxonomy() -> None:
    for tid, attack in TAXONOMY.items():
        ref = attack.get("reference_scenario")
        if ref:
            assert (ROOT / ref).is_dir(), f"{tid}: {ref} missing"
            assert tid in (ROOT / ref / "README.md").read_text(), f"{tid}: {ref} README is for another attack"
