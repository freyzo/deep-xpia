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


def test_scenario_depths_agree() -> None:
    import re

    from fastapi.testclient import TestClient

    from deep_xpia.server import create_app
    from scenarios.intent_laundering.ground_truth import TOPOLOGY as IL
    from scenarios.memory_poisoning.ground_truth import TOPOLOGY as MP
    from scenarios.session_smuggling.ground_truth import TOPOLOGY as SS

    truth = {"session_smuggling": SS.hop_count, "memory_poisoning": MP.hop_count,
             "intent_laundering": IL.hop_count}
    listed = {s["id"]: s["depth"] for s in TestClient(create_app()).get("/api/scenarios").json()["scenarios"]}
    for sid, depth in truth.items():
        assert listed[sid] == depth
        readme = (ROOT / "scenarios" / sid / "README.md").read_text()
        assert int(re.search(r"\*\*Depth:\*\* (\d+)", readme).group(1)) == depth
    assert "depth_definition" in yaml.safe_load((ROOT / "taxonomy/taxonomy.yaml").read_text())
